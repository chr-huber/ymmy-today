"""
Passwordless admin sign-in via emailed magic link.

The admin panel accepts two kinds of caller:

* **You**, in a browser — request a link at `/admin/login`, click it, and a signed
  session cookie keeps you signed in for ADMIN_SESSION_DAYS.
* **The cron process**, via curl — HTTP Basic Auth with ADMIN_PASSWORD. That
  secret stays in the Fly secret store as a machine credential; nobody types it.

Link design notes:

* The destination address comes from ADMIN_EMAIL, never from user input, so the
  login form has no field to enumerate or typo.
* Tokens are stored as SHA-256 hashes, expire in ADMIN_LOGIN_TOKEN_MINUTES, and
  are single-use.
* Clicking the link only *offers* sign-in; a confirm button POSTs to consume it.
  Mail scanners that prefetch links (Outlook Safe Links and friends) therefore
  cannot burn the token before you get to it.
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from services.email_service import send_email, smtp_configured
from services.news_service import db_connect

logger = logging.getLogger(__name__)

TOKEN_TTL_MINUTES = int(os.getenv("ADMIN_LOGIN_TOKEN_MINUTES", "15"))
SESSION_DAYS = int(os.getenv("ADMIN_SESSION_DAYS", "30"))

# Session key holding the ISO timestamp of the last successful magic-link sign-in.
SESSION_KEY = "admin_authed_at"


def admin_email() -> str:
    return os.getenv("ADMIN_EMAIL", "").strip()


def magic_link_available() -> bool:
    """Magic-link sign-in needs both a destination address and working SMTP."""
    return bool(admin_email()) and smtp_configured()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── Token lifecycle ───────────────────────────────────────────────────────────

def create_login_token(requested_ip: Optional[str] = None) -> str:
    """Mint a single-use login token and return the raw value (only stored hashed)."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=TOKEN_TTL_MINUTES)
    with db_connect() as db:
        # Any earlier outstanding link becomes void — requesting a new one
        # invalidates the old, so a forwarded stale email is useless.
        db.execute("DELETE FROM admin_login_tokens WHERE used_at IS NULL")
        db.execute(
            "INSERT INTO admin_login_tokens (token_hash, created_at, expires_at, requested_ip) "
            "VALUES (?, ?, ?, ?)",
            (_hash(token), now.isoformat(), expires.isoformat(), requested_ip),
        )
        db.commit()
    return token


def _lookup(db, token: str):
    return db.execute(
        "SELECT id, expires_at, used_at FROM admin_login_tokens WHERE token_hash = ?",
        (_hash(token),),
    ).fetchone()


def _is_live(row) -> bool:
    if row is None or row["used_at"]:
        return False
    return datetime.now(timezone.utc).isoformat() <= row["expires_at"]


def token_is_valid(token: str) -> bool:
    """True if the token exists, is unused, and has not expired. Does not consume it."""
    if not token:
        return False
    with db_connect() as db:
        return _is_live(_lookup(db, token))


def consume_login_token(token: str) -> bool:
    """
    Atomically spend a token. Returns True exactly once per token; every later
    call returns False, so a replayed link cannot sign anyone in twice.
    """
    if not token:
        return False
    now = datetime.now(timezone.utc).isoformat()
    with db_connect() as db:
        # Single conditional UPDATE — two simultaneous clicks cannot both win.
        cur = db.execute(
            "UPDATE admin_login_tokens SET used_at = ? "
            "WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?",
            (now, _hash(token), now),
        )
        db.commit()
        return cur.rowcount > 0


def purge_expired_tokens() -> int:
    """Housekeeping: drop tokens that are spent or long past their expiry."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with db_connect() as db:
        cur = db.execute(
            "DELETE FROM admin_login_tokens WHERE used_at IS NOT NULL OR expires_at < ?",
            (cutoff,),
        )
        db.commit()
        return cur.rowcount


# ── Session ───────────────────────────────────────────────────────────────────

def mark_session_authed(session) -> None:
    session[SESSION_KEY] = datetime.now(timezone.utc).isoformat()


def clear_session_auth(session) -> None:
    session.pop(SESSION_KEY, None)


def session_is_authed(session) -> bool:
    """True while the signed session still carries a recent magic-link sign-in."""
    stamp = session.get(SESSION_KEY)
    if not stamp:
        return False
    try:
        authed_at = datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return False
    if authed_at.tzinfo is None:
        authed_at = authed_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - authed_at < timedelta(days=SESSION_DAYS)


# ── Email ─────────────────────────────────────────────────────────────────────

def send_login_link(token: str, base_url: str) -> None:
    """Email the magic link to ADMIN_EMAIL. Raises on send failure."""
    url = f"{base_url.rstrip('/')}/admin/auth/{token}"
    html = (
        "<p>Here is your ymmy admin sign-in link:</p>"
        f"<p><a href='{url}'>Sign in to ymmy admin</a></p>"
        f"<p>It expires in {TOKEN_TTL_MINUTES} minutes and can be used once.</p>"
        "<p>If you didn't request this, someone knows your admin URL but not your "
        "inbox — you can safely ignore it.</p>"
    )
    text = (
        "Here is your ymmy admin sign-in link:\n\n"
        f"{url}\n\n"
        f"It expires in {TOKEN_TTL_MINUTES} minutes and can be used once.\n"
        "If you didn't request this, you can safely ignore it.\n"
    )
    send_email(admin_email(), "Your ymmy admin sign-in link", html, text)
