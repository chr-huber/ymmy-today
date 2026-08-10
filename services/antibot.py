"""
Anti-bot helpers for the public forms (register, subscribe).

Four cheap layers that together stop the overwhelming majority of form-spam
bots without putting a captcha in front of real users:

1. Honeypot   — a hidden input that real users never fill in.
2. Time trap  — a signed timestamp embedded in the form; submissions that
                arrive implausibly fast (or impossibly late) are rejected.
3. Validation — strict syntax checks plus a disposable-domain blocklist.
4. IP quota   — a per-IP daily cap, counted in the database so it survives
                machine restarts (unlike the in-memory slowapi limits).

`client_ip()` resolves the real caller address behind the Fly proxy, so the
rate limits and the IP quota key on the visitor rather than on the proxy.
"""

import os
import re
from datetime import datetime, timezone
from typing import Any, Optional

from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from starlette.requests import Request

# The hidden field bots love to fill in. Named to look worth filling.
HONEYPOT_FIELD = "website"

# Field carrying the signed render timestamp.
FORM_TOKEN_FIELD = "form_token"

_signer = TimestampSigner(
    os.getenv("SESSION_SECRET_KEY", "change-me-in-production"),
    salt="ymmy-public-form",
)

# Free/disposable mailbox providers that show up almost exclusively in bot
# signups. Extend at runtime with BLOCKED_EMAIL_DOMAINS (comma-separated).
_DISPOSABLE_DOMAINS = {
    "0-mail.com", "10minutemail.com", "20minutemail.com", "33mail.com",
    "anonbox.net", "byom.de", "cock.li", "dispostable.com", "dropmail.me",
    "e4ward.com", "emailondeck.com", "fakeinbox.com", "getairmail.com",
    "getnada.com", "grr.la", "guerrillamail.com", "guerrillamail.info",
    "guerrillamail.net", "guerrillamail.org", "harakirimail.com",
    "inboxbear.com", "inboxkitten.com", "jetable.org", "mail-temporaire.fr",
    "mail.tm", "mailcatch.com", "maildrop.cc", "mailinator.com",
    "mailnesia.com", "mailsac.com", "moakt.com", "mohmal.com", "mvrht.net",
    "mytemp.email", "nowmymail.com", "sharklasers.com", "spam4.me",
    "spamgourmet.com", "temp-mail.io", "temp-mail.org", "tempail.com",
    "tempinbox.com", "tempmail.net", "tempmailo.com", "tempr.email",
    "throwawaymail.com", "trashmail.com", "trashmail.de", "trbvm.com",
    "vomoto.com", "wegwerfmail.de", "yopmail.com", "yopmail.fr",
    "yopmail.net", "zetmail.com",
}

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{1,30}[A-Za-z0-9])$")

# Anything URL- or markup-shaped in a username is a spam signal.
_SPAMMY_USERNAME_RE = re.compile(
    r"(https?://|www\.|\.com\b|\.ru\b|\.xyz\b|<a\s|\[url|\bviagra\b|\bcasino\b|\bcrypto\b)",
    re.IGNORECASE,
)


def blocked_domains() -> set:
    """Disposable-domain blocklist, extended by BLOCKED_EMAIL_DOMAINS."""
    extra = os.getenv("BLOCKED_EMAIL_DOMAINS", "")
    custom = {d.strip().lower() for d in extra.split(",") if d.strip()}
    return _DISPOSABLE_DOMAINS | custom


# ── Client address ────────────────────────────────────────────────────────────

def client_ip(request: Request) -> str:
    """
    Real client address.

    Fly terminates TLS at its proxy, so request.client.host is the proxy for
    every visitor. Prefer the headers Fly sets, and fall back to the socket
    address when running locally.
    """
    fly_ip = request.headers.get("fly-client-ip")
    if fly_ip:
        return fly_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Left-most entry is the original client.
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


# ── Form token (time trap) ────────────────────────────────────────────────────

def form_token(form_name: str) -> str:
    """Signed, timestamped token to embed in a public form as a hidden field."""
    return _signer.sign(form_name.encode()).decode()


def check_form_token(
    form_name: str,
    token: Optional[str],
    min_seconds: float = 2.0,
    max_seconds: int = 60 * 60 * 12,
) -> Optional[str]:
    """
    Validate a form token. Returns an error string, or None when the token is
    good. Rejects tokens that are forged, stale, issued for a different form,
    or submitted faster than a human could plausibly fill the form in.
    """
    if not token:
        return "This form has expired. Please reload the page and try again."
    try:
        value, timestamp = _signer.unsign(
            token.encode(), max_age=max_seconds, return_timestamp=True
        )
    except SignatureExpired:
        return "This form has expired. Please reload the page and try again."
    except BadSignature:
        return "This form could not be verified. Please reload the page and try again."

    if value.decode() != form_name:
        return "This form could not be verified. Please reload the page and try again."

    age = (datetime.now(timezone.utc) - timestamp).total_seconds()
    if age < min_seconds:
        return "That was a little too quick — please try again."
    return None


# ── Honeypot ──────────────────────────────────────────────────────────────────

def honeypot_tripped(form: Any) -> bool:
    """True when the hidden decoy field came back with a value."""
    return bool((form.get(HONEYPOT_FIELD) or "").strip())


# ── Validation ────────────────────────────────────────────────────────────────

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def validate_email(email: str) -> Optional[str]:
    """Return an error string, or None if the address looks legitimate."""
    if not email:
        return "Please enter an email address."
    if len(email) > 254:
        return "That email address is too long."
    if not _EMAIL_RE.match(email):
        return "Please enter a valid email address."
    domain = email.rsplit("@", 1)[1]
    if domain in blocked_domains():
        return "Disposable email addresses are not accepted. Please use a permanent address."
    return None


def validate_username(username: str) -> Optional[str]:
    """Return an error string, or None if the username looks legitimate."""
    username = (username or "").strip()
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if len(username) > 32:
        return "Username must be at most 32 characters."
    if not _USERNAME_RE.match(username):
        return "Username may only contain letters, numbers, spaces, and . _ -"
    if _SPAMMY_USERNAME_RE.search(username):
        return "That username is not allowed."
    return None


# ── Combined gate ─────────────────────────────────────────────────────────────

def check_bot_signals(
    form: Any,
    form_name: str,
    min_seconds: float = 2.0,
) -> Optional[str]:
    """
    Run the honeypot and time-trap checks for a submitted form.

    Returns an error string, or None when the submission looks human. The
    honeypot deliberately returns the same generic message as a bad token so
    a bot author cannot tell which layer caught them.
    """
    generic = "This form could not be verified. Please reload the page and try again."
    if honeypot_tripped(form):
        return generic
    return check_form_token(form_name, form.get(FORM_TOKEN_FIELD), min_seconds=min_seconds)
