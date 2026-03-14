"""
Newsletter service — subscriber management and weekly digest sending.

Environment variables (in addition to email_service vars):
  APP_BASE_URL   e.g. https://ymmy.fly.dev (no trailing slash)
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from services.email_service import send_email, smtp_configured
from services.news_service import db_connect, split_sentences

logger = logging.getLogger(__name__)

APP_BASE_URL = os.getenv("APP_BASE_URL", "https://ymmy.fly.dev")


# ── Subscriber management ─────────────────────────────────────────────────────

def add_subscriber(email: str, language: str, level: Optional[str]) -> str:
    """
    Insert or update a subscriber row and return a confirmation token.
    If the email already exists and is unconfirmed, refreshes the token.
    If already confirmed, returns the existing unsubscribe_token (no re-confirm needed).
    """
    email = email.strip().lower()
    with db_connect() as db:
        existing = db.execute(
            "SELECT id, confirmed, confirm_token, unsubscribe_token FROM newsletter_subscribers WHERE email = ?",
            (email,),
        ).fetchone()

        if existing:
            if existing["confirmed"]:
                # Already subscribed — update preferences silently
                db.execute(
                    "UPDATE newsletter_subscribers SET language = ?, level = ? WHERE email = ?",
                    (language, level, email),
                )
                db.commit()
                return existing["unsubscribe_token"]
            else:
                # Resend confirmation
                confirm_token = secrets.token_urlsafe(32)
                db.execute(
                    "UPDATE newsletter_subscribers SET language = ?, level = ?, confirm_token = ? WHERE email = ?",
                    (language, level, confirm_token, email),
                )
                db.commit()
                return confirm_token

        confirm_token = secrets.token_urlsafe(32)
        unsubscribe_token = secrets.token_urlsafe(32)
        db.execute(
            """INSERT INTO newsletter_subscribers
               (email, language, level, confirmed, confirm_token, unsubscribe_token, created_at)
               VALUES (?, ?, ?, 0, ?, ?, datetime('now'))""",
            (email, language, level, confirm_token, unsubscribe_token),
        )
        db.commit()
    return confirm_token


def confirm_subscriber(token: str) -> bool:
    """Confirm a subscription. Returns True if successful."""
    with db_connect() as db:
        row = db.execute(
            "SELECT id FROM newsletter_subscribers WHERE confirm_token = ? AND confirmed = 0",
            (token,),
        ).fetchone()
        if not row:
            return False
        db.execute(
            "UPDATE newsletter_subscribers SET confirmed = 1, confirm_token = NULL WHERE id = ?",
            (row["id"],),
        )
        db.commit()
    return True


def unsubscribe(token: str) -> bool:
    """Remove a subscriber by unsubscribe token. Returns True if found."""
    with db_connect() as db:
        cur = db.execute(
            "DELETE FROM newsletter_subscribers WHERE unsubscribe_token = ?",
            (token,),
        )
        db.commit()
    return cur.rowcount > 0


def get_confirmed_subscribers() -> list:
    with db_connect() as db:
        rows = db.execute(
            "SELECT id, email, language, level, unsubscribe_token FROM newsletter_subscribers WHERE confirmed = 1"
        ).fetchall()
    return [dict(r) for r in rows]


def subscriber_count() -> int:
    with db_connect() as db:
        return db.execute(
            "SELECT COUNT(*) FROM newsletter_subscribers WHERE confirmed = 1"
        ).fetchone()[0]


# ── Digest building ───────────────────────────────────────────────────────────

def get_digest_articles(language: str, level: Optional[str], days: int = 7) -> list:
    """Return processed articles from the past `days` days for the given language/level."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with db_connect() as db:
        level_clause = "AND pa.target_level = ?" if level else ""
        params: list = [language, since]
        if level:
            params.append(level)
        rows = db.execute(
            f"""
            SELECT
                a.id, a.title, a.url, a.source_name, a.topic,
                a.assigned_level,
                pa.simple_text, pa.target_level
            FROM articles a
            JOIN processed_articles pa ON pa.article_id = a.id
            WHERE pa.target_language = ?
              AND (a.created_at >= ? OR a.published >= ?)
              {level_clause}
              AND a.is_archived = 0
            ORDER BY a.id DESC
            """,
            [language, since, since] + ([level] if level else []),
        ).fetchall()
    articles = []
    seen_ids = set()
    for row in rows:
        if row["id"] in seen_ids:
            continue
        seen_ids.add(row["id"])
        sentences = split_sentences(row["simple_text"], max_sentences=2)
        preview = " ".join(sentences) if sentences else ""
        articles.append({
            "id": row["id"],
            "title": row["title"],
            "url": row["url"],
            "source_name": row["source_name"],
            "topic": row["topic"] or "World",
            "level": row["assigned_level"] or row["target_level"],
            "preview": preview,
            "article_url": f"{APP_BASE_URL}/article/{row['id']}",
        })
    return articles


# ── Sending ───────────────────────────────────────────────────────────────────

def send_digest_to_subscriber(subscriber: dict, articles: list, dry_run: bool = False) -> bool:
    """Render and send the weekly digest to one subscriber. Returns True on success."""
    if not articles:
        logger.info("No articles for %s — skipping", subscriber["email"])
        return False

    from jinja2 import Environment, FileSystemLoader
    import pathlib
    templates_dir = pathlib.Path(__file__).resolve().parent.parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)
    tmpl = env.get_template("email_digest.html")

    unsubscribe_url = f"{APP_BASE_URL}/unsubscribe/{subscriber['unsubscribe_token']}"
    level_label = subscriber["level"] or "all levels"
    subject = f"Your weekly {subscriber['language']} digest"

    html = tmpl.render(
        language=subscriber["language"],
        level=level_label,
        articles=articles,
        unsubscribe_url=unsubscribe_url,
        base_url=APP_BASE_URL,
        week_label=datetime.now(timezone.utc).strftime("%B %-d, %Y"),
    )

    # Plain-text fallback
    lines = [f"Your weekly {subscriber['language']} news digest\n"]
    for a in articles:
        lines.append(f"[{a['topic']} · {a['level']}] {a['title']}")
        lines.append(f"{a['preview']}")
        lines.append(f"Read: {a['article_url']}\n")
    lines.append(f"Unsubscribe: {unsubscribe_url}")
    text = "\n".join(lines)

    if dry_run:
        print(f"[DRY RUN] Would send to {subscriber['email']}: {subject}")
        print(f"  {len(articles)} articles")
        return True

    try:
        send_email(subscriber["email"], subject, html, text)
        return True
    except Exception as e:
        logger.error("Failed to send digest to %s: %s", subscriber["email"], e)
        return False


def send_weekly_digest(language: Optional[str] = None, dry_run: bool = False) -> dict:
    """
    Send the weekly digest to all confirmed subscribers.
    If `language` is given, only send to subscribers of that language.
    Returns a summary dict.
    """
    subscribers = get_confirmed_subscribers()
    if language:
        subscribers = [s for s in subscribers if s["language"] == language]

    sent = 0
    skipped = 0
    failed = 0

    # Group by (language, level) to avoid fetching articles repeatedly
    from itertools import groupby
    key = lambda s: (s["language"], s.get("level"))
    subscribers_sorted = sorted(subscribers, key=key)

    for (lang, lvl), group in groupby(subscribers_sorted, key=key):
        articles = get_digest_articles(lang, lvl)
        for sub in group:
            ok = send_digest_to_subscriber(sub, articles, dry_run=dry_run)
            if not articles:
                skipped += 1
            elif ok:
                sent += 1
            else:
                failed += 1

    return {"sent": sent, "skipped": skipped, "failed": failed, "total": len(subscribers)}
