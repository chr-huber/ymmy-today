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
from services.news_service import _call_llm_api, db_connect, split_sentences

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


def get_all_subscribers() -> list:
    with db_connect() as db:
        rows = db.execute(
            "SELECT id, email, language, level, confirmed, created_at FROM newsletter_subscribers ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def delete_subscriber(subscriber_id: int) -> bool:
    with db_connect() as db:
        cur = db.execute("DELETE FROM newsletter_subscribers WHERE id = ?", (subscriber_id,))
        db.commit()
    return cur.rowcount > 0


def subscriber_count() -> int:
    with db_connect() as db:
        return db.execute(
            "SELECT COUNT(*) FROM newsletter_subscribers WHERE confirmed = 1"
        ).fetchone()[0]


def log_digest_send(result: dict, language: Optional[str], dry_run: bool) -> None:
    with db_connect() as db:
        db.execute(
            """INSERT INTO digest_log (language, dry_run, sent, skipped, failed, total)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (language, int(dry_run), result["sent"], result["skipped"], result["failed"], result["total"]),
        )
        db.commit()


def get_digest_log(limit: int = 20) -> list:
    with db_connect() as db:
        rows = db.execute(
            "SELECT * FROM digest_log ORDER BY sent_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ── Digest building ───────────────────────────────────────────────────────────

def _pick_article_ids(candidates: list, limit: int) -> list[int]:
    """Ask Mistral to pick the most interesting article IDs from candidates. Falls back to first N."""
    if len(candidates) <= limit:
        return [c["id"] for c in candidates]

    lines = "\n".join(f'{c["id"]}: [{c["topic"]}] {c["title"]}' for c in candidates)
    prompt = (
        f"Here are {len(candidates)} news headlines. "
        f"Pick the {limit} most interesting and varied ones for a weekly language learning digest. "
        f"Reply with ONLY a comma-separated list of the numeric IDs, e.g.: 12,7,3\n\n{lines}"
    )
    result = _call_llm_api("mistral", prompt, "You are a newsletter editor. Reply only with a comma-separated list of IDs.")
    if "error" in result:
        logger.warning("Mistral article picker failed: %s — falling back to recency", result["error"])
        return [c["id"] for c in candidates[:limit]]

    try:
        picked = [int(x.strip()) for x in result["content"].strip().split(",")]
        valid = [i for i in picked if i in {c["id"] for c in candidates}][:limit]
        if valid:
            return valid
    except (ValueError, AttributeError):
        pass

    logger.warning("Could not parse Mistral picker response — falling back to recency")
    return [c["id"] for c in candidates[:limit]]


def generate_digest_intro(articles: list, language: str) -> str:
    """Ask Mistral to write a 1-3 sentence intro for the digest based on the chosen articles."""
    if not articles:
        return ""
    titles = "\n".join(f"- {a['title']}" for a in articles)
    prompt = (
        f"Write a short 1-3 sentence introduction for a weekly {language} language learning newsletter. "
        f"This week's articles are:\n{titles}\n\n"
        f"The intro should feel warm and editorial — briefly mention what's in this week's issue. "
        f"Write in English. No greeting, no sign-off, just the intro text."
    )
    result = _call_llm_api("mistral", prompt, "You are a friendly newsletter editor. Be concise and natural.")
    if "error" in result:
        logger.warning("Intro generation failed: %s", result["error"])
        return ""
    return result.get("content", "").strip()


def get_digest_articles(language: str, level: Optional[str], days: int = 7, limit: int = 3) -> list:
    """Return up to `limit` articles chosen by Mistral from the past `days` days, with vocab and grammar."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    with db_connect() as db:
        level_clause = "AND pa.target_level = ?" if level else ""
        rows = db.execute(
            f"""
            SELECT
                a.id, a.title, a.url, a.source_name, a.topic,
                a.assigned_level,
                pa.simple_text, pa.english_translation, pa.target_level
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

        # Deduplicate by article id
        seen = set()
        candidates = []
        for row in rows:
            if row["id"] not in seen:
                seen.add(row["id"])
                candidates.append(dict(row))

        picked_ids = _pick_article_ids(candidates, limit)

        # Fetch full data for picked articles in order
        by_id = {c["id"]: c for c in candidates}
        articles = []
        for article_id in picked_ids:
            row = by_id.get(article_id)
            if not row:
                continue

            vocab = db.execute(
                "SELECT base_form, grammatical_form, english_translation, used_form FROM vocabulary_items WHERE article_id = ? LIMIT 5",
                (article_id,),
            ).fetchall()

            grammar = db.execute(
                "SELECT sentence_text, grammar_explanation FROM grammar_items WHERE article_id = ? LIMIT 2",
                (article_id,),
            ).fetchall()

            articles.append({
                "id": row["id"],
                "title": row["title"],
                "url": row["url"],
                "source_name": row["source_name"],
                "topic": row["topic"] or "World",
                "level": row["assigned_level"] or row["target_level"],
                "simple_text": row["simple_text"] or "",
                "english_translation": row["english_translation"] or "",
                "vocab": [dict(v) for v in vocab],
                "grammar": [dict(g) for g in grammar],
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
    subject = "ymmy · weekly"

    intro = generate_digest_intro(articles, subscriber["language"])

    html = tmpl.render(
        language=subscriber["language"],
        level=level_label,
        articles=articles,
        intro=intro,
        unsubscribe_url=unsubscribe_url,
        base_url=APP_BASE_URL,
        week_label=datetime.now(timezone.utc).strftime("%B %-d, %Y"),
    )

    # Plain-text fallback
    lines = [f"ymmy · weekly\n"]
    for a in articles:
        lines.append(f"{'─' * 40}")
        lines.append(f"[{a['topic']} · {a['level']}] {a['title']}")
        if a.get("simple_text"):
            lines.append(f"\n{a['simple_text']}")
        if a.get("english_translation"):
            lines.append(f"\n{a['english_translation']}")
        if a.get("vocab"):
            lines.append("\nKey words:")
            for v in a["vocab"]:
                lines.append(f"  {v['base_form']} ({v['grammatical_form']}) — {v['english_translation']}")
        lines.append(f"\nOpen in ymmy: {a['article_url']}\n")
    lines.append(f"{'─' * 40}")
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


def send_weekly_digest(language: Optional[str] = None, dry_run: bool = False, force: bool = False) -> dict:
    """
    Send the weekly digest to all confirmed subscribers.
    If `language` is given, only send to subscribers of that language.
    Returns a summary dict.
    """
    if not dry_run and not force:
        cooldown_minutes = 10
        since = (datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        with db_connect() as db:
            recent = db.execute(
                "SELECT id FROM digest_log WHERE dry_run = 0 AND sent_at >= ? LIMIT 1", (since,)
            ).fetchone()
        if recent:
            logger.warning("Digest already sent in the last %d minutes — skipping", cooldown_minutes)
            return {"sent": 0, "skipped": 0, "failed": 0, "total": 0, "cooldown": True}

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

    result = {"sent": sent, "skipped": skipped, "failed": failed, "total": len(subscribers)}
    log_digest_send(result, language, dry_run)
    return result
