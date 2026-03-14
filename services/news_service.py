import base64
import email.utils
import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import feedparser
import requests
import trafilatura
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DATABASE_PATH", "news.db")

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "mistral")  # "mistral", "deepseek", "claude", or "openai"
REVIEW_LLM_PROVIDER = os.getenv("REVIEW_LLM_PROVIDER", "claude")  # second-pass reviewer, defaults to claude
MISTRAL_MODEL = os.getenv("MISTRAL_MODEL", "mistral-small-latest")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
DEFAULT_TARGET_LANGUAGE = os.getenv("DEFAULT_TARGET_LANGUAGE", "Finnish")
DEFAULT_TARGET_LEVEL = os.getenv("DEFAULT_TARGET_LEVEL", "A2")
LEARNING_LANGUAGES = ["Finnish", "German"]
CEFR_LEVELS = ["A1", "A2", "B1"]
ARTICLE_TOPICS = ["World", "Economics", "Life"]
DEFAULT_VALIDATION_RETRIES = int(os.getenv("DEFAULT_VALIDATION_RETRIES", "2"))
DEFAULT_AUTO_TOP_N = int(os.getenv("DEFAULT_AUTO_TOP_N", "4"))
DEFAULT_AUTO_MAX_AGE_HOURS = int(os.getenv("DEFAULT_AUTO_MAX_AGE_HOURS", "6"))
DEFAULT_MAX_WORKERS = int(os.getenv("DEFAULT_MAX_WORKERS", "8"))
DEFAULT_AUTO_PER_SOURCE = int(os.getenv("DEFAULT_AUTO_PER_SOURCE", "12"))
DEFAULT_MAX_PER_SOURCE_PREFILTER = int(os.getenv("DEFAULT_MAX_PER_SOURCE_PREFILTER", "2"))
DEFAULT_MAX_PER_SOURCE_FINAL = int(os.getenv("DEFAULT_MAX_PER_SOURCE_FINAL", "1"))
DEFAULT_CANDIDATE_POOL_LIMIT = int(os.getenv("DEFAULT_CANDIDATE_POOL_LIMIT", "180"))
_EXCLUDED_HEADLINE_TERMS = tuple(
    term.strip().lower()
    for term in os.getenv("EXCLUDED_HEADLINE_TERMS", "briefing").split(",")
    if term.strip()
)

TRUSTED_SOURCES = [
    {
        "name": "Yle Uutiset",
        "rss": "https://feeds.yle.fi/uutiset/v1/majorHeadlines/YLE_UUTISET.rss",
    },
    {"name": "BBC World", "rss": "http://feeds.bbci.co.uk/news/world/rss.xml"},
    {"name": "ORF", "rss": "https://rss.orf.at/news.xml"},
    {"name": "Tagesschau", "rss": "https://www.tagesschau.de/infoservices/alle-meldungen-100~rss2.xml"},
    {"name": "Euronews", "rss": "https://www.euronews.com/rss"},
    {"name": "The Guardian", "rss": "https://www.theguardian.com/world/rss"},
    {"name": "BBC Science", "rss": "https://feeds.bbci.co.uk/news/science_and_environment/rss.xml"},
    {"name": "DW English", "rss": "https://rss.dw.com/rdf/rss-en-all"},
]

LANGUAGE_SOURCE_EXCLUSIONS: Dict[str, set[str]] = {
    "German": {"Yle Uutiset"},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 260_000


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2:sha256:{_PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, params = stored_hash.split("pbkdf2:sha256:", 1)
        iterations_str, salt_b64, dk_b64 = params.split("$")
        salt = base64.b64decode(salt_b64)
        expected_dk = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations_str))
        return hmac.compare_digest(dk, expected_dk)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------


def create_user(username: str, password: str) -> int:
    """Create a new user. Returns the new user id. Raises ValueError if username taken."""
    with db_connect() as db:
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise ValueError(f"Username '{username}' is already taken.")
        password_hash = _hash_password(password)
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, password_hash, now_iso()),
        )
        db.commit()
        return cursor.lastrowid


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    with db_connect() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with db_connect() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def verify_user_password(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Return user dict if credentials are valid, else None."""
    user = get_user_by_username(username)
    if user and _verify_password(password, user["password_hash"]):
        return user
    return None


def get_user_settings(user_id: int) -> Dict[str, Any]:
    user = get_user_by_id(user_id)
    if not user:
        return {"language": DEFAULT_TARGET_LANGUAGE, "level": DEFAULT_TARGET_LEVEL}
    return {
        "language": user.get("language") or DEFAULT_TARGET_LANGUAGE,
        "level": user.get("level") or DEFAULT_TARGET_LEVEL,
    }


def save_user_settings(user_id: int, language: str, level: str) -> None:
    with db_connect() as db:
        db.execute(
            "UPDATE users SET language = ?, level = ? WHERE id = ?",
            (language, level, user_id),
        )
        db.commit()


# ---------------------------------------------------------------------------
# Per-user article read tracking
# ---------------------------------------------------------------------------


def mark_article_read_for_user(user_id: int, article_id: int) -> None:
    with db_connect() as db:
        db.execute(
            "INSERT OR IGNORE INTO user_article_reads (user_id, article_id, read_at) VALUES (?, ?, ?)",
            (user_id, article_id, now_iso()),
        )
        db.commit()


def mark_article_unread_for_user(user_id: int, article_id: int) -> None:
    with db_connect() as db:
        db.execute(
            "DELETE FROM user_article_reads WHERE user_id = ? AND article_id = ?",
            (user_id, article_id),
        )
        db.commit()


# ---------------------------------------------------------------------------
# Per-user vocabulary state
# ---------------------------------------------------------------------------


def toggle_save_word_for_user(user_id: int, vocab_item_id: int) -> bool:
    """Toggle saved state for a user. Returns new saved state (True = saved)."""
    with db_connect() as db:
        row = db.execute(
            "SELECT saved FROM user_vocab_state WHERE user_id = ? AND vocab_item_id = ?",
            (user_id, vocab_item_id),
        ).fetchone()
        if row is None:
            # Not yet saved — insert as saved
            db.execute(
                "INSERT INTO user_vocab_state (user_id, vocab_item_id, saved) VALUES (?, ?, 1)",
                (user_id, vocab_item_id),
            )
            db.commit()
            return True
        new_state = 0 if row["saved"] else 1
        db.execute(
            "UPDATE user_vocab_state SET saved = ? WHERE user_id = ? AND vocab_item_id = ?",
            (new_state, user_id, vocab_item_id),
        )
        db.commit()
    return bool(new_state)


def get_saved_words_for_user(
    user_id: int,
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return saved vocabulary items due for review for a specific user."""
    now = now_iso()
    where_extra = ""
    params: List[Any] = [user_id, now]
    if target_language:
        where_extra += " AND COALESCE(v.target_language, '') = ?"
        params.append(target_language)
    if target_level:
        where_extra += " AND COALESCE(v.target_level, '') = ?"
        params.append(target_level)

    with db_connect() as db:
        rows = db.execute(
            f"""
            SELECT v.id, v.base_form, v.english_translation AS translation,
                   v.used_form, v.used_form_translation, v.grammatical_form,
                   uvs.review_count, uvs.next_review_at,
                   a.title AS article_title, a.id AS article_id
            FROM user_vocab_state uvs
            JOIN vocabulary_items v ON v.id = uvs.vocab_item_id
            JOIN articles a ON a.id = v.article_id
            WHERE uvs.user_id = ?
              AND uvs.saved = 1
              AND (uvs.next_review_at IS NULL OR uvs.next_review_at <= ?)
              {where_extra}
            ORDER BY CASE WHEN uvs.next_review_at IS NULL THEN 0 ELSE 1 END ASC,
                     uvs.next_review_at ASC
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_all_saved_words_for_user(user_id: int) -> List[Dict[str, Any]]:
    """Return all saved vocabulary items for a user, regardless of due date."""
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT v.id, v.base_form, v.english_translation AS translation,
                   v.used_form, v.grammatical_form,
                   uvs.review_count, uvs.next_review_at,
                   a.title AS article_title, a.id AS article_id
            FROM user_vocab_state uvs
            JOIN vocabulary_items v ON v.id = uvs.vocab_item_id
            JOIN articles a ON a.id = v.article_id
            WHERE uvs.user_id = ? AND uvs.saved = 1
            ORDER BY v.base_form ASC
            """,
            (user_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_due_count_for_user(
    user_id: int,
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
) -> int:
    now = now_iso()
    where_extra = ""
    params: List[Any] = [user_id, now]
    if target_language:
        where_extra += " AND COALESCE(v.target_language, '') = ?"
        params.append(target_language)
    if target_level:
        where_extra += " AND COALESCE(v.target_level, '') = ?"
        params.append(target_level)
    with db_connect() as db:
        row = db.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM user_vocab_state uvs
            JOIN vocabulary_items v ON v.id = uvs.vocab_item_id
            WHERE uvs.user_id = ?
              AND uvs.saved = 1
              AND (uvs.next_review_at IS NULL OR uvs.next_review_at <= ?)
              {where_extra}
            """,
            params,
        ).fetchone()
    return int(row["cnt"]) if row else 0


def mark_word_reviewed_for_user(user_id: int, vocab_item_id: int, knew_it: bool) -> None:
    with db_connect() as db:
        row = db.execute(
            "SELECT review_count FROM user_vocab_state WHERE user_id = ? AND vocab_item_id = ?",
            (user_id, vocab_item_id),
        ).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO user_vocab_state (user_id, vocab_item_id, saved, review_count) VALUES (?, ?, 0, 0)",
                (user_id, vocab_item_id),
            )
            review_count = 0
        else:
            review_count = to_int(row["review_count"], default=0)
        new_count = review_count + 1
        next_review = _next_review_date(new_count, knew_it)
        db.execute(
            "UPDATE user_vocab_state SET review_count = ?, next_review_at = ? WHERE user_id = ? AND vocab_item_id = ?",
            (new_count, next_review, user_id, vocab_item_id),
        )
        db.commit()


def parse_iso_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def clean_html(raw_text: str) -> str:
    if not raw_text:
        return ""
    no_tags = re.sub(r"<[^>]+>", " ", raw_text)
    no_space = re.sub(r"\s+", " ", no_tags)
    return no_space.strip()


def is_excluded_headline(title: str) -> bool:
    lowered = (title or "").lower()
    if not lowered:
        return False
    for term in _EXCLUDED_HEADLINE_TERMS:
        if re.search(rf"\b{re.escape(term)}\b", lowered):
            return True
    return False


FULL_FETCH_THRESHOLD = int(os.getenv("FULL_FETCH_THRESHOLD", "400"))


def fetch_full_content(url: str) -> str:
    """Fetch and extract the main article body from a URL using trafilatura."""
    try:
        downloaded = trafilatura.fetch_url(url)
        if not downloaded:
            return ""
        text = trafilatura.extract(
            downloaded,
            include_comments=False,
            include_tables=False,
            no_fallback=False,
        )
        return (text or "").strip()
    except Exception:
        return ""


def split_sentences(text: str, max_sentences: Optional[int] = 10) -> List[str]:
    raw_text = (text or "").strip()
    if not raw_text:
        return []

    line_parts = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if len(line_parts) > 1:
        return line_parts[:max_sentences] if max_sentences is not None else line_parts

    parts = re.split(r'(?<=[.!?])\s+(?=[A-ZÅÄÖ"])', raw_text)
    sentences = [p.strip() for p in parts if p.strip()]
    return sentences[:max_sentences] if max_sentences is not None else sentences


def format_numbered_lines(sentences: List[str]) -> str:
    return "\n".join([f"{idx}. {sentence}" for idx, sentence in enumerate(sentences, start=1)])


def to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item.strip())
            elif isinstance(item, dict):
                parts.append(json.dumps(item, ensure_ascii=False))
            else:
                parts.append(str(item))
        return "\n".join([p for p in parts if p])
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    if value is None:
        return ""
    return str(value)


def parse_json_object(raw_text: str) -> Dict[str, Any]:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", raw_text, flags=re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def _hash_prompt(title: str, content: str, target_language: str, levels: List[str]) -> str:
    """Generate consistent hash for caching LLM prompts."""
    import hashlib
    combined = f"{title}|{content[:500]}|{target_language}|{','.join(sorted(levels))}"
    return hashlib.md5(combined.encode('utf-8')).hexdigest()


def _log_processing_start(article_id: int, target_language: str, target_level: str) -> int:
    """Log start of processing for tracking."""
    with db_connect() as db:
        cursor = db.execute(
            """
            INSERT INTO processing_log
            (article_id, target_language, target_level, status, started_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (article_id, target_language, target_level, "started", now_iso())
        )
        db.commit()
        return cursor.lastrowid


def _log_pipeline_event(
    stage: str,
    message: str,
    level: str = "info",
    run_type: str = "pipeline",
    run_id: Optional[str] = None,
    article_id: Optional[int] = None,
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
    provider: Optional[str] = None,
) -> None:
    with db_connect() as db:
        db.execute(
            """
            INSERT INTO pipeline_events
            (created_at, run_type, run_id, stage, level, message, article_id, target_language, target_level, provider)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now_iso(),
                run_type,
                run_id,
                stage,
                level,
                message,
                article_id,
                target_language,
                target_level,
                provider,
            ),
        )
        db.commit()


def _log_processing_complete(log_id: int, success: bool, error_msg: str = "") -> None:
    """Update processing log with completion status."""
    with db_connect() as db:
        db.execute(
            """
            UPDATE processing_log
            SET status = ?, error_message = ?, completed_at = ?
            WHERE id = ?
            """,
            ("success" if success else "error", error_msg if not success else "", now_iso(), log_id)
        )
        db.commit()


def _log_quality_issue(article_id: int, target_language: str, target_level: str, 
                      issue_type: str, issue_description: str, severity: str = "medium") -> None:
    """Record quality control issues for manual review."""
    with db_connect() as db:
        db.execute(
            """
            INSERT INTO quality_control
            (article_id, target_language, target_level, issue_type, issue_description, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (article_id, target_language, target_level, issue_type, issue_description, severity, now_iso())
        )
        db.commit()


def _get_cached_response(article_id: int, target_language: str, prompt_hash: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached LLM response if available."""
    with db_connect() as db:
        row = db.execute(
            """
            SELECT response_json, token_count
            FROM llm_cache
            WHERE article_id = ? AND target_language = ? AND prompt_hash = ?
            """,
            (article_id, target_language, prompt_hash)
        ).fetchone()
        if row:
            return {
                "response": row["response_json"],
                "token_count": row["token_count"]
            }
    return None


def _cache_llm_response(article_id: int, target_language: str, prompt_hash: str, 
                      response_json: str, token_count: int) -> None:
    """Store LLM response in cache."""
    with db_connect() as db:
        db.execute(
            """
            INSERT OR REPLACE INTO llm_cache
            (article_id, target_language, prompt_hash, response_json, token_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (article_id, target_language, prompt_hash, response_json, token_count, now_iso())
        )
        db.commit()


def validate_generated_content(
    simple_text: str,
    english_text: str,
    keywords: List[Any],
    target_language: str,
) -> List[str]:
    issues: List[str] = []

    simple_sentences_all = split_sentences(simple_text, max_sentences=None)
    english_sentences_all = split_sentences(english_text, max_sentences=None)

    if not simple_sentences_all:
        issues.append("No simplified text produced.")
    if not english_sentences_all:
        issues.append("No English translation produced.")
    if len(simple_sentences_all) > 12:
        issues.append("Simplified text has more than 12 sentences.")
    if len(english_sentences_all) > 12:
        issues.append("English translation has more than 12 sentences.")
    if len([k for k in keywords if isinstance(k, dict)]) < 3:
        issues.append("Too few valid keywords.")

    # Basic language sanity check: detect if output is obviously in English instead
    # of the requested language.
    _LANGUAGE_MARKERS: Dict[str, set] = {
        "finnish": {" on ", " ja ", " että ", " ei ", " ovat ", " voi ", " mutta "},
        "german": {" der ", " die ", " und ", " ist ", " nicht ", " mit ", " auf "},
        "swedish": {" och ", " är ", " att ", " det ", " en ", " man ", " inte "},
        "danish": {" og ", " er ", " at ", " det ", " en ", " man ", " ikke "},
    }
    lang_key = target_language.lower()
    lang_markers = _LANGUAGE_MARKERS.get(lang_key)
    if lang_markers:
        text = (simple_text or "").lower()
        marker_hits = sum(1 for m in lang_markers if m in f" {text} ")
        english_markers = {" the ", " and ", " is ", " are ", " of ", " to ", " in "}
        english_hits = sum(1 for m in english_markers if m in f" {text} ")
        other_lang_hits = 0
        for key, markers in _LANGUAGE_MARKERS.items():
            if key == lang_key:
                continue
            other_lang_hits = max(other_lang_hits, sum(1 for m in markers if m in f" {text} "))

        if marker_hits == 0 and english_hits >= 2:
            issues.append(f"Simplified text does not look like {target_language}.")
        elif marker_hits == 0 and other_lang_hits >= 2:
            issues.append(f"Simplified text does not look like {target_language}.")

    return issues



class _Sqlite3Connection:
    """Thin wrapper to coerce list params to tuples for sqlite3 compatibility."""
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=()):
        return self._conn.execute(sql, tuple(params))

    def executemany(self, sql, seq):
        return self._conn.executemany(sql, seq)

    def executescript(self, sql):
        return self._conn.executescript(sql)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if exc_type is None:
            self._conn.commit()


def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return _Sqlite3Connection(conn)


def ensure_column(db: sqlite3.Connection, table: str, column_def: str) -> None:
    column_name = column_def.split()[0]
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    existing_columns = {row[1] for row in rows}
    if column_name not in existing_columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")


def ensure_column_rename(db: sqlite3.Connection, table: str, old_name: str, new_name: str) -> None:
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    existing_columns = {row[1] for row in rows}
    if old_name in existing_columns and new_name not in existing_columns:
        db.execute(f"ALTER TABLE {table} RENAME COLUMN {old_name} TO {new_name}")


def _migrate_processed_articles_composite_key(db: sqlite3.Connection) -> None:
    """If processed_articles still has old single-column UNIQUE on article_id, migrate to composite key."""
    indexes = db.execute("PRAGMA index_list(processed_articles)").fetchall()
    for idx in indexes:
        if not idx["unique"]:
            continue
        cols = [row["name"] for row in db.execute(f"PRAGMA index_info('{idx['name']}')").fetchall()]
        if cols == ["article_id"]:
            # Old schema detected — recreate with composite unique
            db.execute(
                """
                CREATE TABLE processed_articles_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    article_id INTEGER NOT NULL,
                    simple_text TEXT NOT NULL,
                    english_translation TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    target_language TEXT NOT NULL DEFAULT 'Finnish',
                    target_level TEXT NOT NULL DEFAULT 'A2',
                    UNIQUE(article_id, target_language, target_level),
                    FOREIGN KEY(article_id) REFERENCES articles(id)
                )
                """
            )
            db.execute(
                """
                INSERT INTO processed_articles_new
                    (id, article_id, simple_text, english_translation, created_at, target_language, target_level)
                SELECT id, article_id, simple_text, english_translation, created_at,
                       COALESCE(target_language, 'Finnish'), COALESCE(target_level, 'A2')
                FROM processed_articles
                """
            )
            db.execute("DROP TABLE processed_articles")
            db.execute("ALTER TABLE processed_articles_new RENAME TO processed_articles")
            break


def init_db() -> None:
    with db_connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT NOT NULL UNIQUE,
                published TEXT,
                content TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS processed_articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                simple_text TEXT NOT NULL,
                english_translation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                target_language TEXT NOT NULL DEFAULT 'Finnish',
                target_level TEXT NOT NULL DEFAULT 'A2',
                llm_tokens INTEGER DEFAULT 0,
                processing_time REAL DEFAULT 0,
                UNIQUE(article_id, target_language, target_level),
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS llm_cache (
                article_id INTEGER NOT NULL,
                target_language TEXT NOT NULL,
                prompt_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                token_count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (article_id, target_language, prompt_hash),
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS processing_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                target_language TEXT NOT NULL,
                target_level TEXT NOT NULL,
                status TEXT NOT NULL,
                error_message TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS vocabulary_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                base_form TEXT NOT NULL,
                grammatical_form TEXT NOT NULL,
                english_translation TEXT NOT NULL,
                used_form TEXT NOT NULL,
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS grammar_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                sentence_index INTEGER NOT NULL,
                sentence_text TEXT NOT NULL,
                grammar_explanation TEXT NOT NULL,
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS auto_pick_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_language TEXT NOT NULL,
                target_level TEXT NOT NULL,
                per_source INTEGER NOT NULL,
                top_n INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS quality_control (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                article_id INTEGER NOT NULL,
                target_language TEXT NOT NULL,
                target_level TEXT NOT NULL,
                issue_type TEXT NOT NULL,
                issue_description TEXT NOT NULL,
                severity TEXT NOT NULL,
                resolved INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS auto_pick_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                article_id INTEGER NOT NULL,
                source_name TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                score REAL NOT NULL,
                processed_ok INTEGER NOT NULL,
                error TEXT,
                FOREIGN KEY(run_id) REFERENCES auto_pick_runs(id),
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS pipeline_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                run_type TEXT NOT NULL,
                run_id TEXT,
                stage TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                article_id INTEGER,
                target_language TEXT,
                target_level TEXT,
                provider TEXT,
                FOREIGN KEY(article_id) REFERENCES articles(id)
            );

            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                language     TEXT NOT NULL DEFAULT 'Finnish',
                level        TEXT NOT NULL DEFAULT 'A2',
                created_at   TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_article_reads (
                user_id    INTEGER NOT NULL REFERENCES users(id),
                article_id INTEGER NOT NULL REFERENCES articles(id),
                read_at    TEXT NOT NULL,
                PRIMARY KEY (user_id, article_id)
            );

            CREATE TABLE IF NOT EXISTS user_vocab_state (
                user_id       INTEGER NOT NULL REFERENCES users(id),
                vocab_item_id INTEGER NOT NULL REFERENCES vocabulary_items(id),
                saved         INTEGER NOT NULL DEFAULT 1,
                review_count  INTEGER NOT NULL DEFAULT 0,
                next_review_at TEXT,
                PRIMARY KEY (user_id, vocab_item_id)
            );

            CREATE TABLE IF NOT EXISTS newsletter_subscribers (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                email            TEXT NOT NULL UNIQUE,
                language         TEXT NOT NULL DEFAULT 'Finnish',
                level            TEXT,
                confirmed        INTEGER NOT NULL DEFAULT 0,
                confirm_token    TEXT UNIQUE,
                unsubscribe_token TEXT NOT NULL UNIQUE,
                created_at       TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS digest_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                sent_at    TEXT NOT NULL DEFAULT (datetime('now')),
                language   TEXT,
                dry_run    INTEGER NOT NULL DEFAULT 0,
                sent       INTEGER NOT NULL DEFAULT 0,
                skipped    INTEGER NOT NULL DEFAULT 0,
                failed     INTEGER NOT NULL DEFAULT 0,
                total      INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        _migrate_processed_articles_composite_key(db)
        ensure_column(db, "processed_articles", "target_language TEXT DEFAULT 'Finnish'")
        ensure_column(db, "processed_articles", "target_level TEXT DEFAULT 'A2'")
        ensure_column(db, "vocabulary_items", "used_form_translation TEXT DEFAULT ''")
        ensure_column(db, "vocabulary_items", "target_language TEXT DEFAULT 'Finnish'")
        ensure_column(db, "vocabulary_items", "target_level TEXT DEFAULT 'A2'")
        ensure_column(db, "grammar_items", "target_language TEXT DEFAULT 'Finnish'")
        ensure_column(db, "grammar_items", "target_level TEXT DEFAULT 'A2'")
        # New columns on existing tables.
        ensure_column(db, "articles", "is_read INTEGER DEFAULT 0")
        ensure_column(db, "articles", "read_at TEXT")
        ensure_column(db, "articles", "assigned_level TEXT DEFAULT 'A2'")
        ensure_column(db, "articles", "is_archived INTEGER DEFAULT 0")
        ensure_column(db, "articles", "topic TEXT")
        ensure_column(db, "vocabulary_items", "saved INTEGER DEFAULT 0")
        ensure_column(db, "vocabulary_items", "review_count INTEGER DEFAULT 0")
        ensure_column(db, "vocabulary_items", "next_review_at TEXT")
        # Migrate language-specific column names to language-agnostic ones.
        ensure_column_rename(db, "processed_articles", "simple_finnish", "simple_text")
        ensure_column_rename(db, "grammar_items", "sentence_finnish", "sentence_text")
        ensure_column_rename(db, "vocabulary_items", "finnish_word", "base_form")
        ensure_column_rename(db, "vocabulary_items", "finnish_explanation", "grammatical_form")
        ensure_column_rename(db, "vocabulary_items", "example_sentence", "used_form")
        ensure_column(db, "processed_articles", "llm_tokens INTEGER DEFAULT 0")
        ensure_column(db, "processed_articles", "processing_time REAL DEFAULT 0")
        ensure_column(db, "pipeline_events", "run_id TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_articles_source_name ON articles(source_name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_articles_published_created ON articles(published, created_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_articles_is_read ON articles(is_read)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_articles_topic ON articles(topic)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_processed_articles_article_created ON processed_articles(article_id, created_at, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_processed_articles_article_lang_level ON processed_articles(article_id, target_language, target_level)")
        db.commit()


def clear_database() -> None:
    tables = [
        "grammar_items", "vocabulary_items",
        "processed_articles", "articles", "auto_pick_items", "auto_pick_runs",
        "processing_log", "quality_control", "pipeline_events", "llm_cache",
    ]
    with db_connect() as db:
        for table in tables:
            try:
                db.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        db.commit()


def clear_language_data(target_language: str) -> Dict[str, int]:
    """Delete generated learning data for a specific language only.

    Keeps raw ingested articles intact.
    Returns per-table deletion counts.
    """
    result = {
        "processed_articles": 0,
        "vocabulary_items": 0,
        "grammar_items": 0,
        "quality_control": 0,
        "processing_log": 0,
        "llm_cache": 0,
        "user_vocab_state": 0,
    }

    with db_connect() as db:
        vocab_ids = db.execute(
            "SELECT id FROM vocabulary_items WHERE target_language = ?",
            (target_language,),
        ).fetchall()
        vocab_ids_list = [row[0] for row in vocab_ids]

        if vocab_ids_list:
            placeholders = ",".join("?" for _ in vocab_ids_list)
            cur = db.execute(
                f"DELETE FROM user_vocab_state WHERE vocab_item_id IN ({placeholders})",
                vocab_ids_list,
            )
            result["user_vocab_state"] = cur.rowcount or 0

        cur = db.execute(
            "DELETE FROM grammar_items WHERE target_language = ?",
            (target_language,),
        )
        result["grammar_items"] = cur.rowcount or 0

        cur = db.execute(
            "DELETE FROM vocabulary_items WHERE target_language = ?",
            (target_language,),
        )
        result["vocabulary_items"] = cur.rowcount or 0

        cur = db.execute(
            "DELETE FROM processed_articles WHERE target_language = ?",
            (target_language,),
        )
        result["processed_articles"] = cur.rowcount or 0

        for table in ["quality_control", "processing_log", "llm_cache"]:
            try:
                cur = db.execute(
                    f"DELETE FROM {table} WHERE target_language = ?",
                    (target_language,),
                )
                result[table] = cur.rowcount or 0
            except Exception:
                pass

        db.commit()

    return result


def ingest_from_rss(per_source: int = DEFAULT_AUTO_PER_SOURCE, run_id: Optional[str] = None) -> Dict[str, Any]:
    """Fast headline-only ingest: parses RSS and stores summary text, no full scraping.

    Full article content is fetched later only for articles that are actually selected.
    """
    inserted = 0
    skipped = 0
    errors: List[str] = []
    debug_logs: List[str] = []
    pending_events: List[Dict[str, str]] = [
        {
            "stage": "ingest",
            "message": f"RSS ingest started (per_source={per_source})",
            "level": "info",
            "run_type": "ingest",
        }
    ]
    active_run_id = run_id or f"ingest-{uuid.uuid4().hex[:8]}"

    with db_connect() as db:
        for source in TRUSTED_SOURCES:
            debug_logs.append(f"Processing source: {source['name']} - {source['rss']}")
            source_inserted = 0
            source_skipped = 0
            try:
                feed = feedparser.parse(source["rss"])
                debug_logs.append(f"Feed parsed for {source['name']}: status={feed.get('status', 'unknown')}, entries={len(feed.entries)}")
                
                if getattr(feed, "bozo", False):
                    error_msg = f"{source['name']}: failed to parse RSS feed (bozo={feed.bozo})"
                    errors.append(error_msg)
                    debug_logs.append(f"Bozo error: {feed.bozo_exception}")
                    pending_events.append(
                        {
                            "stage": "ingest",
                            "message": f"{source['name']}: feed parse failed ({feed.bozo_exception})",
                            "level": "error",
                            "run_type": "ingest",
                        }
                    )
                    continue

                entries = feed.entries[:per_source]
                if not entries:
                    errors.append(f"{source['name']}: no entries returned")
                    pending_events.append(
                        {
                            "stage": "ingest",
                            "message": f"{source['name']}: no entries returned",
                            "level": "warning",
                            "run_type": "ingest",
                        }
                    )
                    continue

                debug_logs.append(f"Found {len(entries)} entries for {source['name']}")
                
                for entry_idx, entry in enumerate(entries):
                    title = entry.get("title", "").strip()
                    url = entry.get("link", "").strip()
                    if not title or not url:
                        skipped += 1
                        source_skipped += 1
                        debug_logs.append(f"Skipped entry {entry_idx + 1}: missing title or url")
                        continue
                    if is_excluded_headline(title):
                        skipped += 1
                        source_skipped += 1
                        debug_logs.append(f"Skipped entry {entry_idx + 1}: excluded headline pattern")
                        continue

                    published_raw = entry.get("published", "") or entry.get("updated", "")
                    try:
                        published = email.utils.parsedate_to_datetime(published_raw).isoformat() if published_raw else ""
                    except Exception:
                        published = published_raw
                    summary = clean_html(entry.get("summary", ""))
                    body = ""
                    if entry.get("content") and isinstance(entry.get("content"), list):
                        first_content = entry["content"][0]
                        if isinstance(first_content, dict):
                            body = clean_html(first_content.get("value", ""))
                    content = body if len(body) > 120 else summary
                    
                    debug_logs.append(f"Processing entry {entry_idx + 1}: {title[:50]}...")
                    
                    try:
                        cursor = db.execute(
                            """
                            INSERT OR IGNORE INTO articles
                            (source_name, title, url, published, content, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (source["name"], title, url, published, content, now_iso()),
                        )
                        if cursor.rowcount == 1:
                            inserted += 1
                            source_inserted += 1
                            debug_logs.append(f"Inserted: {title[:50]}...")
                        else:
                            skipped += 1
                            source_skipped += 1
                            debug_logs.append(f"Skipped (duplicate): {title[:50]}...")
                    except Exception as exc:
                        errors.append(f"{source['name']}: {exc}")
                        debug_logs.append(f"Error inserting entry: {exc}")
                        pending_events.append(
                            {
                                "stage": "ingest",
                                "message": f"{source['name']}: insert error ({exc})",
                                "level": "error",
                                "run_type": "ingest",
                            }
                        )

            except Exception as source_exc:
                errors.append(f"{source['name']}: unexpected error - {str(source_exc)}")
                debug_logs.append(f"Source error: {str(source_exc)}")
                pending_events.append(
                    {
                        "stage": "ingest",
                        "message": f"{source['name']}: unexpected error ({source_exc})",
                        "level": "error",
                        "run_type": "ingest",
                    }
                )
                continue

            pending_events.append(
                {
                    "stage": "ingest",
                    "message": f"{source['name']}: inserted={source_inserted}, skipped={source_skipped}",
                    "level": "info",
                    "run_type": "ingest",
                }
            )

        db.commit()

    pending_events.append(
        {
            "stage": "ingest",
            "message": f"RSS ingest finished: inserted={inserted}, skipped={skipped}, errors={len(errors)}",
            "level": "warning" if errors else "info",
            "run_type": "ingest",
        }
    )
    for event in pending_events:
        _log_pipeline_event(
            stage=event["stage"],
            message=event["message"],
            level=event["level"],
            run_type=event["run_type"],
            run_id=active_run_id,
        )

    return {"inserted": inserted, "skipped": skipped, "errors": errors, "debug_logs": debug_logs}


def _enrich_article_content(article: Dict[str, Any]) -> Dict[str, Any]:
    """Full-scrape a single article if its stored content is thin. Returns updated dict."""
    content = (article.get("content") or "").strip()
    if len(content) < FULL_FETCH_THRESHOLD and article.get("url"):
        fetched = fetch_full_content(article["url"])
        if len(fetched) > len(content):
            content = fetched
            with db_connect() as db:
                db.execute(
                    "UPDATE articles SET content = ? WHERE id = ?",
                    (content, article["id"]),
                )
                db.commit()
            article = dict(article)
            article["content"] = content
    return article


def enrich_selected_articles(articles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parallel full-scrape for a small list of selected articles."""
    if not articles:
        return articles
    with ThreadPoolExecutor(max_workers=min(len(articles), 8)) as pool:
        futures = {pool.submit(_enrich_article_content, a): i for i, a in enumerate(articles)}
        enriched = [None] * len(articles)
        for future in as_completed(futures):
            enriched[futures[future]] = future.result()
    return [a for a in enriched if a is not None]


def simple_fallback_transform(text: str, target_language: str, target_level: str) -> Dict[str, Any]:
    short_text = text[:600]
    simple_text = (
        f"This is demo text for {target_level} {target_language}.\n"
        "Add MISTRAL_API_KEY or DEEPSEEK_API_KEY to your environment.\n"
        f"Then you get real simplified {target_language} output.\n"
        "[Demo mode — no real output without an API key.]"
    )
    english_text = (
        "This is demo text.\n"
        "Add MISTRAL_API_KEY or DEEPSEEK_API_KEY to your environment.\n"
        f"Then you get real {target_level} {target_language} output.\n"
        "Right now the app is in demo mode."
    )
    return {
        "simple_text": simple_text,
        "english_translation": english_text,
        "keywords": [
            {
                "base_form": "news",
                "translation": "news",
                "used_form": "news",
                "used_form_translation": "news",
                "grammatical_form": "noun",
            },
            {
                "base_form": "source",
                "translation": "source",
                "used_form": "source",
                "used_form_translation": "source",
                "grammatical_form": "noun",
            },
        ],
        "grammar_notes": [
            {
                "sentence_index": 1,
                "sentence_text": f"This is demo text for {target_level} {target_language}.",
                "grammar_explanation": (
                    "Demo mode: add MISTRAL_API_KEY or DEEPSEEK_API_KEY to get real grammar explanations "
                    f"for {target_language} at {target_level} level."
                ),
            },
        ],
        "source_excerpt": short_text,
    }


def _call_llm_api(provider: str, prompt: str, system_prompt: str) -> Dict[str, Any]:
    """Call LLM API (Mistral, DeepSeek, Claude, or OpenAI) with given prompts.
    
    Returns {'content': str, 'tokens': int} on success, or {'error': str} on failure.
    """
    if provider == "mistral":
        api_key = os.getenv("MISTRAL_API_KEY")
        if not api_key:
            return {"error": "No MISTRAL_API_KEY set"}
        api_url = os.getenv("MISTRAL_API_URL", "https://api.mistral.ai/v1/chat/completions")
        model = MISTRAL_MODEL
        use_anthropic = False
    elif provider == "deepseek":
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            return {"error": "No DEEPSEEK_API_KEY set"}
        api_url = "https://api.deepseek.com/chat/completions"
        model = DEEPSEEK_MODEL
        use_anthropic = False
    elif provider == "claude":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            return {"error": "No ANTHROPIC_API_KEY set"}
        api_url = "https://api.anthropic.com/v1/messages"
        model = CLAUDE_MODEL
        use_anthropic = True
    elif provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return {"error": "No OPENAI_API_KEY set"}
        api_url = "https://api.openai.com/v1/chat/completions"
        model = OPENAI_MODEL
        use_anthropic = False
    else:
        return {"error": f"Unknown LLM provider: {provider}"}

    try:
        if use_anthropic:
            # Claude/Anthropic API format
            response = requests.post(
                api_url,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 8192,
                    "messages": [
                        {"role": "user", "content": prompt},
                    ],
                    "system": system_prompt,
                },
                timeout=120,
            )
        else:
            # OpenAI-compatible format (Mistral, DeepSeek, OpenAI)
            request_body = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt},
                ],
            }
            # Only set temperature for Mistral/DeepSeek; OpenAI doesn't support it
            if provider in ["mistral", "deepseek"]:
                request_body["temperature"] = 0.2
            
            response = requests.post(
                api_url,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json=request_body,
                timeout=120,
            )
    except requests.RequestException as exc:
        return {"error": f"Could not reach {provider.upper()} API: {exc}"}

    if response.status_code >= 400:
        return {"error": f"{provider.upper()} API error {response.status_code}: {response.text[:240]}"}

    try:
        payload = response.json()
        if use_anthropic:
            content = payload["content"][0]["text"]
            token_count = payload.get("usage", {}).get("input_tokens", 0) + payload.get("usage", {}).get("output_tokens", 0)
        else:
            content = payload["choices"][0]["message"]["content"]
            token_count = payload.get("usage", {}).get("total_tokens", 0)
        return {"content": content, "tokens": token_count}
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as e:
        return {"error": f"{provider.upper()} API response parsing failed: {e}"}




def generate_learning_content(
    article_text: str,
    title: str,
    target_language: str,
    target_level: str,
    article_id: Optional[int] = None,
    provider: Optional[str] = None,
    review_provider: Optional[str] = None,
) -> Dict[str, Any]:
    if provider is None:
        provider = LLM_PROVIDER
    if review_provider is None:
        review_provider = REVIEW_LLM_PROVIDER

    # Check we have a key for the active provider
    key_map = {
        "mistral": "MISTRAL_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
    }
    if not os.getenv(key_map.get(provider, "")):
        return simple_fallback_transform(f"{title}\n\n{article_text}", target_language, target_level)

    # Check cache
    if article_id:
        prompt_hash = _hash_prompt(title, article_text, target_language, [target_level])
        cached = _get_cached_response(article_id, target_language, prompt_hash)
        if cached:
            try:
                return json.loads(cached["response"])
            except (json.JSONDecodeError, KeyError):
                pass

    language_chars = {
        "Finnish": "ä, ö, å",
        "German": "ä, ö, ü, ß",
        "Swedish": "ä, ö, å",
        "Danish": "æ, ø, å",
    }
    char_note = language_chars.get(target_language, "")
    char_instruction = (
        f"- Always use correct {target_language} characters ({char_note}) where needed.\n"
        if char_note
        else ""
    )

    # --- Step 1: Simplify + translate (primary LLM, e.g. Mistral) ---
    step1_prompt = f"""You are a language-learning assistant.

Task:
1) Rewrite the news content in VERY SIMPLE {target_language} ({target_level} CEFR level), maximum 12 sentences.
2) Translate each sentence into natural English.

CEFR Level Guidelines for {target_level}:
- A1: Max 7 words per sentence. Present tense and simple past only. No subordinate clauses. Basic subject-verb-object structure.
- A2: Max 10 words per sentence. One subordinate clause allowed (e.g. "että", "because"). Common past and future tenses permitted.
- B1: Max 15 words per sentence. Compound sentences allowed. Passive voice permitted. Wider range of tenses.

Rules:
- Sentence 1 MUST be a one-sentence summary lede: the single most important fact of the story, written as a punchy newspaper opener.
- Keep facts accurate to the source. Do not invent new facts.
{char_instruction}- Use grammatical complexity appropriate to {target_level} (see guidelines above).
- Topic-specific vocabulary (names, places, events) may exceed typical {target_level} frequency — this is expected and acceptable.
- Avoid grammar structures beyond the {target_level} guidelines.
- Sentences should gradually increase in complexity: sentences 1–3 simplest, 10–12 slightly more complex but still within level.

Return ONLY valid JSON where simple_text and english_translation are arrays of strings (one string per sentence):
{{
  "simple_text": ["sentence 1", "sentence 2", "..."],
  "english_translation": ["sentence 1", "sentence 2", "..."]
}}

Title: {title}
Content: {article_text}
"""

    step1_system = (
        f"You are precise, factual, and write beginner-friendly {target_language}. "
        "Return only valid JSON."
    )
    step1_result = _call_llm_api(provider, step1_prompt, step1_system)
    if "error" in step1_result:
        return step1_result

    try:
        step1_parsed = parse_json_object(step1_result["content"])
    except (TypeError, json.JSONDecodeError):
        return {"error": "Step 1: LLM returned a response, but JSON parsing failed."}

    step1_simple = step1_parsed.get("simple_text", [])
    step1_english = step1_parsed.get("english_translation", [])
    # Normalise: some models may return a string instead of an array
    if isinstance(step1_simple, str):
        step1_simple = [s.strip() for s in step1_simple.splitlines() if s.strip()]
    if isinstance(step1_english, str):
        step1_english = [s.strip() for s in step1_english.splitlines() if s.strip()]

    # --- Step 2: Review, fix, keywords, grammar notes (review LLM, e.g. Claude) ---
    step2_prompt = f"""You are a {target_language} language expert reviewing text written for language learners at {target_level} CEFR level.

You will receive numbered {target_language} sentences (0-indexed) and their English translations.

Fix any: grammar errors, wrong case endings{f', vowel harmony mistakes' if target_language == 'Finnish' else ''}, unnatural phrasing, complexity exceeding {target_level}.
Topic vocabulary being advanced is intentional — do not simplify it.

{target_language} sentences (0-indexed):
{json.dumps(list(enumerate(step1_simple)), ensure_ascii=False)}

English translations (0-indexed):
{json.dumps(list(enumerate(step1_english)), ensure_ascii=False)}

Return JSON only. For corrections, include ONLY sentences that need changes — omit correct sentences entirely. If nothing needs fixing, return an empty array.
Also extract 6 key vocabulary words and add grammar notes (max 2, empty array if none noteworthy).

{{
  "corrections": [
    {{"index": 0, "corrected_text": "...", "corrected_english": "..."}}
  ],
  "keywords": [
    {{
      "base_form": "...",
      "translation": "...",
      "used_form": "...",
      "used_form_translation": "...",
      "grammatical_form": "..."
    }}
  ],
  "grammar_notes": [
    {{
      "sentence_index": 0,
      "sentence_text": "...",
      "grammar_explanation": "..."
    }}
  ]
}}
"""

    step2_system = (
        f"You are a {target_language} language expert and pedagogy specialist. "
        "Grammar explanations must be in English. Return only valid JSON."
    )
    step2_result = _call_llm_api(review_provider, step2_prompt, step2_system)
    if "error" in step2_result:
        return step2_result

    try:
        step2_parsed = parse_json_object(step2_result["content"])
    except (TypeError, json.JSONDecodeError):
        return {"error": "Step 2: LLM returned a response, but JSON parsing failed."}

    # Apply corrections patch to step 1 sentences
    corrected_simple = list(step1_simple)
    corrected_english = list(step1_english)
    for correction in step2_parsed.get("corrections", []):
        idx = correction.get("index", -1)
        if isinstance(idx, int) and 0 <= idx < len(corrected_simple):
            if "corrected_text" in correction:
                corrected_simple[idx] = correction["corrected_text"]
            if "corrected_english" in correction:
                corrected_english[idx] = correction["corrected_english"]

    parsed = {
        "simple_text": "\n".join(corrected_simple),
        "english_translation": "\n".join(corrected_english),
        "keywords": step2_parsed.get("keywords", []),
        "grammar_notes": step2_parsed.get("grammar_notes", []),
    }

    if article_id:
        total_tokens = step1_result.get("tokens", 0) + step2_result.get("tokens", 0)
        _cache_llm_response(article_id, target_language, prompt_hash, json.dumps(parsed), total_tokens)

    return parsed


def generate_learning_content_all_levels(
    article_text: str,
    title: str,
    target_language: str,
    levels: List[str],
    article_id: Optional[int] = None,
    provider: Optional[str] = None,
    review_provider: Optional[str] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Two-step pipeline per article: step 1 (provider) simplifies and translates;
    step 2 (review_provider) reviews/fixes and generates keywords and grammar notes.

    Returns {level: content_dict} on success, or {"error": "..."} on failure.
    Falls back to demo content when no API key is set.
    """
    if provider is None:
        provider = LLM_PROVIDER
    if review_provider is None:
        review_provider = REVIEW_LLM_PROVIDER

    # Check if we have API keys
    has_mistral = bool(os.getenv("MISTRAL_API_KEY"))
    has_deepseek = bool(os.getenv("DEEPSEEK_API_KEY"))
    
    if not has_mistral and not has_deepseek:
        return {
            lvl: simple_fallback_transform(f"{title}\n\n{article_text}", target_language, lvl)
            for lvl in levels
        }

    # Check cache if article_id is provided
    if article_id:
        prompt_hash = _hash_prompt(title, article_text, target_language, levels)
        cached = _get_cached_response(article_id, target_language, prompt_hash)
        if cached:
            try:
                result = json.loads(cached["response"])
                _log_pipeline_event(
                    stage="process",
                    message=f"Article {article_id} ({target_language}) served from cache — skipping step1+step2",
                    run_type="pipeline",
                    run_id=run_id,
                    article_id=article_id,
                    target_language=target_language,
                )
                return result
            except (json.JSONDecodeError, KeyError):
                pass  # Fall through to generate fresh

    language_chars = {
        "Finnish": "ä, ö, å",
        "German": "ä, ö, ü, ß",
        "Swedish": "ä, ö, å",
        "Danish": "æ, ø, å",
    }
    char_note = language_chars.get(target_language, "")
    char_instruction = (
        f"- Always use correct {target_language} characters ({char_note}) where needed.\n"
        if char_note
        else ""
    )

    levels_str = ", ".join(levels)

    # --- Step 1: Simplify + translate (primary LLM, e.g. Mistral) ---
    step1_level_shape = '{"simple_text": ["sentence 1", "sentence 2", "..."], "english_translation": ["sentence 1", "sentence 2", "..."]}'
    step1_json_shape = ",\n  ".join(f'"{lvl}": {step1_level_shape}' for lvl in levels)

    step1_prompt = f"""You are a language-learning assistant.

Task:
Generate simplified {target_language} versions of this news article at {len(levels)} CEFR levels: {levels_str}.

For EACH level:
1) Rewrite in simple {target_language} at that CEFR level, maximum 12 sentences.
2) Translate each sentence into natural English.

CEFR Level Guidelines:
- A1: Max 7 words per sentence. Present tense and simple past only. No subordinate clauses. Basic subject-verb-object structure.
- A2: Max 10 words per sentence. One subordinate clause allowed (e.g. "että", "because"). Common past and future tenses permitted.
- B1: Max 15 words per sentence. Compound sentences allowed. Passive voice permitted. Wider range of tenses.

Rules:
- Sentence 1 MUST be a one-sentence summary lede: the single most important fact of the story, written as a punchy newspaper opener.
- Keep facts accurate to the source. Do not invent new facts.
{char_instruction}- Use grammatical complexity appropriate to each CEFR level (see guidelines above).
- Topic-specific vocabulary (names, places, events) may exceed typical level frequency — this is expected and acceptable.
- Sentences should gradually increase in complexity: sentences 1–3 simplest, 10–12 slightly more complex but still within level.

Return ONLY valid JSON where simple_text and english_translation are arrays of strings (one string per sentence):
{{
  {step1_json_shape}
}}

Title: {title}
Content: {article_text}
"""

    step1_system = (
        f"You are precise, factual, and write beginner-friendly {target_language}. "
        "Return only valid JSON."
    )

    step1_result = _call_llm_api(provider, step1_prompt, step1_system)
    if "error" in step1_result:
        return step1_result

    try:
        step1_parsed = parse_json_object(step1_result["content"])
    except (TypeError, json.JSONDecodeError) as e:
        return {"error": f"Step 1 JSON parsing failed: {e}"}

    for lvl in levels:
        if lvl not in step1_parsed:
            return {"error": f"Step 1 response missing level '{lvl}'."}
        # Normalise: some models may return a string instead of an array
        for key in ("simple_text", "english_translation"):
            val = step1_parsed[lvl].get(key, [])
            if isinstance(val, str):
                step1_parsed[lvl][key] = [s.strip() for s in val.splitlines() if s.strip()]

    _log_pipeline_event(
        stage="process",
        message=f"Article {article_id} ({target_language}) step1 done ({provider}) — {step1_result.get('tokens', 0)} tokens",
        run_type="pipeline",
        run_id=run_id,
        article_id=article_id,
        target_language=target_language,
        provider=provider,
    )

    # --- Step 2: Review, fix, keywords, grammar notes (review LLM, e.g. Claude) ---
    level_texts = "\n\n".join(
        f"Level {lvl} (0-indexed):\n"
        f"{target_language}: {json.dumps(list(enumerate(step1_parsed[lvl].get('simple_text', []))), ensure_ascii=False)}\n"
        f"English: {json.dumps(list(enumerate(step1_parsed[lvl].get('english_translation', []))), ensure_ascii=False)}"
        for lvl in levels
    )

    step2_level_shape = (
        '{"confirmed_level": "A1", '
        '"corrections": [{"index": 0, "corrected_text": "...", "corrected_english": "..."}], '
        '"keywords": [{"base_form": "...", "translation": "...", "used_form": "...", '
        '"used_form_translation": "...", "grammatical_form": "..."}], '
        '"grammar_notes": [{"sentence_index": 0, "sentence_text": "...", "grammar_explanation": "..."}]}'
    )
    step2_json_shape = ",\n  ".join(f'"{lvl}": {step2_level_shape}' for lvl in levels)

    step2_prompt = f"""You are a {target_language} language expert reviewing text written for language learners at multiple CEFR levels: {levels_str}.

Fix any: grammar errors, wrong case endings{f', vowel harmony mistakes' if target_language == 'Finnish' else ''}, unnatural phrasing, complexity exceeding the level.
Topic vocabulary being advanced is intentional — do not simplify it.

{level_texts}

For EACH level return:
- confirmed_level: the CEFR level (one of: {levels_str}) that this text actually reads as after your review. Usually matches the intended level; use your judgement if it clearly does not.
- corrections: ONLY sentences that need changes (omit correct sentences — empty array if all OK)
- keywords: 6 key vocabulary words from the (corrected) {target_language} sentences. Prioritize verbs, case-inflected nouns, news-context words. Include base_form, translation, used_form, used_form_translation, grammatical_form.
- grammar_notes: max 2 pedagogical notes for language learners — highlight interesting grammar structures in the text (e.g. a case usage, verb form, sentence pattern). Do NOT describe corrections you made. Empty array if nothing noteworthy. Explanations in English.

Return JSON only:
{{
  {step2_json_shape}
}}
"""

    step2_system = (
        f"You are a {target_language} language expert and pedagogy specialist. "
        "Grammar explanations must be in English. Return only valid JSON."
    )

    step2_result = _call_llm_api(review_provider, step2_prompt, step2_system)
    if "error" in step2_result:
        return step2_result

    try:
        step2_parsed = parse_json_object(step2_result["content"])
    except (TypeError, json.JSONDecodeError) as e:
        return {"error": f"Step 2 JSON parsing failed: {e}"}

    parsed = {}
    for lvl in levels:
        if lvl not in step2_parsed:
            return {"error": f"Step 2 response missing level '{lvl}'."}
        lvl_step2 = step2_parsed[lvl]

        # Apply corrections patch to step 1 sentences
        corrected_simple = list(step1_parsed[lvl].get("simple_text", []))
        corrected_english = list(step1_parsed[lvl].get("english_translation", []))
        for correction in lvl_step2.get("corrections", []):
            idx = correction.get("index", -1)
            if isinstance(idx, int) and 0 <= idx < len(corrected_simple):
                if "corrected_text" in correction:
                    corrected_simple[idx] = correction["corrected_text"]
                if "corrected_english" in correction:
                    corrected_english[idx] = correction["corrected_english"]

        confirmed_level = to_text(lvl_step2.get("confirmed_level", "")).upper().strip()
        if confirmed_level not in CEFR_LEVELS:
            confirmed_level = lvl  # fall back to intended level if Claude returns garbage

        parsed[lvl] = {
            "simple_text": "\n".join(corrected_simple),
            "english_translation": "\n".join(corrected_english),
            "keywords": lvl_step2.get("keywords", []),
            "grammar_notes": lvl_step2.get("grammar_notes", []),
            "confirmed_level": confirmed_level,
        }

    _log_pipeline_event(
        stage="process",
        message=f"Article {article_id} ({target_language}) step2 done ({review_provider}) — {step2_result.get('tokens', 0)} tokens, {sum(len(parsed[lvl].get('keywords', [])) for lvl in levels)} keywords",
        run_type="pipeline",
        run_id=run_id,
        article_id=article_id,
        target_language=target_language,
        provider=review_provider,
    )

    if article_id:
        total_tokens = step1_result.get("tokens", 0) + step2_result.get("tokens", 0)
        _cache_llm_response(article_id, target_language, prompt_hash, json.dumps(parsed), total_tokens)

    return parsed


def detect_article_difficulty(
    article_text: str,
    title: str,
    target_language: str,
    provider: Optional[str] = None,
) -> str:
    """Use LLM to determine if article should be A1, A2, or B1 level.
    
    Returns 'A1', 'A2', or 'B1'. Defaults to 'A2' on error or no API key.
    """
    if provider is None:
        provider = LLM_PROVIDER
    
    def _heuristic_level(text: str, heading: str) -> str:
        combined = f"{heading}\n{text}".strip()
        text_len = len(combined)
        if text_len < 900:
            return "A1"
        if text_len > 4000:
            return "B1"

        lower = combined.lower()
        b1_keywords = [
            "government", "parliament", "president", "policy", "budget", "inflation",
            "economy", "election", "investigation", "military", "conflict", "strategy",
            "regjering", "riksdag", "eduskunta", "talous", "vaalit", "sota",
        ]
        a1_keywords = [
            "weather", "sport", "goal", "match", "music", "festival", "school",
            "family", "weekend", "dog", "cat", "food", "snow", "rain", "sun",
        ]
        b1_score = sum(1 for kw in b1_keywords if kw in lower)
        a1_score = sum(1 for kw in a1_keywords if kw in lower)
        if b1_score >= 2:
            return "B1"
        if a1_score >= 2:
            return "A1"
        return "A2"

    # Require minimum content length for meaningful LLM classification
    if len(article_text) < 500:
        return _heuristic_level(article_text, title)
    
    # Check if we have API credentials
    has_api = False
    if provider == "mistral" and os.getenv("MISTRAL_API_KEY"):
        has_api = True
    elif provider == "deepseek" and os.getenv("DEEPSEEK_API_KEY"):
        has_api = True
    elif provider == "claude" and os.getenv("ANTHROPIC_API_KEY"):
        has_api = True
    elif provider == "openai" and os.getenv("OPENAI_API_KEY"):
        has_api = True
    
    if not has_api:
        return _heuristic_level(article_text, title)
    
    prompt = f"""Classify this news article's difficulty for {target_language} learners.

CEFR Guidelines:
- A1: very simple everyday topics and language
- A2: standard general-news difficulty
- B1: clearly abstract/technical topics with denser language

Return strictly as JSON: {{"level":"A1"}} or {{"level":"A2"}} or {{"level":"B1"}}.

Title: {title}
Content: {article_text[:2000]}

JSON:"""

    system_prompt = f"You are a {target_language} language pedagogy expert. Return only valid JSON with one key: level."
    
    api_result = _call_llm_api(provider, prompt, system_prompt)
    if "error" in api_result:
        return _heuristic_level(article_text, title)

    content = (api_result.get("content", "") or "").strip()

    try:
        parsed = json.loads(content)
        level = str(parsed.get("level", "")).upper().strip()
        if level in {"A1", "A2", "B1"}:
            return level
    except Exception:
        pass

    direct = content.upper().strip()
    if direct in {"A1", "A2", "B1"}:
        return direct

    match = re.search(r"\b(A1|A2|B1)\b", direct)
    if match:
        matched = match.group(1)
        return matched

    return _heuristic_level(article_text, title)


def list_articles(
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
    user_id: Optional[int] = None,
    published_after: Optional[str] = None,
    published_before: Optional[str] = None,
    topic: Optional[str] = None,
    runs_per_page: int = 4,
    run_offset: int = 0,
) -> List[Dict[str, Any]]:
    # Build optional date filter for reader queries
    # Filter by a.created_at (ingestion time) so RSS articles with old publish dates
    # still appear if they were ingested today, while truly old articles are excluded.
    date_filter = ""
    date_params: List[Any] = []

    # Run-based filtering: show articles from the last N pipeline runs, offset by run_offset.
    # Runs may be stored with NULL target_language (multi-language runs), so don't filter by language here.
    if target_language and runs_per_page > 0:
        with db_connect() as _db:
            run_rows = _db.execute(
                """
                SELECT id FROM auto_pick_runs
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (runs_per_page, run_offset),
            ).fetchall()
        if run_rows:
            run_ids = [r["id"] for r in run_rows]
            placeholders = ",".join("?" * len(run_ids))
            date_filter += f" AND a.id IN (SELECT article_id FROM auto_pick_items WHERE run_id IN ({placeholders}))"
            date_params.extend(run_ids)
        else:
            # No runs recorded yet — paginate by processed_at ordering
            limit = runs_per_page * 4
            sql_offset = run_offset * 4
            date_filter += f" AND a.id IN (SELECT article_id FROM processed_articles ORDER BY created_at DESC LIMIT {limit} OFFSET {sql_offset})"
    elif published_after:
        date_filter += " AND a.created_at >= ?"
        date_params.append(published_after)
    elif published_before:
        date_filter += " AND a.created_at < ?"
        date_params.append(published_before)

    headline_filter = " AND LOWER(a.title) NOT LIKE '%briefing%' AND (a.is_archived IS NULL OR a.is_archived = 0)"
    if topic:
        headline_filter += " AND a.topic = ?"
        date_params.append(topic)

    with db_connect() as db:
        if target_language and target_level:
            if user_id is not None:
                rows = db.execute(
                    f"""
                    SELECT
                        a.id,
                        a.source_name,
                        a.title,
                        a.url,
                        a.published,
                        a.created_at,
                        CASE WHEN uar.article_id IS NOT NULL THEN 1 ELSE 0 END AS is_read,
                        a.assigned_level,
                        a.topic,
                        p.target_language,
                        p.target_level,
                        p.created_at AS processed_at,
                        1 AS is_processed
                    FROM articles a
                    JOIN processed_articles p ON p.article_id = a.id
                    LEFT JOIN user_article_reads uar ON uar.article_id = a.id AND uar.user_id = ?
                    WHERE p.target_language = ?
                      AND a.assigned_level = ?
                      {date_filter}
                      {headline_filter}
                    ORDER BY COALESCE(a.published, a.created_at) DESC,
                             a.id DESC
                    LIMIT 200
                    """,
                    (user_id, target_language, target_level, *date_params),
                ).fetchall()
            else:
                rows = db.execute(
                    f"""
                    SELECT
                        a.id,
                        a.source_name,
                        a.title,
                        a.url,
                        a.published,
                        a.created_at,
                        a.is_read,
                        a.assigned_level,
                        a.topic,
                        p.target_language,
                        p.target_level,
                        p.created_at AS processed_at,
                        1 AS is_processed
                    FROM articles a
                    JOIN processed_articles p ON p.article_id = a.id
                    WHERE p.target_language = ?
                      AND a.assigned_level = ?
                      {date_filter}
                      {headline_filter}
                    ORDER BY COALESCE(a.published, a.created_at) DESC,
                             a.id DESC
                    LIMIT 200
                    """,
                    (target_language, target_level, *date_params),
                ).fetchall()
        elif target_language:
            if user_id is not None:
                rows = db.execute(
                    f"""
                    SELECT
                        a.id,
                        a.source_name,
                        a.title,
                        a.url,
                        a.published,
                        a.created_at,
                        CASE WHEN uar.article_id IS NOT NULL THEN 1 ELSE 0 END AS is_read,
                        a.assigned_level,
                        a.topic,
                        p.target_language,
                        p.target_level,
                        p.created_at AS processed_at,
                        1 AS is_processed
                    FROM articles a
                    JOIN processed_articles p ON p.article_id = a.id
                    LEFT JOIN user_article_reads uar ON uar.article_id = a.id AND uar.user_id = ?
                    WHERE p.target_language = ?
                      AND p.target_level = a.assigned_level
                      {date_filter}
                      {headline_filter}
                    ORDER BY COALESCE(a.published, a.created_at) DESC,
                             a.id DESC
                    LIMIT 200
                    """,
                    (user_id, target_language, *date_params),
                ).fetchall()
            else:
                rows = db.execute(
                    f"""
                    SELECT
                        a.id,
                        a.source_name,
                        a.title,
                        a.url,
                        a.published,
                        a.created_at,
                        a.is_read,
                        a.assigned_level,
                        a.topic,
                        p.target_language,
                        p.target_level,
                        p.created_at AS processed_at,
                        1 AS is_processed
                    FROM articles a
                    JOIN processed_articles p ON p.article_id = a.id
                    WHERE p.target_language = ?
                      AND p.target_level = a.assigned_level
                      {date_filter}
                      {headline_filter}
                    ORDER BY COALESCE(a.published, a.created_at) DESC,
                             a.id DESC
                    LIMIT 200
                    """,
                    (target_language, *date_params),
                ).fetchall()
        else:
            # Admin view: one row per article, aggregated processed state (always global is_read)
            rows = db.execute(
                """
                SELECT
                    a.id,
                    a.source_name,
                    a.title,
                    a.url,
                    a.published,
                    a.created_at,
                    a.is_read,
                    a.assigned_level,
                    CASE WHEN COUNT(p.id) > 0 THEN 1 ELSE 0 END AS is_processed,
                    GROUP_CONCAT(p.target_language || ' ' || p.target_level, ' · ') AS processed_combos,
                    (
                        SELECT p2.target_language
                        FROM processed_articles p2
                        WHERE p2.article_id = a.id
                        ORDER BY p2.created_at DESC, p2.id DESC
                        LIMIT 1
                    ) AS latest_target_language,
                    (
                        SELECT p2.target_level
                        FROM processed_articles p2
                        WHERE p2.article_id = a.id
                        ORDER BY p2.created_at DESC, p2.id DESC
                        LIMIT 1
                    ) AS latest_target_level
                FROM articles a
                LEFT JOIN processed_articles p ON p.article_id = a.id
                GROUP BY a.id
                ORDER BY COALESCE(a.published, a.created_at) DESC, a.id DESC
                """
            ).fetchall()

    return [dict(row) for row in rows]


def archive_old_articles(older_than_days: int = 7) -> int:
    """Move all processed articles older than N days to the archive. Returns count archived."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    with db_connect() as db:
        cur = db.execute(
            """
            UPDATE articles SET is_archived = 1
            WHERE is_archived = 0
              AND created_at < ?
              AND id IN (SELECT DISTINCT article_id FROM processed_articles)
            """,
            (cutoff,),
        )
        db.commit()
    return cur.rowcount


def list_archived_articles(
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
    user_id: Optional[int] = None,
    topic: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return archived articles for the given language/level, newest first."""
    topic_filter = " AND a.topic = ?" if topic else ""
    with db_connect() as db:
        if user_id is not None:
            params = [user_id, target_language, target_level]
            if topic:
                params.append(topic)
            rows = db.execute(
                f"""
                SELECT
                    a.id, a.source_name, a.title, a.url, a.published, a.created_at,
                    CASE WHEN uar.article_id IS NOT NULL THEN 1 ELSE 0 END AS is_read,
                    a.assigned_level, a.topic,
                    p.target_language, p.target_level,
                    p.created_at AS processed_at,
                    1 AS is_processed
                FROM articles a
                JOIN processed_articles p ON p.article_id = a.id
                LEFT JOIN user_article_reads uar ON uar.article_id = a.id AND uar.user_id = ?
                WHERE a.is_archived = 1
                  AND p.target_language = ?
                  AND p.target_level = COALESCE(?, a.assigned_level)
                  AND p.target_level = a.assigned_level
                  {topic_filter}
                ORDER BY COALESCE(a.published, a.created_at) DESC, a.id DESC
                LIMIT 500
                """,
                params,
            ).fetchall()
        else:
            params = [target_language, target_level]
            if topic:
                params.append(topic)
            rows = db.execute(
                f"""
                SELECT
                    a.id, a.source_name, a.title, a.url, a.published, a.created_at,
                    a.is_read, a.assigned_level, a.topic,
                    p.target_language, p.target_level,
                    p.created_at AS processed_at,
                    1 AS is_processed
                FROM articles a
                JOIN processed_articles p ON p.article_id = a.id
                WHERE a.is_archived = 1
                  AND p.target_language = ?
                  AND p.target_level = COALESCE(?, a.assigned_level)
                  AND p.target_level = a.assigned_level
                  {topic_filter}
                ORDER BY COALESCE(a.published, a.created_at) DESC, a.id DESC
                LIMIT 500
                """,
                params,
            ).fetchall()
    return [dict(row) for row in rows]


def get_admin_articles_page(
    page: int = 1,
    per_page: int = 50,
    source: str = "",
    status: str = "",
    lang_filter: str = "",
    level_filter: str = "",
) -> Dict[str, Any]:
    page = max(1, to_int(page, default=1))
    per_page = max(1, min(to_int(per_page, default=50), 200))
    offset = (page - 1) * per_page

    where_clauses: List[str] = []
    params: List[Any] = []

    if source:
        where_clauses.append("a.source_name = ?")
        params.append(source)

    if status == "processed":
        where_clauses.append("EXISTS (SELECT 1 FROM processed_articles p WHERE p.article_id = a.id)")
    elif status == "unprocessed":
        where_clauses.append("NOT EXISTS (SELECT 1 FROM processed_articles p WHERE p.article_id = a.id)")
    elif status == "read":
        where_clauses.append("COALESCE(a.is_read, 0) = 1")
    elif status == "unread":
        where_clauses.append("COALESCE(a.is_read, 0) = 0")

    if lang_filter in LEARNING_LANGUAGES:
        where_clauses.append(
            "COALESCE((SELECT p2.target_language FROM processed_articles p2 WHERE p2.article_id = a.id ORDER BY p2.created_at DESC, p2.id DESC LIMIT 1), '') = ?"
        )
        params.append(lang_filter)

    if level_filter in CEFR_LEVELS:
        where_clauses.append(
            "COALESCE((SELECT p2.target_level FROM processed_articles p2 WHERE p2.article_id = a.id ORDER BY p2.created_at DESC, p2.id DESC LIMIT 1), '') = ?"
        )
        params.append(level_filter)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    with db_connect() as db:
        items = db.execute(
            f"""
            SELECT
                a.id,
                a.source_name,
                a.title,
                a.url,
                a.published,
                a.created_at,
                a.is_read,
                a.assigned_level,
                CASE WHEN EXISTS (SELECT 1 FROM processed_articles p WHERE p.article_id = a.id) THEN 1 ELSE 0 END AS is_processed,
                (SELECT GROUP_CONCAT(p3.target_language || ' ' || p3.target_level, ' · ') FROM processed_articles p3 WHERE p3.article_id = a.id) AS processed_combos,
                (SELECT p2.target_language FROM processed_articles p2 WHERE p2.article_id = a.id ORDER BY p2.created_at DESC, p2.id DESC LIMIT 1) AS latest_target_language,
                (SELECT p2.target_level FROM processed_articles p2 WHERE p2.article_id = a.id ORDER BY p2.created_at DESC, p2.id DESC LIMIT 1) AS latest_target_level
            FROM articles a
            {where_sql}
            ORDER BY COALESCE(a.published, a.created_at) DESC, a.id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, per_page, offset),
        ).fetchall()

        total = db.execute("SELECT COUNT(*) FROM articles").fetchone()[0]

        total_filtered = db.execute(
            f"SELECT COUNT(*) FROM articles a {where_sql}",
            params,
        ).fetchone()[0]

        processed_count = db.execute(
            "SELECT COUNT(*) FROM articles a WHERE EXISTS (SELECT 1 FROM processed_articles p WHERE p.article_id = a.id)"
        ).fetchone()[0]

        processed_filtered = db.execute(
            f"SELECT COUNT(*) FROM articles a {where_sql} "
            + ("AND " if where_sql else "WHERE ")
            + "EXISTS (SELECT 1 FROM processed_articles p WHERE p.article_id = a.id)",
            params,
        ).fetchone()[0]

        source_rows = db.execute(
            "SELECT DISTINCT source_name FROM articles ORDER BY source_name ASC"
        ).fetchall()

    return {
        "items": [dict(row) for row in items],
        "total": to_int(total),
        "total_filtered": to_int(total_filtered),
        "processed_count": to_int(processed_count),
        "processed_filtered": to_int(processed_filtered),
        "source_names": [row[0] for row in source_rows],
        "page": page,
        "per_page": per_page,
        "total_pages": (to_int(total_filtered) + per_page - 1) // per_page if per_page > 0 else 0,
    }


def normalize_title(title: str) -> str:
    lowered = (title or "").lower()
    lowered = re.sub(r"[^a-z0-9åäö\s]", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    return lowered


def tokenize_for_similarity(text: str) -> set[str]:
    cleaned = re.sub(r"[^a-z0-9åäö\s]", " ", (text or "").lower())
    tokens = [t for t in cleaned.split() if len(t) >= 4]
    return set(tokens)


def is_similar_content(a: Dict[str, Any], b: Dict[str, Any], threshold: float = 0.55) -> bool:
    text_a = f"{a.get('title', '')} {(a.get('content') or '')[:1800]}"
    text_b = f"{b.get('title', '')} {(b.get('content') or '')[:1800]}"
    tokens_a = tokenize_for_similarity(text_a)
    tokens_b = tokenize_for_similarity(text_b)
    if not tokens_a or not tokens_b:
        return False
    overlap = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    if union == 0:
        return False
    jaccard = overlap / union
    return jaccard >= threshold


def _recency_score(article: Dict[str, Any]) -> float:
    """Score from 0.0–3.0 based on article age. Fresh articles score highest, decaying over 48h."""
    raw = article.get("published") or article.get("created_at") or ""
    dt = parse_iso_timestamp(raw)
    if dt is None:
        return 0.5  # unknown age — mild neutral score
    hours_old = max(0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600)
    # Full score up to 6h, linear decay to 0 at 48h
    if hours_old <= 6:
        return 3.0
    if hours_old >= 48:
        return 0.0
    return round(3.0 * (1 - (hours_old - 6) / 42), 3)


def relevance_score(article: Dict[str, Any]) -> float:
    content_len = len((article.get("content") or "").strip())
    title = article.get("title") or ""
    source = article.get("source_name") or ""

    # Length signal: rewards articles with real body text (cap at 1200 chars of summary).
    length_score = min(content_len / 1200.0, 1.0) * 3.0

    # Prefer trusted public broadcasters (clearer language for learners).
    source_bonus = 0.5 if source in {"Yle Uutiset", "BBC World", "DR Nyheder", "Tagesschau", "ORF", "Euronews", "The Guardian", "BBC Science", "DW English"} else 0.0

    recency = _recency_score(article)

    return length_score + source_bonus + recency


def get_recently_processed_articles(within_hours: int = DEFAULT_AUTO_MAX_AGE_HOURS) -> List[Dict[str, Any]]:
    """Return articles that were processed within the last `within_hours` hours.

    Used for cross-run deduplication: new candidates that cover the same story
    as a recently-processed article should be skipped.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=within_hours)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT a.id, a.source_name, a.title, a.content
            FROM processed_articles p
            JOIN articles a ON a.id = p.article_id
            WHERE p.created_at >= ?
            GROUP BY a.id
            ORDER BY p.created_at DESC
            LIMIT 200
            """,
            (cutoff,),
        ).fetchall()
    return [dict(row) for row in rows if not is_excluded_headline(row["title"])]


def get_unprocessed_articles(limit: int = 200, max_age_hours: int = DEFAULT_AUTO_MAX_AGE_HOURS) -> List[Dict[str, Any]]:
    """Return unprocessed articles ingested within the last `max_age_hours` hours.

    Filters by created_at (ingestion time) rather than published date, so articles
    with slightly old RSS publish dates are still included.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT
                a.id,
                a.source_name,
                a.title,
                a.url,
                a.published,
                a.created_at,
                a.content
            FROM articles a
            LEFT JOIN processed_articles p ON p.article_id = a.id
            WHERE p.article_id IS NULL
              AND a.created_at >= ?
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (cutoff, limit),
        ).fetchall()
    return [dict(row) for row in rows if not is_excluded_headline(row["title"])]


def limit_articles_per_source(
    articles: List[Dict[str, Any]],
    top_n: int,
    max_per_source: int,
) -> List[Dict[str, Any]]:
    if not articles:
        return []
    if max_per_source <= 0:
        return articles[:top_n]

    picks: List[Dict[str, Any]] = []
    source_counts: Dict[str, int] = {}

    for article in articles:
        source = to_text(article.get("source_name", ""))
        if source_counts.get(source, 0) >= max_per_source:
            continue
        picks.append(article)
        source_counts[source] = source_counts.get(source, 0) + 1
        if len(picks) >= top_n:
            break

    if len(picks) < top_n:
        for article in articles:
            if article in picks:
                continue
            picks.append(article)
            if len(picks) >= top_n:
                break

    return picks[:top_n]


def select_articles_with_llm(
    candidates: List[Dict[str, Any]],
    top_n: int = 10,
    provider: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Ask the LLM to pick the best top_n articles from a candidate list.

    Sends only titles + IDs (cheap). Falls back to heuristic order on any failure.
    """
    if provider is None:
        provider = LLM_PROVIDER

    if not candidates:
        return []

    # Build numbered headline list (cap at 80 to stay within a small prompt)
    pool = candidates[:80]

    def _age_label(article: Dict[str, Any]) -> str:
        raw = article.get("published") or article.get("created_at") or ""
        dt = parse_iso_timestamp(raw)
        if dt is None:
            return "age unknown"
        hours = max(0, (datetime.now(timezone.utc) - dt).total_seconds() / 3600)
        if hours < 1:
            return "<1h ago"
        if hours < 24:
            return f"{int(hours)}h ago"
        return f"{int(hours / 24)}d ago"

    lines = "\n".join(
        f"[{a['id']}] ({_age_label(a)}, {a.get('source_name', '?')}) {a.get('title', '').strip()}"
        for a in pool
    )

    system_prompt = (
        "You are a news editor selecting articles for a language-learning app. "
        "Return only valid JSON — no markdown, no explanation."
    )
    valid_topics_str = ", ".join(ARTICLE_TOPICS)
    levels_str = ", ".join(CEFR_LEVELS)
    prompt = f"""Below are {len(pool)} news headlines with their age and source.

Pick the {top_n} best articles for adult language learners. Apply these rules strictly:

1. FRESHNESS FIRST — strongly prefer articles published less than 12 hours ago.
   Only pick older articles if no fresher coverage exists on that topic.
2. ONE STORY ONCE — if multiple headlines cover the same event, pick only the
   most recent and informative one. Do not pick near-duplicates.
3. TOPIC VARIETY — aim for a mix across the topic categories. A mix of serious
   and lighter stories makes learning more engaging.
4. QUALITY — prefer articles with actual content over pure clickbait, vague
   teasers, or content-free listicles.

For each picked article also assign:
- "topic": one of {valid_topics_str}
  World = politics, international news, sports, conflict
  Economics = business, finance, trade, employment
  Life = science, health, culture, environment, human interest
- "level": one of {levels_str}
  A1 = short, everyday topics, simple vocabulary
  A2 = familiar topics, slightly more varied vocabulary
  B1 = abstract/technical topics, denser language

Return ONLY a JSON array of objects in preference order.
Example: [{{"id": 12, "topic": "World", "level": "A2"}}, {{"id": 7, "topic": "Life", "level": "B1"}}]

Headlines:
{lines}"""

    VALID_TOPICS = set(ARTICLE_TOPICS)

    result = _call_llm_api(provider, prompt, system_prompt)
    if "error" in result:
        return candidates[:top_n]  # fallback

    try:
        import re as _re
        raw = result["content"].strip()
        # Try new object format first
        m = _re.search(r'\[.*\]', raw, _re.DOTALL)
        if not m:
            return candidates[:top_n]
        parsed = json.loads(m.group())
        id_to_article = {a["id"]: a for a in pool}

        picks = []
        topic_map: Dict[int, str] = {}
        level_map: Dict[int, str] = {}
        if parsed and isinstance(parsed[0], dict):
            for item in parsed:
                aid = item.get("id")
                topic = item.get("topic", "")
                level = item.get("level", "")
                if aid in id_to_article:
                    if topic in VALID_TOPICS:
                        topic_map[aid] = topic
                    if level in CEFR_LEVELS:
                        level_map[aid] = level
                    picks.append(id_to_article[aid])
        else:
            for aid in parsed:
                if aid in id_to_article:
                    picks.append(id_to_article[aid])

        # Pad with heuristic order if LLM returned too few
        if len(picks) < top_n:
            for a in candidates:
                if a not in picks:
                    picks.append(a)
                if len(picks) >= top_n:
                    break
        picks = picks[:top_n]

        # Persist topics and LLM-assigned levels to DB
        updates = []
        for pick in picks:
            aid = pick.get("id")
            t = topic_map.get(aid)
            lvl = level_map.get(aid)
            if t or lvl:
                updates.append((t, lvl, aid))
        if updates:
            with db_connect() as db:
                for t, lvl, aid in updates:
                    if t:
                        db.execute("UPDATE articles SET topic = ? WHERE id = ?", (t, aid))
                    if lvl:
                        db.execute("UPDATE articles SET assigned_level = ? WHERE id = ?", (lvl, aid))
                db.commit()

        # Attach level_map to each pick so pipeline can use it without re-querying
        for pick in picks:
            if pick.get("id") in level_map:
                pick["_llm_level"] = level_map[pick["id"]]

        return picks
    except (json.JSONDecodeError, TypeError, KeyError):
        return candidates[:top_n]


def select_top_relevant_articles(
    top_n: int = 10,
    max_per_source: int = DEFAULT_MAX_PER_SOURCE_PREFILTER,
    max_age_hours: int = DEFAULT_AUTO_MAX_AGE_HOURS,
    recent_within_hours: int = DEFAULT_AUTO_MAX_AGE_HOURS,
    candidate_pool_limit: int = DEFAULT_CANDIDATE_POOL_LIMIT,
) -> List[Dict[str, Any]]:
    candidates = get_unprocessed_articles(limit=max(candidate_pool_limit, top_n), max_age_hours=max_age_hours)
    recent_processed = get_recently_processed_articles(within_hours=recent_within_hours)

    seen_titles = set()
    unique_candidates: List[Dict[str, Any]] = []

    for item in candidates:
        if is_excluded_headline(item.get("title", "")):
            continue
        norm_title = normalize_title(item.get("title", ""))
        if not norm_title or norm_title in seen_titles:
            continue
        seen_titles.add(norm_title)
        unique_candidates.append(item)

    ranked = sorted(
        unique_candidates,
        key=lambda x: (relevance_score(x), x.get("id", 0)),
        reverse=True,
    )

    diverse: List[Dict[str, Any]] = []
    source_counts: Dict[str, int] = {}
    for candidate in ranked:
        source = candidate.get("source_name", "")
        if source_counts.get(source, 0) >= max_per_source:
            continue
        if any(is_similar_content(candidate, chosen, threshold=0.55) for chosen in diverse):
            continue
        # Skip if this story was already covered in a recent run
        if any(is_similar_content(candidate, prev, threshold=0.55) for prev in recent_processed):
            continue
        diverse.append(candidate)
        source_counts[source] = source_counts.get(source, 0) + 1
        if len(diverse) >= top_n:
            break
    return diverse


def _process_one_language(article_id: int, target_language: str, provider: Optional[str] = None, review_provider: Optional[str] = None, run_id: Optional[str] = None, allowed_levels: Optional[List[str]] = None) -> Dict[str, Any]:
    return process_article_all_levels(article_id, target_language, CEFR_LEVELS, force=False, provider=provider, review_provider=review_provider, run_id=run_id, allowed_levels=allowed_levels)


def _assign_levels_round_robin(
    picks: List[Dict[str, Any]],
    allowed_levels: Optional[List[str]] = None,
) -> Dict[int, str]:
    """Assign levels to picks, preferring LLM-assigned levels when available.

    Falls back to round-robin for any articles without an LLM-assigned level,
    ensuring balanced distribution across allowed levels overall.
    """
    levels = allowed_levels if allowed_levels else CEFR_LEVELS
    if not picks or not levels:
        return {}

    assigned_by_id: Dict[int, str] = {}
    rr_idx = 0
    for article in picks:
        article_id = to_int(article.get("id"), default=0)
        if article_id <= 0:
            continue
        llm_level = article.get("_llm_level")
        if llm_level in levels:
            assigned_by_id[article_id] = llm_level
        else:
            # Round-robin fallback for articles the LLM didn't assign a level to
            assigned_by_id[article_id] = levels[rr_idx % len(levels)]
            rr_idx += 1

    with db_connect() as db:
        db.executemany(
            "UPDATE articles SET assigned_level = ? WHERE id = ?",
            [(level, article_id) for article_id, level in assigned_by_id.items()],
        )
        db.commit()

    return assigned_by_id


def process_article_all_levels(
    article_id: int,
    target_language: str,
    levels: List[str],
    force: bool = False,
    provider: Optional[str] = None,
    review_provider: Optional[str] = None,
    run_id: Optional[str] = None,
    allowed_levels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Process one article, detect its difficulty level, and generate content for that level only.

    Returns {assigned_level: {"ok": True} | {"error": "..."}}
    allowed_levels: if set, skip articles whose assigned level is not in this list.
    """
    if provider is None:
        provider = LLM_PROVIDER
    if review_provider is None:
        review_provider = REVIEW_LLM_PROVIDER
    if allowed_levels is None:
        allowed_levels = CEFR_LEVELS

    with db_connect() as db:
        article_row = db.execute("SELECT * FROM articles WHERE id = ?", (article_id,)).fetchone()
        if article_row is None:
            return {"error": "Article not found"}
        
        article = dict(article_row)  # Convert to dict for easier access

        # Check if already processed
        if not force and article.get("assigned_level"):
            existing = db.execute(
                "SELECT 1 FROM processed_articles WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, article["assigned_level"]),
            ).fetchone()
            if existing:
                _log_pipeline_event(
                    stage="process",
                    message=f"Article {article_id} ({target_language}, {article['assigned_level']}) skipped — already processed",
                    run_type="pipeline",
                    article_id=article_id,
                    target_language=target_language,
                    target_level=article["assigned_level"],
                )
                return {}  # Already processed

    existing_assigned = to_text(article.get("assigned_level", "")).upper().strip()
    if existing_assigned in CEFR_LEVELS:
        assigned_level = existing_assigned
    else:
        # Fallback: article has no assigned level (e.g. manually triggered).
        # Round-robin assignment always sets this during the pipeline, so this
        # path is only hit for one-off manual calls.
        assigned_level = (allowed_levels or CEFR_LEVELS)[0]

    # Skip if this article's level is not in the requested set
    if assigned_level not in allowed_levels:
        _log_pipeline_event(
            stage="process",
            message=f"Article {article_id} ({target_language}, {assigned_level}) skipped — level not in allowed_levels {allowed_levels}",
            run_type="pipeline",
            article_id=article_id,
            target_language=target_language,
            target_level=assigned_level,
        )
        return {}

    # Update article's assigned_level in DB
    with db_connect() as db:
        db.execute(
            "UPDATE articles SET assigned_level = ? WHERE id = ?",
            (assigned_level, article_id)
        )
        db.commit()
    
    # Log processing start
    log_id = _log_processing_start(article_id, target_language, assigned_level)

    import time
    start_time = time.time()
    
    # Generate content for only the assigned level
    generated = generate_learning_content_all_levels(
        article.get("content") or "",
        article.get("title") or "",
        target_language=target_language,
        levels=[assigned_level],
        article_id=article_id,
        provider=provider,
        review_provider=review_provider,
        run_id=run_id,
    )

    processing_time = time.time() - start_time

    if "error" in generated:
        error_msg = generated["error"]
        _log_processing_complete(log_id, False, error_msg)
        return {assigned_level: generated}

    # Process the generated content
    lvl_data = generated.get(assigned_level)
    if not isinstance(lvl_data, dict):
        error_msg = f"No data returned for level {assigned_level}"
        _log_processing_complete(log_id, False, error_msg)
        return {assigned_level: {"error": error_msg}}

    # If Claude confirmed a different level, reclassify the article
    confirmed_level = to_text(lvl_data.get("confirmed_level", "")).upper().strip()
    if confirmed_level and confirmed_level in CEFR_LEVELS and confirmed_level != assigned_level:
        _log_pipeline_event(
            stage="process",
            message=f"Article {article_id} ({target_language}): Claude reclassified {assigned_level} → {confirmed_level}",
            run_type="pipeline",
            article_id=article_id,
            target_language=target_language,
            target_level=confirmed_level,
        )
        assigned_level = confirmed_level
        with db_connect() as db:
            db.execute("UPDATE articles SET assigned_level = ? WHERE id = ?", (assigned_level, article_id))
            db.commit()

    simple_text = to_text(lvl_data.get("simple_text", ""))
    english_text = to_text(lvl_data.get("english_translation", ""))
    keywords = lvl_data.get("keywords", [])
    grammar_notes = lvl_data.get("grammar_notes", [])
    if not isinstance(keywords, list):
        keywords = []
    if not isinstance(grammar_notes, list):
        grammar_notes = []

    issues = validate_generated_content(simple_text, english_text, keywords, target_language)
    if issues:
        error_msg = f"Validation failed: {'; '.join(issues)}"
        _log_processing_complete(log_id, False, error_msg)
        # Log quality issues for manual review
        for issue in issues:
            _log_quality_issue(article_id, target_language, assigned_level, "validation", issue)
        return {assigned_level: {"error": error_msg}}

    with db_connect() as db:
        if force:
            db.execute(
                "DELETE FROM processed_articles WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, assigned_level),
            )
            db.execute(
                "DELETE FROM vocabulary_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, assigned_level),
            )
            db.execute(
                "DELETE FROM grammar_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, assigned_level),
            )

        # Get token count from cache if available
        prompt_hash = _hash_prompt(article.get("title") or "", article.get("content") or "", target_language, [assigned_level])
        cached = _get_cached_response(article_id, target_language, prompt_hash)
        token_count = cached["token_count"] if cached else 0

        db.execute(
            """
            INSERT INTO processed_articles
            (article_id, simple_text, english_translation, target_language, target_level, created_at, llm_tokens, processing_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (article_id, simple_text, english_text, target_language, assigned_level, now_iso(), token_count, processing_time),
        )
        db.execute(
            "DELETE FROM vocabulary_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
            (article_id, target_language, assigned_level),
        )
        db.execute(
            "DELETE FROM grammar_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
            (article_id, target_language, assigned_level),
        )

        for item in keywords:
            if not isinstance(item, dict):
                continue
            db.execute(
                """
                INSERT INTO vocabulary_items
                (article_id, target_language, target_level, base_form, grammatical_form,
                 english_translation, used_form, used_form_translation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    article_id, target_language, assigned_level,
                    to_text(item.get("base_form") or item.get("word", "")),
                    to_text(item.get("grammatical_form") or item.get("form", "")),
                    to_text(item.get("translation") or item.get("en_translation", "")),
                    to_text(item.get("used_form") or item.get("example", "")),
                    to_text(item.get("used_form_translation") or item.get("translation") or item.get("en_translation", "")),
                ),
            )

        for item in grammar_notes:
            if not isinstance(item, dict):
                continue
            db.execute(
                """
                INSERT INTO grammar_items
                (article_id, target_language, target_level, sentence_index, sentence_text, grammar_explanation)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    article_id, target_language, assigned_level,
                    to_int(item.get("sentence_index", 0), default=0),
                    to_text(item.get("sentence_text", "")),
                    to_text(item.get("grammar_explanation", "")),
                ),
            )

        db.commit()

    # Log successful processing
    _log_processing_complete(log_id, True)

    return {assigned_level: {"ok": True, "article_id": article_id, "level": assigned_level}}



def run_auto_pipeline(
    per_source: int = DEFAULT_AUTO_PER_SOURCE,
    top_n: int = 10,
    max_age_hours: int = DEFAULT_AUTO_MAX_AGE_HOURS,
    max_per_source_prefilter: int = DEFAULT_MAX_PER_SOURCE_PREFILTER,
    max_per_source_final: int = DEFAULT_MAX_PER_SOURCE_FINAL,
    candidate_pool_limit: int = DEFAULT_CANDIDATE_POOL_LIMIT,
    provider: Optional[str] = None,
    review_provider: Optional[str] = None,
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
    languages: Optional[List[str]] = None,
    allowed_levels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run full pipeline: ingest → rank → process all articles with chosen LLM providers.

    Args:
        provider: Step 1 LLM (simplify + translate). If None, uses LLM_PROVIDER env var.
        review_provider: Step 2 LLM (review + keywords + grammar). If None, uses REVIEW_LLM_PROVIDER env var.
        target_language: Optional backward-compatible single-language selector.
        target_level: Optional backward-compatible single-level selector.
        languages: List of languages to process. If None, uses all LEARNING_LANGUAGES.
        allowed_levels: CEFR levels to process. If None, processes all levels.
    """
    per_source = max(1, min(to_int(per_source, default=DEFAULT_AUTO_PER_SOURCE), 50))
    top_n = max(1, min(to_int(top_n, default=DEFAULT_AUTO_TOP_N), 100))
    max_age_hours = max(1, min(to_int(max_age_hours, default=DEFAULT_AUTO_MAX_AGE_HOURS), 48))
    max_per_source_prefilter = max(1, to_int(max_per_source_prefilter, default=DEFAULT_MAX_PER_SOURCE_PREFILTER))
    max_per_source_final = max(1, to_int(max_per_source_final, default=DEFAULT_MAX_PER_SOURCE_FINAL))
    candidate_pool_limit = max(top_n * 4, to_int(candidate_pool_limit, default=DEFAULT_CANDIDATE_POOL_LIMIT))

    if provider is None:
        provider = LLM_PROVIDER
    if review_provider is None:
        review_provider = REVIEW_LLM_PROVIDER

    if languages is None and target_language in LEARNING_LANGUAGES:
        languages = [target_language]
    if allowed_levels is None and target_level in CEFR_LEVELS:
        allowed_levels = [target_level]
    
    if languages is None:
        languages = LEARNING_LANGUAGES
    if allowed_levels is None:
        allowed_levels = CEFR_LEVELS

    run_id = f"pipeline-{uuid.uuid4().hex[:8]}"

    _log_pipeline_event(
        stage="pipeline",
        message=(
            f"Pipeline started (step1={provider}, step2={review_provider}, top_n={top_n}, "
            f"per_source={per_source}, max_age_hours={max_age_hours}, "
            f"languages={','.join(languages)})"
        ),
        run_type="pipeline",
        run_id=run_id,
        provider=f"{provider}/{review_provider}",
    )
    
    # Stage 1: fast RSS headline sweep (no full scraping)
    ingest_result = ingest_from_rss(per_source=per_source, run_id=run_id)
    _log_pipeline_event(
        stage="pipeline",
        message=f"Stage 1 done: ingest inserted={ingest_result.get('inserted', 0)}",
        run_type="pipeline",
        run_id=run_id,
        provider=provider,
    )

    # Stage 2: heuristic pre-filter → LLM picks final top_n
    candidates = select_top_relevant_articles(
        top_n=top_n * 4,
        max_per_source=max_per_source_prefilter,
        max_age_hours=max_age_hours,
        recent_within_hours=max_age_hours,
        candidate_pool_limit=candidate_pool_limit,
    )
    picks = select_articles_with_llm(candidates, top_n=top_n, provider=provider)
    picks = limit_articles_per_source(picks, top_n=top_n, max_per_source=max_per_source_final)
    _log_pipeline_event(
        stage="pipeline",
        message=(
            f"Stage 2 done: selected {len(picks)} candidate articles "
            f"(LLM-curated from {len(candidates)}, cap/source={max_per_source_final})"
        ),
        run_type="pipeline",
        run_id=run_id,
        provider=provider,
    )

    # Stage 3: full-scrape only the selected winners (parallel HTTP)
    picks = enrich_selected_articles(picks)
    _log_pipeline_event(
        stage="pipeline",
        message=f"Stage 3 done: enriched {len(picks)} selected articles",
        run_type="pipeline",
        run_id=run_id,
        provider=provider,
    )

    # Stage 3.5: assign levels via round-robin for guaranteed balance
    assigned_by_id = _assign_levels_round_robin(picks=picks, allowed_levels=allowed_levels)

    level_counts: Dict[str, int] = {lvl: 0 for lvl in (allowed_levels or CEFR_LEVELS)}
    for pick in picks:
        article_id = to_int(pick.get("id"), default=0)
        if article_id <= 0:
            continue
        level = assigned_by_id.get(article_id)
        if level not in CEFR_LEVELS:
            level = (allowed_levels or CEFR_LEVELS)[0]
        pick["assigned_level"] = level
        if level in level_counts:
            level_counts[level] += 1
    level_summary = " ".join(f"{lvl}={count}" for lvl, count in level_counts.items())
    _log_pipeline_event(
        stage="pipeline",
        message=f"Stage 3.5 done: round-robin levels {level_summary}",
        run_type="pipeline",
        run_id=run_id,
        provider=provider,
    )

    # Stage 4: one LLM call per (article, language) — only for selected languages
    valid_picks = [p for p in picks if to_int(p.get("id"), default=0) > 0]
    tasks = []
    skipped_by_lang: Dict[str, int] = {lang: 0 for lang in languages}
    for p in valid_picks:
        source_name = to_text(p.get("source_name", ""))
        aid = to_int(p["id"])
        for lang in languages:
            excluded_sources = LANGUAGE_SOURCE_EXCLUSIONS.get(lang, set())
            if source_name in excluded_sources:
                skipped_by_lang[lang] = skipped_by_lang.get(lang, 0) + 1
                continue
            tasks.append((aid, lang))

    skipped_summary = ", ".join(f"{lang}:{count}" for lang, count in skipped_by_lang.items() if count)
    _log_pipeline_event(
        stage="pipeline",
        message=(
            f"Stage 4 started: running {len(tasks)} processing tasks"
            + (f" (skipped by source filter: {skipped_summary})" if skipped_summary else "")
        ),
        run_type="pipeline",
        run_id=run_id,
        provider=provider,
    )

    processed_article_ids: set = set()
    failed: List[Dict[str, Any]] = []

    if tasks:
        max_workers = min(len(tasks), DEFAULT_MAX_WORKERS)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            # Create tasks with provider parameter
            future_to_task = {
                pool.submit(_process_one_language, aid, lang, provider, review_provider, run_id, allowed_levels): (aid, lang)
                for aid, lang in tasks
            }
            for future in as_completed(future_to_task):
                aid, lang = future_to_task[future]
                try:
                    level_results = future.result()
                except Exception as exc:
                    for lvl in CEFR_LEVELS:
                        failed.append({"article_id": aid, "language": lang, "level": lvl, "error": str(exc)})
                    _log_pipeline_event(
                        stage="process",
                        message=f"Article {aid} ({lang}) crashed: {exc}",
                        level="error",
                        run_type="pipeline",
                        run_id=run_id,
                        article_id=aid,
                        target_language=lang,
                        provider=provider,
                    )
                    continue
                for lvl, lvl_result in level_results.items():
                    if "error" in lvl_result:
                        failed.append({"article_id": aid, "language": lang, "level": lvl, "error": lvl_result["error"]})
                        _log_pipeline_event(
                            stage="process",
                            message=f"Article {aid} ({lang}, {lvl}) failed: {lvl_result['error']}",
                            level="error",
                            run_type="pipeline",
                            run_id=run_id,
                            article_id=aid,
                            target_language=lang,
                            target_level=lvl,
                            provider=provider,
                        )
                    else:
                        processed_article_ids.add(aid)
                        _log_pipeline_event(
                            stage="process",
                            message=f"Article {aid} ({lang}, {lvl}) processed",
                            run_type="pipeline",
                            run_id=run_id,
                            article_id=aid,
                            target_language=lang,
                            target_level=lvl,
                            provider=provider,
                        )

    # Fallback: if fewer articles than requested were processed, try to fill the gap
    deficit = top_n - len(processed_article_ids)
    tried_ids = {to_int(p.get("id"), default=0) for p in picks}
    MAX_RETRY_ROUNDS = 2
    retry_round = 0
    while deficit > 0 and retry_round < MAX_RETRY_ROUNDS:
        retry_round += 1
        fallback_candidates = [
            a for a in get_unprocessed_articles(limit=200, max_age_hours=max_age_hours)
            if to_int(a.get("id"), default=0) not in tried_ids
        ]
        if not fallback_candidates:
            break
        fallback_picks = select_articles_with_llm(fallback_candidates, top_n=deficit * 2, provider=provider)
        fallback_picks = limit_articles_per_source(
            fallback_picks,
            top_n=max(deficit * 2, deficit),
            max_per_source=max_per_source_final,
        )
        fallback_picks = enrich_selected_articles(fallback_picks)
        fallback_assigned = _assign_levels_round_robin(picks=fallback_picks, allowed_levels=allowed_levels)
        for fp in fallback_picks:
            aid = to_int(fp.get("id"), default=0)
            if aid <= 0:
                continue
            fp["assigned_level"] = fallback_assigned.get(aid, "A2")
            tried_ids.add(aid)
        _log_pipeline_event(
            stage="pipeline",
            message=f"Fallback round {retry_round}: trying {len(fallback_picks)} more articles (deficit={deficit})",
            run_type="pipeline",
            run_id=run_id,
            provider=provider,
        )
        fallback_tasks = []
        for fp in fallback_picks:
            source_name = to_text(fp.get("source_name", ""))
            aid = to_int(fp.get("id"), default=0)
            if aid <= 0:
                continue
            for lang in languages:
                if source_name in LANGUAGE_SOURCE_EXCLUSIONS.get(lang, set()):
                    continue
                fallback_tasks.append((aid, lang))
        if fallback_tasks:
            with ThreadPoolExecutor(max_workers=min(len(fallback_tasks), DEFAULT_MAX_WORKERS)) as pool:
                future_to_task = {
                    pool.submit(_process_one_language, aid, lang, provider, review_provider, run_id, allowed_levels): (aid, lang)
                    for aid, lang in fallback_tasks
                }
                for future in as_completed(future_to_task):
                    aid, lang = future_to_task[future]
                    try:
                        level_results = future.result()
                    except Exception as exc:
                        failed.append({"article_id": aid, "language": lang, "error": str(exc)})
                        continue
                    for lvl, lvl_result in level_results.items():
                        if "error" in lvl_result:
                            failed.append({"article_id": aid, "language": lang, "level": lvl, "error": lvl_result["error"]})
                        else:
                            processed_article_ids.add(aid)
                            _log_pipeline_event(
                                stage="process",
                                message=f"Article {aid} ({lang}, {lvl}) processed [fallback round {retry_round}]",
                                run_type="pipeline",
                                run_id=run_id,
                                article_id=aid,
                                target_language=lang,
                                target_level=lvl,
                                provider=provider,
                            )
        deficit = top_n - len(processed_article_ids)

    # Auto-archive processed articles older than 7 days
    archive_old_articles(older_than_days=7)

    # Housekeeping: remove articles older than 7 days (preserves saved vocab)
    purge_counts = purge_old_articles(keep_days=7)
    purged_total = sum(purge_counts.get(t, 0) for t in ("articles",))
    _log_pipeline_event(
        stage="pipeline",
        message=f"Pipeline finished: processed={len(processed_article_ids)} failed={len(failed)} purged={purged_total} old articles",
        level="warning" if failed else "info",
        run_type="pipeline",
        run_id=run_id,
        provider=provider,
    )

    return {
        "ingest": ingest_result,
        "debug_logs": ingest_result.get("debug_logs", []),
        "picked_articles": [
            {
                "id": to_int(x.get("id"), default=0),
                "source_name": x.get("source_name", ""),
                "title": x.get("title", ""),
                "url": x.get("url", ""),
                "score": round(relevance_score(x), 3),
                "assigned_level": x.get("assigned_level", "A2"),
            }
            for x in picks
        ],
        "processed_ids": list(processed_article_ids),
        "failed": failed,
    }


def cleanup_old_unprocessed_articles(days: int = 3) -> int:
    """Delete unprocessed articles older than `days` days."""
    with db_connect() as db:
        result = db.execute(
            """
            DELETE FROM articles
            WHERE id NOT IN (SELECT article_id FROM processed_articles)
            AND created_at < datetime('now', ? || ' days')
            """,
            (f"-{days}",),
        )
        return result.rowcount


def save_auto_pick_run(
    *,
    target_language: str,
    target_level: str,
    per_source: int,
    top_n: int,
    auto_result: Dict[str, Any],
) -> int:
    with db_connect() as db:
        cursor = db.execute(
            """
            INSERT INTO auto_pick_runs
            (target_language, target_level, per_source, top_n, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (target_language, target_level, per_source, top_n, now_iso()),
        )
        run_id = cursor.lastrowid

        processed_set = set(auto_result.get("processed_ids", []))
        failed_by_id: Dict[int, str] = {}
        for item in auto_result.get("failed", []):
            aid = to_int(item.get("article_id"), default=0)
            if aid > 0:
                failed_by_id[aid] = to_text(item.get("error", ""))

        for item in auto_result.get("picked_articles", []):
            article_id = to_int(item.get("id"), default=0)
            already_processed = db.execute(
                "SELECT 1 FROM processed_articles WHERE article_id = ?",
                (article_id,),
            ).fetchone()
            processed_ok = 1 if (article_id in processed_set or already_processed is not None) else 0
            db.execute(
                """
                INSERT INTO auto_pick_items
                (run_id, article_id, source_name, title, url, score, processed_ok, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    article_id,
                    to_text(item.get("source_name", "")),
                    to_text(item.get("title", "")),
                    to_text(item.get("url", "")),
                    float(item.get("score", 0.0) or 0.0),
                    processed_ok,
                    None if processed_ok else failed_by_id.get(article_id),
                ),
            )

        db.commit()
    return run_id


def get_latest_auto_pick_run(target_language: str, target_level: str) -> Optional[Dict[str, Any]]:
    with db_connect() as db:
        run = db.execute(
            """
            SELECT id, target_language, target_level, per_source, top_n, created_at
            FROM auto_pick_runs
            WHERE target_language = ? AND target_level = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (target_language, target_level),
        ).fetchone()
        if run is None:
            return None

        items = db.execute(
            """
            SELECT api.article_id, api.source_name, api.title, api.url, api.score, api.processed_ok, api.error
            FROM auto_pick_items api
            JOIN articles a ON a.id = api.article_id
            WHERE api.run_id = ?
            ORDER BY api.score DESC, api.id ASC
            """,
            (run["id"],),
        ).fetchall()

    return {"run": dict(run), "items": [dict(item) for item in items]}


def get_or_create_auto_pick_run(
    *,
    target_language: str,
    target_level: str,
    per_source: int = 3,
    top_n: int = DEFAULT_AUTO_TOP_N,
    max_age_hours: int = DEFAULT_AUTO_MAX_AGE_HOURS,
    force_refresh: bool = False,
) -> Dict[str, Any]:
    latest = get_latest_auto_pick_run(target_language, target_level)
    if latest and not force_refresh:
        created = parse_iso_timestamp(latest["run"].get("created_at", ""))
        if created is not None:
            age_hours = (datetime.now(timezone.utc) - created).total_seconds() / 3600.0
            if age_hours <= max(1, max_age_hours):
                latest["source"] = "cache"
                return latest

    auto_result = run_auto_pipeline(
        per_source=per_source,
        top_n=top_n,
        target_language=target_language,
        target_level=target_level,
    )
    run_id = save_auto_pick_run(
        target_language=target_language,
        target_level=target_level,
        per_source=per_source,
        top_n=top_n,
        auto_result=auto_result,
    )
    created = get_latest_auto_pick_run(target_language, target_level)
    if created is None:
        return {"run": {"id": run_id}, "items": [], "source": "new"}
    created["source"] = "new"
    return created


def get_article(
    article_id: int,
    target_language: str = DEFAULT_TARGET_LANGUAGE,
    target_level: str = DEFAULT_TARGET_LEVEL,
    user_id: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    with db_connect() as db:
        article = db.execute("SELECT * FROM articles WHERE id = ?", (article_id,)).fetchone()
        if article is None:
            return None

        # Convert to dict immediately to ensure consistent access
        article = {k: article[k] for k in article.keys()}

        # Use article's assigned_level (not the requested target_level)
        # This ensures we always fetch content at the difficulty the article was processed at
        assigned_level = article.get("assigned_level") or target_level

        # Overlay per-user is_read if a user is logged in
        if user_id is not None:
            uar = db.execute(
                "SELECT 1 FROM user_article_reads WHERE user_id = ? AND article_id = ?",
                (user_id, article_id),
            ).fetchone()
            article["is_read"] = 1 if uar else 0

        processed = db.execute(
            "SELECT * FROM processed_articles WHERE article_id = ? AND target_language = ? AND target_level = ?",
            (article_id, target_language, assigned_level),
        ).fetchone()

        if user_id is not None:
            vocabulary = db.execute(
                """
                SELECT
                    v.id,
                    v.base_form,
                    v.english_translation AS translation,
                    v.used_form,
                    v.used_form_translation,
                    v.grammatical_form,
                    COALESCE(uvs.saved, 0) AS saved,
                    COALESCE(uvs.review_count, 0) AS review_count
                FROM vocabulary_items v
                LEFT JOIN user_vocab_state uvs ON uvs.vocab_item_id = v.id AND uvs.user_id = ?
                WHERE v.article_id = ? AND v.target_language = ? AND v.target_level = ?
                ORDER BY v.id ASC
                """,
                (user_id, article_id, target_language, assigned_level),
            ).fetchall()
        else:
            vocabulary = db.execute(
                """
                SELECT
                    id,
                    base_form,
                    english_translation AS translation,
                    used_form,
                    used_form_translation,
                    grammatical_form,
                    saved,
                    review_count
                FROM vocabulary_items
                WHERE article_id = ? AND target_language = ? AND target_level = ?
                ORDER BY id ASC
                """,
                (article_id, target_language, assigned_level),
            ).fetchall()

        grammar = db.execute(
            """
            SELECT sentence_index, sentence_text, grammar_explanation
            FROM grammar_items
            WHERE article_id = ? AND target_language = ? AND target_level = ?
            ORDER BY sentence_index ASC, id ASC
            """,
            (article_id, target_language, assigned_level),
        ).fetchall()

    return {
        "article": {k: article[k] for k in article.keys()} if article else None,
        "processed": {k: processed[k] for k in processed.keys()} if processed else None,
        "vocabulary": [{k: v[k] for k in v.keys()} for v in vocabulary],
        "grammar": [{k: g[k] for k in g.keys()} for g in grammar],
    }


def process_article(
    article_id: int,
    force: bool = False,
    target_language: str = DEFAULT_TARGET_LANGUAGE,
    target_level: str = DEFAULT_TARGET_LEVEL,
    max_retries: int = DEFAULT_VALIDATION_RETRIES,
    provider: Optional[str] = None,
    review_provider: Optional[str] = None,
) -> Dict[str, Any]:
    if provider is None:
        provider = LLM_PROVIDER
    if review_provider is None:
        review_provider = REVIEW_LLM_PROVIDER

    with db_connect() as db:
        article = db.execute("SELECT * FROM articles WHERE id = ?", (article_id,)).fetchone()
        if article is None:
            return {"error": "Article not found"}

        already = db.execute(
            "SELECT id FROM processed_articles WHERE article_id = ? AND target_language = ? AND target_level = ?",
            (article_id, target_language, target_level),
        ).fetchone()
        if already is not None and not force:
            return {"error": "Article already processed"}

    attempts = max(1, min(max_retries, 5))
    final_generated: Optional[Dict[str, Any]] = None
    final_simple = ""
    final_english = ""
    final_keywords: List[Any] = []
    final_grammar_notes: List[Any] = []
    final_issues: List[str] = []
    attempts_used = 0

    for _attempt in range(1, attempts + 1):
        attempts_used = _attempt
        generated = generate_learning_content(
            article["content"] or "",
            article["title"],
            target_language=target_language,
            target_level=target_level,
            article_id=article_id,
            provider=provider,
            review_provider=review_provider,
        )
        if "error" in generated:
            return generated

        simple_text = to_text(generated.get("simple_text", ""))
        english_text = to_text(generated.get("english_translation", ""))
        keywords = generated.get("keywords", [])
        grammar_notes = generated.get("grammar_notes", [])
        if not isinstance(keywords, list):
            keywords = []
        if not isinstance(grammar_notes, list):
            grammar_notes = []

        issues = validate_generated_content(
            simple_text=simple_text,
            english_text=english_text,
            keywords=keywords,
            target_language=target_language,
        )

        final_generated = generated
        final_simple = simple_text
        final_english = english_text
        final_keywords = keywords
        final_grammar_notes = grammar_notes
        final_issues = issues

        if not issues:
            break

    if final_generated is None:
        return {"error": "Processing failed before validation."}

    if final_issues:
        return {
            "error": "Validation failed after retries.",
            "validation_issues": final_issues,
        }

    with db_connect() as db:
        if force:
            db.execute(
                "DELETE FROM processed_articles WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, target_level),
            )
            db.execute(
                "DELETE FROM vocabulary_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, target_level),
            )
            db.execute(
                "DELETE FROM grammar_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, target_level),
            )
        else:
            # Re-check right before insert to avoid race-condition crashes.
            already_now = db.execute(
                "SELECT 1 FROM processed_articles WHERE article_id = ? AND target_language = ? AND target_level = ?",
                (article_id, target_language, target_level),
            ).fetchone()
            if already_now is not None:
                return {"error": "Article already processed"}

        try:
            db.execute(
                "UPDATE articles SET assigned_level = ? WHERE id = ?",
                (target_level, article_id),
            )
            db.execute(
                """
                INSERT INTO processed_articles
                (article_id, simple_text, english_translation, target_language, target_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    article_id,
                    final_simple,
                    final_english,
                    target_language,
                    target_level,
                    now_iso(),
                ),
            )
        except sqlite3.IntegrityError:
            # Safety net for concurrent writes.
            return {"error": "Article already processed"}

        db.execute(
            "DELETE FROM vocabulary_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
            (article_id, target_language, target_level),
        )
        db.execute(
            "DELETE FROM grammar_items WHERE article_id = ? AND target_language = ? AND target_level = ?",
            (article_id, target_language, target_level),
        )

        for item in final_keywords:
            if not isinstance(item, dict):
                continue
            db.execute(
                """
                INSERT INTO vocabulary_items
                (
                    article_id,
                    target_language,
                    target_level,
                    base_form,
                    grammatical_form,
                    english_translation,
                    used_form,
                    used_form_translation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    article_id,
                    target_language,
                    target_level,
                    to_text(item.get("base_form") or item.get("word", "")),
                    to_text(item.get("grammatical_form") or item.get("form", "")),
                    to_text(item.get("translation") or item.get("en_translation", "")),
                    to_text(item.get("used_form") or item.get("example", "")),
                    to_text(item.get("used_form_translation") or item.get("translation") or item.get("en_translation", "")),
                ),
            )

        for item in final_grammar_notes:
            if not isinstance(item, dict):
                continue
            db.execute(
                """
                INSERT INTO grammar_items
                (article_id, target_language, target_level, sentence_index, sentence_text, grammar_explanation)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    article_id,
                    target_language,
                    target_level,
                    to_int(item.get("sentence_index", 0), default=0),
                    to_text(item.get("sentence_text", "")),
                    to_text(item.get("grammar_explanation", "")),
                ),
            )

        db.commit()

    return {"ok": True, "article_id": article_id, "attempts": attempts_used}


# ── Reading progress ──────────────────────────────────────────────────────────

def mark_article_read(article_id: int) -> None:
    with db_connect() as db:
        db.execute(
            "UPDATE articles SET is_read = 1, read_at = ? WHERE id = ?",
            (now_iso(), article_id),
        )
        db.commit()


def mark_article_unread(article_id: int) -> None:
    with db_connect() as db:
        db.execute(
            "UPDATE articles SET is_read = 0, read_at = NULL WHERE id = ?",
            (article_id,),
        )
        db.commit()


# ── Vocabulary saving + spaced repetition ────────────────────────────────────

def _next_review_date(review_count: int, knew_it: bool) -> str:
    """Return ISO timestamp for next review using a simple doubling schedule."""
    if not knew_it:
        delta = timedelta(hours=4)
    else:
        delta = timedelta(days=2 ** max(0, review_count - 1))
    return (datetime.now(timezone.utc) + delta).isoformat()


def toggle_save_word(vocab_item_id: int) -> bool:
    """Toggle saved state. Returns the new saved state (True = saved)."""
    with db_connect() as db:
        row = db.execute(
            "SELECT saved FROM vocabulary_items WHERE id = ?", (vocab_item_id,)
        ).fetchone()
        if row is None:
            return False
        new_state = 0 if row["saved"] else 1
        db.execute(
            "UPDATE vocabulary_items SET saved = ? WHERE id = ?",
            (new_state, vocab_item_id),
        )
        db.commit()
    return bool(new_state)


def get_saved_words(
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return saved vocabulary items due for review, oldest first.

    Optionally filter by processed article language/level.
    """
    now = now_iso()
    where_extra = ""
    params: List[Any] = [now]
    if target_language:
        where_extra += " AND COALESCE(v.target_language, '') = ?"
        params.append(target_language)
    if target_level:
        where_extra += " AND COALESCE(v.target_level, '') = ?"
        params.append(target_level)

    with db_connect() as db:
        rows = db.execute(
            f"""
            SELECT v.id, v.base_form, v.english_translation AS translation,
                   v.used_form, v.used_form_translation, v.grammatical_form, v.review_count,
                   v.next_review_at, a.title AS article_title, a.id AS article_id
            FROM vocabulary_items v
            JOIN articles a ON a.id = v.article_id
            WHERE v.saved = 1
              AND (v.next_review_at IS NULL OR v.next_review_at <= ?)
              {where_extra}
            ORDER BY COALESCE(v.next_review_at, '0') ASC
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_due_count(
    target_language: Optional[str] = None,
    target_level: Optional[str] = None,
) -> int:
    """Return count of saved vocabulary items due for review."""
    now = now_iso()
    where_extra = ""
    params: List[Any] = [now]
    if target_language:
        where_extra += " AND COALESCE(v.target_language, '') = ?"
        params.append(target_language)
    if target_level:
        where_extra += " AND COALESCE(v.target_level, '') = ?"
        params.append(target_level)
    with db_connect() as db:
        row = db.execute(
            f"""
            SELECT COUNT(*) AS cnt
            FROM vocabulary_items v
            JOIN articles a ON a.id = v.article_id
            WHERE v.saved = 1
              AND (v.next_review_at IS NULL OR v.next_review_at <= ?)
              {where_extra}
            """,
            params,
        ).fetchone()
    return int(row["cnt"]) if row else 0


def mark_word_reviewed(vocab_item_id: int, knew_it: bool) -> None:
    with db_connect() as db:
        row = db.execute(
            "SELECT review_count FROM vocabulary_items WHERE id = ?",
            (vocab_item_id,),
        ).fetchone()
        if row is None:
            return
        new_count = to_int(row["review_count"], default=0) + 1
        next_review = _next_review_date(new_count, knew_it)
        db.execute(
            "UPDATE vocabulary_items SET review_count = ?, next_review_at = ? WHERE id = ?",
            (new_count, next_review, vocab_item_id),
        )
        db.commit()


def get_processing_stats() -> Dict[str, Any]:
    """Return statistics about LLM processing and costs."""
    with db_connect() as db:
        # Total processed articles
        total_processed = db.execute(
            "SELECT COUNT(*) FROM processed_articles"
        ).fetchone()[0]
        
        # Total LLM tokens used
        total_tokens = db.execute(
            "SELECT SUM(llm_tokens) FROM processed_articles"
        ).fetchone()[0] or 0
        
        # Processing status breakdown
        status_counts = db.execute(
            """
            SELECT status, COUNT(*) as count
            FROM processing_log
            GROUP BY status
            """
        ).fetchall()
        
        # Quality issues
        open_issues = db.execute(
            "SELECT COUNT(*) FROM quality_control WHERE resolved = 0"
        ).fetchone()[0]
        
        # Cache hit rate
        cache_entries = db.execute(
            "SELECT COUNT(*) FROM llm_cache"
        ).fetchone()[0]
        
    return {
        "total_processed": total_processed,
        "total_tokens": total_tokens,
        "status_counts": {row["status"]: row["count"] for row in status_counts},
        "open_quality_issues": open_issues,
        "cache_entries": cache_entries,
        "estimated_cost_usd": round(total_tokens * 0.000002, 4)  # Assuming $0.20 per 100K tokens
    }


def purge_old_articles(keep_days: int = 7) -> Dict[str, int]:
    """Delete old unprocessed articles and prune stale log/event rows.

    Rules:
    - Processed articles are kept (they have learning content).
    - Unprocessed articles older than `keep_days` days are deleted.
    - pipeline_events and auto_pick_runs older than `keep_days` days are pruned.
    Returns per-table deletion counts.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).isoformat()
    deleted: Dict[str, int] = {}

    with db_connect() as db:
        # Only unprocessed articles — those with no row in processed_articles
        old_ids = [
            row[0]
            for row in db.execute(
                """
                SELECT a.id FROM articles a
                LEFT JOIN processed_articles p ON p.article_id = a.id
                WHERE p.article_id IS NULL
                  AND COALESCE(a.published, a.created_at) < ?
                """,
                (cutoff,),
            ).fetchall()
        ]

        if old_ids:
            ph = ",".join("?" * len(old_ids))

            for table in (
                "auto_pick_items",
                "pipeline_events",
                "processing_log",
                "articles",
            ):
                cur = db.execute(
                    f"DELETE FROM {table} WHERE {'article_id' if table != 'articles' else 'id'} IN ({ph})",
                    old_ids,
                )
                deleted[table] = cur.rowcount or 0

        # Prune global pipeline_events (no article link) older than cutoff
        cur = db.execute(
            "DELETE FROM pipeline_events WHERE article_id IS NULL AND created_at < ?", (cutoff,)
        )
        deleted["pipeline_events"] = deleted.get("pipeline_events", 0) + (cur.rowcount or 0)

        cur = db.execute("DELETE FROM auto_pick_runs WHERE created_at < ?", (cutoff,))
        deleted["auto_pick_runs"] = cur.rowcount or 0

        db.commit()

    return deleted


def get_latest_processed_at(target_language: Optional[str] = None) -> Optional[str]:
    """Return the ISO timestamp of the most recently processed article (globally or per language)."""
    with db_connect() as db:
        if target_language:
            row = db.execute(
                "SELECT MAX(created_at) FROM processed_articles WHERE target_language = ?",
                (target_language,),
            ).fetchone()
        else:
            row = db.execute("SELECT MAX(created_at) FROM processed_articles").fetchone()
    return row[0] if row else None


def get_quality_issues(limit: int = 50, resolved: bool = False) -> List[Dict[str, Any]]:
    """Get quality control issues for manual review."""
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT q.id, q.article_id, q.target_language, q.target_level,
                   q.issue_type, q.issue_description, q.severity, q.created_at,
                   a.title AS article_title
            FROM quality_control q
            JOIN articles a ON a.id = q.article_id
            WHERE q.resolved = ?
            ORDER BY q.created_at DESC
            LIMIT ?
            """,
            (1 if resolved else 0, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def resolve_quality_issue(issue_id: int) -> bool:
    """Mark a quality issue as resolved."""
    with db_connect() as db:
        cursor = db.execute(
            "UPDATE quality_control SET resolved = 1 WHERE id = ?",
            (issue_id,)
        )
        db.commit()
        return cursor.rowcount == 1


def get_processing_log(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent processing activity."""
    with db_connect() as db:
        rows = db.execute(
            """
            SELECT p.id, p.article_id, p.target_language, p.target_level,
                   p.status, p.error_message, p.started_at, p.completed_at,
                   a.title AS article_title
            FROM processing_log p
            JOIN articles a ON a.id = p.article_id
            ORDER BY p.started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_pipeline_events(limit: int = 200) -> List[Dict[str, Any]]:
    """Get recent pipeline/ingestion stage events."""
    with db_connect() as db:
        rows = db.execute(
            """
                 SELECT e.id, e.created_at, e.run_type, e.run_id, e.stage, e.level, e.message,
                   e.article_id, e.target_language, e.target_level, e.provider,
                   a.title AS article_title
            FROM pipeline_events e
            LEFT JOIN articles a ON a.id = e.article_id
            ORDER BY e.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
