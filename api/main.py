"""
SimpleNews reader — FastAPI app.

Start with:
  uvicorn api.main:app --reload --port 8000

Routes:
  GET  /register               self-service signup
  POST /register               create account
  GET  /welcome                post-signup welcome page
  GET  /                       article list (processed only)
  GET  /article/{id}           article reader
  GET  /flashcards             flashcard review session
  GET  /admin/login            request a passwordless admin sign-in link
  POST /admin/login            email a single-use link to ADMIN_EMAIL
  GET  /admin/auth/{token}     confirm page for an emailed link (does not spend it)
  POST /admin/auth/{token}     spend the link, open an admin session
  POST /admin/logout           end the admin session
  GET  /admin                  admin panel (magic-link session, or Basic Auth for cron)
  POST /admin/run              run auto pipeline
  POST /admin/ingest           fetch RSS headlines only
  POST /admin/process/{id}     process a single article
  POST /admin/clear            clear database
  POST /admin/send-digest      send weekly newsletter digest (admin)
  GET  /admin/users            user list with signup IPs and bot flags
  POST /admin/users/delete/{id}            delete one user (+ their reads/words)
  POST /admin/users/delete-selected        bulk delete checked users
  POST /admin/users/delete-unconfirmed     purge accounts that never confirmed
  POST /admin/newsletter/delete/{id}       remove one subscriber
  POST /admin/newsletter/delete-selected   bulk remove checked subscribers
  POST /admin/newsletter/delete-unconfirmed purge unconfirmed signups
  POST /subscribe              subscribe to the weekly newsletter
  GET  /confirm/{token}        confirm newsletter subscription
  GET  /unsubscribe/{token}    unsubscribe from newsletter
  POST /api/toggle-save/{id}   toggle vocab word saved state
  POST /api/mark-read/{id}     mark article read
  POST /api/mark-unread/{id}   mark article unread
  POST /api/review/{id}        mark word reviewed (knew_it=true/false)
"""

import logging
import os
import secrets
import hashlib
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware

from services.admin_auth import (
    SESSION_DAYS as ADMIN_SESSION_DAYS,
    TOKEN_TTL_MINUTES as ADMIN_TOKEN_TTL_MINUTES,
    admin_email,
    clear_session_auth as clear_admin_session,
    consume_login_token,
    create_login_token,
    magic_link_available,
    mark_session_authed as mark_admin_session_authed,
    purge_expired_tokens,
    send_login_link,
    session_is_authed as admin_session_is_authed,
    token_is_valid,
)
from services.antibot import (
    FORM_TOKEN_FIELD,
    HONEYPOT_FIELD,
    check_bot_signals,
    client_ip,
    form_token,
    normalize_email,
    validate_email,
    validate_username,
)
from services.email_service import smtp_configured, send_welcome_email, send_confirmation_email, send_password_reset_email
from services.newsletter_service import (
    add_subscriber,
    confirm_subscriber,
    count_recent_subscriptions_from_ip,
    delete_subscriber as newsletter_delete_subscriber,
    delete_subscribers as newsletter_delete_subscribers,
    delete_unconfirmed_subscribers,
    get_all_subscribers,
    get_digest_log,
    send_weekly_digest,
    subscriber_count,
    unsubscribe as newsletter_unsubscribe,
)
from services.news_service import (
    CEFR_LEVELS,
    CLAUDE_MODEL,
    DEFAULT_AUTO_TOP_N,
    DEFAULT_TARGET_LANGUAGE,
    DEFAULT_TARGET_LEVEL,
    GEMINI_MODEL,
    LEARNING_LANGUAGES,
    LLM_PROVIDER,
    LLM_PROVIDERS,
    MISTRAL_MODEL,
    OPENAI_MODEL,
    REVIEW_LLM_PROVIDER,
    TRUSTED_SOURCES,
    clear_database,
    clear_language_data,
    confirm_user_email,
    count_recent_signups_from_ip,
    create_email_confirm_token,
    create_password_reset_token,
    create_user,
    delete_unconfirmed_users,
    delete_user,
    delete_users,
    get_all_users,
    get_user_by_reset_token,
    reset_user_password,
    resolve_quality_issue,
    db_connect,
    get_article,
    get_due_count,
    get_all_saved_words_for_user,
    get_due_count_for_user,
    get_latest_processed_at,
    get_feature_flags,
    get_pipeline_events,
    get_processing_log,
    get_processing_stats,
    get_provider_api_key,
    get_admin_articles_page,
    get_saved_words,
    get_saved_words_for_user,
    get_user_by_id,
    get_user_settings,
    ingest_from_rss,
    init_db,
    list_articles,
    mark_article_read,
    mark_article_read_for_user,
    mark_article_unread,
    mark_article_unread_for_user,
    mark_word_reviewed,
    mark_word_reviewed_for_user,
    parse_iso_timestamp,
    process_article,
    register_manual_process,
    run_auto_pipeline,
    cleanup_old_unprocessed_articles,
    save_auto_pick_run,
    save_user_settings,
    set_feature_flag,
    split_sentences,
    to_int,
    toggle_save_word,
    toggle_save_word_for_user,
    verify_user_password,
    archive_old_articles,
    list_archived_articles,
    ARTICLE_TOPICS,
)

# DEFAULT_TARGET_LANGUAGE / DEFAULT_TARGET_LEVEL still used for single-article process form defaults

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

_session_secret = os.getenv("SESSION_SECRET_KEY", "change-me-in-production")
if _session_secret == "change-me-in-production":
    if os.getenv("FLY_APP_NAME"):
        import sys
        logging.critical("SESSION_SECRET_KEY is not set in production. Refusing to start.")
        sys.exit(1)
    logging.warning("SESSION_SECRET_KEY is not set — using insecure default. Set this env var in production!")

_admin_password = os.getenv("ADMIN_PASSWORD", "")
_WEAK_ADMIN_PASSWORDS = {"admin", "test", "changeme", "password"}
if os.getenv("FLY_APP_NAME") and (not _admin_password or _admin_password in _WEAK_ADMIN_PASSWORDS):
    import sys
    _why = "is not set" if not _admin_password else "is set to a well-known default"
    logging.critical(
        "ADMIN_PASSWORD %s. Refusing to start - booting would leave the admin panel "
        "reachable with a guessable password, including /admin/clear. Fix with:\n"
        "  fly secrets set ADMIN_PASSWORD='<32 random chars>'\n"
        "Generate one with: python -c \"import secrets,string; "
        "print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))\"\n"
        "The cron process reads the same secret, so scheduled jobs pick it up automatically.",
        _why,
    )
    sys.exit(1)

# Behind the Fly proxy every request appears to come from the proxy, which would
# make a single shared bucket out of every per-IP limit below. Key on the real client.
limiter = Limiter(key_func=client_ip)
app = FastAPI(title="ymmy")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret,
)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Serve static files if the directory exists
static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# Add caching headers middleware
@app.middleware("http")
async def add_caching_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Add caching headers for static assets
    if request.url.path.startswith("/static/") and 200 <= response.status_code < 300:
        response.headers["Cache-Control"] = "public, max-age=3600"
    
    return response


# auto_error=False so a browser with no Authorization header falls through to the
# magic-link session check instead of triggering the Basic Auth popup.
security = HTTPBasic(auto_error=False)


class AdminAuthRequired(Exception):
    """Raised when a browser reaches an admin page without a valid admin session."""


@app.exception_handler(AdminAuthRequired)
async def admin_auth_required_handler(request: Request, exc: AdminAuthRequired):
    return RedirectResponse(url="/admin/login", status_code=303)


def _basic_credentials_ok(credentials: HTTPBasicCredentials) -> bool:
    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD", "admin")
    username_ok = secrets.compare_digest(credentials.username.encode(), expected_username.encode())
    password_ok = secrets.compare_digest(credentials.password.encode(), password.encode())
    return username_ok and password_ok


def require_admin(
    request: Request,
    credentials: Optional[HTTPBasicCredentials] = Depends(security),
):
    """
    Admit either caller of the admin panel:

    * machine callers (the supercronic cron process) send HTTP Basic Auth;
    * you, in a browser, carry a session cookie from a magic-link sign-in.

    An Authorization header means "machine": it is judged on its own merits and
    a bad one gets 401 rather than a redirect, so curl fails loudly.
    """
    if credentials is not None:
        if _basic_credentials_ok(credentials):
            return credentials
        # Slow brute-force attempts without making the admin panel painful to use.
        time.sleep(1)
        raise HTTPException(
            status_code=401,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )

    if admin_session_is_authed(request.session):
        return None

    raise AdminAuthRequired()


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    purge_expired_tokens()


# ── CSRF Protection ──────────────────────────────────────────────────────────

async def generate_csrf_token(request: Request) -> str:
    """Generate CSRF token for the current session."""
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_hex(16)
    return request.session["csrf_token"]


async def verify_csrf_token(request: Request) -> bool:
    """Verify CSRF token from form data."""
    form_data = await request.form()
    token = form_data.get("csrf_token")
    session_token = request.session.get("csrf_token")
    
    if not token or not session_token:
        return False
    
    return secrets.compare_digest(token, session_token)


async def get_template_context(request: Request) -> Dict[str, Any]:
    """Get common template context including CSRF and anti-bot form tokens."""
    # Feature flags go in the shared context because base.html decides whether to
    # render the subscribe and sign-up entry points at all.
    flags = get_feature_flags()
    return {
        "request": request,
        "csrf_token": await generate_csrf_token(request),
        "newsletter_enabled": flags["newsletter_enabled"],
        "signup_enabled": flags["signup_enabled"],
        # Signed render timestamps for the public forms — see services/antibot.py.
        "subscribe_form_token": form_token("subscribe"),
        "register_form_token": form_token("register"),
        "honeypot_field": HONEYPOT_FIELD,
        "form_token_field": FORM_TOKEN_FIELD,
    }


# ── Auth helpers ───────────────────────────────────────────────────────────────

def get_optional_user(request: Request) -> Optional[Dict[str, Any]]:
    """Return the logged-in user dict, or None if anonymous."""
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)


def get_current_user_api(request: Request) -> dict:
    """For JSON API endpoints: return user or raise 401 JSON (not a redirect)."""
    user = get_optional_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Login required")
    return user


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_settings(request: Request, user: Optional[dict] = None) -> dict:
    """Return language/level settings from user DB profile (if logged in) or cookie."""
    if user:
        return get_user_settings(user["id"])
    language = request.cookies.get("language", DEFAULT_TARGET_LANGUAGE)
    level = request.cookies.get("level", DEFAULT_TARGET_LEVEL)
    if language not in LEARNING_LANGUAGES:
        language = DEFAULT_TARGET_LANGUAGE
    if level not in CEFR_LEVELS:
        level = DEFAULT_TARGET_LEVEL
    return {"language": language, "level": level}


def _age_label(published: Optional[str]) -> str:
    """Human-readable age string for an article timestamp."""
    if not published:
        return ""
    dt = parse_iso_timestamp(published)
    if dt is None:
        return published[:10] if len(published) >= 10 else published
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    diff = now - dt
    hours = int(diff.total_seconds() // 3600)
    if hours < 1:
        return "just now"
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    if days < 7:
        return f"{days}d ago"
    return dt.strftime("%b %d")


def _admin_time_label(published: Optional[str]) -> str:
    """Absolute timestamp for admin list rows."""
    if not published:
        return ""
    dt = parse_iso_timestamp(published)
    if dt is None:
        return published[:16] if len(published) >= 16 else published
    return dt.strftime("%Y-%m-%d %H:%M")


def _mask_email(address: str) -> str:
    """Partly obscure the admin address so the login page confirms it without publishing it."""
    if not address or "@" not in address:
        return ""
    local, domain = address.rsplit("@", 1)
    shown = local[:2] if len(local) > 2 else local[:1]
    return f"{shown}{'•' * max(3, len(local) - len(shown))}@{domain}"


def _source_color(source_name: str) -> str:
    palette = {
        "Yle Uutiset": "blue",
        "BBC World": "red",
        "ORF": "purple",
        "Tagesschau": "orange",
    }
    return palette.get(source_name, "gray")


# ── Login / logout ────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if get_optional_user(request):
        return RedirectResponse(url="/", status_code=303)
    context = await get_template_context(request)
    return templates.TemplateResponse("login.html", context)


@app.post("/login")
@limiter.limit("10/minute")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    # Verify CSRF token
    if not await verify_csrf_token(request):
        context = await get_template_context(request)
        context["error"] = "Invalid CSRF token"
        return templates.TemplateResponse(
            "login.html",
            context,
            status_code=403,
        )
    
    user = verify_user_password(username, password)
    if not user:
        context = await get_template_context(request)
        context["error"] = "Invalid username or password"
        return templates.TemplateResponse(
            "login.html",
            context,
            status_code=401,
        )
    if smtp_configured() and user.get("email") and not user.get("email_confirmed"):
        context = await get_template_context(request)
        context["error"] = "Please confirm your email address before signing in. Check your inbox."
        return templates.TemplateResponse("login.html", context, status_code=403)
    request.session["user_id"] = user["id"]
    # Seed language/level from browser cookies on first login if DB still has defaults
    settings = get_user_settings(user["id"])
    cookie_language = request.cookies.get("language")
    cookie_level = request.cookies.get("level")
    if cookie_language in LEARNING_LANGUAGES or cookie_level in CEFR_LEVELS:
        lang = cookie_language if cookie_language in LEARNING_LANGUAGES else settings["language"]
        lvl = cookie_level if cookie_level in CEFR_LEVELS else settings["level"]
        save_user_settings(user["id"], lang, lvl)
    return RedirectResponse(url="/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/", status_code=303)


# ── Register ──────────────────────────────────────────────────────────────────

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    if get_optional_user(request):
        return RedirectResponse(url="/", status_code=303)
    if not get_feature_flags()["signup_enabled"]:
        return RedirectResponse(url="/?msg=signup_closed", status_code=303)
    context = await get_template_context(request)
    return templates.TemplateResponse("register.html", context)


# Accounts one IP may create per day. Bots come in bursts; humans do not.
MAX_SIGNUPS_PER_IP_PER_DAY = int(os.getenv("MAX_SIGNUPS_PER_IP_PER_DAY", "3"))


@app.post("/register")
# Generous, because rejected attempts count too and a real person may fumble the
# form a few times. The hard cap on account creation is the per-IP daily quota below.
@limiter.limit("15/hour")
async def register_submit(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    # Hiding the button is not enough — the endpoint has to refuse too, or a
    # bookmarked form still creates accounts after signup is switched off.
    if not get_feature_flags()["signup_enabled"]:
        return RedirectResponse(url="/?msg=signup_closed", status_code=303)

    if not await verify_csrf_token(request):
        context = await get_template_context(request)
        context["error"] = "Invalid CSRF token"
        return templates.TemplateResponse("register.html", context, status_code=403)

    context = await get_template_context(request)
    username = (username or "").strip()
    email = normalize_email(email)
    context["username"] = username
    context["email"] = email

    def fail(message: str, status: int = 400):
        context["error"] = message
        return templates.TemplateResponse("register.html", context, status_code=status)

    # Honeypot + time trap. Silently generic so bots learn nothing from the message.
    form_data = await request.form()
    bot_signal = check_bot_signals(form_data, "register", min_seconds=3.0)
    if bot_signal:
        logging.info("Blocked bot-like registration from %s (%s)", client_ip(request), bot_signal)
        return fail(bot_signal, status=403)

    ip = client_ip(request)
    if count_recent_signups_from_ip(ip, hours=24) >= MAX_SIGNUPS_PER_IP_PER_DAY:
        logging.warning("Signup quota exceeded for IP %s", ip)
        return fail("Too many accounts have been created from this network today. Please try again tomorrow.", status=429)

    username_error = validate_username(username)
    if username_error:
        return fail(username_error)
    email_error = validate_email(email)
    if email_error:
        return fail(email_error)
    if password != password_confirm:
        return fail("Passwords do not match")
    if len(password) < 8:
        return fail("Password must be at least 8 characters")

    try:
        user_id, confirm_token = create_user(username, password, email=email, signup_ip=ip)
    except ValueError as e:
        return fail(str(e))

    request.session["user_id"] = user_id

    if smtp_configured() and confirm_token:
        try:
            base_url = str(request.base_url).rstrip("/")
            send_confirmation_email(email, username, confirm_token, base_url)
        except Exception:
            logging.warning("Confirmation email failed for %s", email, exc_info=True)

    return RedirectResponse(url="/welcome", status_code=303)


@app.get("/welcome", response_class=HTMLResponse)
async def welcome_page(request: Request):
    user = get_optional_user(request)
    if not user:
        return RedirectResponse(url="/register", status_code=303)
    context = await get_template_context(request)
    context["user"] = user
    return templates.TemplateResponse("welcome.html", context)


# ── Email confirmation ────────────────────────────────────────────────────────

@app.get("/confirm-email/{token}", response_class=HTMLResponse)
async def confirm_email(request: Request, token: str):
    ok = confirm_user_email(token)
    context = await get_template_context(request)
    context["confirmed"] = ok
    return templates.TemplateResponse("confirm_email.html", context)


# ── Password reset ────────────────────────────────────────────────────────────

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    context = await get_template_context(request)
    return templates.TemplateResponse("forgot_password.html", context)


@app.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password_submit(request: Request, email: str = Form(...)):
    if not await verify_csrf_token(request):
        context = await get_template_context(request)
        context["error"] = "Invalid CSRF token"
        return templates.TemplateResponse("forgot_password.html", context, status_code=403)

    # Always show success to avoid email enumeration
    context = await get_template_context(request)
    context["sent"] = True

    token = create_password_reset_token(email)
    if token and smtp_configured():
        user = get_user_by_reset_token(token)
        try:
            base_url = str(request.base_url).rstrip("/")
            send_password_reset_email(email, user["username"], token, base_url)
        except Exception:
            logging.warning("Password reset email failed for %s", email, exc_info=True)

    return templates.TemplateResponse("forgot_password.html", context)


@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str):
    user = get_user_by_reset_token(token)
    context = await get_template_context(request)
    if not user:
        context["invalid"] = True
        return templates.TemplateResponse("reset_password.html", context)
    context["token"] = token
    return templates.TemplateResponse("reset_password.html", context)


@app.post("/reset-password/{token}")
@limiter.limit("5/minute")
async def reset_password_submit(
    request: Request,
    token: str,
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    if not await verify_csrf_token(request):
        context = await get_template_context(request)
        context["error"] = "Invalid CSRF token"
        context["token"] = token
        return templates.TemplateResponse("reset_password.html", context, status_code=403)

    context = await get_template_context(request)

    if password != password_confirm:
        context["error"] = "Passwords do not match"
        context["token"] = token
        return templates.TemplateResponse("reset_password.html", context, status_code=400)
    if len(password) < 8:
        context["error"] = "Password must be at least 8 characters"
        context["token"] = token
        return templates.TemplateResponse("reset_password.html", context, status_code=400)

    ok = reset_user_password(token, password)
    if not ok:
        context["invalid"] = True
        return templates.TemplateResponse("reset_password.html", context, status_code=400)

    context["success"] = True
    return templates.TemplateResponse("reset_password.html", context)


# ── Reader pages ──────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    language: Optional[str] = None,
    level: Optional[str] = None,
    topic: Optional[str] = None,
    older: bool = False,
    page: int = 0,
    user: Optional[dict] = Depends(get_optional_user),
):
    settings = _get_settings(request, user)
    user_id = user["id"] if user else None

    # Optional URL override, e.g. /?language=German
    language_updated = False
    if language in LEARNING_LANGUAGES and language != settings["language"]:
        settings["language"] = language
        language_updated = True

        if user_id is not None:
            save_user_settings(user_id, settings["language"], settings["level"])

    # Default: show all levels. Apply filter only when valid level is provided.
    if level not in CEFR_LEVELS:
        level = None

    if topic not in ARTICLE_TOPICS:
        topic = None

    page = max(0, page)
    # Latest feed: always last 4 runs. Older: paginate runs 4+
    run_offset = 4 + page * 4 if older else 0
    articles = list_articles(
        target_language=settings["language"],
        target_level=level,
        user_id=user_id,
        runs_per_page=4,
        run_offset=run_offset,
        topic=topic,
    )
    # Check if there are articles/runs beyond the current page
    if older:
        with db_connect() as _db:
            next_runs = _db.execute(
                "SELECT id FROM auto_pick_runs ORDER BY id DESC LIMIT 4 OFFSET ?",
                (run_offset + 4,),
            ).fetchall()
        if next_runs:
            has_next = True
        else:
            # Mirror list_articles fallback: paginate processed_articles directly
            next_sql_offset = (run_offset + 4) * 4
            with db_connect() as _db:
                has_next = _db.execute(
                    "SELECT 1 FROM processed_articles ORDER BY created_at DESC LIMIT 1 OFFSET ?",
                    (next_sql_offset,),
                ).fetchone() is not None
    else:
        has_next = False

    # Fetch all previews in a single query
    previews: dict = {}
    if articles:
        assigned_levels = {
            a["id"]: (a.get("assigned_level") or a.get("target_level") or DEFAULT_TARGET_LEVEL)
            for a in articles
        }
        ids = list(assigned_levels.keys())
        placeholders = ",".join("?" * len(ids))
        with db_connect() as db:
            rows = db.execute(
                f"SELECT article_id, target_level, simple_text FROM processed_articles "
                f"WHERE article_id IN ({placeholders}) AND target_language = ?",
                ids + [settings["language"]],
            ).fetchall()
        for row in rows:
            aid = row["article_id"]
            if row["target_level"] == assigned_levels.get(aid):
                sentences = split_sentences(row["simple_text"], max_sentences=1)
                previews[aid] = sentences[0] if sentences else ""

    for a in articles:
        a["age"] = _age_label(a.get("published") or a.get("created_at"))
        a["source_color"] = _source_color(a["source_name"])
        a["preview"] = previews.get(a["id"], "")

    # Use global latest processing time so "updated at" reflects the last pipeline run
    latest_processed_at = get_latest_processed_at(target_language=settings["language"])

    if user_id is not None:
        due_count = get_due_count_for_user(user_id, target_language=settings["language"], target_level=level)
    else:
        due_count = get_due_count(target_language=settings["language"], target_level=level)

    context = await get_template_context(request)
    context.update({
        "articles": articles,
        "settings": settings,
        "current_level": level,
        "current_topic": topic,
        "older": older,
        "page": page,
        "has_next": has_next,
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "article_topics": ARTICLE_TOPICS,
        "due_count": due_count,
        "today_label": datetime.now(timezone.utc).strftime("%A, %B %-d"),
        "updated_at": _age_label(latest_processed_at),
        "current_user": user,
    },
    )

    response = templates.TemplateResponse("index.html", context)
    if language_updated and user_id is None:
        response.set_cookie("language", settings["language"], max_age=60 * 60 * 24 * 365)
    return response


@app.get("/archive", response_class=HTMLResponse)
async def archive_view(
    request: Request,
    level: Optional[str] = None,
    topic: Optional[str] = None,
    user: Optional[dict] = Depends(get_optional_user),
):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    settings = _get_settings(request, user)
    if level not in CEFR_LEVELS:
        level = None
    if topic not in ARTICLE_TOPICS:
        topic = None
    articles = list_archived_articles(
        target_language=settings["language"],
        target_level=level,
        user_id=user["id"],
        topic=topic,
    )
    with db_connect() as db:
        ids = [a["id"] for a in articles]
        previews: dict = {}
        if ids:
            assigned_levels = {
                a["id"]: (a.get("assigned_level") or a.get("target_level") or DEFAULT_TARGET_LEVEL)
                for a in articles
            }
            placeholders = ",".join("?" * len(ids))
            rows = db.execute(
                f"SELECT article_id, target_level, simple_text FROM processed_articles "
                f"WHERE article_id IN ({placeholders}) AND target_language = ?",
                ids + [settings["language"]],
            ).fetchall()
            for row in rows:
                aid = row["article_id"]
                if row["target_level"] == assigned_levels.get(aid):
                    sentences = split_sentences(row["simple_text"], max_sentences=1)
                    previews[aid] = sentences[0] if sentences else ""
    for a in articles:
        a["age"] = _age_label(a.get("published") or a.get("created_at"))
        a["source_color"] = _source_color(a["source_name"])
        a["preview"] = previews.get(a["id"], "")
    context = await get_template_context(request)
    context.update({
        "articles": articles,
        "settings": settings,
        "current_level": level,
        "current_topic": topic,
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "article_topics": ARTICLE_TOPICS,
        "current_user": user,
        "due_count": get_due_count_for_user(user["id"], target_language=settings["language"]),
    })
    return templates.TemplateResponse("archive.html", context)


@app.get("/article/{article_id}", response_class=HTMLResponse)
async def article_view(
    request: Request,
    article_id: int,
    language: Optional[str] = None,
    level: Optional[str] = None,
    user: Optional[dict] = Depends(get_optional_user),
):
    settings = _get_settings(request, user)
    if language in LEARNING_LANGUAGES:
        settings["language"] = language
    if level in CEFR_LEVELS:
        settings["level"] = level
    user_id = user["id"] if user else None
    data = get_article(article_id, target_language=settings["language"], target_level=settings["level"], user_id=user_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Article not found")

    article = data["article"]
    processed = data["processed"]
    if not processed:
        raise HTTPException(status_code=404, detail="Article has not been processed yet")

    simple_sentences = split_sentences(processed["simple_text"], max_sentences=10)
    english_sentences = split_sentences(processed["english_translation"], max_sentences=10)

    max_len = max(len(simple_sentences), len(english_sentences))
    paired = []
    for i in range(max_len):
        left = simple_sentences[i] if i < len(simple_sentences) else ""
        right = english_sentences[i] if i < len(english_sentences) else ""
        paired.append({"index": i + 1, "target": left, "english": right})

    age = _age_label(article.get("published") or article.get("created_at"))
    source_color = _source_color(article["source_name"])

    if user_id is not None:
        due_count = get_due_count_for_user(user_id, target_language=settings["language"], target_level=settings["level"])
        if not to_int(article.get("is_read", 0)):
            mark_article_read_for_user(user_id, article_id)
            article["is_read"] = 1
    else:
        due_count = get_due_count(target_language=settings["language"], target_level=settings["level"])

    context = await get_template_context(request)
    context.update({
        "article": article,
        "processed": processed,
        "vocabulary": data["vocabulary"],
        "grammar": data["grammar"],
        "paired": paired,
        "age": age,
        "source_color": source_color,
        "settings": settings,
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
            "due_count": due_count,
            "current_user": user,
        },
    )

    return templates.TemplateResponse("article.html", context)


@app.get("/flashcards", response_class=HTMLResponse)
async def flashcards_view(
    request: Request,
    user: Optional[dict] = Depends(get_optional_user),
):
    settings = _get_settings(request, user)
    user_id = user["id"] if user else None

    if user_id is not None:
        due_words = get_saved_words_for_user(user_id, target_language=settings["language"], target_level=settings["level"])
    else:
        due_words = get_saved_words(target_language=settings["language"], target_level=settings["level"])
    due_count = len(due_words)

    context = await get_template_context(request)
    context.update({
        "words": due_words,
        "due_count": due_count,
        "settings": settings,
            "learning_languages": LEARNING_LANGUAGES,
            "cefr_levels": CEFR_LEVELS,
            "current_user": user,
        },
    )

    return templates.TemplateResponse("flashcards.html", context)


# ── Word Bank ─────────────────────────────────────────────────────────────────

@app.get("/impressum", response_class=HTMLResponse)
async def impressum_view(
    request: Request,
    user: Optional[dict] = Depends(get_optional_user),
):
    settings = _get_settings(request, user)
    due_count = get_due_count_for_user(user["id"]) if user else 0
    context = await get_template_context(request)
    context.update({
        "settings": settings,
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "current_user": user,
        "due_count": due_count,
    })
    
    return templates.TemplateResponse("impressum.html", context)


@app.get("/faq", response_class=HTMLResponse)
async def faq_view(
    request: Request,
    user: Optional[dict] = Depends(get_optional_user),
):
    settings = _get_settings(request, user)
    due_count = get_due_count_for_user(user["id"]) if user else 0
    context = await get_template_context(request)
    context.update({
        "settings": settings,
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "current_user": user,
        "due_count": due_count,
    })
    
    return templates.TemplateResponse("faq.html", context)


@app.get("/words", response_class=HTMLResponse)
async def words_view(
    request: Request,
    user: Optional[dict] = Depends(get_optional_user),
):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    settings = _get_settings(request, user)
    words = get_all_saved_words_for_user(user["id"])
    due_count = get_due_count_for_user(user["id"])
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    context = await get_template_context(request)
    context.update({
        "words": words,
        "due_count": due_count,
        "now_iso": now_iso,
        "settings": settings,
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "current_user": user,
    })
    
    return templates.TemplateResponse("words.html", context)


# ── Settings ──────────────────────────────────────────────────────────────────

@app.post("/settings")
async def save_settings(
    request: Request,
    language: str = Form(...),
    level: Optional[str] = Form(default=None),
    redirect_to: str = Form(default="/"),
    user: Optional[dict] = Depends(get_optional_user),
):
    # Verify CSRF token
    if not await verify_csrf_token(request):
        return RedirectResponse(url=redirect_to, status_code=403)
    
    if language not in LEARNING_LANGUAGES:
        language = DEFAULT_TARGET_LANGUAGE
    # If level not submitted, keep the existing one
    if level is None or level not in CEFR_LEVELS:
        current = _get_settings(request, user)
        level = current.get("level", DEFAULT_TARGET_LEVEL)
    response = RedirectResponse(url=redirect_to, status_code=303)
    if user:
        save_user_settings(user["id"], language, level)
    else:
        response.set_cookie("language", language, max_age=60 * 60 * 24 * 365)
        response.set_cookie("level", level, max_age=60 * 60 * 24 * 365)
    return response


# ── Admin sign-in (passwordless magic link) ───────────────────────────────────

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, msg: str = "", error: str = ""):
    if admin_session_is_authed(request.session):
        return RedirectResponse(url="/admin", status_code=303)
    context = await get_template_context(request)
    context.update({
        "msg": msg,
        "error": error,
        "magic_link_available": magic_link_available(),
        "admin_email_hint": _mask_email(admin_email()),
        "token_ttl_minutes": ADMIN_TOKEN_TTL_MINUTES,
    })
    return templates.TemplateResponse("admin_login.html", context)


@app.post("/admin/login")
@limiter.limit("5/hour")
async def admin_login_request(request: Request):
    """Email a single-use sign-in link to ADMIN_EMAIL. No input, so nothing to enumerate."""
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/login?error=Invalid CSRF token", status_code=303)
    if not magic_link_available():
        return RedirectResponse(
            url="/admin/login?error=Magic-link sign-in needs ADMIN_EMAIL and SMTP to be configured",
            status_code=303,
        )

    purge_expired_tokens()
    token = create_login_token(requested_ip=client_ip(request))
    # APP_BASE_URL, not request.base_url: uvicorn only trusts forwarded headers from
    # loopback, so behind the Fly proxy request.base_url can come out as http://.
    base_url = os.getenv("APP_BASE_URL") or str(request.base_url)
    try:
        send_login_link(token, base_url)
    except Exception:
        logging.error("Failed to send admin login link", exc_info=True)
        return RedirectResponse(
            url="/admin/login?error=Could not send the email. Check the SMTP settings.",
            status_code=303,
        )

    logging.info("Admin login link requested from %s", client_ip(request))
    return RedirectResponse(url="/admin/login?msg=Check your inbox for the sign-in link", status_code=303)


@app.get("/admin/auth/{token}", response_class=HTMLResponse)
async def admin_auth_confirm(request: Request, token: str):
    """
    Landing page for the emailed link. Deliberately does not consume the token —
    mail scanners that prefetch links would otherwise burn it before you click.
    """
    context = await get_template_context(request)
    context.update({"token": token, "valid": token_is_valid(token)})
    return templates.TemplateResponse("admin_auth.html", context)


@app.post("/admin/auth/{token}")
async def admin_auth_complete(request: Request, token: str):
    """Spend the token and open an admin session."""
    if not consume_login_token(token):
        return RedirectResponse(
            url="/admin/login?error=That link has expired or was already used. Request a new one.",
            status_code=303,
        )
    mark_admin_session_authed(request.session)
    logging.info("Admin signed in via magic link from %s", client_ip(request))
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/logout")
async def admin_logout(request: Request):
    clear_admin_session(request.session)
    return RedirectResponse(url="/admin/login?msg=Signed out", status_code=303)


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.get("/admin", response_class=HTMLResponse)
async def admin_view(
    request: Request,
    page: int = 1,
    source: str = "",
    status: str = "",
    lang_filter: str = "",
    level_filter: str = "",
    msg: str = "",
    error: str = "",
    _: HTTPBasicCredentials = Depends(require_admin),
):
    settings = _get_settings(request)
    page = max(1, page)
    per_page = 20
    admin_data = get_admin_articles_page(
        page=page,
        per_page=per_page,
        source=source,
        status=status,
        lang_filter=lang_filter,
        level_filter=level_filter,
    )
    paginated_articles = admin_data["items"]
    total = admin_data["total"]
    processed_count = admin_data["processed_count"]
    total_filtered = admin_data["total_filtered"]
    processed_filtered = admin_data["processed_filtered"]
    total_pages = admin_data["total_pages"]
    page = min(page, total_pages) if total_pages > 0 else 1
    due_count = get_due_count(
        target_language=settings["language"],
        target_level=settings["level"],
    )
    stats = get_processing_stats()
    processing_log = get_processing_log(limit=15)
    for article in paginated_articles:
        article["age"] = _admin_time_label(article.get("published") or article.get("created_at"))
    source_names = admin_data["source_names"]

    context = await get_template_context(request)
    context.update({
        "articles": paginated_articles,
        "paginated_articles": paginated_articles,
        "total": total,
        "total_filtered": total_filtered,
        "processed_count": processed_count,
        "processed_filtered": processed_filtered,
        "due_count": due_count,
        "page": page,
        "total_pages": total_pages,
        "current_source": source,
        "current_status": status,
        "current_lang_filter": lang_filter,
        "current_level_filter": level_filter,
        "source_names": source_names,
        "settings": settings,
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "default_top_n": DEFAULT_AUTO_TOP_N,
            "llm_provider": LLM_PROVIDER,
            "review_llm_provider": REVIEW_LLM_PROVIDER,
            "mistral_model": MISTRAL_MODEL,
            "trusted_sources": TRUSTED_SOURCES,
            "has_api_key": any(get_provider_api_key(p) for p in LLM_PROVIDERS),
            "msg": msg,
            "error": error,
            "stats": stats,
            "processing_log": processing_log,
            # Only offer "Sign out" to a magic-link session; Basic Auth has nothing to clear.
            "admin_session": admin_session_is_authed(request.session),
        },
    )

    return templates.TemplateResponse("admin.html", context)


@app.post("/admin/run")
async def admin_run_pipeline(
    request: Request,
    top_n: int = Form(DEFAULT_AUTO_TOP_N),
    provider: str = Form(LLM_PROVIDER),
    review_provider: str = Form(REVIEW_LLM_PROVIDER),
    languages: List[str] = Form([]),
    levels: List[str] = Form([]),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    # No CSRF check — protected by HTTP Basic Auth and called by the supercronic
    # cron process via curl (see crontab), which has no session to carry a token.
    top_n = max(1, min(top_n, 100))

    valid_providers = LLM_PROVIDERS
    if provider not in valid_providers:
        provider = LLM_PROVIDER
    if review_provider not in valid_providers:
        review_provider = REVIEW_LLM_PROVIDER

    valid_languages = [lang for lang in languages if lang in LEARNING_LANGUAGES]
    if not valid_languages:
        valid_languages = LEARNING_LANGUAGES

    valid_levels = [lvl for lvl in levels if lvl in CEFR_LEVELS]
    if not valid_levels:
        valid_levels = CEFR_LEVELS

    cleanup_old_unprocessed_articles(days=3)
    result = run_auto_pipeline(top_n=top_n, provider=provider, review_provider=review_provider, languages=valid_languages, allowed_levels=valid_levels)

    save_auto_pick_run(
        target_language=", ".join(valid_languages) or "all",
        target_level=", ".join(valid_levels) or "all",
        per_source=3,
        top_n=top_n,
        auto_result=result,
    )

    inserted = result.get("ingest", {}).get("inserted", 0)
    n_processed = len(result.get("processed_ids", []))
    n_picked = len(result.get("picked_articles", []))
    n_failed = len(result.get("failed", []))

    langs_str = ", ".join(valid_languages)
    msg = f"Pipeline done (step1={provider}, step2={review_provider}) — {inserted} new headlines, {n_processed}/{n_picked} articles × {langs_str}"
    if n_failed:
        msg += f", {n_failed} tasks failed"

    return RedirectResponse(url=f"/admin?msg={msg}", status_code=303)


@app.post("/admin/settings")
async def admin_update_settings(
    request: Request,
    newsletter_enabled: bool = Form(default=False),
    signup_enabled: bool = Form(default=False),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    """Toggle the public subscribe and sign-up entry points.

    Unchecked checkboxes are simply absent from the POST body, so both fields
    default to False and the form always submits the complete desired state.
    """
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin?error=Invalid CSRF token", status_code=303)

    set_feature_flag("newsletter_enabled", newsletter_enabled)
    set_feature_flag("signup_enabled", signup_enabled)

    msg = (
        f"Public features updated — weekly digest {'on' if newsletter_enabled else 'off'}, "
        f"sign up {'on' if signup_enabled else 'off'}"
    )
    return RedirectResponse(url=f"/admin?msg={msg}", status_code=303)


@app.post("/admin/archive-old")
async def admin_archive_old(
    older_than_days: int = Form(7),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    count = archive_old_articles(older_than_days=older_than_days)
    return RedirectResponse(url=f"/admin?msg=Archived {count} articles older than {older_than_days} days", status_code=303)


@app.post("/admin/delete-unprocessed")
async def admin_delete_unprocessed(
    older_than_days: int = Form(3),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    count = cleanup_old_unprocessed_articles(days=older_than_days)
    return RedirectResponse(url=f"/admin?msg=Deleted {count} unprocessed articles older than {older_than_days} days", status_code=303)


@app.post("/admin/ingest")
async def admin_ingest(
    _: HTTPBasicCredentials = Depends(require_admin),
):
    result = ingest_from_rss()
    msg = f"Fetched {result['inserted']} new headlines, {result['skipped']} skipped"
    if result["errors"]:
        msg += f" ({len(result['errors'])} source errors)"
    
    return RedirectResponse(url=f"/admin?msg={msg}", status_code=303)


@app.post("/admin/process/{article_id}")
async def admin_process_article(
    request: Request,
    article_id: int,
    language: str = Form(DEFAULT_TARGET_LANGUAGE),
    level: str = Form(DEFAULT_TARGET_LEVEL),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    # Verify CSRF token
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin", status_code=403)
    
    result = process_article(article_id, force=False, target_language=language, target_level=level)
    if "error" in result:
        return RedirectResponse(url=f"/admin?error={result['error']}", status_code=303)
    register_manual_process(article_id, language, level)
    return RedirectResponse(url="/admin?msg=Article processed", status_code=303)


@app.post("/admin/clear")
async def admin_clear(
    request: Request,
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin", status_code=403)
    clear_database()
    return RedirectResponse(url="/admin?msg=Database cleared", status_code=303)


@app.post("/admin/clear-language")
async def admin_clear_language(
    request: Request,
    language: str = Form(...),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin", status_code=403)
    if language not in LEARNING_LANGUAGES:
        return RedirectResponse(url="/admin?error=Invalid language", status_code=303)

    deleted = clear_language_data(language)
    total_deleted = sum(deleted.values())
    return RedirectResponse(
        url=f"/admin?msg=Cleared {language} data ({total_deleted} rows)",
        status_code=303,
    )


# ── Newsletter ────────────────────────────────────────────────────────────────

# Newsletter signups one IP may create per day.
MAX_SUBSCRIPTIONS_PER_IP_PER_DAY = int(os.getenv("MAX_SUBSCRIPTIONS_PER_IP_PER_DAY", "3"))


@app.post("/subscribe")
@limiter.limit("15/hour")
async def subscribe(
    request: Request,
    email: str = Form(...),
    language: str = Form(DEFAULT_TARGET_LANGUAGE),
    level: Optional[str] = Form(default=None),
):
    if not get_feature_flags()["newsletter_enabled"]:
        return RedirectResponse(url="/?msg=newsletter_closed", status_code=303)

    if not await verify_csrf_token(request):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")

    # Honeypot + time trap. Bots get the same "subscribed" page as everyone
    # else so the failure is invisible to them, but nothing is written.
    form_data = await request.form()
    ip = client_ip(request)
    bot_signal = check_bot_signals(form_data, "subscribe", min_seconds=2.0)
    if bot_signal:
        logging.info("Blocked bot-like subscription from %s (%s)", ip, bot_signal)
        return RedirectResponse(url="/?subscribed=1", status_code=303)

    email = normalize_email(email)
    if validate_email(email):
        return RedirectResponse(url="/?msg=invalid_email", status_code=303)

    if count_recent_subscriptions_from_ip(ip, hours=24) >= MAX_SUBSCRIPTIONS_PER_IP_PER_DAY:
        logging.warning("Subscription quota exceeded for IP %s", ip)
        return RedirectResponse(url="/?subscribed=1", status_code=303)

    if language not in LEARNING_LANGUAGES:
        language = DEFAULT_TARGET_LANGUAGE
    if level not in CEFR_LEVELS:
        level = None

    token = add_subscriber(email, language, level, signup_ip=ip)

    # If SMTP is configured, send confirmation email
    if smtp_configured():
        from services.email_service import send_email
        import os
        base_url = os.getenv("APP_BASE_URL", "https://ymmy.fly.dev")
        confirm_url = f"{base_url}/confirm/{token}"
        html = (
            f"<p>Click the link below to confirm your ymmy newsletter subscription:</p>"
            f"<p><a href='{confirm_url}'>{confirm_url}</a></p>"
            f"<p>If you didn't sign up, just ignore this email.</p>"
        )
        text = f"Confirm your ymmy newsletter subscription:\n{confirm_url}\n\nIf you didn't sign up, ignore this."
        try:
            send_email(email, "Confirm your ymmy newsletter subscription", html, text)
        except Exception:
            pass  # Don't fail the request if email fails

    return RedirectResponse(url="/?subscribed=1", status_code=303)


@app.get("/confirm/{token}", response_class=HTMLResponse)
async def confirm_subscription(request: Request, token: str):
    ok = confirm_subscriber(token)
    context = await get_template_context(request)
    context.update({
        "settings": _get_settings(request),
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "current_user": get_optional_user(request),
        "due_count": 0,
        "confirmed": ok,
    })
    return templates.TemplateResponse("subscribe_confirm.html", context)


@app.get("/unsubscribe/{token}", response_class=HTMLResponse)
async def unsubscribe_view(request: Request, token: str):
    ok = newsletter_unsubscribe(token)
    context = await get_template_context(request)
    context.update({
        "settings": _get_settings(request),
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "current_user": get_optional_user(request),
        "due_count": 0,
        "unsubscribed": ok,
    })
    return templates.TemplateResponse("unsubscribe.html", context)


@app.post("/admin/send-digest")
# No CSRF check — Basic Auth only, called by the supercronic cron process.
# The browser-facing equivalent is /admin/newsletter/send, which does verify CSRF.
async def admin_send_digest(
    request: Request,
    language: Optional[str] = Form(default=None),
    dry_run: bool = Form(default=False),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    # The Sunday cron hits this endpoint. If the newsletter is switched off in
    # the admin panel, it must not quietly keep mailing people.
    if not get_feature_flags()["newsletter_enabled"]:
        return RedirectResponse(url="/admin?msg=Newsletter is disabled — digest not sent", status_code=303)

    result = send_weekly_digest(language=language or None, dry_run=dry_run)
    msg = f"Digest: sent={result['sent']} skipped={result['skipped']} failed={result['failed']} (total={result['total']})"
    if dry_run:
        msg = f"[DRY RUN] {msg}"
    return RedirectResponse(url=f"/admin?msg={msg}", status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users_view(
    request: Request,
    msg: str = "",
    _: HTTPBasicCredentials = Depends(require_admin),
):
    users = get_all_users()
    context = await get_template_context(request)
    context["users"] = users
    context["msg"] = msg
    context["unconfirmed_count"] = sum(1 for u in users if u["email"] and not u["email_confirmed"])
    return templates.TemplateResponse("admin_users.html", context)


@app.post("/admin/users/delete/{user_id}")
async def admin_user_delete(
    request: Request,
    user_id: int,
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/users?msg=Invalid CSRF token", status_code=303)
    deleted = delete_user(user_id)
    msg = "User deleted" if deleted else "User not found"
    return RedirectResponse(url=f"/admin/users?msg={msg}", status_code=303)


@app.post("/admin/users/delete-selected")
async def admin_users_delete_selected(
    request: Request,
    user_ids: List[int] = Form(default=[]),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/users?msg=Invalid CSRF token", status_code=303)
    count = delete_users(user_ids)
    return RedirectResponse(url=f"/admin/users?msg=Deleted {count} users", status_code=303)


@app.post("/admin/users/delete-unconfirmed")
async def admin_users_delete_unconfirmed(
    request: Request,
    older_than_days: int = Form(7),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/users?msg=Invalid CSRF token", status_code=303)
    count = delete_unconfirmed_users(max(0, older_than_days))
    return RedirectResponse(
        url=f"/admin/users?msg=Deleted {count} unconfirmed accounts older than {older_than_days} days",
        status_code=303,
    )


@app.get("/admin/newsletter", response_class=HTMLResponse)
async def admin_newsletter_view(
    request: Request,
    msg: str = "",
    _: HTTPBasicCredentials = Depends(require_admin),
):
    from services.email_service import smtp_configured
    context = await get_template_context(request)
    context.update({
        "settings": _get_settings(request),
        "current_user": get_optional_user(request),
        "learning_languages": LEARNING_LANGUAGES,
        "cefr_levels": CEFR_LEVELS,
        "due_count": 0,
        "subscribers": get_all_subscribers(),
        "digest_log": get_digest_log(),
        "smtp_ok": smtp_configured(),
        "msg": msg,
    })
    return templates.TemplateResponse("admin_newsletter.html", context)


@app.post("/admin/newsletter/send")
async def admin_newsletter_send(
    request: Request,
    language: Optional[str] = Form(default=None),
    dry_run: bool = Form(default=False),
    force: bool = Form(default=False),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/newsletter?msg=Invalid CSRF token", status_code=303)
    result = send_weekly_digest(language=language or None, dry_run=dry_run, force=force)
    prefix = "[DRY RUN] " if dry_run else ""
    msg = f"{prefix}Sent {result['sent']}, skipped {result['skipped']}, failed {result['failed']} (total {result['total']})"
    return RedirectResponse(url=f"/admin/newsletter?msg={msg}", status_code=303)


@app.post("/admin/newsletter/delete/{subscriber_id}")
async def admin_newsletter_delete(
    request: Request,
    subscriber_id: int,
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/newsletter?msg=Invalid CSRF token", status_code=303)
    deleted = newsletter_delete_subscriber(subscriber_id)
    msg = "Subscriber removed" if deleted else "Subscriber not found"
    return RedirectResponse(url=f"/admin/newsletter?msg={msg}", status_code=303)


@app.post("/admin/newsletter/delete-selected")
async def admin_newsletter_delete_selected(
    request: Request,
    subscriber_ids: List[int] = Form(default=[]),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/newsletter?msg=Invalid CSRF token", status_code=303)
    count = newsletter_delete_subscribers(subscriber_ids)
    return RedirectResponse(url=f"/admin/newsletter?msg=Removed {count} subscribers", status_code=303)


@app.post("/admin/newsletter/delete-unconfirmed")
async def admin_newsletter_delete_unconfirmed(
    request: Request,
    older_than_days: int = Form(7),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    if not await verify_csrf_token(request):
        return RedirectResponse(url="/admin/newsletter?msg=Invalid CSRF token", status_code=303)
    count = delete_unconfirmed_subscribers(max(0, older_than_days))
    return RedirectResponse(
        url=f"/admin/newsletter?msg=Removed {count} unconfirmed signups older than {older_than_days} days",
        status_code=303,
    )


# ── API endpoints (JSON, for Alpine.js) ───────────────────────────────────────

@app.post("/api/toggle-save/{vocab_item_id}")
@limiter.limit("60/minute")
async def api_toggle_save(
    request: Request,
    vocab_item_id: int,
    user: dict = Depends(get_current_user_api),
):
    new_state = toggle_save_word_for_user(user["id"], vocab_item_id)
    return JSONResponse({"saved": new_state})


@app.post("/api/mark-read/{article_id}")
@limiter.limit("60/minute")
async def api_mark_read(
    request: Request,
    article_id: int,
    user: dict = Depends(get_current_user_api),
):
    mark_article_read_for_user(user["id"], article_id)
    return JSONResponse({"ok": True, "is_read": True})


@app.post("/api/mark-unread/{article_id}")
@limiter.limit("60/minute")
async def api_mark_unread(
    request: Request,
    article_id: int,
    user: dict = Depends(get_current_user_api),
):
    mark_article_unread_for_user(user["id"], article_id)
    return JSONResponse({"ok": True, "is_read": False})


@app.post("/api/review/{vocab_item_id}")
@limiter.limit("120/minute")
async def api_review_word(
    request: Request,
    vocab_item_id: int,
    knew_it: bool = Form(...),
    user: dict = Depends(get_current_user_api),
):
    mark_word_reviewed_for_user(user["id"], vocab_item_id, knew_it=knew_it)
    return JSONResponse({"ok": True})


@app.post("/admin/resolve-issue/{issue_id}")
async def admin_resolve_issue(
    issue_id: int,
    _: HTTPBasicCredentials = Depends(require_admin),
):
    resolve_quality_issue(issue_id)
    return RedirectResponse(url="/admin?msg=Issue resolved", status_code=303)


@app.get("/admin/debug-logs")
async def admin_debug_logs(
    request: Request,
    _: HTTPBasicCredentials = Depends(require_admin),
):
    """View recent stage/activity logs for ingestion and processing."""
    settings = _get_settings(request)
    due_count = get_due_count(
        target_language=settings["language"],
        target_level=settings["level"],
    )

    event_logs = get_pipeline_events(limit=250)
    processing_log = get_processing_log(limit=100)

    grouped_event_logs = []
    grouped_index = {}
    for event in event_logs:
        key = event.get("run_id") or f"legacy-{event.get('id')}"
        if key not in grouped_index:
            group = {
                "run_id": event.get("run_id") or "legacy",
                "run_type": event.get("run_type"),
                "created_at": event.get("created_at"),
                "provider": event.get("provider"),
                "entries": [],
            }
            grouped_index[key] = group
            grouped_event_logs.append(group)
        grouped_index[key]["entries"].append(event)
    
    context = await get_template_context(request)
    context.update({
        "settings": settings,
        "learning_languages": LEARNING_LANGUAGES,
        "due_count": due_count,
        "event_logs": event_logs,
        "grouped_event_logs": grouped_event_logs,
        "processing_log": processing_log,
    })
    
    return templates.TemplateResponse("admin_debug.html", context)


