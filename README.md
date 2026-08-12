# ymmy

A language learning app that turns real news into CEFR-levelled reading material.

The pipeline selects relevant articles, simplifies them to the target language and level, and generates vocabulary and grammar notes. Articles are tagged by topic (World, Economics, Life) and CEFR level (A1, A2, B1).

**Supported learning languages:** Finnish, German, Danish

**Sources:** Yle Uutiset, BBC World, DR Nyheder, Tagesschau, ORF, Euronews, The Guardian, BBC Science, DW English

## Stack

- **Backend:** Python, FastAPI, Jinja2
- **Frontend:** Tailwind CSS v3, Alpine.js
- **Database:** SQLite (local: `ymmy.db`, production: `/data/news.db` on Fly.io volume)
- **LLM pipeline:** Mistral (article selection + simplification), Claude (review)
- **Hosting:** Fly.io
- **Scheduling:** supercronic on Fly (`cron` process, 4 pipeline runs/day + weekly digest)

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in API keys
.venv/bin/python -m uvicorn api.main:app --reload --port 8000
```

Open `http://localhost:8000`.

Build CSS (requires [Tailwind CLI](https://github.com/tailwindlabs/tailwindcss/releases)):

```bash
./build_tailwind.sh
```

## Environment variables

```env
LLM_PROVIDER=mistral              # mistral | deepseek | claude | openai | gemini | qwen
REVIEW_LLM_PROVIDER=qwen         # second-pass reviewer

MISTRAL_API_KEY=...
MISTRAL_MODEL=mistral-small-latest

ANTHROPIC_API_KEY=...
CLAUDE_MODEL=claude-sonnet-4-6

DEEPSEEK_API_KEY=...
DEEPSEEK_MODEL=deepseek-chat

OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4o-mini

GEMINI_API_KEY=...
GEMINI_MODEL=gemini-2.5-pro

QWEN_API_KEY=...                 # or DASHSCOPE_API_KEY; QwenCloud, OpenAI-compatible
QWEN_MODEL=qwen3.7-plus          # qwen3.8-max | qwen3.7-plus | qwen3.7-flash

DATABASE_PATH=ymmy.db

ADMIN_EMAIL=...                  # magic-link sign-in destination
ADMIN_LOGIN_TOKEN_MINUTES=15
ADMIN_SESSION_DAYS=30
ADMIN_USERNAME=admin
ADMIN_PASSWORD=...               # machine credential for cron; required in production
SESSION_SECRET_KEY=...           # required in production

MAX_SIGNUPS_PER_IP_PER_DAY=3
MAX_SUBSCRIPTIONS_PER_IP_PER_DAY=3
BLOCKED_EMAIL_DOMAINS=           # extra domains to reject, comma-separated
```

## Spam protection

Public forms (`/register`, `/subscribe`) run four layers, in `services/antibot.py`:

1. **Honeypot** — a hidden `website` field; any submission that fills it is dropped.
2. **Time trap** — a signed timestamp in the form; submissions faster than 2–3s are rejected.
3. **Validation** — strict email syntax, a disposable-provider blocklist, and a username
   check that rejects URL- and spam-shaped names.
4. **Per-IP daily quota** — counted in the database, so it survives machine restarts
   (unlike the in-memory `slowapi` limits, which act as a secondary backstop).

Signup IPs are recorded and surfaced in the admin panel: `/admin/users` and
`/admin/newsletter` flag addresses sharing an IP, which is the clearest bot tell.
Both pages support per-row delete, checkbox bulk delete, and a one-click purge of
unconfirmed signups older than N days.

## Admin sign-in

The admin panel admits two kinds of caller, and `require_admin` in `api/main.py`
routes them apart by whether an `Authorization` header is present:

| Caller | Method | On failure |
|---|---|---|
| You, in a browser | magic link → signed session cookie, valid `ADMIN_SESSION_DAYS` | redirect to `/admin/login` |
| The `cron` process | HTTP Basic Auth with `ADMIN_PASSWORD` | `401` with `WWW-Authenticate`, so curl fails loudly |

To sign in, open `/admin` — you are redirected to `/admin/login`, which has a single
button. It emails a link to `ADMIN_EMAIL`; the address is never taken from user
input, so there is no field to enumerate or mistype. Clicking the link lands on a
confirm page and only the confirm button spends the token, so mail scanners that
prefetch links (Outlook Safe Links and friends) cannot burn it first.

Tokens are stored as SHA-256 hashes, expire after `ADMIN_LOGIN_TOKEN_MINUTES`, are
single-use, and requesting a new link voids any outstanding one.

`ADMIN_PASSWORD` is therefore a machine credential only — you never type it. Rotate
it with a single Fly secret; the `cron` process reads the same app-wide secret and
picks it up on the restart that `fly secrets set` triggers:

```bash
fly secrets set ADMIN_PASSWORD='...' SESSION_SECRET_KEY='...'
```

Changing `SESSION_SECRET_KEY` signs you out of admin, logs every user out, and
invalidates in-flight form tokens.

If `ADMIN_EMAIL` or SMTP is unconfigured, the login page says so and Basic Auth
remains the way in — so a broken mail setup cannot lock you out of your own panel.

## Pipeline

The pipeline runs automatically on Fly, via the `cron` process defined in
`fly.toml` (supercronic reading `crontab`) — weekdays at 05/10/15/20 UTC, plus the
weekly digest on Sundays at 05:00 UTC. Both jobs `curl` admin endpoints with
HTTP Basic Auth using the app's `ADMIN_PASSWORD` secret.

1. **Ingest** — fetch RSS feeds, store new articles
2. **Select** — Mistral LLM picks the top N most relevant, non-overlapping articles and assigns topic + CEFR level
3. **Process** — simplify, translate, generate vocabulary and grammar notes per language/level
4. **Log** — run recorded in `auto_pick_runs` for feed pagination

Trigger manually via the admin panel at `/admin`.

## Deploy to Fly.io

```bash
fly deploy
```

Persistent SQLite lives on a Fly volume mounted at `/data`.

## Key files

- `api/main.py` — FastAPI routes
- `services/news_service.py` — ingestion, LLM pipeline, database
- `services/admin_service.py` — admin dashboards, cost tracking
- `templates/` — Jinja2 HTML templates
- `Dockerfile` — builds Tailwind CSS and runs uvicorn
- `services/antibot.py` — honeypot, time trap, email/username validation, per-IP quotas
- `services/admin_auth.py` — passwordless admin sign-in (magic link + session)
- `fly.toml` — Fly.io deployment config (`app` + `cron` processes)
- `crontab` — schedule run by supercronic in the `cron` process
