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
- **CI/CD:** Bitbucket Pipelines (triggers pipeline runs 4x/day)

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
LLM_PROVIDER=mistral              # mistral | deepseek | claude | openai
REVIEW_LLM_PROVIDER=claude

MISTRAL_API_KEY=...
MISTRAL_MODEL=mistral-small-latest

ANTHROPIC_API_KEY=...
CLAUDE_MODEL=claude-sonnet-4-6

DEEPSEEK_API_KEY=...
DEEPSEEK_MODEL=deepseek-chat

OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4o-mini

DATABASE_PATH=ymmy.db
ADMIN_PASSWORD=...
```

## Pipeline

The pipeline runs automatically via Bitbucket Pipelines (`bitbucket-pipelines.yml`):

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
- `fly.toml` — Fly.io deployment config
- `bitbucket-pipelines.yml` — scheduled pipeline trigger
