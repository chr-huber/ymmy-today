#!/usr/bin/env python3
"""
CLI — run the pipeline from the command line or a cron job.

Usage examples:
  # Fetch + process top 5 articles in Finnish at A2
  python cli.py run

  # Custom options
  python cli.py run --language German --level B1 --top-n 8 --per-source 5

  # Only fetch RSS (no processing)
  python cli.py ingest --per-source 10

  # Just show what's in the DB
  python cli.py status

Cron example (every 6 hours):
  0 */6 * * * cd /path/to/simplenews && .venv/bin/python cli.py run >> logs/cron.log 2>&1
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from services.news_service import (
    CEFR_LEVELS,
    DEFAULT_AUTO_MAX_AGE_HOURS,
    DEFAULT_AUTO_TOP_N,
    DEFAULT_TARGET_LANGUAGE,
    DEFAULT_TARGET_LEVEL,
    LEARNING_LANGUAGES,
    create_user,
    get_saved_words,
    ingest_from_rss,
    init_db,
    list_articles,
    run_auto_pipeline,
    save_auto_pick_run,
    to_int,
)
from services.newsletter_service import send_weekly_digest, subscriber_count


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def cmd_ingest(args: argparse.Namespace) -> int:
    print(f"[{_ts()}] Fetching RSS feeds ({args.per_source} per source)…")
    result = ingest_from_rss(per_source=args.per_source)
    print(f"  inserted={result['inserted']}  skipped={result['skipped']}")
    for err in result["errors"]:
        print(f"  WARNING: {err}", file=sys.stderr)
    
    # Write debug logs to file
    if result.get("debug_logs"):
        with open("ingest_debug.log", "w", encoding="utf-8") as f:
            f.write("\n".join(result["debug_logs"]))
        print(f"  Debug logs written to ingest_debug.log")
    
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    print(
        f"[{_ts()}] Running pipeline — language={args.language}  level={args.level}"
        f"  top_n={args.top_n}  per_source={args.per_source}"
    )
    auto = run_auto_pipeline(
        per_source=args.per_source,
        top_n=args.top_n,
        target_language=args.language,
        target_level=args.level,
    )

    ingest = auto["ingest"]
    print(
        f"  ingest: inserted={ingest['inserted']}  skipped={ingest['skipped']}"
    )
    for err in ingest["errors"]:
        print(f"  WARNING (ingest): {err}", file=sys.stderr)

    picked = auto.get("picked_articles", [])
    print(f"  picked {len(picked)} article(s)")
    for p in picked:
        print(f"    [{p['id']}] {p['source_name']} — {p['title'][:72]}  (score={p['score']})")

    print(f"  processed: {auto['processed_ids']}")
    if auto["failed"]:
        print(f"  FAILURES ({len(auto['failed'])}):", file=sys.stderr)
        for f in auto["failed"]:
            print(f"    article_id={f['article_id']}  {f['error']}", file=sys.stderr)

    # Persist run to DB.
    run_id = save_auto_pick_run(
        target_language=args.language,
        target_level=args.level,
        per_source=args.per_source,
        top_n=args.top_n,
        auto_result=auto,
    )
    print(f"  saved as run_id={run_id}")

    if args.json:
        print(json.dumps(auto, ensure_ascii=False, indent=2))

    failed_count = len(auto["failed"])
    return 1 if failed_count > 0 else 0


def cmd_status(args: argparse.Namespace) -> int:
    articles = list_articles()
    total = len(articles)
    processed = sum(1 for a in articles if a["is_processed"])
    read = sum(1 for a in articles if to_int(a.get("is_read", 0)))
    saved_words = get_saved_words()

    print(f"[{_ts()}] DB status")
    print(f"  articles : {total} total  |  {processed} processed  |  {read} read")
    print(f"  flashcards due: {len(saved_words)}")

    if args.verbose:
        print()
        for a in articles[:20]:
            status = "P" if a["is_processed"] else " "
            read_marker = "R" if to_int(a.get("is_read", 0)) else " "
            lang = a.get("target_language") or "-"
            lvl = a.get("target_level") or "-"
            print(
                f"  [{status}{read_marker}] #{a['id']:4d}  {a['source_name'][:14]:<14s}  "
                f"{lang}/{lvl}  {a['title'][:60]}"
            )
        if total > 20:
            print(f"  … {total - 20} more")
    return 0


def cmd_send_digest(args: argparse.Namespace) -> int:
    count = subscriber_count()
    print(f"[{_ts()}] Sending weekly digest — confirmed subscribers: {count}")
    if args.dry_run:
        print("  (dry run — no emails will be sent)")
    result = send_weekly_digest(language=args.language or None, dry_run=args.dry_run)
    print(
        f"  sent={result['sent']}  skipped={result['skipped']}  failed={result['failed']}  total={result['total']}"
    )
    return 1 if result["failed"] > 0 else 0


def cmd_create_user(args: argparse.Namespace) -> int:
    try:
        user_id, _ = create_user(args.username, args.password)
        print(f"User '{args.username}' created (id={user_id}).")
        return 0
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="ymmy pipeline CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # ── ingest ────────────────────────────────────────────────────────────────
    p_ingest = sub.add_parser("ingest", help="Fetch RSS feeds and store raw articles")
    p_ingest.add_argument(
        "--per-source",
        type=int,
        default=5,
        metavar="N",
        help="Articles to fetch per source (default: 5)",
    )

    # ── run ───────────────────────────────────────────────────────────────────
    p_run = sub.add_parser("run", help="Full pipeline: ingest → rank → process")
    p_run.add_argument(
        "--language",
        default=DEFAULT_TARGET_LANGUAGE,
        choices=LEARNING_LANGUAGES,
        help=f"Target language (default: {DEFAULT_TARGET_LANGUAGE})",
    )
    p_run.add_argument(
        "--level",
        default=DEFAULT_TARGET_LEVEL,
        choices=CEFR_LEVELS,
        help=f"CEFR level (default: {DEFAULT_TARGET_LEVEL})",
    )
    p_run.add_argument(
        "--top-n",
        type=int,
        default=DEFAULT_AUTO_TOP_N,
        metavar="N",
        help=f"Number of articles to pick and process (default: {DEFAULT_AUTO_TOP_N})",
    )
    p_run.add_argument(
        "--per-source",
        type=int,
        default=20,
        metavar="N",
        help="Articles to fetch per source (default: 20)",
    )
    p_run.add_argument(
        "--json",
        action="store_true",
        help="Also print full result as JSON",
    )

    # ── status ────────────────────────────────────────────────────────────────
    p_status = sub.add_parser("status", help="Show DB stats")
    p_status.add_argument("-v", "--verbose", action="store_true", help="List recent articles")

    # ── create-user ───────────────────────────────────────────────────────────
    p_user = sub.add_parser("create-user", help="Create a new reader account")
    p_user.add_argument("--username", required=True, help="Username for the new account")
    p_user.add_argument("--password", required=True, help="Password for the new account")

    # ── send-digest ───────────────────────────────────────────────────────────
    p_digest = sub.add_parser("send-digest", help="Send the weekly newsletter digest")
    p_digest.add_argument(
        "--language",
        default=None,
        choices=LEARNING_LANGUAGES,
        help="Only send to subscribers of this language (default: all)",
    )
    p_digest.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be sent without actually sending",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    init_db()

    if args.command == "ingest":
        sys.exit(cmd_ingest(args))
    elif args.command == "run":
        sys.exit(cmd_run(args))
    elif args.command == "status":
        sys.exit(cmd_status(args))
    elif args.command == "create-user":
        sys.exit(cmd_create_user(args))
    elif args.command == "send-digest":
        sys.exit(cmd_send_digest(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
