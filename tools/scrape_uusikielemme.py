"""Build the bundled Finnish beginner dictionary from uusikielemme.fi.

The site publishes topic-by-topic Finnish/English vocabulary tables. This walks
the beginner index, pulls every two-column Finnish→English table it links to,
and writes data/finnish_beginner_vocab.json.

Run manually when you want to refresh the data; the app only reads the JSON:

    python tools/scrape_uusikielemme.py
    python tools/scrape_uusikielemme.py --limit 5 --dry-run

Content is sourced from uusikielemme.fi, a free Finnish-learning site. The app
credits it on article pages. If you plan to keep this long term, ask the site
owner — the compilation is her work and carries no reuse licence.
"""

import argparse
import html as html_mod
import json
import re
import sys
import time
from datetime import date
from pathlib import Path
from typing import Dict, List, Set, Tuple

import requests

INDEX_URL = "https://uusikielemme.fi/vocabulary-for-beginners-finnish-vocabulary"
OUT_PATH = Path(__file__).resolve().parent.parent / "data" / "finnish_beginner_vocab.json"

HEADERS = {"User-Agent": "ymmy-today vocabulary import (https://ymmy.fly.dev)"}
DELAY_SECONDS = 1.0  # be a polite guest on someone else's small site

# Only follow content pages; skip author archives, feeds and the Spanish site.
ALLOWED_PREFIXES = ("/finnish-vocabulary/", "/finnish-grammar/")
SKIP_MARKERS = ("/author/", "/feed", "/comments/", "/espanja/", "/wp-", "/tag/")

# Rows that are section labels rather than word pairs.
NOISE = {"finnish", "english", "suomi", "englanti", "sana", "word"}


def fetch(url: str) -> str:
    response = requests.get(url, headers=HEADERS, timeout=30)
    response.raise_for_status()
    return response.text


def clean_cell(cell: str) -> str:
    """Strip markup, footnote markers and stray whitespace from a table cell."""
    text = re.sub(r"<br\s*/?>", " ", cell, flags=re.I)
    text = re.sub(r"<[^>]+>", "", text)
    text = html_mod.unescape(text)
    text = text.replace("\xa0", " ")
    # Drop trailing reference markers like "[1]" and surrounding whitespace.
    text = re.sub(r"\[\d+\]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def discover_pages(index_html: str) -> List[str]:
    urls: Set[str] = set()
    for href in re.findall(r'href="(https://uusikielemme\.fi/[^"#?]+)"', index_html):
        path = href[len("https://uusikielemme.fi"):]
        if any(marker in path for marker in SKIP_MARKERS):
            continue
        if not path.startswith(ALLOWED_PREFIXES):
            continue
        urls.add(href.rstrip("/") + "/")
    return sorted(urls)


def strip_example(cell: str) -> str:
    """Drop the example sentence some tables append after a dash.

    e.g. "Afganistan – Olen kotoisin Afganistanista." -> "Afganistan"
    """
    return re.split(r"\s[–—-]\s", cell, maxsplit=1)[0].strip()


def parse_tables(page_html: str) -> List[Tuple[str, str]]:
    """Return (finnish, english) pairs from every Finnish→English table.

    Column order and position vary across the site: some tables put Finnish
    first, some English, and the verb list has Finnish in the second of five
    columns. So locate the columns by their header label rather than by index.
    """
    pairs: List[Tuple[str, str]] = []

    for table in re.findall(r"<table[^>]*>.*?</table>", page_html, re.DOTALL | re.I):
        rows = re.findall(r"<tr[^>]*>(.*?)</tr>", table, re.DOTALL | re.I)
        if not rows:
            continue

        header = [clean_cell(c).lower()
                  for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", rows[0], re.DOTALL | re.I)]

        # The numbers page has no column labels — just a title row — and its
        # English column holds an example sentence, so pair the spelled-out
        # Finnish number with the numeral instead.
        if len(header) == 1 and "numbers" in header[0]:
            for row in rows[1:]:
                cells = [clean_cell(c)
                         for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.DOTALL | re.I)]
                if len(cells) >= 2 and cells[1] and " " not in cells[1] and cells[0]:
                    pairs.append((cells[1], cells[0]))
            continue

        # "Resident" is the Finnish column on the nationalities table.
        fi_col = next((i for i, h in enumerate(header) if h in ("finnish", "resident")), None)
        en_col = next((i for i, h in enumerate(header) if h == "english"), None)
        # Without both labelled columns this is a grammar or conjugation table.
        if fi_col is None or en_col is None:
            continue

        needed = max(fi_col, en_col) + 1
        for row in rows[1:]:
            cells = [clean_cell(c)
                     for c in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", row, re.DOTALL | re.I)]
            if len(cells) < needed:
                continue

            finnish = strip_example(cells[fi_col])
            english = strip_example(cells[en_col])
            if not finnish or not english:
                continue
            if finnish.lower() in NOISE or english.lower() in NOISE:
                continue
            # Multi-word phrases are useful in a glossary but never match a
            # single tapped word, so keep the lookup to single tokens.
            if " " in finnish:
                continue
            # Guard against a stray row that repeats the header.
            if finnish.lower() == "finnish" or english.lower() == "english":
                continue
            pairs.append((finnish, english))

    return pairs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, help="only scrape the first N pages")
    parser.add_argument("--dry-run", action="store_true", help="do not write the JSON")
    parser.add_argument("--delay", type=float, default=DELAY_SECONDS)
    args = parser.parse_args()

    print(f"index: {INDEX_URL}")
    pages = discover_pages(fetch(INDEX_URL))
    if args.limit:
        pages = pages[: args.limit]
    print(f"found {len(pages)} vocabulary page(s)\n")

    entries: Dict[str, str] = {}
    sources: List[str] = []
    failed: List[str] = []

    for i, url in enumerate(pages, 1):
        try:
            pairs = parse_tables(fetch(url))
        except Exception as exc:
            print(f"  [{i}/{len(pages)}] FAILED {url} — {exc}")
            failed.append(url)
            continue

        added = 0
        for finnish, english in pairs:
            key = finnish.lower()
            # First occurrence wins; topic pages repeat common words.
            if key not in entries:
                entries[key] = english
                added += 1

        if pairs:
            sources.append(url)
        print(f"  [{i}/{len(pages)}] {len(pairs):>4} pairs ({added:>4} new)  {url}")
        time.sleep(args.delay)

    print(f"\n{len(entries)} unique words from {len(sources)} page(s)")
    if failed:
        print(f"{len(failed)} page(s) failed: {failed}")

    if args.dry_run:
        sample = list(entries.items())[:15]
        print("\nsample:")
        for k, v in sample:
            print(f"  {k} = {v}")
        return 0

    payload = {
        "_source": "https://uusikielemme.fi/vocabulary-for-beginners-finnish-vocabulary",
        "_note": "Vocabulary compiled by uusikielemme.fi. Credited on article pages.",
        "_scraped": date.today().isoformat(),
        "_pages": len(sources),
        "words": dict(sorted(entries.items())),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nwrote {OUT_PATH} ({OUT_PATH.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
