"""Bundled beginner word list used for tap-to-translate in article text.

The data is a static JSON file built by ``tools/scrape_uusikielemme.py`` from
uusikielemme.fi's beginner vocabulary pages. It is loaded once and held in
memory — it is small (a few thousand entries) and never changes at runtime.

Finnish is heavily inflected while the word list holds dictionary forms, so an
exact match alone would miss most words as they actually appear in an article.
Lookups therefore go through three stages, cheapest first:

1. exact match
2. Voikko lemmatisation — the real Finnish morphological analyser, which handles
   consonant gradation and stem changes that suffix rules cannot (kadulla ->
   katu). Voikko also decomposes compounds, so kouluvuosi can fall back to its
   final part when the whole word is absent from a beginner list.
3. suffix stripping — a heuristic fallback for environments without Voikko
   (local dev on Windows/macOS), accepting only candidates already in the list

Voikko needs the libvoikko1 and voikko-fi system packages, installed in the
Dockerfile. If they are missing the module still works, just less accurately.
"""

import json
import logging
import re
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "finnish_beginner_vocab.json"

# Longest first, so "ssa" is tried before "a" and wins where both would match.
# Restricted to endings that leave the stem intact, since anything requiring
# gradation cannot be undone reliably by suffix stripping alone.
_SUFFIXES = (
    "ihin", "seen", "ssa", "ssä", "sta", "stä", "lla", "llä", "lta", "ltä",
    "lle", "ksi", "tta", "ttä", "han", "hän", "kin", "kaan", "kään",
    "jen", "ien", "iin", "na", "nä", "ta", "tä", "en", "an", "än", "in",
    "on", "un", "yn", "a", "ä", "n", "t",
)

_words: Optional[Dict[str, str]] = None
_meta: Dict[str, str] = {}

# Voikko analyser instances are not thread-safe, and FastAPI may call this from
# more than one worker thread, so serialise access to the single instance.
_voikko = None
_voikko_tried = False
_voikko_lock = threading.Lock()

# Voikko reports compound structure as e.g. "+koulu(koulu)+vuosi(vuosi)".
_WORDBASE_RE = re.compile(r"\+([^(+]+)")


def _get_voikko():
    """Return a Voikko instance, or None when the system packages are absent."""
    global _voikko, _voikko_tried
    if _voikko_tried:
        return _voikko

    _voikko_tried = True
    try:
        import ctypes.util

        # Check the native library first: constructing Voikko without it raises
        # from its own destructor too, which prints an ignored traceback.
        if not (ctypes.util.find_library("voikko") or ctypes.util.find_library("libvoikko-1")):
            raise OSError("libvoikko shared library not found")

        from libvoikko import Voikko

        _voikko = Voikko("fi")
        logger.info("Voikko lemmatiser available")
    except Exception as exc:
        # ImportError without the pip package, OSError/VoikkoException without
        # the system library or dictionary. Either way, use suffix stripping.
        logger.info("Voikko unavailable (%s) — using suffix heuristics instead", exc)
        _voikko = None

    return _voikko


def lemmas(word: str) -> List[str]:
    """Return candidate dictionary forms for a word, best first.

    Includes the analysed base form and, for compounds, the final component —
    a beginner list will hold "vuosi" but not "kouluvuosi".
    """
    voikko = _get_voikko()
    if voikko is None:
        return []

    try:
        with _voikko_lock:
            analyses = voikko.analyze(word)
    except Exception as exc:
        logger.warning("Voikko analysis failed for %r: %s", word, exc)
        return []

    found: List[str] = []
    for analysis in analyses:
        base = (analysis.get("BASEFORM") or "").lower()
        if base and base not in found:
            found.append(base)

        parts = _WORDBASE_RE.findall(analysis.get("WORDBASES") or "")
        if len(parts) > 1:
            tail = parts[-1].lower()
            if tail and tail not in found:
                found.append(tail)

    return found


def _load() -> Dict[str, str]:
    global _words, _meta
    if _words is not None:
        return _words

    try:
        payload = json.loads(DATA_PATH.read_text(encoding="utf-8"))
        _words = {k.lower(): v for k, v in payload.get("words", {}).items()}
        _meta = {k: v for k, v in payload.items() if k != "words"}
        logger.info("Loaded %d beginner words from %s", len(_words), DATA_PATH.name)
    except FileNotFoundError:
        # The app must run without the data file; lookups simply return nothing.
        logger.info("No bundled word list at %s — tap-to-translate limited to article vocabulary", DATA_PATH)
        _words = {}
    except (ValueError, OSError) as exc:
        logger.warning("Could not read bundled word list: %s", exc)
        _words = {}

    return _words


def available() -> bool:
    return bool(_load())


def source_url() -> str:
    _load()
    return _meta.get("_source", "")


def size() -> int:
    return len(_load())


def best_lemma(word: str) -> str:
    """Dictionary form for a word, or "" if it cannot be determined.

    Used for dictionary links: sanakirja.fi resolves a base form far more
    reliably than an inflected one, so "kaduilla" should link to "katu".
    """
    for lemma in lemmas(word):
        # Skip a compound tail when the full base form is available; the first
        # entry is always the whole-word analysis.
        return lemma
    return ""


def lookup(word: str) -> Optional[Tuple[str, str]]:
    """Return (base_form, translation) for a word, or None.

    base_form is the dictionary form matched, which differs from the input when
    an ending was stripped — worth showing, since it is what the learner would
    look up.
    """
    words = _load()
    if not words or not word:
        return None

    key = word.lower()
    hit = words.get(key)
    if hit is not None:
        return key, hit

    # Voikko knows the real dictionary form, including compound parts.
    for lemma in lemmas(word):
        hit = words.get(lemma)
        if hit is not None:
            return lemma, hit

    # Try to recover a dictionary form by removing an inflectional ending.
    for suffix in _SUFFIXES:
        if not key.endswith(suffix):
            continue
        stem = key[: -len(suffix)]
        # Very short stems produce coincidental matches, not real ones.
        if len(stem) < 3:
            continue
        hit = words.get(stem)
        if hit is not None:
            return stem, hit
        # Many Finnish stems end in a vowel that the ending replaced.
        for vowel in ("a", "ä", "i", "o", "u", "y", "e"):
            hit = words.get(stem + vowel)
            if hit is not None:
                return stem + vowel, hit

    return None
