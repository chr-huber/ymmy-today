"""Text-to-speech synthesis with on-disk caching, via the Gemini API.

Audio is generated lazily — the first time somebody presses Listen on a given
article/language/level — and then cached forever. Most processed articles are
never listened to, so generating during the pipeline would pay for audio nobody
hears.

Files live next to the database (``/data/audio`` on Fly, ``./audio`` locally),
so they share the existing volume and survive redeploys.

The Gemini TTS endpoint returns raw PCM with no output-format option, so ffmpeg
compresses it here (it is installed in the Docker image). Without ffmpeg the
audio is stored as uncompressed WAV instead — playable, but roughly 6x larger.

Configuration::

    TTS_PROVIDER=gemini              # gemini | none
    GEMINI_API_KEY=...               # free from aistudio.google.com/apikey
    GEMINI_TTS_MODEL=gemini-2.5-flash-preview-tts
    GEMINI_VOICE_FINNISH=Kore
    GEMINI_VOICE_GERMAN=Kore

    TTS_AUDIO_FORMAT=mp3             # mp3 | opus
    TTS_AUDIO_BITRATE=               # optional, defaults per format
    TTS_CACHE_MAX_FILES=50           # least-recently-played evicted past this; 0 = no cap
    FFMPEG_PATH=                     # optional, if ffmpeg is not on PATH
    AUDIO_DIR=/data/audio            # optional, defaults to next to the DB

Note that the Gemini API (aistudio.google.com) is a different product from
Google Cloud Text-to-Speech (console.cloud.google.com); their keys are not
interchangeable.

List the available voices with::

    python -m services.tts_service --list-voices
"""

import base64
import io
import logging
import os
import re
import shutil
import subprocess
import threading
import wave
from pathlib import Path
from typing import Dict, Optional

import requests

logger = logging.getLogger(__name__)

TTS_PROVIDER = os.getenv("TTS_PROVIDER", "none").lower()

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-2.5-flash-preview-tts"

# Gemini voices are language-neutral names: the model infers the language from
# the text rather than from the voice. The full set is in the Gemini API docs.
VOICES = (
    "Zephyr", "Puck", "Charon", "Kore", "Fenrir", "Leda", "Orus", "Aoede",
)
DEFAULT_VOICE = "Kore"

VOICE_ENV = {
    "Finnish": "GEMINI_VOICE_FINNISH",
    "German": "GEMINI_VOICE_GERMAN",
}

# Target format for the stored file.
#   mp3  — plays everywhere, including older iOS Safari. The safe default.
#   opus — ~35% smaller at the same speech quality, but Ogg/Opus support on
#          Safari/iOS has been patchy, so only pick it if your readers aren't there.
TRANSCODE_FORMAT = os.getenv("TTS_AUDIO_FORMAT", "mp3").lower()
TRANSCODE_BITRATE = os.getenv("TTS_AUDIO_BITRATE", "")

_FORMAT_SPEC = {
    "mp3": {"ext": "mp3", "codec": "libmp3lame", "muxer": "mp3", "bitrate": "64k"},
    "opus": {"ext": "opus", "codec": "libopus", "muxer": "ogg", "bitrate": "32k"},
}

KNOWN_EXTS = ("mp3", "opus", "wav")

# Cache ceiling. Audio is regenerable, so evicting is cheap: a pruned article
# just re-synthesises next time somebody plays it. 0 disables the limit.
CACHE_MAX_FILES = int(os.getenv("TTS_CACHE_MAX_FILES", "50"))

REQUEST_TIMEOUT = 120

# One lock per cache key, so two simultaneous listeners don't both pay to
# synthesise the same article.
_locks: Dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class TTSError(RuntimeError):
    """Synthesis failed — the caller should fall back to browser speech."""


# ── configuration ─────────────────────────────────────────────────────────────

def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def provider() -> str:
    """Read the provider at call time so tests and the CLI can override it."""
    return os.getenv("TTS_PROVIDER", TTS_PROVIDER).lower()


def is_configured() -> bool:
    """True when synthesis is possible, so the UI can pick a player or fallback."""
    return provider() == "gemini" and bool(_env("GEMINI_API_KEY"))


def audio_dir() -> Path:
    """Directory for cached audio, alongside the database by default."""
    override = _env("AUDIO_DIR")
    if override:
        return Path(override)
    db_path = Path(os.getenv("DATABASE_PATH", "news.db"))
    parent = db_path.parent if str(db_path.parent) not in ("", ".") else Path(".")
    return parent / "audio"


def voice_for(language: str) -> str:
    env_name = VOICE_ENV.get(language)
    return (_env(env_name) if env_name else "") or DEFAULT_VOICE


# ── audio format ──────────────────────────────────────────────────────────────

def ffmpeg_path() -> Optional[str]:
    """Locate ffmpeg, honouring an explicit override."""
    override = _env("FFMPEG_PATH")
    if override:
        return override if Path(override).exists() else None
    return shutil.which("ffmpeg")


def _format_spec() -> dict:
    return _FORMAT_SPEC.get(TRANSCODE_FORMAT, _FORMAT_SPEC["mp3"])


def audio_ext() -> str:
    """Extension of the file we actually store."""
    # Without ffmpeg there is no way to compress Gemini's PCM, so keep the WAV.
    return _format_spec()["ext"] if ffmpeg_path() else "wav"


def media_type_for(path: Path) -> str:
    """Content-Type derived from the file actually on disk."""
    suffix = path.suffix.lower().lstrip(".")
    if suffix == "wav":
        return "audio/wav"
    if suffix == "opus":
        return "audio/ogg"
    return "audio/mpeg"


def _pcm_to_wav(pcm: bytes, sample_rate: int = 24000) -> bytes:
    """Wrap raw 16-bit mono PCM in a WAV container so browsers can play it."""
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)  # 16-bit
        handle.setframerate(sample_rate)
        handle.writeframes(pcm)
    return buffer.getvalue()


def _parse_pcm_rate(mime_type: str, default: int = 24000) -> int:
    """Pull the sample rate out of a mime like 'audio/L16;codec=pcm;rate=24000'."""
    match = re.search(r"rate=(\d+)", mime_type or "")
    return int(match.group(1)) if match else default


def _transcode(wav: bytes) -> bytes:
    """Compress WAV with ffmpeg, reading and writing through pipes."""
    binary = ffmpeg_path()
    if not binary:
        raise TTSError("ffmpeg not available")

    spec = _format_spec()
    result = subprocess.run(
        [
            binary, "-hide_banner", "-loglevel", "error",
            "-f", "wav", "-i", "pipe:0",
            "-codec:a", spec["codec"],
            "-b:a", TRANSCODE_BITRATE or spec["bitrate"],
            "-ac", "1",
            "-f", spec["muxer"], "pipe:1",
        ],
        input=wav,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if result.returncode != 0 or not result.stdout:
        raise TTSError(f"ffmpeg failed: {result.stderr.decode('utf-8', 'replace')[:200]}")
    return result.stdout


# ── synthesis ─────────────────────────────────────────────────────────────────

def synthesize(text: str, language: str) -> bytes:
    """Return WAV bytes for the given text. Raises TTSError on failure."""
    key = _env("GEMINI_API_KEY")
    if not key:
        raise TTSError("GEMINI_API_KEY is not set")

    model = _env("GEMINI_TTS_MODEL") or DEFAULT_MODEL
    # The model takes a spoken-style instruction and infers the language from
    # the text itself — there is no locale parameter.
    prompt = (
        f"Read the following {language} news text aloud, clearly and at a "
        f"slightly slow pace for language learners:\n\n{text}"
    )

    response = requests.post(
        f"{GEMINI_API_BASE}/models/{model}:generateContent",
        params={"key": key},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "responseModalities": ["AUDIO"],
                "speechConfig": {
                    "voiceConfig": {
                        "prebuiltVoiceConfig": {"voiceName": voice_for(language)}
                    }
                },
            },
        },
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code != 200:
        raise TTSError(f"Gemini TTS HTTP {response.status_code}: {response.text[:300]}")

    try:
        part = response.json()["candidates"][0]["content"]["parts"][0]
        inline = part["inlineData"]
        pcm = base64.b64decode(inline["data"])
    except (KeyError, IndexError, TypeError) as exc:
        raise TTSError(f"Gemini TTS returned no audio: {exc}") from exc

    if not pcm:
        raise TTSError("Gemini TTS returned empty audio")
    return _pcm_to_wav(pcm, _parse_pcm_rate(inline.get("mimeType", "")))


# ── cache ─────────────────────────────────────────────────────────────────────

def _safe(part: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "", part) or "x"


def _cache_stem(article_id: int, language: str, level: str) -> str:
    return f"{article_id}_{_safe(language)}_{_safe(level)}"


def cache_path(article_id: int, language: str, level: str) -> Path:
    # The extension follows the stored format, so changing codec produces a
    # separate cache rather than serving bytes that contradict the Content-Type.
    return audio_dir() / f"{_cache_stem(article_id, language, level)}.{audio_ext()}"


def find_cached(article_id: int, language: str, level: str) -> Optional[Path]:
    """Return any already-cached file for this article, whatever its format."""
    stem = _cache_stem(article_id, language, level)
    directory = audio_dir()
    # Preferred format first, so a re-encode wins over an older leftover.
    for ext in (audio_ext(), *KNOWN_EXTS):
        candidate = directory / f"{stem}.{ext}"
        if candidate.exists() and candidate.stat().st_size > 0:
            _touch(candidate)
            return candidate
    return None


def _touch(path: Path) -> None:
    """Mark a file as recently used, so pruning evicts genuinely cold audio."""
    try:
        os.utime(path, None)
    except OSError:
        pass  # a stale timestamp is not worth failing a playback request over


def _cached_files() -> list:
    directory = audio_dir()
    if not directory.exists():
        return []
    return [p for p in directory.iterdir() if p.is_file() and p.suffix.lstrip(".") in KNOWN_EXTS]


def prune_cache(max_files: Optional[int] = None) -> int:
    """Delete least-recently-used audio beyond the cap. Returns how many went.

    Files are regenerable, so this is safe: a pruned article simply costs one
    synthesis the next time somebody presses Listen.
    """
    limit = CACHE_MAX_FILES if max_files is None else max_files
    if limit <= 0:
        return 0

    files = _cached_files()
    if len(files) <= limit:
        return 0

    # Oldest access first; mtime is refreshed by _touch on every cache hit.
    files.sort(key=lambda p: p.stat().st_mtime)
    removed = 0
    for path in files[: len(files) - limit]:
        try:
            path.unlink()
            removed += 1
        except OSError as exc:
            logger.warning("Could not prune %s: %s", path.name, exc)

    if removed:
        logger.info("Pruned %d cached audio file(s), keeping %d", removed, limit)
    return removed


def _lock_for(key: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def get_or_create_audio(
    article_id: int, language: str, level: str, text: str
) -> Optional[Path]:
    """Return a cached audio path, synthesising it first if it does not exist.

    Returns None when TTS is not configured. Raises TTSError if generation was
    attempted and failed.
    """
    if not is_configured():
        return None

    existing = find_cached(article_id, language, level)
    if existing:
        return existing

    path = cache_path(article_id, language, level)

    text = (text or "").strip()
    if not text:
        raise TTSError("Nothing to synthesise")

    with _lock_for(_cache_stem(article_id, language, level)):
        # Another request may have generated it while we waited for the lock.
        existing = find_cached(article_id, language, level)
        if existing:
            return existing

        logger.info(
            "Synthesising audio: article=%s language=%s level=%s chars=%d",
            article_id, language, level, len(text),
        )
        audio = synthesize(text, language)

        if ffmpeg_path():
            raw_kb = len(audio) // 1024
            try:
                audio = _transcode(audio)
                logger.info("Transcoded: %d KB -> %d KB", raw_kb, len(audio) // 1024)
            except TTSError as exc:
                # Storing the larger WAV beats failing outright, but the cache
                # path assumed transcoding, so correct the extension.
                logger.warning("Transcode failed, storing WAV instead: %s", exc)
                path = path.with_suffix(".wav")

        path.parent.mkdir(parents=True, exist_ok=True)
        # Write then rename so a crash mid-write cannot leave a truncated file
        # that would be served as a valid cache hit forever.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(audio)
        tmp.replace(path)

        # Prune after writing, so the file just created is the newest and so
        # never the one evicted.
        prune_cache()
        return path


# ── CLI ───────────────────────────────────────────────────────────────────────

def list_voices() -> None:
    print("Gemini prebuilt voices (language-neutral — the text decides the language):\n")
    print("  " + "  ".join(VOICES) + "\n")
    print(f"Set {' / '.join(VOICE_ENV.values())} to one of these (default: {DEFAULT_VOICE}).")
    print("Audition with:  --voice Puck --say '...'")
    print("\nMore voices exist; see the Gemini API speech-generation docs.")


if __name__ == "__main__":
    import argparse

    from dotenv import load_dotenv

    load_dotenv()

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-voices", action="store_true", help="list available voices")
    parser.add_argument("--prune", nargs="?", type=int, const=-1, metavar="MAX",
                        help="evict least-recently-played audio beyond MAX files")
    parser.add_argument("--say", help="synthesise this text and write a sample file")
    parser.add_argument("--voice", help="override the configured voice for --say")
    parser.add_argument("--language", default="Finnish", choices=sorted(VOICE_ENV))
    parser.add_argument("--out", help="output file for --say (default: sample.<ext>)")
    args = parser.parse_args()

    # The CLI is useful even when the app itself has TTS switched off.
    os.environ["TTS_PROVIDER"] = "gemini"
    if args.voice:
        os.environ[VOICE_ENV[args.language]] = args.voice

    if args.list_voices:
        list_voices()
    elif args.prune is not None:
        limit = None if args.prune < 0 else args.prune
        before = len(_cached_files())
        removed = prune_cache(limit)
        print(f"{before} cached file(s), removed {removed}, {before - removed} remaining")
    elif args.say:
        try:
            audio = synthesize(args.say, args.language)
            if ffmpeg_path():
                audio = _transcode(audio)
            else:
                print("ffmpeg not found — writing uncompressed WAV")
        except TTSError as exc:
            raise SystemExit(f"Synthesis failed: {exc}")
        out = Path(args.out or f"sample.{audio_ext()}")
        out.write_bytes(audio)
        print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
    else:
        parser.print_help()
