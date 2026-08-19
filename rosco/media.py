"""Local video / audio transcription with faster-whisper (CTranslate2) — fully offline.

ffmpeg (already on the box) decodes the media's audio to 16 kHz mono; a small English
model transcribes it on CPU (int8). No cloud, no per-minute spend. It's heavy — a
minute of speech is a few seconds to a minute of CPU — so the pull budgets how many
clips run and this caps each clip's length. Returns '' if faster-whisper or ffmpeg is
missing, the audio won't decode, or nothing intelligible came out; the pull then just
degrades that file to 'unreadable' and never crashes.
"""
from __future__ import annotations

import threading

_MODEL = None
_TRIED = False                 # latched True only once we KNOW the answer (loaded, or lib absent)
_LOAD_LOCK = threading.Lock()  # serializes the one-time model load (server is multi-threaded)
_INFER_LOCK = threading.Lock() # base.en isn't safe for concurrent inference — one clip at a time


def _model():
    """The cached Whisper model, or None if faster-whisper can't load. base.en is a
    good speed/accuracy balance for English business clips on CPU; loaded once, behind
    a lock. A *transient* load failure (a dropped model download) is NOT latched, so a
    later pull retries; only a permanently-absent library latches None."""
    global _MODEL, _TRIED
    with _LOAD_LOCK:
        if _TRIED:
            return _MODEL
        try:
            from faster_whisper import WhisperModel
            _MODEL = WhisperModel("base.en", device="cpu", compute_type="int8")
            _TRIED = True                    # success — cache it
        except ImportError:
            _TRIED = True                    # library isn't installed — permanent, don't retry
        except Exception:
            _MODEL = None                    # transient (download/timeout) — leave _TRIED False to retry
        return _MODEL


def _ffmpeg() -> str | None:
    """Locate ffmpeg: PATH first, then winget's Gyan.FFmpeg install dir (which isn't
    always on a background process's PATH)."""
    import glob
    import os
    import shutil
    cmd = shutil.which("ffmpeg")
    if cmd:
        return cmd
    base = os.path.expanduser(r"~\AppData\Local\Microsoft\WinGet\Packages")
    hits = glob.glob(os.path.join(base, "Gyan.FFmpeg*", "**", "ffmpeg.exe"), recursive=True)
    return hits[0] if hits else None


def available() -> bool:
    return _model() is not None and _ffmpeg() is not None


def _decode(data: bytes, max_seconds: int = 600):
    """Decode media bytes to a 16 kHz mono float32 numpy array via ffmpeg (bytes in on
    stdin, raw PCM out on stdout). Capped at max_seconds so a long video can't hang the
    pull. None on any failure."""
    ff = _ffmpeg()
    if not ff or not data:
        return None
    try:
        import subprocess

        import numpy as np
        p = subprocess.run(
            [ff, "-nostdin", "-threads", "1", "-i", "pipe:0", "-t", str(max_seconds),
             "-vn", "-ac", "1", "-ar", "16000", "-f", "f32le", "pipe:1"],
            input=data, capture_output=True, timeout=300)
        if p.returncode != 0 or not p.stdout:
            return None
        return np.frombuffer(p.stdout, dtype=np.float32)
    except Exception:
        return None


def transcribe(data: bytes, name: str = "") -> str:
    """Transcribe a video/audio file's speech. '' if unavailable, undecodable, or the
    result is too thin to be real speech (a silent clip, music-only, background noise)."""
    m = _model()
    if m is None:                       # no model — don't waste ffmpeg decoding the whole clip
        return ""
    audio = _decode(data)
    if audio is None or len(audio) < 16000:   # under ~1s of audio
        return ""
    try:
        with _INFER_LOCK:               # one clip at a time — concurrent calls garble base.en's output
            segments, _info = m.transcribe(audio, language="en", vad_filter=True)
            text = " ".join(seg.text.strip() for seg in segments).strip()
    except Exception:
        return ""
    if len(text) < 20 or len(text.split()) < 5:
        return ""
    return (f"[transcript of {name}]\n" if name else "") + text
