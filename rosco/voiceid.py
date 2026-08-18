"""Voice fingerprint — a local, offline "is this Ross?" gate for listen mode.

Classical speaker verification, no cloud and no torch: MFCC + delta features,
standardized against an enrollment scaler (so the feature space is centred on
Ross's own voice), pooled to a fixed-length vector, and compared by cosine to the
enrolled reference. Tunable threshold; a pluggable seam if a neural embedding is
ever wanted later. Enrollment (Ross reading a few prompts) and the reference live
in <home>/voiceid.json — it's biometric-ish, so it stays on the machine, same
trust boundary as the vault. Not perfect the way a neural model would be, but it
reliably separates Ross from a clearly different voice once the threshold is
dialled to his own scores.

Deps: numpy + python_speech_features (+ scipy). WAV in, everything else numpy.
"""
from __future__ import annotations

import io
import json
import wave
from pathlib import Path

_FILE = "voiceid.json"
_DEFAULT_THRESHOLD = 0.55


def _path(home) -> Path:
    return Path(home) / _FILE


def _load(home) -> dict:
    try:
        return json.loads(_path(home).read_text())
    except Exception:
        return {}


def _save(home, d: dict) -> bool:
    try:
        _path(home).write_text(json.dumps(d))
        return True
    except OSError:
        return False


def _read_wav(b: bytes):
    """(mono float32 signal, sample rate) from WAV bytes."""
    import numpy as np
    w = wave.open(io.BytesIO(b), "rb")
    ch, sw, rate, n = (w.getnchannels(), w.getsampwidth(),
                       w.getframerate(), w.getnframes())
    raw = w.readframes(n)
    w.close()
    if sw == 1:
        a = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128) / 128.0
    else:                                   # treat anything else as 16-bit PCM
        a = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
    if ch > 1:
        a = a.reshape(-1, ch).mean(axis=1)
    return a, rate


def _frames(b: bytes):
    """(F, 26) MFCC+delta features for one clip, or None if too short/quiet."""
    import numpy as np
    from python_speech_features import delta, mfcc
    sig, rate = _read_wav(b)
    if sig.size < int(0.3 * rate):          # under ~0.3s — nothing to go on
        return None
    nfft = 512
    while nfft < int(0.025 * rate):         # nfft must cover a 25ms frame
        nfft *= 2
    m = mfcc(sig, rate, numcep=13, nfft=nfft, appendEnergy=False)  # drop loudness
    if m.shape[0] < 5:
        return None
    return np.hstack([m, delta(m, 2)])


def _pool(feats, mu, sd):
    """A standardized, L2-normalized voiceprint vector for one clip."""
    import numpy as np
    f = (feats - mu) / sd
    v = np.hstack([f.mean(0), f.std(0)])
    return v / (np.linalg.norm(v) + 1e-9)


def enroll(home, clips: list) -> dict:
    """Build Ross's reference voiceprint from several read clips. Enabling the gate
    on first enrollment, since enrolling is the opt-in."""
    import numpy as np
    sets = [f for f in (_frames(c) for c in clips) if f is not None]
    if len(sets) < 2:
        r = status(home)
        r["ok"] = False
        r["error"] = "need at least two clear clips — read the prompts a bit longer"
        return r
    allf = np.vstack(sets)
    mu = allf.mean(0)
    sd = allf.std(0) + 1e-6
    vecs = [_pool(f, mu, sd) for f in sets]
    ref = np.mean(vecs, axis=0)
    ref = ref / (np.linalg.norm(ref) + 1e-9)
    prev = _load(home)
    _save(home, {
        "mu": mu.tolist(), "sd": sd.tolist(), "ref": ref.tolist(),
        "samples": len(sets),
        "threshold": float(prev.get("threshold", _DEFAULT_THRESHOLD)),
        "enabled": bool(prev.get("enabled", True)),
    })
    r = status(home)
    r["ok"] = True
    return r


def score(home, clip: bytes):
    """Cosine similarity of one clip to the enrolled reference, or None."""
    import numpy as np
    d = _load(home)
    if not d.get("ref"):
        return None
    f = _frames(clip)
    if f is None:
        return None
    v = _pool(f, np.array(d["mu"]), np.array(d["sd"]))
    return float(np.dot(v, np.array(d["ref"])))


def verify(home, clip: bytes) -> dict:
    """Is this clip Ross? {gate, match, score, threshold}. Gate off or not enrolled
    -> match True (everyone passes), so the feature only ever ADDS a check."""
    d = _load(home)
    if not d.get("enabled", False) or not d.get("ref"):
        return {"gate": False, "match": True, "score": None,
                "threshold": d.get("threshold")}
    s = score(home, clip)
    if s is None:
        return {"gate": True, "match": False, "score": None,
                "threshold": d.get("threshold"), "reason": "unclear audio"}
    return {"gate": True, "match": s >= float(d.get("threshold", _DEFAULT_THRESHOLD)),
            "score": round(s, 3), "threshold": d.get("threshold")}


def status(home) -> dict:
    d = _load(home)
    return {"enrolled": bool(d.get("ref")), "samples": int(d.get("samples", 0)),
            "threshold": float(d.get("threshold", _DEFAULT_THRESHOLD)),
            "enabled": bool(d.get("enabled", False))}


def set_config(home, *, enabled=None, threshold=None) -> dict:
    d = _load(home)
    if enabled is not None:
        d["enabled"] = bool(enabled)
    if threshold is not None:
        try:
            d["threshold"] = max(0.0, min(1.0, float(threshold)))
        except (TypeError, ValueError):
            pass
    _save(home, d)
    return status(home)


def clear(home) -> dict:
    try:
        _path(home).unlink()
    except OSError:
        pass
    return status(home)
