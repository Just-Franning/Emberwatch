"""Second factor: time-based one-time passwords (RFC 6238), recovery codes and the QR code for authenticator apps.

- TOTP: HMAC-SHA1, 6 digits, 30-second steps (the defaults every authenticator app supports). One step of clock
  drift is accepted in either direction; a step that was used once is refused afterwards (replay protection).
- The secret is stored encrypted (AES-256-GCM, bound to the user id) with a key derived from the server key.
- Recovery codes: ten codes of ten characters (about 50 bits each), stored as HMAC values, each usable once.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
ISSUER = "Emberwatch"
RECOVERY_COUNT = 10
# no 0/o, 1/l/i: codes are read off paper and typed by hand
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
CODE_RE = re.compile(r"^\d{6}$")
_now = time.time  # replaceable in tests


def new_secret() -> str:
    """160-bit secret as base32 without padding (what authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = DIGITS) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def code_at(secret: str, ts: float, digits: int = DIGITS) -> str:
    return hotp(_key(secret), int(ts // STEP), digits)


def verify(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Returns the matching time step (to be stored as last_step) or None. Steps <= last_step are refused."""
    code = (code or "").strip().replace(" ", "")
    if not CODE_RE.match(code):
        return None
    key = _key(secret)
    step = int((_now() if now is None else now) // STEP)
    hit = None
    for s in (step - 1, step, step + 1):  # compare all three: the timing does not reveal which step matched
        if hmac.compare_digest(hotp(key, s), code) and s > last_step and hit is None:
            hit = s
    return hit


def uri(secret: str, account: str) -> str:
    label = quote(f"{ISSUER}:{account}", safe=":@")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


def qr_data_uri(text: str) -> str:
    """QR code as an SVG data URI (black on white with a quiet zone: readable by every camera app)."""
    import segno

    return segno.make_qr(text, error="m").svg_data_uri(scale=5, border=3, dark="#000000", light="#ffffff")


def new_recovery_codes(n: int = RECOVERY_COUNT) -> list[str]:
    out = []
    for _ in range(n):
        raw = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(10))
        out.append(f"{raw[:5]}-{raw[5:]}")
    return out


def norm_recovery(code: str) -> str | None:
    """'ABCDE-fghjk', 'abcde fghjk' -> 'abcdefghjk'; None if it cannot be a recovery code."""
    s = re.sub(r"[\s-]", "", (code or "").lower())
    if len(s) != 10 or any(c not in RECOVERY_ALPHABET for c in s):
        return None
    return s


def recovery_digest(key: bytes, code: str) -> str:
    return hmac.new(key, code.encode("ascii"), hashlib.sha256).hexdigest()
