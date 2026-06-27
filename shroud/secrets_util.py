"""CSPRNG secret generation.

All values here come from :mod:`secrets` (CSPRNG). Every generated secret is
registered with the logger so it can never leak into a log line.
"""
from __future__ import annotations

import secrets
import uuid as _uuid

from .log import register_secret


def _track(value: str) -> str:
    register_secret(value)
    return value


def gen_uuid() -> str:
    return _track(str(_uuid.uuid4()))


def gen_hex(nbytes: int = 16) -> str:
    return _track(secrets.token_hex(nbytes))


def gen_short_id() -> str:
    # Reality shortId: 1..16 hex chars; 8 bytes -> 16 hex is the common choice.
    return _track(secrets.token_hex(8))


def gen_password(nbytes: int = 18) -> str:
    # URL-safe, no padding; strip '-'/'_' ambiguity-free enough for a panel cred.
    return _track(secrets.token_urlsafe(nbytes))


def gen_username() -> str:
    return _track("adm_" + secrets.token_hex(4))


def gen_mtproto_secret() -> str:
    # MTProto secret = 16 random bytes, hex-encoded (32 hex chars).
    return _track(secrets.token_hex(16))


def gen_hysteria_auth() -> str:
    return _track(secrets.token_urlsafe(24))
