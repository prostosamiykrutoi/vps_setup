"""Reality X25519 keypair generation.

Xray's ``xray x25519`` emits a standard X25519 keypair, base64-RawURL encoded
(privateKey -> server, publicKey -> client). We reproduce that here so secrets
can be generated before the container is up. Two backends, in order:

1. Python ``cryptography`` (preferred, no container needed).
2. ``docker run --rm --entrypoint xray <3x-ui image> x25519`` (parsed).
"""
from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from .log import register_secret

if TYPE_CHECKING:
    from .context import Context


def _b64raw(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _via_cryptography() -> tuple[str, str] | None:
    # A broken cryptography install can raise more than ImportError (e.g. a Rust
    # PanicException from a missing cffi backend); treat any failure as "absent"
    # and fall back to the Docker path.
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        priv = X25519PrivateKey.generate()
    except BaseException:
        return None
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64raw(priv_raw), _b64raw(pub_raw)


def _via_docker(ctx: "Context") -> tuple[str, str] | None:
    image = ctx.profile.image_ref("xray_3xui")
    res = ctx.runner.run(
        ["docker", "run", "--rm", "--entrypoint", "xray", image, "x25519"],
        mutating=False, timeout=120,
    )
    if not res.ok:
        return None
    priv = pub = None
    for line in res.stdout.splitlines():
        low = line.lower()
        val = line.split(":", 1)[1].strip() if ":" in line else ""
        if "private" in low:
            priv = val
        elif "public" in low or "password" in low:
            pub = val
    if priv and pub:
        return priv, pub
    return None


def generate_keypair(ctx: "Context") -> tuple[str, str]:
    """Return (private_key_b64raw, public_key_b64raw)."""
    result = _via_cryptography() or _via_docker(ctx)
    if result is None:
        raise RuntimeError(
            "could not generate Reality x25519 keypair "
            "(install python3-cryptography or ensure Docker is available)")
    priv, pub = result
    register_secret(priv)
    return priv, pub
