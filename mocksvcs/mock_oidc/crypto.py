"""RSA key management, JWT signing, and JWKS formatting."""

from __future__ import annotations

import hashlib
import time
from base64 import urlsafe_b64encode
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64_uint(value: int, length: int) -> str:
    """Encode an integer as a base64url-encoded unsigned big-endian."""
    return urlsafe_b64encode(value.to_bytes(length, byteorder="big")).rstrip(b"=").decode("ascii")


class KeyPair:
    """RSA-2048 key pair for signing JWTs and exposing JWKS."""

    def __init__(self) -> None:
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._public_key = self._private_key.public_key()

        # Compute a stable key ID from the public key DER
        pub_der = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._kid = hashlib.sha256(pub_der).hexdigest()[:16]

    @property
    def kid(self) -> str:
        return self._kid

    def private_key_pem(self) -> bytes:
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def jwks(self) -> dict[str, Any]:
        """Return the JWKS document containing the public key."""
        pub_numbers = self._public_key.public_numbers()
        n_bytes = (pub_numbers.n.bit_length() + 7) // 8
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self._kid,
                    "n": _b64_uint(pub_numbers.n, n_bytes),
                    "e": _b64_uint(pub_numbers.e, 3),
                }
            ]
        }

    def sign_jwt(
        self,
        claims: dict[str, Any],
        expires_in: int = 3600,
    ) -> str:
        """Sign a JWT with RS256 using this key pair."""
        now = int(time.time())
        payload = {
            **claims,
            "iat": now,
            "nbf": now,
            "exp": now + expires_in,
        }
        return jwt.encode(
            payload,
            self.private_key_pem(),
            algorithm="RS256",
            headers={"kid": self._kid},
        )

    def decode_jwt(
        self,
        token: str,
        *,
        verify_exp: bool = True,
        audience: str | None = None,
    ) -> dict[str, Any]:
        """Decode and verify a JWT signed by this key pair."""
        options: dict[str, Any] = {"verify_exp": verify_exp}
        if audience is None:
            options["verify_aud"] = False
        return jwt.decode(
            token,
            self._public_key,
            algorithms=["RS256"],
            options=options,
            audience=audience,
        )
