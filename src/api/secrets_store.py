"""
Envelope encryption for credentials at rest.

SECRETS_MASTER_KEY has been declared in .env.sample since the project started but was
referenced nowhere in code, and SystemConfig.is_encrypted was a column that nothing
ever set. This module makes both real.

Design decisions worth stating, because they are security-relevant:

1. **Fail closed.** With no master key configured, storing a secret raises. It does not
   silently fall back to plaintext. A store that quietly degrades is worse than one that
   refuses, because callers believe their data is protected.
2. **Key derivation, not key reuse.** The configured value is run through HKDF-SHA256 to
   produce the Fernet key, so any passphrase works and the stored ciphertext is not
   directly bound to the raw env-var contents.
3. **Nothing decrypted is logged or returned by list endpoints.** Callers get a masked
   preview (length and last four characters) unless they explicitly ask for the value.
   This is the same discipline applied to third-party secrets during the
   corp-functions-it-spend-tracker assessment: report name, classification, and length —
   never the value.
"""

import base64
import hashlib
import logging
import os
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

_MASTER_KEY_ENV = "SECRETS_MASTER_KEY"

# Bumped if the derivation scheme ever changes, so old ciphertext stays identifiable.
_SCHEME = "v1"
_HKDF_INFO = b"auditgithub-secrets-store-v1"
_PREFIX = f"enc:{_SCHEME}:"


class SecretsNotConfigured(RuntimeError):
    """Raised when an encryption operation is attempted with no master key present."""


class SecretDecryptionError(RuntimeError):
    """Raised when stored ciphertext cannot be decrypted with the current master key."""


def _master_key_material() -> Optional[bytes]:
    raw = os.environ.get(_MASTER_KEY_ENV, "").strip()
    if not raw:
        return None
    return raw.encode("utf-8")


def is_configured() -> bool:
    """Whether a master key is available. Safe to call from health checks."""
    return _master_key_material() is not None


def master_key_fingerprint() -> Optional[str]:
    """
    Short non-reversible fingerprint of the active master key.

    Lets an operator confirm which key is loaded, and detect an unintended key change,
    without exposing the key. Never log the key itself.
    """
    material = _master_key_material()
    if material is None:
        return None
    return hashlib.sha256(material).hexdigest()[:12]


def _fernet() -> Fernet:
    material = _master_key_material()
    if material is None:
        raise SecretsNotConfigured(
            f"{_MASTER_KEY_ENV} is not set. Credential storage is disabled rather than "
            "falling back to plaintext. Generate one with: "
            "python -c \"import secrets;print(secrets.token_urlsafe(48))\""
        )
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    ).derive(material)
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt(plaintext: str) -> str:
    """Encrypt a value for storage. Returns a prefixed, self-describing string."""
    if plaintext is None:
        raise ValueError("Cannot encrypt None")
    token = _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
    return f"{_PREFIX}{token}"


def is_encrypted_value(stored: Optional[str]) -> bool:
    return bool(stored) and stored.startswith("enc:")


def decrypt(stored: str) -> str:
    """
    Decrypt a stored value.

    Values without the encryption prefix are returned unchanged, so pre-existing
    plaintext SystemConfig rows keep working during migration.
    """
    if not is_encrypted_value(stored):
        return stored
    if not stored.startswith(_PREFIX):
        raise SecretDecryptionError(
            f"Unrecognised encryption scheme on stored value (expected {_SCHEME})."
        )
    token = stored[len(_PREFIX):]
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except SecretsNotConfigured:
        raise
    except InvalidToken as exc:
        raise SecretDecryptionError(
            f"Stored secret could not be decrypted. The {_MASTER_KEY_ENV} in use "
            f"(fingerprint {master_key_fingerprint()}) is probably not the key it was "
            "encrypted with. Rotating the master key requires re-encrypting every stored "
            "secret; it is not a drop-in replacement."
        ) from exc


def mask(value: Optional[str], keep_last: int = 4) -> Dict[str, Any]:
    """
    Non-reversible descriptor of a secret, safe to return from an API or write to a log.

    Reports presence, length, and a short suffix — enough to confirm which credential is
    loaded and to spot truncation, without disclosing it. Length alone is meaningful:
    an Azure AD client secret is 40 characters, which is how the leaked
    it-spend-tracker credential was classified without ever reading its value.
    """
    if not value:
        return {"present": False, "length": 0, "preview": None}
    keep = max(0, min(keep_last, len(value)))
    return {
        "present": True,
        "length": len(value),
        "preview": ("*" * (len(value) - keep)) + value[len(value) - keep:] if keep else "*" * len(value),
    }


# =============================================================================
# SystemConfig-backed store
# =============================================================================

def set_system_secret(db, key: str, value: str, description: Optional[str] = None) -> None:
    """
    Store an encrypted value in system_config, setting is_encrypted correctly.

    Uses a late import of models to avoid a circular dependency at module load.
    """
    from . import models

    ciphertext = encrypt(value)
    config = db.query(models.SystemConfig).filter(models.SystemConfig.key == key).first()
    if config:
        config.value = ciphertext
        config.is_encrypted = True
        if description:
            config.description = description
    else:
        db.add(models.SystemConfig(
            key=key,
            value=ciphertext,
            is_encrypted=True,
            description=description,
        ))
    db.commit()
    logger.info(f"Stored encrypted system secret '{key}' (master key {master_key_fingerprint()})")


def get_system_secret(db, key: str) -> Optional[str]:
    """Retrieve and decrypt a system_config value. Returns None if absent."""
    from . import models

    config = db.query(models.SystemConfig).filter(models.SystemConfig.key == key).first()
    if not config or config.value is None:
        return None
    return decrypt(config.value)


def resolve_secret(db, config_key: str, env_var: str) -> Optional[str]:
    """
    Resolve a secret from the database first, then the environment.

    Database wins so that a credential rotated through the UI takes effect without a
    redeploy, while .env keeps working as a bootstrap path for local development.
    """
    try:
        stored = get_system_secret(db, config_key)
        if stored:
            return stored
    except (SecretsNotConfigured, SecretDecryptionError) as exc:
        # Do not fall through silently — an operator needs to know the DB copy is
        # unreadable rather than merely absent.
        logger.error(f"Stored secret '{config_key}' is unreadable: {exc}")
    value = os.environ.get(env_var, "").strip()
    return value or None
