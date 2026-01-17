"""
Secrets Manager Abstraction Layer

Provides a unified interface for credential storage and retrieval.
Supports multiple backends:
- MockSecretsManager: In-memory storage for development
- VaultSecretsManager: HashiCorp Vault (production)
- AWSSecretsManager: AWS Secrets Manager (production)

The interface ensures code works identically regardless of backend,
enabling seamless transition from development to production.
"""

import os
import json
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Optional, Any, List
from dataclasses import dataclass
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import hashlib


@dataclass
class SecretMetadata:
    """Metadata about a stored secret."""
    key: str
    created_at: datetime
    updated_at: datetime
    version: int
    tags: Dict[str, str]


class SecretsManagerInterface(ABC):
    """
    Abstract interface for secrets management.
    
    All secrets managers must implement this interface to ensure
    consistent behavior across development and production environments.
    """
    
    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        """
        Retrieve a secret by key.
        
        Args:
            key: Secret identifier (e.g., 'sealmindset/github_token')
            
        Returns:
            Decrypted secret value or None if not found
        """
        pass
    
    @abstractmethod
    async def set_secret(self, key: str, value: str, tags: Optional[Dict[str, str]] = None) -> bool:
        """
        Store a secret.
        
        Args:
            key: Secret identifier
            value: Secret value to store
            tags: Optional metadata tags
            
        Returns:
            True if successful
        """
        pass
    
    @abstractmethod
    async def delete_secret(self, key: str) -> bool:
        """
        Delete a secret.
        
        Args:
            key: Secret identifier
            
        Returns:
            True if deleted, False if not found
        """
        pass
    
    @abstractmethod
    async def list_secrets(self, prefix: Optional[str] = None) -> List[SecretMetadata]:
        """
        List secrets, optionally filtered by prefix.
        
        Args:
            prefix: Optional key prefix filter (e.g., 'sealmindset/')
            
        Returns:
            List of secret metadata (not values)
        """
        pass
    
    @abstractmethod
    async def secret_exists(self, key: str) -> bool:
        """Check if a secret exists."""
        pass
    
    @abstractmethod
    async def rotate_secret(self, key: str, new_value: str) -> bool:
        """
        Rotate a secret to a new value.
        
        Increments version and updates timestamp.
        
        Args:
            key: Secret identifier
            new_value: New secret value
            
        Returns:
            True if rotated successfully
        """
        pass


class MockSecretsManager(SecretsManagerInterface):
    """
    In-memory secrets manager for development.
    
    Stores secrets encrypted in memory with optional file persistence.
    Mimics the exact workflow of production secrets managers.
    
    Features:
    - Encryption at rest (Fernet/AES-128)
    - Version tracking
    - Tag support
    - Optional file persistence for dev restarts
    """
    
    def __init__(
        self,
        encryption_key: Optional[str] = None,
        persistence_file: Optional[str] = None
    ):
        """
        Initialize mock secrets manager.
        
        Args:
            encryption_key: 32-byte base64 key for encryption.
                           If None, generates a new key.
            persistence_file: Optional file path to persist secrets
                             across restarts (development only)
        """
        if encryption_key:
            self._cipher = Fernet(encryption_key.encode())
        else:
            # Generate key from environment or create new
            env_key = os.environ.get('SECRETS_MASTER_KEY')
            if env_key:
                # Derive Fernet key from master key
                derived = hashlib.sha256(env_key.encode()).digest()
                fernet_key = base64.urlsafe_b64encode(derived)
                self._cipher = Fernet(fernet_key)
            else:
                self._cipher = Fernet(Fernet.generate_key())
        
        self._persistence_file = persistence_file
        self._secrets: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        
        # Load persisted secrets if file exists
        if persistence_file and os.path.exists(persistence_file):
            self._load_from_file()
    
    def _load_from_file(self):
        """Load secrets from persistence file."""
        try:
            with open(self._persistence_file, 'r') as f:
                data = json.load(f)
                self._secrets = data
                print(f"[SecretsManager] Loaded {len(self._secrets)} secrets from {self._persistence_file}")
        except Exception as e:
            print(f"[SecretsManager] Failed to load secrets: {e}")
            self._secrets = {}
    
    def _save_to_file(self):
        """Save secrets to persistence file."""
        if not self._persistence_file:
            return
        try:
            with open(self._persistence_file, 'w') as f:
                json.dump(self._secrets, f, indent=2, default=str)
        except Exception as e:
            print(f"[SecretsManager] Failed to save secrets: {e}")
    
    def _encrypt(self, value: str) -> str:
        """Encrypt a value."""
        return self._cipher.encrypt(value.encode()).decode()
    
    def _decrypt(self, encrypted: str) -> str:
        """Decrypt a value."""
        return self._cipher.decrypt(encrypted.encode()).decode()
    
    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve and decrypt a secret."""
        async with self._lock:
            if key not in self._secrets:
                return None
            
            encrypted = self._secrets[key]['value']
            return self._decrypt(encrypted)
    
    async def set_secret(self, key: str, value: str, tags: Optional[Dict[str, str]] = None) -> bool:
        """Store an encrypted secret."""
        async with self._lock:
            now = datetime.utcnow().isoformat()
            
            if key in self._secrets:
                # Update existing
                self._secrets[key]['value'] = self._encrypt(value)
                self._secrets[key]['updated_at'] = now
                self._secrets[key]['version'] += 1
                if tags:
                    self._secrets[key]['tags'].update(tags)
            else:
                # Create new
                self._secrets[key] = {
                    'value': self._encrypt(value),
                    'created_at': now,
                    'updated_at': now,
                    'version': 1,
                    'tags': tags or {}
                }
            
            self._save_to_file()
            return True
    
    async def delete_secret(self, key: str) -> bool:
        """Delete a secret."""
        async with self._lock:
            if key not in self._secrets:
                return False
            
            del self._secrets[key]
            self._save_to_file()
            return True
    
    async def list_secrets(self, prefix: Optional[str] = None) -> List[SecretMetadata]:
        """List secret metadata."""
        async with self._lock:
            results = []
            for key, data in self._secrets.items():
                if prefix and not key.startswith(prefix):
                    continue
                
                results.append(SecretMetadata(
                    key=key,
                    created_at=datetime.fromisoformat(data['created_at']),
                    updated_at=datetime.fromisoformat(data['updated_at']),
                    version=data['version'],
                    tags=data.get('tags', {})
                ))
            
            return results
    
    async def secret_exists(self, key: str) -> bool:
        """Check if secret exists."""
        async with self._lock:
            return key in self._secrets
    
    async def rotate_secret(self, key: str, new_value: str) -> bool:
        """Rotate secret to new value."""
        async with self._lock:
            if key not in self._secrets:
                return False
            
            now = datetime.utcnow().isoformat()
            self._secrets[key]['value'] = self._encrypt(new_value)
            self._secrets[key]['updated_at'] = now
            self._secrets[key]['version'] += 1
            
            self._save_to_file()
            print(f"[SecretsManager] Rotated secret: {key} (v{self._secrets[key]['version']})")
            return True


class VaultSecretsManager(SecretsManagerInterface):
    """
    HashiCorp Vault secrets manager for production.
    
    Placeholder implementation - to be completed when Vault is configured.
    """
    
    def __init__(self, vault_addr: str, vault_token: str, mount_path: str = "secret"):
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.mount_path = mount_path
        # TODO: Initialize hvac client
    
    async def get_secret(self, key: str) -> Optional[str]:
        raise NotImplementedError("Vault integration pending")
    
    async def set_secret(self, key: str, value: str, tags: Optional[Dict[str, str]] = None) -> bool:
        raise NotImplementedError("Vault integration pending")
    
    async def delete_secret(self, key: str) -> bool:
        raise NotImplementedError("Vault integration pending")
    
    async def list_secrets(self, prefix: Optional[str] = None) -> List[SecretMetadata]:
        raise NotImplementedError("Vault integration pending")
    
    async def secret_exists(self, key: str) -> bool:
        raise NotImplementedError("Vault integration pending")
    
    async def rotate_secret(self, key: str, new_value: str) -> bool:
        raise NotImplementedError("Vault integration pending")


# =============================================================================
# Factory and Global Instance
# =============================================================================

_secrets_manager: Optional[SecretsManagerInterface] = None


def get_secrets_manager() -> SecretsManagerInterface:
    """
    Get the global secrets manager instance.
    
    Creates a MockSecretsManager by default for development.
    Configure via environment variables for production.
    """
    global _secrets_manager
    
    if _secrets_manager is None:
        backend = os.environ.get('SECRETS_BACKEND', 'mock')
        
        if backend == 'vault':
            vault_addr = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
            vault_token = os.environ.get('VAULT_TOKEN', '')
            _secrets_manager = VaultSecretsManager(vault_addr, vault_token)
        else:
            # Default to mock for development
            persistence_file = os.environ.get(
                'SECRETS_PERSISTENCE_FILE',
                '/tmp/auditgithub_secrets.json'
            )
            _secrets_manager = MockSecretsManager(
                persistence_file=persistence_file
            )
    
    return _secrets_manager


async def initialize_secrets_from_env():
    """
    Initialize secrets manager with credentials from environment.
    
    Loads credentials from .env file in two formats:
    1. Default org: GITHUB_TOKEN + GITHUB_ORG
    2. Additional orgs: ORG_{NAME}_TOKEN + ORG_{NAME}_GITHUB
    
    Call this on application startup.
    """
    manager = get_secrets_manager()
    orgs_loaded = []
    
    # Load default organization credentials (GITHUB_TOKEN + GITHUB_ORG)
    github_token = os.environ.get('GITHUB_TOKEN')
    github_org = os.environ.get('GITHUB_ORG')
    
    if github_token and github_org:
        org_name = github_org.lower()
        await manager.set_secret(
            f"{org_name}/github_token",
            github_token,
            tags={'type': 'github_token', 'org': org_name}
        )
        await manager.set_secret(
            f"{org_name}/github_org",
            github_org,
            tags={'type': 'github_org', 'org': org_name}
        )
        orgs_loaded.append(org_name)
    
    # Scan for additional organizations: ORG_{NAME}_TOKEN pattern
    # Example: ORG_ACME_TOKEN=ghp_xxx, ORG_ACME_GITHUB=acme-corp
    org_tokens = {}
    org_githubs = {}
    
    for key, value in os.environ.items():
        if key.startswith('ORG_') and key.endswith('_TOKEN'):
            # Extract org name: ORG_ACME_TOKEN -> acme
            org_name = key[4:-6].lower()  # Remove 'ORG_' prefix and '_TOKEN' suffix
            org_tokens[org_name] = value
        elif key.startswith('ORG_') and key.endswith('_GITHUB'):
            # Extract org name: ORG_ACME_GITHUB -> acme
            org_name = key[4:-7].lower()  # Remove 'ORG_' prefix and '_GITHUB' suffix
            org_githubs[org_name] = value
    
    # Store additional organization credentials
    for org_name, token in org_tokens.items():
        github_org_name = org_githubs.get(org_name, org_name)  # Default to org_name if not specified
        
        await manager.set_secret(
            f"{org_name}/github_token",
            token,
            tags={'type': 'github_token', 'org': org_name}
        )
        await manager.set_secret(
            f"{org_name}/github_org",
            github_org_name,
            tags={'type': 'github_org', 'org': org_name}
        )
        orgs_loaded.append(org_name)
    
    # Load global API keys (silently)
    anthropic_key = os.environ.get('ANTHROPIC_API_KEY')
    if anthropic_key:
        await manager.set_secret(
            'global/anthropic_api_key',
            anthropic_key,
            tags={'type': 'api_key', 'service': 'anthropic'}
        )
    
    openai_key = os.environ.get('OPENAI_API_KEY')
    if openai_key:
        await manager.set_secret(
            'global/openai_api_key',
            openai_key,
            tags={'type': 'api_key', 'service': 'openai'}
        )
    
    print(f"[SecretsManager] Loaded {len(orgs_loaded)} org(s) from env: {', '.join(orgs_loaded)}")


# =============================================================================
# Convenience Functions
# =============================================================================

async def get_org_credentials(org_name: str) -> Dict[str, str]:
    """
    Get all credentials for an organization.

    Args:
        org_name: Organization name (e.g., 'sealmindset')

    Returns:
        Dict with keys like 'github_token', 'github_org', etc.
    """
    manager = get_secrets_manager()
    org_name = org_name.lower()

    credentials = {}

    # Get org-specific secrets first, then fall back to .env
    github_token = await manager.get_secret(f"{org_name}/github_token")
    if github_token:
        credentials['github_token'] = github_token
    else:
        # Fall back to global GITHUB_TOKEN from .env
        env_token = os.getenv('GITHUB_TOKEN')
        if env_token:
            credentials['github_token'] = env_token

    github_org = await manager.get_secret(f"{org_name}/github_org")
    if github_org:
        credentials['github_org'] = github_org
    else:
        # Fall back to DEFAULT_GITHUB_ORG or org_name from .env
        env_org = os.getenv('DEFAULT_GITHUB_ORG') or os.getenv('GITHUB_ORG')
        if env_org:
            credentials['github_org'] = env_org
        else:
            # Use org_name as fallback
            credentials['github_org'] = org_name

    # Get global secrets (shared across orgs)
    anthropic_key = await manager.get_secret('global/anthropic_api_key')
    if anthropic_key:
        credentials['anthropic_api_key'] = anthropic_key
    elif os.getenv('ANTHROPIC_API_KEY'):
        credentials['anthropic_api_key'] = os.getenv('ANTHROPIC_API_KEY')

    openai_key = await manager.get_secret('global/openai_api_key')
    if openai_key:
        credentials['openai_api_key'] = openai_key
    elif os.getenv('OPENAI_API_KEY'):
        credentials['openai_api_key'] = os.getenv('OPENAI_API_KEY')

    return credentials


async def set_org_credentials(
    org_name: str,
    github_token: str,
    github_org: Optional[str] = None
) -> bool:
    """
    Set credentials for an organization.
    
    Args:
        org_name: Organization name
        github_token: GitHub personal access token
        github_org: GitHub organization name (defaults to org_name)
        
    Returns:
        True if successful
    """
    manager = get_secrets_manager()
    org_name = org_name.lower()
    github_org = github_org or org_name
    
    await manager.set_secret(
        f"{org_name}/github_token",
        github_token,
        tags={'type': 'github_token', 'org': org_name}
    )
    
    await manager.set_secret(
        f"{org_name}/github_org",
        github_org,
        tags={'type': 'github_org', 'org': org_name}
    )
    
    return True


async def list_configured_orgs() -> List[str]:
    """
    List all organizations with configured credentials.
    
    Returns:
        List of organization names
    """
    manager = get_secrets_manager()
    secrets = await manager.list_secrets()
    
    orgs = set()
    for secret in secrets:
        if '/' in secret.key and not secret.key.startswith('global/'):
            org_name = secret.key.split('/')[0]
            orgs.add(org_name)
    
    return sorted(list(orgs))
