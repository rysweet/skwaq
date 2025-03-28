"""Encryption module for Skwaq.

This module provides encryption functionality for the Skwaq
vulnerability assessment copilot, including encryption of sensitive
data and secure credential handling.
"""

import base64
import json
import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, TypeVar, Union, cast

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class EncryptionError(Exception):
    """Exception raised for encryption-related errors."""

    pass


class DataClassification(Enum):
    """Classification levels for data sensitivity."""

    PUBLIC = "public"  # Public data, no encryption needed
    INTERNAL = "internal"  # Internal data, basic encryption needed
    CONFIDENTIAL = "confidential"  # Confidential data, strong encryption needed
    RESTRICTED = "restricted"  # Restricted data, highest level encryption needed


@dataclass
class EncryptionKey:
    """Encryption key container."""

    key: bytes
    algorithm: str = "fernet"
    created_at: float = field(default_factory=lambda: __import__("time").time())
    key_id: str = field(default_factory=lambda: secrets.token_hex(8))

    @property
    def key_string(self) -> str:
        """Get the key as a string.

        Returns:
            Key as string
        """
        return self.key.decode() if hasattr(self.key, "decode") else self.key


class EncryptionManager:
    """Manager for encryption operations."""

    _instance = None

    def __new__(cls) -> "EncryptionManager":
        """Create a singleton instance.

        Returns:
            Singleton instance
        """
        if cls._instance is None:
            cls._instance = super(EncryptionManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the encryption manager."""
        if self._initialized:
            return

        self._initialized = True
        self._default_key = self._get_or_create_encryption_key()
        self._data_keys: Dict[DataClassification, EncryptionKey] = {
            DataClassification.PUBLIC: EncryptionKey(
                key=b"no-encryption-used", algorithm="none"
            ),
            DataClassification.INTERNAL: self._default_key,
            DataClassification.CONFIDENTIAL: self._default_key,
            DataClassification.RESTRICTED: self._default_key,
        }

        # Initialize each classification with its own key if available
        for classification in DataClassification:
            if classification != DataClassification.PUBLIC:
                key = self._get_or_create_encryption_key(f"{classification.value}_key")
                self._data_keys[classification] = key

    def _get_or_create_encryption_key(
        self, config_key: str = "encryption.default_key"
    ) -> EncryptionKey:
        """Get or create an encryption key.

        Args:
            config_key: Configuration key for storing the encryption key

        Returns:
            EncryptionKey instance
        """
        config = get_config()
        key_str = config.get(config_key)

        if not key_str:
            # Generate a new key
            key = Fernet.generate_key()
            key_str = key.decode()
            config.set(config_key, key_str, source="encryption_manager")
            logger.info(f"Generated new encryption key for {config_key}")
        else:
            key = key_str.encode()

        return EncryptionKey(key=key)

    def encrypt(
        self,
        data: Union[str, bytes, Dict[str, Any]],
        classification: DataClassification = DataClassification.INTERNAL,
    ) -> bytes:
        """Encrypt data.

        Args:
            data: Data to encrypt
            classification: Data classification

        Returns:
            Encrypted data

        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Skip encryption for public data
            if classification == DataClassification.PUBLIC:
                if isinstance(data, dict):
                    data = json.dumps(data).encode()
                elif isinstance(data, str):
                    data = data.encode()

                # Add a prefix to indicate no encryption
                return b"PLAIN:" + data

            # Convert data to bytes
            if isinstance(data, dict):
                data = json.dumps(data).encode()
            elif isinstance(data, str):
                data = data.encode()

            # Get the appropriate encryption key
            key = self._data_keys.get(classification, self._default_key)

            # Encrypt the data
            fernet = Fernet(key.key)
            encrypted_data = fernet.encrypt(data)

            # Add metadata (key ID, classification)
            metadata = {
                "kid": key.key_id,
                "alg": key.algorithm,
                "cls": classification.value,
            }

            metadata_json = json.dumps(metadata).encode()
            metadata_b64 = base64.b64encode(metadata_json)

            # Combine metadata with encrypted data
            return b"ENC:" + metadata_b64 + b":" + encrypted_data

        except Exception as e:
            logger.error(f"Encryption error: {e}")
            raise EncryptionError(f"Failed to encrypt data: {e}")

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data.

        Args:
            encrypted_data: Encrypted data

        Returns:
            Decrypted data

        Raises:
            EncryptionError: If decryption fails
        """
        try:
            # Check if the data is encrypted
            if encrypted_data.startswith(b"PLAIN:"):
                # No encryption, just return the data
                return encrypted_data[6:]

            if not encrypted_data.startswith(b"ENC:"):
                raise EncryptionError("Invalid encrypted data format")

            # Split the data into metadata and encrypted content
            parts = encrypted_data[4:].split(b":", 1)
            if len(parts) != 2:
                raise EncryptionError("Invalid encrypted data format")

            metadata_b64, encrypted_content = parts

            # Parse metadata
            try:
                metadata_json = base64.b64decode(metadata_b64)
                metadata = json.loads(metadata_json)

                key_id = metadata.get("kid")
                algorithm = metadata.get("alg")
                classification = metadata.get("cls")

                # Find the key based on classification
                if classification:
                    data_class = DataClassification(classification)
                    key = self._data_keys.get(data_class, self._default_key)
                else:
                    key = self._default_key

            except Exception as e:
                logger.warning(f"Error parsing metadata, using default key: {e}")
                key = self._default_key

            # Decrypt the data
            fernet = Fernet(key.key)
            return fernet.decrypt(encrypted_content)

        except Exception as e:
            logger.error(f"Decryption error: {e}")
            raise EncryptionError(f"Failed to decrypt data: {e}")

    def encrypt_dict(
        self,
        data: Dict[str, Any],
        classification: DataClassification = DataClassification.INTERNAL,
    ) -> str:
        """Encrypt a dictionary to a string.

        Args:
            data: Dictionary to encrypt
            classification: Data classification

        Returns:
            Base64-encoded encrypted JSON string

        Raises:
            EncryptionError: If encryption fails
        """
        encrypted_data = self.encrypt(data, classification)
        return base64.b64encode(encrypted_data).decode()

    def decrypt_dict(self, encrypted_str: str) -> Dict[str, Any]:
        """Decrypt a string to a dictionary.

        Args:
            encrypted_str: Base64-encoded encrypted string

        Returns:
            Decrypted dictionary

        Raises:
            EncryptionError: If decryption fails
        """
        try:
            encrypted_data = base64.b64decode(encrypted_str)
            decrypted_data = self.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            logger.error(f"Error decrypting dictionary: {e}")
            raise EncryptionError(f"Failed to decrypt dictionary: {e}")

    def rotate_key(self, classification: DataClassification) -> None:
        """Rotate the encryption key for a classification level.

        Args:
            classification: Data classification

        Raises:
            EncryptionError: If key rotation fails
        """
        try:
            # Skip rotation for public data
            if classification == DataClassification.PUBLIC:
                return

            # Generate a new key
            new_key = Fernet.generate_key()
            key = EncryptionKey(key=new_key)

            # Update the configuration
            config = get_config()
            config_key = f"encryption.{classification.value}_key"
            config.set(config_key, key.key_string, source="encryption_manager")

            # Update the key in our collection
            self._data_keys[classification] = key

            logger.info(f"Rotated encryption key for {classification.value}")
        except Exception as e:
            logger.error(f"Key rotation error: {e}")
            raise EncryptionError(f"Failed to rotate key: {e}")

    def derive_key_from_password(
        self, password: str, salt: Optional[bytes] = None
    ) -> bytes:
        """Derive a key from a password using PBKDF2.

        Args:
            password: Password
            salt: Optional salt (generated if not provided)

        Returns:
            Derived key
        """
        if salt is None:
            salt = os.urandom(16)

        # Derive the key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )

        return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def get_encryption_manager() -> EncryptionManager:
    """Get the global encryption manager instance.

    Returns:
        EncryptionManager instance
    """
    return EncryptionManager()


# Helper functions for common encryption tasks


def encrypt_sensitive_data(data: Union[str, bytes, Dict[str, Any]]) -> bytes:
    """Encrypt sensitive data with CONFIDENTIAL classification.

    Args:
        data: Data to encrypt

    Returns:
        Encrypted data
    """
    manager = get_encryption_manager()
    return manager.encrypt(data, DataClassification.CONFIDENTIAL)


def decrypt_sensitive_data(encrypted_data: bytes) -> bytes:
    """Decrypt sensitive data.

    Args:
        encrypted_data: Encrypted data

    Returns:
        Decrypted data
    """
    manager = get_encryption_manager()
    return manager.decrypt(encrypted_data)


def encrypt_config_value(value: str) -> str:
    """Encrypt a configuration value.

    Args:
        value: Value to encrypt

    Returns:
        Encrypted value as string
    """
    manager = get_encryption_manager()
    encrypted = manager.encrypt(value, DataClassification.CONFIDENTIAL)
    return base64.b64encode(encrypted).decode()


def decrypt_config_value(encrypted_value: str) -> str:
    """Decrypt a configuration value.

    Args:
        encrypted_value: Encrypted value

    Returns:
        Decrypted value
    """
    manager = get_encryption_manager()
    encrypted_bytes = base64.b64decode(encrypted_value)
    decrypted = manager.decrypt(encrypted_bytes)
    return decrypted.decode()
