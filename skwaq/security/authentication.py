"""Authentication module for Skwaq.

This module provides authentication functionality for the Skwaq
vulnerability assessment copilot, including user verification,
token management, and secure credential handling.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import time
import uuid

import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from skwaq.events.system_events import SystemEvent, publish
from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class AuthenticationError(Exception):
    """Exception raised for authentication failures."""

    pass


class CredentialError(Exception):
    """Exception raised for credential handling errors."""

    pass


class TokenError(Exception):
    """Exception raised for token-related errors."""

    pass


class AuthEvent(SystemEvent):
    """Event emitted for authentication-related actions."""

    def __init__(
        self,
        action: str,
        user_id: str,
        success: bool,
        source_ip: Optional[str] = None,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an authentication event.

        Args:
            action: The authentication action performed
            user_id: ID of the user (anonymized if necessary)
            success: Whether the authentication was successful
            source_ip: Optional source IP address (anonymized)
            message: Optional message describing the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender="authentication",
            message=message
            or f"Authentication {action}: {'success' if success else 'failed'} for user {user_id}",
            target=None,
            metadata=metadata or {},
        )
        self.action = action
        self.user_id = user_id
        self.success = success
        self.source_ip = source_ip


class AuthRole(Enum):
    """Roles for authentication and authorization."""

    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"
    SYSTEM = "system"


@dataclass
class UserCredentials:
    """User credentials for authentication."""

    username: str
    password_hash: str
    salt: str
    roles: Set[AuthRole] = field(default_factory=set)
    api_keys: Dict[str, str] = field(default_factory=dict)
    last_login: Optional[float] = None
    failed_attempts: int = 0
    locked_until: Optional[float] = None
    user_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage.

        Returns:
            Dictionary representation
        """
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "salt": self.salt,
            "roles": [role.value for role in self.roles],
            "api_keys": self.api_keys,
            "last_login": self.last_login,
            "failed_attempts": self.failed_attempts,
            "locked_until": self.locked_until,
            "user_id": self.user_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserCredentials":
        """Create from dictionary.

        Args:
            data: Dictionary with user data

        Returns:
            UserCredentials object
        """
        roles = set(AuthRole(role) for role in data.get("roles", []))
        return cls(
            username=data["username"],
            password_hash=data["password_hash"],
            salt=data["salt"],
            roles=roles,
            api_keys=data.get("api_keys", {}),
            last_login=data.get("last_login"),
            failed_attempts=data.get("failed_attempts", 0),
            locked_until=data.get("locked_until"),
            user_id=data.get("user_id", str(uuid.uuid4())),
        )


class AuthenticationManager:
    """Manager for authentication operations."""

    _instance = None

    def __new__(cls) -> "AuthenticationManager":
        """Create a singleton instance.

        Returns:
            Singleton instance
        """
        if cls._instance is None:
            cls._instance = super(AuthenticationManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the authentication manager."""
        if self._initialized:
            return

        self._initialized = True
        self._users: Dict[str, UserCredentials] = {}
        self._tokens: Dict[str, Dict[str, Any]] = {}
        self._token_secret = self._get_or_create_token_secret()
        self._credentials_key = self._get_or_create_credentials_key()
        self._max_failed_attempts = 5
        self._lockout_period = 300  # 5 minutes

        # Load users from secure storage
        self._load_users()

        # Ensure admin user exists
        self._ensure_admin_user()

    def _get_or_create_token_secret(self) -> str:
        """Get or create a secret for token signing.

        Returns:
            Token signing secret
        """
        config = get_config()
        secret = config.get("security.token_secret")

        if not secret:
            # Generate a new secret
            secret = secrets.token_hex(32)
            config.set("security.token_secret", secret, source="authentication_manager")
            logger.info("Generated new token signing secret")

        return secret

    def _get_or_create_credentials_key(self) -> bytes:
        """Get or create a key for encrypting credentials.

        Returns:
            Encryption key
        """
        config = get_config()
        key_str = config.get("security.credentials_key")

        if not key_str:
            # Generate a new key
            key = Fernet.generate_key()
            key_str = key.decode()
            config.set(
                "security.credentials_key", key_str, source="authentication_manager"
            )
            logger.info("Generated new credentials encryption key")
        else:
            key = key_str.encode()

        return key

    def _load_users(self) -> None:
        """Load users from secure storage."""
        try:
            config = get_config()
            users_home = config.get(
                "security.users_file", os.path.expanduser("~/.skwaq/users.json")
            )

            if os.path.exists(users_home):
                with open(users_home, "r") as f:
                    encrypted_data = f.read()

                if encrypted_data:
                    # Decrypt the data
                    fernet = Fernet(self._credentials_key)
                    decrypted_data = fernet.decrypt(encrypted_data.encode())
                    user_data = json.loads(decrypted_data)

                    # Load the users
                    for username, user_dict in user_data.items():
                        self._users[username] = UserCredentials.from_dict(user_dict)

                    logger.info(f"Loaded {len(self._users)} users from secure storage")
        except Exception as e:
            logger.error(f"Error loading users: {e}")

    def _save_users(self) -> None:
        """Save users to secure storage."""
        try:
            config = get_config()
            users_home = config.get(
                "security.users_file", os.path.expanduser("~/.skwaq/users.json")
            )

            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(users_home), exist_ok=True)

            # Convert users to dictionary
            user_data = {
                username: user.to_dict() for username, user in self._users.items()
            }

            # Encrypt the data
            fernet = Fernet(self._credentials_key)
            encrypted_data = fernet.encrypt(json.dumps(user_data).encode())

            # Save to file
            with open(users_home, "w") as f:
                f.write(encrypted_data.decode())

            logger.info(f"Saved {len(self._users)} users to secure storage")
        except Exception as e:
            logger.error(f"Error saving users: {e}")

    def _ensure_admin_user(self) -> None:
        """Ensure that an admin user exists."""
        config = get_config()
        admin_username = config.get("security.admin_username", "admin")

        if admin_username not in self._users:
            # Generate a random password if none is defined
            admin_password = config.get("security.admin_password")
            if not admin_password:
                admin_password = secrets.token_urlsafe(12)
                logger.warning(f"Generated random admin password: {admin_password}")
                logger.warning("Please change this password immediately!")

            # Create the admin user
            self.create_user(
                username=admin_username,
                password=admin_password,
                roles={AuthRole.ADMIN, AuthRole.USER},
            )

            logger.info(f"Created admin user: {admin_username}")

    def _hash_password(
        self, password: str, salt: Optional[str] = None
    ) -> Tuple[str, str]:
        """Hash a password with a salt.

        Args:
            password: The password to hash
            salt: Optional salt (generated if not provided)

        Returns:
            Tuple of (password_hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)

        # Hash the password
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt.encode(),
            100000,  # Number of iterations
        )

        # Convert to hex
        password_hash = key.hex()

        return password_hash, salt

    def create_user(
        self, username: str, password: str, roles: Set[AuthRole] = None
    ) -> UserCredentials:
        """Create a new user.

        Args:
            username: Username
            password: Password
            roles: Set of roles

        Returns:
            UserCredentials object

        Raises:
            AuthenticationError: If the user already exists
        """
        if username in self._users:
            raise AuthenticationError(f"User {username} already exists")

        # Hash the password
        password_hash, salt = self._hash_password(password)

        # Create the user
        user = UserCredentials(
            username=username,
            password_hash=password_hash,
            salt=salt,
            roles=roles or {AuthRole.USER},
        )

        # Add to users
        self._users[username] = user

        # Save users
        self._save_users()

        # Emit event
        publish(
            AuthEvent(
                action="create_user",
                user_id=user.user_id,
                success=True,
                message=f"Created user {username} with roles {[role.value for role in user.roles]}",
            )
        )

        return user

    def authenticate(
        self, username: str, password: str, source_ip: Optional[str] = None
    ) -> Optional[UserCredentials]:
        """Authenticate a user with password.

        Args:
            username: Username
            password: Password
            source_ip: Optional source IP for logging

        Returns:
            UserCredentials if authentication successful, None otherwise
        """
        user = self._users.get(username)

        if not user:
            # Always take the same amount of time to prevent timing attacks
            self._hash_password("dummy_password", "dummy_salt")

            # Log failed attempt
            publish(
                AuthEvent(
                    action="password_login",
                    user_id="unknown",
                    success=False,
                    source_ip=source_ip,
                    message=f"Invalid username: {username}",
                )
            )

            return None

        # Check if account is locked
        if user.locked_until and user.locked_until > time.time():
            # Calculate remaining lockout time
            remaining = int(user.locked_until - time.time())

            # Log failed attempt
            publish(
                AuthEvent(
                    action="password_login",
                    user_id=user.user_id,
                    success=False,
                    source_ip=source_ip,
                    message=f"Account locked: {username} (remaining: {remaining}s)",
                )
            )

            return None

        # Reset lockout if it's expired
        if user.locked_until and user.locked_until <= time.time():
            user.locked_until = None
            user.failed_attempts = 0

        # Hash the password with the user's salt
        password_hash, _ = self._hash_password(password, user.salt)

        # Check if the password is correct
        if user.password_hash != password_hash:
            # Increment failed attempts
            user.failed_attempts += 1

            # Lock the account if too many failed attempts
            if user.failed_attempts >= self._max_failed_attempts:
                user.locked_until = time.time() + self._lockout_period
                logger.warning(
                    f"Account locked for {self._lockout_period}s: {username} (failed attempts: {user.failed_attempts})"
                )

            # Save users
            self._save_users()

            # Log failed attempt
            publish(
                AuthEvent(
                    action="password_login",
                    user_id=user.user_id,
                    success=False,
                    source_ip=source_ip,
                    message=f"Invalid password for {username} (attempts: {user.failed_attempts})",
                )
            )

            return None

        # Authentication successful
        user.last_login = time.time()
        user.failed_attempts = 0
        user.locked_until = None

        # Save users
        self._save_users()

        # Log successful attempt
        publish(
            AuthEvent(
                action="password_login",
                user_id=user.user_id,
                success=True,
                source_ip=source_ip,
                message=f"Successful login for {username}",
            )
        )

        return user

    def authenticate_api_key(
        self, api_key: str, source_ip: Optional[str] = None
    ) -> Optional[UserCredentials]:
        """Authenticate a user with API key.

        Args:
            api_key: API key
            source_ip: Optional source IP for logging

        Returns:
            UserCredentials if authentication successful, None otherwise
        """
        # Find the user with this API key
        for user in self._users.values():
            if api_key in user.api_keys.values():
                # Authentication successful
                user.last_login = time.time()

                # Save users
                self._save_users()

                # Log successful attempt
                publish(
                    AuthEvent(
                        action="api_key_login",
                        user_id=user.user_id,
                        success=True,
                        source_ip=source_ip,
                        message=f"Successful API key login for {user.username}",
                    )
                )

                return user

        # API key not found
        publish(
            AuthEvent(
                action="api_key_login",
                user_id="unknown",
                success=False,
                source_ip=source_ip,
                message="Invalid API key",
            )
        )

        return None

    def generate_api_key(self, username: str, key_name: str) -> str:
        """Generate an API key for a user.

        Args:
            username: Username
            key_name: Name for the API key

        Returns:
            Generated API key

        Raises:
            AuthenticationError: If the user doesn't exist
        """
        user = self._users.get(username)

        if not user:
            raise AuthenticationError(f"User {username} does not exist")

        # Generate an API key
        api_key = f"sk-{secrets.token_urlsafe(32)}"

        # Add to user's API keys
        user.api_keys[key_name] = api_key

        # Save users
        self._save_users()

        # Log API key generation
        publish(
            AuthEvent(
                action="generate_api_key",
                user_id=user.user_id,
                success=True,
                message=f"Generated API key '{key_name}' for {username}",
            )
        )

        return api_key

    def revoke_api_key(self, username: str, key_name: str) -> bool:
        """Revoke an API key.

        Args:
            username: Username
            key_name: Name of the API key

        Returns:
            True if the key was revoked, False otherwise

        Raises:
            AuthenticationError: If the user doesn't exist
        """
        user = self._users.get(username)

        if not user:
            raise AuthenticationError(f"User {username} does not exist")

        # Remove the API key
        if key_name in user.api_keys:
            del user.api_keys[key_name]

            # Save users
            self._save_users()

            # Log API key revocation
            publish(
                AuthEvent(
                    action="revoke_api_key",
                    user_id=user.user_id,
                    success=True,
                    message=f"Revoked API key '{key_name}' for {username}",
                )
            )

            return True

        return False

    def change_password(
        self, username: str, current_password: str, new_password: str
    ) -> bool:
        """Change a user's password.

        Args:
            username: Username
            current_password: Current password
            new_password: New password

        Returns:
            True if the password was changed, False otherwise

        Raises:
            AuthenticationError: If the current password is incorrect
        """
        # Authenticate the user
        user = self.authenticate(username, current_password)

        if not user:
            raise AuthenticationError("Invalid username or password")

        # Hash the new password
        password_hash, salt = self._hash_password(new_password)

        # Update the user
        user.password_hash = password_hash
        user.salt = salt

        # Save users
        self._save_users()

        # Log password change
        publish(
            AuthEvent(
                action="change_password",
                user_id=user.user_id,
                success=True,
                message=f"Changed password for {username}",
            )
        )

        return True

    def reset_password(self, username: str, new_password: str) -> bool:
        """Reset a user's password (admin function).

        Args:
            username: Username
            new_password: New password

        Returns:
            True if the password was reset, False otherwise

        Raises:
            AuthenticationError: If the user doesn't exist
        """
        user = self._users.get(username)

        if not user:
            raise AuthenticationError(f"User {username} does not exist")

        # Hash the new password
        password_hash, salt = self._hash_password(new_password)

        # Update the user
        user.password_hash = password_hash
        user.salt = salt
        user.failed_attempts = 0
        user.locked_until = None

        # Save users
        self._save_users()

        # Log password reset
        publish(
            AuthEvent(
                action="reset_password",
                user_id=user.user_id,
                success=True,
                message=f"Reset password for {username}",
            )
        )

        return True

    def add_user_role(self, username: str, role: AuthRole) -> bool:
        """Add a role to a user.

        Args:
            username: Username
            role: Role to add

        Returns:
            True if the role was added, False otherwise

        Raises:
            AuthenticationError: If the user doesn't exist
        """
        user = self._users.get(username)

        if not user:
            raise AuthenticationError(f"User {username} does not exist")

        # Add the role
        if role not in user.roles:
            user.roles.add(role)

            # Save users
            self._save_users()

            # Log role addition
            publish(
                AuthEvent(
                    action="add_role",
                    user_id=user.user_id,
                    success=True,
                    message=f"Added role {role.value} to {username}",
                )
            )

            return True

        return False

    def remove_user_role(self, username: str, role: AuthRole) -> bool:
        """Remove a role from a user.

        Args:
            username: Username
            role: Role to remove

        Returns:
            True if the role was removed, False otherwise

        Raises:
            AuthenticationError: If the user doesn't exist
        """
        user = self._users.get(username)

        if not user:
            raise AuthenticationError(f"User {username} does not exist")

        # Remove the role
        if role in user.roles:
            user.roles.remove(role)

            # Save users
            self._save_users()

            # Log role removal
            publish(
                AuthEvent(
                    action="remove_role",
                    user_id=user.user_id,
                    success=True,
                    message=f"Removed role {role.value} from {username}",
                )
            )

            return True

        return False

    def delete_user(self, username: str) -> bool:
        """Delete a user.

        Args:
            username: Username

        Returns:
            True if the user was deleted, False otherwise
        """
        if username in self._users:
            user = self._users[username]
            user_id = user.user_id

            # Delete the user
            del self._users[username]

            # Save users
            self._save_users()

            # Log user deletion
            publish(
                AuthEvent(
                    action="delete_user",
                    user_id=user_id,
                    success=True,
                    message=f"Deleted user {username}",
                )
            )

            return True

        return False

    def generate_token(self, user: UserCredentials, expires_in: int = 3600) -> str:
        """Generate a JWT token for a user.

        Args:
            user: UserCredentials
            expires_in: Expiration time in seconds

        Returns:
            JWT token
        """
        now = datetime.datetime.utcnow()

        # Create token payload
        payload = {
            "sub": user.user_id,
            "username": user.username,
            "roles": [role.value for role in user.roles],
            "iat": now,
            "exp": now + datetime.timedelta(seconds=expires_in),
            "jti": str(uuid.uuid4()),
        }

        # Sign the token
        token = jwt.encode(payload, self._token_secret, algorithm="HS256")

        # Store token metadata
        self._tokens[payload["jti"]] = {
            "user_id": user.user_id,
            "username": user.username,
            "expires": payload["exp"],
            "issued": payload["iat"],
        }

        # Log token generation
        publish(
            AuthEvent(
                action="generate_token",
                user_id=user.user_id,
                success=True,
                message=f"Generated token for {user.username}",
            )
        )

        return token

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate a JWT token.

        Args:
            token: JWT token

        Returns:
            Token payload if valid, None otherwise
        """
        try:
            # Decode the token
            payload = jwt.decode(token, self._token_secret, algorithms=["HS256"])

            # Check if token is in our tokens store
            if payload.get("jti") not in self._tokens:
                # This might be a valid token but we don't have it in our store
                # (e.g., after a restart)
                logger.warning(
                    f"Valid token not found in token store: {payload.get('jti')}"
                )

                # We'll trust it if it's valid
                return payload

            # Token is valid
            return payload
        except jwt.ExpiredSignatureError:
            logger.info("Token validation failed: token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.info(f"Token validation failed: {e}")
            return None

    def revoke_token(self, token: str) -> bool:
        """Revoke a JWT token.

        Args:
            token: JWT token

        Returns:
            True if the token was revoked, False otherwise
        """
        try:
            # Decode the token
            payload = jwt.decode(
                token,
                self._token_secret,
                algorithms=["HS256"],
                options={"verify_exp": False},
            )

            # Remove from tokens store
            if payload.get("jti") in self._tokens:
                token_data = self._tokens.pop(payload["jti"])

                # Log token revocation
                publish(
                    AuthEvent(
                        action="revoke_token",
                        user_id=token_data["user_id"],
                        success=True,
                        message=f"Revoked token for {token_data['username']}",
                    )
                )

                return True
        except jwt.InvalidTokenError:
            pass

        return False

    def clean_expired_tokens(self) -> int:
        """Clean expired tokens from the tokens store.

        Returns:
            Number of tokens removed
        """
        now = datetime.datetime.utcnow()
        expired_tokens = []

        # Find expired tokens
        for jti, token_data in self._tokens.items():
            if token_data["expires"] < now:
                expired_tokens.append(jti)

        # Remove expired tokens
        for jti in expired_tokens:
            del self._tokens[jti]

        if expired_tokens:
            logger.info(f"Cleaned {len(expired_tokens)} expired tokens")

        return len(expired_tokens)


def get_auth_manager() -> AuthenticationManager:
    """Get the global authentication manager instance.

    Returns:
        AuthenticationManager instance
    """
    return AuthenticationManager()


# Helper functions for common authentication tasks


def authenticate_user(username: str, password: str) -> Optional[UserCredentials]:
    """Authenticate a user with password.

    Args:
        username: Username
        password: Password

    Returns:
        UserCredentials if authentication successful, None otherwise
    """
    auth_manager = get_auth_manager()
    return auth_manager.authenticate(username, password)


def authenticate_token(token: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user with token.

    Args:
        token: JWT token

    Returns:
        Token payload if valid, None otherwise
    """
    auth_manager = get_auth_manager()
    return auth_manager.validate_token(token)


def authenticate_api_key(api_key: str) -> Optional[UserCredentials]:
    """Authenticate a user with API key.

    Args:
        api_key: API key

    Returns:
        UserCredentials if authentication successful, None otherwise
    """
    auth_manager = get_auth_manager()
    return auth_manager.authenticate_api_key(api_key)


def generate_token(user: UserCredentials, expires_in: int = 3600) -> str:
    """Generate a JWT token for a user.

    Args:
        user: UserCredentials
        expires_in: Expiration time in seconds

    Returns:
        JWT token
    """
    auth_manager = get_auth_manager()
    return auth_manager.generate_token(user, expires_in)
