"""Authentication service for the Flask API."""

from typing import Any, Dict, Optional, Tuple

from werkzeug.security import check_password_hash, generate_password_hash

from skwaq.api.middleware.auth import generate_token
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# In-memory user database for development
# In production, this would be stored in a database
USERS = {
    "admin": {
        "id": "user-001",
        "username": "admin",
        "password_hash": generate_password_hash("admin"),
        "roles": ["admin"],
    },
    "user": {
        "id": "user-002",
        "username": "user",
        "password_hash": generate_password_hash("password"),
        "roles": ["user"],
    },
}


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticate a user with username and password.

    Args:
        username: User's username
        password: User's password

    Returns:
        User information if authentication is successful, None otherwise
    """
    user = USERS.get(username)
    if not user:
        logger.warning(f"Authentication failed: user {username} not found")
        return None

    if not check_password_hash(user["password_hash"], password):
        logger.warning(f"Authentication failed: invalid password for user {username}")
        return None

    logger.info(f"User {username} authenticated successfully")
    return user


def login(
    username: str, password: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Login a user and generate a JWT token.

    Args:
        username: User's username
        password: User's password

    Returns:
        Tuple of (user_info, token) if login is successful, (None, None) otherwise
    """
    user = authenticate(username, password)
    if not user:
        return None, None

    # Generate JWT token
    token = generate_token(user["id"], user["username"], user["roles"])

    # Return user info and token
    return {
        "id": user["id"],
        "username": user["username"],
        "roles": user["roles"],
    }, token


def get_user_info(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user information by ID.

    Args:
        user_id: User ID

    Returns:
        User information if found, None otherwise
    """
    for user in USERS.values():
        if user["id"] == user_id:
            return {
                "id": user["id"],
                "username": user["username"],
                "roles": user["roles"],
            }

    return None
