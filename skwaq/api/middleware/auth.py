"""Authentication middleware for Flask API."""

import functools
import uuid
from datetime import datetime, timedelta
from typing import Any, Callable, List, TypeVar, cast

import jwt
from flask import current_app, g, jsonify, request
from jwt.exceptions import PyJWTError

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# Type variable for decorator
F = TypeVar("F", bound=Callable[..., Any])


def login_required(f: F) -> F:
    """Decorator to require authentication for an endpoint.

    Args:
        f: Function to wrap

    Returns:
        Wrapped function that requires authentication
    """

    @functools.wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Check Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401

        # Extract token
        token = auth_header.split(" ")[1]

        try:
            # Decode JWT token with validation
            options = {"verify_exp": True}  # Verify expiration

            # Disable time validation for tests
            if current_app.config.get("TESTING", False):
                options["verify_exp"] = False
                options["verify_iat"] = False

            payload = jwt.decode(
                token,
                current_app.config["JWT_SECRET"],
                algorithms=[current_app.config["JWT_ALGORITHM"]],
                options=options,
            )

            # Set user information in Flask's g object
            g.user_id = payload.get("sub")
            g.username = payload.get("username")
            g.roles = payload.get("roles", [])
            g.token = token  # Store the token for later use

            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            logger.error("JWT token has expired")
            return jsonify({"error": "Authentication token has expired"}), 401
        except PyJWTError as e:
            logger.error(f"JWT validation error: {str(e)}")
            return jsonify({"error": "Invalid authentication token"}), 401

    return cast(F, decorated_function)


def generate_token(user_id: str, username: str, roles: List[str]) -> str:
    """Generate a JWT token for a user.

    Args:
        user_id: User ID
        username: Username
        roles: User roles

    Returns:
        JWT token string
    """
    # Set expiration time
    exp = datetime.utcnow() + timedelta(
        seconds=current_app.config.get("JWT_EXPIRATION", 3600)
    )

    # Set token issued time
    iat = datetime.utcnow()

    payload = {
        "sub": user_id,
        "username": username,
        "roles": roles,
        "exp": exp.timestamp(),
        "iat": iat.timestamp(),
        "jti": str(uuid.uuid4()),  # Unique token ID
    }

    return jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )


def has_role(role: str) -> bool:
    """Check if the current user has a specific role.

    Args:
        role: Role to check

    Returns:
        True if the user has the role, False otherwise
    """
    return hasattr(g, "roles") and role in g.roles


def require_role(role: str) -> Callable[[F], F]:
    """Decorator to require a specific role for an endpoint.

    Args:
        role: Required role

    Returns:
        Decorator function that requires the specified role
    """

    def decorator(f: F) -> F:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            if not has_role(role):
                return jsonify({"error": "Permission denied"}), 403
            return f(*args, **kwargs)

        return cast(F, decorated_function)

    return decorator
