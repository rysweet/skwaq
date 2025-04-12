"""Authentication routes for the Flask API."""

from flask import Blueprint, Response, g, jsonify, request

from skwaq.api.middleware.auth import login_required
from skwaq.api.middleware.error_handling import BadRequestError, UnauthorizedError
from skwaq.api.services.auth_service import get_user_info, login
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@bp.route("/login", methods=["POST"])
def auth_login() -> Response:
    """Login endpoint for obtaining a JWT token.

    Returns:
        JSON response with token and user information
    """
    if not request.is_json:
        raise BadRequestError("Request must be JSON")

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        raise BadRequestError("Username and password are required")

    # Authenticate user
    user, token = login(username, password)
    if not user or not token:
        raise UnauthorizedError("Invalid username or password")

    # Return token and user info
    return jsonify({"token": token, "user": user})


@bp.route("/logout", methods=["POST"])
@login_required
def auth_logout() -> Response:
    """Logout endpoint for invalidating a JWT token.

    Returns:
        JSON response confirming logout
    """
    # In a real implementation, we would add the token to a blacklist
    # or revoke it on the server. For now, we'll just return a success response
    # since token invalidation is handled client-side by removing the token.
    return jsonify({"message": "Successfully logged out"})


@bp.route("/me", methods=["GET"])
@login_required
def auth_me() -> Response:
    """Get current user information.

    Returns:
        JSON response with user information
    """
    user_info = get_user_info(g.user_id)
    if not user_info:
        # This shouldn't happen if the token is valid, but just in case
        logger.error(f"User info not found for authenticated user {g.user_id}")
        return jsonify(
            {"user": {"id": g.user_id, "username": g.username, "roles": g.roles}}
        )

    return jsonify({"user": user_info})


@bp.route("/refresh", methods=["POST"])
@login_required
def auth_refresh() -> Response:
    """Refresh JWT token.

    Returns:
        JSON response with new token and user information
    """
    from skwaq.api.middleware.auth import generate_token

    # Generate new token
    token = generate_token(g.user_id, g.username, g.roles)

    # Get user info
    user_info = get_user_info(g.user_id)
    if not user_info:
        # Use information from token if user info not found
        user_info = {"id": g.user_id, "username": g.username, "roles": g.roles}

    return jsonify({"token": token, "user": user_info})
