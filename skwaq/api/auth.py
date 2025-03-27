"""Authentication middleware for Flask API."""

import functools
from typing import Any, Callable, Dict, Optional, TypeVar, cast, List

from flask import current_app, g, request, jsonify, Blueprint, Response
import jwt

from skwaq.security.authentication import (
    authenticate_user,
    authenticate_token,
    authenticate_api_key,
    generate_token,
    UserCredentials
)
from skwaq.security.authorization import (
    Permission, 
    get_authorization,
    AuthorizationError
)
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Type variable for decorator
F = TypeVar('F', bound=Callable[..., Any])


def login_required(f: F) -> F:
    """Decorator to require authentication for an endpoint."""
    @functools.wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({"error": "Authentication required"}), 401
        
        try:
            parts = auth_header.split(' ')
            if len(parts) != 2 or parts[0].lower() not in ('bearer', 'apikey'):
                return jsonify({"error": "Invalid authorization header format"}), 401
                
            auth_type, token = parts
            
            if auth_type.lower() == 'bearer':
                # Validate JWT token
                payload = authenticate_token(token)
                if not payload:
                    return jsonify({"error": "Invalid or expired token"}), 401
                
                # Store user info in Flask's g object for this request
                g.user_id = payload.get('sub')
                g.username = payload.get('username')
                g.roles = payload.get('roles', [])
                
            elif auth_type.lower() == 'apikey':
                # Validate API key
                user = authenticate_api_key(token)
                if not user:
                    return jsonify({"error": "Invalid API key"}), 401
                    
                # Store user info in Flask's g object for this request
                g.user_id = user.user_id
                g.username = user.username
                g.roles = [role.value for role in user.roles]
                
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({"error": "Authentication failed"}), 401
            
    return cast(F, decorated_function)


def require_permission(permission: Permission) -> Callable[[F], F]:
    """Decorator to require a specific permission for an endpoint."""
    def decorator(f: F) -> F:
        @functools.wraps(f)
        @login_required
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            try:
                # Check if user has the required permission
                auth = get_authorization()
                
                # Create a temporary UserCredentials object from Flask's g
                user = UserCredentials(
                    username=g.username,
                    password_hash="",  # Not needed for permission check
                    salt="",           # Not needed for permission check
                    user_id=g.user_id,
                )
                
                # Add roles from g.roles
                from skwaq.security.authentication import AuthRole
                for role_value in g.roles:
                    try:
                        user.roles.add(AuthRole(role_value))
                    except ValueError:
                        logger.warning(f"Unknown role: {role_value}")
                
                if not auth.has_permission(user, permission):
                    return jsonify({
                        "error": "Permission denied",
                        "required": permission.value
                    }), 403
                    
                return f(*args, **kwargs)
                
            except AuthorizationError as e:
                return jsonify({"error": str(e)}), 403
            except Exception as e:
                logger.error(f"Authorization error: {e}")
                return jsonify({"error": "Authorization failed"}), 500
                
        return cast(F, decorated_function)
    return decorator


@bp.route('/login', methods=['POST'])
def login() -> Response:
    """Login endpoint for obtaining a JWT token."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
        
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
        
    # Authenticate user
    user = authenticate_user(username, password)
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401
        
    # Generate token
    token = generate_token(user)
    
    return jsonify({
        "token": token,
        "user": {
            "id": user.user_id,
            "username": user.username,
            "roles": [role.value for role in user.roles]
        }
    })


@bp.route('/logout', methods=['POST'])
@login_required
def logout() -> Response:
    """Logout endpoint for invalidating a JWT token."""
    # In a real implementation, we would add the token to a blacklist
    # or revoke it on the server. For now, we'll just return a success response
    # since token invalidation is handled client-side by removing the token.
    return jsonify({"message": "Successfully logged out"})


@bp.route('/me', methods=['GET'])
@login_required
def me() -> Response:
    """Get current user information."""
    return jsonify({
        "user": {
            "id": g.user_id,
            "username": g.username,
            "roles": g.roles
        }
    })


@bp.route('/refresh', methods=['POST'])
@login_required
def refresh_token() -> Response:
    """Refresh JWT token."""
    # In a real implementation, we might verify the old token and issue a new one
    # with updated expiration. For simplicity, we'll just reuse the login logic.
    
    # Create a temporary UserCredentials object from Flask's g
    user = UserCredentials(
        username=g.username,
        password_hash="",  # Not needed for token generation
        salt="",           # Not needed for token generation
        user_id=g.user_id,
    )
    
    # Add roles from g.roles
    from skwaq.security.authentication import AuthRole
    for role_value in g.roles:
        try:
            user.roles.add(AuthRole(role_value))
        except ValueError:
            logger.warning(f"Unknown role: {role_value}")
    
    # Generate new token
    token = generate_token(user)
    
    return jsonify({
        "token": token,
        "user": {
            "id": user.user_id,
            "username": user.username,
            "roles": g.roles
        }
    })