"""Authorization module for Skwaq.

This module provides authorization functionality for the Skwaq
vulnerability assessment copilot, including role-based access control
and permission checking.
"""

from enum import Enum, auto
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union, cast

from skwaq.events.system_events import SystemEvent, publish
from skwaq.security.authentication import AuthRole, UserCredentials
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class AuthorizationError(Exception):
    """Exception raised for authorization failures."""

    pass


class Permission(Enum):
    """Permissions for authorization."""

    # System permissions
    ADMIN = "admin"  # Admin access
    VIEW_SYSTEM_STATUS = "view_system_status"  # View system status
    MANAGE_USERS = "manage_users"  # Manage users

    # Repository permissions
    LIST_REPOSITORIES = "list_repositories"  # List repositories
    VIEW_REPOSITORY = "view_repository"  # View repository details
    ADD_REPOSITORY = "add_repository"  # Add a repository
    DELETE_REPOSITORY = "delete_repository"  # Delete a repository

    # Investigation permissions
    LIST_INVESTIGATIONS = "list_investigations"  # List investigations
    CREATE_INVESTIGATION = "create_investigation"  # Create investigation
    VIEW_INVESTIGATION = "view_investigation"  # View investigation details
    EDIT_INVESTIGATION = "edit_investigation"  # Edit investigation
    DELETE_INVESTIGATION = "delete_investigation"  # Delete investigation

    # Knowledge permissions
    VIEW_KNOWLEDGE = "view_knowledge"  # View knowledge
    ADD_KNOWLEDGE = "add_knowledge"  # Add knowledge
    DELETE_KNOWLEDGE = "delete_knowledge"  # Delete knowledge

    # Finding permissions
    LIST_FINDINGS = "list_findings"  # List vulnerability findings
    VIEW_FINDING = "view_finding"  # View finding details
    CONFIRM_FINDING = "confirm_finding"  # Confirm/validate finding
    DELETE_FINDING = "delete_finding"  # Delete finding

    # Report permissions
    GENERATE_REPORT = "generate_report"  # Generate vulnerability report
    VIEW_REPORT = "view_report"  # View report
    EXPORT_REPORT = "export_report"  # Export report

    # Tool permissions
    RUN_TOOLS = "run_tools"  # Run vulnerability assessment tools
    CONFIGURE_TOOLS = "configure_tools"  # Configure tools

    # API permissions
    API_ACCESS = "api_access"  # Access API


class AuthEvent(SystemEvent):
    """Event emitted for authorization-related actions."""

    def __init__(
        self,
        action: str,
        user_id: str,
        permission: Permission,
        resource_id: Optional[str] = None,
        success: bool = True,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an authorization event.

        Args:
            action: The authorization action performed
            user_id: ID of the user
            permission: Permission requested
            resource_id: Optional resource identifier
            success: Whether the authorization was successful
            message: Optional message describing the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender="authorization",
            message=message
            or f"Authorization {action}: {'granted' if success else 'denied'} for user {user_id} ({permission.value})",
            target=None,
            metadata=metadata or {},
        )
        self.action = action
        self.user_id = user_id
        self.permission = permission.value
        self.resource_id = resource_id
        self.success = success


# Default role-permission mappings
DEFAULT_ROLE_PERMISSIONS: Dict[AuthRole, Set[Permission]] = {
    AuthRole.ADMIN: {
        # Admin has all permissions
        Permission.ADMIN,
        Permission.VIEW_SYSTEM_STATUS,
        Permission.MANAGE_USERS,
        Permission.LIST_REPOSITORIES,
        Permission.VIEW_REPOSITORY,
        Permission.ADD_REPOSITORY,
        Permission.DELETE_REPOSITORY,
        Permission.LIST_INVESTIGATIONS,
        Permission.CREATE_INVESTIGATION,
        Permission.VIEW_INVESTIGATION,
        Permission.EDIT_INVESTIGATION,
        Permission.DELETE_INVESTIGATION,
        Permission.VIEW_KNOWLEDGE,
        Permission.ADD_KNOWLEDGE,
        Permission.DELETE_KNOWLEDGE,
        Permission.LIST_FINDINGS,
        Permission.VIEW_FINDING,
        Permission.CONFIRM_FINDING,
        Permission.DELETE_FINDING,
        Permission.GENERATE_REPORT,
        Permission.VIEW_REPORT,
        Permission.EXPORT_REPORT,
        Permission.RUN_TOOLS,
        Permission.CONFIGURE_TOOLS,
        Permission.API_ACCESS,
    },
    AuthRole.USER: {
        # Regular user has most permissions except admin and sensitive operations
        Permission.VIEW_SYSTEM_STATUS,
        Permission.LIST_REPOSITORIES,
        Permission.VIEW_REPOSITORY,
        Permission.ADD_REPOSITORY,
        Permission.LIST_INVESTIGATIONS,
        Permission.CREATE_INVESTIGATION,
        Permission.VIEW_INVESTIGATION,
        Permission.EDIT_INVESTIGATION,
        Permission.VIEW_KNOWLEDGE,
        Permission.ADD_KNOWLEDGE,
        Permission.LIST_FINDINGS,
        Permission.VIEW_FINDING,
        Permission.CONFIRM_FINDING,
        Permission.GENERATE_REPORT,
        Permission.VIEW_REPORT,
        Permission.EXPORT_REPORT,
        Permission.RUN_TOOLS,
        Permission.API_ACCESS,
    },
    AuthRole.READONLY: {
        # Read-only user can only view information
        Permission.VIEW_SYSTEM_STATUS,
        Permission.LIST_REPOSITORIES,
        Permission.VIEW_REPOSITORY,
        Permission.LIST_INVESTIGATIONS,
        Permission.VIEW_INVESTIGATION,
        Permission.VIEW_KNOWLEDGE,
        Permission.LIST_FINDINGS,
        Permission.VIEW_FINDING,
        Permission.VIEW_REPORT,
    },
    AuthRole.SYSTEM: {
        # System role has special permissions for automated processes
        Permission.VIEW_SYSTEM_STATUS,
        Permission.LIST_REPOSITORIES,
        Permission.VIEW_REPOSITORY,
        Permission.LIST_INVESTIGATIONS,
        Permission.VIEW_INVESTIGATION,
        Permission.VIEW_KNOWLEDGE,
        Permission.LIST_FINDINGS,
        Permission.VIEW_FINDING,
        Permission.GENERATE_REPORT,
        Permission.RUN_TOOLS,
        Permission.API_ACCESS,
    },
}


class Authorization:
    """Authorization helper for permission checks."""

    _instance = None

    def __new__(cls) -> "Authorization":
        """Create a singleton instance.

        Returns:
            Singleton instance
        """
        if cls._instance is None:
            cls._instance = super(Authorization, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the authorization helper."""
        if self._initialized:
            return

        self._initialized = True
        self._role_permissions = DEFAULT_ROLE_PERMISSIONS.copy()

    def has_permission(
        self,
        user: UserCredentials,
        permission: Permission,
        resource_id: Optional[str] = None,
    ) -> bool:
        """Check if a user has a permission.

        Args:
            user: User credentials
            permission: Permission to check
            resource_id: Optional resource identifier

        Returns:
            True if the user has the permission, False otherwise
        """
        # Check each role the user has
        for role in user.roles:
            # If this role has the permission, grant access
            if permission in self._role_permissions.get(role, set()):
                # Log the permission check
                publish(
                    AuthEvent(
                        action="check_permission",
                        user_id=user.user_id,
                        permission=permission,
                        resource_id=resource_id,
                        success=True,
                        message=f"Permission {permission.value} granted to {user.username} via role {role.value}",
                    )
                )
                return True

        # No role had the permission
        publish(
            AuthEvent(
                action="check_permission",
                user_id=user.user_id,
                permission=permission,
                resource_id=resource_id,
                success=False,
                message=f"Permission {permission.value} denied to {user.username}",
            )
        )
        return False

    def add_role_permission(self, role: AuthRole, permission: Permission) -> None:
        """Add a permission to a role.

        Args:
            role: Role
            permission: Permission to add
        """
        # Ensure the role exists in our mapping
        if role not in self._role_permissions:
            self._role_permissions[role] = set()

        # Add the permission
        self._role_permissions[role].add(permission)
        logger.info(f"Added permission {permission.value} to role {role.value}")

    def remove_role_permission(self, role: AuthRole, permission: Permission) -> None:
        """Remove a permission from a role.

        Args:
            role: Role
            permission: Permission to remove
        """
        if (
            role in self._role_permissions
            and permission in self._role_permissions[role]
        ):
            self._role_permissions[role].remove(permission)
            logger.info(f"Removed permission {permission.value} from role {role.value}")

    def get_role_permissions(self, role: AuthRole) -> Set[Permission]:
        """Get all permissions for a role.

        Args:
            role: Role

        Returns:
            Set of permissions
        """
        return self._role_permissions.get(role, set()).copy()

    def reset_to_defaults(self) -> None:
        """Reset role-permission mappings to defaults."""
        self._role_permissions = DEFAULT_ROLE_PERMISSIONS.copy()
        logger.info("Reset role permissions to defaults")


def get_authorization() -> Authorization:
    """Get the global authorization instance.

    Returns:
        Authorization instance
    """
    return Authorization()


# Decorator for permission checking
F = TypeVar("F", bound=Callable[..., Any])


def require_permission(
    permission: Permission, resource_id_arg: Optional[str] = None
) -> Callable[[F], F]:
    """Decorator to require a permission for a function.

    Args:
        permission: Required permission
        resource_id_arg: Optional argument name for resource ID

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find the user in the arguments
            user = None
            for arg in args:
                if isinstance(arg, UserCredentials):
                    user = arg
                    break

            # Check kwargs if not found in args
            if user is None:
                user = kwargs.get("user")

            if user is None:
                raise AuthorizationError(
                    "User credentials not found in function arguments"
                )

            # Get resource ID if specified
            resource_id = None
            if resource_id_arg:
                resource_id = kwargs.get(resource_id_arg)

            # Check permission
            auth = get_authorization()
            if not auth.has_permission(user, permission, resource_id):
                raise AuthorizationError(f"Permission denied: {permission.value}")

            # Permission granted, call the function
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator


def get_resource_permissions(
    resource_type: str, resource_id: str
) -> Dict[AuthRole, List[Permission]]:
    """Get permissions for a specific resource.

    For complex applications with resource-specific permissions beyond roles.

    Args:
        resource_type: Type of resource (repository, investigation, etc.)
        resource_id: Resource identifier

    Returns:
        Dictionary mapping roles to permissions for this resource
    """
    # In a more complex system, this would query a database for
    # resource-specific permissions. For now, we just return the default
    # role permissions.
    auth = get_authorization()
    return {role: list(auth.get_role_permissions(role)) for role in AuthRole}
