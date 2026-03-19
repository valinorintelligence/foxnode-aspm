from fastapi import Depends, HTTPException, status
from app.core.security import get_current_user
from app.models.user import User, UserRole

# Permission definitions
ROLE_PERMISSIONS = {
    UserRole.ADMIN: {"*"},  # all permissions
    UserRole.MANAGER: {
        "products:read", "products:write", "products:delete",
        "findings:read", "findings:write", "findings:delete",
        "engagements:read", "engagements:write",
        "integrations:read", "integrations:write", "integrations:delete",
        "scans:read", "scans:import",
        "dashboard:read",
        "users:read",
        "jira:read", "jira:write",
        "notifications:read", "notifications:write",
    },
    UserRole.ANALYST: {
        "products:read",
        "findings:read", "findings:write",
        "engagements:read", "engagements:write",
        "integrations:read",
        "scans:read", "scans:import",
        "dashboard:read",
        "jira:read", "jira:write",
        "notifications:read",
    },
    UserRole.VIEWER: {
        "products:read",
        "findings:read",
        "engagements:read",
        "integrations:read",
        "scans:read",
        "dashboard:read",
    },
}


def require_permission(permission: str):
    """Dependency that checks if current user has the required permission."""
    async def permission_checker(current_user: User = Depends(get_current_user)):
        user_permissions = ROLE_PERMISSIONS.get(current_user.role, set())
        if "*" not in user_permissions and permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission}",
            )
        return current_user
    return permission_checker


def require_role(*roles: UserRole):
    """Dependency that checks if current user has one of the required roles."""
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(r.value for r in roles)}",
            )
        return current_user
    return role_checker
