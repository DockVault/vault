"""
API Catalog - Comprehensive mapping of all API endpoints to functional groups.

This module defines all API endpoints, their security requirements, and functionality groupings.
Used by the permission system to grant/revoke access to specific features.

Structure:
- Each functionality group has a unique name, description, and UI widget
- Each endpoint specifies HTTP method, path pattern, required role, and owner-only flags
- Permissions can be granted at group level (all endpoints) or individual endpoint level
"""

from enum import Enum
from typing import List, Dict, Optional
from dataclasses import dataclass, field


class RoleRequirement(Enum):
    """Role requirements for endpoints"""
    PUBLIC = "public"          # No authentication required
    USER = "user"              # Any authenticated user
    ADMIN = "admin"            # Admin role required
    OWNER = "owner"            # Resource owner only
    

@dataclass
class APIEndpoint:
    """Represents a single API endpoint"""
    method: str                        # HTTP method (GET, POST, PUT, DELETE, PATCH)
    path: str                          # URL path pattern
    function_name: str                 # Python function name
    description: str                   # Human-readable description
    role_requirement: RoleRequirement  # Minimum role needed
    requires_ownership: bool = False   # True if user must own the resource
    resource_type: Optional[str] = None  # Resource type for ownership check (vault, file, user)
    ui_widgets: List[str] = field(default_factory=list)  # UI elements that depend on this endpoint


@dataclass
class FunctionalityGroup:
    """Represents a logical grouping of related API endpoints"""
    name: str                          # Unique identifier (e.g., "DASHBOARD_VIEW")
    display_name: str                  # Human-readable name
    description: str                   # What this functionality does
    ui_section: str                    # Which UI section it relates to
    default_for_roles: List[str]       # Roles that get this by default
    endpoints: List[APIEndpoint]       # List of endpoints in this group
    dependencies: List[str] = field(default_factory=list)  # Other groups this depends on


# ============================================================================
# API CATALOG - Complete mapping of all endpoints
# ============================================================================

API_CATALOG = {
    # ------------------------------------------------------------------------
    # SYSTEM & HEALTH
    # ------------------------------------------------------------------------
    "SYSTEM_HEALTH": FunctionalityGroup(
        name="SYSTEM_HEALTH",
        display_name="System Health & Status",
        description="Check system health and API status",
        ui_section="System",
        default_for_roles=["user", "admin"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/api",
                function_name="api_info",
                description="Get API information and version",
                role_requirement=RoleRequirement.PUBLIC,
                ui_widgets=[]
            ),
            APIEndpoint(
                method="GET",
                path="/health",
                function_name="health_check",
                description="Health check endpoint for monitoring",
                role_requirement=RoleRequirement.PUBLIC,
                ui_widgets=[]
            ),
        ]
    ),
    
    # ------------------------------------------------------------------------
    # AUTHENTICATION
    # ------------------------------------------------------------------------
    "AUTH_LOGIN": FunctionalityGroup(
        name="AUTH_LOGIN",
        display_name="User Authentication",
        description="Login and authentication endpoints",
        ui_section="Authentication",
        default_for_roles=["user", "admin"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/auth/login",
                function_name="login",
                description="User login with username and password",
                role_requirement=RoleRequirement.PUBLIC,
                ui_widgets=["login-form"]
            ),
            APIEndpoint(
                method="GET",
                path="/users/me",
                function_name="get_current_user_info",
                description="Get current authenticated user information",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["user-profile", "sidebar-user-info"]
            ),
        ]
    ),
    
    # ------------------------------------------------------------------------
    # TEMPORARY CREDENTIALS
    # ------------------------------------------------------------------------
    "TEMP_CREDS_VIEW": FunctionalityGroup(
        name="TEMP_CREDS_VIEW",
        display_name="View Temporary Credentials",
        description="View list of temporary SFTP credentials",
        ui_section="Temporary Credentials",
        # Users may view their OWN credentials (the handler scopes the list to
        # current_user; admins see all).
        default_for_roles=["user", "admin"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/temp-creds/list",
                function_name="list_temp_credentials",
                description="List all temporary credentials",
                role_requirement=RoleRequirement.ADMIN,
                ui_widgets=["temp-creds-list", "temp-creds-table"]
            ),
        ]
    ),
    
    "TEMP_CREDS_MANAGE": FunctionalityGroup(
        name="TEMP_CREDS_MANAGE",
        display_name="Manage Temporary Credentials",
        description="Create and delete temporary SFTP credentials",
        ui_section="Temporary Credentials",
        # Users may create/manage their OWN credentials; every handler rejects
        # acting on another user's credential unless you're an admin.
        default_for_roles=["user", "admin"],
        dependencies=["TEMP_CREDS_VIEW"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/auth/temp-credentials",
                function_name="generate_temp_credential",
                description="Generate new temporary credential",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["generate-temp-creds-btn", "temp-creds-modal"]
            ),
            APIEndpoint(
                method="POST",
                path="/temp-creds/{temp_username}/delete",
                function_name="delete_temp_credential",
                description="Delete temporary credential",
                role_requirement=RoleRequirement.ADMIN,
                ui_widgets=["temp-creds-delete-btn"]
            ),
        ]
    ),
    
    # ------------------------------------------------------------------------
    # USER MANAGEMENT
    # ------------------------------------------------------------------------
    "USER_VIEW": FunctionalityGroup(
        name="USER_VIEW",
        display_name="View Users",
        description="View list of users and user details",
        ui_section="Users",
        default_for_roles=["admin"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/users",
                function_name="list_users",
                description="List all users in the system",
                role_requirement=RoleRequirement.ADMIN,
                ui_widgets=["users-table", "users-list", "permission-user-select"]
            ),
            APIEndpoint(
                method="GET",
                path="/users/{user_id}",
                function_name="get_user",
                description="Get specific user details",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="user",
                ui_widgets=["user-details-modal"]
            ),
        ]
    ),
    
    "USER_MANAGE": FunctionalityGroup(
        name="USER_MANAGE",
        display_name="Manage Users",
        description="Create, update, and delete user accounts",
        ui_section="Users",
        default_for_roles=["admin"],
        dependencies=["USER_VIEW"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/users",
                function_name="create_user",
                description="Create new user account",
                role_requirement=RoleRequirement.ADMIN,
                ui_widgets=["create-user-btn", "create-user-modal"]
            ),
            APIEndpoint(
                method="PATCH",
                path="/users/{user_id}",
                function_name="update_user",
                description="Update user information",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="user",
                ui_widgets=["edit-user-btn", "user-settings"]
            ),
            APIEndpoint(
                method="POST",
                path="/users/{user_id}/delete",
                function_name="delete_user",
                description="Delete user account",
                role_requirement=RoleRequirement.ADMIN,
                ui_widgets=["delete-user-btn"]
            ),
        ]
    ),
    
    # ------------------------------------------------------------------------
    # DASHBOARD & STATISTICS
    # ------------------------------------------------------------------------
    "DASHBOARD_VIEW": FunctionalityGroup(
        name="DASHBOARD_VIEW",
        display_name="View Dashboard",
        description="View dashboard statistics and overview",
        ui_section="Dashboard",
        default_for_roles=["user", "admin"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/dashboard/stats",
                function_name="get_dashboard_stats",
                description="Get dashboard statistics (admin only shows all stats)",
                role_requirement=RoleRequirement.ADMIN,
                ui_widgets=["stat-users", "stat-temp-creds", "events-feed"]
            ),
        ]
    ),
    
    # ------------------------------------------------------------------------
    # VAULT ACCESS
    # ------------------------------------------------------------------------
    "VAULT_VIEW": FunctionalityGroup(
        name="VAULT_VIEW",
        display_name="View Vaults",
        description="View list of vaults and vault details",
        ui_section="Vaults",
        default_for_roles=["user", "admin"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/vaults",
                function_name="list_vaults",
                description="List all accessible vaults",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["vaults-grid", "vaults-list", "stat-vaults", "stat-storage"]
            ),
            APIEndpoint(
                method="GET",
                path="/vaults/{vault_id}",
                function_name="get_vault",
                description="Get specific vault details",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["vault-view", "vault-header", "vault-details"]
            ),
        ]
    ),
    
    "VAULT_CREATE": FunctionalityGroup(
        name="VAULT_CREATE",
        display_name="Create Vaults",
        description="Create new vaults",
        ui_section="Vaults",
        default_for_roles=["user", "admin"],
        dependencies=["VAULT_VIEW"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/vaults",
                function_name="create_vault",
                description="Create new vault",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["create-vault-btn", "create-vault-modal"]
            ),
        ]
    ),
    
    "VAULT_DELETE": FunctionalityGroup(
        name="VAULT_DELETE",
        display_name="Delete Vaults",
        description="Delete vaults (owner only)",
        ui_section="Vaults",
        default_for_roles=["user", "admin"],
        dependencies=["VAULT_VIEW"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/vaults/{vault_id}/delete",
                function_name="delete_vault",
                description="Delete vault",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="vault",
                ui_widgets=["delete-vault-btn"]
            ),
        ]
    ),
    
    "VAULT_SETTINGS": FunctionalityGroup(
        name="VAULT_SETTINGS",
        display_name="Manage Vault Settings",
        description="Change vault password, expiration, size limits (owner only)",
        ui_section="Vaults",
        default_for_roles=["user", "admin"],
        dependencies=["VAULT_VIEW"],
        endpoints=[
            APIEndpoint(
                method="PUT",
                path="/vaults/{vault_id}/password",
                function_name="change_vault_password",
                description="Change or remove vault password",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="vault",
                ui_widgets=["change-vault-password-btn", "vault-security-section"]
            ),
            APIEndpoint(
                method="PATCH",
                path="/vaults/{vault_id}/settings",
                function_name="update_vault_settings",
                description="Update vault settings (expiration, size limit)",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="vault",
                ui_widgets=["vault-settings-tab", "update-size-limit-btn", "set-expiration-btn"]
            ),
        ]
    ),
    
    "VAULT_PERMISSIONS": FunctionalityGroup(
        name="VAULT_PERMISSIONS",
        display_name="Manage Vault Permissions",
        description="Grant/revoke vault access to users (owner only)",
        ui_section="Vaults",
        default_for_roles=["user", "admin"],
        dependencies=["VAULT_VIEW", "USER_VIEW"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/vaults/{vault_id}/permissions",
                function_name="list_vault_permissions",
                description="List users with vault access",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="vault",
                ui_widgets=["permissions-tab", "permissions-table"]
            ),
            APIEndpoint(
                method="POST",
                path="/vaults/{vault_id}/permissions",
                function_name="grant_vault_permission",
                description="Grant vault access to user",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="vault",
                ui_widgets=["grant-access-btn", "grant-permission-modal"]
            ),
            APIEndpoint(
                method="DELETE",
                path="/vaults/{vault_id}/permissions/{user_id}",
                function_name="revoke_vault_permission",
                description="Revoke vault access from user",
                role_requirement=RoleRequirement.USER,
                requires_ownership=True,
                resource_type="vault",
                ui_widgets=["revoke-permission-btn"]
            ),
        ]
    ),
    
    # ------------------------------------------------------------------------
    # FILE OPERATIONS
    # ------------------------------------------------------------------------
    "FILE_VIEW": FunctionalityGroup(
        name="FILE_VIEW",
        display_name="View Files",
        description="View and list files in vaults",
        ui_section="Files",
        default_for_roles=["user", "admin"],
        dependencies=["VAULT_VIEW"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/vaults/{vault_id}/files",
                function_name="list_vault_files",
                description="List files and folders in vault",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["files-tab", "files-table", "breadcrumb"]
            ),
        ]
    ),
    
    "FILE_DOWNLOAD": FunctionalityGroup(
        name="FILE_DOWNLOAD",
        display_name="Download Files",
        description="Download files from vaults",
        ui_section="Files",
        default_for_roles=["user", "admin"],
        dependencies=["FILE_VIEW"],
        endpoints=[
            APIEndpoint(
                method="GET",
                path="/vaults/{vault_id}/files/{file_id}/download",
                function_name="download_file",
                description="Download file",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["download-file-btn", "file-context-menu"]
            ),
        ]
    ),
    
    "FILE_UPLOAD": FunctionalityGroup(
        name="FILE_UPLOAD",
        display_name="Upload Files",
        description="Upload files to vaults (requires write permission)",
        ui_section="Files",
        default_for_roles=["user", "admin"],
        dependencies=["FILE_VIEW"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/vaults/{vault_id}/files",
                function_name="upload_file",
                description="Upload file to vault",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["upload-file-btn", "file-upload-modal", "drag-drop-area"]
            ),
        ]
    ),
    
    "FILE_DELETE": FunctionalityGroup(
        name="FILE_DELETE",
        display_name="Delete Files",
        description="Delete files and folders (requires delete permission)",
        ui_section="Files",
        default_for_roles=["user", "admin"],
        dependencies=["FILE_VIEW"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/vaults/{vault_id}/files/{file_id}/delete",
                function_name="delete_file",
                description="Delete file",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["delete-file-btn", "file-context-menu"]
            ),
        ]
    ),
    
    "FOLDER_MANAGE": FunctionalityGroup(
        name="FOLDER_MANAGE",
        display_name="Manage Folders",
        description="Create and manage folders in vaults",
        ui_section="Files",
        default_for_roles=["user", "admin"],
        dependencies=["FILE_VIEW"],
        endpoints=[
            APIEndpoint(
                method="POST",
                path="/vaults/{vault_id}/folders",
                function_name="create_folder",
                description="Create new folder",
                role_requirement=RoleRequirement.USER,
                ui_widgets=["create-folder-btn", "new-folder-modal"]
            ),
        ]
    ),
}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_all_endpoints() -> List[APIEndpoint]:
    """Get flat list of all endpoints across all groups"""
    endpoints = []
    for group in API_CATALOG.values():
        endpoints.extend(group.endpoints)
    return endpoints


def get_endpoints_by_ui_widget(widget_name: str) -> List[APIEndpoint]:
    """Get all endpoints that power a specific UI widget"""
    endpoints = []
    for group in API_CATALOG.values():
        for endpoint in group.endpoints:
            if widget_name in endpoint.ui_widgets:
                endpoints.append(endpoint)
    return endpoints


def get_groups_for_role(role: str) -> List[str]:
    """Get all functionality groups that a role should have by default"""
    groups = []
    for group_name, group in API_CATALOG.items():
        if role in group.default_for_roles:
            groups.append(group_name)
    return groups


def get_group_by_name(name: str) -> Optional[FunctionalityGroup]:
    """Get functionality group by name"""
    return API_CATALOG.get(name)


def search_endpoints(query: str) -> List[tuple]:
    """Search endpoints by path, description, or function name"""
    results = []
    query_lower = query.lower()
    for group_name, group in API_CATALOG.items():
        for endpoint in group.endpoints:
            if (query_lower in endpoint.path.lower() or 
                query_lower in endpoint.description.lower() or 
                query_lower in endpoint.function_name.lower()):
                results.append((group_name, group, endpoint))
    return results


def export_catalog_summary() -> Dict:
    """Export catalog summary for documentation or UI"""
    return {
        "total_groups": len(API_CATALOG),
        "total_endpoints": len(get_all_endpoints()),
        "groups": [
            {
                "name": group.name,
                "display_name": group.display_name,
                "description": group.description,
                "ui_section": group.ui_section,
                "endpoint_count": len(group.endpoints),
                "default_for_roles": group.default_for_roles,
                "dependencies": group.dependencies
            }
            for group in API_CATALOG.values()
        ]
    }


# ============================================================================
# VALIDATION
# ============================================================================

def validate_catalog():
    """Validate the catalog for consistency"""
    errors = []
    
    # Check for duplicate endpoint paths
    seen_paths = {}
    for group_name, group in API_CATALOG.items():
        for endpoint in group.endpoints:
            key = f"{endpoint.method} {endpoint.path}"
            if key in seen_paths:
                errors.append(f"Duplicate endpoint: {key} in {group_name} and {seen_paths[key]}")
            seen_paths[key] = group_name
    
    # Check dependencies exist
    for group_name, group in API_CATALOG.items():
        for dep in group.dependencies:
            if dep not in API_CATALOG:
                errors.append(f"Group {group_name} depends on non-existent group {dep}")
    
    return errors


if __name__ == "__main__":
    # Run validation and print summary
    print("=" * 80)
    print("API CATALOG VALIDATION")
    print("=" * 80)
    
    errors = validate_catalog()
    if errors:
        print("\nΓ¥î ERRORS FOUND:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("\nΓ£à No errors found!")
    
    print("\n" + "=" * 80)
    print("CATALOG SUMMARY")
    print("=" * 80)
    
    summary = export_catalog_summary()
    print(f"\nTotal Functionality Groups: {summary['total_groups']}")
    print(f"Total API Endpoints: {summary['total_endpoints']}")
    
    print("\n" + "-" * 80)
    print("GROUPS BY UI SECTION:")
    print("-" * 80)
    
    by_section = {}
    for group in summary['groups']:
        section = group['ui_section']
        if section not in by_section:
            by_section[section] = []
        by_section[section].append(group)
    
    for section, groups in sorted(by_section.items()):
        print(f"\n≡ƒôü {section}")
        for group in groups:
            print(f"   ΓÇó {group['display_name']} ({group['endpoint_count']} endpoints)")
            print(f"     ΓööΓöÇ {group['description']}")
            if group['dependencies']:
                print(f"     ΓööΓöÇ Depends on: {', '.join(group['dependencies'])}")
    
    print("\n" + "=" * 80)
    print("DEFAULT PERMISSIONS BY ROLE")
    print("=" * 80)
    
    admin_groups = get_groups_for_role('admin')
    user_groups = get_groups_for_role('user')
    
    print(f"\n≡ƒæñ USER role gets {len(user_groups)} groups by default:")
    for group_name in user_groups:
        group = API_CATALOG[group_name]
        print(f"   ΓÇó {group.display_name}")
    
    print(f"\n≡ƒææ ADMIN role gets {len(admin_groups)} groups by default:")
    for group_name in admin_groups:
        group = API_CATALOG[group_name]
        print(f"   ΓÇó {group.display_name}")
    
    print("\n" + "=" * 80)
