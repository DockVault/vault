/**
 * Roles Management JavaScript
 * Handles role display, user management, and role changes
 * Version: 2025100501
 */

// State management
const rolesState = {
    roles: [],
    users: [],
    filteredUsers: [],
    currentFilter: 'all',
    searchQuery: '',
    isAdmin: false
};

// API_BASE is already defined in dashboard_new.js, so we don't redeclare it

/**
 * Initialize the roles view
 */
async function initRolesView() {
    console.log('🎯 Initializing Roles Management View');
    
    // Check if user is admin
    rolesState.isAdmin = state.user && state.user.role === 'admin';
    
    // Load role definitions and users
    await Promise.all([
        fetchRoleDefinitions(),
        fetchUsersForRoles()
    ]);
    
    // Render everything
    renderRoleCards();
    renderUsersTable();
    
    // Setup event listeners
    setupRolesEventListeners();
}

/**
 * Fetch role definitions from API
 */
async function fetchRoleDefinitions() {
    try {
        const response = await fetch(`${API_BASE}/api/user-management/roles`, {
            headers: {
                'Authorization': `Bearer ${state.token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Failed to fetch roles: ${response.statusText}`);
        }
        
        rolesState.roles = await response.json();
        console.log(`✓ Loaded ${rolesState.roles.length} role definitions`);
    } catch (error) {
        console.error('Error fetching role definitions:', error);
        showRolesAlert('error', 'Failed to load role definitions', error.message);
    }
}

/**
 * Fetch users for roles management
 */
async function fetchUsersForRoles() {
    try {
        const response = await fetch(`${API_BASE}/api/user-management/users`, {
            headers: {
                'Authorization': `Bearer ${state.token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Failed to fetch users: ${response.statusText}`);
        }
        
        rolesState.users = await response.json();
        rolesState.filteredUsers = rolesState.users;
        console.log(`✓ Loaded ${rolesState.users.length} users`);
    } catch (error) {
        console.error('Error fetching users:', error);
        showRolesAlert('error', 'Failed to load users', error.message);
    }
}

/**
 * Render role definition cards
 */
function renderRoleCards() {
    const container = document.getElementById('roles-cards-container');
    if (!container) return;
    
    container.innerHTML = rolesState.roles.map(role => `
        <div class="role-card ${role.role}">
            <div class="role-card-header">
                <span class="role-icon">${role.icon}</span>
                <div class="role-title">
                    <h3>${role.display_name}</h3>
                    <span class="role-badge ${role.role}">${role.role}</span>
                </div>
            </div>
            <p class="role-description">${role.description}</p>
            <ul class="role-permissions-list">
                ${role.permissions.map(permission => `
                    <li>${permission}</li>
                `).join('')}
            </ul>
        </div>
    `).join('');
}

/**
 * Render users table with roles
 */
function renderUsersTable() {
    const tbody = document.getElementById('users-table-body');
    if (!tbody) return;
    
    if (rolesState.filteredUsers.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4" style="text-align: center; padding: 2rem;">
                    <div class="empty-state">
                        <div class="empty-state-icon">${svgIcon('search', 48)}</div>
                        <h3>No users found</h3>
                        <p>Try adjusting your search or filters</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }
    
    tbody.innerHTML = rolesState.filteredUsers.map(user => {
        const roleInfo = rolesState.roles.find(r => r.role === user.role) || {};
        const statusClass = user.is_locked ? 'locked' : (user.is_active ? 'active' : 'inactive');
        const statusText = user.is_locked ? 'Locked' : (user.is_active ? 'Active' : 'Inactive');
        const initials = user.username.substring(0, 2).toUpperCase();
        const isCurrentUser = state.user && state.user.id === user.id;
        
        return `
            <tr>
                <td>
                    <div class="user-info">
                        <div class="user-avatar">${initials}</div>
                        <div class="user-details">
                            <span class="user-name">${escapeHtml(user.username)}${isCurrentUser ? ' (You)' : ''}</span>
                            <span class="user-email">${escapeHtml(user.email)}</span>
                        </div>
                    </div>
                </td>
                <td>
                    <div class="user-role-cell">
                        <span class="role-icon">${roleInfo.icon || svgIcon('user')}</span>
                        <span class="role-badge ${user.role}">${user.role}</span>
                    </div>
                </td>
                <td>
                    <span class="user-status ${statusClass}">
                        <span class="user-status-dot"></span>
                        ${statusText}
                    </span>
                </td>
                <td>
                    <div class="user-actions">
                        ${rolesState.isAdmin ? `
                            <button 
                                class="btn-change-role" 
                                data-user-id="${user.id}"
                                data-username="${escapeHtml(user.username)}"
                                data-current-role="${user.role}"
                                ${isCurrentUser ? 'disabled title="Cannot change your own role"' : ''}
                            >
                                Change Role
                            </button>
                        ` : ''}
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

/**
 * Setup event listeners
 */
function setupRolesEventListeners() {
    // Search input
    const searchInput = document.getElementById('roles-search-input');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            rolesState.searchQuery = e.target.value.toLowerCase();
            filterUsers();
        });
    }
    
    // Role filter buttons
    const filterButtons = document.querySelectorAll('.role-filter-btn');
    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            // Update active state
            filterButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update filter
            rolesState.currentFilter = btn.dataset.role;
            filterUsers();
        });
    });
    
    // Event delegation for Change Role buttons
    const tbody = document.getElementById('users-table-body');
    if (tbody) {
        tbody.addEventListener('click', (e) => {
            const btn = e.target.closest('.btn-change-role');
            if (btn && !btn.disabled) {
                const userId = btn.dataset.userId;
                const username = btn.dataset.username;
                const currentRole = btn.dataset.currentRole;
                openChangeRoleModal(userId, username, currentRole);
            }
        });
    }
}

/**
 * Filter users based on search and role filter
 */
function filterUsers() {
    rolesState.filteredUsers = rolesState.users.filter(user => {
        // Role filter
        if (rolesState.currentFilter !== 'all' && user.role !== rolesState.currentFilter) {
            return false;
        }
        
        // Search filter
        if (rolesState.searchQuery) {
            const searchLower = rolesState.searchQuery.toLowerCase();
            return user.username.toLowerCase().includes(searchLower) ||
                   user.email.toLowerCase().includes(searchLower) ||
                   user.role.toLowerCase().includes(searchLower);
        }
        
        return true;
    });
    
    renderUsersTable();
    
    // Update result count
    const resultCount = document.getElementById('users-result-count');
    if (resultCount) {
        resultCount.textContent = `Showing ${rolesState.filteredUsers.length} of ${rolesState.users.length} users`;
    }
}

/**
 * Open change role modal
 */
function openChangeRoleModal(userId, username, currentRole) {
    // Create modal HTML
    const modal = document.createElement('div');
    modal.className = 'role-modal-overlay';
    modal.id = 'change-role-modal';
    
    const roleOptions = rolesState.roles.map(role => {
        const isSelected = role.role === currentRole;
        return `
            <label class="role-option ${isSelected ? 'selected' : ''}" data-role="${role.role}">
                <input 
                    type="radio" 
                    name="new-role" 
                    value="${role.role}"
                    ${isSelected ? 'checked' : ''}
                >
                <div class="role-option-content">
                    <div class="role-option-header">
                        <span>${role.icon}</span>
                        <span class="role-option-title">${role.display_name}</span>
                        <span class="role-badge ${role.role}">${role.role}</span>
                    </div>
                    <p class="role-option-description">${role.description}</p>
                </div>
            </label>
        `;
    }).join('');
    
    modal.innerHTML = `
        <div class="role-modal">
            <div class="role-modal-header">
                <h3>Change User Role</h3>
                <button class="role-modal-close">×</button>
            </div>
            <div class="role-modal-body">
                <div class="current-role-info">
                    <p><strong>User:</strong> ${escapeHtml(username)}</p>
                    <p><strong>Current Role:</strong> <span class="role-badge ${currentRole}">${currentRole}</span></p>
                </div>
                <form id="change-role-form">
                    <div class="role-options">
                        ${roleOptions}
                    </div>
                </form>
            </div>
            <div class="role-modal-footer">
                <button type="button" class="btn-modal btn-cancel">
                    Cancel
                </button>
                <button type="button" class="btn-modal btn-confirm" data-user-id="${userId}" data-old-role="${currentRole}">
                    Change Role
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Add click handlers for role options
    const roleOptionElements = modal.querySelectorAll('.role-option');
    roleOptionElements.forEach(option => {
        option.addEventListener('click', function() {
            roleOptionElements.forEach(o => o.classList.remove('selected'));
            this.classList.add('selected');
            this.querySelector('input[type="radio"]').checked = true;
        });
    });
    
    // Add event listeners for modal buttons
    const closeBtn = modal.querySelector('.role-modal-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeChangeRoleModal);
    }
    
    const cancelBtn = modal.querySelector('.btn-cancel');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeChangeRoleModal);
    }
    
    const confirmBtn = modal.querySelector('.btn-confirm');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', () => {
            const userId = confirmBtn.dataset.userId;
            const oldRole = confirmBtn.dataset.oldRole;
            confirmRoleChange(userId, oldRole);
        });
    }
    
    // Close on overlay click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeChangeRoleModal();
        }
    });
    
    // Close on escape key
    document.addEventListener('keydown', function escapeHandler(e) {
        if (e.key === 'Escape') {
            closeChangeRoleModal();
            document.removeEventListener('keydown', escapeHandler);
        }
    });
}

/**
 * Close change role modal
 */
function closeChangeRoleModal() {
    const modal = document.getElementById('change-role-modal');
    if (modal) {
        modal.remove();
    }
}

/**
 * Confirm role change
 */
async function confirmRoleChange(userId, oldRole) {
    const form = document.getElementById('change-role-form');
    const selectedRole = form.querySelector('input[name="new-role"]:checked')?.value;
    
    if (!selectedRole) {
        showRolesAlert('warning', 'No role selected', 'Please select a new role');
        return;
    }
    
    if (selectedRole === oldRole) {
        showRolesAlert('warning', 'Same role selected', 'The selected role is the same as the current role');
        return;
    }
    
    // Disable confirm button during request
    const confirmBtn = document.querySelector('.btn-confirm');
    if (confirmBtn) {
        confirmBtn.disabled = true;
        confirmBtn.textContent = 'Changing...';
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/user-management/users/${userId}/role`, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${state.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ new_role: selectedRole })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to change role');
        }
        
        const result = await response.json();
        console.log('✓ Role changed successfully:', result);
        
        showRolesAlert('success', 'Role Changed', result.message);
        
        // Refresh users list
        await fetchUsersForRoles();
        filterUsers();
        
        // Close modal
        closeChangeRoleModal();
        
    } catch (error) {
        console.error('Error changing role:', error);
        showRolesAlert('error', 'Failed to change role', error.message);
        
        // Re-enable button
        if (confirmBtn) {
            confirmBtn.disabled = false;
            confirmBtn.textContent = 'Change Role';
        }
    }
}

/**
 * Show alert message
 */
function showRolesAlert(type, title, message) {
    const container = document.getElementById('roles-alert-container');
    if (!container) return;
    
    const iconMap = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = `
        <span class="alert-icon">${iconMap[type] || 'ℹ'}</span>
        <div class="alert-content">
            <strong>${title}</strong>
            ${message ? `<p>${message}</p>` : ''}
        </div>
        <button class="alert-close">×</button>
    `;
    
    // Add event listener for close button
    const closeBtn = alert.querySelector('.alert-close');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => alert.remove());
    }
    
    container.appendChild(alert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (alert.parentElement) {
            alert.remove();
        }
    }, 5000);
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Cleanup function when leaving roles view
 */
function cleanupRolesView() {
    console.log('🧹 Cleaning up Roles Management View');
    // Close any open modals
    closeChangeRoleModal();
    // Clear state
    rolesState.roles = [];
    rolesState.users = [];
    rolesState.filteredUsers = [];
}

// Export functions for global access
window.initRolesView = initRolesView;
window.cleanupRolesView = cleanupRolesView;
window.openChangeRoleModal = openChangeRoleModal;
window.closeChangeRoleModal = closeChangeRoleModal;
window.confirmRoleChange = confirmRoleChange;
