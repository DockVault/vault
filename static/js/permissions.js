/**
 * Permission Management JavaScript
 * Handles user permission management UI
 * Integrated with dashboard_new.js
 */

// Permissions state management (separate from dashboard state)
const permissionsState = {
    users: [],
    selectedUserId: null,
    permissionGroups: [],
    userPermissions: { grantedGroups: [] },
    changes: new Map(), // Track changes before saving
    expandedGroups: new Set(),
    initialized: false
};

// API Configuration
const PERMISSIONS_API_BASE = window.location.origin;

/**
 * Initialize permissions view - called when view becomes active
 */
async function initializePermissionsView() {
    console.log('Initializing permissions view...');
    
    if (permissionsState.initialized) {
        console.log('Permissions already initialized, skipping...');
        return; // Already initialized
    }
    
    // Check if we have access to dashboard state
    if (typeof state === 'undefined' || !state.token) {
        console.error('No authentication state or token available');
        showPermissionsAlert('Authentication required', 'error');
        return;
    }

    setupPermissionsEventListeners();
    
    try {
        console.log('Loading permission data...');
        // Load data
        await Promise.all([
            loadPermissionUsers(),
            loadPermissionGroups()
        ]);
        
        permissionsState.initialized = true;
        console.log('✅ Permissions view initialized successfully');
        console.log('Users loaded:', permissionsState.users.length);
        console.log('Permission groups loaded:', permissionsState.permissionGroups.length);
    } catch (error) {
        console.error('Failed to initialize permissions view:', error);
        showPermissionsAlert('Failed to load permissions data', 'error');
    }
}

/**
 * Setup event listeners
 */
function setupPermissionsEventListeners() {
    // User search
    const searchInput = document.getElementById('userSearch');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            filterPermissionUsers(e.target.value);
        });
    }

    // User list click delegation (for dynamically created items)
    const usersList = document.getElementById('usersList');
    if (usersList) {
        usersList.addEventListener('click', (e) => {
            const userItem = e.target.closest('.user-item');
            if (userItem) {
                const userId = userItem.dataset.userId;
                if (userId) {
                    selectPermissionUser(userId);
                }
            }
        });
    }

    // Save button - will be created dynamically
    // Logout handled by dashboard
}

/**
 * Load users list
 */
async function loadPermissionUsers() {
    try {
        const response = await fetch(`${PERMISSIONS_API_BASE}/users`, {
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });

        if (response.ok) {
            permissionsState.users = await response.json();
            renderPermissionUsersList();
        } else {
            throw new Error('Failed to load users');
        }
    } catch (error) {
        console.error('Error loading users:', error);
        showPermissionsAlert('Failed to load users', 'error');
    }
}

/**
 * Load permission groups catalog
 */
async function loadPermissionGroups() {
    try {
        const response = await fetch(`${PERMISSIONS_API_BASE}/permissions/groups`, {
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });

        if (response.ok) {
            permissionsState.permissionGroups = await response.json();
            console.log('Loaded permission groups:', permissionsState.permissionGroups);
        } else {
            throw new Error('Failed to load permission groups');
        }
    } catch (error) {
        console.error('Error loading permission groups:', error);
        showPermissionsAlert('Failed to load permission groups', 'error');
    }
}

/**
 * Render users list
 */
function renderPermissionUsersList() {
    const container = document.getElementById('usersList');
    
    if (permissionsState.users.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #999;">No users found</p>';
        return;
    }

    container.innerHTML = permissionsState.users.map(user => `
        <div class="user-item ${permissionsState.selectedUserId === user.id ? 'active' : ''}" 
             data-user-id="${user.id}">
            <div class="user-item-name">${escapePermissionsHtml(user.username)}</div>
            <div class="user-item-email">${escapePermissionsHtml(user.email)}</div>
            <span class="user-item-role role-${user.role.toLowerCase().replace('roleenum.', '')}">${user.role.replace('RoleEnum.', '')}</span>
        </div>
    `).join('');
    // Event listeners handled by delegation in setupPermissionsEventListeners
}

/**
 * Filter users by search term
 */
function filterPermissionUsers(searchTerm) {
    const term = searchTerm.toLowerCase();
    const userItems = document.querySelectorAll('.user-item');
    
    userItems.forEach(item => {
        const name = item.querySelector('.user-item-name').textContent.toLowerCase();
        const email = item.querySelector('.user-item-email').textContent.toLowerCase();
        
        if (name.includes(term) || email.includes(term)) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });
}

/**
 * Select a user to manage permissions
 */
async function selectPermissionUser(userId) {
    console.log('👤 [SELECT USER] Selecting user:', userId);
    permissionsState.selectedUserId = userId;
    permissionsState.changes.clear(); // Clear unsaved changes
    
    // Update UI
    renderPermissionUsersList();
    
    // Load user's permissions
    console.log('📡 [SELECT USER] About to load user permissions...');
    await loadUserPermissions(userId);
    console.log('📡 [SELECT USER] Finished loading permissions');
    
    // Render permissions panel
    console.log('🎨 [SELECT USER] About to render panel...');
    renderPermissionsPanel();
    console.log('🎨 [SELECT USER] Finished rendering panel');
}

/**
 * Load permissions for selected user
 */
async function loadUserPermissions(userId) {
    console.log('🔄 [LOAD PERMS] Starting to load permissions for user:', userId);
    const container = document.getElementById('permissionsContent');
    container.innerHTML = '<div class="loading"><div class="spinner"></div><p>Loading permissions...</p></div>';
    
    try {
        console.log('🌐 [LOAD PERMS] Fetching from:', `${PERMISSIONS_API_BASE}/permissions/users/${userId}`);
        const response = await fetch(`${PERMISSIONS_API_BASE}/permissions/users/${userId}`, {
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });

        console.log('📥 [LOAD PERMS] Response status:', response.status, response.ok);
        
        if (response.ok) {
            const data = await response.json();
            console.log('✅ [PERMISSIONS PANEL] Loaded user permissions:', data);
            permissionsState.userPermissions = {
                userId: data.user_id,
                username: data.username,
                email: data.email,
                role: data.role,
                grantedGroups: data.granted_groups || []
            };
            console.log('📋 [PERMISSIONS PANEL] Granted groups:', permissionsState.userPermissions.grantedGroups);
            console.log('📋 [PERMISSIONS PANEL] State after assignment:', permissionsState.userPermissions);
        } else {
            const errorText = await response.text();
            console.error('❌ [LOAD PERMS] Response not OK:', response.status, errorText);
            throw new Error('Failed to load user permissions');
        }
    } catch (error) {
        console.error('💥 [LOAD PERMS] Error loading user permissions:', error);
        showPermissionsAlert('Failed to load user permissions', 'error');
        // Ensure grantedGroups is always initialized even on error
        permissionsState.userPermissions = {
            userId: userId,
            username: 'Unknown',
            email: '',
            role: 'user',
            grantedGroups: []
        };
    }
}

/**
 * Render permissions panel
 */
function renderPermissionsPanel() {
    console.log('🎨 [RENDER] Starting render, permissionsState.userPermissions:', permissionsState.userPermissions);
    console.log('🎨 [RENDER] grantedGroups:', permissionsState.userPermissions?.grantedGroups);
    
    const container = document.getElementById('permissionsContent');
    
    if (!permissionsState.selectedUserId) {
        container.innerHTML = `
            <div class="no-selection">
                <i>${svgIcon('users', 48)}</i>
                <h3>Select a user to manage permissions</h3>
                <p>Choose a user from the list on the left</p>
            </div>
        `;
        return;
    }

    const user = permissionsState.users.find(u => u.id === permissionsState.selectedUserId);
    const hasChanges = permissionsState.changes.size > 0;

    // Group permissions by UI section
    const sections = {};
    permissionsState.permissionGroups.forEach(group => {
        if (!sections[group.ui_section]) {
            sections[group.ui_section] = [];
        }
        sections[group.ui_section].push(group);
    });

    // Render
    container.innerHTML = `
        <div class="permissions-header">
            <div>
                <h2>Permissions for ${escapePermissionsHtml(permissionsState.userPermissions.username)}</h2>
                <p style="color: #666; margin: 5px 0 0 0;">
                    ${escapePermissionsHtml(permissionsState.userPermissions.email)} • ${permissionsState.userPermissions.role}
                </p>
            </div>
            <button class="save-button" id="savePermissions" ${!hasChanges ? 'disabled' : ''}>
                💾 Save Changes ${hasChanges ? `<span class="changes-indicator"></span>` : ''}
            </button>
        </div>

        ${Object.entries(sections).sort().map(([sectionName, groups]) => `
            <div class="section-group">
                <div class="section-title">
                    ${getSectionIcon(sectionName)} ${sectionName}
                </div>
                ${groups.map(group => renderPermissionCard(group)).join('')}
            </div>
        `).join('')}
    `;

    // Setup save button
    const saveBtn = document.getElementById('savePermissions');
    if (saveBtn) {
        saveBtn.addEventListener('click', savePermissions);
    }

    // Setup toggle switches
    document.querySelectorAll('.permission-toggle input').forEach(toggle => {
        toggle.addEventListener('change', handlePermissionToggle);
    });

    // Setup expand/collapse
    document.querySelectorAll('.expand-toggle').forEach(toggle => {
        toggle.addEventListener('click', handleExpandToggle);
    });
}

/**
 * Render a permission card
 */
function renderPermissionCard(group) {
    const isGranted = isGroupGranted(group.name);
    const isExpanded = permissionsState.expandedGroups.has(group.name);
    
    return `
        <div class="permission-card ${isGranted ? 'granted' : ''}" data-group="${group.name}">
            <div class="permission-header">
                <div>
                    <div class="permission-name">${escapePermissionsHtml(group.display_name)}</div>
                </div>
                <label class="permission-toggle">
                    <input type="checkbox" 
                           data-group="${group.name}" 
                           ${isGranted ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                </label>
            </div>
            
            <div class="permission-description">${escapePermissionsHtml(group.description)}</div>
            
            <div class="permission-details">
                <span class="permission-badge badge-endpoints">
                    ${svgIcon('file', 14)} ${group.endpoint_count} endpoint${group.endpoint_count !== 1 ? 's' : ''}
                </span>
                <span class="permission-badge badge-role">
                    ${svgIcon('user', 14)} Default: ${group.default_for_roles.join(', ')}
                </span>
                ${group.dependencies.length > 0 ? `
                    <span class="permission-badge badge-dependency">
                        ${svgIcon('link', 14)} Requires: ${group.dependencies.join(', ')}
                    </span>
                ` : ''}
                <span class="expand-toggle" data-group="${group.name}">
                    ${isExpanded ? '▼ Hide' : '▶ Show'} endpoints
                </span>
            </div>
            
            <div class="endpoint-list ${isExpanded ? '' : 'collapsed'}">
                ${group.endpoints.map(ep => `
                    <div class="endpoint-item">
                        <span class="endpoint-method method-${ep.method.toLowerCase()}">${ep.method}</span>
                        <span class="endpoint-path">${escapePermissionsHtml(ep.path)}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
}

/**
 * Check if group is granted (considering pending changes)
 */
function isGroupGranted(groupName) {
    // Check if there's a pending change
    if (permissionsState.changes.has(groupName)) {
        return permissionsState.changes.get(groupName);
    }
    
    // Check current state - with null safety
    if (!permissionsState.userPermissions || !permissionsState.userPermissions.grantedGroups) {
        console.warn('⚠️  userPermissions.grantedGroups not initialized');
        return false;
    }
    
    const granted = permissionsState.userPermissions.grantedGroups.includes(groupName);
    // Debug logging
    console.log(`🔍 Checking group "${groupName}": ${granted ? '✓ GRANTED' : '✗ NOT GRANTED'}`);
    console.log(`   Available groups:`, permissionsState.userPermissions.grantedGroups);
    return granted;
}

/**
 * Handle permission toggle
 */
function handlePermissionToggle(event) {
    const groupName = event.target.dataset.group;
    const isChecked = event.target.checked;
    
    // Track the change
    const currentState = permissionsState.userPermissions.grantedGroups.includes(groupName);
    
    if (isChecked === currentState) {
        // Change cancelled - remove from pending changes
        permissionsState.changes.delete(groupName);
    } else {
        // Change made - add to pending changes
        permissionsState.changes.set(groupName, isChecked);
    }
    
    // Update UI
    const card = event.target.closest('.permission-card');
    if (isChecked) {
        card.classList.add('granted');
    } else {
        card.classList.remove('granted');
    }
    
    // Update save button
    const saveBtn = document.getElementById('savePermissions');
    if (saveBtn) {
        saveBtn.disabled = permissionsState.changes.size === 0;
    }
}

/**
 * Handle expand/collapse toggle
 */
function handleExpandToggle(event) {
    const groupName = event.target.dataset.group;
    const card = event.target.closest('.permission-card');
    const endpointList = card.querySelector('.endpoint-list');
    
    if (permissionsState.expandedGroups.has(groupName)) {
        permissionsState.expandedGroups.delete(groupName);
        endpointList.classList.add('collapsed');
        event.target.textContent = '▶ Show endpoints';
    } else {
        permissionsState.expandedGroups.add(groupName);
        endpointList.classList.remove('collapsed');
        event.target.textContent = '▼ Hide endpoints';
    }
}

/**
 * Save permission changes
 */
async function savePermissions() {
    if (permissionsState.changes.size === 0) return;
    
    const saveBtn = document.getElementById('savePermissions');
    saveBtn.disabled = true;
    saveBtn.textContent = '💾 Saving...';
    
    let successCount = 0;
    let errorCount = 0;
    
    try {
        // Process each change
        for (const [groupName, shouldGrant] of permissionsState.changes.entries()) {
            try {
                if (shouldGrant) {
                    // Grant permission
                    const response = await fetch(`${PERMISSIONS_API_BASE}/permissions/users/${permissionsState.selectedUserId}/grant`, {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${state.token}`,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ endpoint_group: groupName })
                    });
                    
                    if (response.ok) {
                        successCount++;
                    } else {
                        throw new Error(`Failed to grant ${groupName}`);
                    }
                } else {
                    // Revoke permission
                    const response = await fetch(`${PERMISSIONS_API_BASE}/permissions/users/${permissionsState.selectedUserId}/revoke/${groupName}`, {
                        method: 'DELETE',
                        headers: {
                            'Authorization': `Bearer ${state.token}`
                        }
                    });
                    
                    if (response.ok) {
                        successCount++;
                    } else {
                        throw new Error(`Failed to revoke ${groupName}`);
                    }
                }
            } catch (error) {
                console.error(`Error processing ${groupName}:`, error);
                errorCount++;
            }
        }
        
        // Show result
        if (errorCount === 0) {
            showPermissionsAlert(`✅ Successfully saved ${successCount} permission change${successCount !== 1 ? 's' : ''}`, 'success');
        } else {
            showPermissionsAlert(`⚠️ Saved ${successCount} changes, ${errorCount} failed`, 'error');
        }
        
        // Clear changes and reload
        permissionsState.changes.clear();
        await loadUserPermissions(permissionsState.selectedUserId);
        renderPermissionsPanel();
        
    } catch (error) {
        console.error('Error saving permissions:', error);
        showPermissionsAlert('Failed to save permissions', 'error');
    } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = '💾 Save Changes';
    }
}

/**
 * Show alert message
 */
function showPermissionsAlert(message, type = 'success') {
    const container = document.getElementById('permissions-alert-container');
    const alertId = Date.now();
    
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.id = `alert-${alertId}`;
    alert.innerHTML = `
        <span>${message}</span>
        <button class="alert-close-btn" style="margin-left: auto; background: none; border: none; cursor: pointer; font-size: 18px;">×</button>
    `;
    
    // Add close button event listener
    const closeBtn = alert.querySelector('.alert-close-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => alert.remove());
    }
    
    container.appendChild(alert);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        const alertEl = document.getElementById(`alert-${alertId}`);
        if (alertEl) alertEl.remove();
    }, 5000);
}

/**
 * Get section icon
 */
function getSectionIcon(section) {
    const icons = {
        'System': 'settings',
        'Authentication': 'lock',
        'Temporary Credentials': 'clock',
        'Users': 'users',
        'Dashboard': 'activity',
        'Vaults': 'vault',
        'Files': 'folder'
    };
    return svgIcon(icons[section] || 'folder');
}

/**
 * Escape HTML to prevent XSS
 */
function escapePermissionsHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


