/**
 * User Management Module - Modern UI for comprehensive user administration
 * Features: User list, temp credentials, roles, activity logs, metrics
 */

// =============================================================================
// State Management
// =============================================================================

const userManagementState = {
    users: [],
    selectedUser: null,
    metrics: null,
    filters: {
        search: '',
        role: null,
        isActive: null
    },
    currentTab: 'info', // info, temp-creds, roles, activity
    autoRefreshInterval: null, // For live updates
    autoRefreshEnabled: true,
    etags: {} // Store ETags for conditional requests: { url: etag }
};

// =============================================================================
// Conditional Update System (ETag-based)
// =============================================================================

/**
 * Enhanced fetch with ETag support for conditional updates.
 * Returns { data, unchanged } where unchanged=true means 304 Not Modified.
 */
async function fetchWithETag(endpoint) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
        'Authorization': `Bearer ${state.token}`,
        'Content-Type': 'application/json'
    };
    
    // Add If-None-Match header if we have a cached ETag
    const cachedETag = userManagementState.etags[endpoint];
    if (cachedETag) {
        headers['If-None-Match'] = cachedETag;
    }
    
    console.log(`API Request: GET ${endpoint}` + (cachedETag ? ' (with ETag)' : ''));
    
    try {
        const response = await fetch(url, { headers });
        
        // Handle 304 Not Modified - data hasn't changed
        if (response.status === 304) {
            console.log(`✓ No changes for ${endpoint} (saved bandwidth!)`);
            return { data: null, unchanged: true };
        }
        
        // Handle auth errors
        if (response.status === 401) {
            if (window.sessionManager) {
                window.sessionManager.handleAuthError(response);
            }
            throw new Error('Session expired. Please log in again.');
        }
        
        // Handle permission errors
        if (response.status === 403) {
            const data = await response.json();
            throw new Error(data.detail || 'Access denied');
        }
        
        // Handle other errors
        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.detail || `Request failed with status ${response.status}`);
        }
        
        // Extract and cache ETag from response headers
        const etag = response.headers.get('ETag');
        if (etag) {
            userManagementState.etags[endpoint] = etag;
            console.log(`✓ Cached ETag for ${endpoint}: ${etag.substring(0, 12)}...`);
        }
        
        // Return data
        const data = await response.json();
        console.log(`API Success: ${endpoint}`, data);
        return { data, unchanged: false };
        
    } catch (error) {
        console.error(`API Request failed: ${endpoint}`, error);
        throw error;
    }
}

// =============================================================================
// Utility Functions (defensive wrappers around global functions)
// =============================================================================

function safeEscapeHtml(text) {
    if (text === null || text === undefined) return '';
    // Use global escapeHtml if available, otherwise do basic escaping
    if (typeof escapeHtml === 'function') {
        return escapeHtml(text);
    }
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

function safeFormatDateTime(isoString) {
    if (!isoString) return 'Never';
    try {
        // Use global formatDateTime if available
        if (typeof formatDateTime === 'function') {
            return formatDateTime(isoString);
        }
        // Fallback: basic date formatting
        const date = new Date(isoString);
        return date.toLocaleString();
    } catch (e) {
        return isoString;
    }
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchUserMetrics() {
    try {
        const response = await fetchAPI('/api/user-management/metrics');
        userManagementState.metrics = response;
        renderMetricsCards();
    } catch (error) {
        console.error('Failed to fetch metrics:', error);
        showError('Failed to load user metrics');
    }
}

async function fetchUsers() {
    try {
        const params = new URLSearchParams();
        if (userManagementState.filters.search) {
            params.append('search', userManagementState.filters.search);
        }
        if (userManagementState.filters.role) {
            params.append('role', userManagementState.filters.role);
        }
        if (userManagementState.filters.isActive !== null) {
            params.append('is_active', userManagementState.filters.isActive);
        }
        
        const endpoint = `/api/user-management/users${params.toString() ? '?' + params.toString() : ''}`;
        const { data, unchanged } = await fetchWithETag(endpoint);
        
        // Skip update if data hasn't changed (304 Not Modified)
        if (unchanged) {
            console.log('⏭️ Skipping user list update - data unchanged');
            return;
        }
        
        userManagementState.users = data;
        renderUsersList();
    } catch (error) {
        console.error('Failed to fetch users:', error);
        showError('Failed to load users');
    }
}

async function fetchUserDetail(userId) {
    try {
        const endpoint = `/api/user-management/users/${userId}`;
        const { data, unchanged } = await fetchWithETag(endpoint);
        
        // Skip update if data hasn't changed
        if (unchanged) {
            console.log('⏭️ Skipping user detail update - data unchanged');
            return;
        }
        
        userManagementState.selectedUser = data;
        renderUserDetailModal();
    } catch (error) {
        console.error('Failed to fetch user details:', error);
        showError('Failed to load user details');
    }
}

async function updateUser(userId, updateData) {
    try {
        await fetchAPI(`/api/user-management/users/${userId}`, {
            method: 'PUT',
            body: JSON.stringify(updateData)
        });
        showSuccess('User updated successfully');
        await fetchUsers();
        await fetchUserDetail(userId);
    } catch (error) {
        console.error('Failed to update user:', error);
        showError(error.message || 'Failed to update user');
    }
}

async function toggleUserActive(userId) {
    try {
        await fetchAPI(`/api/user-management/users/${userId}/toggle-active`, {
            method: 'POST'
        });
        showSuccess('User status updated');
        await fetchUsers();
        if (userManagementState.selectedUser?.id === userId) {
            await fetchUserDetail(userId);
        }
    } catch (error) {
        console.error('Failed to toggle user status:', error);
        showError(error.message || 'Failed to update user status');
    }
}

async function toggleUserLocked(userId) {
    try {
        await fetchAPI(`/api/user-management/users/${userId}/toggle-locked`, {
            method: 'POST'
        });
        showSuccess('User lock status updated');
        await fetchUsers();
        if (userManagementState.selectedUser?.id === userId) {
            await fetchUserDetail(userId);
        }
    } catch (error) {
        console.error('Failed to toggle lock status:', error);
        showError(error.message || 'Failed to update lock status');
    }
}

async function fetchUserTempCredentials(userId) {
    try {
        const endpoint = `/api/user-management/users/${userId}/temp-credentials`;
        const { data, unchanged } = await fetchWithETag(endpoint);
        
        // Return indication of whether data changed
        return { tempCreds: data, unchanged };
    } catch (error) {
        console.error('Failed to fetch temp credentials:', error);
        return { tempCreds: [], unchanged: false };
    }
}

async function createTempCredentialForUser(userId) {
    try {
        const result = await fetchAPI(`/api/user-management/users/${userId}/temp-credentials`, {
            method: 'POST',
            body: JSON.stringify({ user_id: userId, validity_minutes: 65 })
        });
        showSuccess(result.message);
        // Refresh temp credentials tab
        if (userManagementState.currentTab === 'temp-creds') {
            await renderTempCredentialsTab(userId);
        }
    } catch (error) {
        console.error('Failed to create temp credential:', error);
        showError(error.message || 'Failed to create temp credential');
    }
}

async function revealTempCredentialPassword(tempUsername) {
    try {
        const result = await fetchAPI(`/temp-creds/${tempUsername}/password`, {
            method: 'GET'
        });
        return result.password;
    } catch (error) {
        console.error('Failed to reveal password:', error);
        showError('Password not available (expired, used, or deactivated)');
        return null;
    }
}

async function deactivateTempCredential(tempUsername) {
    try {
        await fetchAPI(`/temp-creds/${tempUsername}/deactivate`, {
            method: 'POST'
        });
        showSuccess('Temp credential deactivated');
        // Refresh temp credentials tab
        if (userManagementState.currentTab === 'temp-creds' && userManagementState.selectedUser) {
            await renderTempCredentialsTab(userManagementState.selectedUser.id);
        }
    } catch (error) {
        console.error('Failed to deactivate temp credential:', error);
        showError(error.message || 'Failed to deactivate');
    }
}

async function deleteTempCredential(tempUsername) {
    if (!confirm('Are you sure you want to delete this temp credential? This action cannot be undone.')) {
        return;
    }
    
    try {
        await fetchAPI(`/temp-creds/${tempUsername}/delete`, {
            method: 'POST'
        });
        showSuccess('Temp credential deleted');
        // Refresh temp credentials tab
        if (userManagementState.currentTab === 'temp-creds' && userManagementState.selectedUser) {
            await renderTempCredentialsTab(userManagementState.selectedUser.id);
        }
    } catch (error) {
        console.error('Failed to delete temp credential:', error);
        showError(error.message || 'Failed to delete');
    }
}

async function fetchUserActivity(userId, days = 30) {
    try {
        const endpoint = `/api/user-management/users/${userId}/activity?days=${days}`;
        const { data, unchanged } = await fetchWithETag(endpoint);
        
        // Return indication of whether data changed
        return { activity: data, unchanged };
    } catch (error) {
        console.error('Failed to fetch activity:', error);
        return { activity: [], unchanged: false };
    }
}

// =============================================================================
// Render Functions
// =============================================================================

function renderMetricsCards() {
    const container = document.getElementById('user-metrics-cards');
    if (!container || !userManagementState.metrics) return;
    
    const metrics = userManagementState.metrics;
    
    container.innerHTML = `
        <div class="metric-card metric-card-primary">
            <div class="metric-icon">${svgIcon('users', 24)}</div>
            <div class="metric-content">
                <div class="metric-value">${metrics.total_users}</div>
                <div class="metric-label">Total Users</div>
            </div>
        </div>

        <div class="metric-card metric-card-success">
            <div class="metric-icon">${svgIcon('check', 24)}</div>
            <div class="metric-content">
                <div class="metric-value">${metrics.active_users}</div>
                <div class="metric-label">Active Users</div>
            </div>
        </div>

        <div class="metric-card metric-card-info">
            <div class="metric-icon">${svgIcon('calendar', 24)}</div>
            <div class="metric-content">
                <div class="metric-value">${metrics.new_this_month}</div>
                <div class="metric-label">New This Month</div>
            </div>
        </div>

        <div class="metric-card metric-card-warning">
            <div class="metric-icon">${svgIcon('key', 24)}</div>
            <div class="metric-content">
                <div class="metric-value">${metrics.active_temp_credentials}</div>
                <div class="metric-label">Active Temp Accounts</div>
            </div>
        </div>

        <div class="metric-card metric-card-secondary">
            <div class="metric-icon">${svgIcon('link', 24)}</div>
            <div class="metric-content">
                <div class="metric-value">${metrics.total_sessions}</div>
                <div class="metric-label">Active Sessions</div>
            </div>
        </div>

        <div class="metric-card metric-card-danger">
            <div class="metric-icon">${svgIcon('lock', 24)}</div>
            <div class="metric-content">
                <div class="metric-value">${metrics.locked_users}</div>
                <div class="metric-label">Locked Users</div>
            </div>
        </div>
    `;
}

function renderUsersList() {
    const container = document.getElementById('users-list-container');
    if (!container) return;
    
    if (userManagementState.users.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">${svgIcon('users', 48)}</div>
                <p>No users found</p>
            </div>
        `;
        return;
    }
    
    const table = `
        <table class="data-table users-expandable-table">
            <thead>
                <tr>
                    <th style="width: 40px;"></th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Temp Accounts</th>
                    <th>Sessions</th>
                    <th>Last Login</th>
                </tr>
            </thead>
            <tbody>
                ${userManagementState.users.map(user => renderUserRow(user)).join('')}
            </tbody>
        </table>
    `;
    
    container.innerHTML = table;
    
    // Add click handlers for expand buttons
    container.querySelectorAll('.expand-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const userId = btn.dataset.userId;
            toggleUserDetails(userId);
        });
    });
}

function renderUserRow(user) {
    const statusBadge = user.is_active 
        ? '<span class="badge badge-success">Active</span>' 
        : '<span class="badge badge-secondary">Inactive</span>';
    
    const lockedBadge = user.is_locked 
        ? '<span class="badge badge-danger">Locked</span>' 
        : '';
    
    const roleBadge = getRoleBadge(user.role);
    
    const lastLogin = user.last_login 
        ? safeFormatDateTime(user.last_login)
        : '<span class="text-muted">Never</span>';
    
    return `
        <tr class="user-row" data-user-id="${user.id}">
            <td style="width: 40px;">
                <button class="expand-btn" data-user-id="${user.id}" aria-label="Expand details">
                    <svg class="chevron-icon" width="18" height="18" viewBox="0 0 24 24" fill="none">
                        <path d="M9 7l5 5-5 5" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </button>
            </td>
            <td><strong>${safeEscapeHtml(user.username)}</strong></td>
            <td>${safeEscapeHtml(user.email)}</td>
            <td>${roleBadge}</td>
            <td>${statusBadge} ${lockedBadge}</td>
            <td>${user.temp_credentials_count}</td>
            <td>${user.active_sessions_count}</td>
            <td>${lastLogin}</td>
        </tr>
        <tr class="user-details-row" data-user-id="${user.id}" style="display: none;">
            <td colspan="8" class="details-cell">
                <div class="user-details-panel">
                    <div class="details-loading">Loading...</div>
                </div>
            </td>
        </tr>
    `;
}

function getRoleBadge(role) {
    const badges = {
        admin: '<span class="badge badge-danger">Admin</span>',
        user: '<span class="badge badge-primary">User</span>',
        external: '<span class="badge badge-warning">External</span>'
    };
    return badges[role] || '<span class="badge badge-secondary">Unknown</span>';
}

// =============================================================================
// Expandable Row Functions (replaces modal)
// =============================================================================

async function toggleUserDetails(userId) {
    const detailsRow = document.querySelector(`.user-details-row[data-user-id="${userId}"]`);
    const userRow = document.querySelector(`.user-row[data-user-id="${userId}"]`);
    const expandBtn = userRow?.querySelector('.expand-btn');
    const chevronIcon = expandBtn?.querySelector('.chevron-icon');
    
    if (!detailsRow || !userRow) return;
    
    const isExpanded = detailsRow.style.display !== 'none';
    
    if (isExpanded) {
        // Collapse this row
        detailsRow.style.display = 'none';
        userRow.classList.remove('expanded');
        if (chevronIcon) {
            chevronIcon.style.transform = 'rotate(0deg)';
        }
    } else {
        // Collapse all other rows first (accordion behavior)
        document.querySelectorAll('.user-details-row').forEach(row => {
            row.style.display = 'none';
        });
        document.querySelectorAll('.user-row').forEach(row => {
            row.classList.remove('expanded');
        });
        document.querySelectorAll('.chevron-icon').forEach(icon => {
            icon.style.transform = 'rotate(0deg)';
        });
        
        // Expand this row
        detailsRow.style.display = 'table-row';
        userRow.classList.add('expanded');
        if (chevronIcon) {
            chevronIcon.style.transform = 'rotate(90deg)';
        }
        
        // Load user details
        await loadUserDetails(userId, detailsRow);
    }
}

async function loadUserDetails(userId, detailsRow) {
    const panel = detailsRow.querySelector('.user-details-panel');
    if (!panel) return;
    
    // Show loading state
    panel.innerHTML = '<div class="details-loading">Loading user details...</div>';
    
    try {
        // Fetch user details
        const user = await fetchAPI(`/api/user-management/users/${userId}`);
        userManagementState.selectedUser = user;
        
        // Render the expanded panel with tabs
        renderExpandedUserPanel(panel, user);
        
        // Load initial tab content (Info tab)
        await renderInfoTabInline(panel, user);
        
    } catch (error) {
        console.error('Failed to load user details:', error);
        panel.innerHTML = '<div class="details-error">Failed to load user details</div>';
    }
}

function renderExpandedUserPanel(panel, user) {
    panel.innerHTML = `
        <div class="expanded-panel-content">
            <div class="panel-header">
                <h3><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                    <circle cx="12" cy="7" r="4"></circle>
                </svg> ${safeEscapeHtml(user.username)}</h3>
            </div>
            
            <div class="panel-tabs">
                <button class="panel-tab-btn active" data-tab="info" data-user-id="${user.id}">
                    ${svgIcon('info')} Information
                </button>
                <button class="panel-tab-btn" data-tab="temp-creds" data-user-id="${user.id}">
                    ${svgIcon('key')} Temp Accounts
                </button>
                <button class="panel-tab-btn" data-tab="activity" data-user-id="${user.id}">
                    ${svgIcon('activity')} Activity
                </button>
            </div>
            
            <div class="panel-tab-content" id="panel-content-${user.id}">
                <div class="content-loading">Loading...</div>
            </div>
        </div>
    `;
    
    // Add tab click handlers
    panel.querySelectorAll('.panel-tab-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const tabName = btn.dataset.tab;
            const userId = btn.dataset.userId;
            
            // Update active tab button
            panel.querySelectorAll('.panel-tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Load tab content
            const contentDiv = panel.querySelector(`#panel-content-${userId}`);
            switch(tabName) {
                case 'info':
                    await renderInfoTabInline(panel, user);
                    break;
                case 'temp-creds':
                    await renderTempCredsTabInline(panel, user);
                    break;
                case 'activity':
                    await renderActivityTabInline(panel, user);
                    break;
            }
        });
    });
}

async function renderInfoTabInline(panel, user) {
    const contentDiv = panel.querySelector(`#panel-content-${user.id}`);
    if (!contentDiv) return;
    
    contentDiv.innerHTML = `
        <div class="info-grid">
            <div class="info-card">
                <h4>${svgIcon('info')} Basic Information</h4>
                <div class="info-row">
                    <label>Username:</label>
                    <span>${safeEscapeHtml(user.username)}</span>
                </div>
                <div class="info-row">
                    <label>Email:</label>
                    <span>${safeEscapeHtml(user.email)}</span>
                </div>
                <div class="info-row">
                    <label>Role:</label>
                    <span class="badge badge-${user.role}">${safeEscapeHtml(user.role)}</span>
                </div>
                <div class="info-row">
                    <label>Created:</label>
                    <span>${safeFormatDateTime(user.created_at)}</span>
                </div>
            </div>
            
            <div class="info-card">
                <h4>${svgIcon('lock')} Status & Security</h4>
                <div class="info-row">
                    <label>Status:</label>
                    <span class="badge ${user.is_active ? 'badge-success' : 'badge-secondary'}">
                        ${user.is_active ? 'Active' : 'Inactive'}
                    </span>
                </div>
                <div class="info-row">
                    <label>Lock Status:</label>
                    <span class="badge ${user.is_locked ? 'badge-danger' : 'badge-success'}">
                        ${user.is_locked ? 'Locked' : 'Unlocked'}
                    </span>
                </div>
                <div class="info-row">
                    <label>Failed Logins Since Last Success:</label>
                    <span>${user.failed_login_attempts || 0}</span>
                </div>
                <div class="info-row">
                    <label>Last Login:</label>
                    <span>${safeFormatDateTime(user.last_login)}</span>
                </div>
            </div>
            
            <div class="info-card">
                <h4>${svgIcon('activity')} Statistics</h4>
                <div class="info-row">
                    <label>Active Sessions:</label>
                    <span>${user.active_sessions_count || 0}</span>
                </div>
                <div class="info-row">
                    <label>Temp Credentials:</label>
                    <span>${user.temp_credentials_count || 0}</span>
                </div>
                <div class="info-row">
                    <label>Vaults Owned:</label>
                    <span>${user.vaults_owned_count || 0}</span>
                </div>
                <div class="info-row">
                    <label>Shared Vaults:</label>
                    <span>${user.vaults_accessible_count || 0}</span>
                </div>
            </div>
        </div>
    `;
}

async function renderTempCredsTabInline(panel, user) {
    const contentDiv = panel.querySelector(`#panel-content-${user.id}`);
    if (!contentDiv) return;
    
    try {
        const endpoint = `/api/user-management/users/${user.id}/temp-credentials`;
        const { data: tempCreds, unchanged } = await fetchWithETag(endpoint);
        
        // 🎯 SKIP DOM UPDATE if data hasn't changed (no scroll jump!)
        if (unchanged) {
            console.log('⏭️ Skipping temp creds DOM update - data unchanged');
            return;
        }
        
        if (!tempCreds || tempCreds.length === 0) {
            contentDiv.innerHTML = '<div class="empty-state-small">No temporary credentials found</div>';
            return;
        }
        
        contentDiv.innerHTML = `
            <div class="temp-creds-list">
                ${tempCreds.map(cred => `
                    <div class="temp-cred-card">
                        <div class="cred-header">
                            <span class="badge ${cred.is_active ? 'badge-success' : 'badge-secondary'}">
                                ${cred.is_active ? 'Active' : 'Inactive'}
                            </span>
                            <span class="cred-created">Created: ${safeFormatDateTime(cred.created_at)}</span>
                        </div>
                        <div class="cred-info">
                            <div><strong>Username:</strong> ${safeEscapeHtml(cred.temp_username)}</div>
                            <div><strong>Expires:</strong> ${safeFormatDateTime(cred.expires_at)}</div>
                            <div><strong>Used:</strong> ${cred.is_used ? 'Yes' + (cred.used_at ? ' at ' + safeFormatDateTime(cred.used_at) : '') : 'No'}</div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        contentDiv.innerHTML = '<div class="details-error">Failed to load temp credentials</div>';
    }
}

async function renderActivityTabInline(panel, user) {
    const contentDiv = panel.querySelector(`#panel-content-${user.id}`);
    if (!contentDiv) return;
    
    try {
        const endpoint = `/api/user-management/users/${user.id}/activity`;
        const { data: activities, unchanged } = await fetchWithETag(endpoint);
        
        // 🎯 SKIP DOM UPDATE if data hasn't changed (no scroll jump!)
        if (unchanged) {
            console.log('⏭️ Skipping activity DOM update - data unchanged');
            return;
        }
        
        if (!activities || activities.length === 0) {
            contentDiv.innerHTML = '<div class="empty-state-small">No activity recorded</div>';
            return;
        }
        
        contentDiv.innerHTML = `
            <div class="activity-timeline-inline">
                ${activities.map(activity => `
                    <div class="activity-item-inline" data-action-type="${getActionType(activity.action)}">
                        <div class="activity-icon">
                            ${getActivityIcon(activity.action)}
                        </div>
                        <div class="activity-content">
                            <div class="activity-action">${safeEscapeHtml(activity.action)}</div>
                            <div class="activity-meta">
                                ${safeFormatDateTime(activity.timestamp)}
                                ${activity.ip_address ? ` • ${safeEscapeHtml(activity.ip_address)}` : ''}
                                ${activity.performed_by_username ? ` • by ${safeEscapeHtml(activity.performed_by_username)}` : ''}
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        contentDiv.innerHTML = '<div class="details-error">Failed to load activity</div>';
    }
}

function getActivityIcon(action) {
    // Convert action to lowercase for matching
    const actionLower = (action || '').toLowerCase();
    
    // Match based on action content
    if (actionLower.includes('login')) return svgIcon('login');
    if (actionLower.includes('logout')) return svgIcon('logout');
    if (actionLower.includes('create')) return svgIcon('plus');
    if (actionLower.includes('update') || actionLower.includes('edit') || actionLower.includes('modif')) return svgIcon('edit');
    if (actionLower.includes('delete') || actionLower.includes('remove')) return svgIcon('trash');
    if (actionLower.includes('unlock')) return svgIcon('unlock');
    if (actionLower.includes('lock')) return svgIcon('lock');
    if (actionLower.includes('activat')) return svgIcon('check');
    if (actionLower.includes('deactivat') || actionLower.includes('disable')) return svgIcon('ban');
    if (actionLower.includes('upload')) return svgIcon('upload');
    if (actionLower.includes('download')) return svgIcon('download');
    if (actionLower.includes('access') || actionLower.includes('view')) return svgIcon('eye');
    if (actionLower.includes('password') || actionLower.includes('credential')) return svgIcon('key');

    return svgIcon('info'); // Default icon
}

function getActionType(action) {
    // Determine action category for color coding
    const actionLower = (action || '').toLowerCase();
    
    if (actionLower.includes('login') && !actionLower.includes('fail')) return 'login';
    if (actionLower.includes('logout')) return 'logout';
    if (actionLower.includes('create')) return 'create';
    if (actionLower.includes('update') || actionLower.includes('edit')) return 'update';
    if (actionLower.includes('delete') || actionLower.includes('remove')) return 'delete';
    if (actionLower.includes('fail') || actionLower.includes('error')) return 'error';
    if (actionLower.includes('lock')) return 'warning';
    if (actionLower.includes('unlock') || actionLower.includes('activat')) return 'success';
    
    return 'default';
}

// Keep modal functions for backward compatibility but they won't be used
async function openUserDetailModal(userId) {
    // Deprecated: Now using expandable rows instead
    await toggleUserDetails(userId);
}

function renderUserDetailModal() {
    const modal = document.getElementById('user-detail-modal-content');
    if (!modal || !userManagementState.selectedUser) return;
    
    const user = userManagementState.selectedUser;
    
    modal.innerHTML = `
        <div class="modal-header">
            <h3>${svgIcon('user')} User: ${escapeHtml(user.username)}</h3>
            <button class="modal-close close-user-modal-btn">&times;</button>
        </div>
        <div class="modal-body">
            <!-- Tab Navigation -->
            <div class="tabs">
                <button class="tab-btn ${userManagementState.currentTab === 'info' ? 'active' : ''} user-tab-btn" 
                        data-tab="info">
                    ${svgIcon('info')} Information
                </button>
                <button class="tab-btn ${userManagementState.currentTab === 'temp-creds' ? 'active' : ''} user-tab-btn"
                        data-tab="temp-creds">
                    ${svgIcon('key')} Temp Accounts
                </button>
                <button class="tab-btn ${userManagementState.currentTab === 'activity' ? 'active' : ''} user-tab-btn"
                        data-tab="activity">
                    ${svgIcon('activity')} Activity
                </button>
            </div>
            
            <!-- Tab Content -->
            <div class="tab-content">
                <div id="user-tab-content"></div>
            </div>
        </div>
    `;
    
    // Render initial tab
    switchUserTab(userManagementState.currentTab);
}

async function switchUserTab(tabName) {
    userManagementState.currentTab = tabName;
    
    // Update tab buttons
    document.querySelectorAll('.user-tab-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
        }
    });
    
    const contentDiv = document.getElementById('user-tab-content');
    if (!contentDiv || !userManagementState.selectedUser) return;
    
    switch (tabName) {
        case 'info':
            renderInfoTab();
            break;
        case 'temp-creds':
            await renderTempCredentialsTab(userManagementState.selectedUser.id);
            break;
        case 'activity':
            await renderActivityTab(userManagementState.selectedUser.id);
            break;
    }
}

function renderInfoTab() {
    const contentDiv = document.getElementById('user-tab-content');
    const user = userManagementState.selectedUser;
    if (!contentDiv || !user) return;
    
    contentDiv.innerHTML = `
        <div class="user-info-grid">
            <div class="info-section">
                <h4>Basic Information</h4>
                <div class="info-row">
                    <label>Username:</label>
                    <span>${escapeHtml(user.username)}</span>
                </div>
                <div class="info-row">
                    <label>Email:</label>
                    <input type="email" id="user-email-input" value="${escapeHtml(user.email)}" />
                </div>
                <div class="info-row">
                    <label>Role:</label>
                    <select id="user-role-input">
                        <option value="user" ${user.role === 'user' ? 'selected' : ''}>User</option>
                        <option value="external" ${user.role === 'external' ? 'selected' : ''}>External</option>
                        <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                </div>
            </div>
            
            <div class="info-section">
                <h4>Status & Security</h4>
                <div class="info-row">
                    <label>Status:</label>
                    <button class="btn btn-small ${user.is_active ? 'btn-success' : 'btn-secondary'} toggle-active-btn" 
                            data-user-id="${user.id}">
                        ${user.is_active ? `${svgIcon('check')} Active` : `${svgIcon('x')} Inactive`}
                    </button>
                </div>
                <div class="info-row">
                    <label>Lock Status:</label>
                    <button class="btn btn-small ${user.is_locked ? 'btn-danger' : 'btn-success'} toggle-locked-btn" 
                            data-user-id="${user.id}">
                        ${user.is_locked ? `${svgIcon('lock')} Locked` : `${svgIcon('unlock')} Unlocked`}
                    </button>
                </div>
                <div class="info-row">
                    <label>Failed Attempts:</label>
                    <span>${user.failed_login_attempts}</span>
                </div>
            </div>
            
            <div class="info-section">
                <h4>Statistics</h4>
                <div class="info-row">
                    <label>Temp Credentials:</label>
                    <span>${user.temp_credentials_count}</span>
                </div>
                <div class="info-row">
                    <label>Active Sessions:</label>
                    <span>${user.active_sessions_count}</span>
                </div>
                <div class="info-row">
                    <label>Vaults Owned:</label>
                    <span>${user.vaults_owned_count}</span>
                </div>
                <div class="info-row">
                    <label>Vaults Accessible:</label>
                    <span>${user.vaults_accessible_count}</span>
                </div>
            </div>
            
            <div class="info-section">
                <h4>Timestamps</h4>
                <div class="info-row">
                    <label>Created:</label>
                    <span>${formatDateTime(user.created_at)}</span>
                </div>
                <div class="info-row">
                    <label>Last Login:</label>
                    <span>${user.last_login ? formatDateTime(user.last_login) : 'Never'}</span>
                </div>
                <div class="info-row">
                    <label>Last Updated:</label>
                    <span>${formatDateTime(user.updated_at)}</span>
                </div>
            </div>
        </div>
        
        <div class="modal-actions">
            <button class="btn btn-secondary close-user-modal-btn">Close</button>
            <button class="btn btn-primary save-user-info-btn">Save Changes</button>
        </div>
    `;
}

async function renderTempCredentialsTab(userId) {
    const contentDiv = document.getElementById('user-tab-content');
    if (!contentDiv) return;
    
    contentDiv.innerHTML = '<div class="loading">Loading temp credentials...</div>';
    
    const tempCreds = await fetchUserTempCredentials(userId);
    
    if (tempCreds.length === 0) {
        contentDiv.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">${svgIcon('key', 48)}</div>
                <p>No temp credentials found</p>
                <button class="btn btn-primary create-temp-cred-btn" data-user-id="${userId}">
                    Create Temp Credential
                </button>
            </div>
        `;
        return;
    }
    
    const table = `
        <div class="temp-creds-actions">
            <button class="btn btn-primary create-temp-cred-btn" data-user-id="${userId}">
                ${svgIcon('plus')} Create New
            </button>
        </div>
        
        <table class="data-table">
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Expires</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${tempCreds.map(cred => renderTempCredRow(cred)).join('')}
            </tbody>
        </table>
    `;
    
    contentDiv.innerHTML = table;
}

function renderTempCredRow(cred) {
    const statusBadge = getTempCredStatusBadge(cred);
    const expiresIn = getTimeUntilExpiry(cred.expires_at);
    
    return `
        <tr>
            <td><code>${escapeHtml(cred.temp_username)}</code></td>
            <td>${statusBadge}</td>
            <td>${formatDateTime(cred.created_at)}</td>
            <td>${expiresIn}</td>
            <td>
                ${cred.has_password && !cred.is_used ? `
                    <button class="btn btn-small btn-info show-temp-password-btn" data-username="${escapeHtml(cred.temp_username)}">
                        ${svgIcon('eye')} Show Password
                    </button>
                ` : ''}
                ${cred.is_active ? `
                    <button class="btn btn-small btn-warning deactivate-temp-cred-btn" data-username="${escapeHtml(cred.temp_username)}">
                        Deactivate
                    </button>
                ` : ''}
                <button class="btn btn-small btn-danger delete-temp-cred-btn" data-username="${escapeHtml(cred.temp_username)}">
                    ${svgIcon('trash')} Delete
                </button>
            </td>
        </tr>
    `;
}

function getTempCredStatusBadge(cred) {
    if (!cred.is_active) {
        return '<span class="badge badge-secondary">Deactivated</span>';
    }
    if (cred.is_used) {
        return '<span class="badge badge-success">In Use</span>';
    }
    if (new Date(cred.expires_at) < new Date()) {
        return '<span class="badge badge-danger">Expired</span>';
    }
    return '<span class="badge badge-primary">Active</span>';
}

function getTimeUntilExpiry(expiryDate) {
    const now = new Date();
    const expires = new Date(expiryDate);
    const diffMs = expires - now;
    
    if (diffMs < 0) {
        return '<span class="text-danger">Expired</span>';
    }
    
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 60) {
        return `<span class="text-warning">${diffMins}m remaining</span>`;
    }
    
    const diffHours = Math.floor(diffMins / 60);
    return `<span class="text-success">${diffHours}h ${diffMins % 60}m</span>`;
}

async function showTempCredPassword(tempUsername) {
    const password = await revealTempCredentialPassword(tempUsername);
    if (password) {
        // Show in modal or inline
        alert(`Password: ${password}\n\nCopy this password now!`);
    }
}

async function renderActivityTab(userId) {
    const contentDiv = document.getElementById('user-tab-content');
    if (!contentDiv) return;
    
    contentDiv.innerHTML = '<div class="loading">Loading activity...</div>';
    
    const activity = await fetchUserActivity(userId, 30);
    
    if (activity.length === 0) {
        contentDiv.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">${svgIcon('activity', 48)}</div>
                <p>No activity found in the last 30 days</p>
            </div>
        `;
        return;
    }
    
    const timeline = `
        <div class="activity-timeline">
            ${activity.map(log => renderActivityItem(log)).join('')}
        </div>
    `;
    
    contentDiv.innerHTML = timeline;
}

function renderActivityItem(log) {
    const icon = getActivityIcon(log.action);
    return `
        <div class="activity-item">
            <div class="activity-icon">${icon}</div>
            <div class="activity-content">
                <div class="activity-action">${escapeHtml(log.action)}</div>
                ${log.details ? `<div class="activity-details">${escapeHtml(log.details)}</div>` : ''}
                <div class="activity-meta">
                    ${formatDateTime(log.timestamp)}
                    ${log.performed_by_username ? ` • by ${escapeHtml(log.performed_by_username)}` : ''}
                    ${log.ip_address ? ` • from ${log.ip_address}` : ''}
                </div>
            </div>
        </div>
    `;
}

function getActivityIcon(action) {
    const icons = {
        'USER_LOGIN': 'login',
        'USER_LOGOUT': 'logout',
        'USER_CREATED': 'sparkles',
        'USER_UPDATED': 'edit',
        'USER_DELETED': 'trash',
        'USER_STATUS_CHANGED': 'refresh',
        'USER_LOCK_CHANGED': 'lock',
        'TEMP_CREDENTIAL_CREATED': 'key',
        'TEMP_CREDENTIAL_DEACTIVATED': 'ban',
        'TEMP_CREDENTIAL_DELETED': 'trash',
        'VAULT_CREATED': 'vault',
        'FILE_UPLOADED': 'upload',
        'FILE_DOWNLOADED': 'download',
        'FILE_DELETED': 'trash'
    };
    return svgIcon(icons[action] || 'info');
}

async function saveUserInfo() {
    const user = userManagementState.selectedUser;
    if (!user) return;
    
    const email = document.getElementById('user-email-input')?.value;
    const role = document.getElementById('user-role-input')?.value;
    
    const updateData = {};
    if (email && email !== user.email) {
        updateData.email = email;
    }
    if (role && role !== user.role) {
        updateData.role = role;
    }
    
    if (Object.keys(updateData).length === 0) {
        showInfo('No changes to save');
        return;
    }
    
    await updateUser(user.id, updateData);
}

function closeUserDetailModal() {
    const modal = document.getElementById('user-detail-modal');
    if (modal) {
        modal.classList.remove('active');
        setTimeout(() => {
            userManagementState.selectedUser = null;
            userManagementState.currentTab = 'info';
        }, 300);
    }
}

// =============================================================================
// Filter Functions
// =============================================================================

function applyUserFilters() {
    const search = document.getElementById('user-search-input')?.value || '';
    const role = document.getElementById('user-role-filter')?.value || null;
    const status = document.getElementById('user-status-filter')?.value;
    
    userManagementState.filters.search = search;
    userManagementState.filters.role = role === 'all' ? null : role;
    userManagementState.filters.isActive = status === 'all' ? null : status === 'active';
    
    fetchUsers();
}

function clearUserFilters() {
    document.getElementById('user-search-input').value = '';
    document.getElementById('user-role-filter').value = 'all';
    document.getElementById('user-status-filter').value = 'all';
    
    userManagementState.filters = {
        search: '',
        role: null,
        isActive: null
    };
    
    fetchUsers();
}

// =============================================================================
// Initialization
// =============================================================================

async function initializeUserManagement() {
    console.log('Initializing user management...');
    
    // Fetch initial data
    await Promise.all([
        fetchUserMetrics(),
        fetchUsers()
    ]);
    
    // Set up event listeners for filters
    document.getElementById('user-search-input')?.addEventListener('input', debounce(applyUserFilters, 500));
    document.getElementById('user-role-filter')?.addEventListener('change', applyUserFilters);
    document.getElementById('user-status-filter')?.addEventListener('change', applyUserFilters);
    document.getElementById('clear-user-filters-btn')?.addEventListener('click', clearUserFilters);
    
    // Set up event delegation for dynamically created buttons
    setupUserManagementEventDelegation();
    
    // Refresh metrics every 30 seconds
    setInterval(fetchUserMetrics, 30000);
    
    // Start auto-refresh for live updates
    startAutoRefresh();
}

// Event delegation for all user management buttons
function setupUserManagementEventDelegation() {
    // Delegate for user list container
    document.getElementById('users-list-container')?.addEventListener('click', (e) => {
        const target = e.target.closest('button');
        if (!target) return;
        
        if (target.classList.contains('user-view-btn')) {
            const userId = target.dataset.userId;
            if (userId) openUserDetailModal(userId);
        }
    });
    
    // Delegate for modal
    const modal = document.getElementById('user-detail-modal');
    modal?.addEventListener('click', (e) => {
        const target = e.target.closest('button');
        if (!target) return;
        
        // Close modal buttons
        if (target.classList.contains('close-user-modal-btn')) {
            closeUserDetailModal();
        }
        // Save user info
        else if (target.classList.contains('save-user-info-btn')) {
            saveUserInfo();
        }
        // Tab buttons
        else if (target.classList.contains('user-tab-btn')) {
            const tab = target.dataset.tab;
            if (tab) switchUserTab(tab);
        }
        // Toggle active status
        else if (target.classList.contains('toggle-active-btn')) {
            const userId = target.dataset.userId;
            if (userId) toggleUserActive(userId);
        }
        // Toggle locked status
        else if (target.classList.contains('toggle-locked-btn')) {
            const userId = target.dataset.userId;
            if (userId) toggleUserLocked(userId);
        }
        // Create temp credential
        else if (target.classList.contains('create-temp-cred-btn')) {
            const userId = target.dataset.userId;
            if (userId) createTempCredentialForUser(userId);
        }
        // Show temp password
        else if (target.classList.contains('show-temp-password-btn')) {
            const username = target.dataset.username;
            if (username) showTempCredPassword(username);
        }
        // Deactivate temp credential
        else if (target.classList.contains('deactivate-temp-cred-btn')) {
            const username = target.dataset.username;
            if (username) deactivateTempCredential(username);
        }
        // Delete temp credential
        else if (target.classList.contains('delete-temp-cred-btn')) {
            const username = target.dataset.username;
            if (username) deleteTempCredential(username);
        }
    });
    
    // Close modal on backdrop click
    modal?.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeUserDetailModal();
        }
    });
}

// Debounce helper
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// =============================================================================
// Auto-Refresh / Live Updates
// =============================================================================

function startAutoRefresh() {
    // Clear any existing interval
    if (userManagementState.autoRefreshInterval) {
        clearInterval(userManagementState.autoRefreshInterval);
    }
    
    // Refresh every 10 seconds
    userManagementState.autoRefreshInterval = setInterval(async () => {
        if (!userManagementState.autoRefreshEnabled) return;
        
        try {
            // Check if a user is expanded FIRST
            if (userManagementState.selectedUser) {
                const userId = userManagementState.selectedUser.id;
                const detailsRow = document.querySelector(`.user-details-row[data-user-id="${userId}"]`);
                
                if (detailsRow && detailsRow.style.display !== 'none') {
                    // User is currently expanded, refresh ONLY their data
                    console.log(`Auto-refresh: User ${userId} is expanded, refreshing only their details`);
                    await refreshExpandedUserDetails(userId);
                    return; // EXIT EARLY - don't refresh the full list
                }
            }
            
            // No user expanded, refresh the full user list
            console.log('Auto-refresh: No user expanded, refreshing full list');
            await fetchUsers();
        } catch (error) {
            console.error('Auto-refresh failed:', error);
            // Don't show error to user, just log it
        }
    }, 10000); // 10 seconds
}

async function refreshExpandedUserDetails(userId) {
    try {
        // Fetch fresh user data
        const user = await fetchAPI(`/api/user-management/users/${userId}`);
        userManagementState.selectedUser = user;
        
        // Find the expanded panel
        const detailsRow = document.querySelector(`.user-details-row[data-user-id="${userId}"]`);
        if (!detailsRow) return;
        
        const panel = detailsRow.querySelector('.user-details-panel');
        if (!panel) return;
        
        // Get current active tab
        const activeTabBtn = panel.querySelector('.panel-tab-btn.active');
        const currentTab = activeTabBtn ? activeTabBtn.dataset.tab : 'info';
        
        // Update ONLY the tab content, not the entire panel structure
        // This prevents the "reset" feeling and preserves scroll position
        switch(currentTab) {
            case 'info':
                await renderInfoTabInline(panel, user);
                break;
            case 'temp-creds':
                await renderTempCredsTabInline(panel, user);
                break;
            case 'activity':
                await renderActivityTabInline(panel, user);
                break;
        }
    } catch (error) {
        console.error('Failed to refresh user details:', error);
    }
}

function stopAutoRefresh() {
    if (userManagementState.autoRefreshInterval) {
        clearInterval(userManagementState.autoRefreshInterval);
        userManagementState.autoRefreshInterval = null;
    }
}

// Export for use in main dashboard
window.userManagement = {
    initialize: initializeUserManagement,
    fetchUsers,
    fetchUserMetrics,
    startAutoRefresh,
    stopAutoRefresh
};
