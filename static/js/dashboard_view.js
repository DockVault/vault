/**
 * Dashboard View - Role-Based Dashboard with Real Data
 * Version: 2025100501
 */

// Initialize dashboard when view becomes active
async function initDashboardView() {
    console.log('Initializing dashboard view...');
    
    try {
        // Load dashboard data in parallel
        const [stats, events] = await Promise.all([
            fetchDashboardStats(),
            fetchRecentEvents()
        ]);
        
        // Render based on role
        renderDashboardStats(stats);
        renderRecentEvents(events);
        
        // Load active connections if admin
        if (state.user && state.user.role === 'admin') {
            const connections = await fetchActiveConnections();
            renderActiveConnections(connections);
        }
        
    } catch (error) {
        console.error('Failed to load dashboard:', error);
        showError('Failed to load dashboard data');
    }
}

/**
 * Fetch dashboard statistics from API
 * Uses cache manager for ETag-based caching (304 Not Modified)
 */
async function fetchDashboardStats() {
    try {
        // Use fetchAPI helper which supports cache manager
        return await fetchAPI('/api/dashboard/stats');
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        throw error;
    }
}

/**
 * Fetch recent events from API
 * Uses cache manager for ETag-based caching (304 Not Modified)
 */
async function fetchRecentEvents(limit = 10) {
    try {
        // Use fetchAPI helper which supports cache manager
        return await fetchAPI(`/api/dashboard/recent-events?limit=${limit}`);
    } catch (error) {
        console.error('Error fetching recent events:', error);
        throw error;
    }
}

/**
 * Fetch active connections (admin only)
 * Uses cache manager for ETag-based caching (304 Not Modified)
 */
async function fetchActiveConnections() {
    try {
        // Use fetchAPI helper which supports cache manager
        return await fetchAPI('/api/dashboard/active-connections');
    } catch (error) {
        console.error('Error fetching active connections:', error);
        // Handle 403 gracefully (non-admin)
        if (error.message && error.message.includes('permission')) {
            return [];
        }
        return [];
    }
}

/**
 * Render dashboard statistics
 */
function renderDashboardStats(stats) {
    const role = stats.role;
    
    // Helper function to safely update element
    const safeUpdate = (selector, value) => {
        const element = document.getElementById(selector) || document.querySelector(selector);
        if (element) {
            element.textContent = value;
            return element;
        }
        console.warn(`Element not found: ${selector}`);
        return null;
    };
    
    // Helper function to safely update parent's child element
    const safeUpdateParentChild = (childSelector, parentChildSelector, value) => {
        const child = document.getElementById(childSelector) || document.querySelector(childSelector);
        if (child && child.parentElement) {
            const target = child.parentElement.querySelector(parentChildSelector);
            if (target) {
                target.textContent = value;
                return target;
            }
        }
        console.warn(`Parent/child not found: ${childSelector} -> ${parentChildSelector}`);
        return null;
    };
    
    // Update stat cards based on role
    if (role === 'admin') {
        // Admin sees system-wide stats
        safeUpdate('stat-vaults', stats.vaults || 0);
        safeUpdate('stat-users', stats.users || 0);
        safeUpdate('stat-storage', `${stats.storage_mb || 0} MB`);
        safeUpdate('stat-temp-creds', stats.temp_creds || 0);
        
        // Show system status section (already visible by default for admin)
        const systemStatusCard = document.querySelector('.card:has(#status-db)');
        if (systemStatusCard) {
            systemStatusCard.style.display = 'block';
        }
        
    } else if (role === 'user') {
        // User sees personal stats
        safeUpdate('stat-vaults', stats.vaults || 0);
        safeUpdateParentChild('#stat-vaults', '.stat-label', 'My Vaults');
        
        safeUpdate('stat-users', stats.accessible_vaults || 0);
        safeUpdateParentChild('#stat-users', '.stat-label', 'Accessible Vaults');
        safeUpdateParentChild('#stat-users', '.stat-icon', '🔓');
        
        safeUpdate('stat-storage', `${stats.storage_mb || 0} MB`);
        safeUpdateParentChild('#stat-storage', '.stat-label', 'My Storage');
        
        safeUpdate('stat-temp-creds', stats.temp_creds || 0);
        safeUpdateParentChild('#stat-temp-creds', '.stat-label', 'My Temp Creds');
        
        // Hide system status section for non-admin
        const systemStatusCard = document.querySelector('.card:has(#status-db)');
        if (systemStatusCard) {
            systemStatusCard.style.display = 'none';
        }
        
    } else if (role === 'external') {
        // External user sees minimal stats
        safeUpdate('stat-vaults', stats.accessible_vaults || 0);
        safeUpdateParentChild('#stat-vaults', '.stat-label', 'Accessible Vaults');
        
        // Hide user stat card
        const userStatCard = document.querySelector('#stat-users')?.closest('.stat-card');
        if (userStatCard) {
            userStatCard.style.display = 'none';
        }
        
        // Hide storage card
        const storageStatCard = document.querySelector('#stat-storage').closest('.stat-card');
        if (storageStatCard) {
            storageStatCard.style.display = 'none';
        }
        
        document.getElementById('stat-temp-creds').textContent = stats.temp_creds || 0;
        document.querySelector('#stat-temp-creds').parentElement.querySelector('.stat-label').textContent = 'My Temp Creds';
        
        // Hide system status section for external
        const systemStatusCard = document.querySelector('.card:has(#status-db)');
        if (systemStatusCard) {
            systemStatusCard.style.display = 'none';
        }
    }
}

/**
 * Render recent events
 */
function renderRecentEvents(events) {
    const eventsFeed = document.getElementById('events-feed');
    if (!eventsFeed) return;
    
    if (!events || events.length === 0) {
        eventsFeed.innerHTML = '<div class="empty-state"><p>No recent events</p></div>';
        return;
    }
    
    const eventsHTML = events.map(event => {
        const timestamp = event.timestamp ? formatDateTime(event.timestamp) : 'Unknown time';
        const statusClass = event.status === 'success' ? 'success' : event.status === 'error' ? 'danger' : 'warning';
        const actionLabel = formatActionLabel(event.action);
        
        return `
            <div class="event-item">
                <div class="event-icon ${statusClass}">
                    ${getActionIcon(event.action)}
                </div>
                <div class="event-content">
                    <div class="event-title">${actionLabel}</div>
                    <div class="event-meta">
                        <span>${event.username}</span> • 
                        <span>${timestamp}</span>
                        ${event.ip_address ? ` • <span>${event.ip_address}</span>` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
    
    eventsFeed.innerHTML = eventsHTML;
}

/**
 * Render active connections (admin only)
 */
function renderActiveConnections(connections) {
    // Find or create connections card
    let connectionsCard = document.getElementById('active-connections-card');
    
    if (!connectionsCard && connections.length > 0) {
        // Create the connections card if it doesn't exist
        const contentGrid = document.querySelector('#dashboard-view .content-grid');
        if (contentGrid) {
            const cardHTML = `
                <div class="card" id="active-connections-card">
                    <div class="card-header">
                        <h3>Active Connections</h3>
                    </div>
                    <div class="card-body">
                        <div id="connections-list" class="connections-list"></div>
                    </div>
                </div>
            `;
            contentGrid.insertAdjacentHTML('beforeend', cardHTML);
            connectionsCard = document.getElementById('active-connections-card');
        }
    }
    
    const connectionsList = document.getElementById('connections-list');
    if (!connectionsList) return;
    
    if (!connections || connections.length === 0) {
        connectionsList.innerHTML = '<div class="empty-state"><p>No active connections</p></div>';
        return;
    }
    
    const connectionsHTML = connections.map(conn => {
        const typeLabel = conn.is_temporary ? 'Temp' : 'Permanent';
        const typeBadge = conn.is_temporary ? 'warning' : 'primary';
        
        return `
            <div class="connection-item">
                <div class="connection-icon">${svgIcon('user')}</div>
                <div class="connection-content">
                    <div class="connection-title">
                        ${conn.username} 
                        <span class="badge badge-${typeBadge}">${typeLabel}</span>
                    </div>
                    <div class="connection-meta">
                        ${conn.ip_address} • 
                        ${conn.session_duration_minutes} min • 
                        Last activity: ${formatDateTime(conn.last_activity)}
                    </div>
                </div>
            </div>
        `;
    }).join('');
    
    connectionsList.innerHTML = connectionsHTML;
}

/**
 * Helper function to format action labels
 */
function formatActionLabel(action) {
    const labels = {
        'login': 'User Login',
        'logout': 'User Logout',
        'user_created': 'User Created',
        'user_deleted': 'User Deleted',
        'role_changed': 'Role Changed',
        'vault_created': 'Vault Created',
        'vault_deleted': 'Vault Deleted',
        'file_uploaded': 'File Uploaded',
        'file_downloaded': 'File Downloaded',
        'file_deleted': 'File Deleted',
        'temp_credential_created': 'Temp Credential Created',
        'temp_credential_used': 'Temp Credential Used'
    };
    
    return labels[action] || action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Helper function to get action icon
 */
function getActionIcon(action) {
    const icons = {
        'login': 'login',
        'logout': 'logout',
        'user_created': 'user',
        'user_deleted': 'ban',
        'role_changed': 'key',
        'vault_created': 'vault',
        'vault_deleted': 'trash',
        'file_uploaded': 'upload',
        'file_downloaded': 'download',
        'file_deleted': 'trash',
        'temp_credential_created': 'clock',
        'temp_credential_used': 'check'
    };

    return svgIcon(icons[action] || 'info');
}

/**
 * Helper function to format datetime
 */
function formatDateTime(isoString) {
    if (!isoString) return 'Unknown';
    
    try {
        const date = new Date(isoString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} min ago`;
        
        const diffHours = Math.floor(diffMins / 60);
        if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        
        const diffDays = Math.floor(diffHours / 24);
        if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    } catch (e) {
        return isoString;
    }
}
