// API Configuration
const API_BASE = 'http://localhost:8000';

// State Management
let authToken = null;
let currentUser = null;

// Security: HTML Escaping to prevent XSS
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    
    const div = document.createElement('div');
    div.textContent = unsafe;
    return div.innerHTML;
}

// API Request Helper with Authorization
async function apiRequest(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...(authToken && { 'Authorization': `Bearer ${authToken}` }),
        ...options.headers
    };
    
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers
        });
        
        // Handle 401 Unauthorized - token expired or invalid
        if (response.status === 401) {
            showError('Session expired. Please log in again.');
            logout();
            return null;
        }
        
        // Handle 403 Forbidden - insufficient permissions
        if (response.status === 403) {
            showError('You do not have permission to perform this action.');
            return null;
        }
        
        // Handle 404 Not Found
        if (response.status === 404) {
            showError('Resource not found.');
            return null;
        }
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'An error occurred' }));
            throw new Error(error.detail || 'Request failed');
        }
        
        // Handle 204 No Content
        if (response.status === 204) {
            return null;
        }
        
        return await response.json();
    } catch (error) {
        console.error('API Request Error:', error);
        showError(error.message || 'Failed to communicate with server');
        return null;
    }
}

// Authentication
async function login(event) {
    event.preventDefault();
    
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    
    if (!username || !password) {
        showError('Please enter both username and password');
        return;
    }
    
    const data = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
    });
    
    if (data && data.access_token) {
        authToken = data.access_token;
        
        // FIXED: Use user data from login response instead of separate API call
        // The login endpoint returns the user object, so we don't need to call /users/me
        if (data.user) {
            currentUser = data.user;
            showDashboard();
            initializeDashboard();
        } else {
            authToken = null;
            showError('Failed to retrieve user information');
        }
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    
    // Clear all forms
    document.querySelectorAll('form').forEach(form => form.reset());
    
    // Show login screen
    showScreen('login-screen');
}

// Screen Management
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

function showDashboard() {
    showScreen('dashboard-screen');
    
    // Update user info in sidebar
    const userName = document.getElementById('user-name');
    const userRole = document.getElementById('user-role');
    const userAvatar = document.getElementById('user-avatar');
    
    if (currentUser) {
        userName.textContent = escapeHtml(currentUser.username);
        userRole.textContent = escapeHtml(currentUser.role);
        userAvatar.textContent = currentUser.username.charAt(0).toUpperCase();
    }
    
    // Apply role-based access control
    applyRBAC();
}

// Role-Based Access Control
function applyRBAC() {
    if (!currentUser) return;
    
    const isAdmin = currentUser.role === 'admin';
    
    // Hide admin-only navigation items for non-admin users
    const adminNavItems = ['nav-users', 'nav-audit'];
    adminNavItems.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.style.display = isAdmin ? 'flex' : 'none';
        }
    });
    
    // Hide admin-only buttons and sections within views
    document.querySelectorAll('[data-admin-only]').forEach(element => {
        element.style.display = isAdmin ? '' : 'none';
    });
}

// Navigation
function navigate(viewId) {
    // Hide all views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.remove('active');
    });
    
    // Remove active state from all nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Show selected view
    const viewElement = document.getElementById(viewId);
    if (viewElement) {
        viewElement.classList.add('active');
    }
    
    // Add active state to current nav item
    const navItem = document.querySelector(`[onclick="navigate('${viewId}')"]`);
    if (navItem) {
        navItem.classList.add('active');
    }
    
    // Load view data based on view ID
    switch (viewId) {
        case 'dashboard-view':
            loadDashboard();
            break;
        case 'vaults-view':
            loadVaults();
            break;
        case 'users-view':
            loadUsers();
            break;
        case 'temp-access-view':
            loadTempAccess();
            break;
        case 'audit-view':
            loadAudit();
            break;
        case 'settings-view':
            loadSettings();
            break;
    }
}

// Initialize Dashboard
async function initializeDashboard() {
    navigate('dashboard-view');
}

// Dashboard View
async function loadDashboard() {
    try {
        // Load statistics
        const [vaults, users, tempCreds] = await Promise.all([
            apiRequest('/vaults'),
            currentUser.role === 'admin' ? apiRequest('/users') : Promise.resolve([]),
            apiRequest('/temp-creds/list')
        ]);
        
        // Update stats cards
        if (vaults) {
            document.getElementById('total-vaults').textContent = vaults.length;
        }
        
        if (users && currentUser.role === 'admin') {
            document.getElementById('total-users').textContent = users.length;
            const activeUsers = users.filter(u => u.is_active).length;
            document.getElementById('active-users').textContent = activeUsers;
        }
        
        if (tempCreds) {
            const activeTemp = tempCreds.filter(tc => {
                const expires = new Date(tc.expires_at);
                return expires > new Date();
            }).length;
            document.getElementById('active-temp-access').textContent = activeTemp;
        }
        
        // Load recent activity (mock for now)
        loadRecentActivity();
        
        // Load system status
        loadSystemStatus();
        
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

async function loadRecentActivity() {
    const activityFeed = document.getElementById('activity-feed');
    if (!activityFeed) return;
    
    // This would typically come from an audit log endpoint
    activityFeed.innerHTML = `
        <div class="activity-item">
            <div class="activity-title">System started</div>
            <div class="activity-time">Just now</div>
        </div>
    `;
}

async function loadSystemStatus() {
    try {
        const status = await apiRequest('/health');
        
        if (status) {
            const dbStatus = document.getElementById('db-status');
            const redisStatus = document.getElementById('redis-status');
            const sftpStatus = document.getElementById('sftp-status');
            
            if (dbStatus) {
                dbStatus.className = `badge ${status.database === 'connected' ? 'badge-success' : 'badge-danger'}`;
                dbStatus.textContent = status.database === 'connected' ? 'Connected' : 'Disconnected';
            }
            
            if (redisStatus) {
                redisStatus.className = `badge ${status.redis === 'connected' ? 'badge-success' : 'badge-danger'}`;
                redisStatus.textContent = status.redis === 'connected' ? 'Connected' : 'Disconnected';
            }
            
            if (sftpStatus) {
                sftpStatus.className = 'badge badge-success';
                sftpStatus.textContent = 'Running';
            }
        }
    } catch (error) {
        console.error('Error loading system status:', error);
    }
}

// Vaults View
async function loadVaults() {
    const vaults = await apiRequest('/vaults');
    
    if (!vaults) return;
    
    const vaultsGrid = document.getElementById('vaults-grid');
    if (!vaultsGrid) return;
    
    if (vaults.length === 0) {
        vaultsGrid.innerHTML = `
            <div class="empty-state">
                <h3>No Vaults Found</h3>
                <p>Create your first vault to get started</p>
            </div>
        `;
        return;
    }
    
    vaultsGrid.innerHTML = vaults.map(vault => `
        <div class="item-card">
            <h3>${escapeHtml(vault.name)}</h3>
            <p>${escapeHtml(vault.path)}</p>
            <p class="text-muted">
                ${vault.encrypted ? '🔒 Encrypted' : '🔓 Not Encrypted'} • 
                ${vault.password_protected ? '🔑 Password Protected' : '📂 Open'}
            </p>
            <div class="item-actions">
                <button class="btn btn-secondary" onclick="viewVault(${vault.id})">View</button>
                ${currentUser.role === 'admin' ? `<button class="btn btn-danger" onclick="deleteVault(${vault.id})">Delete</button>` : ''}
            </div>
        </div>
    `).join('');
}

function showCreateVaultModal() {
    document.getElementById('create-vault-modal').classList.add('active');
}

function closeCreateVaultModal() {
    document.getElementById('create-vault-modal').classList.remove('active');
    document.getElementById('create-vault-form').reset();
}

async function createVault(event) {
    event.preventDefault();
    
    const name = document.getElementById('vault-name').value.trim();
    const path = document.getElementById('vault-path').value.trim();
    const encrypted = document.getElementById('vault-encrypted').checked;
    const passwordProtected = document.getElementById('vault-password-protected').checked;
    const password = document.getElementById('vault-password').value;
    
    // Input validation
    if (!name || !path) {
        showError('Vault name and path are required');
        return;
    }
    
    if (passwordProtected && !password) {
        showError('Password is required for password-protected vaults');
        return;
    }
    
    const data = {
        name,
        path,
        encrypted,
        password_protected: passwordProtected,
        ...(passwordProtected && { password })
    };
    
    const result = await apiRequest('/vaults', {
        method: 'POST',
        body: JSON.stringify(data)
    });
    
    if (result) {
        closeCreateVaultModal();
        loadVaults();
        showSuccess('Vault created successfully');
    }
}

async function deleteVault(vaultId) {
    if (!confirm('Are you sure you want to delete this vault? This action cannot be undone.')) {
        return;
    }
    
    const result = await apiRequest(`/vaults/${vaultId}`, {
        method: 'DELETE'
    });
    
    if (result !== null) {
        loadVaults();
        showSuccess('Vault deleted successfully');
    }
}

// Users View (Admin Only)
async function loadUsers() {
    // RBAC: Only admins can view users
    if (currentUser.role !== 'admin') {
        showError('Access denied');
        return;
    }
    
    const users = await apiRequest('/users');
    
    if (!users) return;
    
    const usersBody = document.getElementById('users-body');
    if (!usersBody) return;
    
    if (users.length === 0) {
        usersBody.innerHTML = '<tr><td colspan="5" class="text-center">No users found</td></tr>';
        return;
    }
    
    usersBody.innerHTML = users.map(user => `
        <tr>
            <td>${escapeHtml(user.username)}</td>
            <td>${escapeHtml(user.email || 'N/A')}</td>
            <td><span class="badge badge-info">${escapeHtml(user.role)}</span></td>
            <td><span class="badge ${user.is_active ? 'badge-success' : 'badge-danger'}">${user.is_active ? 'Active' : 'Inactive'}</span></td>
            <td>
                <button class="btn-icon" onclick="editUser(${user.id})" title="Edit">✏️</button>
                ${user.id !== currentUser.id ? `<button class="btn-icon" onclick="deleteUser(${user.id})" title="Delete">🗑️</button>` : ''}
            </td>
        </tr>
    `).join('');
}

function showCreateUserModal() {
    document.getElementById('create-user-modal').classList.add('active');
}

function closeCreateUserModal() {
    document.getElementById('create-user-modal').classList.remove('active');
    document.getElementById('create-user-form').reset();
}

async function createUser(event) {
    event.preventDefault();
    
    // RBAC: Only admins can create users
    if (currentUser.role !== 'admin') {
        showError('Access denied');
        return;
    }
    
    const username = document.getElementById('user-username').value.trim();
    const email = document.getElementById('user-email').value.trim();
    const password = document.getElementById('user-password').value;
    const role = document.getElementById('user-role').value;
    
    // Input validation
    if (!username || !password) {
        showError('Username and password are required');
        return;
    }
    
    if (password.length < 8) {
        showError('Password must be at least 8 characters');
        return;
    }
    
    const data = {
        username,
        email: email || null,
        password,
        role,
        is_active: true
    };
    
    const result = await apiRequest('/users', {
        method: 'POST',
        body: JSON.stringify(data)
    });
    
    if (result) {
        closeCreateUserModal();
        loadUsers();
        showSuccess('User created successfully');
    }
}

async function deleteUser(userId) {
    // RBAC: Only admins can delete users
    if (currentUser.role !== 'admin') {
        showError('Access denied');
        return;
    }
    
    // Prevent self-deletion
    if (userId === currentUser.id) {
        showError('You cannot delete your own account');
        return;
    }
    
    if (!confirm('Are you sure you want to delete this user?')) {
        return;
    }
    
    const result = await apiRequest(`/users/${userId}`, {
        method: 'DELETE'
    });
    
    if (result !== null) {
        loadUsers();
        showSuccess('User deleted successfully');
    }
}

// Temp Access View
async function loadTempAccess() {
    const tempCreds = await apiRequest('/temp-creds/list');
    
    if (!tempCreds) return;
    
    const tempAccessBody = document.getElementById('temp-access-body');
    if (!tempAccessBody) return;
    
    if (tempCreds.length === 0) {
        tempAccessBody.innerHTML = '<tr><td colspan="5" class="text-center">No temporary access credentials found</td></tr>';
        return;
    }
    
    const now = new Date();
    
    tempAccessBody.innerHTML = tempCreds.map(cred => {
        const expiresAt = new Date(cred.expires_at);
        const isExpired = expiresAt < now;
        
        return `
            <tr>
                <td>${escapeHtml(cred.temp_username)}</td>
                <td>${escapeHtml(cred.vault_name || 'N/A')}</td>
                <td><span class="badge ${isExpired ? 'badge-danger' : 'badge-success'}">${isExpired ? 'Expired' : 'Active'}</span></td>
                <td>${expiresAt.toLocaleString()}</td>
                <td>
                    <button class="btn-icon" onclick="deleteTempCred('${escapeHtml(cred.temp_username)}')" title="Delete">🗑️</button>
                </td>
            </tr>
        `;
    }).join('');
}

async function generateTempCreds(event) {
    event.preventDefault();
    
    const vaultId = document.getElementById('temp-vault-id').value;
    const expiresIn = parseInt(document.getElementById('temp-expires-in').value);
    
    if (!vaultId || !expiresIn) {
        showError('Please select a vault and expiration time');
        return;
    }
    
    const data = await apiRequest('/temp-creds/generate', {
        method: 'POST',
        body: JSON.stringify({
            vault_id: parseInt(vaultId),
            expires_in_hours: expiresIn
        })
    });
    
    if (data) {
        // Show credentials in modal or alert
        const credsHtml = `
            <div class="credentials-box">
                <div class="cred-item">
                    <strong>Username:</strong>
                    <code>${escapeHtml(data.temp_username)}</code>
                </div>
                <div class="cred-item">
                    <strong>Password:</strong>
                    <code>${escapeHtml(data.temp_password)}</code>
                </div>
                <div class="cred-item">
                    <strong>Expires:</strong>
                    <span>${new Date(data.expires_at).toLocaleString()}</span>
                </div>
                <p class="text-muted" style="margin-top: 1rem;">
                    ⚠️ Save these credentials now. The password will not be shown again.
                </p>
            </div>
        `;
        
        // Create a modal to show credentials
        showCredentialsModal(credsHtml);
        
        // Reload temp access list
        loadTempAccess();
    }
}

function showCredentialsModal(html) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('credentials-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'credentials-modal';
        modal.className = 'modal';
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Temporary Credentials Generated</h3>
                    <button class="modal-close" onclick="closeCredentialsModal()">&times;</button>
                </div>
                <div class="modal-body" id="credentials-content"></div>
                <div class="modal-footer">
                    <button class="btn btn-primary" onclick="closeCredentialsModal()">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    
    document.getElementById('credentials-content').innerHTML = html;
    modal.classList.add('active');
}

function closeCredentialsModal() {
    const modal = document.getElementById('credentials-modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

async function deleteTempCred(tempUsername) {
    if (!confirm('Are you sure you want to delete this temporary credential?')) {
        return;
    }
    
    const result = await apiRequest(`/temp-creds/${tempUsername}`, {
        method: 'DELETE'
    });
    
    if (result !== null) {
        loadTempAccess();
        showSuccess('Temporary credential deleted successfully');
    }
}

// Audit View (Admin Only)
async function loadAudit() {
    // RBAC: Only admins can view audit logs
    if (currentUser.role !== 'admin') {
        showError('Access denied');
        return;
    }
    
    // This would load from an audit log endpoint
    const auditBody = document.getElementById('audit-body');
    if (auditBody) {
        auditBody.innerHTML = '<tr><td colspan="4" class="text-center">Audit logging coming soon</td></tr>';
    }
}

// Settings View
async function loadSettings() {
    // Load current user settings
    const settingsForm = document.getElementById('settings-form');
    if (settingsForm && currentUser) {
        document.getElementById('settings-email').value = currentUser.email || '';
    }
}

async function updateSettings(event) {
    event.preventDefault();
    
    const email = document.getElementById('settings-email').value.trim();
    const currentPassword = document.getElementById('settings-current-password').value;
    const newPassword = document.getElementById('settings-new-password').value;
    const confirmPassword = document.getElementById('settings-confirm-password').value;
    
    // Update email if changed
    if (email && email !== currentUser.email) {
        const emailData = { email };
        const result = await apiRequest(`/users/${currentUser.id}`, {
            method: 'PATCH',
            body: JSON.stringify(emailData)
        });
        
        if (result) {
            currentUser.email = email;
            showSuccess('Email updated successfully');
        }
    }
    
    // Update password if provided
    if (newPassword) {
        if (newPassword !== confirmPassword) {
            showError('New passwords do not match');
            return;
        }
        
        if (newPassword.length < 8) {
            showError('Password must be at least 8 characters');
            return;
        }
        
        if (!currentPassword) {
            showError('Current password is required to change password');
            return;
        }
        
        // Verify current password by attempting login
        const verifyResult = await apiRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify({
                username: currentUser.username,
                password: currentPassword
            })
        });
        
        if (!verifyResult) {
            showError('Current password is incorrect');
            return;
        }
        
        const passwordData = { password: newPassword };
        const result = await apiRequest(`/users/${currentUser.id}`, {
            method: 'PATCH',
            body: JSON.stringify(passwordData)
        });
        
        if (result) {
            document.getElementById('settings-current-password').value = '';
            document.getElementById('settings-new-password').value = '';
            document.getElementById('settings-confirm-password').value = '';
            showSuccess('Password updated successfully');
        }
    }
}

// Notification Functions
function showError(message) {
    showNotification(message, 'error');
}

function showSuccess(message) {
    showNotification(message, 'success');
}

function showNotification(message, type = 'info') {
    // Create notification element
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
        document.body.appendChild(container);
    }
    
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.textContent = message;
    notification.style.cssText = 'margin-bottom: 10px; animation: slideIn 0.3s ease-out;';
    
    container.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Add CSS for notification animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Load vaults for temp creds dropdown
async function loadVaultsForTempCreds() {
    const vaults = await apiRequest('/vaults');
    const select = document.getElementById('temp-vault-id');
    
    if (select && vaults) {
        select.innerHTML = '<option value="">Select a vault...</option>' +
            vaults.map(vault => `<option value="${vault.id}">${escapeHtml(vault.name)}</option>`).join('');
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', login);
    }
    
    // Logout button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
    
    // Create vault form
    const createVaultForm = document.getElementById('create-vault-form');
    if (createVaultForm) {
        createVaultForm.addEventListener('submit', createVault);
    }
    
    // Create user form
    const createUserForm = document.getElementById('create-user-form');
    if (createUserForm) {
        createUserForm.addEventListener('submit', createUser);
    }
    
    // Generate temp creds form
    const generateTempForm = document.getElementById('generate-temp-form');
    if (generateTempForm) {
        generateTempForm.addEventListener('submit', generateTempCreds);
    }
    
    // Settings form
    const settingsForm = document.getElementById('settings-form');
    if (settingsForm) {
        settingsForm.addEventListener('submit', updateSettings);
    }
    
    // Load vaults for temp creds dropdown when temp access view is shown
    const tempVaultSelect = document.getElementById('temp-vault-id');
    if (tempVaultSelect) {
        loadVaultsForTempCreds();
    }
    
    // Close modals when clicking outside
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            e.target.classList.remove('active');
        }
    });
});
