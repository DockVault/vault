// Security: HTML escaping utility
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// State management with localStorage persistence
const state = {
    get token() {
        // Try localStorage first, fallback to sessionStorage for private mode
        return localStorage.getItem('psftp_token') || sessionStorage.getItem('psftp_token');
    },
    set token(value) {
        if (value) {
            try {
                localStorage.setItem('psftp_token', value);
            } catch (e) {
                // Private mode fallback
                sessionStorage.setItem('psftp_token', value);
            }
        } else {
            localStorage.removeItem('psftp_token');
            sessionStorage.removeItem('psftp_token');
        }
    },
    get user() {
        const userJson = localStorage.getItem('psftp_user') || sessionStorage.getItem('psftp_user');
        return userJson ? JSON.parse(userJson) : null;
    },
    set user(value) {
        if (value) {
            const json = JSON.stringify(value);
            try {
                localStorage.setItem('psftp_user', json);
            } catch (e) {
                // Private mode fallback
                sessionStorage.setItem('psftp_user', json);
            }
        } else {
            localStorage.removeItem('psftp_user');
            sessionStorage.removeItem('psftp_user');
        }
    },
    get currentVaultId() {
        return sessionStorage.getItem('psftp_current_vault_id');
    },
    set currentVaultId(value) {
        if (value) {
            sessionStorage.setItem('psftp_current_vault_id', value);
        } else {
            sessionStorage.removeItem('psftp_current_vault_id');
        }
    },
    currentView: 'dashboard',
    selectedUser: null,
    currentVault: null,
    dashboardRefreshInterval: null,
    vaultFilesRefreshInterval: null,
    get vaultPassword() {
        const passwordData = sessionStorage.getItem('psftp_vault_password');
        if (!passwordData) return null;
        
        try {
            const { password, timestamp, vaultId } = JSON.parse(passwordData);
            const now = Date.now();
            const fifteenMinutes = 15 * 60 * 1000;
            
            // Check if password has expired (15 minutes)
            if (now - timestamp > fifteenMinutes) {
                console.log('Vault password expired (15 minutes passed)');
                sessionStorage.removeItem('psftp_vault_password');
                return null;
            }
            
            return password;
        } catch (e) {
            // Old format or corrupted data, clear it
            sessionStorage.removeItem('psftp_vault_password');
            return null;
        }
    },
    set vaultPassword(value) {
        if (value) {
            // Store password with timestamp and vault ID for 15-minute expiry
            const passwordData = {
                password: value,
                timestamp: Date.now(),
                vaultId: state.currentVaultId
            };
            sessionStorage.setItem('psftp_vault_password', JSON.stringify(passwordData));
        } else {
            sessionStorage.removeItem('psftp_vault_password');
        }
    },
    // Check if vault password is still valid (not expired)
    isVaultPasswordValid() {
        const passwordData = sessionStorage.getItem('psftp_vault_password');
        if (!passwordData) return false;
        
        try {
            const { timestamp } = JSON.parse(passwordData);
            const now = Date.now();
            const fifteenMinutes = 15 * 60 * 1000;
            return (now - timestamp) <= fifteenMinutes;
        } catch (e) {
            return false;
        }
    },
    get userPermissions() {
        const permsJson = sessionStorage.getItem('psftp_user_permissions');
        return permsJson ? JSON.parse(permsJson) : [];
    },
    set userPermissions(value) {
        if (value && Array.isArray(value)) {
            sessionStorage.setItem('psftp_user_permissions', JSON.stringify(value));
        } else {
            sessionStorage.removeItem('psftp_user_permissions');
        }
    }
};

// Permission checking helper
function hasPermission(groupName) {
    // Admin has all permissions
    if (state.user && state.user.role === 'admin') {
        return true;
    }
    
    // Check if user has the permission group
    return state.userPermissions.includes(groupName);
}

// Check multiple permissions (user needs at least one)
function hasAnyPermission(...groupNames) {
    if (state.user && state.user.role === 'admin') {
        return true;
    }
    return groupNames.some(name => state.userPermissions.includes(name));
}

// API Base URL
const API_BASE = '';

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    checkExistingSession();
});

function initializeApp() {
    // Setup navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const view = item.dataset.view;
            if (view) {
                console.log('Nav item clicked:', view);
                navigateToView(view);
            }
        });
    });

    // Setup logout
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    // Setup login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    // Setup modal controls
    setupModals();

    // Setup create vault form
    const createVaultForm = document.getElementById('create-vault-form');
    if (createVaultForm) {
        createVaultForm.addEventListener('submit', handleCreateVault);
    }

    // Setup create user form
    const createUserForm = document.getElementById('create-user-form');
    if (createUserForm) {
        createUserForm.addEventListener('submit', handleCreateUser);
    }

    // Setup temp creds button (on dashboard)
    const generateTempCredsBtn = document.getElementById('generate-temp-creds-btn');
    if (generateTempCredsBtn) {
        generateTempCredsBtn.addEventListener('click', handleGenerateTempCreds);
    }

    // Setup create temp credential button (in temp-creds view)
    const createTempCredBtn = document.getElementById('create-temp-cred-btn');
    if (createTempCredBtn) {
        createTempCredBtn.addEventListener('click', () => {
            if (typeof handleCreateTempCredential === 'function') {
                handleCreateTempCredential();
            }
        });
    }

    // Setup password toggle
    const togglePasswordBtns = document.querySelectorAll('.toggle-password-btn');
    togglePasswordBtns.forEach(btn => {
        btn.addEventListener('click', togglePasswordVisibility);
    });

    // Setup copy buttons (enhanced with security notices)
    const copyBtns = document.querySelectorAll('.copy-btn');
    copyBtns.forEach(btn => {
        btn.addEventListener('click', handleSecureCopy);
    });

    // Setup copy button
    const copyCommandBtn = document.getElementById('copy-command-btn');
    if (copyCommandBtn) {
        copyCommandBtn.addEventListener('click', copyToClipboard);
    }
    
    // Setup create vault button
    const createVaultBtn = document.getElementById('create-vault-btn');
    if (createVaultBtn) {
        createVaultBtn.addEventListener('click', () => {
            console.log('Create vault button clicked');
            openModal('create-vault-modal');
        });
    }
    
    // Setup create user button
    const createUserBtn = document.getElementById('create-user-btn');
    if (createUserBtn) {
        createUserBtn.addEventListener('click', () => {
            console.log('Create user button clicked');
            openModal('create-user-modal');
        });
    }
}

// Load user permissions from API
async function loadUserPermissions() {
    if (!state.user || !state.user.id) {
        console.warn('No user ID, skipping permission load');
        state.userPermissions = [];
        return;
    }
    
    try {
        console.log('Loading permissions for user:', state.user.id);
        const response = await fetch(`${API_BASE}/permissions/users/${state.user.id}`, {
            headers: {
                'Authorization': `Bearer ${state.token}`
            }
        });
        
        if (!response.ok) {
            console.warn('Failed to load permissions:', response.status);
            state.userPermissions = [];
            return;
        }
        
        const data = await response.json();
        state.userPermissions = data.granted_groups || [];
        console.log('✅ Loaded user permissions:', state.userPermissions);
        
        // Update UI based on permissions
        updateUIForPermissions();
    } catch (error) {
        console.error('Error loading permissions:', error);
        state.userPermissions = [];
    }
}

// Update UI elements based on user permissions
function updateUIForPermissions() {
    console.log('Updating UI for permissions...');
    
    // Update navigation visibility
    updateNavigationPermissions();
    
    // Update button visibility/state
    updateActionButtonPermissions();
}

// Update navigation items based on permissions
function updateNavigationPermissions() {
    const isAdmin = state.user && state.user.role === 'admin';
    
    // Users navigation
    const usersNav = document.querySelector('.nav-item[data-view="users"]');
    if (usersNav) {
        if (isAdmin || hasPermission('USER_VIEW')) {
            usersNav.style.display = 'flex';
        } else {
            usersNav.style.display = 'none';
        }
    }
    
    // Vaults navigation
    const vaultsNav = document.querySelector('.nav-item[data-view="vaults"]');
    if (vaultsNav) {
        if (isAdmin || hasPermission('VAULT_VIEW')) {
            vaultsNav.style.display = 'flex';
        } else {
            vaultsNav.style.display = 'none';
        }
    }
    
    // Temp Credentials navigation (admin only for now)
    const tempCredsNav = document.getElementById('nav-temp-creds');
    if (tempCredsNav) {
        if (isAdmin || hasPermission('TEMP_CRED_CREATE')) {
            tempCredsNav.style.display = 'flex';
        } else {
            tempCredsNav.style.display = 'none';
        }
    }
    
    // Live Monitor navigation (admin only)
    const monitorNav = document.getElementById('nav-monitor');
    if (monitorNav) {
        if (isAdmin) {
            monitorNav.style.display = 'flex';
        } else {
            monitorNav.style.display = 'none';
        }
    }
    
    // Roles navigation (admin only)
    const rolesNav = document.getElementById('nav-roles');
    if (rolesNav) {
        if (isAdmin) {
            rolesNav.style.display = 'flex';
        } else {
            rolesNav.style.display = 'none';
        }
    }
}

// Update action button visibility/state based on permissions
function updateActionButtonPermissions() {
    // Create User button
    const createUserBtn = document.getElementById('create-user-btn');
    if (createUserBtn) {
        if (hasPermission('USER_MANAGE')) {
            createUserBtn.style.display = 'block';
            createUserBtn.disabled = false;
        } else {
            createUserBtn.style.display = 'none';
        }
    }
    
    // Create Vault button
    const createVaultBtn = document.getElementById('create-vault-btn');
    if (createVaultBtn) {
        if (hasPermission('VAULT_MANAGE')) {
            createVaultBtn.style.display = 'block';
            createVaultBtn.disabled = false;
        } else {
            createVaultBtn.style.display = 'none';
        }
    }
    
    // Generate Temp Creds button
    const generateTempCredsBtn = document.getElementById('generate-temp-creds-btn');
    if (generateTempCredsBtn) {
        if (hasPermission('TEMP_CREDS_MANAGE')) {
            generateTempCredsBtn.style.display = 'block';
            generateTempCredsBtn.disabled = false;
        } else {
            generateTempCredsBtn.style.display = 'none';
        }
    }
}

// Session restoration
async function checkExistingSession() {
    console.log('=== Checking for existing session ===');
    console.log('Token exists:', !!state.token);
    console.log('User exists:', !!state.user);
    console.log('Token value:', state.token ? state.token.substring(0, 20) + '...' : 'null');
    
    // Check if we have a token in localStorage
    if (state.token && state.user) {
        try {
            // Verify token is still valid by making a test API call to /users/me
            console.log('Validating existing token with /users/me endpoint...');
            const userData = await fetchAPI('/users/me');
            
            console.log('User data received:', userData);
            
            // Token is valid, update user data and restore session
            state.user = userData; // Update with latest user data
            console.log('Token valid! Restoring session for user:', state.user.username);
            
            // Load user permissions
            await loadUserPermissions();
            
            // Check if we should restore a specific view
            const lastView = localStorage.getItem('lastView');
            
            hideLoadingScreen();
            hideLoginScreen();
            
            // Show dashboard screen
            document.getElementById('dashboard-screen').classList.add('active');
            
            // Update user info in sidebar
            const userAvatar = document.getElementById('user-avatar');
            const userName = document.getElementById('user-name');
            const userRole = document.getElementById('user-role');
            
            if (userAvatar && userName && userRole && state.user) {
                userAvatar.textContent = state.user.username.charAt(0).toUpperCase();
                userName.textContent = escapeHtml(state.user.username);
                userRole.textContent = escapeHtml(state.user.role);
                console.log('User role:', state.user.role); // Debug
            }
            
            // RBAC: Show/hide nav items based on role
            const isAdmin = state.user && (
                state.user.role === 'admin' || 
                state.user.role === 'RoleEnum.ADMIN' ||
                state.user.role.toLowerCase() === 'admin'
            );
            
            console.log('Is admin?', isAdmin, 'Role:', state.user?.role); // Debug
            
            if (isAdmin) {
                // Show admin-only items
                const rolesNav = document.getElementById('nav-roles');
                if (rolesNav) {
                    rolesNav.style.display = 'flex';
                }
                const tempCredsNav = document.getElementById('nav-temp-creds');
                if (tempCredsNav) {
                    tempCredsNav.style.display = 'flex';
                }
                const monitorNav = document.getElementById('nav-monitor');
                if (monitorNav) {
                    monitorNav.style.display = 'flex';
                }
            } else {
                // Hide admin-only items for non-admins
                const usersNav = document.querySelector('.nav-item[data-view="users"]');
                if (usersNav) {
                    usersNav.style.display = 'none';
                }
                const rolesNav = document.getElementById('nav-roles');
                if (rolesNav) {
                    rolesNav.style.display = 'none';
                }
            }
            
            // Check if we need to restore a vault view
            const savedVaultId = state.currentVaultId;
            
            // Smart vault restoration on page refresh
            // Check if we have a valid cached password (15-minute expiry in sessionStorage)
            if (savedVaultId && lastView === 'vault') {
                if (state.isVaultPasswordValid()) {
                    // Password still valid (within 15 minutes), safe to auto-restore
                    console.log('Restoring vault after refresh - password still cached and valid');
                    
                    // Remove active from all nav items first
                    document.querySelectorAll('.nav-item').forEach(item => {
                        item.classList.remove('active');
                    });
                    
                    // Highlight Vaults menu item (not Dashboard)
                    const vaultsNav = document.getElementById('nav-vaults');
                    if (vaultsNav) {
                        vaultsNav.classList.add('active');
                    }
                    
                    // Don't navigate anywhere - openVault will show the vault view directly
                    // This prevents flashing the dashboard before showing vault
                    openVault(savedVaultId);
                    // Skip navigation and dashboard refresh
                } else {
                    // Password expired or missing, return to vaults list for re-authentication
                    console.log('Vault password expired or missing, returning to vaults list');
                    state.currentVaultId = null;
                    navigateToView('vaults');
                }
            } else {
                // Normal navigation
                const viewToNavigate = lastView || 'dashboard';
                navigateToView(viewToNavigate);
                
                // Start auto-refresh for dashboard if on dashboard
                if (!lastView || lastView === 'dashboard') {
                    startDashboardRefresh();
                }
            }
        } catch (error) {
            // Token expired or invalid, clear it
            console.error('=== Token validation failed ===');
            console.error('Error message:', error.message);
            console.error('Error details:', error);
            console.log('Clearing session and showing login screen');
            state.token = null;
            state.user = null;
            localStorage.removeItem('lastView');
            hideLoadingScreen();
            showLoginScreen();
        }
    } else {
        // No token found, show login immediately
        console.log('No existing session found');
        hideLoadingScreen();
        showLoginScreen();
    }
}

// Show/hide loading screen
function hideLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    if (loadingScreen) {
        loadingScreen.classList.remove('active');
    }
}

function showLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    if (loadingScreen) {
        loadingScreen.classList.add('active');
    }
    hideLoginScreen();
    hideDashboardScreen();
}

function showLoginScreen() {
    const loginScreen = document.getElementById('login-screen');
    if (loginScreen) {
        loginScreen.classList.add('active');
    }
    hideDashboardScreen();
}

function hideLoginScreen() {
    const loginScreen = document.getElementById('login-screen');
    if (loginScreen) {
        loginScreen.classList.remove('active');
    }
}

function hideDashboardScreen() {
    const dashboardScreen = document.getElementById('dashboard-screen');
    if (dashboardScreen) {
        dashboardScreen.classList.remove('active');
    }
}

// Navigation
function navigateToView(viewName) {
    // Hide all views explicitly
    document.querySelectorAll('.view').forEach(view => {
        view.classList.remove('active');
        view.style.display = 'none'; // Explicitly hide all views
    });

    // Remove active state from nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });

    // Hide vault view if switching away from vaults
    const vaultView = document.getElementById('vault-view');
    if (vaultView && viewName !== 'vaults' && viewName !== 'vault') {
        vaultView.style.display = 'none';
        vaultView.classList.remove('active');
        state.currentVault = null;
        // Don't clear password immediately - let it expire naturally after 15 minutes
        // This allows user to return to vault within 15 minutes without re-entering password
        // Stop vault files auto-refresh
        stopVaultFilesAutoRefresh();
    }
    
    // If navigating TO vaults, ensure vault detail view is hidden and vaults list is visible
    if (viewName === 'vaults' && vaultView) {
        vaultView.style.display = 'none';
        vaultView.classList.remove('active');
        stopVaultFilesAutoRefresh();
        // Clear vault-specific state but keep currentVaultId if set (for refresh scenarios)
        state.currentVault = null;
        state.currentFolderId = null;
        state.currentPath = [];
    }

    // Show selected view
    const viewElement = document.getElementById(`${viewName}-view`);
    if (viewElement) {
        viewElement.classList.add('active');
        viewElement.style.display = 'block'; // Explicitly set display
        console.log(`Navigated to ${viewName} view`);
    } else {
        console.error(`View not found: ${viewName}-view`);
    }

    // Highlight active nav item
    const navItem = document.querySelector(`.nav-item[data-view="${viewName}"]`);
    if (navItem) {
        navItem.classList.add('active');
    }

    // Reset user details panel when switching views
    if (viewName !== 'users') {
        const detailsPanel = document.querySelector('.user-details');
        if (detailsPanel) {
            detailsPanel.classList.remove('active');
        }
        state.selectedUser = null;
    }

    state.currentView = viewName;
    
    // Save current view to localStorage for persistence across page refreshes
    localStorage.setItem('lastView', viewName);

    // Load view data
    loadViewData(viewName);
}

async function loadViewData(viewName) {
    console.log(`Loading data for view: ${viewName}`);
    
    switch (viewName) {
        case 'dashboard':
            // Use new dashboard view with real data
            if (typeof initDashboardView === 'function') {
                await initDashboardView();
            } else {
                await loadDashboard();
            }
            break;
        case 'vaults':
            // Clear vault state when navigating to vaults list
            state.currentVaultId = null;
            state.currentVault = null;
            sessionStorage.removeItem('psftp_vault_password');
            await loadVaults();
            break;
        case 'users':
            await loadUsers();
            break;
        case 'temp-creds':
            // Load temporary credentials
            if (typeof loadTempCredentials === 'function') {
                await loadTempCredentials();
                startTempCredsRefresh();
            } else {
                console.error('Temp credentials module not loaded');
            }
            break;
        case 'monitor':
            // Initialize live monitor
            if (typeof initializeLiveMonitor === 'function') {
                initializeLiveMonitor();
            } else {
                console.error('Live monitor module not loaded');
            }
            break;
        case 'permissions':
            // Initialize permissions view if the function exists (old)
            if (typeof initializePermissionsView === 'function') {
                await initializePermissionsView();
            } else {
                console.error('Permissions module not loaded');
            }
            break;
        case 'roles':
            // Initialize roles view
            if (typeof initRolesView === 'function') {
                await initRolesView();
            } else {
                console.error('Roles module not loaded');
            }
            break;
        case 'settings':
            // Empty for now
            console.log('Settings view - no data to load');
            break;
        default:
            console.warn(`Unknown view: ${viewName}`);
    }
    
    // Clean up when leaving certain views
    cleanupPreviousView(viewName);
}

// Clean up resources when leaving views
function cleanupPreviousView(newView) {
    // Stop temp creds refresh if leaving that view
    if (newView !== 'temp-creds' && typeof stopTempCredsRefresh === 'function') {
        stopTempCredsRefresh();
    }
    
    // Disconnect WebSocket if leaving monitor view
    if (newView !== 'monitor' && typeof disconnectMonitorWebSocket === 'function') {
        disconnectMonitorWebSocket();
    }
    
    // Cleanup roles view if leaving it
    if (newView !== 'roles' && typeof cleanupRolesView === 'function') {
        cleanupRolesView();
    }
}

// Authentication
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('login-error');
    
    errorDiv.style.display = 'none';
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Login failed');
        }

        // Store token and user info
        state.token = data.access_token;
        state.user = data.user;

        // Load user permissions
        await loadUserPermissions();

        // Update UI
        showDashboard();
        
    } catch (error) {
        errorDiv.textContent = error.message;
        errorDiv.style.display = 'block';
    }
}

function showDashboard() {
    // Hide login and loading screens
    hideLoginScreen();
    hideLoadingScreen();
    
    // Show dashboard screen
    document.getElementById('dashboard-screen').classList.add('active');
    
    // Update user info in sidebar
    const userAvatar = document.getElementById('user-avatar');
    const userName = document.getElementById('user-name');
    const userRole = document.getElementById('user-role');
    
    if (userAvatar && userName && userRole && state.user) {
        userAvatar.textContent = state.user.username.charAt(0).toUpperCase();
        userName.textContent = escapeHtml(state.user.username);
        userRole.textContent = escapeHtml(state.user.role);
    }
    
    // Update UI based on permissions
    updateUIForPermissions();
    
    // Load dashboard
    navigateToView('dashboard');
    
    // Start auto-refresh for dashboard
    startDashboardRefresh();
}

function logout() {
    console.log('[LOGOUT] Starting logout process');
    
    // Use session manager to handle logout
    if (window.sessionManager) {
        window.sessionManager.clearSession('manual');
    } else {
        // Fallback if session manager not available
        // Clear state and localStorage
        state.token = null;
        state.user = null;
        state.selectedUser = null;
        localStorage.removeItem('lastView');
        
        // Stop dashboard refresh
        stopDashboardRefresh();
        stopVaultFilesAutoRefresh();
        
        // Hide dashboard screen
        hideDashboardScreen();
        
        // Show login screen
        showLoginScreen();
        
        // Reset form
        document.getElementById('login-form').reset();
    }
    
    console.log('Logged out successfully');
}

// Dashboard functions
function startDashboardRefresh() {
    stopDashboardRefresh();
    // Refresh every 30 seconds
    const intervalId = setInterval(() => {
        if (state.currentView === 'dashboard') {
            // Use new dashboard view if available, otherwise fallback to old
            if (typeof initDashboardView === 'function') {
                initDashboardView();
            } else {
                loadDashboard();
            }
        }
    }, 30000);
    state.dashboardRefreshInterval = intervalId;
    
    // Register with session manager
    if (window.sessionManager) {
        window.sessionManager.registerInterval(intervalId);
    }
}

function stopDashboardRefresh() {
    if (state.dashboardRefreshInterval) {
        clearInterval(state.dashboardRefreshInterval);
        state.dashboardRefreshInterval = null;
    }
}

async function loadDashboard() {
    try {
        console.log('Loading dashboard data... (with ETag caching)');
        
        // Check if user is admin - only admins can see full dashboard
        const isAdmin = state.user && state.user.role === 'admin';
        
        if (!isAdmin) {
            // Non-admin users: show simplified dashboard with only their vaults
            // Using cache manager: 304 Not Modified if vaults unchanged
            const vaults = await fetchAPI('/vaults');
            
            document.getElementById('stat-vaults').textContent = vaults.length;
            document.getElementById('stat-users').textContent = '-';
            
            const totalStorage = vaults.reduce((sum, vault) => sum + (vault.total_size_bytes || 0), 0);
            document.getElementById('stat-storage').textContent = formatBytes(totalStorage);
            document.getElementById('stat-temp-creds').textContent = '-';
            
            loadEvents();
            return;
        }
        
        // Admin users: load full stats
        const [vaults, users, tempCreds] = await Promise.all([
            fetchAPI('/vaults'),
            fetchAPI('/users'),
            fetchAPI('/temp-creds/list')
        ]);

        console.log('Dashboard data loaded:', { vaults: vaults.length, users: users.length, tempCreds: tempCreds.length });

        // Update stat cards
        document.getElementById('stat-vaults').textContent = vaults.length;
        document.getElementById('stat-users').textContent = users.length;
        
        // Calculate total storage (sum of all vault sizes)
        const totalStorage = vaults.reduce((sum, vault) => sum + (vault.total_size_bytes || 0), 0);
        document.getElementById('stat-storage').textContent = formatBytes(totalStorage);
        
        // Count active temp credentials
        const activeTempCreds = tempCreds.filter(tc => tc.is_active && !tc.is_used).length;
        document.getElementById('stat-temp-creds').textContent = activeTempCreds;

        // Load events (mock for now - would come from backend)
        loadEvents();
        
    } catch (error) {
        console.error('Failed to load dashboard:', error);
        showError('Failed to load dashboard data: ' + error.message);
    }
}

function loadEvents() {
    const eventsContainer = document.getElementById('events-feed');
    
    if (!eventsContainer) {
        console.error('Events feed container not found');
        return;
    }
    
    // Mock events - in production these would come from API
    const events = [
        { title: 'New vault created', time: new Date().toISOString() },
        { title: 'User login detected', time: new Date(Date.now() - 300000).toISOString() },
        { title: 'Temporary credentials generated', time: new Date(Date.now() - 600000).toISOString() }
    ];
    
    eventsContainer.innerHTML = events.map(event => `
        <div class="event-item">
            <div class="event-title">${escapeHtml(event.title)}</div>
            <div class="event-time">${formatDateTime(event.time)}</div>
        </div>
    `).join('');
}

// Vaults functions
async function loadVaults() {
    try {
        console.log('Loading vaults... (with ETag caching)');
        // Using cache manager: Returns 304 Not Modified if vault list unchanged
        const vaults = await fetchAPI('/vaults');
        const container = document.getElementById('vaults-grid');
        
        if (!container) {
            console.error('Vaults container not found');
            return;
        }
        
        console.log('Loaded vaults:', vaults.length);
        
        // Sort vaults by name for consistent ordering
        vaults.sort((a, b) => a.name.localeCompare(b.name));
        
        if (vaults.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <h3>No vaults yet</h3>
                    <p>Create your first vault to get started</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = vaults.map(vault => `
            <div class="vault-card" data-vault-id="${vault.id}">
                <h3>🗂️ ${escapeHtml(vault.name)}</h3>
                <p>${escapeHtml(vault.description || 'No description')}</p>
                <div class="vault-meta">
                    <span>📦 ${vault.file_count || 0} files</span>
                    <span>� ${formatBytes(vault.total_size_bytes || 0)}</span>
                    ${vault.has_password ? '<span>🔒 Protected</span>' : ''}
                </div>
                <div class="vault-actions">
                    <button class="btn btn-small btn-primary vault-action-btn" data-action="open" data-vault-id="${vault.id}">Open</button>
                    <button class="btn btn-small btn-danger vault-action-btn" data-action="delete" data-vault-id="${vault.id}">Delete</button>
                </div>
            </div>
        `).join('');
        
        // Use event delegation on container (prevents duplicate listeners)
        // Remove old listener if exists
        const oldListener = container._vaultActionListener;
        if (oldListener) {
            container.removeEventListener('click', oldListener);
        }
        
        // Add new listener
        const newListener = (e) => {
            if (e.target.classList.contains('vault-action-btn')) {
                const action = e.target.dataset.action;
                const vaultId = e.target.dataset.vaultId;
                if (action === 'open') openVault(vaultId);
                else if (action === 'delete') deleteVault(vaultId);
            }
        };
        container.addEventListener('click', newListener);
        container._vaultActionListener = newListener; // Store reference for cleanup
        
    } catch (error) {
        console.error('Failed to load vaults:', error);
        showError('Failed to load vaults: ' + error.message);
    }
}

async function handleCreateVault(e) {
    e.preventDefault();
    
    const name = document.getElementById('vault-name').value;
    const description = document.getElementById('vault-description').value;
    const password = document.getElementById('vault-password').value;
    
    try {
        const payload = { 
            name: name.trim(), 
            description: description.trim() || null,
            password: password ? password : null // Send null if empty
        };
        
        await fetchAPI('/vaults', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        
        closeModal('create-vault-modal');
        document.getElementById('create-vault-form').reset();
        await loadVaults();
        showSuccess('Vault created successfully');
        
    } catch (error) {
        console.error('Failed to create vault:', error);
        showError(error.message || 'Failed to create vault');
    }
}

// Users functions
async function loadUsers() {
    try {
        console.log('Loading users with new user management module...');
        // Initialize the new user management module
        if (typeof userManagement !== 'undefined' && userManagement.initialize) {
            await userManagement.initialize();
        } else {
            console.error('User management module not loaded');
            showError('User management module not available');
        }
    } catch (error) {
        console.error('Failed to load users:', error);
        showError('Failed to load users: ' + error.message);
    }
}

async function selectUser(userId) {
    try {
        // Highlight selected row
        document.querySelectorAll('#users-table tbody tr').forEach(tr => {
            tr.classList.remove('selected');
        });
        const row = document.querySelector(`#users-table tbody tr[data-user-id="${userId}"]`);
        if (row) {
            row.classList.add('selected');
        }
        
        // Fetch user details
        const user = await fetchAPI(`/users/${userId}`);
        state.selectedUser = user;
        
        // Populate user details
        document.getElementById('detail-username').textContent = escapeHtml(user.username);
        document.getElementById('detail-email').textContent = escapeHtml(user.email || 'N/A');
        document.getElementById('detail-role').textContent = escapeHtml(user.role);
        document.getElementById('detail-status').textContent = user.is_active ? 'Active' : 'Inactive';
        document.getElementById('detail-created').textContent = formatDateTime(user.created_at);
        document.getElementById('detail-last-login').textContent = user.last_login ? formatDateTime(user.last_login) : 'Never';
        
        // Load user's temporary credentials
        await loadUserTempCreds(userId);
        
        // Show details panel
        const detailsPanel = document.querySelector('.user-details');
        if (detailsPanel) {
            detailsPanel.classList.add('active');
        }
        
    } catch (error) {
        console.error('Failed to load user details:', error);
        showError('Failed to load user details');
    }
}

async function loadUserTempCreds(userId) {
    try {
        const tempCreds = await fetchAPI('/temp-creds/list');
        
        // Filter for this user if not admin
        const userTempCreds = state.user.role === 'admin' 
            ? tempCreds.filter(tc => tc.user_id === userId)
            : tempCreds;
        
        const tbody = document.querySelector('#temp-creds-table tbody');
        
        if (userTempCreds.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No temporary credentials</td></tr>';
            return;
        }
        
        tbody.innerHTML = userTempCreds.map(tc => `
            <tr>
                <td>${escapeHtml(tc.temp_username)}</td>
                <td>${formatDateTime(tc.created_at)}</td>
                <td>${formatDateTime(tc.expires_at)}</td>
                <td><span class="badge badge-${tc.is_active ? 'success' : 'danger'}">${tc.is_active ? 'Active' : 'Inactive'}</span></td>
                <td class="action-buttons">
                    <button class="btn-icon temp-cred-delete-btn" data-username="${escapeHtml(tc.temp_username)}" title="Delete">🗑️</button>
                </td>
            </tr>
        `).join('');
        
        // Add event delegation for delete buttons
        tbody.querySelectorAll('.temp-cred-delete-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                deleteTempCred(btn.dataset.username);
            });
        });
        
    } catch (error) {
        console.error('Failed to load temp credentials:', error);
        showError('Failed to load temporary credentials');
    }
}

async function handleCreateUser(e) {
    e.preventDefault();
    
    const username = document.getElementById('user-username').value;
    const email = document.getElementById('user-email').value;
    const password = document.getElementById('user-password').value;
    const roleElement = document.getElementById('create-user-role');
    const role = roleElement ? roleElement.value : 'user';
    
    console.log('[DEBUG] Frontend - Role element:', roleElement);
    console.log('[DEBUG] Frontend - Creating user with role:', role);
    console.log('[DEBUG] Frontend - Request body:', { username: username.trim(), email: email.trim(), password: '***', role });
    
    if (!role) {
        showError('Please select a role');
        return;
    }
    
    try {
        const requestBody = { 
            username: username.trim(), 
            email: email.trim(), 
            password: password, // Don't trim password
            role: role
        };
        
        console.log('[DEBUG] Frontend - Final request body:', JSON.stringify(requestBody));
        
        await fetchAPI('/users', {
            method: 'POST',
            body: JSON.stringify(requestBody)
        });
        
        closeModal('create-user-modal');
        document.getElementById('create-user-form').reset();
        await loadUsers();
        showSuccess('User created successfully');
        
    } catch (error) {
        console.error('Failed to create user:', error);
        showError(error.message || 'Failed to create user');
    }
}

// Temporary credentials functions
async function handleGenerateTempCreds() {
    try {
        const response = await fetchAPI('/auth/temp-credentials', {
            method: 'POST'
        });
        
        // Display credentials in modal
        document.getElementById('temp-cred-username').textContent = response.temp_username;
        document.getElementById('temp-cred-password').textContent = response.credential;
        document.getElementById('temp-cred-expires').textContent = formatDateTime(response.expires_at);
        
        // Update SFTP command
        const command = `sftp -P 2222 ${response.temp_username}@localhost`;
        document.getElementById('temp-cred-command').textContent = command;
        
        // Show password by default (it's visible once!)
        const passwordField = document.getElementById('temp-cred-password');
        if (passwordField) {
            passwordField.style.filter = 'none';
            passwordField.setAttribute('data-visible', 'true');
        }
        
        // Store password temporarily in memory for copy functionality
        // It will be cleared when modal closes
        window._tempCredentialPassword = response.credential;
        
        // Open modal
        openModal('temp-creds-modal');
        
        // Reload temp creds if on users view
        if (state.currentView === 'users' && state.selectedUser) {
            await loadUserTempCreds(state.selectedUser.id);
        }
        
    } catch (error) {
        console.error('Failed to generate temp credentials:', error);
        showError(error.message || 'Failed to generate temporary credentials');
    }
}

async function deleteTempCred(tempUsername) {
    if (!confirm(`Delete temporary credential ${tempUsername}?`)) {
        return;
    }
    
    try {
        await fetchAPI(`/temp-creds/${tempUsername}/delete`, {
            method: 'POST'
        });
        
        showSuccess('Temporary credential deleted');
        
        // Reload temp creds
        if (state.selectedUser) {
            await loadUserTempCreds(state.selectedUser.id);
        }
        
    } catch (error) {
        console.error('Failed to delete temp credential:', error);
        showError(error.message || 'Failed to delete temporary credential');
    }
}

// User action functions
async function resetPassword(userId) {
    const newPassword = prompt('Enter new password (minimum 8 characters):');
    if (!newPassword) return;
    
    if (newPassword.length < 8) {
        showError('Password must be at least 8 characters');
        return;
    }
    
    try {
        await fetchAPI(`/users/${userId}`, {
            method: 'PATCH',
            body: JSON.stringify({ password: newPassword })
        });
        
        showSuccess('Password reset successfully');
    } catch (error) {
        console.error('Failed to reset password:', error);
        showError(error.message || 'Failed to reset password');
    }
}

async function toggleUserLock(userId) {
    try {
        const user = await fetchAPI(`/users/${userId}`);
        
        await fetchAPI(`/users/${userId}`, {
            method: 'PATCH',
            body: JSON.stringify({ is_active: !user.is_active })
        });
        
        showSuccess(`User ${user.is_active ? 'locked' : 'unlocked'} successfully`);
        await loadUsers();
        
    } catch (error) {
        console.error('Failed to toggle user lock:', error);
        showError(error.message || 'Failed to update user status');
    }
}

async function deleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        return;
    }
    
    try {
        await fetchAPI(`/users/${userId}/delete`, {
            method: 'POST'
        });
        
        showSuccess('User deleted successfully');
        await loadUsers();
        
        // Hide details if deleted user was selected
        if (state.selectedUser && state.selectedUser.id === userId) {
            const detailsPanel = document.querySelector('.user-details');
            if (detailsPanel) {
                detailsPanel.classList.remove('active');
            }
            state.selectedUser = null;
        }
        
    } catch (error) {
        console.error('Failed to delete user:', error);
        showError(error.message || 'Failed to delete user');
    }
}

// Vault action functions
async function openVault(vaultId) {
    try {
        // Validate vault ID
        if (!vaultId) {
            console.error('Invalid vault ID:', vaultId);
            showError('Invalid vault ID');
            navigateToView('vaults');
            return;
        }
        
        // Fetch vault details (metadata only, no password required)
        const vault = await fetchAPI(`/vaults/${vaultId}`);
        
        // Validate vault data
        if (!vault || !vault.id) {
            console.error('Invalid vault data received');
            showError('Failed to load vault');
            navigateToView('vaults');
            return;
        }
        
        // Store vault metadata in state (but don't show view yet)
        state.currentVault = vault;
        state.currentVaultId = vaultId; // Persist for page refresh
        state.currentFolderId = null;  // Start at root
        state.currentPath = [];  // Empty path array (root)
        
        // Update vault view header (even though not visible yet)
        document.getElementById('vault-view-title').textContent = vault.name;
        document.getElementById('vault-view-description').textContent = vault.description || 'No description';
        document.getElementById('vault-view-lock-icon').textContent = vault.has_password ? '🔒' : '';
        
        // If vault is password-protected, prompt for password BEFORE making any file requests
        if (vault.has_password) {
            const hasValidPassword = state.isVaultPasswordValid();
            
            if (!hasValidPassword) {
                // No valid password - prompt in a loop until correct, cancelled, or rate limited
                console.log('Vault is password-protected, prompting for password...');
                let passwordVerified = false;
                
                while (!passwordVerified) {
                    try {
                        // Show modal to get password
                        const password = await showVaultPasswordModal(vault.name, 'access');
                        console.log('Testing password...');
                        
                        // Test password with a file list request
                        const testHeaders = { 'X-Vault-Password': password };
                        await fetchAPI(`/vaults/${vaultId}/files`, { headers: testHeaders });
                        
                        // SUCCESS! Password is correct
                        console.log('✓ Password verified');
                        state.vaultPassword = password;
                        passwordVerified = true;
                        
                    } catch (error) {
                        // Check if user cancelled
                        if (error.message === 'Password entry cancelled') {
                            console.log('User cancelled password entry');
                            showInfo('Vault access cancelled');
                            state.currentVault = null;
                            state.currentVaultId = null;
                            return;
                        }
                        
                        // Check if rate limited
                        if (error.message && (error.message.includes('Too many') || error.message.includes('429'))) {
                            showError('Too many password attempts. Please try again later.');
                            state.currentVault = null;
                            state.currentVaultId = null;
                            return;
                        }
                        
                        // Wrong password - show error and loop will continue
                        if (error.message && (error.message.includes('password') || error.message.includes('Password') || error.message.includes('Unauthorized') || error.message.includes('401'))) {
                            showError('❌ Invalid vault password. Please try again.');
                            // Loop continues - modal will appear again
                        } else {
                            // Unexpected error
                            showError('Failed to access vault: ' + error.message);
                            state.currentVault = null;
                            state.currentVaultId = null;
                            return;
                        }
                    }
                }
            } else {
                console.log('Using cached vault password');
            }
        }
        
        // Password verified (or vault has no password) - NOW load files and show view
        await loadVaultFiles();
        
        console.log('Opened vault:', vault.name);
        
    } catch (error) {
        console.error('Failed to open vault:', error);
        showError(error.message || 'Failed to open vault');
        
        // Clear vault state and return to vaults list
        state.currentVault = null;
        state.currentVaultId = null;
        state.vaultPassword = null;
        navigateToView('vaults');
    }
}

function editVault(vaultId) {
    // Removed - editing happens in vault view settings tab
    openVault(vaultId);
}

async function deleteVault(vaultId) {
    try {
        // First, get vault info to check if it has a password
        const vault = await fetchAPI(`/vaults/${vaultId}`);
        
        let vaultPassword = null;
        
        // If vault has password, prompt for it using modal
        if (vault.has_password) {
            try {
                vaultPassword = await showVaultPasswordModal(vault.name, 'delete');
            } catch (error) {
                // User cancelled password entry
                return;
            }
        }
        
        // Confirm deletion
        if (!confirm(`Are you sure you want to delete vault "${vault.name}"?\n\nAll files will be permanently lost. This action cannot be undone.`)) {
            return;
        }
        
        showInfo('Deleting vault...');
        
        // Delete vault with password if needed
        const deleteUrl = vaultPassword 
            ? `/vaults/${vaultId}/delete?vault_password=${encodeURIComponent(vaultPassword)}`
            : `/vaults/${vaultId}/delete`;
            
        await fetchAPI(deleteUrl, {
            method: 'POST'
        });
        
        showSuccess('Vault deleted successfully');
        
        // Navigate to vaults list
        state.currentVault = null;
        state.currentVaultId = null;
        state.vaultPassword = null;
        navigateToView('vaults');
        await loadVaults();
        
    } catch (error) {
        console.error('Failed to delete vault:', error);
        showError(error.message || 'Failed to delete vault');
    }
}

// Modal functions
function setupModals() {
    // Close modals when clicking backdrop
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal(modal.id);
            }
        });
    });
    
    // Close modals with close button
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            const modal = btn.closest('.modal');
            if (modal) {
                closeModal(modal.id);
            }
        });
    });
    
    // Close modals with cancel button
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalId = btn.dataset.closeModal;
            closeModal(modalId);
        });
    });
    
    // Open modals
    document.querySelectorAll('[data-open-modal]').forEach(btn => {
        btn.addEventListener('click', () => {
            const modalId = btn.dataset.openModal;
            openModal(modalId);
        });
    });
}

function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
        
        // Special handling for temp credentials modal - clear password from memory
        if (modalId === 'temp-creds-modal') {
            // Clear password from memory (security!)
            if (window._tempCredentialPassword) {
                window._tempCredentialPassword = null;
                delete window._tempCredentialPassword;
            }
            
            // Mask the password field to show it's no longer available
            const passwordField = document.getElementById('temp-cred-password');
            if (passwordField) {
                passwordField.textContent = '••••••••••••••••';
                passwordField.style.filter = 'blur(4px)';
                passwordField.style.userSelect = 'none';
                passwordField.setAttribute('data-visible', 'false');
            }
        }
    }
}

// Password toggle
function togglePasswordVisibility(e) {
    const btn = e.target.closest('.toggle-password-btn');
    const passwordField = btn.previousElementSibling;
    
    if (passwordField.classList.contains('hidden')) {
        passwordField.classList.remove('hidden');
        passwordField.textContent = passwordField.dataset.password;
        btn.textContent = '🙈';
    } else {
        passwordField.dataset.password = passwordField.textContent;
        passwordField.textContent = '••••••••••••';
        passwordField.classList.add('hidden');
        btn.textContent = '👁️';
    }
}

// Copy to clipboard
function copyToClipboard() {
    const command = document.getElementById('sftp-command').textContent;
    
    navigator.clipboard.writeText(command).then(() => {
        const btn = document.getElementById('copy-command-btn');
        const originalText = btn.textContent;
        btn.textContent = '✓ Copied!';
        setTimeout(() => {
            btn.textContent = originalText;
        }, 2000);
    }).catch(err => {
        showError('Failed to copy to clipboard');
    });
}

// Enhanced copy with security handling for temp credentials
function handleSecureCopy(e) {
    e.preventDefault();
    const btn = e.target.closest('.copy-btn');
    const targetId = btn.getAttribute('data-copy');
    const targetElement = document.getElementById(targetId);
    
    if (!targetElement) {
        showError('Nothing to copy');
        return;
    }
    
    let textToCopy = targetElement.textContent.trim();
    let isPassword = false;
    
    // Special handling for password fields
    if (targetId === 'temp-cred-password') {
        isPassword = true;
        
        // Check if password is still available
        if (window._tempCredentialPassword) {
            textToCopy = window._tempCredentialPassword;
        } else {
            // Password has been cleared!
            showError('🔒 Password is no longer available. It was only shown once for security.');
            return;
        }
    }
    
    // Copy to clipboard
    navigator.clipboard.writeText(textToCopy).then(() => {
        // Visual feedback
        const originalText = btn.textContent;
        btn.textContent = '✓';
        btn.style.color = '#28a745';
        
        // Show security notice for passwords
        if (isPassword) {
            showSuccess('🔐 Password copied securely. Remember to save it!');
        } else {
            showSuccess('✓ Copied to clipboard');
        }
        
        // Reset button after delay
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.color = '';
        }, 2000);
    }).catch(err => {
        console.error('Copy failed:', err);
        showError('Failed to copy to clipboard');
    });
}

// API helper with ETag caching support
async function fetchAPI(endpoint, options = {}) {
    // Build headers properly - don't use spread at top level to avoid issues
    const headers = {};
    
    // Add Authorization first
    if (state.token) {
        headers['Authorization'] = `Bearer ${state.token}`;
    }
    
    // Add Content-Type if needed
    if (!options.skipContentType && (!options.headers || options.headers['Content-Type'] === undefined)) {
        headers['Content-Type'] = 'application/json';
    }
    
    // Merge any additional headers from options
    if (options.headers) {
        Object.assign(headers, options.headers);
    }
    
    console.log(`API Request: ${options.method || 'GET'} ${endpoint}`);
    
    // Use cache manager for GET requests if available (enables ETag caching)
    const useCache = !options.method || options.method === 'GET';
    
    try {
        let response;
        let data;
        
        if (useCache && window.cacheManager) {
            // Use cache manager for GET requests (supports 304 Not Modified)
            try {
                // Cache manager returns parsed data directly
                data = await window.cacheManager.fetch(`${API_BASE}${endpoint}`, {
                    ...options,
                    headers
                });
                
                // Data successfully retrieved from cache manager
                // For GET requests with cache hits, return the data immediately
                console.log(`API Success (cached): ${endpoint}`);
                return data;
                
            } catch (cacheError) {
                // If cache manager fails, fall back to direct fetch
                // Don't log password 404s as warnings - they're expected
                const isPasswordEndpoint = endpoint.includes('/password');
                const is404 = cacheError.message && cacheError.message.includes('HTTP 404');
                
                if (!isPasswordEndpoint || !is404) {
                    console.warn('Cache manager failed, using direct fetch:', cacheError);
                }
                
                response = await fetch(`${API_BASE}${endpoint}`, {
                    ...options,
                    headers
                });
            }
        } else {
            // Direct fetch for non-GET requests or when cache manager unavailable
            response = await fetch(`${API_BASE}${endpoint}`, {
                ...options,
                headers
            });
        }
        
        // If we got here via fallback or non-cached request, handle response normally
        if (!response) {
            throw new Error('No response received');
        }
        
        // Try to parse response as JSON first to check error details
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else if (!response.ok) {
            // If not JSON and error, get text for debugging
            const text = await response.text();
            console.error(`Non-JSON response from ${endpoint}:`, text);
            data = { detail: `Server error: ${response.status} ${response.statusText}` };
        } else {
            // Success but not JSON (like file download)
            return response;
        }
        
        if (response.status === 401) {
            // Check if it's a password requirement or session expiration
            const errorDetail = data.detail || '';
            if (errorDetail.includes('password') || errorDetail.includes('Password')) {
                // Password required - throw error but don't log out
                console.log('Password required for resource');
                throw new Error(errorDetail);
            } else {
                // Session expired - use session manager to handle logout
                console.log('Session expired, logging out');
                if (window.sessionManager) {
                    window.sessionManager.handleAuthError(response);
                } else {
                    logout();
                }
                throw new Error('Session expired. Please log in again.');
            }
        }
        
        if (response.status === 403) {
            // Check if this is an inactive account or permission denied
            const errorDetail = data.detail || '';
            if (errorDetail.includes('inactive') || errorDetail.includes('terminated')) {
                // Account issue - use session manager to handle logout
                console.log('Account inactive, logging out');
                if (window.sessionManager) {
                    window.sessionManager.handleAuthError(response);
                } else {
                    logout();
                }
                throw new Error(errorDetail);
            } else {
                // Permission denied - show friendly message but don't log out
                console.warn('Permission denied:', endpoint);
                const message = data.detail || 'You do not have permission to perform this action.';
                showPermissionDeniedMessage(message);
                throw new Error(message);
            }
        }
        
        if (!response.ok) {
            console.error(`API Error: ${endpoint}`, data);
            // For validation errors (422), log the details properly
            if (data.detail && Array.isArray(data.detail)) {
                console.error('Validation errors:', JSON.stringify(data.detail, null, 2));
                const errorMsg = data.detail.map(err => `${err.loc ? err.loc.join('.') : ''}: ${err.msg}`).join(', ');
                throw new Error(errorMsg || 'Validation failed');
            }
            throw new Error(data.detail || `Request failed with status ${response.status}`);
        }
        
        console.log(`API Success: ${endpoint}`, data);
        return data;
    } catch (error) {
        if (error.message === 'Session expired. Please login again.') {
            throw error;
        }
        console.error(`API Request failed: ${endpoint}`, error);
        throw new Error(`Network error: ${error.message}`);
    }
}

// Notification functions
function showSuccess(message) {
    showNotification(message, 'success');
}

function showError(message) {
    showNotification(message, 'error');
}

function showInfo(message) {
    showNotification(message, 'info');
}

function showPermissionDeniedMessage(message) {
    // Show a more prominent permission denied message
    const notification = document.createElement('div');
    notification.className = 'alert alert-warning notification-active';
    notification.innerHTML = `
        <strong>⛔ Permission Denied</strong><br>
        ${escapeHtml(message)}
    `;
    notification.style.position = 'fixed';
    notification.style.right = '20px';
    notification.style.zIndex = '9999';
    notification.style.minWidth = '350px';
    notification.style.maxWidth = '500px';
    notification.style.animation = 'slideIn 0.3s ease-out';
    notification.style.padding = '15px';
    notification.style.borderLeft = '4px solid #ff9800';
    
    // Calculate vertical position based on ACTIVE notifications only
    const existingNotifications = document.querySelectorAll('.notification-active');
    let topOffset = 20;
    existingNotifications.forEach(existing => {
        const rect = existing.getBoundingClientRect();
        topOffset = Math.max(topOffset, rect.bottom + 10);
    });
    notification.style.top = `${topOffset}px`;
    
    document.body.appendChild(notification);
    
    // Remove after 7 seconds
    setTimeout(() => {
        notification.classList.remove('notification-active'); // Mark as inactive
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => {
            if (notification.parentNode) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 7000);
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} notification-active`;
    notification.textContent = message;
    notification.style.position = 'fixed';
    notification.style.right = '20px';
    notification.style.zIndex = '9999';
    notification.style.minWidth = '300px';
    notification.style.animation = 'slideIn 0.3s ease-out';
    
    // Calculate vertical position based on ACTIVE notifications only
    const existingNotifications = document.querySelectorAll('.notification-active');
    let topOffset = 20;
    existingNotifications.forEach(existing => {
        const rect = existing.getBoundingClientRect();
        topOffset = Math.max(topOffset, rect.bottom + 10); // 10px gap between notifications
    });
    notification.style.top = `${topOffset}px`;
    
    document.body.appendChild(notification);
    
    // Remove after 5 seconds
    setTimeout(() => {
        notification.classList.remove('notification-active'); // Mark as inactive
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => {
            if (notification.parentNode) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 5000);
}

// Utility functions
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatDateTime(isoString) {
    if (!isoString) return 'N/A';
    
    const date = new Date(isoString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        timeZoneName: 'short'
    });
}

// Add CSS animation
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

// ===== VAULT MANAGEMENT FUNCTIONS =====

// Tab Management
function setupVaultTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    // Check if user is owner or admin
    const isOwner = state.currentVault.owner_id === state.user.id;
    const isAdmin = state.user.role === 'ADMIN';
    const canManage = isOwner || isAdmin;
    
    // Get tab elements
    const filesTab = document.querySelector('[data-tab="files"]');
    const infoTab = document.querySelector('[data-tab="info"]');
    const permissionsTab = document.querySelector('[data-tab="permissions"]');
    const settingsTab = document.querySelector('[data-tab="settings"]');
    
    // Role-based tab visibility
    if (!canManage) {
        // Non-owners: Show Files and Info tabs only
        if (filesTab) filesTab.style.display = '';
        if (infoTab) infoTab.style.display = '';
        if (permissionsTab) permissionsTab.style.display = 'none';
        if (settingsTab) settingsTab.style.display = 'none';
        
        // Auto-activate Files tab for non-owners
        if (filesTab && !filesTab.classList.contains('active')) {
            filesTab.click();
        }
    } else {
        // Owners/Admins: Show all tabs
        if (filesTab) filesTab.style.display = '';
        if (infoTab) infoTab.style.display = '';
        if (permissionsTab) permissionsTab.style.display = '';
        if (settingsTab) settingsTab.style.display = '';
    }
    
    tabBtns.forEach(btn => {
        // Remove old listeners to prevent duplicates
        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);
    });
    
    // Re-query after cloning
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const tabName = btn.dataset.tab;
            
            // Update active tab button
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update active tab content
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(`${tabName}-tab`).classList.add('active');
            
            // Load tab data
            if (tabName === 'files') {
                await loadVaultFiles();
            } else if (tabName === 'info') {
                await loadVaultInfo();
            } else if (tabName === 'permissions') {
                await loadVaultPermissions();
            } else if (tabName === 'settings') {
                await loadVaultSettings();
            }
        });
    });
    
    // Only setup event listeners once (check if already setup)
    if (!window.vaultEventListenersSetup) {
        window.vaultEventListenersSetup = true;
        
        // Close vault button
        document.getElementById('close-vault-btn').addEventListener('click', () => {
            closeVault();
        });
        
        // File operations buttons
        document.getElementById('upload-file-btn').addEventListener('click', () => {
            openModal('upload-file-modal');
        });
        
        document.getElementById('create-folder-btn').addEventListener('click', () => {
            openModal('create-folder-modal');
        });
        
        // Form submissions
        document.getElementById('upload-file-form').addEventListener('submit', handleFileUpload);
        document.getElementById('create-folder-form').addEventListener('submit', handleCreateFolder);
        document.getElementById('rename-item-form').addEventListener('submit', handleRenameItem);
        document.getElementById('grant-permission-form').addEventListener('submit', handleGrantPermission);
        document.getElementById('edit-vault-info-form').addEventListener('submit', handleEditVaultInfo);
        document.getElementById('change-vault-password-form').addEventListener('submit', handleChangeVaultPassword);
        document.getElementById('set-expiry-form').addEventListener('submit', handleSetExpiry);
        
        // Setup drag & drop for file upload
        setupFileDragDrop();
    }
    
    // These buttons need current vault context, so update them each time
    // Also check permissions to show/hide edit buttons
    const addPermBtn = document.getElementById('add-permission-btn');
    if (addPermBtn) {
        if (!canManage) {
            addPermBtn.style.display = 'none';
        } else {
            addPermBtn.style.display = '';
            const newAddPermBtn = addPermBtn.cloneNode(true);
            addPermBtn.parentNode.replaceChild(newAddPermBtn, addPermBtn);
            newAddPermBtn.addEventListener('click', async () => {
                await loadUsersForPermission();
                openModal('grant-permission-modal');
            });
        }
    }
    
    const editVaultBtn = document.getElementById('edit-vault-info-btn');
    if (editVaultBtn) {
        if (!canManage) {
            editVaultBtn.style.display = 'none';
        } else {
            editVaultBtn.style.display = '';
            const newEditBtn = editVaultBtn.cloneNode(true);
            editVaultBtn.parentNode.replaceChild(newEditBtn, editVaultBtn);
            newEditBtn.addEventListener('click', () => {
                // Pre-fill form with current vault data
                document.getElementById('edit-vault-name').value = state.currentVault.name;
                document.getElementById('edit-vault-description').value = state.currentVault.description || '';
                openModal('edit-vault-info-modal');
            });
        }
    }
    
    const updateSizeLimitBtn = document.getElementById('update-size-limit-btn');
    if (updateSizeLimitBtn) {
        if (!canManage) {
            updateSizeLimitBtn.style.display = 'none';
        } else {
            updateSizeLimitBtn.style.display = '';
            const newSizeLimitBtn = updateSizeLimitBtn.cloneNode(true);
            updateSizeLimitBtn.parentNode.replaceChild(newSizeLimitBtn, updateSizeLimitBtn);
            newSizeLimitBtn.addEventListener('click', async () => {
                await updateVaultSizeLimit();
            });
        }
    }
    
    const changePasswordBtn = document.getElementById('change-vault-password-btn');
    if (changePasswordBtn) {
        if (!canManage) {
            changePasswordBtn.style.display = 'none';
        } else {
            changePasswordBtn.style.display = '';
            const newChangePassBtn = changePasswordBtn.cloneNode(true);
            changePasswordBtn.parentNode.replaceChild(newChangePassBtn, changePasswordBtn);
            newChangePassBtn.addEventListener('click', () => {
                document.getElementById('change-vault-password-form').reset();
                openModal('change-vault-password-modal');
            });
        }
    }
    
    const setExpiryBtn = document.getElementById('set-expiry-btn');
    if (setExpiryBtn) {
        if (!canManage) {
            setExpiryBtn.style.display = 'none';
        } else {
            setExpiryBtn.style.display = '';
            const newExpiryBtn = setExpiryBtn.cloneNode(true);
            setExpiryBtn.parentNode.replaceChild(newExpiryBtn, setExpiryBtn);
            newExpiryBtn.addEventListener('click', () => {
                const currentExpiry = state.currentVault.expire_files_after_days || 0;
                const currentUnit = state.currentVault.expire_files_unit || 'days';
                document.getElementById('expire-files-value').value = currentExpiry;
                document.getElementById('expire-files-unit').value = currentUnit;
                openModal('set-expiry-modal');
            });
        }
    }
    
    const deleteVaultBtn = document.getElementById('delete-vault-from-settings-btn');
    if (deleteVaultBtn) {
        // Only show delete button for owners/admins
        const isOwner = state.currentVault.owner_id === state.user.id;
        const isAdmin = state.user.role === 'ADMIN';
        const canDelete = isOwner || isAdmin;
        
        if (!canDelete) {
            deleteVaultBtn.style.display = 'none';
        } else {
            deleteVaultBtn.style.display = '';
            const newDeleteBtn = deleteVaultBtn.cloneNode(true);
            deleteVaultBtn.parentNode.replaceChild(newDeleteBtn, deleteVaultBtn);
            newDeleteBtn.addEventListener('click', () => {
                deleteVault(state.currentVault.id);
            });
        }
    }
}

function closeVault() {
    // Stop auto-refresh
    stopVaultFilesAutoRefresh();
    
    // Hide vault view completely
    const vaultView = document.getElementById('vault-view');
    vaultView.style.display = 'none';
    vaultView.classList.remove('active');
    
    // Show vaults view
    const vaultsView = document.getElementById('vaults-view');
    vaultsView.style.display = 'block';
    vaultsView.classList.add('active');
    
    // Reset state
    state.currentVault = null;
    state.currentVaultId = null; // Clear persisted vault ID
    state.currentFolderId = null;
    state.currentPath = [];
    state.currentView = 'vaults';
    state.vaultPassword = null;
    
    // Update lastView so refresh doesn't try to restore vault
    localStorage.setItem('lastView', 'vaults');
    
    // Clear vault password
    sessionStorage.removeItem('psftp_vault_password');
    
    // Highlight Vaults nav item
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    const vaultsNav = document.getElementById('nav-vaults');
    if (vaultsNav) {
        vaultsNav.classList.add('active');
    }
    
    // Reset to files tab
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector('[data-tab="files"]')?.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    document.getElementById('files-tab')?.classList.add('active');
    
    // Reload vault list to refresh file counts and sizes
    loadVaults();
}

// Auto-refresh functions for vault files
function startVaultFilesAutoRefresh() {
    // Clear any existing interval
    stopVaultFilesAutoRefresh();
    
    // Refresh files every 5 seconds when on files tab AND in vault view
    const intervalId = setInterval(() => {
        const filesTab = document.getElementById('files-tab');
        const vaultView = document.getElementById('vault-view');
        // Only refresh if vault view is active, files tab is active, and we have a current vault
        if (vaultView && vaultView.classList.contains('active') && 
            filesTab && filesTab.classList.contains('active') && 
            state.currentVault) {
            loadVaultFiles();
        }
    }, 5000); // 5 seconds
    state.vaultFilesRefreshInterval = intervalId;
    
    // Register with session manager
    if (window.sessionManager) {
        window.sessionManager.registerInterval(intervalId);
    }
}

function stopVaultFilesAutoRefresh() {
    if (state.vaultFilesRefreshInterval) {
        clearInterval(state.vaultFilesRefreshInterval);
        state.vaultFilesRefreshInterval = null;
    }
}

// Files Tab Functions
async function loadVaultFiles() {
    // Check if we have a current vault to load
    if (!state.currentVault) {
        console.log('Skipping loadVaultFiles - no current vault');
        return;
    }
    
    const vaultView = document.getElementById('vault-view');
    const isViewActive = vaultView && vaultView.classList.contains('active');
    
    const tbody = document.getElementById('files-table-body');
    
    try {
        console.log('🚀 Loading files for vault:', state.currentVault.id, 'folder:', state.currentFolderId, '(ETag caching active - 5s polling optimized)');
        
        // Build URL with folder_id if navigating into a folder
        let url = `/vaults/${state.currentVault.id}/files`;
        if (state.currentFolderId) {
            url += `?folder_id=${state.currentFolderId}`;
        }
        
        // Build headers with vault password (NOT in URL for security)
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        
        const data = await fetchAPI(url, { headers });
        
        // PASSWORD VERIFIED! If view isn't active yet, show it now
        if (!isViewActive) {
            console.log('✓ Password verified, showing vault view');
            
            // Hide ALL views first (including dashboard, users, etc.)
            document.querySelectorAll('.view').forEach(view => {
                view.classList.remove('active');
                view.style.display = 'none';
            });
            
            // Now show vault detail view
            vaultView.classList.add('active');
            vaultView.style.display = 'block';
            
            // Mark current view state (use 'vault' to indicate we're in vault detail)
            state.currentView = 'vault';
            localStorage.setItem('lastView', 'vault');
            
            // Start auto-refresh for files (every 5 seconds)
            startVaultFilesAutoRefresh();
            
            // Initialize tab switching
            setupVaultTabs();
        }
        
        // Update breadcrumb
        updateBreadcrumb();
        
        if (!data.items || data.items.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center" style="padding: 40px;">
                        <div class="empty-state">
                            <p style="font-size: 48px; margin: 0;">📂</p>
                            <h3 style="margin: 16px 0 8px 0;">No files yet</h3>
                            <p style="color: var(--text-muted);">Upload files or create folders to get started</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }
        
        // Sort: folders first, then files
        data.items.sort((a, b) => {
            if (a.type === 'folder' && b.type !== 'folder') return -1;
            if (a.type !== 'folder' && b.type === 'folder') return 1;
            return a.name.localeCompare(b.name);
        });
        
        // Render items
        tbody.innerHTML = data.items.map(item => {
            const icon = item.type === 'folder' ? '📁' : getFileIcon(item.name, false);
            const size = item.type === 'folder' ? '-' : formatFileSize(item.size);
            const modified = new Date(item.modified).toLocaleString();
            const lockIcon = item.has_password ? ' 🔒' : '';
            const rowClass = item.type === 'folder' ? 'folder-row' : '';
            
            return `
                <tr class="${rowClass}">
                    <td>
                        <span class="file-icon">${icon}</span>
                        <span class="file-name">${escapeHtml(item.name)}${lockIcon}</span>
                    </td>
                    <td>${size}</td>
                    <td>${item.mime_type || '-'}</td>
                    <td>${modified}</td>
                    <td>
                        ${item.type === 'folder' ? `
                            <button class="btn btn-sm" data-action="open-folder" data-id="${item.id}" data-name="${escapeHtml(item.name)}">Open</button>
                            <button class="btn btn-sm" data-action="rename" data-id="${item.id}" data-name="${escapeHtml(item.name)}" data-type="folder">✏️ Rename</button>
                        ` : `
                            <button class="btn btn-sm" data-action="download" data-id="${item.id}" data-name="${escapeHtml(item.name)}">Download</button>
                            <button class="btn btn-sm" data-action="rename" data-id="${item.id}" data-name="${escapeHtml(item.name)}" data-type="file">✏️ Rename</button>
                            <button class="btn btn-sm btn-danger" data-action="delete" data-id="${item.id}" data-name="${escapeHtml(item.name)}">Delete</button>
                        `}
                    </td>
                </tr>
            `;
        }).join('');
        
        // Add event listeners for buttons (CSP-compliant)
        tbody.querySelectorAll('button[data-action]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const action = e.target.getAttribute('data-action');
                const id = e.target.getAttribute('data-id');
                const name = e.target.getAttribute('data-name');
                const type = e.target.getAttribute('data-type');
                
                if (action === 'open-folder') {
                    openFolder(id, name);
                } else if (action === 'download') {
                    downloadFile(id, name);
                } else if (action === 'rename') {
                    showRenameModal(id, name);
                } else if (action === 'delete') {
                    deleteFile(id, name);
                }
            });
        });
        
    } catch (error) {
        console.error('Failed to load files:', error);
        
        // Check if folder not found (404)
        if (error.message && error.message.includes('Folder not found')) {
            showError('The folder you were viewing has been deleted. Returning to vault root...');
            // Reset to root and reload
            state.currentFolderId = null;
            state.currentPath = [];
            await loadVaultFiles();
            return;
        }
        
        // Check if rate limited
        if (error.message && (error.message.includes('Too many') || error.message.includes('429'))) {
            showError('Too many password attempts. Please try again later.');
            // Don't show vault view, just close it
            setTimeout(() => {
                closeVault();
            }, 2000);
            return;
        }
        
        // Check if password is wrong or required
        if (error.message && (error.message.includes('password') || error.message.includes('Password') || error.message.includes('Unauthorized') || error.message.includes('401'))) {
            // Wrong password or missing password - prompt in a loop
            let passwordVerified = false;
            
            while (!passwordVerified) {
                try {
                    const password = await showVaultPasswordModal(state.currentVault.name, 'access');
                    console.log('Retrying with password from modal...');
                    
                    // Build headers with new password
                    const headers = {};
                    if (state.currentVault.has_password) {
                        headers['X-Vault-Password'] = password;
                    }
                    
                    // Try to fetch files with new password (DON'T call loadVaultFiles recursively!)
                    let url = `/vaults/${state.currentVault.id}/files`;
                    if (state.currentFolderId) {
                        url += `?folder_id=${state.currentFolderId}`;
                    }
                    
                    const data = await fetchAPI(url, { headers });
                    
                    // SUCCESS! Password is correct
                    console.log('✓ Password verified successfully');
                    state.vaultPassword = password; // Store for future use
                    passwordVerified = true;
                    
                    // Now show vault view (if not already shown)
                    if (!isViewActive) {
                        console.log('✓ Showing vault view after password verification');
                        document.getElementById('vaults-view').classList.remove('active');
                        document.getElementById('vaults-view').style.display = 'none';
                        vaultView.classList.add('active');
                        vaultView.style.display = 'block';
                        
                        // Start auto-refresh for files
                        startVaultFilesAutoRefresh();
                        
                        // Initialize tab switching
                        setupVaultTabs();
                    }
                    
                    // Display the files
                    updateBreadcrumb();
                    
                    if (!data.items || data.items.length === 0) {
                        tbody.innerHTML = `
                            <tr>
                                <td colspan="5" class="text-center" style="padding: 40px;">
                                    <div class="empty-state">
                                        <p style="font-size: 48px; margin: 0;">�</p>
                                        <h3 style="margin: 16px 0 8px 0;">No files yet</h3>
                                        <p style="color: var(--text-muted);">Upload files or create folders to get started</p>
                                    </div>
                                </td>
                            </tr>
                        `;
                        return;
                    }
                    
                    // Sort and render files (copy the rendering logic from above)
                    data.items.sort((a, b) => {
                        if (a.type === 'folder' && b.type !== 'folder') return -1;
                        if (a.type !== 'folder' && b.type === 'folder') return 1;
                        return a.name.localeCompare(b.name);
                    });
                    
                    tbody.innerHTML = data.items.map(item => {
                        const icon = item.type === 'folder' ? '📁' : getFileIcon(item.name, false);
                        const size = item.type === 'folder' ? '-' : formatFileSize(item.size);
                        const modified = new Date(item.modified).toLocaleString();
                        const lockIcon = item.has_password ? ' 🔒' : '';
                        const rowClass = item.type === 'folder' ? 'folder-row' : '';
                        
                        return `
                            <tr class="${rowClass}">
                                <td>
                                    <span class="file-icon">${icon}</span>
                                    <span class="file-name">${escapeHtml(item.name)}${lockIcon}</span>
                                </td>
                                <td>${size}</td>
                                <td>${item.mime_type || '-'}</td>
                                <td>${modified}</td>
                                <td>
                                    ${item.type === 'folder' ? `
                                        <button class="btn btn-sm" data-action="open-folder" data-id="${item.id}" data-name="${escapeHtml(item.name)}">Open</button>
                                    ` : `
                                        <button class="btn btn-sm" data-action="download" data-id="${item.id}" data-name="${escapeHtml(item.name)}">Download</button>
                                        <button class="btn btn-sm btn-danger" data-action="delete" data-id="${item.id}" data-name="${escapeHtml(item.name)}">Delete</button>
                                    `}
                                </td>
                            </tr>
                        `;
                    }).join('');
                    
                    // Add event listeners
                    tbody.querySelectorAll('button[data-action]').forEach(btn => {
                        btn.addEventListener('click', async (e) => {
                            const action = e.target.dataset.action;
                            const itemId = e.target.dataset.id;
                            const itemName = e.target.dataset.name;
                            
                            if (action === 'open-folder') {
                                await openFolder(itemId, itemName);
                            } else if (action === 'download') {
                                await downloadFile(itemId, itemName);
                            } else if (action === 'delete') {
                                await deleteVaultItem(itemId, itemName);
                            }
                        });
                    });
                    
                    return; // Success - exit the function
                    
                } catch (retryError) {
                    // Check if user cancelled
                    if (retryError.message === 'Password entry cancelled') {
                        console.log('User cancelled password entry');
                        showInfo('Vault access cancelled');
                        closeVault(); // Go back to vaults list
                        return;
                    }
                    
                    // Check if rate limited during retry
                    if (retryError.message && (retryError.message.includes('Too many') || retryError.message.includes('429'))) {
                        showError('Too many password attempts. Please try again later.');
                        setTimeout(() => {
                            closeVault();
                        }, 2000);
                        return;
                    }
                    
                    // Still wrong password - show error and loop will continue
                    if (retryError.message && (retryError.message.includes('password') || retryError.message.includes('Password') || retryError.message.includes('Unauthorized') || retryError.message.includes('401'))) {
                        showError('❌ Invalid vault password. Please try again.');
                        // Loop continues to prompt again
                    } else {
                        // Unexpected error during retry
                        showError('Failed to load files: ' + retryError.message);
                        closeVault();
                        return;
                    }
                }
            }
            return;
        }
        
        // Other errors - show error and stay in vaults list
        showError('Failed to load files: ' + error.message);
        if (!isViewActive) {
            // View not shown yet, so we can safely return to vaults
            closeVault();
        }
    }
}

// Helper function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Open a folder
async function openFolder(folderId, folderName) {
    state.currentFolderId = folderId;
    state.currentPath.push({ id: folderId, name: folderName });
    await loadVaultFiles();
}

// Navigate via breadcrumb
async function navigateToBreadcrumb(index) {
    if (index === -1) {
        // Root
        state.currentFolderId = null;
        state.currentPath = [];
    } else {
        // Navigate to specific folder
        state.currentFolderId = state.currentPath[index].id;
        state.currentPath = state.currentPath.slice(0, index + 1);
    }
    await loadVaultFiles();
}

function updateBreadcrumb() {
    const breadcrumb = document.querySelector('.breadcrumb');
    const pathParts = state.currentPath || [];
    
    let breadcrumbHTML = '<span class="breadcrumb-item" data-breadcrumb="-1" style="cursor: pointer;">🏠 Root</span>';
    
    pathParts.forEach((folder, index) => {
        breadcrumbHTML += `<span class="breadcrumb-item" data-breadcrumb="${index}" style="cursor: pointer;">${escapeHtml(folder.name)}</span>`;
    });
    
    breadcrumb.innerHTML = breadcrumbHTML;
    
    // Add event listeners for breadcrumb navigation (CSP-compliant)
    breadcrumb.querySelectorAll('[data-breadcrumb]').forEach(item => {
        item.addEventListener('click', () => {
            const index = parseInt(item.getAttribute('data-breadcrumb'), 10);
            navigateToBreadcrumb(index);
        });
    });
}

function getFileIcon(filename, isFolder) {
    if (isFolder) return '📁';
    
    const ext = filename.split('.').pop().toLowerCase();
    const iconMap = {
        // Documents
        'pdf': '📄',
        'doc': '📝', 'docx': '📝',
        'xls': '📊', 'xlsx': '📊',
        'ppt': '📊', 'pptx': '📊',
        'txt': '📃',
        
        // Images
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️',
        'svg': '🎨', 'bmp': '🖼️', 'ico': '🖼️',
        
        // Archives
        'zip': '🗜️', 'rar': '🗜️', '7z': '🗜️', 'tar': '🗜️', 'gz': '🗜️',
        
        // Code
        'js': '📜', 'py': '🐍', 'java': '☕', 'cpp': '⚙️', 'c': '⚙️',
        'html': '🌐', 'css': '🎨', 'json': '📋', 'xml': '📋',
        
        // Media
        'mp3': '🎵', 'wav': '🎵', 'flac': '🎵',
        'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬', 'mov': '🎬',
        
        // Default
        'default': '📄'
    };
    
    return iconMap[ext] || iconMap['default'];
}

// Permissions Tab Functions
async function loadVaultPermissions() {
    const tbody = document.getElementById('permissions-table-body');
    
    try {
        console.log('Loading permissions for vault:', state.currentVault.id);
        
        const permissions = await fetchAPI(`/vaults/${state.currentVault.id}/permissions`);
        
        if (!permissions || permissions.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center" style="padding: 40px;">
                        <div class="empty-state">
                            <p style="font-size: 48px; margin: 0;">👥</p>
                            <h3 style="margin: 16px 0 8px 0;">No Users with Access</h3>
                            <p style="color: var(--text-muted);">Grant permissions to share this vault with others</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = permissions.map(perm => {
            // Build list of all granted permissions
            const permissionsList = [];
            if (perm.read_permission) permissionsList.push('Read');
            if (perm.write_permission) permissionsList.push('Write');
            if (perm.delete_permission) permissionsList.push('Delete');
            
            // Determine badge style based on highest permission
            let badgeClass = 'permission-read';
            if (perm.delete_permission) badgeClass = 'permission-delete';
            else if (perm.write_permission) badgeClass = 'permission-write';
            
            const permissionsText = permissionsList.join(' + ');
            
            // Format granted date
            const grantedDate = perm.added_at ? formatDateTime(perm.added_at) : 'Unknown';
            
            return `
                <tr>
                    <td>
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <div class="user-avatar">
                                ${escapeHtml(perm.username[0].toUpperCase())}
                            </div>
                            <div style="font-weight: 500;">${escapeHtml(perm.username)}</div>
                        </div>
                    </td>
                    <td>
                        <span style="color: var(--text-muted);">${escapeHtml(perm.email)}</span>
                    </td>
                    <td>
                        <span class="permission-badge ${badgeClass}">
                            ${permissionsText}
                        </span>
                    </td>
                    <td>
                        <span style="color: var(--text-muted); font-size: 14px;">${grantedDate}</span>
                    </td>
                    <td>
                        <div style="display: flex; gap: 8px; justify-content: flex-end;">
                            <button class="btn btn-sm btn-danger revoke-permission-btn" data-user-id="${perm.user_id}" title="Revoke access">
                                <span>🚫</span> Revoke
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
        
        // Attach event listeners to revoke buttons
        document.querySelectorAll('.revoke-permission-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                revokePermission(this.dataset.userId);
            });
        });
        
    } catch (error) {
        console.error('Failed to load permissions:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center" style="padding: 40px; color: var(--error);">
                    Failed to load permissions: ${escapeHtml(error.message)}
                </td>
            </tr>
        `;
    }
}

async function loadUsersForPermission() {
    try {
        const users = await fetchAPI('/users');
        const select = document.getElementById('permission-user');
        
        select.innerHTML = '<option value="">Select a user...</option>';
        users.forEach(user => {
            // Don't show current user or vault owner
            if (user.id !== state.currentVault.owner_id) {
                select.innerHTML += `<option value="${user.id}">${escapeHtml(user.username)} (${escapeHtml(user.email)})</option>`;
            }
        });
    } catch (error) {
        console.error('Failed to load users:', error);
        showError('Failed to load users for permissions');
    }
}

async function handleGrantPermission(e) {
    e.preventDefault();
    
    const userId = document.getElementById('permission-user').value;
    const level = document.getElementById('permission-level').value;
    
    if (!userId) {
        showError('Please select a user');
        return;
    }
    
    try {
        await fetchAPI(`/vaults/${state.currentVault.id}/permissions`, {
            method: 'POST',
            body: JSON.stringify({
                user_id: userId,
                level: level
            })
        });
        
        showSuccess('Permission granted successfully!');
        closeModal('grant-permission-modal');
        document.getElementById('grant-permission-form').reset();
        await loadVaultPermissions();
    } catch (error) {
        console.error('Failed to grant permission:', error);
        showError(error.message || 'Failed to grant permission');
    }
}

async function revokePermission(userId) {
    if (!confirm('Are you sure you want to revoke access for this user?')) {
        return;
    }
    
    try {
        await fetchAPI(`/vaults/${state.currentVault.id}/permissions/${userId}`, {
            method: 'DELETE'
        });
        
        showSuccess('Permission revoked successfully!');
        await loadVaultPermissions();
    } catch (error) {
        console.error('Failed to revoke permission:', error);
        showError(error.message || 'Failed to revoke permission');
    }
}

// Refresh current vault data from API (updates metrics)
async function refreshCurrentVault() {
    if (!state.currentVaultId) return;
    
    try {
        const vault = await fetchAPI(`/vaults/${state.currentVaultId}`);
        state.currentVault = vault;
        console.log('Refreshed vault data:', vault);
    } catch (error) {
        console.error('Failed to refresh vault data:', error);
    }
}

// Info Tab Functions (Read-only vault information for non-owners)
async function loadVaultInfo() {
    try {
        const vault = state.currentVault;
        
        // Basic Information
        document.getElementById('info-vault-name').textContent = vault.name;
        document.getElementById('info-vault-description').textContent = vault.description || 'No description provided';
        
        // Get owner username - use cached data instead of API call to avoid permission issues
        document.getElementById('info-vault-owner').textContent = vault.owner_username || 'Unknown';
        
        const createdDate = new Date(vault.created_at);
        const now = new Date();
        const daysAgo = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
        const createdText = daysAgo === 0 ? 'Today' : 
                           daysAgo === 1 ? 'Yesterday' : 
                           `${daysAgo} days ago`;
        document.getElementById('info-vault-created').textContent = formatDateTime(vault.created_at);
        document.getElementById('info-vault-created-ago').textContent = createdText;
        
        // Storage Information with visual progress bar
        const fileCount = vault.file_count || 0;
        document.getElementById('info-file-count').textContent = fileCount;
        document.getElementById('info-file-count-label').textContent = fileCount === 1 ? 'file' : 'files';
        
        const totalSize = vault.total_size_bytes || 0;
        document.getElementById('info-total-size').textContent = formatFileSize(totalSize);
        
        // Storage bar visualization
        const storageBar = document.getElementById('info-storage-bar');
        const storageBarFill = document.getElementById('info-storage-bar-fill');
        const storageText = document.getElementById('info-storage-text');
        
        if (vault.size_limit && vault.size_limit > 0) {
            const usagePercent = (totalSize / vault.size_limit * 100);
            const displayPercent = Math.min(usagePercent, 100).toFixed(1);
            
            storageBarFill.style.width = `${displayPercent}%`;
            
            // Color coding based on usage
            if (usagePercent >= 90) {
                storageBarFill.style.background = 'linear-gradient(90deg, #ef4444, #dc2626)';
            } else if (usagePercent >= 75) {
                storageBarFill.style.background = 'linear-gradient(90deg, #f59e0b, #d97706)';
            } else {
                storageBarFill.style.background = 'linear-gradient(90deg, #10b981, #059669)';
            }
            
            storageText.textContent = `${formatFileSize(totalSize)} of ${formatFileSize(vault.size_limit)} (${displayPercent}%)`;
            storageBar.style.display = 'block';
        } else {
            storageBar.style.display = 'none';
            storageText.textContent = 'No size limit';
        }
        
        // Security Information with icons
        const passwordEl = document.getElementById('info-has-password');
        if (vault.has_password) {
            passwordEl.innerHTML = '<span class="status-badge status-protected">🔒 Protected</span>';
        } else {
            passwordEl.innerHTML = '<span class="status-badge status-open">🔓 Open Access</span>';
        }
        
        const expirationEl = document.getElementById('info-file-expiration');
        if (vault.expire_files_after_days) {
            const unit = vault.expire_files_unit || 'days';
            expirationEl.innerHTML = `<span class="status-badge status-warning">⏱️ ${vault.expire_files_after_days} ${unit}</span>`;
        } else {
            expirationEl.innerHTML = '<span class="status-badge status-success">♾️ Permanent</span>';
        }
        
        const lastAccessedEl = document.getElementById('info-last-accessed');
        if (vault.last_accessed) {
            const lastDate = new Date(vault.last_accessed);
            const hoursAgo = Math.floor((now - lastDate) / (1000 * 60 * 60));
            const accessText = hoursAgo < 1 ? 'Just now' :
                              hoursAgo < 24 ? `${hoursAgo} hours ago` :
                              `${Math.floor(hoursAgo / 24)} days ago`;
            lastAccessedEl.textContent = formatDateTime(vault.last_accessed);
            document.getElementById('info-last-accessed-ago').textContent = accessText;
        } else {
            lastAccessedEl.textContent = 'Never accessed';
            document.getElementById('info-last-accessed-ago').textContent = '';
        }
        
    } catch (error) {
        console.error('Failed to load vault info:', error);
        showError('Failed to load vault information');
    }
}

// Settings Tab Functions
async function loadVaultSettings() {
    try {
        const vault = state.currentVault;
        
        // Vault Information
        document.getElementById('settings-vault-name').textContent = vault.name;
        document.getElementById('settings-vault-description').textContent = vault.description || 'No description';
        document.getElementById('settings-vault-created').textContent = formatDateTime(vault.created_at);
        
        // Storage Usage
        const currentSize = vault.total_size_bytes || 0;
        const sizeLimit = vault.size_limit || 1073741824; // 1GB default
        const percentage = Math.min((currentSize / sizeLimit) * 100, 100);
        
        document.getElementById('settings-vault-size').textContent = formatBytes(currentSize);
        document.getElementById('settings-vault-limit').textContent = formatBytes(sizeLimit);
        document.getElementById('settings-vault-files').textContent = vault.file_count || 0;
        document.getElementById('storage-bar-fill').style.width = `${percentage}%`;
        document.getElementById('storage-percentage').textContent = percentage.toFixed(1);
        
        // Set size limit input (convert bytes to MB)
        const sizeLimitMB = Math.ceil(sizeLimit / (1024 * 1024));
        document.getElementById('vault-size-limit').value = sizeLimitMB;
        document.getElementById('vault-size-limit').min = Math.ceil(currentSize / (1024 * 1024));
        
        // Security
        document.getElementById('settings-has-password').textContent = vault.has_password ? '🔒 Yes' : '🔓 No';
        
        // Format expiration display
        let expiryText = 'Never';
        if (vault.expire_files_after_days) {
            const unit = vault.expire_files_unit || 'days';
            expiryText = `${vault.expire_files_after_days} ${unit}`;
        }
        document.getElementById('settings-file-expiry').textContent = expiryText;
        
    } catch (error) {
        console.error('Failed to load settings:', error);
        showError('Failed to load vault settings');
    }
}

async function updateVaultSizeLimit() {
    try {
        const newLimitMB = parseInt(document.getElementById('vault-size-limit').value);
        const currentSizeMB = Math.ceil((state.currentVault.total_size_bytes || 0) / (1024 * 1024));
        
        if (isNaN(newLimitMB) || newLimitMB <= 0) {
            showError('Please enter a valid size limit in MB');
            return;
        }
        
        if (newLimitMB < currentSizeMB) {
            showError(`Size limit cannot be less than currently used space (${currentSizeMB} MB)`);
            return;
        }
        
        const newLimitBytes = newLimitMB * 1024 * 1024;
        
        showInfo('Updating size limit...');
        
        const response = await fetch(`${API_BASE}/vaults/${state.currentVault.id}/settings`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`
            },
            body: JSON.stringify({ size_limit: newLimitBytes })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to update size limit');
        }
        
        // Update local state
        state.currentVault.size_limit = newLimitBytes;
        
        showSuccess('Size limit updated successfully!');
        
        // Refresh settings display
        await loadVaultSettings();
        
    } catch (error) {
        console.error('Failed to update size limit:', error);
        showError(error.message || 'Failed to update size limit');
    }
}

async function handleChangeVaultPassword(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('current-vault-password').value;
    const newPassword = document.getElementById('new-vault-password').value;
    const confirmPassword = document.getElementById('confirm-new-vault-password').value;
    
    try {
        // Validate passwords match
        if (newPassword !== confirmPassword) {
            showError('New passwords do not match');
            return;
        }
        
        showInfo('Changing vault password...');
        
        const payload = {
            current_password: currentPassword || null,
            new_password: newPassword || null
        };
        
        const response = await fetch(`${API_BASE}/vaults/${state.currentVault.id}/password`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to change password');
        }
        
        // Update local state
        state.currentVault.has_password = !!newPassword;
        if (newPassword) {
            state.vaultPassword = newPassword;
        } else {
            state.vaultPassword = null;
        }
        
        showSuccess('Vault password changed successfully!');
        
        closeModal('change-vault-password-modal');
        document.getElementById('change-vault-password-form').reset();
        
        // Refresh settings display
        await loadVaultSettings();
        
    } catch (error) {
        console.error('Failed to change password:', error);
        showError(error.message || 'Failed to change vault password');
    }
}

async function handleSetExpiry(e) {
    e.preventDefault();
    
    const expireValue = parseInt(document.getElementById('expire-files-value').value) || 0;
    const expireUnit = document.getElementById('expire-files-unit').value;
    
    try {
        showInfo('Updating file expiration...');
        
        const response = await fetch(`${API_BASE}/vaults/${state.currentVault.id}/settings`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`
            },
            body: JSON.stringify({ 
                expire_files_after_days: expireValue > 0 ? expireValue : null,
                expire_files_unit: expireValue > 0 ? expireUnit : 'days'
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Failed to set expiration');
        }
        
        // Update local state
        state.currentVault.expire_files_after_days = expireValue > 0 ? expireValue : null;
        state.currentVault.expire_files_unit = expireValue > 0 ? expireUnit : 'days';
        
        showSuccess(expireValue > 0 
            ? `Files will expire after ${expireValue} ${expireUnit}` 
            : 'File expiration disabled');
        
        closeModal('set-expiry-modal');
        
        // Refresh settings display
        await loadVaultSettings();
        
    } catch (error) {
        console.error('Failed to set expiration:', error);
        showError(error.message || 'Failed to set file expiration');
    }
}

async function handleEditVaultInfo(e) {
    e.preventDefault();
    
    const name = document.getElementById('edit-vault-name').value.trim();
    const description = document.getElementById('edit-vault-description').value.trim();
    
    try {
        // Validate
        if (!name) {
            showError('Vault name cannot be empty');
            return;
        }
        
        showInfo('Updating vault information...');
        
        const response = await fetch(`${API_BASE}/vaults/${state.currentVault.id}`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${state.token}`
            },
            body: JSON.stringify({
                name: name,
                description: description || null
            })
        });
        
        if (!response.ok) {
            let errorMessage = 'Failed to update vault';
            try {
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    const errorData = await response.json();
                    errorMessage = errorData.detail || errorMessage;
                } else {
                    const errorText = await response.text();
                    errorMessage = errorText || errorMessage;
                }
            } catch (e) {
                console.error('Error parsing error response:', e);
            }
            throw new Error(errorMessage);
        }
        
        const updatedVault = await response.json();
        
        // Update local state
        state.currentVault.name = updatedVault.name;
        state.currentVault.description = updatedVault.description;
        state.currentVault.updated_at = updatedVault.updated_at;
        
        // Update UI - vault header
        document.getElementById('vault-view-title').textContent = updatedVault.name;
        document.getElementById('vault-view-description').textContent = updatedVault.description || 'No description';
        
        // Also update the vault card in the vaults list if visible
        const vaultCard = document.querySelector(`[data-vault-id="${state.currentVault.id}"]`);
        if (vaultCard) {
            const nameEl = vaultCard.querySelector('.vault-name');
            const descEl = vaultCard.querySelector('.vault-description');
            if (nameEl) nameEl.textContent = updatedVault.name;
            if (descEl) descEl.textContent = updatedVault.description || 'No description';
        }
        
        showSuccess('Vault information updated successfully!');
        
        closeModal('edit-vault-info-modal');
        await loadVaultSettings();
    } catch (error) {
        console.error('Failed to update vault info:', error);
        showError(error.message || 'Failed to update vault information');
    }
}

// File Operation Functions
async function handleFileUpload(e) {
    e.preventDefault();
    
    const fileInput = document.getElementById('file-input');
    const files = fileInput.files;
    
    if (files.length === 0) {
        showError('Please select at least one file');
        return;
    }
    
    // Calculate total size
    let totalSize = 0;
    for (let file of files) {
        totalSize += file.size;
    }
    
    try {
        const formData = new FormData();
        for (let file of files) {
            formData.append('files', file);
        }
        
        // Build URL
        let url = `/vaults/${state.currentVault.id}/files`;
        const params = new URLSearchParams();
        if (state.currentFolderId) {
            params.append('folder_id', state.currentFolderId);
        }
        if (params.toString()) {
            url += '?' + params.toString();
        }
        
        // Build headers (vault password in header, NOT URL for security)
        const uploadHeaders = {
            'Authorization': `Bearer ${state.token}`
        };
        if (state.currentVault.has_password && state.vaultPassword) {
            uploadHeaders['X-Vault-Password'] = state.vaultPassword;
        }
        
        // Show progress UI immediately
        const progressDiv = document.getElementById('upload-progress');
        const progressFill = document.getElementById('upload-progress-fill');
        const progressText = document.getElementById('upload-progress-text');
        progressDiv.style.display = 'block';
        progressFill.style.width = '100%'; // Full width for indeterminate progress
        progressFill.classList.add('indeterminate'); // Add animation class
        progressText.textContent = 'Connecting to server...';
        
        // Track current upload operation ID for progress updates
        let currentUploadOpId = null;
        
        // Listen for WebSocket progress events
        const progressListener = (event) => {
            if (event.detail && event.detail.event) {
                const evt = event.detail.event;
                // Check if this is our upload operation
                if (evt.operation_id && evt.operation_id === currentUploadOpId) {
                    if (evt.bytes_uploaded !== undefined) {
                        const mb = (evt.bytes_uploaded / (1024 * 1024)).toFixed(1);
                        progressText.textContent = `Uploading: ${mb} MB processed by server...`;
                    }
                    if (evt.completed) {
                        progressText.textContent = 'Upload completed! Finalizing...';
                    }
                }
            }
        };
        
        // Add event listener for WebSocket messages
        window.addEventListener('live-monitor-event', progressListener);
        
        // Note: Browser upload progress is misleading - it shows 100% when data is sent to server,
        // but server processes the file in chunks afterward. We rely on WebSocket events for real progress.
        
        // Disable form inputs during upload
        fileInput.disabled = true;
        const submitBtn = e.target.querySelector('button[type="submit"]');
        if (submitBtn) submitBtn.disabled = true;
        
        // Use XMLHttpRequest for upload
        await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            
            // Note: xhr.upload.onprogress removed - it's misleading
            // It shows 100% when browser finishes sending data, but server
            // hasn't started processing yet. Real progress comes from WebSocket events.
            
            xhr.upload.onloadstart = () => {
                console.log('Upload started - sending data to server');
                progressText.textContent = 'Sending file to server...';
                // Get operation ID from first WebSocket event (will be set by listener)
            };
            
            xhr.onload = async () => {
                // Cleanup WebSocket listener
                window.removeEventListener('live-monitor-event', progressListener);
                if (xhr.status >= 200 && xhr.status < 300) {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        console.log('Upload completed:', response);
                        progressText.textContent = 'Upload completed! Refreshing files...';
                        
                        // Wait a moment to show completion, then reload files before closing
                        setTimeout(async () => {
                            try {
                                // Reload files first
                                await refreshCurrentVault(); // Update vault metrics
                                await loadVaultFiles();
                                
                                // Then close modal and cleanup
                                showSuccess(response.message || 'Files uploaded successfully');
                                closeModal('upload-file-modal');
                                document.getElementById('upload-file-form').reset();
                                progressDiv.style.display = 'none';
                                fileInput.disabled = false;
                                if (submitBtn) submitBtn.disabled = false;
                                resolve(response);
                            } catch (reloadErr) {
                                console.error('Error reloading files:', reloadErr);
                                // Still close modal even if reload fails
                                showSuccess(response.message || 'Files uploaded successfully');
                                closeModal('upload-file-modal');
                                document.getElementById('upload-file-form').reset();
                                progressDiv.style.display = 'none';
                                fileInput.disabled = false;
                                if (submitBtn) submitBtn.disabled = false;
                                resolve(response);
                            }
                        }, 300);
                    } catch (err) {
                        console.error('Error parsing response:', err);
                        reject(new Error('Invalid server response'));
                    }
                } else {
                    try {
                        const error = JSON.parse(xhr.responseText);
                        reject(new Error(error.detail || xhr.statusText));
                    } catch {
                        reject(new Error(xhr.statusText || 'Upload failed'));
                    }
                }
            };
            
            xhr.onerror = () => {
                console.error('Upload error');
                window.removeEventListener('live-monitor-event', progressListener);
                reject(new Error('Network error during upload'));
            };
            
            xhr.onabort = () => {
                console.log('Upload aborted');
                window.removeEventListener('live-monitor-event', progressListener);
                reject(new Error('Upload was cancelled'));
            };
            
            // Set up and send request
            xhr.open('POST', url);
            for (const [key, value] of Object.entries(uploadHeaders)) {
                xhr.setRequestHeader(key, value);
            }
            
            console.log(`Starting upload: ${files.length} file(s), total size: ${formatBytes(totalSize)}`);
            
            // Extract operation ID from URL or generate it
            // Server will assign operation_id and broadcast it
            // We'll capture it from the first WebSocket event
            const originalListener = progressListener;
            const opIdCapture = (event) => {
                if (event.detail && event.detail.event && event.detail.event.operation_id) {
                    currentUploadOpId = event.detail.event.operation_id;
                    console.log('Captured upload operation ID:', currentUploadOpId);
                }
            };
            window.addEventListener('live-monitor-event', opIdCapture);
            
            xhr.send(formData);
        });
        
    } catch (error) {
        console.error('Failed to upload file:', error);
        showError(error.message || 'Failed to upload file');
        
        // Re-enable form
        const progressDiv = document.getElementById('upload-progress');
        progressDiv.style.display = 'none';
        fileInput.disabled = false;
        const submitBtn = document.querySelector('#upload-file-form button[type="submit"]');
        if (submitBtn) submitBtn.disabled = false;
    }
}

async function handleCreateFolder(e) {
    e.preventDefault();
    
    const folderName = document.getElementById('folder-name').value;
    
    if (!folderName || !folderName.trim()) {
        showError('Please enter a folder name');
        return;
    }
    
    try {
        const url = `/vaults/${state.currentVault.id}/folders`;
        
        const data = {
            name: folderName.trim(),
            parent_folder_id: state.currentFolderId || null
        };
        
        // Build headers with vault password (NOT in URL for security)
        const headers = { 'Content-Type': 'application/json' };
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        
        const response = await fetchAPI(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(data)
        });
        
        showSuccess(response.message || 'Folder created successfully');
        closeModal('create-folder-modal');
        document.getElementById('create-folder-form').reset();
        await loadVaultFiles();
        
    } catch (error) {
        console.error('Failed to create folder:', error);
        showError(error.message || 'Failed to create folder');
    }
}

// Download file
async function downloadFile(fileId, fileName) {
    try {
        const url = `/vaults/${state.currentVault.id}/files/${fileId}/download`;
        
        // Build headers securely
        const headers = { 'Authorization': `Bearer ${state.token}` };
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        
        console.log('Starting download:', fileName);
        showInfo(`Downloading ${fileName}...`);
        
        // Fetch with proper headers
        const response = await fetch(`${API_BASE}${url}`, { headers });
        
        console.log('Download response status:', response.status);
        console.log('Response headers:', {
            contentType: response.headers.get('content-type'),
            contentLength: response.headers.get('content-length'),
            contentDisposition: response.headers.get('content-disposition')
        });
        
        if (!response.ok) {
            let errorText;
            try {
                const errorData = await response.json();
                errorText = errorData.detail || 'Download failed';
            } catch {
                errorText = await response.text() || 'Download failed';
            }
            throw new Error(errorText);
        }
        
        // Get blob and trigger download
        console.log('Converting response to blob...');
        const blob = await response.blob();
        console.log('Blob size:', blob.size, 'type:', blob.type);
        
        if (blob.size === 0) {
            throw new Error('Downloaded file is empty');
        }
        
        // Create download URL and trigger click
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = fileName;
        a.style.display = 'none';
        document.body.appendChild(a);
        
        console.log('Triggering download click...');
        // Force click
        a.click();
        
        // Cleanup after download starts
        setTimeout(() => {
            URL.revokeObjectURL(downloadUrl);
            if (document.body.contains(a)) {
                document.body.removeChild(a);
            }
        }, 1000);
        
        showSuccess(`Downloaded ${fileName}`);
        
    } catch (error) {
        console.error('Failed to download file:', error);
        showError(error.message || 'Failed to download file');
    }
}

// Delete file
async function deleteFile(fileId, fileName) {
    const confirmed = confirm(`Are you sure you want to delete "${fileName}"?`);
    if (!confirmed) return;
    
    try {
        const url = `/vaults/${state.currentVault.id}/files/${fileId}/delete`;
        
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        
        const response = await fetchAPI(url, { method: 'POST', headers });
        
        showSuccess(response.message || 'File deleted successfully');
        await refreshCurrentVault(); // Update vault metrics
        await loadVaultFiles();
        
    } catch (error) {
        console.error('Failed to delete file:', error);
        showError(error.message || 'Failed to download file');
    }
}

// Rename File/Folder Functions
function showRenameModal(fileId, currentName) {
    // Set the file ID and current name
    document.getElementById('rename-item-id').value = fileId;
    document.getElementById('new-item-name').value = currentName;
    
    // Open modal
    openModal('rename-item-modal');
    
    // Focus and select text for easy editing
    setTimeout(() => {
        const input = document.getElementById('new-item-name');
        input.focus();
        input.select();
    }, 100);
}

async function deleteFile(fileId, fileName) {
    if (!confirm(`Are you sure you want to delete "${fileName}"?`)) {
        return;
    }
    
    try {
        const url = `/vaults/${state.currentVault.id}/files/${fileId}/delete`;
        
        // Build headers with vault password (NOT in URL for security)
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        
        const response = await fetchAPI(url, { method: 'POST', headers });
        
        showSuccess(response.message || 'File deleted successfully');
        await refreshCurrentVault(); // Update vault metrics
        await loadVaultFiles();
        
    } catch (error) {
        console.error('Failed to delete file:', error);
        showError(error.message || 'Failed to download file');
    }
}

async function handleRenameItem(e) {
    e.preventDefault();
    
    const newName = document.getElementById('new-item-name').value.trim();
    const fileId = document.getElementById('rename-item-id').value;
    
    if (!newName) {
        showError('Name cannot be empty');
        return;
    }
    
    // Client-side validation for invalid characters
    const invalidChars = ['/', '\\', '\0', '<', '>', ':', '"', '|', '?', '*'];
    for (const char of invalidChars) {
        if (newName.includes(char)) {
            showError(`Name cannot contain: ${invalidChars.join(' ')}`);
            return;
        }
    }
    
    try {
        const url = `/vaults/${state.currentVault.id}/files/${fileId}/rename`;
        
        const headers = {
            'Content-Type': 'application/json'
        };
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        
        const response = await fetchAPI(url, {
            method: 'PUT',
            headers,
            body: JSON.stringify({ new_name: newName })
        });
        
        closeModal('rename-item-modal');
        document.getElementById('rename-item-form').reset();
        showSuccess(response.message || 'Renamed successfully');
        await loadVaultFiles();
        
    } catch (error) {
        console.error('Failed to rename item:', error);
        
        // If file not found (404), it means the file list is stale - refresh it
        if (error.message && error.message.includes('not found')) {
            closeModal('rename-item-modal');
            document.getElementById('rename-item-form').reset();
            showError('This item no longer exists. Refreshing file list...');
            await loadVaultFiles();
        } else {
            showError(error.message || 'Failed to rename item');
        }
    }
}

function setupFileDragDrop() {
    const dropZone = document.getElementById('drop-zone');
    const filesTab = document.getElementById('files-tab');
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        filesTab.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        filesTab.addEventListener(eventName, () => {
            dropZone.style.display = 'flex';
            dropZone.classList.add('drag-over');
        }, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        filesTab.addEventListener(eventName, () => {
            dropZone.style.display = 'none';
            dropZone.classList.remove('drag-over');
        }, false);
    });
    
    filesTab.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            // Set files to file input and trigger upload
            document.getElementById('file-input').files = files;
            openModal('upload-file-modal');
        }
    }, false);
}



// Vault Password Modal Functions
function showVaultPasswordModal(vaultName, action = 'access') {
    return new Promise((resolve, reject) => {
        const modal = document.getElementById('vault-password-modal');
        const form = document.getElementById('vault-password-form');
        const input = document.getElementById('vault-password-input');
        const error = document.getElementById('vault-password-error');
        const cancelBtn = document.getElementById('vault-password-cancel-btn');
        const submitBtn = document.getElementById('vault-password-submit-btn');
        const submitText = document.getElementById('vault-password-submit-text');
        
        // Set modal content based on action
        const title = document.getElementById('vault-password-modal-title');
        const message = document.getElementById('vault-password-modal-message');
        
        if (action === 'access') {
            title.textContent = '🔒 Enter Password for "' + vaultName + '"';
            message.textContent = 'This vault is password-protected. Please enter the password to access its contents.';
            submitText.textContent = 'Unlock';
        } else if (action === 'delete') {
            title.textContent = '⚠️ Confirm Deletion of "' + vaultName + '"';
            message.textContent = 'This vault is password-protected. Enter the password to confirm deletion.';
            submitText.textContent = 'Delete Vault';
            submitBtn.classList.add('btn-danger');
            submitBtn.classList.remove('btn-primary');
        }
        
        // Reset form
        form.reset();
        error.style.display = 'none';
        input.disabled = false;
        submitBtn.disabled = false;
        
        // Show modal (use flex display for proper centering)
        modal.style.display = 'flex';
        setTimeout(() => modal.classList.add('active'), 10);
        input.focus();
        
        // Handle form submission
        const handleSubmit = async (e) => {
            e.preventDefault();
            const password = input.value;
            
            if (!password) {
                error.textContent = 'Please enter a password';
                error.style.display = 'block';
                return;
            }
            
            // Disable form during verification
            input.disabled = true;
            submitBtn.disabled = true;
            submitText.textContent = 'Verifying...';
            
            // Return password (caller will verify it)
            cleanup();
            resolve(password);
        };
        
        // Handle cancel
        const handleCancel = () => {
            cleanup();
            reject(new Error('Password entry cancelled'));
        };
        
        // Cleanup function
        const cleanup = () => {
            form.removeEventListener('submit', handleSubmit);
            cancelBtn.removeEventListener('click', handleCancel);
            modal.classList.remove('active');
            setTimeout(() => {
                modal.style.display = 'none';
                submitBtn.classList.remove('btn-danger');
                submitBtn.classList.add('btn-primary');
            }, 300);
        };
        
        // Add event listeners
        form.addEventListener('submit', handleSubmit);
        cancelBtn.addEventListener('click', handleCancel);
        
        // Close on backdrop click
        modal.querySelector('.modal-backdrop')?.addEventListener('click', handleCancel, { once: true });
    });
}
