// ============================================================================
// SESSION MANAGEMENT & STATE
// ============================================================================

// Session management with localStorage (with sessionStorage fallback for private mode)
let authToken = null;
let currentUser = null;
let userPermissions = [];
// Nav allowlist for a SCOPED temporary credential (from GET /auth/session).
// null / non-scoped => normal role+permission nav (see applyScopedNavLock).
let sessionAccess = null;
// Known from the login response / stored session: is this a SCOPED temporary
// credential? Lets the nav fail CLOSED (hide admin sections) BEFORE the
// /auth/session probe resolves, and even if that probe fails. A legacy scope-less
// temp cred is intentionally unrestricted, so this stays false for it.
let isScopedTemp = false;

// Storage helper functions (with private mode fallback)
const storage = {
    getItem(key) {
        return localStorage.getItem(key) || sessionStorage.getItem(key);
    },
    setItem(key, value) {
        try {
            localStorage.setItem(key, value);
        } catch (e) {
            // Private mode fallback
            sessionStorage.setItem(key, value);
        }
    },
    removeItem(key) {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
    }
};

// Initialize from storage
authToken = storage.getItem('authToken');
try {
    const storedUser = storage.getItem('currentUser');
    if (storedUser) {
        currentUser = JSON.parse(storedUser);
    }
    const storedPerms = storage.getItem('userPermissions');
    if (storedPerms) {
        userPermissions = JSON.parse(storedPerms);
    }
    isScopedTemp = storage.getItem('isScopedTemp') === '1';
} catch (e) {
    console.error('Failed to parse stored data:', e);
    storage.removeItem('currentUser');
    storage.removeItem('userPermissions');
}

// API Base URL
const API_BASE = window.location.origin;

// Global state for vault management
const state = {
    currentVault: null,
    currentVaultId: null,
    currentFolderId: null,
    currentPath: [],
    vaultPassword: null,
    vaultPasswordTimestamp: null,
    token: authToken,
    
    // Vault password with 15-minute expiry
    get isVaultPasswordValid() {
        if (!this.vaultPassword || !this.vaultPasswordTimestamp) return false;
        const now = Date.now();
        const fifteenMinutes = 15 * 60 * 1000;
        return (now - this.vaultPasswordTimestamp) <= fifteenMinutes;
    },
    
    setVaultPassword(password) {
        this.vaultPassword = password;
        this.vaultPasswordTimestamp = password ? Date.now() : null;
    },

    clearVaultPassword() {
        this.vaultPassword = null;
        this.vaultPasswordTimestamp = null;
    },

    // Per-vault remembered passwords so re-opening a vault within its configured
    // window doesn't re-prompt. Persisted to sessionStorage ONLY (per-tab, gone
    // when the tab closes) and only for the unlock window, so a refresh keeps you
    // in the vault. The password never leaves the browser / never hits the server.
    rememberedVaults: {},
    rememberVaultPassword(vaultId, password, minutes) {
        const mins = (typeof minutes === 'number' && minutes >= 0) ? minutes : 15;
        if (mins === 0) { delete this.rememberedVaults[vaultId]; this._persistRemembered(); return; } // 0 = always ask
        this.rememberedVaults[vaultId] = { password, expiresAt: Date.now() + mins * 60 * 1000 };
        this._persistRemembered();
    },
    getRememberedVaultPassword(vaultId) {
        const r = this.rememberedVaults[vaultId];
        if (r && Date.now() < r.expiresAt) return r.password;
        if (r) { delete this.rememberedVaults[vaultId]; this._persistRemembered(); }
        return null;
    },
    forgetVaultPassword(vaultId) {
        delete this.rememberedVaults[vaultId];
        this._persistRemembered();
    },
    _persistRemembered() {
        try { sessionStorage.setItem('dv_remembered', JSON.stringify(this.rememberedVaults)); } catch (_) {}
    },
    _loadRemembered() {
        try {
            const obj = JSON.parse(sessionStorage.getItem('dv_remembered') || 'null');
            if (!obj) return;
            const now = Date.now();
            this.rememberedVaults = {};
            for (const k in obj) { if (obj[k] && obj[k].expiresAt > now) this.rememberedVaults[k] = obj[k]; }
            this._persistRemembered();  // re-write without the expired entries
        } catch (_) {}
    },

    // Background poll that kicks the user out if their access is revoked.
    accessCheckInterval: null,
    // Background poll that refreshes the file list when other users make changes.
    fileWatchInterval: null,
    lastFilesSignature: null,
    // Caller's write capability for the currently-open vault (drives UI hiding).
    canWriteCurrentVault: true,
    // A scoped temp credential's effective caps on the currently-open vault (Set),
    // or null when the session is not a scoped temp cred (=> no extra button gating).
    tempVaultCaps: null,
    // Vaults-list view filter: 'all' | 'favorites'
    vaultFilter: 'all'
};

state._loadRemembered();

// ============================================================================
// PERMISSION SYSTEM
// ============================================================================

// Permission checking helper
function hasPermission(groupName) {
    // Admin has all permissions
    if (currentUser && currentUser.role === 'admin') {
        return true;
    }
    // Check if user has the permission group
    return userPermissions.includes(groupName);
}

// Check multiple permissions (user needs at least one)
function hasAnyPermission(...groupNames) {
    if (currentUser && currentUser.role === 'admin') {
        return true;
    }
    return groupNames.some(name => userPermissions.includes(name));
}

// Load user permissions from API
async function loadUserPermissions() {
    if (!currentUser || !currentUser.id) {
        console.warn('No user ID, skipping permission load');
        userPermissions = [];
        return;
    }
    
    try {
        console.log('Loading permissions for user:', currentUser.id);
        const response = await fetch(`${API_BASE}/permissions/users/${currentUser.id}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        if (!response.ok) {
            console.warn('Failed to load permissions:', response.status);
            userPermissions = [];
            return;
        }
        
        const data = await response.json();
        userPermissions = data.granted_groups || [];
        storage.setItem('userPermissions', JSON.stringify(userPermissions));
        console.log('✅ Loaded user permissions:', userPermissions);
        
        // Update UI based on permissions
        updateUIForPermissions();
    } catch (error) {
        console.error('Error loading permissions:', error);
        userPermissions = [];
    }
}

// Update UI elements based on user permissions
function updateUIForPermissions() {
    console.log('Updating UI for permissions...');
    updateNavigationPermissions();
    updateActionButtonPermissions();
    // A temporary credential can NEVER reach the admin surfaces — hide them as
    // soon as we know the session is temp (before/without the /auth/session probe),
    // so a slow or failed probe can't leave admin nav painted (fail-closed + no flash).
    hideAdminNavForTempSession();
    // Re-assert the precise scoped allowlist LAST (no-op until the probe resolves),
    // so it overrides any role/permission nav that showed a forbidden section.
    applyScopedNavLock();
}

// Sidebar sections a SCOPED temp credential can never access (temp_scope maps
// these endpoint groups to '__deny__'). Hidden the moment we know it's a scoped
// temp session, so a slow/failed /auth/session probe can't leave them painted.
const TEMP_FORBIDDEN_SECTIONS = ['users', 'groups', 'settings', 'monitor', 'roles'];
function hideAdminNavForTempSession() {
    if (!isScopedTemp) return;
    TEMP_FORBIDDEN_SECTIONS.forEach(sec => {
        const el = document.querySelector(`.sidebar-item[data-section="${sec}"]`);
        if (el) el.style.display = 'none';
    });
    reconcileNavGroupLabels();
}

// The v2 (Console) skin injects presentational rail group labels (Overview / Storage / Access /
// System) unconditionally, assuming each group leads with an always-visible item. That holds for a
// full admin, but a scoped temp credential (or a regular non-admin) hides whole groups of items,
// leaving a label stranded over an empty run. Hide a label when every sidebar-item until the next
// label is hidden. No-op on the v1 skin (no labels) and for an admin (every group keeps an item).
function reconcileNavGroupLabels() {
    const nav = document.querySelector('.sidebar-nav');
    if (!nav) return;
    nav.querySelectorAll('.nav-group-label').forEach(label => {
        let visible = false;
        let sib = label.nextElementSibling;
        while (sib && !sib.classList.contains('nav-group-label')) {
            if (sib.classList.contains('sidebar-item') && getComputedStyle(sib).display !== 'none') {
                visible = true;
                break;
            }
            sib = sib.nextElementSibling;
        }
        label.style.display = visible ? '' : 'none';
    });
}

// Fetch which nav sections the CURRENT session may see. Only a SCOPED temporary
// credential is restricted; the backend returns accessible_sections=null for
// regular users / admins / legacy temp creds (they keep normal nav).
async function loadSessionAccess() {
    if (!authToken) return;
    try {
        const r = await fetch(`${API_BASE}/auth/session`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (!r.ok) throw new Error(`session probe ${r.status}`);
        sessionAccess = await r.json();
    } catch (e) {
        // Fail CLOSED: if we couldn't fetch the precise allowlist but we KNOW this
        // is a temp session, still hide the admin surfaces it can never have, and
        // re-gate the action buttons (which now default to hidden without caps).
        console.warn('Failed to load session access:', e);
        hideAdminNavForTempSession();
        updateActionButtonPermissions();
        return;
    }
    applyScopedNavLock();
    // Now that the credential's caps are known, re-gate the action buttons (the
    // earlier pass in updateUIForPermissions ran before this fetch resolved).
    updateActionButtonPermissions();
    // On session restore, openVault() may have already run with an empty (fail-closed)
    // cap Set because this probe hadn't resolved yet — recompute + re-gate the open
    // vault so its permitted buttons reappear.
    refreshOpenVaultCapGating();
}

// Recompute a scoped temp credential's caps for the CURRENTLY-OPEN vault and re-apply
// the vault-view + file-row gating. No-op for non-scoped sessions or when no vault is
// open. Used after loadSessionAccess resolves (the restore path opens a vault before
// the /auth/session probe lands).
function refreshOpenVaultCapGating() {
    if (!isScopedTemp || !state.currentVaultId || !state.currentVault) return;
    state.tempVaultCaps = tempVaultCaps(state.currentVaultId);
    const v = state.currentVault;
    const isOwner = v.owner_id === currentUser.id;
    applyVaultViewPermissions(isOwner, state.canWriteCurrentVault !== false, state.canManageCurrentVault === true);
    renderVaultFiles();  // re-render rows + bulk bar with the now-known caps
}

// Hide every sidebar section a scoped temp credential's scope does not grant
// (fail-closed), and move off any forbidden section we happen to be on.
function applyScopedNavLock() {
    if (!sessionAccess || !sessionAccess.is_scoped_temp) return;  // normal sessions untouched
    const sections = sessionAccess.accessible_sections || [];
    const allowed = new Set(sections);
    document.querySelectorAll('.sidebar-item[data-section]').forEach(item => {
        item.style.display = allowed.has(item.getAttribute('data-section')) ? 'flex' : 'none';
    });
    reconcileNavGroupLabels();  // drop group headers left over an empty run of hidden items
    // If we're on a section the scope doesn't permit (default dashboard, or a
    // restored view), move to the first allowed one — or show nothing at all if
    // the scope grants no pages.
    const active = document.querySelector('.sidebar-item.active[data-section]');
    const activeSec = active ? active.getAttribute('data-section') : null;
    if (activeSec && allowed.has(activeSec)) return;
    if (sections.length) {
        const el = document.querySelector(`.sidebar-item[data-section="${sections[0]}"]`);
        if (el) el.click();
    } else {
        document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    }
}

// The effective capabilities a SCOPED temp credential holds on a specific vault:
// its per-vault caps (mode 'selected') or the default caps (mode 'all'), UNIONED
// with the global caps — exactly what require_cap() checks server-side. Returns
// null for any non-scoped session (=> no extra gating), or an empty Set when it IS
// a scoped session but the scope hasn't loaded yet (=> fail closed).
function tempVaultCaps(vaultId) {
    if (!isScopedTemp) return null;
    if (!sessionAccess) return new Set();  // scoped but /auth/session not resolved -> deny
    const caps = new Set(sessionAccess.caps || []);  // global caps apply to every vault
    const perVault = sessionAccess.vault_access_mode === 'all'
        ? (sessionAccess.vault_caps_default || [])
        : ((sessionAccess.vault_caps || {})[vaultId] || []);
    perVault.forEach(c => caps.add(c));
    return caps;
}

// True if the current open vault's scope permits `cap` (or the session is not a
// scoped temp credential, in which case the vault-role gating alone applies).
function vaultCapAllowed(cap) {
    const caps = state.tempVaultCaps;   // set by openVault(); null when not scope-limited
    return !caps || caps.has(cap);
}

// The two BULK file actions (select checkboxes + the bulk bar) must be cap-gated
// the same way the per-row buttons are, or a scoped cred sees a bulk button that 403s.
function bulkDownloadAllowed() { return vaultCapAllowed('file.download'); }
function bulkDeleteAllowed() { return state.canWriteCurrentVault !== false && vaultCapAllowed('file.delete'); }
// Show file-selection checkboxes only when at least one bulk action is available.
function allowBulkSelect() { return bulkDownloadAllowed() || bulkDeleteAllowed(); }

// Update navigation items based on permissions
function updateNavigationPermissions() {
    const isAdmin = currentUser && currentUser.role === 'admin';
    
    // Users navigation
    const usersNav = document.querySelector('[data-section="users"]');
    if (usersNav) {
        if (isAdmin || hasPermission('USER_VIEW')) {
            usersNav.style.display = 'flex';
        } else {
            usersNav.style.display = 'none';
        }
    }
    
    // Vaults navigation
    const vaultsNav = document.querySelector('[data-section="vaults"]');
    if (vaultsNav) {
        if (isAdmin || hasPermission('VAULT_VIEW')) {
            vaultsNav.style.display = 'flex';
        } else {
            vaultsNav.style.display = 'none';
        }
    }
    
    // Temp Credentials navigation
    const tempCredsNav = document.querySelector('[data-section="temp-creds"]');
    if (tempCredsNav) {
        if (isAdmin || hasPermission('TEMP_CREDS_VIEW')) {
            tempCredsNav.style.display = 'flex';
        } else {
            tempCredsNav.style.display = 'none';
        }
    }
    
    // Live Monitor navigation (admin only)
    const monitorNav = document.querySelector('[data-section="monitor"]');
    if (monitorNav) {
        if (isAdmin) {
            monitorNav.style.display = 'flex';
        } else {
            monitorNav.style.display = 'none';
        }
    }
    
    // Roles navigation (admin only)
    const rolesNav = document.querySelector('[data-section="roles"]');
    if (rolesNav) {
        if (isAdmin) {
            rolesNav.style.display = 'flex';
        } else {
            rolesNav.style.display = 'none';
        }
    }
    reconcileNavGroupLabels();  // hide any group header whose whole run of items is now hidden
}

// Update action button visibility/state based on permissions
function updateActionButtonPermissions() {
    // For a SCOPED temp credential these buttons are gated by the credential's
    // effective caps (from /auth/session), NOT the owner's role/permissions — so an
    // admin-owned scoped cred doesn't see actions its scope forbids. Fail closed if
    // the scope hasn't loaded yet. (loadSessionAccess re-runs this once it lands.)
    const scoped = isScopedTemp;
    const scopeCaps = (sessionAccess && sessionAccess.caps) || [];
    const tempPerms = (sessionAccess && sessionAccess.temp_perms) || {};
    const setBtn = (el, ok) => {
        if (!el) return;
        el.style.display = ok ? 'block' : 'none';
        if (ok) el.disabled = false;
    };

    // Create User — an admin surface a temp credential can never hold.
    setBtn(document.getElementById('create-user-btn'),
           !scoped && hasPermission('USER_MANAGE'));

    // Create Vault — the global vault.create cap.
    setBtn(document.getElementById('create-vault-btn'),
           scoped ? scopeCaps.includes('vault.create') : hasPermission('VAULT_CREATE'));

    // Generate Temp Creds — the temp.create sub-permission.
    setBtn(document.getElementById('generate-temp-creds-btn'),
           scoped ? !!tempPerms.create : hasPermission('TEMP_CREDS_MANAGE'));
}

// HTML escaping utility for security
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// Render an inline SVG icon from the #i-* sprite defined in index.html.
// Icons stroke with currentColor; pass extra classes (e.g. 'icon-sm', 'icon-lg').
function iconSvg(name, extraClass = '') {
    const cls = extraClass ? `icon ${extraClass}` : 'icon';
    return `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================

function showToast(message, type = 'info', duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icons = {
        success: '✓',
        error: '✗',
        warning: '⚠',
        info: 'ℹ'
    };
    
    const titles = {
        success: 'Success',
        error: 'Error',
        warning: 'Warning',
        info: 'Information'
    };
    
    toast.innerHTML = `
        <div class="toast-icon">${icons[type]}</div>
        <div class="toast-content">
            <div class="toast-title">${titles[type]}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after duration
    if (duration > 0) {
        setTimeout(() => {
            toast.classList.add('toast-exit');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
    
    return toast;
}

// Shorthand functions
function showSuccess(message) {
    return showToast(message, 'success');
}

function showError(message) {
    return showToast(message, 'error');
}

function showWarning(message) {
    return showToast(message, 'warning');
}

function showInfo(message) {
    return showToast(message, 'info');
}

// ============================================================================
// CONFIRMATION MODAL
// ============================================================================

let confirmModalResolver = null;

function showConfirm(message, title = 'Confirm Action', requireInput = null) {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-modal-title');
        const messageEl = document.getElementById('confirm-modal-message');
        const inputEl = document.getElementById('confirm-modal-input');
        const confirmBtn = document.getElementById('confirm-modal-confirm-btn');
        const cancelBtn = document.getElementById('confirm-modal-cancel-btn');
        const closeBtn = document.getElementById('confirm-modal-close-btn');
        
        if (!modal) {
            resolve(false);
            return;
        }
        
        // Set content
        titleEl.textContent = title;
        messageEl.textContent = message;
        
        // Show/hide input
        if (requireInput) {
            inputEl.style.display = 'block';
            inputEl.placeholder = `Type "${requireInput}" to confirm`;
            inputEl.value = '';
            confirmBtn.disabled = true;
            
            // Enable confirm button when input matches
            const inputHandler = () => {
                confirmBtn.disabled = inputEl.value !== requireInput;
            };
            inputEl.addEventListener('input', inputHandler);
            
            // Store handler for cleanup
            inputEl._handler = inputHandler;
        } else {
            inputEl.style.display = 'none';
            confirmBtn.disabled = false;
        }
        
        // Show modal
        modal.classList.add('active');
        
        // Confirm button handler
        const confirmHandler = () => {
            if (requireInput && inputEl.value !== requireInput) {
                return;
            }
            cleanup();
            resolve(true);
        };
        
        // Cancel handler
        const cancelHandler = () => {
            cleanup();
            resolve(false);
        };
        
        // Cleanup function
        const cleanup = () => {
            modal.classList.remove('active');
            confirmBtn.removeEventListener('click', confirmHandler);
            cancelBtn.removeEventListener('click', cancelHandler);
            closeBtn.removeEventListener('click', cancelHandler);
            if (inputEl._handler) {
                inputEl.removeEventListener('input', inputEl._handler);
                delete inputEl._handler;
            }
            document.removeEventListener('keydown', escHandler);
        };
        
        // Attach handlers
        confirmBtn.addEventListener('click', confirmHandler);
        cancelBtn.addEventListener('click', cancelHandler);
        closeBtn.addEventListener('click', cancelHandler);
        
        // ESC key to cancel
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                cleanup();
                resolve(false);
            }
        };
        document.addEventListener('keydown', escHandler);
    });
}

// Prompt the user for a value (reuses the confirm modal). Resolves to the entered
// string, or null if cancelled. Unlike showConfirm, this RETURNS THE INPUT VALUE.
function showPrompt(message, title = 'Enter value', options = {}) {
    const { password = false, placeholder = '', defaultValue = '' } = options;
    return new Promise((resolve) => {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-modal-title');
        const messageEl = document.getElementById('confirm-modal-message');
        const inputEl = document.getElementById('confirm-modal-input');
        const confirmBtn = document.getElementById('confirm-modal-confirm-btn');
        const cancelBtn = document.getElementById('confirm-modal-cancel-btn');
        const closeBtn = document.getElementById('confirm-modal-close-btn');
        if (!modal) { resolve(null); return; }

        titleEl.textContent = title;
        messageEl.textContent = message;
        inputEl.style.display = 'block';
        inputEl.type = password ? 'password' : 'text';
        inputEl.placeholder = placeholder || '';
        inputEl.value = defaultValue || '';
        confirmBtn.disabled = false;

        modal.classList.add('active');
        setTimeout(() => inputEl.focus(), 50);

        const cleanup = () => {
            modal.classList.remove('active');
            inputEl.type = 'text';
            inputEl.style.display = 'none';
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtn.removeEventListener('click', onCancel);
            closeBtn.removeEventListener('click', onCancel);
            inputEl.removeEventListener('keydown', onKey);
            document.removeEventListener('keydown', onEsc);
            modal.removeEventListener('click', onBackdrop);
        };
        const onConfirm = () => { const v = inputEl.value; cleanup(); resolve(v); };
        const onCancel = () => { cleanup(); resolve(null); };
        const onKey = (e) => { if (e.key === 'Enter') { e.preventDefault(); onConfirm(); } };
        const onEsc = (e) => { if (e.key === 'Escape') onCancel(); };
        // A backdrop click is dismissed by the global modal handler (closeModal),
        // which would otherwise leave THIS promise unresolved forever (hanging any
        // awaiting caller). Treat it as cancel so the promise always settles.
        const onBackdrop = (e) => { if (e.target === modal) onCancel(); };
        confirmBtn.addEventListener('click', onConfirm);
        cancelBtn.addEventListener('click', onCancel);
        closeBtn.addEventListener('click', onCancel);
        inputEl.addEventListener('keydown', onKey);
        document.addEventListener('keydown', onEsc);
        modal.addEventListener('click', onBackdrop);
    });
}

// Loading spinner utility
function showLoading(element, message = 'Loading...') {
    if (!element) return;
    
    const spinner = document.createElement('div');
    spinner.className = 'loading-state';
    spinner.innerHTML = `
        <div class="loading-spinner"></div>
        <p class="text-secondary">${escapeHtml(message)}</p>
    `;
    
    element.innerHTML = '';
    element.appendChild(spinner);
}

// ============================================================================
// API & UTILITY FUNCTIONS
// ============================================================================

// Utility: API Request with auth and enhanced error handling
async function apiRequest(endpoint, options = {}) {
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    // Silent mode suppresses error logging (for optional endpoints)
    const silent = options.silent || false;
    if (options.silent) {
        delete options.silent; // Remove from fetch options
    }
    
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers
        });
        
        if (!silent || response.ok) {
            console.log(`API Request: ${options.method || 'GET'} ${endpoint}`, response.status);
        }
        
        // Parse response body for error details
        let data;
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else if (!response.ok) {
            // Non-JSON error response
            const text = await response.text();
            if (!silent) console.error(`Non-JSON response from ${endpoint}:`, text);
            data = { detail: `Server error: ${response.status} ${response.statusText}` };
        }
        
        // Handle 401 Unauthorized - distinguish between password required vs session expired
        if (response.status === 401) {
            const errorDetail = data?.detail || '';
            
            // Check if it's a password requirement (vault access) vs session expiration
            if (errorDetail.includes('password') || errorDetail.includes('Password')) {
                // Password required for resource - don't log out, just throw error
                console.log('Password required for resource');
                throw new Error(errorDetail);
            } else {
                // Session expired - log out user
                console.error('Session expired, logging out');
                if (!silent) showError('Session expired. Please log in again.');
                logout();
                throw new Error('Session expired. Please log in again.');
            }
        }
        
        // Handle 403 Forbidden - distinguish between inactive account vs permission denied
        if (response.status === 403) {
            const errorDetail = data?.detail || '';
            
            // Check if this is an account issue (inactive/terminated)
            if (errorDetail.includes('inactive') || errorDetail.includes('terminated') || errorDetail.includes('locked')) {
                // Account issue - log out user
                console.error('Account issue, logging out');
                if (!silent) showError(errorDetail);
                logout();
                throw new Error(errorDetail);
            } else {
                // Permission denied - show specific message but don't log out
                if (!silent) {
                    console.warn('Permission denied:', endpoint);
                    showPermissionDenied(errorDetail || 'You do not have permission to perform this action.');
                }
                throw new Error(errorDetail || 'Permission denied');
            }
        }
        
        // Handle 404 Not Found - provide context
        if (response.status === 404) {
            const errorDetail = data?.detail || 'Resource not found';
            
            // Check for specific scenarios
            if (endpoint.includes('/files') && errorDetail.includes('Folder')) {
                // Folder was deleted
                throw new Error('Folder not found - it may have been deleted');
            }
            
            throw new Error(errorDetail);
        }
        
        // Handle 422 Validation Errors - parse field-specific errors
        if (response.status === 422 && data?.detail) {
            if (Array.isArray(data.detail)) {
                // FastAPI validation error format
                if (!silent) {
                    console.error('Validation errors:', JSON.stringify(data.detail, null, 2));
                }
                const errorMsg = data.detail
                    .map(err => {
                        const field = err.loc ? err.loc.join('.') : 'field';
                        return `${field}: ${err.msg}`;
                    })
                    .join(', ');
                throw new Error(errorMsg || 'Validation failed');
            } else {
                // Simple validation error
                throw new Error(data.detail);
            }
        }
        
        // Handle 429 Too Many Requests (Rate Limiting)
        if (response.status === 429) {
            const errorDetail = data?.detail || 'Too many requests. Please try again later.';
            if (!silent) {
                showWarning(errorDetail);
                console.warn('Rate limited:', endpoint);
            }
            throw new Error(errorDetail);
        }
        
        // Handle other errors
        if (!response.ok) {
            const errorMsg = data?.detail || `Request failed with status ${response.status}`;
            if (!silent) {
                console.error(`API Error: ${endpoint}`, data);
            }
            const err = new Error(errorMsg);
            err.status = response.status;  // let callers branch on e.g. 409 conflict
            throw err;
        }
        
        // Handle 204 No Content
        if (response.status === 204) {
            return null;
        }
        
        // Return parsed data (or response for non-JSON like file downloads)
        return data || response;
    } catch (error) {
        if (!silent) {
            console.error('API Error:', error);
        }
        throw error;
    }
}

// Show permission denied message with special styling
function showPermissionDenied(message) {
    showToast(`⛔ ${message}`, 'warning', 8000);
}

// Show/Hide Screens
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

// Update profile UI with user information
function updateProfileUI(user) {
    // Get initials from username
    const initials = user.username.substring(0, 2).toUpperCase();
    
    // Update avatars
    const avatar = document.getElementById('profile-avatar');
    const avatarLarge = document.getElementById('profile-avatar-large');
    if (avatar) avatar.textContent = initials;
    if (avatarLarge) avatarLarge.textContent = initials;
    
    // Update username and role
    const usernameEl = document.getElementById('profile-username');
    const roleEl = document.getElementById('profile-role');
    if (usernameEl) usernameEl.textContent = user.username;
    if (roleEl) {
        const roleMap = {
            'admin': 'Administrator',
            'user': 'User',
            'guest': 'Guest'
        };
        roleEl.textContent = roleMap[user.role] || user.role;
    }
    
    // Show admin tab if admin
    if (user.role === 'admin') {
        // Show admin-only sidebar items
        document.querySelectorAll('.sidebar-item.admin-only').forEach(item => {
            item.style.display = 'flex';
        });
        
        // Legacy tab support (if exists)
        const usersTab = document.getElementById('users-tab');
        if (usersTab) {
            usersTab.style.display = 'block';
        }
        // Revealing the admin-only items may have re-populated a group that was empty when
        // updateNavigationPermissions last reconciled, so reconcile again (a group whose whole run
        // is admin-only would otherwise keep a wrongly-hidden header).
        reconcileNavGroupLabels();
    }

    // If this is a scoped temp credential whose owner is an admin, the block above
    // just revealed admin sidebar items — re-hide them in the SAME synchronous pass
    // (before any repaint) so they never flash on screen.
    hideAdminNavForTempSession();
}

// Login
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('login-error');
    
    // Hide previous errors
    errorDiv.style.display = 'none';
    
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        });
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ detail: 'Invalid credentials' }));
            throw new Error(error.detail || 'Invalid credentials');
        }
        
        const data = await response.json();
        authToken = data.access_token;
        
        // Store token with storage helper (handles private mode)
        storage.setItem('authToken', authToken);
        
        // FIXED: Use user data from login response (login endpoint returns user object)
        currentUser = data.user;

        // Know up-front whether this is a SCOPED temp credential, so the nav can
        // fail closed (hide admin sections) before/without the /auth/session probe.
        isScopedTemp = !!data.is_scoped_temp;
        sessionAccess = null;  // clear any stale allowlist from a prior same-tab session
        storage.setItem('isScopedTemp', isScopedTemp ? '1' : '');

        // Store user data
        storage.setItem('currentUser', JSON.stringify(currentUser));
        
        console.log('Login successful:', currentUser);

        // Load user permissions
        await loadUserPermissions();

        // Apply this account's server-saved UI preferences (theme/accent/skin) so a
        // login on a fresh browser picks up the look they set elsewhere. May reload
        // once if the saved skin differs; if so, stop — the reload restarts the flow.
        let reloadingPrefs = false;
        try { reloadingPrefs = await applyServerPreferences(); } catch (_) {}
        if (reloadingPrefs) return;

        // Update profile UI
        updateProfileUI(currentUser);

        // Restrict the sidebar to the pages a scoped temp credential may use
        // (runs after the role/permission nav so it can override it).
        await loadSessionAccess();

        // Show dashboard
        showScreen('dashboard-screen');

        // Open the live-monitor socket app-wide so this account is notified (on any
        // page) when one of its temporary credentials signs in. The server filters
        // events per connection (admins see all; everyone else only their own).
        try { connectMonitorWebSocket(); } catch (_) {}

        // Load dashboard stats
        loadDashboardStats();

        // Prompt a keyless user who's been invited to a ZK vault to set up a key.
        zkMaybePromptPendingInvites();

    } catch (error) {
        console.error('Login error:', error);
        errorDiv.textContent = error.message;
        errorDiv.style.display = 'block';
    }
});

// Logout
function logout() {
    authToken = null;
    currentUser = null;
    userPermissions = [];
    // Drop the scoped-temp nav state so a prior credential's allowlist can't
    // restrict the NEXT user who logs in on this same tab without a refresh.
    sessionAccess = null;
    isScopedTemp = false;
    zkResetKeys();  // drop the in-memory ECC private key + per-vault DEKs
    // Wipe any saved zero-knowledge upload ciphertext too — on a shared machine it must
    // not outlive the session (it's opaque without the DEK, but matches the scrub above).
    try { zkUploadStore.clear(); } catch (_) {}
    // Re-arm the once-per-session pending-invite prompt so a DIFFERENT keyless user who
    // logs in on this same tab (no page refresh) is still prompted to set up a key.
    _zkInvitePrompted = false;

    // Tear down any open vault session + its watchers.
    if (state.accessCheckInterval) { clearInterval(state.accessCheckInterval); state.accessCheckInterval = null; }
    stopVaultFileWatch();
    state.currentVault = null;
    state.currentVaultId = null;
    state.currentFolderId = null;
    state.currentPath = [];
    state.vaultPassword = null;

    // Drop remembered vault passwords + restored-view so they can't leak to
    // another user who logs in on this same tab without a refresh.
    state.rememberedVaults = {};
    try { sessionStorage.removeItem('dv_remembered'); } catch (_) {}
    try { sessionStorage.removeItem('dv_nav'); } catch (_) {}

    // Clear storage with helper (handles both localStorage and sessionStorage)
    storage.removeItem('authToken');
    storage.removeItem('currentUser');
    storage.removeItem('userPermissions');
    storage.removeItem('isScopedTemp');

    // Clear the pre-paint boot state so the splash-override CSS releases and the
    // login screen shows (matters when logout runs from the boot verify path).
    document.documentElement.removeAttribute('data-auth');
    document.getElementById('login-form').reset();
    showScreen('login-screen');
}

// Load Dashboard Statistics
async function loadDashboardStats() {
    try {
        // Load vaults count (silent: the dashboard polls endpoints a non-admin
        // can't reach — surface nothing, just leave those tiles blank).
        const vaults = await apiRequest('/vaults', { silent: true });
        const vaultsCountEl = document.getElementById('dashboard-vaults-count');
        if (vaultsCountEl) {
            vaultsCountEl.textContent = vaults.length;
        }
        
        // Calculate total storage. The /vaults list exposes per-vault size as
        // total_size_bytes (not total_size) — reading the wrong field showed 0 B.
        let totalStorage = 0;
        vaults.forEach(vault => {
            totalStorage += vault.total_size_bytes || vault.total_size || 0;
        });
        const storageEl = document.getElementById('dashboard-storage');
        if (storageEl) {
            storageEl.textContent = formatBytes(totalStorage);
        }
        
        // Load temp credentials count
        try {
            const tempCreds = await apiRequest('/temp-creds/list', { silent: true });
            const tempCredsCountEl = document.getElementById('dashboard-temp-creds-count');
            if (tempCredsCountEl) {
                const activeCount = tempCreds.filter(c => c.is_active).length;
                tempCredsCountEl.textContent = activeCount;
            }
        } catch (error) {
            console.log('Temp creds endpoint not accessible:', error);
        }
        
        // Load users count — the /users list is admin-only (require_interactive_admin), so a
        // non-admin dashboard shouldn't fire it and eat a 403 (and the browser's console error).
        if (currentUser && currentUser.role === 'admin') {
            try {
                const users = await apiRequest('/users', { silent: true });
                const usersCountEl = document.getElementById('dashboard-users-count');
                if (usersCountEl) {
                    const activeUsers = users.filter(u => u.is_active).length;
                    usersCountEl.textContent = activeUsers;
                }
            } catch (error) {
                console.log('Users endpoint not accessible:', error);
            }
        }

        // Recent events are admin-only — skip (and show a proper message) for non-admins instead
        // of a 403 that renders the misleading "Event logging not configured".
        if (currentUser && currentUser.role === 'admin') {
            try {
                await loadRecentEvents();
            } catch (error) {
                console.log('Events endpoint not available:', error);
            }
        } else {
            const eventsFeed = document.getElementById('events-feed');
            if (eventsFeed) {
                const box = document.createElement('div');
                box.className = 'empty-state text-center p-lg';
                const p = document.createElement('p');
                p.className = 'text-secondary';
                p.textContent = 'Activity log is available to administrators.';
                box.appendChild(p);
                eventsFeed.replaceChildren(box);
            }
        }
        
        // Update system status
        updateSystemStatus();
        
    } catch (error) {
        console.error('Failed to load dashboard stats:', error);
    }
}

// Pick an icon for a dashboard audit event. Audit action strings vary
// ("login_success", "temp_credential_created", …) so match on substrings
// instead of exact equality (which fell through to a single generic icon).
function dashboardEventIcon(event) {
    const a = (event.action || '').toLowerCase();
    if (a.includes('login')) return 'login';
    if (a.includes('logout')) return 'logout';
    if (a.includes('upload')) return 'upload';
    if (a.includes('download')) return 'download';
    if (a.includes('temp') || a.includes('cred')) return 'clock';
    if (a.includes('vault')) return 'vault';
    if (a.includes('folder')) return 'folder';
    if (a.includes('user') || a.includes('member')) return 'user';
    if (a.includes('permission') || a.includes('access') || a.includes('grant')) return 'unlock';
    if (a.includes('delete') || a.includes('remove')) return 'trash';
    if (a.includes('create') || a.includes('add') || a.includes('generat')) return 'plus';
    if (a.includes('rename') || a.includes('edit') || a.includes('updat')) return 'edit';
    if ((event.level || '') === 'error') return 'alert-triangle';
    return 'activity';
}

// Load recent events from audit log
async function loadRecentEvents() {
    try {
        const events = await apiRequest('/audit/events?limit=10', { silent: true });
        const eventsFeed = document.getElementById('events-feed');
        
        if (!eventsFeed) return;
        
        if (!events || events.length === 0) {
            eventsFeed.innerHTML = `
                <div class="empty-state text-center p-lg">
                    <p class="text-secondary">No recent events</p>
                </div>
            `;
            return;
        }
        
        eventsFeed.innerHTML = events.map(event => {
            const eventClass = event.level === 'error' ? 'event-error' : 
                              event.level === 'warning' ? 'event-warning' :
                              event.level === 'success' ? 'event-success' : 'event-info';
            
            const iconName = dashboardEventIcon(event);

            return `
                <div class="event-item ${eventClass}">
                    <div class="event-header">
                        <span class="event-icon">${iconSvg(iconName)}</span>
                        <span class="event-user">${escapeHtml(event.username || 'System')}</span>
                        <span class="event-action">${escapeHtml(event.description || event.action)}</span>
                        <span class="event-time">${formatTimeAgo(event.timestamp)}</span>
                    </div>
                    ${event.details ? `<div class="event-details">${escapeHtml(event.details)}</div>` : ''}
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.log('Failed to load events:', error);
        const eventsFeed = document.getElementById('events-feed');
        if (eventsFeed) {
            const box = document.createElement('div');
            box.className = 'empty-state text-center p-lg';
            const p = document.createElement('p');
            p.className = 'text-secondary';
            p.textContent = "Couldn't load recent events.";
            box.appendChild(p);
            eventsFeed.replaceChildren(box);
        }
    }
}

// Update system status indicators
async function updateSystemStatus() {
    const setBadge = (id, ok, okText, badText, badClass = 'badge-error') => {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = ok ? okText : badText;
        el.className = 'badge ' + (ok ? 'badge-success' : badClass);
    };
    try {
        // Real signal from the API's own health check (DB + cache + overall).
        const health = await apiRequest('/health', { silent: true });
        setBadge('status-db', health.database === 'connected', 'Connected', 'Disconnected');
        setBadge('status-sftp', health.redis === 'connected', 'Connected', 'Disconnected');
        setBadge('status-sessions', health.status === 'healthy', 'Healthy', 'Degraded', 'badge-warning');
    } catch (e) {
        ['status-db', 'status-sftp', 'status-sessions'].forEach(id => {
            const el = document.getElementById(id);
            if (el) { el.textContent = 'Unknown'; el.className = 'badge badge-secondary'; }
        });
    }
}

// Format bytes to human readable
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Format timestamp to relative time
function formatTimeAgo(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
    if (seconds < 604800) return Math.floor(seconds / 86400) + 'd ago';
    return date.toLocaleDateString();
}

// Tab Management
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.getAttribute('data-tab');
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        
        const tabContent = document.getElementById(`${tabName}-tab`) || document.getElementById(`${tabName}-tab-content`);
        if (tabContent) {
            tabContent.classList.add('active');
            
            // Load data for active tab
            if (tabName === 'vaults') loadVaults();
            else if (tabName === 'temp-creds') loadTempCreds();
            else if (tabName === 'users') loadUsers();
        }
    });
});

// Load Vaults
async function loadVaults() {
    const container = document.getElementById('vaults-list');
    container.innerHTML = '<div class="spinner"></div>';

    // Wire the All / Favorites filter (idempotent — onclick is replaced each load).
    const allBtn = document.getElementById('vault-filter-all');
    const favBtn = document.getElementById('vault-filter-fav');
    if (allBtn) allBtn.onclick = () => { state.vaultFilter = 'all'; renderVaults(); };
    if (favBtn) favBtn.onclick = () => { state.vaultFilter = 'favorites'; renderVaults(); };

    try {
        state.allVaults = await apiRequest('/vaults');
        renderVaults();
    } catch (error) {
        container.innerHTML = `<div class="alert alert-error">Failed to load vaults: ${error.message}</div>`;
    }
}

// Apply the persisted vaults view (grid | list) to the list container.
function applyVaultsView() {
    const container = document.getElementById('vaults-list');
    if (!container) return;
    if (!state.vaultsView) {
        try { state.vaultsView = localStorage.getItem('vaultsView') || 'grid'; } catch (_) { state.vaultsView = 'grid'; }
    }
    const isList = state.vaultsView === 'list';
    container.classList.toggle('vaults-as-list', isList);
    document.querySelectorAll('[data-vaults-view]').forEach(b =>
        b.classList.toggle('active', b.getAttribute('data-vaults-view') === (isList ? 'list' : 'grid')));
}

// Wire the vaults grid/list switch exactly once.
function setupVaultsViewControls() {
    if (state._vaultsCtrlWired) return;
    state._vaultsCtrlWired = true;
    document.querySelectorAll('[data-vaults-view]').forEach(btn => {
        btn.addEventListener('click', () => {
            state.vaultsView = btn.getAttribute('data-vaults-view') === 'list' ? 'list' : 'grid';
            try { localStorage.setItem('vaultsView', state.vaultsView); } catch (_) {}
            applyVaultsView();
        });
    });
}

function renderVaults() {
    const container = document.getElementById('vaults-list');
    if (!container) return;
    applyVaultsView();
    setupVaultsViewControls();
    const all = state.allVaults || [];
    const favOnly = state.vaultFilter === 'favorites';
    const vaults = favOnly ? all.filter(v => v.is_favorite) : all;

    const allBtn = document.getElementById('vault-filter-all');
    const favBtn = document.getElementById('vault-filter-fav');
    if (allBtn) allBtn.classList.toggle('active', !favOnly);
    if (favBtn) favBtn.classList.toggle('active', favOnly);

    if (vaults.length === 0) {
        container.innerHTML = `
            <div class="empty-state-center p-xl">
                <div style="font-size: 3rem; margin-bottom: var(--space-md);">${iconSvg(favOnly ? 'star' : 'folder', 'icon-lg')}</div>
                <h3 class="text-xl font-bold mb-xs">${favOnly ? 'No favorite vaults yet' : 'No Vaults Yet'}</h3>
                <p class="text-secondary">${favOnly ? 'Tap the star on a vault to pin it here for quick access.' : 'Create your first vault to start storing files securely'}</p>
            </div>
        `;
        return;
    }

    container.innerHTML = vaults.map(vault => `
        <div class="card card-interactive vault-card" data-vault-id="${vault.id}">
            <button class="vault-fav ${vault.is_favorite ? 'is-fav' : ''}" data-vault-id="${vault.id}"
                    title="${vault.is_favorite ? 'Remove from favorites' : 'Add to favorites'}" aria-label="Toggle favorite">
                ${iconSvg('star')}
            </button>
            ${currentUser.role === 'admin' ? `<button class="delete-vault-btn vault-del" data-vault-id="${vault.id}" title="Delete vault" aria-label="Delete vault">${iconSvg('trash', 'icon-sm')}</button>` : ''}
            <div class="vault-card-body">
                <div class="vault-tile">${iconSvg('vault')}</div>
                <div class="vault-card-main">
                    <h3 class="vault-name">${escapeHtml(vault.name)}</h3>
                    <p class="vault-desc">${escapeHtml(vault.description || 'No description')}</p>
                    <div class="vault-meta">
                        <span>${iconSvg('folder', 'icon-sm')} ${vault.file_count || 0} files</span>
                        <span>${iconSvg('users', 'icon-sm')} ${vault.member_count || 1} members</span>
                    </div>
                </div>
                <button class="open-vault-btn btn btn-primary btn-sm vault-open" data-vault-id="${vault.id}">Open</button>
            </div>
        </div>
    `).join('');

    container.querySelectorAll('.open-vault-btn').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); openVault(e.currentTarget.getAttribute('data-vault-id')); });
    });
    container.querySelectorAll('.delete-vault-btn').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); deleteVault(e.currentTarget.getAttribute('data-vault-id')); });
    });
    container.querySelectorAll('.vault-fav').forEach(btn => {
        btn.addEventListener('click', (e) => { e.stopPropagation(); toggleVaultFavorite(e.currentTarget.getAttribute('data-vault-id')); });
    });
}

// Star / un-star a vault (optimistic; reverts on failure).
async function toggleVaultFavorite(vaultId) {
    const v = (state.allVaults || []).find(x => x.id === vaultId);
    const makeFav = v ? !v.is_favorite : true;
    if (v) v.is_favorite = makeFav;
    renderVaults();
    try {
        await apiRequest(`/vaults/${vaultId}/favorite`, { method: makeFav ? 'PUT' : 'DELETE' });
    } catch (error) {
        if (v) v.is_favorite = !makeFav;
        renderVaults();
        showError('Failed to update favorite: ' + error.message);
    }
}

// The effective vault type the create form will submit. When the type chooser
// is hidden entirely, only standard is creatable; when zero-knowledge is forced
// the chooser is replaced by a static note but the (hidden) select still carries
// the effective 'zero_knowledge' value.
function effectiveVaultType() {
    const grp = document.getElementById('vault-type-group');
    const sel = document.getElementById('vault-type');
    if (!grp || grp.style.display === 'none') return 'standard';
    return (sel && sel.value) || 'standard';
}

// Reflect the chosen vault type into the rest of the create form. The top-level
// "Vault Password" is a web access gate that only applies to STANDARD vaults
// (zero-knowledge vaults are unlocked by the browser passphrase flow in the
// follow-up encryption-key modal), so it — and only it — is hidden for ZK.
// Team mode is a zero-knowledge-only option, so it hides for standard.
function syncCreateVaultForm() {
    const isZk = effectiveVaultType() === 'zero_knowledge';
    const pwGroup = document.getElementById('vault-password-group');
    const pwInput = document.getElementById('vault-password');
    const hierWrap = document.getElementById('vault-hierarchical-wrap');
    if (pwGroup) pwGroup.style.display = isZk ? 'none' : '';
    // Disable the hidden password field: a disabled control is barred from HTML5
    // constraint validation (a too-short value on a display:none, non-focusable input
    // would otherwise silently block "Create Vault") and is never submitted.
    if (pwInput) pwInput.disabled = isZk;
    if (hierWrap) hierWrap.style.display = isZk ? '' : 'none';
}

// Create Vault Modal
async function fetchAccountStorage(excludeVaultId) {
    const qs = excludeVaultId ? `?exclude_vault_id=${encodeURIComponent(excludeVaultId)}` : '';
    try { return await apiRequest('/account/storage' + qs, { silent: true }); }
    catch (_) { return null; }
}
function _bytesToGb(bytes) { return bytes / (1024 ** 3); }
// Fill a "how much you can allocate" note + set the size input's soft max from /account/storage.
// Pass the vault id being edited (else null) so its own reservation is excluded from the headroom.
async function renderVaultSizeAvailability(noteId, inputEl, excludeVaultId, baseText) {
    const note = document.getElementById(noteId);
    if (!note) return;
    const base = baseText || 'The most this vault may hold.';
    const s = await fetchAccountStorage(excludeVaultId);
    if (!s) return;
    if (s.available_bytes == null) {  // unlimited on both axes (or budget-exempt admin)
        note.textContent = s.budget_exempt ? base + ' No account storage limit.' : base;
        if (inputEl) inputEl.removeAttribute('max');
        return;
    }
    const fmt = g => g.toFixed(g < 10 ? 2 : 0);
    const availGb = _bytesToGb(s.available_bytes);
    const usedGb = _bytesToGb(s.reserved_bytes || 0);
    note.textContent = `${base} You can allocate up to ${fmt(availGb)} GB (${fmt(usedGb)} GB reserved on your account).`;
    if (inputEl) inputEl.max = String(Math.max(0.1, availGb));
}

async function showCreateVault() {
    // The zero-knowledge option is only offered when the deployment enables it.
    const grp = document.getElementById('vault-type-group');
    const sel = document.getElementById('vault-type');
    const note = document.getElementById('zk-unavailable-note');
    const choice = document.getElementById('vault-type-choice');
    const forcedNote = document.getElementById('vault-type-forced-note');

    // Reset to the fail-safe default (standard only, real chooser, no notes) so a
    // re-open never inherits a previous session's forced/hidden state.
    if (sel) { sel.disabled = false; sel.value = 'standard'; }
    if (choice) choice.style.display = '';
    if (forcedNote) forcedNote.style.display = 'none';
    if (note) note.style.display = 'none';

    if (grp) {
        try {
            const f = await apiRequest('/zk-enabled', { silent: true });
            const on = !!(f && f.zero_knowledge_enabled);
            const must = !!(f && f.must_use_zk);
            const planHasZk = !!(f && f.plan_zero_knowledge);
            // Honour the operator allowlist: an allowlist present but omitting
            // 'standard' means only zero-knowledge is creatable here (same UI
            // effect as the force policy). An empty/absent list = no restriction.
            const allowed = Array.isArray(f && f.allowed_vault_types) ? f.allowed_vault_types : [];
            const standardBlocked = allowed.length > 0 && !allowed.includes('standard');
            const forceZk = must || (on && standardBlocked);

            if (!on && !must) {
                // Zero-knowledge not offered — standard only. Say WHY (plan vs admin
                // toggle) instead of silently omitting the option (textContent, no HTML).
                grp.style.display = 'none';
                if (note) {
                    note.textContent = planHasZk
                        ? 'Zero-knowledge vaults are turned off for this workspace. An administrator can enable them in Settings.'
                        : 'Zero-knowledge vaults are not available on your current plan.';
                    note.style.display = '';
                }
            } else if (forceZk) {
                // Zero-knowledge is required. Show a clear message rather than a dead,
                // disabled dropdown that just reads "Zero-knowledge" and ignores clicks.
                grp.style.display = '';
                if (sel) sel.value = 'zero_knowledge';
                if (choice) choice.style.display = 'none';
                if (forcedNote) forcedNote.style.display = '';
            } else {
                // Both types creatable — offer the real, enabled choice.
                grp.style.display = '';
                if (sel) sel.value = 'standard';
            }
        } catch (e) {
            console.warn('Could not check zero-knowledge availability:', e);
            grp.style.display = 'none';  // fail safe: standard only if we can't confirm
            if (note) note.style.display = 'none';
            if (sel) sel.value = 'standard';
        }
    }

    // Reset the size to the 1 GB default + surface how much the account can still allocate.
    const sizeInput = document.getElementById('vault-size-gb');
    if (sizeInput) sizeInput.value = '1';
    renderVaultSizeAvailability('vault-size-avail', sizeInput, null,
        'The most this vault may hold. Default 1 GB; changeable later in policies.');

    // Reflect the resolved type into password + team-mode visibility, then show.
    syncCreateVaultForm();
    document.getElementById('create-vault-modal').classList.add('active');
}

document.getElementById('create-vault-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const name = document.getElementById('vault-name').value.trim();
    const description = document.getElementById('vault-desc').value.trim();
    const password = document.getElementById('vault-password').value;
    const vaultType = effectiveVaultType();
    const sizeGb = parseFloat(document.getElementById('vault-size-gb').value);

    try {
        const payload = {
            name,
            description: description || null,
            // The top-level password only applies to standard vaults; never send a
            // stale value for a zero-knowledge vault (its field is hidden).
            password: (vaultType === 'standard' ? (password || null) : null),
            expire_files_after_days: null,
            // Per-vault maximum size; default 1 GB. The server bounds it by the account budget
            // and the per-vault ceiling and 400s if over.
            size_limit_gb: (sizeGb && sizeGb > 0) ? sizeGb : 1
        };

        // Zero-knowledge: generate the vault DEK IN THE BROWSER and wrap it to our
        // OWN public key. The server only ever receives the opaque wrapped DEK — it
        // never sees the key (true zero-knowledge). Requires an ECC keypair.
        let zkPendingDek = null;
        if (vaultType === 'zero_knowledge') {
            try {
                await zkEnsureKeypair();
                const lib = eccLib();
                const mine = await apiRequest('/ecc/keys/public', { silent: true });
                if (!mine || !mine.public_key) throw new Error('Your public key is unavailable.');
                const myPub = await lib.importPublicKeyPEM(mine.public_key);
                const dek = await lib.generateVaultDEK();
                payload.type = 'zero_knowledge';
                const hcb = document.getElementById('vault-hierarchical');
                if (hcb && hcb.checked) {
                    // HIERARCHICAL: mint a per-vault TEAM keypair, wrap the DEK to the team PUBLIC
                    // key, and wrap the team PRIVATE key to the owner. The server holds only public
                    // keys + opaque wraps; it never sees the DEK or the team private key.
                    const teamKp = await lib.generateKeypair();
                    const dekWrap = await lib.wrapVaultDEK(dek, teamKp.publicKey);
                    const privWrap = await lib.wrapPrivateKeyToPublic(teamKp.privateKey, myPub);
                    payload.key_wrapping_mode = 'hierarchical';
                    payload.team_public_key = await lib.exportPublicKeyPEM(teamKp.publicKey);
                    payload.team_wrapped_dek = dekWrap.wrappedDEK;
                    payload.team_dek_ephemeral_public_key = dekWrap.ephemeralPublicKey;
                    payload.wrapped_team_privkey = privWrap.wrappedKey;
                    payload.team_privkey_ephemeral_public_key = privWrap.ephemeralPublicKey;
                } else {
                    const { wrappedDEK, ephemeralPublicKey } = await lib.wrapVaultDEK(dek, myPub);
                    payload.wrapped_dek = wrappedDEK;
                    payload.ephemeral_public_key = ephemeralPublicKey;
                }
                zkPendingDek = dek;
            } catch (err) {
                showError('Encryption key setup failed: ' + err.message);
                return;
            }
        }

        const created = await apiRequest('/vaults', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        // Cache the just-generated DEK (epoch 1) so the first upload needn't round-trip to
        // unwrap. zkState.vaultDeks is keyed {vaultId: {epoch: dek}} — store under epoch 1.
        if (zkPendingDek && created && created.id) {
            zkState.vaultDeks[created.id] = { 1: zkPendingDek };
            if (payload.key_wrapping_mode === 'hierarchical') zkState.pinnedHier[created.id] = true;
        }

        closeModal();
        document.getElementById('create-vault-form').reset();
        loadVaults();
    } catch (error) {
        showError('Failed to create vault: ' + error.message);
    }
});

// Keep the password + team-mode visibility in step with the vault-type choice.
// (app.js runs after the DOM is parsed, so the select already exists here.)
(function bindVaultTypeSync() {
    const sel = document.getElementById('vault-type');
    if (sel) sel.addEventListener('change', syncCreateVaultForm);
})();

// Open the modal that lets the user choose the credential's validity/expiry
function showGenerateTempCreds() {
    const modal = document.getElementById('generate-temp-creds-modal');
    if (!modal) {
        // Fallback: modal markup missing, generate with server defaults
        generateTempCreds();
        return;
    }

    // Reset inputs to defaults each time the modal opens
    const minutesInput = document.getElementById('temp-cred-validity-minutes');
    const endInput = document.getElementById('temp-cred-end-datetime');
    if (minutesInput) minutesInput.value = '65';
    if (endInput) endInput.value = '';
    const noteInput = document.getElementById('temp-cred-note');
    const canCreateInput = document.getElementById('temp-cred-can-create');
    if (noteInput) noteInput.value = '';
    if (canCreateInput) canCreateInput.checked = false;

    initTempScopeBuilder();      // wire the scope-builder controls once
    resetTempScopeBuilder();     // reset to defaults
    populateTempScopeVaults();   // fill the selectable vault list

    modal.classList.add('active');
}

let _tempScopeWired = false;
function initTempScopeBuilder() {
    if (_tempScopeWired) return;
    _tempScopeWired = true;
    const enable = document.getElementById('tc-scope-enable');
    const builder = document.getElementById('tc-scope-builder');
    const legacy = document.getElementById('tc-legacy-cancreate-group');
    const movedHint = document.getElementById('tc-cancreate-moved-hint');
    if (enable && builder) {
        enable.addEventListener('change', () => {
            builder.hidden = !enable.checked;
            // The coarse "can create" checkbox only applies to an unscoped credential; under
            // scoping it is replaced by the nested Temp-credentials "Create temp credentials"
            // control, so hide it and point the user at where the ability moved.
            if (legacy) legacy.style.display = enable.checked ? 'none' : '';
            // toggle via style.display, not the hidden attr: .form-help is display:block, which
            // would override [hidden] and leave the hint always showing.
            if (movedHint) movedHint.style.display = enable.checked ? '' : 'none';
        });
    }
    const tcPage = document.getElementById('tc-page-tempcreds');
    const tempPerms = document.getElementById('tc-temp-perms');
    if (tcPage && tempPerms) tcPage.addEventListener('change', () => { tempPerms.hidden = !tcPage.checked; });
    const tCreate = document.getElementById('tc-temp-create');
    const delRow = document.getElementById('tc-temp-delegate-row');
    if (tCreate && delRow) tCreate.addEventListener('change', () => {
        delRow.hidden = !tCreate.checked;
        if (!tCreate.checked) { const d = delRow.querySelector('input'); if (d) d.checked = false; }
    });
    document.querySelectorAll('input[name="tc-vault-mode"]').forEach(r => r.addEventListener('change', () => {
        const sel = document.getElementById('tc-vault-select');
        const isSel = document.querySelector('input[name="tc-vault-mode"]:checked')?.value === 'selected';
        if (sel) sel.style.display = isSel ? '' : 'none';
        _tcRestrictSyncAvailability();
    }));
    // File/folder restriction: reveal the picker when enabled; keep availability in sync as the
    // vault selection changes (the list is re-rendered on open, so delegate the pick listener).
    const restrictEnable = document.getElementById('tc-restrict-enable');
    if (restrictEnable) restrictEnable.addEventListener('change', () => {
        const panel = document.getElementById('tc-restrict-panel');
        if (restrictEnable.checked) {
            _tcRestrict.crumbs = [{ id: null, name: 'Root' }];  // re-anchor so the trail matches the root load
            _tcRestrictLoad(null);
        } else if (panel) { panel.hidden = true; }
        _tcRestrictRenderSummary();
    });
    const vlist = document.getElementById('tc-vault-list');
    if (vlist) vlist.addEventListener('change', (e) => {
        if (e.target && e.target.classList && e.target.classList.contains('tc-vault-pick')) {
            _tcRestrictSyncAvailability();
        }
    });
    const search = document.getElementById('tc-vault-search');
    if (search) search.addEventListener('input', () => {
        const q = search.value.toLowerCase();
        document.querySelectorAll('#tc-vault-list .member-pick-item').forEach(it => {
            const show = (it.dataset.name || '').includes(q);
            it.style.display = show ? '' : 'none';
            // Keep a locked vault's sibling password input in sync, so filtering never
            // leaves an orphaned, unlabeled password box floating in the list.
            const cb = it.querySelector('.tc-vault-pick');
            const pw = cb && document.querySelector(`.tc-vault-pw[data-vault="${cb.value}"]`);
            if (pw) pw.style.display = show ? '' : 'none';
        });
    });
}

function resetTempScopeBuilder() {
    const enable = document.getElementById('tc-scope-enable');
    const builder = document.getElementById('tc-scope-builder');
    const legacy = document.getElementById('tc-legacy-cancreate-group');
    if (enable) enable.checked = false;
    if (builder) builder.hidden = true;
    if (legacy) legacy.style.display = '';
    const movedHint = document.getElementById('tc-cancreate-moved-hint');
    if (movedHint) movedHint.style.display = 'none';
    _tcHideError();
    document.querySelectorAll('.tc-page').forEach(c => { c.checked = (c.value === 'dashboard' || c.value === 'vaults'); });
    const tempPerms = document.getElementById('tc-temp-perms'); if (tempPerms) tempPerms.hidden = true;
    const delRow = document.getElementById('tc-temp-delegate-row'); if (delRow) delRow.hidden = true;
    document.querySelectorAll('.tc-temp').forEach(c => { c.checked = (c.value === 'view'); });
    const selRadio = document.querySelector('input[name="tc-vault-mode"][value="selected"]'); if (selRadio) selRadio.checked = true;
    const sel = document.getElementById('tc-vault-select'); if (sel) sel.style.display = '';
    const baseline = new Set(['vault.see_info', 'vault.see_files', 'file.download']);
    document.querySelectorAll('.tc-cap').forEach(c => { c.checked = baseline.has(c.value); });
    document.querySelectorAll('.tc-global-cap').forEach(c => { c.checked = false; });
    const search = document.getElementById('tc-vault-search'); if (search) search.value = '';
    _tcRestrictReset();
}

async function populateTempScopeVaults() {
    const list = document.getElementById('tc-vault-list');
    if (!list) return;
    list.innerHTML = '<div class="text-tertiary text-sm p-sm">Loading vaults…</div>';
    try {
        const vaults = await apiRequest('/vaults', { silent: true });
        _tcVaultObjs = {};
        if (Array.isArray(vaults)) vaults.forEach(v => { _tcVaultObjs[v.id] = v; });
        if (!Array.isArray(vaults) || !vaults.length) {
            list.innerHTML = '<div class="text-tertiary text-sm p-sm">No vaults available to grant.</div>';
            return;
        }
        // A password-protected vault can only be granted over SFTP if the issuer proves
        // its password here (the credential then carries that proof — SFTP has no per-vault
        // prompt). So render a password field for locked vaults; it's required to grant one.
        list.innerHTML = vaults.map(v => `
            <label class="member-pick-item" data-name="${escapeHtml((v.name || '').toLowerCase())}">
                <input type="checkbox" class="tc-vault-pick" value="${escapeHtml(v.id)}" data-haspw="${v.has_password ? '1' : '0'}">
                <span class="member-pick-name">${escapeHtml(v.name || 'Untitled vault')}${v.has_password ? ' <span class="text-tertiary text-sm">· password-protected</span>' : ''}</span>
            </label>${v.has_password ? `
            <input type="password" class="tc-vault-pw form-control" data-vault="${escapeHtml(v.id)}" placeholder="Vault password — required to grant access to this password-protected vault" autocomplete="new-password" style="margin:2px 0 10px 26px;max-width:340px;">` : ''}`).join('');
    } catch (_) {
        list.innerHTML = '<div class="text-tertiary text-sm p-sm">Could not load vaults.</div>';
    }
}

// --- File/folder restriction picker (produces selected_vaults[].scope_ids) ------------------
// A restriction targets exactly ONE selected vault (file/folder sharing is inherently single-vault);
// with 0 or 2+ vaults selected, or "all my vaults", it is disabled and the credential is whole-vault.
const _tcRestrict = { vaultId: null, files: new Set(), folders: new Set(), crumbs: [{ id: null, name: 'Root' }] };
let _tcVaultObjs = {};  // id -> vault object (from the picker fetch), so the picker can decrypt ZK names
let _tcRestrictSeq = 0; // monotonic load token: only the latest _tcRestrictLoad may paint (last-click-wins)

function _tcRestrictReset() {
    _tcRestrict.vaultId = null;
    _tcRestrict.files.clear();
    _tcRestrict.folders.clear();
    _tcRestrict.crumbs = [{ id: null, name: 'Root' }];
    const en = document.getElementById('tc-restrict-enable');
    if (en) { en.checked = false; en.disabled = true; }
    const panel = document.getElementById('tc-restrict-panel'); if (panel) panel.hidden = true;
    const hint = document.getElementById('tc-restrict-hint'); if (hint) hint.style.display = '';
    _tcRestrictRenderSummary();
}

function _tcRestrictSyncAvailability() {
    const en = document.getElementById('tc-restrict-enable');
    const hint = document.getElementById('tc-restrict-hint');
    if (!en) return;
    const picks = Array.from(document.querySelectorAll('.tc-vault-pick:checked'));
    const isSelected = document.querySelector('input[name="tc-vault-mode"]:checked')?.value === 'selected';
    if (isSelected && picks.length === 1) {
        en.disabled = false;
        if (hint) hint.style.display = 'none';
        const vid = picks[0].value;
        if (_tcRestrict.vaultId !== vid) {
            // The single selected vault changed — drop any prior selection (ids are per-vault).
            _tcRestrict.vaultId = vid;
            _tcRestrict.files.clear();
            _tcRestrict.folders.clear();
            _tcRestrict.crumbs = [{ id: null, name: 'Root' }];
            if (en.checked) _tcRestrictLoad(null);
        }
    } else {
        en.disabled = true;
        en.checked = false;
        _tcRestrict.vaultId = null;
        _tcRestrict.files.clear();
        _tcRestrict.folders.clear();
        const panel = document.getElementById('tc-restrict-panel'); if (panel) panel.hidden = true;
        if (hint) hint.style.display = '';
    }
    _tcRestrictRenderSummary();
}

async function _tcRestrictLoad(folderId) {
    const panel = document.getElementById('tc-restrict-panel');
    const list = document.getElementById('tc-restrict-list');
    if (!panel || !list || !_tcRestrict.vaultId) return;
    // Last-click-wins: a slower earlier load (esp. behind a ZK unlock prompt) must not paint over a
    // newer navigation, which would show one folder's contents under another's breadcrumb.
    const seq = ++_tcRestrictSeq;
    panel.hidden = false;
    list.innerHTML = '<div class="text-tertiary text-sm p-sm">Loading…</div>';
    let items = [];
    try {
        const q = folderId ? `?folder_id=${encodeURIComponent(folderId)}` : '';
        const res = await apiRequest(`/vaults/${encodeURIComponent(_tcRestrict.vaultId)}/files${q}`, { silent: true });
        items = (res && res.items) || [];
    } catch (_) {
        if (seq === _tcRestrictSeq) list.innerHTML = '<div class="text-tertiary text-sm p-sm">Could not load files.</div>';
        return;
    }
    if (seq !== _tcRestrictSeq) return;  // superseded by a newer navigation
    // Zero-knowledge vaults return encrypted names; decrypt them client-side (same flow as the
    // main file view) so the picker shows real names. IDs are always cleartext, so selection works
    // either way — a cancelled unlock just leaves "🔒 Encrypted name" labels.
    const vobj = _tcVaultObjs[_tcRestrict.vaultId];
    if (vobj && vobj.type === 'zero_knowledge') {
        try { await zkDecryptListingNames(items, vobj); } catch (_) { /* names stay encrypted; ids still work */ }
        if (seq !== _tcRestrictSeq) return;  // the unlock prompt is async — re-check after it
    }
    _tcRestrictRenderCrumbs();
    const rows = [];
    for (const f of items.filter(i => i.type === 'folder')) {
        const on = _tcRestrict.folders.has(f.id) ? 'checked' : '';
        rows.push(`<div class="tc-restrict-row">
            <input type="checkbox" class="tc-restrict-include" data-id="${escapeHtml(f.id)}" data-kind="folder" ${on}>
            <span class="name" title="${escapeHtml(f.name || '')}">\u{1F4C1} ${escapeHtml(f.name || 'Folder')}</span>
            <button type="button" class="open" data-open="${escapeHtml(f.id)}" data-name="${escapeHtml(f.name || 'Folder')}">open →</button>
        </div>`);
    }
    for (const f of items.filter(i => i.type === 'file')) {
        const on = _tcRestrict.files.has(f.id) ? 'checked' : '';
        rows.push(`<div class="tc-restrict-row">
            <input type="checkbox" class="tc-restrict-include" data-id="${escapeHtml(f.id)}" data-kind="file" ${on}>
            <span class="name" title="${escapeHtml(f.name || '')}">\u{1F4C4} ${escapeHtml(f.name || 'File')}</span>
        </div>`);
    }
    list.innerHTML = rows.length ? rows.join('') : '<div class="text-tertiary text-sm p-sm">This folder is empty.</div>';
    list.querySelectorAll('.tc-restrict-include').forEach(cb => {
        cb.addEventListener('change', () => {
            const set = cb.dataset.kind === 'folder' ? _tcRestrict.folders : _tcRestrict.files;
            if (cb.checked) set.add(cb.dataset.id); else set.delete(cb.dataset.id);
            _tcRestrictRenderSummary();
        });
    });
    list.querySelectorAll('button[data-open]').forEach(b => {
        b.addEventListener('click', () => {
            _tcRestrict.crumbs.push({ id: b.dataset.open, name: b.dataset.name });
            _tcRestrictLoad(b.dataset.open);
        });
    });
    _tcRestrictRenderSummary();
}

function _tcRestrictRenderCrumbs() {
    const el = document.getElementById('tc-restrict-crumbs');
    if (!el) return;
    el.innerHTML = _tcRestrict.crumbs.map((c, i) => {
        const last = i === _tcRestrict.crumbs.length - 1;
        const label = escapeHtml(c.name);
        return last ? `<span>${label}</span>` : `<a data-crumb="${i}">${label}</a><span class="sep">/</span>`;
    }).join('');
    el.querySelectorAll('a[data-crumb]').forEach(a => {
        a.addEventListener('click', () => {
            const idx = parseInt(a.dataset.crumb, 10);
            _tcRestrict.crumbs = _tcRestrict.crumbs.slice(0, idx + 1);
            _tcRestrictLoad(_tcRestrict.crumbs[idx].id);
        });
    });
}

function _tcRestrictRenderSummary() {
    const el = document.getElementById('tc-restrict-summary');
    if (!el) return;
    const en = document.getElementById('tc-restrict-enable');
    if (!en || !en.checked) { el.textContent = ''; return; }
    const nf = _tcRestrict.files.size, nd = _tcRestrict.folders.size;
    if (nf + nd === 0) {
        el.innerHTML = '<span style="color:var(--danger,#b91c1c)">Select at least one file or folder — with nothing selected the credential is granted the WHOLE vault.</span>';
    } else {
        el.textContent = `Restricted to ${nf} file${nf === 1 ? '' : 's'} + ${nd} folder${nd === 1 ? '' : 's'} `
            + `(plus the folders needed to reach them).`;
    }
}

// Collect the scope document from the builder, or null when scoping is disabled.
function collectTempScope() {
    const enable = document.getElementById('tc-scope-enable');
    if (!enable || !enable.checked) return null;
    const pages = Array.from(document.querySelectorAll('.tc-page:checked')).map(c => c.value);
    const caps = Array.from(document.querySelectorAll('.tc-global-cap:checked')).map(c => c.value);
    const vaultCaps = Array.from(document.querySelectorAll('.tc-cap:checked')).map(c => c.value);
    const temp = {};
    document.querySelectorAll('.tc-temp').forEach(c => { temp[c.value] = c.checked; });
    if (!pages.includes('temp_creds')) { temp.view = temp.create = temp.invalidate = temp.clear = temp.delegate = false; }
    const mode = document.querySelector('input[name="tc-vault-mode"]:checked')?.value === 'all' ? 'all' : 'selected';
    let selected_vaults = [];
    if (mode === 'selected') {
        selected_vaults = Array.from(document.querySelectorAll('.tc-vault-pick:checked'))
            .map(c => {
                const item = { vault_id: c.value, caps: vaultCaps };
                // Carry the vault password for a locked vault so the server can verify the
                // proof at mint (required to grant SFTP access to a password-protected vault).
                if (c.dataset.haspw === '1') {
                    const pwEl = document.querySelector(`.tc-vault-pw[data-vault="${c.value}"]`);
                    if (pwEl && pwEl.value) item.password = pwEl.value;
                }
                return item;
            });
        // A single-vault file/folder restriction attaches scope_ids to that vault's entry. Only when
        // at least one file/folder is chosen — an empty {files:[],folders:[]} means deny-all on the
        // server, so "restrict enabled but nothing picked" is treated as whole-vault (scope omitted).
        const restrictEnable = document.getElementById('tc-restrict-enable');
        if (restrictEnable && restrictEnable.checked && _tcRestrict.vaultId
            && (_tcRestrict.files.size + _tcRestrict.folders.size) > 0) {
            const entry = selected_vaults.find(sv => sv.vault_id === _tcRestrict.vaultId);
            if (entry) entry.scope_ids = {
                files: Array.from(_tcRestrict.files),
                folders: Array.from(_tcRestrict.folders),
            };
        }
    }
    return { scope: { v: 1, pages, caps, vault_caps_default: vaultCaps, temp }, vault_access_mode: mode, selected_vaults };
}

// Generate Temporary Credentials
// options.validity_minutes / options.total_lifetime_minutes override the
// server-configured default lifetime when provided.
// Surface a temp-credential error INSIDE the open generate modal (via textContent, so a
// server-supplied vault name can't inject markup) instead of a transient toast, so a recoverable
// failure — e.g. a missing/incorrect vault password — doesn't discard the operator's form state.
// Falls back to a toast when the modal isn't the active surface (e.g. the markup-missing path).
function _tcShowError(msg) {
    const modal = document.getElementById('generate-temp-creds-modal');
    const box = document.getElementById('temp-cred-error');
    if (box && modal && modal.classList.contains('active')) {
        box.textContent = msg;
        box.style.display = '';  // .alert is display:flex; inline style toggles it (the [hidden] attr can't, .alert wins)
        box.scrollIntoView({ block: 'nearest' });
    } else {
        showError(msg);
    }
}
function _tcHideError() {
    const box = document.getElementById('temp-cred-error');
    if (box) { box.style.display = 'none'; box.textContent = ''; }
}

let _tcGenerating = false;
async function generateTempCreds(options = {}) {
    // Re-entrancy guard: the modal now stays open across the await (so a recoverable error can be
    // shown inline), so nothing else stops a double-click from minting two credentials — block it
    // and disable the submit button for the duration of the request.
    if (_tcGenerating) return;
    _tcGenerating = true;
    const submitBtn = document.querySelector('#generate-temp-creds-form button[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;
    try {
        const body = {};
        if (options.validity_minutes != null) {
            body.validity_minutes = options.validity_minutes;
        }
        if (options.total_lifetime_minutes != null) {
            body.total_lifetime_minutes = options.total_lifetime_minutes;
        }
        if (options.note) body.note = options.note;
        if (options.can_create_temp_credentials) body.can_create_temp_credentials = true;
        if (options.scope) {
            body.scope = options.scope;
            body.vault_access_mode = options.vault_access_mode || 'selected';
            body.selected_vaults = options.selected_vaults || [];
        }

        const creds = await apiRequest('/auth/temp-credentials', {
            method: 'POST',
            body: JSON.stringify(body)
        });

        // Success only: close the generate modal now, then show the result modal. On failure the
        // catch below keeps the generate modal open so the operator's entered scope/note/passwords
        // survive a recoverable error.
        closeModal();
        showTempCredsModal(creds);

        // Reload active credentials after a short delay
        setTimeout(() => loadTempCreds(), 1000);
    } catch (error) {
        _tcShowError('Failed to generate credentials: ' + error.message);
    } finally {
        _tcGenerating = false;
        if (submitBtn) submitBtn.disabled = false;
    }
}

// Show temp credentials in a modal
function showTempCredsModal(creds) {
    const sftpCmd = `sftp -P 2222 ${creds.temp_username}@localhost`;
    const expires = creds.expires_at ? new Date(creds.expires_at).toLocaleString() : 'N/A';
    const validity = creds.validity_minutes != null
        ? `Valid for ${creds.validity_minutes} minute${creds.validity_minutes === 1 ? '' : 's'}` : '';

    // A read-only field + working Copy button (the old copy was broken by a
    // duplicate copyToClipboard, and double-click selected stray whitespace).
    const field = (label, value) => `
        <div class="cred-field">
            <span class="cred-field-label">${label}</span>
            <div class="cred-field-row">
                <input class="cred-field-input mono" type="text" readonly value="${escapeHtml(value)}">
                <button class="btn btn-sm btn-secondary cred-copy-btn" type="button" data-copy="${escapeHtml(value)}">${iconSvg('copy', 'icon-sm')} Copy</button>
            </div>
        </div>`;

    const noteHtml = creds.note
        ? `<div class="cred-field"><span class="cred-field-label">Note</span><div class="cred-note">${escapeHtml(creds.note)}</div></div>`
        : '';
    const canCreateHtml = creds.can_create_temp_credentials
        ? `<div class="alert alert-warning" style="font-size:.85rem;">${iconSvg('alert-triangle', 'icon-sm')} This credential can itself create more temporary credentials.</div>`
        : '';

    const modalHTML = `
        <div id="temp-creds-modal" class="modal active">
            <div class="modal-content" style="max-width: 560px;">
                <div class="modal-header">
                    <h3>${iconSvg('key')} Temporary credentials</h3>
                    <button class="close-modal-btn modal-close" id="close-temp-creds-x" aria-label="Close">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="alert alert-warning mb-md">
                        ${iconSvg('alert-triangle', 'icon-sm')} <strong>Copy these now.</strong> The password is shown once and can't be retrieved later.
                    </div>
                    ${field('Username', creds.temp_username || 'N/A')}
                    ${field('Password', creds.credential || 'N/A')}
                    <div class="cred-field">
                        <span class="cred-field-label">SFTP command</span>
                        <div class="cred-field-row">
                            <code class="cred-code mono">${escapeHtml(sftpCmd)}</code>
                            <button class="btn btn-sm btn-secondary cred-copy-btn" type="button" data-copy="${escapeHtml(sftpCmd)}">${iconSvg('copy', 'icon-sm')} Copy</button>
                        </div>
                    </div>
                    <div class="cred-field">
                        <span class="cred-field-label">SFTP host key fingerprint</span>
                        <div class="cred-field-row">
                            <code id="tc-hostkey-fp" class="cred-code mono">loading…</code>
                        </div>
                        <small class="text-tertiary text-sm">Verify this matches the fingerprint your SFTP client shows on first connect.</small>
                    </div>
                    ${noteHtml}
                    ${canCreateHtml}
                    <div class="cred-expiry text-secondary text-sm mt-sm">
                        ${iconSvg('clock', 'icon-sm')} Expires ${expires}${validity ? ` &middot; ${validity}` : ''}
                    </div>
                </div>
                <div class="modal-footer">
                    <button class="btn btn-primary btn-block" id="close-temp-creds-modal">I've saved the credentials</button>
                </div>
            </div>
        </div>`;
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    const modal = document.getElementById('temp-creds-modal');
    // Self-contained copy — does not rely on the global copyToClipboard.
    modal.querySelectorAll('.cred-copy-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const text = btn.getAttribute('data-copy');
            navigator.clipboard.writeText(text).then(() => {
                const orig = btn.innerHTML;
                btn.innerHTML = `${iconSvg('check', 'icon-sm')} Copied`;
                btn.classList.add('is-copied');
                setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('is-copied'); }, 1500);
            }).catch(() => showError('Copy failed - click the field and press Ctrl+C.'));
        });
    });
    // Clicking a field selects all of its text for easy manual copy.
    modal.querySelectorAll('.cred-field-input').forEach(inp => {
        const sel = () => inp.select();
        inp.addEventListener('focus', sel);
        inp.addEventListener('click', sel);
    });
    modal.querySelector('#close-temp-creds-modal').addEventListener('click', closeTempCredsModal);
    modal.querySelector('#close-temp-creds-x').addEventListener('click', closeTempCredsModal);

    // Fill in the SFTP host-key fingerprint (so the customer can verify it on first connect).
    const _hostKeyPending = 'not generated yet — created when the SFTP service first starts';
    apiRequest('/sftp/host-key', { silent: true }).then(r => {
        const el = document.getElementById('tc-hostkey-fp');
        if (el) el.textContent = (r && r.available && r.fingerprint_sha256) ? r.fingerprint_sha256 : _hostKeyPending;
    }).catch(() => {
        const el = document.getElementById('tc-hostkey-fp');
        if (el) el.textContent = _hostKeyPending;
    });
}

// Close temp creds modal
function closeTempCredsModal() {
    const modal = document.getElementById('temp-creds-modal');
    if (modal) {
        modal.remove();
    }
}

// Load Active Temporary Credentials
let tempCredTimers = {};
const tempCredsExpanded = new Set();
let tempCredsAll = [];

// Classify a credential into a single status bucket.
function credStatus(cred) {
    const now = new Date();
    const exp = new Date(cred.expires_at);
    if (cred.is_used) return 'used';
    if (now > exp) return 'expired';
    if (!cred.is_active) return 'deactivated';
    return 'active';
}

let tempCredsLimit = 50; // how many temp-cred rows to render before "Show more"

async function loadTempCreds() {
    const container = document.getElementById('active-temp-creds');
    if (!container) return;

    try {
        const creds = await apiRequest('/temp-creds/list');
        Object.values(tempCredTimers).forEach(timer => clearInterval(timer));
        tempCredTimers = {};
        tempCredsAll = creds || [];
        tempCredsAll.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        tempCredsLimit = 50;
        renderTempCreds();
    } catch (error) {
        console.error('Failed to load temp creds:', error);
        tempCredsAll = [];
        container.innerHTML = emptyTempCredsState();
    }
}

// Render the temp-cred table honouring the status filter (#tc-status-filter).
function renderTempCreds() {
    const container = document.getElementById('active-temp-creds');
    if (!container) return;
    Object.values(tempCredTimers).forEach(timer => clearInterval(timer));
    tempCredTimers = {};

    const filter = document.getElementById('tc-status-filter')?.value || 'all';
    const list = filter === 'all' ? tempCredsAll : tempCredsAll.filter(c => credStatus(c) === filter);

    if (tempCredsAll.length === 0) {
        const c0 = document.getElementById('tc-count');
        if (c0) c0.textContent = '';
        container.innerHTML = emptyTempCredsState();
        return;
    }
    if (list.length === 0) {
        const c1 = document.getElementById('tc-count');
        if (c1) c1.textContent = `0 of ${tempCredsAll.length}`;
        container.innerHTML = `<div class="card"><div class="card-body text-center text-secondary p-xl">No credentials match this filter.</div></div>`;
        return;
    }

    // Paginate: only render up to tempCredsLimit rows so large lists stay snappy
    // (the list can grow into the hundreds). "Show more" reveals the next page.
    const visible = list.slice(0, tempCredsLimit);
    const remaining = list.length - visible.length;

    const countEl = document.getElementById('tc-count');
    if (countEl) countEl.textContent = `${visible.length} of ${list.length}`;

    container.innerHTML = `
        <div class="card table-card">
            <div class="data-table-wrapper">
                <table class="data-table exp-table">
                    <thead><tr>
                        <th class="col-toggle"></th>
                        <th>Credential</th>
                        <th>User</th>
                        <th>Status</th>
                        <th>Expires</th>
                    </tr></thead>
                    <tbody>${visible.map(renderTempCredRow).join('')}</tbody>
                </table>
            </div>
        </div>
        ${remaining > 0 ? `<div class="text-center mt-md">
            <button id="tc-show-more" class="btn btn-secondary btn-sm" type="button">Show ${Math.min(50, remaining)} more · ${remaining} hidden</button>
        </div>` : ''}`;

    visible.forEach(cred => {
        if (cred.is_active && !cred.is_used) startCountdownTimer(cred.temp_username, cred.expires_at);
    });
    const moreBtn = document.getElementById('tc-show-more');
    if (moreBtn) moreBtn.addEventListener('click', () => { tempCredsLimit += 50; renderTempCreds(); });
    attachTempCredListeners();
}

// Bulk-delete expired / used / both.
async function cleanupTempCreds(which) {
    const targets = tempCredsAll.filter(c => {
        const s = credStatus(c);
        return which === 'expired' ? s === 'expired' : which === 'used' ? s === 'used' : (s === 'expired' || s === 'used');
    });
    if (!targets.length) { showInfo('Nothing to clean up'); return; }
    const label = which === 'both' ? 'expired & used' : which;
    const confirmed = await showConfirm(`Permanently delete ${targets.length} ${label} credential(s)?`, 'Clean up credentials');
    if (!confirmed) return;
    const results = await Promise.allSettled(targets.map(c => apiRequest(`/temp-creds/${c.temp_username}/delete`, { method: 'POST' })));
    const ok = results.filter(r => r.status === 'fulfilled').length;
    showSuccess(`Deleted ${ok} of ${targets.length} credential(s)`);
    await loadTempCreds();
}

// Invalidate (deactivate) every currently-active credential.
async function invalidateAllActive() {
    const targets = tempCredsAll.filter(c => credStatus(c) === 'active');
    if (!targets.length) { showInfo('No active credentials to invalidate'); return; }
    const confirmed = await showConfirm(
        `Invalidate ${targets.length} active credential(s)? They can no longer be used for new logins.`,
        'Invalidate all active'
    );
    if (!confirmed) return;
    const results = await Promise.allSettled(targets.map(c => apiRequest(`/temp-creds/${c.temp_username}/deactivate`, { method: 'POST' })));
    const ok = results.filter(r => r.status === 'fulfilled').length;
    showSuccess(`Invalidated ${ok} of ${targets.length} credential(s)`);
    await loadTempCreds();
}

function emptyTempCredsState() {
    return `
        <div class="empty-state-center p-xl">
            <div style="font-size: 3rem;">${iconSvg('key', 'icon-lg')}</div>
            <h3 class="text-xl font-bold mb-xs mt-sm">No Temporary Credentials</h3>
            <p class="text-secondary">Generate one-time credentials for secure temporary access.</p>
        </div>`;
}

function toggleTempCredRow(id) {
    const open = tempCredsExpanded.has(id);
    if (open) tempCredsExpanded.delete(id); else tempCredsExpanded.add(id);
    const c = document.getElementById('active-temp-creds');
    if (!c) return;
    const row = c.querySelector(`.exp-row[data-id="${id}"]`);
    const det = c.querySelector(`.exp-detail[data-id="${id}"]`);
    if (row) row.classList.toggle('open', !open);
    if (det) det.classList.toggle('is-open', !open);
}

// Back-compat alias; renders one credential as an expandable table row pair.
function renderTempCredItem(cred) { return renderTempCredRow(cred); }
function renderTempCredRow(cred) {
    const now = new Date();
    const expiresAt = new Date(cred.expires_at);

    let status, statusBadge, dataStatus;
    if (cred.is_used) {
        status = 'Used'; statusBadge = 'secondary'; dataStatus = 'used';
    } else if (now > expiresAt) {
        status = 'Expired'; statusBadge = 'error'; dataStatus = 'expired';
    } else if (!cred.is_active) {
        status = 'Deactivated'; statusBadge = 'error'; dataStatus = 'expired';
    } else {
        status = 'Active'; statusBadge = 'success'; dataStatus = 'active';
        if ((expiresAt - now) / (1000 * 60 * 60) < 1) dataStatus = 'warning'; // expiring soon
    }

    const canDeactivate = cred.is_active && !cred.is_used && now < expiresAt;
    const canShowPassword = cred.has_password;
    const uname = escapeHtml(cred.temp_username);
    const open = tempCredsExpanded.has(cred.temp_username);

    return `
        <tr class="exp-row cred-row${open ? ' open' : ''}" data-id="${uname}" data-status="${dataStatus}">
            <td class="col-toggle"><button class="exp-toggle" aria-label="Toggle details">${iconSvg('chevron-right', 'icon-sm')}</button></td>
            <td><span class="mono cred-name">${uname}</span></td>
            <td>${escapeHtml(cred.username)}</td>
            <td><span class="badge badge-${statusBadge}">${status}</span></td>
            <td><span class="mono cred-expires" id="countdown-${uname}">${expiresAt.toLocaleString()}</span></td>
        </tr>
        <tr class="exp-detail${open ? ' is-open' : ''}" data-id="${uname}">
            <td colspan="5">
                <div class="row-detail">
                    <div class="detail-meta">
                        <span class="meta-item">${iconSvg('calendar', 'icon-sm')}<span class="meta-label">Created</span><span class="meta-value">${new Date(cred.created_at).toLocaleString()}</span></span>
                        ${cred.note ? `<span class="meta-item">${iconSvg('file-text', 'icon-sm')}<span class="meta-label">Note</span><span class="meta-value">${escapeHtml(cred.note)}</span></span>` : ''}
                        ${cred.can_create_temp_credentials ? `<span class="entity-note">${iconSvg('key', 'icon-sm')} Can create temp credentials</span>` : ''}
                        ${cred.active_session_count > 0 ? `<span class="entity-note">${iconSvg('activity', 'icon-sm')} ${cred.active_session_count} active session(s)</span>` : ''}
                    </div>
                    <div class="entity-actions">
                        ${canShowPassword ? `<button class="btn btn-sm btn-secondary show-password-btn" data-username="${uname}">${iconSvg('eye', 'icon-sm')} Show Password</button>` : ''}
                        ${canDeactivate ? `<button class="btn btn-sm btn-warning deactivate-temp-cred-btn" data-username="${uname}">${iconSvg('ban', 'icon-sm')} Deactivate</button>` : ''}
                        <button class="btn btn-sm btn-danger delete-temp-cred-btn" data-username="${uname}">${iconSvg('trash', 'icon-sm')} Delete</button>
                        ${cred.active_session_count > 0 ? `<button class="btn btn-sm btn-danger terminate-sessions-btn" data-username="${uname}">${iconSvg('alert-triangle', 'icon-sm')} Terminate Sessions</button>` : ''}
                    </div>
                </div>
            </td>
        </tr>`;
}

// Start countdown timer for active credential
function startCountdownTimer(username, expiresAt) {
    const countdownEl = document.getElementById(`countdown-${username}`);
    if (!countdownEl) return;
    
    const updateCountdown = () => {
        const now = new Date();
        const expires = new Date(expiresAt);
        const timeLeft = expires - now;
        
        if (timeLeft <= 0) {
            countdownEl.textContent = 'Expired';
            countdownEl.style.color = 'var(--error)';
            if (tempCredTimers[username]) {
                clearInterval(tempCredTimers[username]);
                delete tempCredTimers[username];
            }
            // Don't reload - just update the status text
            // User can manually refresh if they want to see updated list
            return;
        }
        
        const hours = Math.floor(timeLeft / (1000 * 60 * 60));
        const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
        
        if (hours > 0) {
            countdownEl.textContent = `${hours}h ${minutes}m ${seconds}s left`;
        } else if (minutes > 0) {
            countdownEl.textContent = `${minutes}m ${seconds}s left`;
        } else {
            countdownEl.textContent = `${seconds}s left`;
            countdownEl.style.color = 'var(--warning)';
        }
    };
    
    updateCountdown();
    const intervalId = setInterval(updateCountdown, 1000);
    tempCredTimers[username] = intervalId;
    
    // Register interval with sessionManager if available
    if (window.sessionManager && typeof window.sessionManager.registerInterval === 'function') {
        window.sessionManager.registerInterval(intervalId);
    }
}

// Attach event listeners for temp cred actions
function attachTempCredListeners() {
    // Show password buttons
    document.querySelectorAll('.show-password-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const username = btn.getAttribute('data-username');
            await showTempCredPassword(username);
        });
    });
    
    // Deactivate buttons
    document.querySelectorAll('.deactivate-temp-cred-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const username = btn.getAttribute('data-username');
            await deactivateTempCred(username);
        });
    });
    
    // Delete buttons
    document.querySelectorAll('.delete-temp-cred-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const username = btn.getAttribute('data-username');
            await deleteTempCred(username);
        });
    });
    
    // Terminate sessions buttons
    document.querySelectorAll('.terminate-sessions-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const username = btn.getAttribute('data-username');
            await terminateTempCredSessions(username);
        });
    });
}

// Show temp credential password
async function showTempCredPassword(username) {
    try {
        const response = await apiRequest(`/temp-creds/${username}/password`);
        // Show password in info toast and copy to clipboard
        showInfo(`Password for ${username}: ${response.password}\n\nCopied to clipboard!`);
        
        // Copy to clipboard
        navigator.clipboard.writeText(response.password).catch(err => {
            console.error('Failed to copy:', err);
        });
    } catch (error) {
        showError('Failed to retrieve password: ' + error.message);
    }
}

// Deactivate temp credential
async function deactivateTempCred(username) {
    const confirmed = await showConfirm(
        `This will prevent any new logins but won't affect active sessions.`,
        `Deactivate credential "${username}"?`
    );
    if (!confirmed) return;
    
    try {
        await apiRequest(`/temp-creds/${username}/deactivate`, { method: 'POST' });
        showSuccess('Credential deactivated successfully');
        await loadTempCreds();
    } catch (error) {
        showError('Failed to deactivate: ' + error.message);
    }
}

// Delete temp credential
async function deleteTempCred(username) {
    const confirmed = await showConfirm(
        `This will permanently remove the credential and terminate any active sessions.`,
        `Delete credential "${username}"?`
    );
    if (!confirmed) return;
    
    try {
        await apiRequest(`/temp-creds/${username}/delete`, { method: 'POST' });
        showSuccess('Credential deleted successfully');
        await loadTempCreds();
    } catch (error) {
        showError('Failed to delete: ' + error.message);
    }
}

// Terminate active sessions for temp credential
async function terminateTempCredSessions(username) {
    const confirmed = await showConfirm(
        `Terminate all active sessions for "${username}"?`,
        'Confirm Terminate Sessions'
    );
    if (!confirmed) return;
    
    try {
        await apiRequest(`/temp-creds/${username}/terminate-sessions`, { method: 'POST' });
        showSuccess('Sessions terminated successfully');
        await loadTempCreds();
    } catch (error) {
        showError('Failed to terminate sessions: ' + error.message);
    }
}

// ============================================================================
// USER MANAGEMENT — dense table with expandable rows, search & filters
// ============================================================================

const usersView = { users: [], groups: [], expanded: new Set() };

// Load Users (Admin Only)
async function loadUsers() {
    const container = document.getElementById('users-list');
    if (!container) return;

    container.innerHTML = '<div class="spinner"></div>';

    try {
        const [users, groups] = await Promise.all([
            apiRequest('/users'),
            apiRequest('/groups', { silent: true }).catch(() => [])
        ]);
        usersView.users = users || [];
        usersView.groups = Array.isArray(groups) ? groups : [];
        populateUsersGroupFilter();
        renderUsersTable();
    } catch (error) {
        console.error('Failed to load users:', error);
        container.innerHTML = `<div class="alert alert-error">Failed to load users: ${escapeHtml(error.message)}</div>`;
    }
}

// Fill the "department" filter dropdown from loaded groups
function populateUsersGroupFilter() {
    const sel = document.getElementById('users-group-filter');
    if (!sel) return;
    const current = sel.value;
    const opts = usersView.groups
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name))
        .map(g => `<option value="${g.id}">${escapeHtml(g.name)} (${g.member_count})</option>`)
        .join('');
    sel.innerHTML = `<option value="all">All departments</option>${opts}`;
    if (current && sel.querySelector(`option[value="${current}"]`)) sel.value = current;
}

// Small coloured department chip (optionally removable)
function groupChip(g, removable, userId) {
    const rm = removable
        ? `<button class="chip-remove" data-user-id="${userId}" data-group-id="${g.id}" aria-label="Remove from ${escapeHtml(g.name)}">${iconSvg('x', 'icon-sm')}</button>`
        : '';
    return `<span class="chip" style="--chip:${chipColorValue(g.color)}">${escapeHtml(g.name)}${rm}</span>`;
}

// Render the filtered users table (re-runs on each search/filter change)
function renderUsersTable() {
    const container = document.getElementById('users-list');
    if (!container) return;

    const q = (document.getElementById('users-search')?.value || '').trim().toLowerCase();
    const roleF = document.getElementById('users-role-filter')?.value || 'all';
    const groupF = document.getElementById('users-group-filter')?.value || 'all';
    const statusF = document.getElementById('users-status-filter')?.value || 'all';

    const list = usersView.users.filter(u => {
        if (roleF !== 'all' && u.role !== roleF) return false;
        if (statusF === 'active' && !(u.is_active && !u.is_locked)) return false;
        if (statusF === 'inactive' && u.is_active) return false;
        if (statusF === 'locked' && !u.is_locked) return false;
        if (groupF !== 'all' && !(u.groups || []).some(g => g.id === groupF)) return false;
        if (q && !(u.username.toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q))) return false;
        return true;
    });

    const countEl = document.getElementById('users-count');
    if (countEl) countEl.textContent = `${list.length} of ${usersView.users.length}`;

    if (usersView.users.length === 0) {
        container.innerHTML = `<div class="card"><div class="card-body text-center text-secondary p-xl">${iconSvg('users', 'icon-lg')}<p class="mt-sm">No users yet — create your first user to get started.</p></div></div>`;
        return;
    }
    if (list.length === 0) {
        container.innerHTML = `<div class="card"><div class="card-body text-center text-secondary p-xl">No users match your filters.</div></div>`;
        return;
    }

    container.innerHTML = `
        <div class="card table-card">
            <div class="data-table-wrapper">
                <table class="data-table exp-table">
                    <thead><tr>
                        <th class="col-toggle"></th>
                        <th>User</th>
                        <th>Role</th>
                        <th>Departments</th>
                        <th>Status</th>
                    </tr></thead>
                    <tbody>${list.map(renderUserRow).join('')}</tbody>
                </table>
            </div>
        </div>`;
    attachUserListeners();
}

function renderUserRow(u) {
    const initials = (u.username || '?').substring(0, 2).toUpperCase();
    const groupChips = (u.groups || []).length
        ? u.groups.map(g => groupChip(g)).join('')
        : '<span class="text-tertiary text-xs">—</span>';
    const open = usersView.expanded.has(u.id);
    return `
        <tr class="exp-row${open ? ' open' : ''}" data-id="${u.id}">
            <td class="col-toggle"><button class="exp-toggle" aria-label="Toggle details">${iconSvg('chevron-right', 'icon-sm')}</button></td>
            <td>
                <div class="cell-user">
                    <span class="avatar-sm">${initials}</span>
                    <div class="cell-user-text">
                        <span class="cell-user-name">${escapeHtml(u.username)}</span>
                        <span class="cell-user-sub">${escapeHtml(u.email || '')}</span>
                    </div>
                </div>
            </td>
            <td><span class="badge badge-${u.role}">${u.role}</span></td>
            <td><div class="chip-row">${groupChips}</div></td>
            <td><div class="badge-row">
                <span class="badge badge-${u.is_active ? 'success' : 'secondary'}">${u.is_active ? 'Active' : 'Inactive'}</span>
                ${u.is_locked ? `<span class="badge badge-warning">${iconSvg('lock', 'icon-sm')} Locked</span>` : ''}
            </div></td>
        </tr>
        <tr class="exp-detail${open ? ' is-open' : ''}" data-id="${u.id}">
            <td colspan="5">${renderUserDetail(u)}</td>
        </tr>`;
}

function renderUserDetail(u) {
    const lastLogin = u.last_login ? new Date(u.last_login).toLocaleString() : 'Never';
    const created = new Date(u.created_at).toLocaleString();
    const inGroups = new Set((u.groups || []).map(g => g.id));
    const addable = usersView.groups.filter(g => !inGroups.has(g.id));
    return `
        <div class="row-detail">
            <div class="detail-meta">
                <span class="meta-item">${iconSvg('calendar', 'icon-sm')}<span class="meta-label">Created</span><span class="meta-value">${created}</span></span>
                <span class="meta-item">${iconSvg('clock', 'icon-sm')}<span class="meta-label">Last Login</span><span class="meta-value">${lastLogin}</span></span>
            </div>
            <div class="detail-block">
                <div class="detail-label">Departments</div>
                <div class="chip-row">
                    ${(u.groups || []).length ? u.groups.map(g => groupChip(g, true, u.id)).join('') : '<span class="text-tertiary text-sm">Not in any department</span>'}
                </div>
                ${addable.length ? `
                    <div class="add-group-row">
                        <select class="form-control add-group-select" data-user-id="${u.id}">
                            <option value="">Add to department…</option>
                            ${addable.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('')}
                        </select>
                    </div>` : ''}
            </div>
            <div class="detail-block">
                <div class="detail-label">SFTP access</div>
                <div class="flex flex-col gap-sm">
                    <label class="flex items-center gap-sm">
                        <input type="checkbox" class="sftp-access-toggle" data-user-id="${u.id}" data-field="sftp_enabled" ${u.sftp_enabled !== false ? 'checked' : ''}>
                        <span>SFTP enabled</span>
                    </label>
                    <label class="flex items-center gap-sm">
                        <input type="checkbox" class="sftp-access-toggle" data-user-id="${u.id}" data-field="sftp_password_auth" ${u.sftp_password_auth !== false ? 'checked' : ''}>
                        <span>Allow password authentication <span class="text-tertiary text-xs">(off = SSH-key only)</span></span>
                    </label>
                </div>
            </div>
            <div class="detail-block">
                <div class="detail-label">SSH keys</div>
                <div class="ssh-keys-list" data-user-id="${u.id}"><span class="text-tertiary text-sm">Loading…</span></div>
                <div class="ssh-key-add">
                    <input type="text" class="form-control ssh-key-name" data-user-id="${u.id}" placeholder="Key label (e.g. laptop)" maxlength="120">
                    <input type="text" class="form-control ssh-key-public" data-user-id="${u.id}" placeholder="ssh-ed25519 AAAA… or ssh-rsa AAAA…">
                    <button type="button" class="btn btn-sm btn-secondary ssh-key-add-btn" data-user-id="${u.id}">${iconSvg('plus', 'icon-sm')} Add key</button>
                </div>
            </div>
            <div class="entity-actions">
                <button class="btn btn-sm btn-secondary edit-user-btn" data-user-id="${u.id}">${iconSvg('edit', 'icon-sm')} Edit</button>
                ${u.is_locked
                    ? `<button class="btn btn-sm btn-success unlock-user-btn" data-user-id="${u.id}">${iconSvg('unlock', 'icon-sm')} Unlock</button>`
                    : `<button class="btn btn-sm btn-warning lock-user-btn" data-user-id="${u.id}">${iconSvg('lock', 'icon-sm')} Lock</button>`}
                <button class="btn btn-sm btn-secondary change-password-btn" data-user-id="${u.id}">${iconSvg('key', 'icon-sm')} Change Password</button>
                ${currentUser.role === 'admin' && u.role !== 'admin' ? `<button class="btn btn-sm btn-secondary manage-perms-btn" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">${iconSvg('shield', 'icon-sm')} Permissions</button>` : ''}
                ${currentUser.role === 'admin' && u.username !== currentUser.username ? `<button class="btn btn-sm btn-warning terminate-user-sessions-btn" data-user-id="${u.id}">${iconSvg('alert-triangle', 'icon-sm')} Terminate Sessions</button>` : ''}
                ${u.username !== currentUser.username ? `<button class="btn btn-sm btn-danger delete-user-btn" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">${iconSvg('trash', 'icon-sm')} Delete</button>` : ''}
            </div>
        </div>`;
}

function toggleUserRow(id) {
    const open = usersView.expanded.has(id);
    if (open) usersView.expanded.delete(id); else usersView.expanded.add(id);
    const list = document.getElementById('users-list');
    if (!list) return;
    const row = list.querySelector(`.exp-row[data-id="${id}"]`);
    const det = list.querySelector(`.exp-detail[data-id="${id}"]`);
    if (row) row.classList.toggle('open', !open);
    if (det) det.classList.toggle('is-open', !open);
    if (!open) loadUserSshKeys(id);  // newly opened -> fetch this user's SSH keys
}

async function addUserToGroup(userId, groupId) {
    try {
        await apiRequest(`/groups/${groupId}/members`, { method: 'POST', body: JSON.stringify({ user_ids: [userId] }) });
        showSuccess('Added to department');
        await loadUsers();
    } catch (e) { showError('Failed to add to department: ' + e.message); }
}

async function removeUserFromGroup(userId, groupId) {
    try {
        await apiRequest(`/groups/${groupId}/members/${userId}`, { method: 'DELETE' });
        showSuccess('Removed from department');
        await loadUsers();
    } catch (e) { showError('Failed to remove from department: ' + e.message); }
}

// ---- Per-user SFTP access + SSH keys (inside the expandable user detail) ----

// Toggle one of the per-account SFTP flags. Updates the cached user in place so
// the row keeps its state without a full reload; reverts the checkbox on failure.
async function updateUserSftp(userId, field, value, cb) {
    try {
        await apiRequest(`/users/${userId}`, { method: 'PATCH', body: JSON.stringify({ [field]: value }) });
        const u = usersView.users.find(x => x.id === userId);
        if (u) u[field] = value;
        showSuccess('SFTP settings updated');
    } catch (e) {
        showError('Failed to update SFTP settings: ' + e.message);
        if (cb) cb.checked = !value; // revert on failure
    }
}

// Lazily fetch + render a user's SSH keys when their row is expanded.
// `root` scopes the DOM lookups so the same widget can appear in more than one place
// (the admin Users panel AND the self-service account modal) without colliding on
// `[data-user-id]` — the modal passes its own element so it never grabs the panel's inputs.
async function loadUserSshKeys(userId, root = document) {
    const host = root.querySelector(`.ssh-keys-list[data-user-id="${userId}"]`);
    if (!host) return;
    try {
        const keys = await apiRequest(`/users/${userId}/ssh-keys`, { silent: true });
        renderUserSshKeys(userId, Array.isArray(keys) ? keys : [], root);
    } catch (e) {
        host.replaceChildren();
        const msg = document.createElement('span');
        msg.className = 'text-tertiary text-sm';
        msg.textContent = 'Could not load SSH keys.';
        host.appendChild(msg);
    }
}

function renderUserSshKeys(userId, keys, root = document) {
    const host = root.querySelector(`.ssh-keys-list[data-user-id="${userId}"]`);
    if (!host) return;
    host.replaceChildren();
    if (!keys.length) {
        const none = document.createElement('span');
        none.className = 'text-tertiary text-sm';
        none.textContent = 'No SSH keys registered.';
        host.appendChild(none);
        return;
    }
    keys.forEach(k => {
        const item = document.createElement('div');
        item.className = 'ssh-key-item';
        const meta = document.createElement('span');
        meta.className = 'ssh-key-meta';
        meta.appendChild(svgUseIcon('key', 'icon-sm'));
        const nm = document.createElement('span');
        nm.className = 'ssh-key-name-text';
        nm.textContent = k.name;
        meta.appendChild(nm);
        const fp = document.createElement('span');
        fp.className = 'ssh-key-fp';
        fp.textContent = k.fingerprint;
        meta.appendChild(fp);
        item.appendChild(meta);
        const del = document.createElement('button');
        del.type = 'button';
        del.className = 'btn btn-sm btn-danger ssh-key-delete-btn';
        del.dataset.userId = userId;
        del.dataset.keyId = String(k.id);
        del.setAttribute('aria-label', `Remove SSH key ${k.name}`);
        del.appendChild(svgUseIcon('trash', 'icon-sm'));
        del.addEventListener('click', () => deleteSshKey(userId, k.id, k.name, root));
        item.appendChild(del);
        host.appendChild(item);
    });
}

async function addSshKey(userId, root = document) {
    const nameEl = root.querySelector(`.ssh-key-name[data-user-id="${userId}"]`);
    const pubEl = root.querySelector(`.ssh-key-public[data-user-id="${userId}"]`);
    const name = (nameEl?.value || '').trim();
    const publicKey = (pubEl?.value || '').trim();
    if (!name || !publicKey) {
        showError('Enter a label and an OpenSSH public key.');
        return;
    }
    try {
        await apiRequest(`/users/${userId}/ssh-keys`, { method: 'POST', body: JSON.stringify({ name, public_key: publicKey }) });
        if (nameEl) nameEl.value = '';
        if (pubEl) pubEl.value = '';
        showSuccess('SSH key added');
        await loadUserSshKeys(userId, root);
    } catch (e) {
        showError('Failed to add SSH key: ' + e.message);
    }
}

async function deleteSshKey(userId, keyId, keyName, root = document) {
    const confirmed = await showConfirm(
        `Remove SSH key “${keyName}”? Any SFTP session using it will lose access.`,
        'Remove SSH key?'
    );
    if (!confirmed) return;
    try {
        await apiRequest(`/users/${userId}/ssh-keys/${keyId}`, { method: 'DELETE' });
        showSuccess('SSH key removed');
        await loadUserSshKeys(userId, root);
    } catch (e) {
        showError('Failed to remove SSH key: ' + e.message);
    }
}

// ---- Self-service "Your account" modal --------------------------------------------------------
function _usShowError(msg) {
    const box = document.getElementById('us-error');
    if (box) { box.textContent = msg; box.style.display = ''; box.scrollIntoView({ block: 'nearest' }); }
}
function _usHideError() {
    const box = document.getElementById('us-error');
    if (box) { box.style.display = 'none'; box.textContent = ''; }
}

// Open the account modal for the CURRENT user. Credential-write sections are hidden for a temporary
// credential (the server rejects those writes too — this is UX, not the security boundary).
function openUserSettingsModal() {
    const modal = document.getElementById('user-settings-modal');
    if (!modal || !currentUser) return;
    _usHideError();
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
    set('us-username', currentUser.username || '');
    set('us-email-display', currentUser.email || '');
    set('us-role', currentUser.role === 'admin' ? 'Administrator' : (currentUser.role || 'User'));
    set('us-last-login', currentUser.last_login ? new Date(currentUser.last_login).toLocaleString() : '—');

    const isTemp = isScopedTemp || !!(sessionAccess && sessionAccess.is_scoped_temp);
    document.querySelectorAll('#user-settings-modal .us-credential').forEach(s => { s.style.display = isTemp ? 'none' : ''; });
    const note = document.getElementById('us-temp-note'); if (note) note.style.display = isTemp ? '' : 'none';

    if (!isTemp) {
        ['us-cur-pw', 'us-new-pw', 'us-new-pw2', 'us-new-email', 'us-email-cur-pw'].forEach(id => {
            const e = document.getElementById(id); if (e) e.value = '';
        });
        const se = document.getElementById('us-sftp-enabled'); if (se) se.checked = currentUser.sftp_enabled !== false;
        const sp = document.getElementById('us-sftp-pw-auth'); if (sp) sp.checked = currentUser.sftp_password_auth !== false;
        // Point the reusable SSH-key list/inputs at the current user, then load their keys —
        // scoped to the modal so they never collide with the admin Users panel's rows.
        modal.querySelectorAll('.ssh-keys-list, .ssh-key-name, .ssh-key-public')
            .forEach(el => el.setAttribute('data-user-id', String(currentUser.id)));
        loadUserSshKeys(currentUser.id, modal);
    }
    const tm = window.themeManager;
    const themeSel = document.getElementById('us-theme'); if (themeSel && tm) themeSel.value = (tm.currentTheme === 'dark') ? 'dark' : 'light';
    const skinSel = document.getElementById('us-skin'); if (skinSel && tm) skinSel.value = (tm.currentUi === 'v1') ? 'v1' : 'v2';

    document.querySelector('.profile-menu')?.classList.remove('active');  // close the dropdown
    openModal('user-settings-modal');
}

// Wire the account-modal form handlers once (idempotent via a flag).
let _usWired = false;
function wireUserSettingsModal() {
    if (_usWired) return;
    _usWired = true;
    document.getElementById('us-password-form')?.addEventListener('submit', async (e) => {
        e.preventDefault(); _usHideError();
        const cur = document.getElementById('us-cur-pw').value;
        const np = document.getElementById('us-new-pw').value;
        const np2 = document.getElementById('us-new-pw2').value;
        if (!cur) { _usShowError('Enter your current password.'); return; }
        if (!np) { _usShowError('Enter a new password.'); return; }
        if (np !== np2) { _usShowError('The new passwords do not match.'); return; }
        try {
            await apiRequest('/users/me', { method: 'PATCH', body: JSON.stringify({ current_password: cur, new_password: np }) });
            showSuccess('Password updated');
            ['us-cur-pw', 'us-new-pw', 'us-new-pw2'].forEach(id => { document.getElementById(id).value = ''; });
        } catch (err) { _usShowError(err.message || 'Could not update password.'); }
    });
    document.getElementById('us-email-form')?.addEventListener('submit', async (e) => {
        e.preventDefault(); _usHideError();
        const email = document.getElementById('us-new-email').value.trim();
        const cur = document.getElementById('us-email-cur-pw').value;
        if (!email) { _usShowError('Enter a new email address.'); return; }
        if (!cur) { _usShowError('Enter your current password.'); return; }
        try {
            const updated = await apiRequest('/users/me', { method: 'PATCH', body: JSON.stringify({ current_password: cur, email }) });
            if (updated && updated.email) { currentUser.email = updated.email; document.getElementById('us-email-display').textContent = updated.email; }
            showSuccess('Email updated');
            document.getElementById('us-email-cur-pw').value = '';
        } catch (err) { _usShowError(err.message || 'Could not update email.'); }
    });
    document.getElementById('us-sftp-save')?.addEventListener('click', async () => {
        _usHideError();
        const en = document.getElementById('us-sftp-enabled').checked;
        const pa = document.getElementById('us-sftp-pw-auth').checked;
        if (en === (currentUser.sftp_enabled !== false) && pa === (currentUser.sftp_password_auth !== false)) {
            showSuccess('No changes'); return;  // the endpoint 400s on a no-op change
        }
        try {
            const updated = await apiRequest('/users/me', { method: 'PATCH', body: JSON.stringify({ sftp_enabled: en, sftp_password_auth: pa }) });
            if (updated) { currentUser.sftp_enabled = updated.sftp_enabled; currentUser.sftp_password_auth = updated.sftp_password_auth; }
            showSuccess('SFTP options saved');
        } catch (err) { _usShowError(err.message || 'Could not save SFTP options.'); }
    });
    document.getElementById('us-ssh-add')?.addEventListener('click', () => {
        const modal = document.getElementById('user-settings-modal');
        if (currentUser && modal) addSshKey(currentUser.id, modal);
    });
    document.getElementById('us-theme')?.addEventListener('change', (e) => {
        if (window.themeManager) window.themeManager.applyTheme(e.target.value);
        if (window.saveUserPreference) window.saveUserPreference({ theme: e.target.value });
    });
    document.getElementById('us-skin')?.addEventListener('change', (e) => {
        // Delegate to themeManager.setUi — it persists to the server, then reloads (ui-boot.js
        // re-applies the skin pre-paint), handling the save/reload race for us.
        const v = e.target.value === 'v1' ? 'v1' : 'v2';
        if (window.themeManager && typeof window.themeManager.setUi === 'function') window.themeManager.setUi(v);
    });
}

// Attach event listeners for user actions
function attachUserListeners() {
    // Edit user buttons
    document.querySelectorAll('.edit-user-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const userId = btn.getAttribute('data-user-id');
            showEditUserModal(userId);
        });
    });
    
    // Lock user buttons
    document.querySelectorAll('.lock-user-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const userId = btn.getAttribute('data-user-id');
            await lockUser(userId);
        });
    });
    
    // Unlock user buttons
    document.querySelectorAll('.unlock-user-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const userId = btn.getAttribute('data-user-id');
            await unlockUser(userId);
        });
    });
    
    // Terminate sessions buttons
    document.querySelectorAll('.terminate-user-sessions-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const userId = btn.getAttribute('data-user-id');
            await terminateUserSessions(userId);
        });
    });
    
    // Change password buttons
    document.querySelectorAll('.change-password-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const userId = btn.getAttribute('data-user-id');
            showChangePasswordModal(userId);
        });
    });
    
    // Delete user buttons
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const userId = btn.getAttribute('data-user-id');
            const username = btn.getAttribute('data-username');
            await deleteUser(userId, username);
        });
    });

    // Manage permissions buttons (admin only)
    document.querySelectorAll('.manage-perms-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            openUserPermissionsModal(btn.getAttribute('data-user-id'), btn.getAttribute('data-username'));
        });
    });

    // Re-hydrate SSH-key lists for rows that are still expanded after a re-render.
    usersView.expanded.forEach(id => loadUserSshKeys(id));
}

// ---- Admin: per-user permission management --------------------------------
let permissionCatalog = null; // cached list of all functionality groups

async function openUserPermissionsModal(userId, username) {
    const modal = document.getElementById('user-permissions-modal');
    if (!modal) return;
    const titleEl = document.getElementById('user-permissions-title');
    if (titleEl) titleEl.innerHTML = `${iconSvg('shield')} Permissions — ${escapeHtml(username || '')}`;
    const body = document.getElementById('user-permissions-body');
    if (body) body.innerHTML = '<div class="spinner"></div>';
    modal.classList.add('active');
    try {
        if (!permissionCatalog) {
            permissionCatalog = await apiRequest('/permissions/groups');
        }
        const userPerms = await apiRequest(`/permissions/users/${userId}`);
        renderPermissionToggles(userId, userPerms);
    } catch (e) {
        if (body) body.innerHTML = `<div class="alert alert-error">Failed to load permissions: ${escapeHtml(e.message)}</div>`;
    }
}

function renderPermissionToggles(userId, userPerms) {
    const body = document.getElementById('user-permissions-body');
    if (!body) return;
    const granted = new Set(userPerms.granted_groups || []);
    const isAdminTarget = String(userPerms.role || '').toLowerCase().includes('admin');

    // Group the catalog by ui_section, preserving catalog order.
    const sections = [];
    const byName = {};
    permissionCatalog.forEach(g => {
        const sec = g.ui_section || 'Other';
        if (!byName[sec]) { byName[sec] = []; sections.push(sec); }
        byName[sec].push(g);
    });

    body.innerHTML = `
        ${isAdminTarget ? `<div class="alert alert-info mb-md">Administrators have every permission by role. Change the user's role to customize individual permissions.</div>` : ''}
        ${sections.map(sec => `
            <div class="perm-section">
                <div class="perm-section-title">${escapeHtml(sec)}</div>
                ${byName[sec].map(g => `
                    <label class="perm-row">
                        <input type="checkbox" class="perm-toggle" data-group="${g.name}" ${granted.has(g.name) ? 'checked' : ''} ${isAdminTarget ? 'disabled' : ''}>
                        <span class="perm-text">
                            <span class="perm-name">${escapeHtml(g.display_name)}</span>
                            <span class="perm-desc">${escapeHtml(g.description || '')}${g.dependencies && g.dependencies.length ? ` · needs ${g.dependencies.join(', ')}` : ''}</span>
                        </span>
                    </label>`).join('')}
            </div>`).join('')}`;

    body.querySelectorAll('.perm-toggle').forEach(cb => {
        cb.addEventListener('change', () => togglePermission(userId, cb.dataset.group, cb.checked, cb));
    });
}

async function togglePermission(userId, group, grant, cb) {
    try {
        if (grant) {
            await apiRequest(`/permissions/users/${userId}/grant`, { method: 'POST', body: JSON.stringify({ endpoint_group: group }) });
        } else {
            await apiRequest(`/permissions/users/${userId}/revoke/${group}`, { method: 'DELETE' });
        }
    } catch (e) {
        showError('Failed to update permission: ' + e.message);
        if (cb) cb.checked = !grant; // revert the toggle on failure
    }
}

// Show edit user modal
function showEditUserModal(userId) {
    // Find user data
    apiRequest(`/users/${userId}`)
        .then(user => {
            // Populate form with user data
            document.getElementById('edit-user-id').value = user.id;
            document.getElementById('edit-user-username').value = user.username;
            document.getElementById('edit-user-email').value = user.email;
            document.getElementById('edit-user-role').value = user.role;
            document.getElementById('edit-user-active').checked = user.is_active;
            
            // Show modal
            document.getElementById('edit-user-modal').classList.add('active');
        })
        .catch(error => {
            showError('Failed to load user: ' + error.message);
        });
}

// Lock user
async function lockUser(userId) {
    const confirmed = await showConfirm(
        'They will not be able to log in until unlocked.',
        'Lock this user?'
    );
    if (!confirmed) return;
    
    try {
        await apiRequest(`/users/${userId}`, { method: 'PATCH', body: JSON.stringify({ is_locked: true }) });
        showSuccess('User locked successfully');
        await loadUsers();
    } catch (error) {
        showError('Failed to lock user: ' + error.message);
    }
}

// Unlock user
async function unlockUser(userId) {
    try {
        await apiRequest(`/users/${userId}`, { method: 'PATCH', body: JSON.stringify({ is_locked: false }) });
        showSuccess('User unlocked successfully');
        await loadUsers();
    } catch (error) {
        showError('Failed to unlock user: ' + error.message);
    }
}

// Terminate user sessions
async function terminateUserSessions(userId) {
    const confirmed = await showConfirm(
        'Terminate all active sessions for this user?',
        'Confirm Terminate Sessions'
    );
    if (!confirmed) return;
    
    try {
        await apiRequest(`/users/${userId}/terminate-sessions`, { method: 'POST' });
        showSuccess('Sessions terminated successfully');
        await loadUsers();
    } catch (error) {
        showError('Failed to terminate sessions: ' + error.message);
    }
}

// Show change password modal
function showChangePasswordModal(userId) {
    document.getElementById('change-password-user-id').value = userId;
    document.getElementById('change-password-new').value = '';
    document.getElementById('change-password-confirm').value = '';
    document.getElementById('change-password-modal').classList.add('active');
}

// Delete user
async function deleteUser(userId, username) {
    const confirmed = await showConfirm(
        `This action cannot be undone. All user data will be permanently deleted.`,
        `Delete user "${username}"?`
    );
    if (!confirmed) return;
    
    // Double confirmation for admin users - require typing username
    const typedCorrectly = await showConfirm(
        `Type "${username}" to confirm deletion:`,
        'Confirm Deletion',
        username
    );
    if (!typedCorrectly) {
        showWarning('Deletion cancelled - username did not match');
        return;
    }
    
    try {
        await apiRequest(`/users/${userId}/delete`, { method: 'POST' });
        showSuccess('User deleted successfully');
        await loadUsers();
    } catch (error) {
        showError('Failed to delete user: ' + error.message);
    }
}

// Create User Modal
function showCreateUser() {
    document.getElementById('create-user-modal').classList.add('active');
}

document.getElementById('create-user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('new-username').value;
    const email = document.getElementById('new-email').value;
    const password = document.getElementById('new-password').value;
    const role = document.getElementById('new-role').value;
    
    try {
        await apiRequest('/users', {
            method: 'POST',
            body: JSON.stringify({
                username,
                email,
                password,
                role
            })
        });
        
        closeModal();
        document.getElementById('create-user-form').reset();
        loadUsers();
    } catch (error) {
        showError('Failed to create user: ' + error.message);
    }
});

// Toggle User Status
async function toggleUserStatus(userId, activate) {
    try {
        await apiRequest(`/users/${userId}`, {
            method: 'PATCH',
            body: JSON.stringify({
                is_active: activate
            })
        });
        loadUsers();
    } catch (error) {
        alert('Failed to update user: ' + error.message);
    }
}

// ============================================================================
// ROLES/GROUPS MANAGEMENT
// ============================================================================

// Load Groups & Roles view: department tree + role distribution overview.
const groupsView = { groups: [], users: [], selectedId: null };

async function loadGroups() {
    try {
        const [groups, users] = await Promise.all([
            apiRequest('/groups', { silent: true }).catch(() => []),
            apiRequest('/users')
        ]);
        groupsView.groups = Array.isArray(groups) ? groups : [];
        groupsView.users = users || [];
        renderGroupTree();
        if (groupsView.selectedId && groupsView.groups.some(g => g.id === groupsView.selectedId)) {
            openGroupDetail(groupsView.selectedId);
        } else {
            groupsView.selectedId = null;
            renderGroupDetailEmpty();
        }
    } catch (error) {
        console.error('Failed to load groups:', error);
    }
}

// Named department colours -> hex (also accepts a raw #hex for custom colours).
const CHIP_COLORS = { teal: '#14b8a6', indigo: '#6366f1', violet: '#8b5cf6', rose: '#f43f5e', orange: '#f97316', sky: '#0ea5e9', emerald: '#10b981', amber: '#f59e0b' };
// The returned value is interpolated into a `style="--chip:…"` attribute, so only ever hand back
// a strict #hex or a known preset — a raw `#`-prefixed value could carry a quote and break out of
// the attribute. Non-hex `#` input falls back to the default swatch.
const CHIP_HEX_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
function chipColorValue(color) {
    if (!color) return CHIP_COLORS.teal;
    if (color.charAt(0) === '#') return CHIP_HEX_RE.test(color) ? color : CHIP_COLORS.teal;
    return CHIP_COLORS[color] || CHIP_COLORS.teal;
}

// Render the nested department tree (groups bucketed by parent, indented by depth).
function renderGroupTree() {
    const el = document.getElementById('groups-tree');
    if (!el) return;
    const groups = groupsView.groups;
    if (!groups.length) {
        el.innerHTML = `<div class="text-tertiary text-sm p-sm">No departments yet. Click “New Group” to add one.</div>`;
        return;
    }
    const ids = new Set(groups.map(g => g.id));
    const byParent = {};
    groups.forEach(g => {
        const key = (g.parent_id && ids.has(g.parent_id)) ? g.parent_id : 'root';
        (byParent[key] = byParent[key] || []).push(g);
    });
    const renderNodes = (key, depth) => {
        const nodes = (byParent[key] || []).slice().sort((a, b) => a.name.localeCompare(b.name));
        return nodes.map(g => `
            <button class="tree-node${groupsView.selectedId === g.id ? ' active' : ''}" data-group-id="${g.id}" style="--depth:${depth}">
                <span class="tree-dot" style="--chip:${chipColorValue(g.color)}"></span>
                <span class="tree-name">${escapeHtml(g.name)}</span>
                <span class="tree-count">${g.member_count}</span>
            </button>
            ${renderNodes(g.id, depth + 1)}
        `).join('');
    };
    el.innerHTML = renderNodes('root', 0);
}

// Build the breadcrumb name path for a group by walking parent links.
function groupPath(id) {
    const byId = {};
    groupsView.groups.forEach(g => { byId[g.id] = g; });
    const names = [];
    let cur = byId[id];
    const seen = new Set();
    while (cur && !seen.has(cur.id)) {
        seen.add(cur.id);
        names.unshift(cur.name);
        cur = (cur.parent_id && byId[cur.parent_id]) ? byId[cur.parent_id] : null;
    }
    return names;
}

function renderGroupDetailEmpty() {
    const el = document.getElementById('group-detail');
    if (el) el.innerHTML = `
        <div class="empty-state text-center p-xl text-secondary">
            <div style="font-size:3rem;">${iconSvg('users', 'icon-lg')}</div>
            <p class="mt-sm">Select a department to manage its members, or create a new one.</p>
        </div>`;
}

async function openGroupDetail(id) {
    groupsView.selectedId = id;
    renderGroupTree();
    const el = document.getElementById('group-detail');
    if (!el) return;
    el.innerHTML = '<div class="spinner"></div>';
    try {
        const g = await apiRequest(`/groups/${id}`);
        const path = groupPath(id);
        const memberIds = new Set(g.members.map(m => m.id));
        groupsView.currentMemberIds = memberIds;
        el.innerHTML = `
            <div class="group-detail-head">
                <div class="min-w-0">
                    <div class="group-breadcrumb">${path.map(p => escapeHtml(p)).join(' <span class="sep">/</span> ')}</div>
                    <h3 class="group-detail-title"><span class="tree-dot" style="--chip:${chipColorValue(g.color)}"></span>${escapeHtml(g.name)}</h3>
                    ${g.description ? `<p class="text-secondary">${escapeHtml(g.description)}</p>` : ''}
                </div>
                <div class="flex gap-sm">
                    <button class="btn btn-sm btn-secondary" id="group-edit-btn">${iconSvg('edit', 'icon-sm')} Edit</button>
                    <button class="btn btn-sm btn-secondary" id="group-subgroup-btn">${iconSvg('plus', 'icon-sm')} Sub-group</button>
                    <button class="btn btn-sm btn-danger" id="group-delete-btn">${iconSvg('trash', 'icon-sm')} Delete</button>
                </div>
            </div>
            <div class="group-stats">
                <span class="meta-item">${iconSvg('users', 'icon-sm')}<span class="meta-label">Members</span><span class="meta-value">${g.member_count}</span></span>
                <span class="meta-item">${iconSvg('folder', 'icon-sm')}<span class="meta-label">Sub-groups</span><span class="meta-value">${g.child_count}</span></span>
            </div>
            ${g.children.length ? `<div class="chip-row mb-sm">${g.children.map(c => `<button class="chip tree-jump" style="--chip:${chipColorValue(c.color)}" data-group-id="${c.id}">${escapeHtml(c.name)} · ${c.member_count}</button>`).join('')}</div>` : ''}
            <div class="flex justify-between items-center mt-md mb-sm">
                <div class="detail-label" style="margin:0;">Members</div>
                <button class="btn btn-sm btn-secondary" id="group-add-members-btn">${iconSvg('plus', 'icon-sm')} Add members</button>
            </div>
            <div class="member-list">
                ${g.members.length ? g.members.map(m => `
                    <div class="member-row">
                        <span class="avatar-sm">${(m.username || '?').substring(0, 2).toUpperCase()}</span>
                        <div class="cell-user-text"><span class="cell-user-name">${escapeHtml(m.username)}</span><span class="cell-user-sub">${escapeHtml(m.email || '')}</span></div>
                        <span class="badge badge-${m.role}">${m.role}</span>
                        <button class="btn btn-sm btn-ghost member-remove" data-user-id="${m.id}" title="Remove from department">${iconSvg('x', 'icon-sm')}</button>
                    </div>`).join('') : '<div class="text-tertiary text-sm p-sm">No members yet.</div>'}
            </div>`;
        document.getElementById('group-edit-btn').onclick = () => openGroupModal(g);
        document.getElementById('group-delete-btn').onclick = () => deleteGroup(g);
        document.getElementById('group-subgroup-btn').onclick = () => openGroupModal(null, g.id);
        document.getElementById('group-add-members-btn').onclick = () => openAddMembersModal(id);
        el.querySelectorAll('.member-remove').forEach(b => { b.onclick = () => removeGroupMember(id, b.dataset.userId); });
        el.querySelectorAll('.tree-jump').forEach(b => { b.onclick = () => openGroupDetail(b.dataset.groupId); });
    } catch (e) {
        el.innerHTML = `<div class="alert alert-error">Failed to load department: ${escapeHtml(e.message)}</div>`;
    }
}

async function addGroupMember(groupId, userId) {
    try {
        await apiRequest(`/groups/${groupId}/members`, { method: 'POST', body: JSON.stringify({ user_ids: [userId] }) });
        showSuccess('Member added');
        await loadGroups();
    } catch (e) { showError('Failed to add member: ' + e.message); }
}

async function removeGroupMember(groupId, userId) {
    try {
        await apiRequest(`/groups/${groupId}/members/${userId}`, { method: 'DELETE' });
        showSuccess('Member removed');
        await loadGroups();
    } catch (e) { showError('Failed to remove member: ' + e.message); }
}

// --- Searchable "Add members" modal (scales past a dropdown) ----------------
const addMembersState = { groupId: null };

function openAddMembersModal(groupId) {
    addMembersState.groupId = groupId;
    const modal = document.getElementById('add-members-modal');
    if (!modal) return;
    const search = document.getElementById('add-members-search');
    if (search) search.value = '';
    renderAddMembersList('');
    modal.classList.add('active');
    setTimeout(() => search && search.focus(), 60);
}

function renderAddMembersList(query) {
    const listEl = document.getElementById('add-members-list');
    if (!listEl) return;
    const q = (query || '').trim().toLowerCase();
    const inGroup = groupsView.currentMemberIds || new Set();
    const addable = groupsView.users.filter(u =>
        !inGroup.has(u.id) &&
        (!q || u.username.toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q))
    );
    if (!addable.length) {
        listEl.innerHTML = `<div class="text-tertiary text-sm p-sm">${groupsView.users.length === (inGroup.size) ? 'Everyone is already a member.' : 'No users match your search.'}</div>`;
        updateAddMembersCount();
        return;
    }
    listEl.innerHTML = addable.map(u => `
        <label class="pick-row">
            <input type="checkbox" value="${u.id}">
            <span class="avatar-sm">${(u.username || '?').substring(0, 2).toUpperCase()}</span>
            <div class="cell-user-text"><span class="cell-user-name">${escapeHtml(u.username)}</span><span class="cell-user-sub">${escapeHtml(u.email || '')}</span></div>
            <span class="badge badge-${u.role}">${u.role}</span>
        </label>`).join('');
    updateAddMembersCount();
}

function updateAddMembersCount() {
    const n = document.querySelectorAll('#add-members-list input:checked').length;
    const countEl = document.getElementById('add-members-count');
    if (countEl) countEl.textContent = n ? `${n} selected` : '';
    const confirmBtn = document.getElementById('add-members-confirm');
    if (confirmBtn) confirmBtn.disabled = n === 0;
}

async function confirmAddMembers() {
    const ids = Array.from(document.querySelectorAll('#add-members-list input:checked')).map(c => c.value);
    if (!ids.length || !addMembersState.groupId) return;
    try {
        await apiRequest(`/groups/${addMembersState.groupId}/members`, { method: 'POST', body: JSON.stringify({ user_ids: ids }) });
        showSuccess(`Added ${ids.length} member(s)`);
        closeModal();
        await loadGroups();
    } catch (e) { showError('Failed to add members: ' + e.message); }
}

async function deleteGroup(g) {
    const confirmed = await showConfirm(
        `Delete department “${g.name}”? Members are kept; any sub-groups move up to its parent.`,
        'Delete department?'
    );
    if (!confirmed) return;
    try {
        await apiRequest(`/groups/${g.id}`, { method: 'DELETE' });
        showSuccess('Department deleted');
        if (groupsView.selectedId === g.id) groupsView.selectedId = null;
        await loadGroups();
    } catch (e) { showError('Failed to delete department: ' + e.message); }
}

// Populate the parent <select> in the group modal (cannot parent a group to itself).
function populateGroupParentSelect(excludeId) {
    const sel = document.getElementById('group-parent');
    if (!sel) return;
    const opts = groupsView.groups
        .filter(g => g.id !== excludeId)
        .slice().sort((a, b) => a.name.localeCompare(b.name))
        .map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`)
        .join('');
    sel.innerHTML = `<option value="">— None (top level) —</option>${opts}`;
}

// Reflect the chosen colour on the modal swatches + hidden input. Accepts a
// named preset ('indigo') or a custom #hex from the colour picker.
function setGroupColor(color) {
    const hidden = document.getElementById('group-color');
    if (hidden) hidden.value = color || '';
    document.querySelectorAll('#group-color-swatches .accent-swatch').forEach(s => {
        s.classList.toggle('selected', (s.getAttribute('data-color') || '') === (color || ''));
    });
    const custom = document.getElementById('group-color-custom');
    if (custom && color && color.charAt(0) === '#') custom.value = color;
}

// Open the create/edit modal. group=null + parentId => create (optionally nested).
function openGroupModal(group, parentId) {
    const modal = document.getElementById('group-modal');
    if (!modal) return;
    document.getElementById('group-id').value = group ? group.id : '';
    document.getElementById('group-name').value = group ? group.name : '';
    document.getElementById('group-desc').value = group ? (group.description || '') : '';
    document.getElementById('group-modal-title').innerHTML = group
        ? `${iconSvg('edit')} Edit Group`
        : `${iconSvg('users')} New Group`;
    document.getElementById('group-save-btn').textContent = group ? 'Save Changes' : 'Create Group';
    populateGroupParentSelect(group ? group.id : null);
    document.getElementById('group-parent').value = group ? (group.parent_id || '') : (parentId || '');
    setGroupColor(group ? (group.color || '') : '');
    modal.classList.add('active');
}

async function submitGroupForm(e) {
    e.preventDefault();
    const id = document.getElementById('group-id').value;
    const name = document.getElementById('group-name').value.trim();
    const description = document.getElementById('group-desc').value.trim();
    const parent = document.getElementById('group-parent').value;
    const color = document.getElementById('group-color').value;
    if (!name) { showError('Group name is required'); return; }
    const body = { name, description: description || null, color: color || null, parent_id: parent || null };
    try {
        const saved = id
            ? await apiRequest(`/groups/${id}`, { method: 'PATCH', body: JSON.stringify(body) })
            : await apiRequest('/groups', { method: 'POST', body: JSON.stringify(body) });
        showSuccess(id ? 'Department updated' : 'Department created');
        closeModal();
        if (saved && saved.id) groupsView.selectedId = saved.id;
        await loadGroups();
    } catch (err) {
        showError('Failed to save department: ' + err.message);
    }
}

// (Legacy renderRolesUsersTable/attachRolesListeners removed — the Groups & Roles
//  view now uses loadGroups() above; role changes happen via the Users page edit.)

// ============================================================================
// LIVE MONITOR
// ============================================================================

let monitorWebSocket = null;
let monitorReconnectTimer = null;   // single pending reconnect timer (coalesced; never stacks)
let monitorEvents = [];
let monitorCurrentFilter = 'all';
let monitorMetrics = {
    activeUsers: 0,
    eventsRate: 0,
    activeSessions: 0,
    totalEvents: 0
};

// Initialize Live Monitor
function initMonitor() {
    console.log('🔴 Initializing Live Monitor...');
    
    // Reset events
    monitorEvents = [];
    updateMonitorUI();
    
    // Connect to WebSocket for real-time events
    connectMonitorWebSocket();
    
    // Attach event listeners
    attachMonitorListeners();
    
    // Fetch initial statistics
    fetchMonitorStats();
}

// Schedule at most ONE pending reconnect. Any newer schedule (or a direct connect) cancels the prior
// timer, so repeated failures across the several entry points (init, reconnect button, onclose, and a
// WebSocket-constructor throw) can't stack into a burst of connection attempts.
function scheduleMonitorReconnect() {
    clearTimeout(monitorReconnectTimer);
    monitorReconnectTimer = setTimeout(() => {
        monitorReconnectTimer = null;
        if (authToken) connectMonitorWebSocket();
    }, 5000);
}

// Connect to WebSocket
function connectMonitorWebSocket() {
    // A direct (re)connect supersedes any pending auto-reconnect — don't let them stack.
    clearTimeout(monitorReconnectTimer);
    monitorReconnectTimer = null;
    // Close existing connection if any
    if (monitorWebSocket) {
        monitorWebSocket.close();
    }
    
    // Determine WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/monitor`;
    
    console.log('Connecting to WebSocket:', wsUrl);
    updateMonitorStatus('connecting', 'Connecting...');
    
    try {
        // Capture this specific socket so its handlers can tell whether they still belong to the
        // current connection: connect() may close a live socket and immediately open a new one, and a
        // close/open handshake has no ordering guarantee — a stale event from a superseded socket must
        // not touch shared state (re-arm the reconnect, flash "Disconnected") for the live one.
        const ws = new WebSocket(wsUrl);
        monitorWebSocket = ws;

        ws.onopen = () => {
            if (monitorWebSocket !== ws) return;   // superseded by a newer connect
            console.log('✓ WebSocket connected');
            // Connected — cancel any pending reconnect scheduled by a prior close/error.
            clearTimeout(monitorReconnectTimer);
            monitorReconnectTimer = null;
            updateMonitorStatus('connected', 'Connected');

            // Send authentication token
            if (authToken) {
                ws.send(JSON.stringify({
                    type: 'auth',
                    token: authToken
                }));
            }
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleMonitorEvent(data);
            } catch (error) {
                console.error('Failed to parse WebSocket message:', error);
            }
        };

        ws.onerror = (error) => {
            if (monitorWebSocket !== ws) return;   // superseded by a newer connect
            console.error('WebSocket error:', error);
            updateMonitorStatus('error', 'Connection Error');
        };

        ws.onclose = () => {
            // A stale close from a socket we've already replaced must not re-arm the reconnect (it
            // would tear down the healthy replacement 5s later) or flash a false "Disconnected".
            if (monitorWebSocket !== ws) return;
            console.log('WebSocket closed');
            updateMonitorStatus('disconnected', 'Disconnected');

            // Auto-reconnect while logged in (the socket is app-wide so the owner
            // keeps receiving temp-credential login notifications on any page).
            scheduleMonitorReconnect();
        };

    } catch (error) {
        console.error('Failed to create WebSocket:', error);
        updateMonitorStatus('error', 'Reconnecting…');
        // The live event feed is WebSocket-only; retry the connection shortly (mirrors the
        // onclose reconnect) rather than polling a non-existent endpoint.
        scheduleMonitorReconnect();
    }
}

// Handle incoming monitor event
function handleMonitorEvent(data) {
    // Event types: login, logout, upload, download, vault_access, temp_cred_created, temp_cred_used, error
    // Server broadcasts wrap the event under `event`; unwrap for inspection.
    const ev = (data && data.event) ? data.event : data;

    // Owner notification: a temporary credential I created just signed in.
    if (ev && ev.type === 'login' && ev.is_temporary && currentUser &&
        String(ev.owner_user_id) === String(currentUser.id)) {
        showWarning(`Temporary credential ${ev.temp_username || ''} just signed in${ev.ip ? ' from ' + ev.ip : ''}`.trim());
    }

    if (data.type === 'stats') {
        // Update metrics
        monitorMetrics.activeUsers = data.active_users || 0;
        monitorMetrics.activeSessions = data.active_sessions || 0;
        updateMonitorMetrics();
        return;
    }
    
    // Add event to list
    const event = {
        id: Date.now() + Math.random(),
        timestamp: data.timestamp || new Date().toISOString(),
        type: data.type || 'unknown',
        user: data.user || 'System',
        message: data.message || '',
        details: data.details || {},
        icon: getEventIcon(data.type)
    };
    
    monitorEvents.unshift(event); // Add to beginning
    
    // Keep only last 100 events
    if (monitorEvents.length > 100) {
        monitorEvents = monitorEvents.slice(0, 100);
    }
    
    // Update metrics
    monitorMetrics.totalEvents = monitorEvents.length;
    
    // Calculate events per minute (count events in last minute)
    const oneMinuteAgo = new Date(Date.now() - 60000).toISOString();
    const recentEvents = monitorEvents.filter(e => e.timestamp > oneMinuteAgo);
    monitorMetrics.eventsRate = recentEvents.length;
    
    // Update UI
    updateMonitorUI();
}

// Get icon for event type (returns inline SVG markup from the sprite)
function getEventIcon(type) {
    const icons = {
        'login': 'login',
        'logout': 'logout',
        'upload': 'upload',
        'download': 'download',
        'vault_access': 'unlock',
        'vault_created': 'vault',
        'temp_cred_created': 'clock',
        'temp_cred_used': 'check',
        'temp_cred_expired': 'clock',
        'user_created': 'user',
        'user_deleted': 'trash',
        'error': 'alert-triangle',
        'warning': 'alert-triangle',
        'info': 'info'
    };
    return iconSvg(icons[type] || 'activity');
}

// Update monitor status indicator
function updateMonitorStatus(status, text) {
    const dot = document.getElementById('monitor-status-dot');
    const statusText = document.getElementById('monitor-status-text');
    const reconnectBtn = document.getElementById('monitor-reconnect-btn');
    
    if (!dot || !statusText) return;
    
    const colors = {
        'connected': '#10b981',
        'connecting': '#f59e0b',
        'disconnected': '#6b7280',
        'error': '#ef4444',
        'polling': '#3b82f6'
    };
    
    dot.style.background = colors[status] || colors.disconnected;
    statusText.textContent = text;
    
    // Show reconnect button if disconnected or error
    if (reconnectBtn) {
        reconnectBtn.style.display = (status === 'disconnected' || status === 'error') ? 'block' : 'none';
    }
}

// Update monitor metrics display
function updateMonitorMetrics() {
    document.getElementById('monitor-active-users').textContent = monitorMetrics.activeUsers;
    document.getElementById('monitor-events-rate').textContent = monitorMetrics.eventsRate;
    document.getElementById('monitor-total-events').textContent = `${monitorMetrics.totalEvents} total`;
    document.getElementById('monitor-active-sessions').textContent = monitorMetrics.activeSessions;
    
    const sessionInfo = monitorMetrics.activeSessions > 0 
        ? `${monitorMetrics.activeSessions} active` 
        : 'No activity';
    document.getElementById('monitor-session-info').textContent = sessionInfo;
}

// Update monitor UI
function updateMonitorUI() {
    updateMonitorMetrics();
    
    const eventsList = document.getElementById('monitor-events-list');
    const eventCount = document.getElementById('monitor-event-count');
    
    if (!eventsList) return;
    
    // Filter events
    const filteredEvents = monitorCurrentFilter === 'all' 
        ? monitorEvents 
        : monitorEvents.filter(e => e.type === monitorCurrentFilter);
    
    // Update count
    if (eventCount) {
        eventCount.textContent = `${filteredEvents.length} events`;
    }
    
    // Render events
    if (filteredEvents.length === 0) {
        eventsList.innerHTML = `
            <div class="text-center py-xl text-secondary">
                <div style="font-size: 3rem; margin-bottom: 1rem;">${iconSvg('activity', 'icon-lg')}</div>
                <p class="font-semibold mb-xs">No events yet</p>
                <p class="text-sm">Waiting for ${monitorCurrentFilter === 'all' ? 'events' : monitorCurrentFilter + ' events'}...</p>
            </div>
        `;
        return;
    }
    
    eventsList.innerHTML = filteredEvents.map(event => {
        const time = new Date(event.timestamp);
        const timeStr = time.toLocaleTimeString();
        
        // Event type badge color
        const typeColors = {
            'login': 'success',
            'logout': 'secondary',
            'upload': 'primary',
            'download': 'info',
            'vault_access': 'warning',
            'error': 'danger'
        };
        const badgeClass = typeColors[event.type] || 'secondary';
        
        return `
            <div class="monitor-event-item" style="border-left: 4px solid var(--${badgeClass}); padding: 1rem; margin-bottom: 0.5rem; background: var(--surface-1); border-radius: 8px;">
                <div class="flex items-start gap-md">
                    <span style="font-size: 1.5rem;">${event.icon}</span>
                    <div class="flex-1">
                        <div class="flex items-center gap-md mb-xs">
                            <span class="font-semibold">${escapeHtml(event.user)}</span>
                            <span class="badge badge-${badgeClass}">${escapeHtml(event.type.replace('_', ' '))}</span>
                            <span class="text-xs text-secondary ml-auto">${timeStr}</span>
                        </div>
                        <p class="text-sm text-secondary">${escapeHtml(event.message || `${event.type} event`)}</p>
                        ${Object.keys(event.details).length > 0 ? `
                            <div class="text-xs text-secondary mt-xs">
                                ${Object.entries(event.details).map(([key, value]) =>
                                    `<span class="mr-md">${escapeHtml(key)}: ${escapeHtml(String(value))}</span>`
                                ).join('')}
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Fetch monitor statistics
async function fetchMonitorStats() {
    try {
        const stats = await apiRequest('/monitor/stats', { silent: true });
        
        monitorMetrics.activeUsers = stats.active_users || 0;
        monitorMetrics.activeSessions = stats.active_sessions || 0;
        
        updateMonitorMetrics();
    } catch (error) {
        console.log('Monitor stats endpoint not available');
        // Use defaults if endpoint doesn't exist
        monitorMetrics.activeUsers = 0;
        monitorMetrics.activeSessions = 0;
        updateMonitorMetrics();
    }
}

// Attach monitor event listeners
function attachMonitorListeners() {
    // Event filter buttons
    document.querySelectorAll('.event-filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            // Update active state
            document.querySelectorAll('.event-filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update filter
            monitorCurrentFilter = btn.dataset.type;
            updateMonitorUI();
        });
    });
    
    // Clear events button
    const clearBtn = document.getElementById('monitor-clear-events');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            const confirmed = await showConfirm(
                'This will clear all events from the monitor.',
                'Clear all events?'
            );
            if (confirmed) {
                monitorEvents = [];
                monitorMetrics.totalEvents = 0;
                updateMonitorUI();
                showSuccess('Monitor events cleared');
            }
        });
    }
    
    // Reconnect button
    const reconnectBtn = document.getElementById('monitor-reconnect-btn');
    if (reconnectBtn) {
        reconnectBtn.addEventListener('click', () => {
            connectMonitorWebSocket();
        });
    }
}

// Cleanup monitor on navigation away
function cleanupMonitor() {
    if (monitorWebSocket) {
        monitorWebSocket.close();
        monitorWebSocket = null;
    }
}

// ============================================================================
// SETTINGS
// ============================================================================

let currentSettings = {};
let settingsAllGroups = [];          // all departments, backing the policy pickers
let sftpRequireTempCredGroups = [];  // selected department ids (string UUIDs); persisted on Save
let standardVaultAllowedGroups = []; // departments exempt from force-zero-knowledge
let settingsGroupsLoaded = false;    // did GET /groups succeed? guards against wiping the policy

// Initialize Settings
async function initSettings() {
    console.log('⚙️ Initializing Settings...');
    
    // Setup tab switching
    setupSettingsTabs();
    setupLogAccess();  // log-access tab wiring

    // Wire the branding color pickers <-> text inputs + logo/favicon uploads
    wireBrandColorInputs();
    wireBrandAssetUploads();

    // Load current settings
    await loadSettings();
    loadLogSettings();  // silent; no-op for non-admins
    
    // Attach event listeners
    attachSettingsListeners();
    
    // Load storage statistics
    loadStorageStats();
    
    // Load users for audit filter
    loadAuditFilterUsers();
}

// A3 — Branding editor: maps each Settings brand input id to its /settings +
// /branding key. Editing these persists an override into SystemSetting('brand')
// (mirrored server-side) so /branding and the rendered shell update live.
const BRAND_SETTING_FIELDS = {
    'setting-brand-full-name': 'app_full_name',
    'setting-brand-tagline': 'app_tagline',
    'setting-brand-company-name': 'company_name',
    'setting-brand-support-email': 'support_email',
    'setting-brand-copyright-holder': 'copyright_holder',
    'setting-brand-company-url': 'company_url',
    'setting-brand-website-url': 'website_url',
    'setting-brand-docs-url': 'docs_url',
    'setting-brand-primary-color': 'primary_color',
    'setting-brand-secondary-color': 'secondary_color',
    'setting-brand-accent-color': 'accent_color',
    'setting-brand-success-color': 'success_color',
    'setting-brand-warning-color': 'warning_color',
    'setting-brand-error-color': 'error_color',
    'setting-brand-text-color': 'text_color',
    'setting-brand-background-color': 'background_color',
};
// text-input id -> its /branding.colors[...] CSS-var key (for placeholder + swatch)
const BRAND_COLOR_VARS = {
    'setting-brand-primary-color': '--primary-color',
    'setting-brand-secondary-color': '--secondary-color',
    'setting-brand-accent-color': '--accent-color',
    'setting-brand-success-color': '--success-color',
    'setting-brand-warning-color': '--warning-color',
    'setting-brand-error-color': '--error-color',
    'setting-brand-text-color': '--text-color',
    'setting-brand-background-color': '--background-color',
};
const HEX_COLOR_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;

// The native <input type="color"> only accepts #rrggbb; expand a valid #rgb.
function expandHex(v) {
    if (!v) return null;
    const s = v.trim();
    if (!HEX_COLOR_RE.test(s)) return null;
    if (s.length === 4) return '#' + s[1] + s[1] + s[2] + s[2] + s[3] + s[3];
    return s.toLowerCase();
}

// Two-way sync each color text input with its <input type="color"> companion.
// The text input is the source of truth (it can be empty = "use the default");
// the picker is a convenience. Attached once at Settings init.
function wireBrandColorInputs() {
    Object.keys(BRAND_COLOR_VARS).forEach(textId => {
        const text = document.getElementById(textId);
        const pick = document.getElementById(textId + '-pick');
        if (!text || !pick) return;
        pick.addEventListener('input', () => { text.value = pick.value; });
        text.addEventListener('input', () => {
            const hex = expandHex(text.value);
            if (hex) pick.value = hex;
        });
    });
}

// Populate the brand inputs from the stored overrides (settings) and use the
// effective /branding values as informative placeholders + initial picker colors.
async function applyBrandFields(settings) {
    for (const [elId, key] of Object.entries(BRAND_SETTING_FIELDS)) {
        const el = document.getElementById(elId);
        if (el) el.value = settings[key] || '';
    }
    let brand = null;
    try {
        brand = await apiRequest('/branding', { method: 'GET', silent: true });
    } catch (_) { /* /branding is best-effort for placeholders; ignore */ }
    if (!brand) return;
    // text/url/email placeholders = the current effective value
    const textPlaceholders = {
        'setting-brand-full-name': brand.app_full_name,
        'setting-brand-tagline': brand.app_tagline,
        'setting-brand-company-name': brand.company_name,
        'setting-brand-support-email': brand.support_email,
        'setting-brand-company-url': brand.company_url,
        'setting-brand-website-url': brand.website_url,
        'setting-brand-docs-url': brand.docs_url,
    };
    for (const [elId, val] of Object.entries(textPlaceholders)) {
        const el = document.getElementById(elId);
        if (el && val) el.placeholder = val;
    }
    // colors: placeholder + set the picker to the override (if any) else the effective
    const colors = brand.colors || {};
    for (const [textId, varKey] of Object.entries(BRAND_COLOR_VARS)) {
        const text = document.getElementById(textId);
        const pick = document.getElementById(textId + '-pick');
        const eff = colors[varKey];
        if (text && eff) text.placeholder = eff;
        if (pick) {
            const hex = expandHex(text && text.value) || expandHex(eff);
            if (hex) pick.value = hex;
        }
    }
    // asset previews show the current effective logo / favicon
    const assets = brand.assets || {};
    setBrandPreview('brand-logo-preview', assets.logo_small || assets.logo);
    setBrandPreview('brand-favicon-preview', assets.favicon);
}

// A4 — brand asset (logo/favicon) upload. safeAssetUrl mirrors brand.js::safeUrl so a
// hostile stored URL never becomes a live src; <img> never executes it either, this is
// defence in depth. The text of a status line is set via textContent only.
function safeAssetUrl(u) {
    // Mirrors static/js/brand.js::safeUrl: allow only a same-origin path or an
    // absolute http(s) URL; reject backslash + control chars (no regex control-char
    // literals here on purpose). <img>.src never executes it either -- defence in depth.
    if (typeof u !== 'string') return null;
    const s = u.trim();
    if (!s) return null;
    for (let i = 0; i < s.length; i++) {
        if (s.charCodeAt(i) < 0x20 || s.charAt(i) === '\\') return null;
    }
    if (s.charAt(0) === '/' && s.charAt(1) !== '/') return s;
    const low = s.toLowerCase();
    if (low.startsWith('http://') || low.startsWith('https://')) return s;
    return null;
}
function setBrandPreview(id, url, bust) {
    const img = document.getElementById(id);
    if (!img) return;
    const safe = safeAssetUrl(url);
    if (!safe) { img.removeAttribute('src'); return; }
    img.src = bust ? safe + (safe.includes('?') ? '&' : '?') + 't=' + Date.now() : safe;
}
function _brandStatus(slot, msg, isError) {
    const el = document.getElementById(`brand-${slot}-status`);
    if (!el) return;
    el.textContent = msg;
    el.style.color = isError ? 'var(--error-color, #ef4444)' : 'var(--text-secondary, inherit)';
}
async function uploadBrandAsset(slot) {
    const input = document.getElementById(`brand-${slot}-file`);
    const file = input && input.files && input.files[0];
    if (!file) { _brandStatus(slot, 'Choose a file first.', true); return; }
    _brandStatus(slot, 'Uploading…', false);
    const form = new FormData();
    form.append('file', file);
    try {
        // multipart: let the browser set Content-Type (+ boundary); apiRequest forces JSON.
        const headers = {};
        if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
        const resp = await fetch(`${API_BASE}/settings/brand/asset/${slot}`,
            { method: 'POST', headers, body: form });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.detail || `Upload failed (${resp.status})`);
        setBrandPreview(`brand-${slot}-preview`, data.url, true);
        if (input) input.value = '';
        _brandStatus(slot, 'Uploaded. Reload to apply site-wide.', false);
    } catch (e) {
        _brandStatus(slot, e.message || 'Upload failed', true);
    }
}
async function resetBrandAsset(slot) {
    _brandStatus(slot, 'Resetting…', false);
    try {
        await apiRequest(`/settings/brand/asset/${slot}`, { method: 'DELETE' });
        const brand = await apiRequest('/branding', { method: 'GET', silent: true }).catch(() => null);
        const assets = (brand && brand.assets) || {};
        const url = slot === 'favicon' ? assets.favicon : (assets.logo_small || assets.logo);
        setBrandPreview(`brand-${slot}-preview`, url, true);
        const input = document.getElementById(`brand-${slot}-file`);
        if (input) input.value = '';
        _brandStatus(slot, 'Reset to default.', false);
    } catch (e) {
        _brandStatus(slot, e.message || 'Reset failed', true);
    }
}
// Attach the logo/favicon Upload + Reset buttons (once, at Settings init).
function wireBrandAssetUploads() {
    ['logo', 'favicon'].forEach(slot => {
        const up = document.getElementById(`brand-${slot}-upload`);
        const rs = document.getElementById(`brand-${slot}-reset`);
        if (up) up.addEventListener('click', () => uploadBrandAsset(slot));
        if (rs) rs.addEventListener('click', () => resetBrandAsset(slot));
    });
}

// Setup settings tabs
function setupSettingsTabs() {
    const tabButtons = document.querySelectorAll('.tabs .tab-btn');
    const tabContents = document.querySelectorAll('.settings-tab-content');
    
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all buttons and contents
            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Add active class to clicked button and corresponding content
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            const content = document.getElementById(`settings-tab-${tabId}`);
            if (content) {
                content.classList.add('active');
            }
            if (tabId === 'logs') { loadLogSettings(); }  // refresh on tab open
        });
    });
}

// ---- Log access (admin Settings tab) ---------------------------------------------
const LOG_COMPONENT_LABELS = {
    'web': 'Web / API', 'sftp': 'SFTP',
    'db-diag': 'DB diagnostics', 'redis-diag': 'Redis diagnostics',
};

function setupLogAccess() {
    const gen = document.getElementById('log-token-generate-btn');
    const create = document.getElementById('log-token-create-btn');
    const cancel = document.getElementById('log-token-cancel-btn');
    if (gen) gen.addEventListener('click', () => toggleLogTokenGenerate(true));
    if (create) create.addEventListener('click', generateLogToken);
    if (cancel) cancel.addEventListener('click', () => toggleLogTokenGenerate(false));
    const stealth = document.getElementById('log-stealth-toggle');
    if (stealth) stealth.addEventListener('change', () => saveLogStealth(stealth.checked));
}

async function loadLogSettings() {
    let data;
    try {
        data = await apiRequest('/settings/logs', { silent: true });
    } catch (e) { return; }               // non-admin / feature absent -> leave the tab inert
    if (!data || !Array.isArray(data.components)) return;
    window._logSettings = data;
    const note = document.getElementById('log-ceiling-note');
    if (note) {
        if (!data.ceiling) {
            note.textContent = 'The log-pull endpoint is disabled for this deployment’s plan, '
                + 'so tokens will not return logs until the plan enables it. You can still prepare '
                + 'components and tokens here.';
            note.style.display = '';
        } else {
            note.style.display = 'none';
        }
    }
    renderLogFlags(data);
    const stealth = document.getElementById('log-stealth-toggle');
    if (stealth) stealth.checked = !!data.stealth_404;
    renderLogTokens(data.tokens || []);
}

function renderLogFlags(data) {
    const host = document.getElementById('log-flags');
    if (!host) return;
    host.textContent = '';
    const serveable = data.serveable || [];
    (data.components || []).forEach(c => {
        const row = document.createElement('label');
        row.className = 'flex items-center gap-sm mb-sm';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.checked = !!(data.flags || {})[c];
        cb.dataset.component = c;
        cb.addEventListener('change', () => saveLogFlag(c, cb.checked));
        const span = document.createElement('span');
        span.textContent = LOG_COMPONENT_LABELS[c] || c;
        row.append(cb, span);
        if (!serveable.includes(c)) {
            const badge = document.createElement('span');
            badge.className = 'badge badge-secondary';
            badge.textContent = 'coming soon';
            row.append(badge);
        }
        host.appendChild(row);
    });
}

async function saveLogFlag(component, enabled) {
    try {
        const cur = (window._logSettings && window._logSettings.flags) || {};
        const flags = { ...cur, [component]: enabled };
        const res = await apiRequest('/settings/logs', { method: 'PUT', body: JSON.stringify({ flags }) });
        if (res && res.flags && window._logSettings) { window._logSettings.flags = res.flags; }
        showSuccess('Log access updated');
    } catch (e) {
        showError('Could not update log access');
        loadLogSettings();  // resync the checkbox to the server truth
    }
}

async function saveLogStealth(enabled) {
    try {
        const res = await apiRequest('/settings/logs', { method: 'PUT', body: JSON.stringify({ stealth_404: enabled }) });
        if (res && window._logSettings) { window._logSettings.stealth_404 = !!res.stealth_404; }
        showSuccess(enabled ? 'Endpoint hidden from unauthenticated callers' : 'Endpoint returns the standard 401');
    } catch (e) {
        showError('Could not update log visibility');
        loadLogSettings();  // resync the toggle to the server truth
    }
}

function renderLogTokens(tokens) {
    const host = document.getElementById('log-token-list');
    if (!host) return;
    host.textContent = '';
    if (!tokens.length) {
        const p = document.createElement('p');
        p.className = 'text-secondary';
        p.textContent = 'No pull tokens yet. Generate one to connect a monitoring system.';
        host.appendChild(p);
        return;
    }
    tokens.forEach(t => {
        const row = document.createElement('div');
        row.className = 'flex justify-between items-center mb-sm';
        const left = document.createElement('div');
        const name = document.createElement('strong');
        name.textContent = t.name;
        const meta = document.createElement('div');
        meta.className = 'text-secondary text-sm';
        const scopeTxt = (t.scope || []).join(', ') || 'no scope';
        let metaTxt = `${t.token_prefix}… · ${scopeTxt}`;
        if (t.disabled) metaTxt += ' · disabled';
        if (t.last_used_at) metaTxt += ` · last used ${t.last_used_at}`;
        meta.textContent = metaTxt;
        left.append(name, meta);
        row.appendChild(left);
        if (!t.disabled) {
            const btn = document.createElement('button');
            btn.className = 'btn btn-outline btn-sm';
            btn.type = 'button';
            btn.textContent = 'Disable';
            btn.addEventListener('click', () => disableLogToken(t.id));
            row.appendChild(btn);
        } else {
            const badge = document.createElement('span');
            badge.className = 'badge badge-secondary';
            badge.textContent = 'disabled';
            row.appendChild(badge);
        }
        host.appendChild(row);
    });
}

async function disableLogToken(id) {
    if (!confirm('Disable this token? Any monitoring system using it will stop receiving logs.')) return;
    try {
        await apiRequest(`/settings/logs/${encodeURIComponent(id)}/disable`, { method: 'POST', body: '{}' });
        showSuccess('Token disabled');
        loadLogSettings();
    } catch (e) {
        showError('Could not disable token');
    }
}

function toggleLogTokenGenerate(show) {
    const panel = document.getElementById('log-token-generate-panel');
    if (!panel) return;
    panel.style.display = show ? '' : 'none';
    if (!show) return;
    const nameEl = document.getElementById('log-token-name');
    if (nameEl) nameEl.value = '';
    const scopeHost = document.getElementById('log-token-scope');
    if (scopeHost) {
        scopeHost.textContent = '';
        // Only offer scopes we can actually SERVE (web/sftp) — minting a db-diag token that
        // always 404s in this phase would mislead.
        const serveable = (window._logSettings && window._logSettings.serveable) || ['web', 'sftp'];
        serveable.forEach(c => {
            const lbl = document.createElement('label');
            lbl.className = 'flex items-center gap-sm mb-sm';
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.value = c;
            cb.checked = true;
            const span = document.createElement('span');
            span.textContent = LOG_COMPONENT_LABELS[c] || c;
            lbl.append(cb, span);
            scopeHost.appendChild(lbl);
        });
    }
    const reveal = document.getElementById('log-token-reveal');
    if (reveal) reveal.style.display = 'none';
}

async function generateLogToken() {
    const name = (document.getElementById('log-token-name').value || '').trim();
    const scope = Array.from(
        document.querySelectorAll('#log-token-scope input[type=checkbox]:checked')).map(cb => cb.value);
    if (!name) { showError('Give the token a name'); return; }
    if (!scope.length) { showError('Select at least one component'); return; }
    let res;
    try {
        res = await apiRequest('/settings/logs', { method: 'POST', body: JSON.stringify({ name, scope }) });
    } catch (e) { showError('Could not create token'); return; }
    if (!res || !res.token) { showError('Could not create token'); return; }
    toggleLogTokenGenerate(false);
    revealLogToken(res);
    loadLogSettings();
}

function revealLogToken(res) {
    const host = document.getElementById('log-token-reveal');
    if (!host) return;
    host.textContent = '';
    host.style.display = '';
    const warn = document.createElement('p');
    warn.className = 'text-secondary mb-sm';
    warn.textContent = 'Copy this token now — it is shown only once and cannot be retrieved later.';
    const box = document.createElement('div');
    box.className = 'flex items-center gap-sm';
    const code = document.createElement('code');
    code.id = 'log-token-value';
    code.textContent = res.token;
    code.style.wordBreak = 'break-all';
    const copy = document.createElement('button');
    copy.className = 'btn btn-outline btn-sm';
    copy.type = 'button';
    copy.textContent = 'Copy';
    copy.addEventListener('click', () => {
        navigator.clipboard.writeText(res.token).then(() => showSuccess('Copied')).catch(() => {});
    });
    box.append(code, copy);

    // Usage docs: a ready-to-copy curl per granted component, so the token is actually usable. The
    // `service` query param is REQUIRED (a missing/unknown one 404s by design), the endpoint is on
    // this same host, and it stays a header-only Bearer token (never a ?token= query param).
    // Only the serveable components (web/sftp) return logs; others 404, so don't advertise a curl
    // for them even if the token happens to carry one. Default to web when none are serveable.
    const serveable = new Set((window._logSettings && window._logSettings.serveable) || ['web', 'sftp']);
    const granted = (Array.isArray(res.scope) ? res.scope : []).filter(s => serveable.has(s));
    const scopes = granted.length ? granted : ['web'];
    const origin = window.location.origin;
    const usage = document.createElement('div');
    usage.className = 'mt-md';
    const uhead = document.createElement('p');
    uhead.className = 'text-secondary text-sm mb-sm';
    uhead.textContent = 'Pull logs with it — the service query param is REQUIRED and must be one of the token’s components:';
    usage.appendChild(uhead);
    scopes.forEach(svc => {
        const cmd = `curl -H "Authorization: Bearer ${res.token}" "${origin}/logs?service=${svc}"`;
        const row = document.createElement('div');
        row.className = 'flex items-center gap-sm mb-sm';
        const c = document.createElement('code');
        c.textContent = cmd;
        c.style.wordBreak = 'break-all';
        const b = document.createElement('button');
        b.className = 'btn btn-outline btn-sm';
        b.type = 'button';
        b.textContent = 'Copy';
        b.addEventListener('click', () => { navigator.clipboard.writeText(cmd).then(() => showSuccess('Copied')).catch(() => {}); });
        row.append(c, b);
        usage.appendChild(row);
    });
    const note = document.createElement('small');
    note.className = 'form-help';
    note.textContent = 'Same host/port as this page. Append &tail=N (max 5000) inside the quotes for more lines. A missing/unknown service, a component switched off above, or the log endpoint being disabled for this deployment all return 404.';
    usage.appendChild(note);

    host.append(warn, box, usage);
}

// Load settings from API
async function loadSettings() {
    try {
        const settings = await apiRequest('/settings', { silent: true });
        currentSettings = settings;
        
        // Populate form fields
        // General
        document.getElementById('setting-app-name').value = settings.app_name || '';
        document.getElementById('setting-app-description').value = settings.app_description || '';
        document.getElementById('setting-max-file-size').value = settings.max_file_size || 100;
        document.getElementById('setting-allowed-types').value = (settings.allowed_file_types || []).join(', ');
        
        // Security
        document.getElementById('setting-password-min-length').value = settings.password_min_length || 8;  // 8 = the enforced floor
        document.getElementById('setting-require-uppercase').checked = settings.require_uppercase !== false;
        document.getElementById('setting-require-lowercase').checked = settings.require_lowercase !== false;
        document.getElementById('setting-require-numbers').checked = settings.require_numbers !== false;
        document.getElementById('setting-require-special').checked = settings.require_special !== false;
        document.getElementById('setting-session-timeout').value = settings.session_timeout || 60;
        document.getElementById('setting-max-login-attempts').value = settings.max_login_attempts || 5;
        document.getElementById('setting-lockout-duration').value = settings.lockout_duration || 30;
        
        // Storage
        // Show the actual stored quota, or BLANK when unset/0 (which the backend treats as
        // unlimited) — don't render 10/100 as if a limit were enforced.
        document.getElementById('setting-default-quota').value = (settings.default_user_quota > 0) ? settings.default_user_quota : '';
        document.getElementById('setting-max-vault-size').value = (settings.max_vault_size > 0) ? settings.max_vault_size : '';
        document.getElementById('setting-storage-path').value = settings.storage_path || '';
        
        // Email
        document.getElementById('setting-smtp-server').value = settings.smtp_server || '';
        document.getElementById('setting-smtp-port').value = settings.smtp_port || 587;
        document.getElementById('setting-smtp-username').value = settings.smtp_username || '';
        // Don't populate password for security
        document.getElementById('setting-from-email').value = settings.from_email || '';
        document.getElementById('setting-from-name').value = settings.from_name || '';

        // SFTP & Encryption
        const zkEl = document.getElementById('setting-zero-knowledge-enabled');
        if (zkEl) zkEl.checked = settings.zero_knowledge_enabled === true;
        const fzkEl = document.getElementById('setting-force-zero-knowledge');
        if (fzkEl) fzkEl.checked = settings.force_zero_knowledge === true;
        const dssEl = document.getElementById('setting-directory-search-scope');
        if (dssEl) dssEl.value = (settings.directory_search_scope === 'same_department') ? 'same_department' : 'deployment';

        // Temporary Vault Passcodes. GET /settings overlays the EFFECTIVE policy, so these keys
        // are always present (feature default off; allow-ZK default on).
        const setPasscodeChk = (id, val) => { const el = document.getElementById(id); if (el) el.checked = val === true; };
        setPasscodeChk('setting-temp-passcodes-enabled', settings.temp_passcodes_enabled);
        setPasscodeChk('setting-temp-passcode-one-time-default', settings.temp_passcode_one_time_default);
        setPasscodeChk('setting-temp-passcode-single-vault-only', settings.temp_passcode_single_vault_only);
        setPasscodeChk('setting-temp-passcode-allow-custom', settings.temp_passcode_allow_custom);
        setPasscodeChk('setting-temp-passcode-require-uppercase', settings.temp_passcode_require_uppercase);
        setPasscodeChk('setting-temp-passcode-require-lowercase', settings.temp_passcode_require_lowercase);
        setPasscodeChk('setting-temp-passcode-require-numbers', settings.temp_passcode_require_numbers);
        setPasscodeChk('setting-temp-passcode-require-special', settings.temp_passcode_require_special);
        // allow-ZK-in-scope defaults to ON (today's behavior) when the key is absent.
        const tczkEl = document.getElementById('setting-temp-cred-allow-zk-vaults');
        if (tczkEl) tczkEl.checked = settings.temp_cred_allow_zk_vaults !== false;
        const tpMinEl = document.getElementById('setting-temp-passcode-min-length');
        if (tpMinEl) tpMinEl.value = settings.temp_passcode_min_length || 16;
        const tpMaxEl = document.getElementById('setting-temp-passcode-max-lifetime');
        if (tpMaxEl) tpMaxEl.value = (settings.temp_passcode_max_lifetime_minutes > 0) ? settings.temp_passcode_max_lifetime_minutes : '';
        // When the PLAN mandates zero-knowledge (Enterprise tier), the local toggles can't
        // lower that floor — show ZK as allowed + required, checked and LOCKED, with an
        // explanatory note, so an unchecked-but-forced box isn't contradictory. Best-effort:
        // if the plan state can't be read, leave the local toggles as-is.
        try {
            const zk = await apiRequest('/zk-enabled', { silent: true });
            const planForced = !!(zk && zk.plan_force_zero_knowledge);
            const zkAllowEl = document.getElementById('setting-zero-knowledge-enabled');
            const note = document.getElementById('force-zk-plan-note');
            if (planForced) {
                if (zkAllowEl) { zkAllowEl.checked = true; zkAllowEl.disabled = true; }
                if (fzkEl) { fzkEl.checked = true; fzkEl.disabled = true; }
            } else {
                if (zkAllowEl) zkAllowEl.disabled = false;
                if (fzkEl) fzkEl.disabled = false;
            }
            if (note) note.style.display = planForced ? '' : 'none';
        } catch (_) { /* plan state unavailable — leave the toggles editable */ }
        sftpRequireTempCredGroups = (settings.sftp_require_temp_cred_groups || []).map(String);
        standardVaultAllowedGroups = (settings.standard_vault_allowed_groups || []).map(String);
        await loadSftpPolicyGroups();

        // Branding: stored overrides -> values, effective /branding -> placeholders
        await applyBrandFields(settings);

        console.log('✓ Settings loaded');
    } catch (error) {
        console.log('Settings endpoint not available');
        // Load default values
        currentSettings = {};
    }
}

// Save all settings
async function saveAllSettings() {
    try {
        // Collect all settings
        const settings = {
            // General
            app_name: document.getElementById('setting-app-name').value,
            app_description: document.getElementById('setting-app-description').value,
            max_file_size: parseInt(document.getElementById('setting-max-file-size').value) || 100,
            allowed_file_types: document.getElementById('setting-allowed-types').value
                .split(',')
                .map(t => t.trim())
                .filter(t => t),
            
            // Security
            password_min_length: parseInt(document.getElementById('setting-password-min-length').value) || 8,
            require_uppercase: document.getElementById('setting-require-uppercase').checked,
            require_lowercase: document.getElementById('setting-require-lowercase').checked,
            require_numbers: document.getElementById('setting-require-numbers').checked,
            require_special: document.getElementById('setting-require-special').checked,
            session_timeout: parseInt(document.getElementById('setting-session-timeout').value) || 60,
            max_login_attempts: parseInt(document.getElementById('setting-max-login-attempts').value) || 5,
            lockout_duration: parseInt(document.getElementById('setting-lockout-duration').value) || 30,
            
            // Storage
            // Blank -> 0 (unlimited); the backend enforces a positive value and ignores 0.
            default_user_quota: parseInt(document.getElementById('setting-default-quota').value) || 0,
            max_vault_size: parseInt(document.getElementById('setting-max-vault-size').value) || 0,
            
            // Email
            smtp_server: document.getElementById('setting-smtp-server').value,
            smtp_port: parseInt(document.getElementById('setting-smtp-port').value) || 587,
            smtp_username: document.getElementById('setting-smtp-username').value,
            from_email: document.getElementById('setting-from-email').value,
            from_name: document.getElementById('setting-from-name').value,

            // SFTP & Encryption
            zero_knowledge_enabled: document.getElementById('setting-zero-knowledge-enabled').checked,
            force_zero_knowledge: document.getElementById('setting-force-zero-knowledge').checked,
            directory_search_scope: (document.getElementById('setting-directory-search-scope') || {}).value || 'deployment',

            // Temporary Vault Passcodes
            temp_passcodes_enabled: document.getElementById('setting-temp-passcodes-enabled').checked,
            temp_passcode_allow_custom: document.getElementById('setting-temp-passcode-allow-custom').checked,
            temp_passcode_one_time_default: document.getElementById('setting-temp-passcode-one-time-default').checked,
            temp_passcode_single_vault_only: document.getElementById('setting-temp-passcode-single-vault-only').checked,
            temp_passcode_require_uppercase: document.getElementById('setting-temp-passcode-require-uppercase').checked,
            temp_passcode_require_lowercase: document.getElementById('setting-temp-passcode-require-lowercase').checked,
            temp_passcode_require_numbers: document.getElementById('setting-temp-passcode-require-numbers').checked,
            temp_passcode_require_special: document.getElementById('setting-temp-passcode-require-special').checked,
            temp_passcode_min_length: parseInt(document.getElementById('setting-temp-passcode-min-length').value) || 16,
            temp_passcode_max_lifetime_minutes: parseInt(document.getElementById('setting-temp-passcode-max-lifetime').value) || 0,
            temp_cred_allow_zk_vaults: document.getElementById('setting-temp-cred-allow-zk-vaults').checked
        };

        // Branding: send the brand overrides. An empty value clears that
        // override server-side (reverts to the env default). app_name/app_description
        // are already collected above from the General tab.
        for (const [elId, key] of Object.entries(BRAND_SETTING_FIELDS)) {
            const el = document.getElementById(elId);
            if (el) settings[key] = el.value;
        }

        // Persist the department-scoped policies ONLY when the department list
        // actually loaded. If GET /groups failed, the pickers are read-only and the
        // selection may have been pruned — omitting the keys here lets PUT /settings
        // keep the stored policies instead of overwriting live controls with [].
        if (settingsGroupsLoaded) {
            settings.sftp_require_temp_cred_groups = sftpRequireTempCredGroups.slice();
            settings.standard_vault_allowed_groups = standardVaultAllowedGroups.slice();
        }

        // Only include password if provided
        const smtpPassword = document.getElementById('setting-smtp-password').value;
        if (smtpPassword) {
            settings.smtp_password = smtpPassword;
        }
        
        // Save to API
        await apiRequest('/settings', {
            method: 'PUT',
            body: JSON.stringify(settings)
        });
        
        showSuccess('Settings saved successfully');
        currentSettings = settings;
    } catch (error) {
        console.error('Failed to save settings:', error);
        showError('Failed to save settings: ' + error.message);
    }
}

// Build an icon node from the #i-* sprite via DOM (no innerHTML), for controls
// inserted dynamically into already-rendered panels.
const SVG_NS = 'http://www.w3.org/2000/svg';
function svgUseIcon(name, extraClass = '') {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', extraClass ? `icon ${extraClass}` : 'icon');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.appendChild(use);
    return svg;
}

// Load the department list backing the SFTP temp-cred policy picker.
async function loadSftpPolicyGroups() {
    try {
        const groups = await apiRequest('/groups', { silent: true });
        settingsAllGroups = Array.isArray(groups) ? groups : [];
        settingsGroupsLoaded = true;
    } catch (error) {
        settingsAllGroups = [];
        settingsGroupsLoaded = false;
        // Surface it: a silent failure here would otherwise let a later Save wipe
        // the policy (now guarded in saveAllSettings + the read-only render below).
        showWarning('Could not load departments — the confidentiality policies are read-only and will not be changed on save.');
    }
    renderSftpGroupPicker();
    renderStandardWhitelistPicker();
}

// Generic chip multi-select group picker used by the Settings confidentiality
// policies. getArr/setArr read+write the backing id array; `rerender` is the
// caller's own render fn (so add/remove refresh in place); addClass/removeClass
// keep stable hooks per picker. Mutations stay local until "Save All Changes".
function _renderGroupPickerInto(hostId, getArr, setArr, emptyText, rerender, addClass, removeClass) {
    const host = document.getElementById(hostId);
    if (!host) return;
    const byId = {};
    settingsAllGroups.forEach(g => { byId[String(g.id)] = g; });
    host.replaceChildren();

    // Department list unavailable: show the persisted policy READ-ONLY and don't
    // touch the selection. saveAllSettings omits the key in this state, so a
    // transient /groups failure can't overwrite a good policy with [].
    if (!settingsGroupsLoaded) {
        const roRow = document.createElement('div');
        roRow.className = 'chip-row';
        const sel = getArr();
        if (sel.length) {
            sel.forEach(id => {
                const chip = document.createElement('span');
                chip.className = 'chip';
                chip.append(`Department ${String(id).slice(0, 8)}`);
                roRow.appendChild(chip);
            });
        } else {
            const none = document.createElement('span');
            none.className = 'text-tertiary text-sm';
            none.textContent = emptyText;
            roRow.appendChild(none);
        }
        host.appendChild(roRow);
        const note = document.createElement('div');
        note.className = 'text-tertiary text-sm mt-sm';
        note.textContent = 'Department list unavailable — policy shown read-only and will not be changed on save.';
        host.appendChild(note);
        return;
    }

    setArr(getArr().filter(id => byId[id]));  // prune ids that no longer resolve
    const selected = getArr();

    const chipRow = document.createElement('div');
    chipRow.className = 'chip-row';
    if (selected.length) {
        selected.forEach(id => {
            const g = byId[id];
            const chip = document.createElement('span');
            chip.className = 'chip';
            chip.style.setProperty('--chip', chipColorValue(g.color));
            chip.append(g.name);
            const rm = document.createElement('button');
            rm.type = 'button';
            rm.className = 'chip-remove ' + removeClass;
            rm.setAttribute('aria-label', `Remove ${g.name}`);
            rm.appendChild(svgUseIcon('x', 'icon-sm'));
            rm.addEventListener('click', () => { setArr(getArr().filter(x => x !== id)); rerender(); });
            chip.appendChild(rm);
            chipRow.appendChild(chip);
        });
    } else {
        const none = document.createElement('span');
        none.className = 'text-tertiary text-sm';
        none.textContent = emptyText;
        chipRow.appendChild(none);
    }
    host.appendChild(chipRow);

    if (!settingsAllGroups.length) {
        const note = document.createElement('div');
        note.className = 'text-tertiary text-sm mt-sm';
        note.textContent = 'No departments yet — create one on the Groups page first.';
        host.appendChild(note);
        return;
    }
    const addable = settingsAllGroups
        .filter(g => !selected.includes(String(g.id)))
        .slice()
        .sort((a, b) => a.name.localeCompare(b.name));
    if (!addable.length) return;

    const row = document.createElement('div');
    row.className = 'add-group-row mt-sm';
    const select = document.createElement('select');
    select.className = 'form-control ' + addClass;
    const ph = document.createElement('option');
    ph.value = '';
    ph.textContent = 'Add a department…';
    select.appendChild(ph);
    addable.forEach(g => {
        const opt = document.createElement('option');
        opt.value = String(g.id);
        opt.textContent = g.name;
        select.appendChild(opt);
    });
    select.addEventListener('change', () => {
        if (select.value && !getArr().includes(select.value)) { setArr([...getArr(), select.value]); rerender(); }
    });
    row.appendChild(select);
    host.appendChild(row);
}

// SFTP temp-cred policy: which departments must use a temp credential for SFTP.
function renderSftpGroupPicker() {
    _renderGroupPickerInto(
        'sftp-temp-cred-group-picker',
        () => sftpRequireTempCredGroups, v => { sftpRequireTempCredGroups = v; },
        'No departments require a temporary credential.', renderSftpGroupPicker,
        'sftp-group-add', 'sftp-group-remove'
    );
}

// Force-zero-knowledge whitelist: which departments may still create Standard vaults.
function renderStandardWhitelistPicker() {
    _renderGroupPickerInto(
        'standard-vault-allowed-group-picker',
        () => standardVaultAllowedGroups, v => { standardVaultAllowedGroups = v; },
        'No departments are exempt — everyone must use zero-knowledge.', renderStandardWhitelistPicker,
        'std-group-add', 'std-group-remove'
    );
}

// Load storage statistics
async function loadStorageStats() {
    try {
        const stats = await apiRequest('/storage/stats', { silent: true });
        
        document.getElementById('storage-stat-total').textContent = formatBytes(stats.total || 0);
        document.getElementById('storage-stat-used').textContent = formatBytes(stats.used || 0);
        document.getElementById('storage-stat-available').textContent = formatBytes(stats.available || 0);
    } catch (error) {
        console.log('Storage stats endpoint not available');
        // Show defaults
        document.getElementById('storage-stat-total').textContent = 'N/A';
        document.getElementById('storage-stat-used').textContent = 'N/A';
        document.getElementById('storage-stat-available').textContent = 'N/A';
    }
}

// Test email configuration
async function testEmail() {
    const resultSpan = document.getElementById('test-email-result');
    const btn = document.getElementById('test-email-btn');
    
    try {
        btn.disabled = true;
        btn.textContent = 'Sending...';
        resultSpan.textContent = '';
        
        await apiRequest('/settings/test-email', {
            method: 'POST'
        });
        
        showSuccess('Test email sent successfully');
        resultSpan.textContent = '✓ Email sent';
        resultSpan.style.color = 'var(--success)';
    } catch (error) {
        showError('Failed to send test email: ' + error.message);
        resultSpan.textContent = '✗ Failed';
        resultSpan.style.color = 'var(--error)';
    } finally {
        btn.disabled = false;
        btn.textContent = '📧 Send Test Email';
    }
}

// Load users for audit filter dropdown
async function loadAuditFilterUsers() {
    try {
        // Silent: an unrestricted (NULL-scope) temp credential is still shown the admin nav even
        // though the backend now 403s these admin routes; degrade quietly here instead of firing a
        // permission-denied toast. (Full temp-cred nav alignment is a separate follow-up.)
        const users = await apiRequest('/users', { silent: true });
        const select = document.getElementById('audit-filter-user');
        
        if (select && users.length > 0) {
            // Keep "All Users" option and add user options
            const options = users.map(user => 
                `<option value="${user.id}">${escapeHtml(user.username)}</option>`
            ).join('');
            
            select.innerHTML = '<option value="">All Users</option>' + options;
        }
    } catch (error) {
        console.error('Failed to load users for audit filter:', error);
    }
}

// Search audit log
async function searchAuditLog() {
    const tbody = document.getElementById('audit-log-body');
    const countBadge = document.getElementById('audit-count');
    
    try {
        tbody.innerHTML = '<tr><td colspan="6" class="text-center py-lg"><div class="loading-spinner mx-auto"></div></td></tr>';
        
        // Get filter values
        const filters = {
            user_id: document.getElementById('audit-filter-user').value,
            action: document.getElementById('audit-filter-action').value,
            from_date: document.getElementById('audit-filter-from').value,
            to_date: document.getElementById('audit-filter-to').value
        };
        
        // Build query string
        const queryParams = new URLSearchParams();
        if (filters.user_id) queryParams.append('user_id', filters.user_id);
        if (filters.action) queryParams.append('action', filters.action);
        if (filters.from_date) queryParams.append('from_date', filters.from_date);
        if (filters.to_date) queryParams.append('to_date', filters.to_date);
        
        const logs = await apiRequest(`/audit/log?${queryParams.toString()}`, { silent: true });
        
        if (countBadge) {
            countBadge.textContent = `${logs.length} entries`;
        }
        
        if (logs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center py-xl text-secondary">
                        No audit log entries found for the selected filters
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = logs.map(log => {
            const timestamp = new Date(log.timestamp);
            const statusClass = log.status === 'success' ? 'success' : 'danger';
            
            return `
                <tr>
                    <td>${timestamp.toLocaleString()}</td>
                    <td>${escapeHtml(log.username || '-')}</td>
                    <td><span class="badge badge-secondary">${escapeHtml(log.action.replace('_', ' '))}</span></td>
                    <td><span class="badge badge-${statusClass}">${log.status}</span></td>
                    <td>${escapeHtml(log.ip_address || '-')}</td>
                    <td>
                        <details>
                            <summary class="cursor-pointer text-primary">View</summary>
                            <pre class="text-xs mt-sm">${escapeHtml(JSON.stringify(log.details || {}, null, 2))}</pre>
                        </details>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to search audit log:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-lg">
                    <div class="alert alert-error">Failed to load audit log: ${escapeHtml(error.message)}</div>
                </td>
            </tr>
        `;
    }
}

// Export audit log to CSV
async function exportAuditLog() {
    try {
        // Same filters as search
        const filters = {
            user_id: document.getElementById('audit-filter-user').value,
            action: document.getElementById('audit-filter-action').value,
            from_date: document.getElementById('audit-filter-from').value,
            to_date: document.getElementById('audit-filter-to').value
        };

        const queryParams = new URLSearchParams();
        if (filters.user_id) queryParams.append('user_id', filters.user_id);
        if (filters.action) queryParams.append('action', filters.action);
        if (filters.from_date) queryParams.append('from_date', filters.from_date);
        if (filters.to_date) queryParams.append('to_date', filters.to_date);

        // Fetch with the bearer token (a plain <a href> navigation can't send it),
        // then save the returned CSV as a blob.
        const resp = await fetch(`${API_BASE}/audit/export?${queryParams.toString()}`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-log-${new Date().toISOString().split('T')[0]}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        showSuccess('Audit log exported');
    } catch (error) {
        console.error('Failed to export audit log:', error);
        showError('Failed to export audit log: ' + error.message);
    }
}

// Clear audit filters
function clearAuditFilters() {
    document.getElementById('audit-filter-user').value = '';
    document.getElementById('audit-filter-action').value = '';
    document.getElementById('audit-filter-from').value = '';
    document.getElementById('audit-filter-to').value = '';
    
    // Clear table
    document.getElementById('audit-log-body').innerHTML = `
        <tr>
            <td colspan="6" class="text-center py-xl text-secondary">
                Click "Search" to load audit log entries
            </td>
        </tr>
    `;
    document.getElementById('audit-count').textContent = '0 entries';
}

// Attach settings event listeners
function attachSettingsListeners() {
    // Save all settings button
    const saveBtn = document.getElementById('save-all-settings-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveAllSettings);
    }
    
    // Test email button
    const testEmailBtn = document.getElementById('test-email-btn');
    if (testEmailBtn) {
        testEmailBtn.addEventListener('click', testEmail);
    }
    
    // Audit log buttons
    const searchBtn = document.getElementById('audit-search-btn');
    if (searchBtn) {
        searchBtn.addEventListener('click', searchAuditLog);
    }
    
    const exportBtn = document.getElementById('audit-export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportAuditLog);
    }
    
    const clearBtn = document.getElementById('audit-clear-filters-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearAuditFilters);
    }
}

// Open Vault (Placeholder - needs SFTP integration or file listing)
async function openVault(vaultId) {
    try {
        // Validate vault ID
        if (!vaultId) {
            console.error('Invalid vault ID:', vaultId);
            alert('Invalid vault ID');
            return;
        }
        
        // Fetch vault details (metadata only, no password required)
        const vault = await apiRequest(`/vaults/${vaultId}`);
        
        // Validate vault data
        if (!vault || !vault.id) {
            console.error('Invalid vault data received');
            alert('Failed to load vault');
            return;
        }
        
        // Store vault metadata in global state
        state.currentVault = vault;
        state.currentVaultId = vaultId;
        state.currentFolderId = null;  // Start at root
        state.currentPath = [];  // Empty path array (root)
        
        // Update vault view header
        document.getElementById('vault-view-title').textContent = vault.name;
        const descEl = document.getElementById('vault-view-description');
        if (descEl) {
            descEl.textContent = vault.description || '';
            descEl.style.display = vault.description ? '' : 'none';  // no "No description" filler
        }
        window.scrollTo({ top: 0 });  // open a vault at the top, not at the grid's scroll position
        
        const lockIcon = document.getElementById('vault-view-lock-icon');
        if (lockIcon) {
            // Build the lock icon via DOM (no innerHTML) so the SVG <use> renders safely.
            lockIcon.replaceChildren();
            if (vault.has_password) {
                const svgNS = 'http://www.w3.org/2000/svg';
                const svg = document.createElementNS(svgNS, 'svg');
                svg.setAttribute('class', 'icon');
                const use = document.createElementNS(svgNS, 'use');
                use.setAttribute('href', '#i-lock');
                svg.appendChild(use);
                lockIcon.appendChild(svg);
            }
        }
        
        // If vault is password-protected, reuse a remembered password when it's
        // still within the vault's window; otherwise prompt. (showPrompt returns
        // the typed value — showConfirm only returns true/false, which broke unlock.)
        if (vault.has_password) {
            let password = state.getRememberedVaultPassword(vaultId);
            if (!password) {
                password = await showPrompt(
                    'This vault is password-protected. Enter its password to unlock it.',
                    `Unlock "${vault.name}"`,
                    { password: true, placeholder: 'Vault password' }
                );
                if (password === null || password === '') {
                    // User cancelled or left it blank
                    state.currentVault = null;
                    state.currentVaultId = null;
                    showWarning('Vault unlock cancelled');
                    return;
                }
            }
            state.setVaultPassword(password);
        }

        // Load vault files — this validates the password. If it fails (wrong /
        // changed password), do NOT show the vault view.
        const loaded = await loadVaultFiles();
        if (!loaded) {
            if (vault.has_password) state.forgetVaultPassword(vaultId);
            state.currentVault = null;
            state.currentVaultId = null;
            state.setVaultPassword(null);
            return;
        }
        if (vault.has_password) {
            // Remember the password for the unlock window so leaving and re-entering
            // (or a refresh) within that window doesn't re-prompt. We do NOT lock a
            // vault that's already open — the window only governs re-entry.
            state.rememberVaultPassword(vaultId, state.vaultPassword, vault.unlock_remember_minutes);
        }

        // Determine the caller's capabilities and hide controls they can't use
        // (read-only users shouldn't see Upload/New folder; non-owners shouldn't
        // see the owner-only Permissions/Settings tabs).
        const isOwner = vault.owner_id === currentUser.id;
        const canWrite = ['owner', 'manage', 'write', 'delete'].includes(vault.my_permission);
        // A Manager (manage_permission) may administer membership/access but is
        // not the owner — they get the Permissions tab, not the owner-only Settings.
        const canManage = ['owner', 'manage'].includes(vault.my_permission);
        state.canWriteCurrentVault = canWrite;
        state.canManageCurrentVault = canManage;
        // For a scoped temp credential, further restrict what's shown to the caps its
        // scope grants ON THIS vault (the vault-role above reflects the OWNER, not the
        // credential). null for everyone else => no extra gating. Read by
        // vaultCapAllowed() in applyVaultViewPermissions + fileActionButtons.
        state.tempVaultCaps = tempVaultCaps(vaultId);
        applyVaultViewPermissions(isOwner, canWrite, canManage);
        startVaultAccessWatch(vaultId);

        // Show vault view section (don't hide navbar/sidebar)
        document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
        document.getElementById('vault-view-section').classList.add('active');
        
        // Make sure Files tab is active by default
        document.querySelectorAll('[data-vault-tab]').forEach(t => t.classList.remove('active'));
        document.querySelector('[data-vault-tab="files"]')?.classList.add('active');
        
        document.querySelectorAll('.vault-tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById('vault-files-tab')?.classList.add('active');
        
        // Update sidebar active state
        document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
        const vaultsItem = document.querySelector('.sidebar-item[data-section="vaults"]');
        if (vaultsItem) vaultsItem.classList.add('active');
        
        // Setup drag-and-drop for file uploads
        setupFileDragDrop();

        // Live-refresh the listing when other users change this vault, and
        // remember we're inside this vault so a refresh restores us here.
        startVaultFileWatch();
        saveNavState();

        console.log('✓ Opened vault:', vault.name);

    } catch (error) {
        console.error('Failed to open vault:', error);
        showError(error.message || 'Failed to open vault');

        // Clear vault state
        state.currentVault = null;
        state.currentVaultId = null;
        state.vaultPassword = null;
    }
}

// Load files in current vault
async function loadVaultFiles() {
    // Check if we have a current vault to load
    if (!state.currentVault) {
        console.log('Skipping loadVaultFiles - no current vault');
        return;
    }
    
    const tbody = document.getElementById('vault-files-table-body');
    if (!tbody) {
        console.error('Table body not found');
        return;
    }
    
    try {
        console.log('Loading files for vault:', state.currentVault.id, 'folder:', state.currentFolderId);
        
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
        
        const data = await apiRequest(url, { headers });

        // Baseline for the live-change watcher, computed on the RAW server response (the
        // watcher computes it the same way, pre-decrypt) so zero-knowledge name decryption
        // below doesn't make every poll look "changed". filesSignature keys on enc_name so a
        // ZK rename (which only changes the ciphertext) is still detected.
        state.lastFilesSignature = filesSignature(data.items);

        // Zero-knowledge: names/MIME come back encrypted (the server can't read them).
        // Decrypt them in the browser so the UI shows the real names, then lazily seal any
        // legacy plaintext rows still at rest.
        if (isZkVault(state.currentVault)) {
            await zkDecryptListingNames(data.items || [], state.currentVault);
            zkSealLegacyNames(state.currentVault, data.items || []);  // fire-and-forget
        }

        // Update breadcrumb
        updateBreadcrumb();

        // Sort: folders first, then files (A->Z within each group), then hand
        // off to the active renderer (table or grid).
        const items = (data.items || []).slice().sort((a, b) => {
            if (a.type === 'folder' && b.type !== 'folder') return -1;
            if (a.type !== 'folder' && b.type === 'folder') return 1;
            return a.name.localeCompare(b.name);
        });
        state.currentFiles = items;
        renderVaultFiles();
        
        // Surface any incomplete (resumable) uploads for this vault in the tray.
        try { uploadManager.refreshResumable(); } catch (_) {}

        return true;
    } catch (error) {
        console.error('Failed to load files:', error);

        // Return false so callers (openVault) know the load failed and can decide
        // what to do — do NOT navigate away from here, or a wrong password ends up
        // showing an empty vault view ("accepts any password").

        // 1. Folder was deleted — drop back to root and retry.
        if (error.message && error.message.includes('Folder not found')) {
            showError('The folder you were viewing has been deleted. Returning to vault root…');
            state.currentFolderId = null;
            state.currentPath = [];
            setTimeout(() => loadVaultFiles(), 1000);
            return false;
        }

        // 2. Rate limiting (429)
        if (error.message && (error.message.includes('Too many') || error.message.includes('429'))) {
            showError('Too many password attempts. Please try again later.');
            return false;
        }

        // 3. Wrong / missing vault password
        if (error.message && (error.message.includes('password') || error.message.includes('Password') || error.message.includes('Unauthorized') || error.message.includes('401'))) {
            showWarning('Invalid vault password.');
            state.setVaultPassword(null);
            return false;
        }

        // 4. Other errors
        showError('Failed to load files: ' + error.message);
        return false;
    }
}

// Get file icon based on extension (returns inline SVG markup from the sprite)
// A short, human-friendly file-type label (instead of a raw MIME string).
function friendlyFileType(item) {
    if (item.type === 'folder') return 'Folder';
    const ext = (item.name.split('.').pop() || '').toLowerCase();
    const map = {
        pdf: 'PDF', doc: 'Word', docx: 'Word', xls: 'Spreadsheet', xlsx: 'Spreadsheet',
        csv: 'CSV', ppt: 'Slides', pptx: 'Slides', txt: 'Text', md: 'Markdown', rtf: 'Text',
        jpg: 'Image', jpeg: 'Image', png: 'Image', gif: 'Image', svg: 'Image', webp: 'Image', bmp: 'Image',
        mp4: 'Video', mov: 'Video', avi: 'Video', mkv: 'Video', webm: 'Video',
        mp3: 'Audio', wav: 'Audio', flac: 'Audio', ogg: 'Audio',
        zip: 'Archive', rar: 'Archive', tar: 'Archive', gz: 'Archive', '7z': 'Archive',
        js: 'Code', ts: 'Code', py: 'Code', java: 'Code', json: 'JSON', html: 'HTML', css: 'CSS', sh: 'Script',
    };
    if (map[ext]) return map[ext];
    if (ext && ext.length <= 5 && ext !== item.name.toLowerCase()) return ext.toUpperCase();
    return 'File';
}

// A compact, single-line "modified" timestamp.
function formatModified(iso) {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return '—';
    const date = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    return `${date} · ${time}`;
}

// Render the current vault's files in the active view (table or grid). Reads
// state.currentFiles (set by loadVaultFiles) so the view can be re-rendered on
// a view-switch without re-fetching. All dynamic text is escaped via escapeHtml.
function renderVaultFiles() {
    if (!state.filesView) {
        try { state.filesView = localStorage.getItem('filesView') || 'table'; } catch (_) { state.filesView = 'table'; }
    }
    if (!(state.selectedFileIds instanceof Set)) state.selectedFileIds = new Set();

    const items = state.currentFiles || [];
    const view = state.filesView === 'grid' ? 'grid' : 'table';
    const canWrite = state.canWriteCurrentVault !== false;

    // Drop any selected ids that are no longer present (e.g. after navigation).
    const fileIds = new Set(items.filter(i => i.type !== 'folder').map(i => i.id));
    state.selectedFileIds.forEach(id => { if (!fileIds.has(id)) state.selectedFileIds.delete(id); });

    const tableWrap = document.getElementById('vault-files-table-wrap');
    const grid = document.getElementById('vault-files-grid');
    const tbody = document.getElementById('vault-files-table-body');

    if (tableWrap) tableWrap.hidden = view !== 'table';
    if (grid) grid.hidden = view !== 'grid';
    document.querySelectorAll('[data-files-view]').forEach(b =>
        b.classList.toggle('active', b.getAttribute('data-files-view') === view));

    if (view === 'table') {
        renderFilesTable(items, canWrite, tbody);
        wireFileItemHandlers(tbody);
    } else {
        renderFilesGrid(items, canWrite, grid);
        wireFileItemHandlers(grid);
    }

    setupFilesViewControls();
    updateFilesBulkBar();
}

function filesEmptyStateHtml(grid) {
    const inner = `<p style="font-size:48px;margin:0;">${iconSvg('folder', 'icon-lg')}</p>
        <h3 style="margin:16px 0 8px 0;">No files yet</h3>
        <p style="color:var(--text-secondary);">Upload files or create folders to get started</p>`;
    return grid
        ? `<div class="empty-state text-center p-xl" style="grid-column:1/-1;">${inner}</div>`
        : `<tr><td colspan="6" style="text-align:center;padding:40px;"><div class="empty-state">${inner}</div></td></tr>`;
}

// Build the inline action buttons for a file/folder row or tile. Keeps the
// .action-btn + data-action hooks the e2e tests rely on; only the look changes.
// opts.slot splits the grid tile's controls into two positioned clusters:
//   'primary'   -> the left cluster (Download for files; nothing for folders),
//   'secondary' -> the right cluster (Rename + Delete for both),
// so a file gets an Edit affordance in grid too. Undefined slot (the table view)
// returns every button in one cluster, as before.
function fileActionButtons(item, canWrite, opts) {
    const isFolder = item.type === 'folder';
    const id = item.id;
    const nm = escapeHtml(item.name);
    const slot = opts && opts.slot;
    const btn = (action, icon, label, danger) =>
        `<button class="action-btn${danger ? ' action-btn-danger' : ''}" data-action="${action}" data-id="${id}" data-name="${nm}" title="${label}" aria-label="${label}">${iconSvg(icon, 'icon-sm')}</button>`;
    // vaultCapAllowed() is a no-op (true) for non-scoped sessions; for a scoped temp
    // credential it gates each action by the cap its scope grants on this vault,
    // matching require_vault_cap server-side (rename=file.rename, delete=file.delete,
    // folder delete=folder.delete, download=file.download). The same gate applies in
    // every slot, so splitting the cluster never grants an affordance the scope lacks.
    const out = [];
    if (isFolder) {
        const canRename = canWrite && vaultCapAllowed('file.rename');
        const canDelete = canWrite && vaultCapAllowed('folder.delete');
        if (slot !== 'primary') {  // folders have no download -> primary (left) is empty
            if (canRename) out.push(btn('rename-folder', 'edit', 'Rename'));
            if (canDelete) out.push(btn('delete-folder', 'trash', 'Delete', true));
        }
        if (!canRename && !canDelete && !slot && (!opts || !opts.grid)) out.push('<span class="text-tertiary text-sm">—</span>');
    } else {
        const canDownload = vaultCapAllowed('file.download');
        const canRename = canWrite && vaultCapAllowed('file.rename');
        const canDelete = canWrite && vaultCapAllowed('file.delete');
        if (slot !== 'secondary' && canDownload) out.push(btn('download', 'download', 'Download'));
        if (slot !== 'primary') {
            if (canRename) out.push(btn('rename-file', 'edit', 'Rename'));
            if (canDelete) out.push(btn('delete-file', 'trash', 'Delete', true));
        }
    }
    return out.join('');
}

function renderFilesTable(items, canWrite, tbody) {
    if (!tbody) return;
    if (!items.length) { tbody.innerHTML = filesEmptyStateHtml(false); return; }
    tbody.innerHTML = items.map(item => {
        const isFolder = item.type === 'folder';
        const icon = isFolder ? iconSvg('folder') : getFileIcon(item.name);
        const size = isFolder ? '—' : formatBytes(item.size);
        const lockIcon = item.has_password ? ` ${iconSvg('lock', 'icon-sm')}` : '';
        const selected = state.selectedFileIds.has(item.id);
        const nameAttrs = isFolder
            ? `data-folder-id="${item.id}" data-folder-name="${escapeHtml(item.name)}" style="cursor:pointer;"`
            : `data-file-id="${item.id}" data-file-name="${escapeHtml(item.name)}" data-mime="${escapeHtml(item.mime_type || '')}" style="cursor:pointer;" title="Click to preview"`;
        const check = (isFolder || !allowBulkSelect()) ? ''
            : `<input type="checkbox" class="files-check file-check" data-id="${item.id}" ${selected ? 'checked' : ''} aria-label="Select ${escapeHtml(item.name)}">`;
        return `
            <tr class="${selected ? 'is-selected' : ''}">
                <td class="col-check">${check}</td>
                <td>
                    <div class="file-name" ${nameAttrs}>
                        <span class="file-icon">${icon}</span>
                        <span>${escapeHtml(item.name)}${lockIcon}</span>
                    </div>
                </td>
                <td class="col-num"><span class="file-size">${size}</span></td>
                <td><span class="file-type">${escapeHtml(friendlyFileType(item))}</span></td>
                <td><span class="file-modified">${formatModified(item.modified)}</span></td>
                <td class="col-actions"><div class="file-actions">${fileActionButtons(item, canWrite, { grid: false })}</div></td>
            </tr>`;
    }).join('');
}

function renderFilesGrid(items, canWrite, grid) {
    if (!grid) return;
    if (!items.length) { grid.innerHTML = filesEmptyStateHtml(true); return; }
    grid.innerHTML = items.map(item => {
        const isFolder = item.type === 'folder';
        const icon = isFolder ? iconSvg('folder') : getFileIcon(item.name);
        const meta = isFolder ? 'Folder' : formatBytes(item.size);
        const selected = state.selectedFileIds.has(item.id);
        const lockIcon = item.has_password ? ` ${iconSvg('lock', 'icon-sm')}` : '';
        const nameAttrs = isFolder
            ? `data-folder-id="${item.id}" data-folder-name="${escapeHtml(item.name)}"`
            : `data-file-id="${item.id}" data-file-name="${escapeHtml(item.name)}" data-mime="${escapeHtml(item.mime_type || '')}" title="Click to preview"`;
        const check = (isFolder || !allowBulkSelect()) ? ''
            : `<input type="checkbox" class="files-check file-check" data-id="${item.id}" ${selected ? 'checked' : ''} aria-label="Select ${escapeHtml(item.name)}">`;
        const primary = fileActionButtons(item, canWrite, { grid: true, slot: 'primary' });
        const secondary = fileActionButtons(item, canWrite, { grid: true, slot: 'secondary' });
        const openLabel = escapeHtml(isFolder ? `Open folder ${item.name}` : `Preview file ${item.name}`);
        // The name (the primary open action) comes first in DOM so it is the first tab stop and
        // the destructive Delete is last; the two control clusters are position:absolute, so their
        // top-left / top-right placement is unchanged by trailing them in source order.
        return `
            <div class="file-tile ${isFolder ? 'is-folder' : ''} ${selected ? 'is-selected' : ''}">
                <div class="tile-icon">${icon}</div>
                <div class="file-name tile-name" ${nameAttrs} role="button" tabindex="0" aria-label="${openLabel}">${escapeHtml(item.name)}${lockIcon}</div>
                <div class="tile-meta">${meta}</div>
                <div class="tile-tl">${check}${primary}</div>
                <div class="tile-tr file-actions">${secondary}</div>
            </div>`;
    }).join('');
}

// Wire file-name / folder / action / checkbox handlers within a container
// (called fresh after each render of either view).
function wireFileItemHandlers(container) {
    if (!container) return;
    // Open the file/folder a name element points at (folder -> navigate, file -> preview).
    const openFromName = (elem) => {
        if (elem.hasAttribute('data-folder-id')) openFolder(elem.getAttribute('data-folder-id'), elem.getAttribute('data-folder-name'));
        else if (elem.hasAttribute('data-file-id')) openFilePreview(elem.getAttribute('data-file-id'), elem.getAttribute('data-file-name'), elem.getAttribute('data-mime'));
    };
    container.querySelectorAll('.file-name[data-folder-id], .file-name[data-file-id]').forEach(elem => {
        elem.addEventListener('click', () => openFromName(elem));
        // Keyboard: the grid tile name is role=button tabindex=0, so make Enter/Space
        // activate it too (a plain div was mouse-only). preventDefault on Space stops
        // the page from scrolling.
        elem.addEventListener('keydown', (e) => {
            if (e.repeat) return;  // holding the key must not re-open repeatedly
            if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); openFromName(elem); }
        });
    });
    // Whole-card click in grid view: clicking anywhere on a tile that is NOT an action
    // control opens the item. .file-tile exists only in the grid render, so this is a
    // no-op in the table view. The guard (incl. .file-name) keeps a name/button/checkbox
    // click from firing this a second time.
    container.querySelectorAll('.file-tile').forEach(tile => {
        tile.addEventListener('click', (e) => {
            if (e.target.closest('button, input, a, .file-actions, .tile-tl, .tile-tr, .file-check, .file-name')) return;
            const nameEl = tile.querySelector('.file-name');
            if (nameEl) openFromName(nameEl);
        });
    });
    container.querySelectorAll('button[data-action]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const action = btn.getAttribute('data-action');
            const id = btn.getAttribute('data-id');
            const name = btn.getAttribute('data-name');
            if (action === 'download') downloadFile(id, name);
            else if (action === 'rename-file' || action === 'rename-folder') renameVaultItem(id, name, action === 'rename-folder' ? 'folder' : 'file');
            else if (action === 'delete-file' || action === 'delete-folder') deleteVaultItem(id, name, action === 'delete-folder' ? 'folder' : 'file');
        });
    });
    container.querySelectorAll('.file-check').forEach(cb => {
        cb.addEventListener('click', (e) => e.stopPropagation());
        cb.addEventListener('change', () => toggleFileSelected(cb.getAttribute('data-id'), cb.checked));
    });
}

function toggleFileSelected(id, on) {
    if (!(state.selectedFileIds instanceof Set)) state.selectedFileIds = new Set();
    if (on) state.selectedFileIds.add(id); else state.selectedFileIds.delete(id);
    document.querySelectorAll(`.file-check[data-id="${id}"]`).forEach(cb => {
        cb.checked = on;
        const row = cb.closest('tr, .file-tile');
        if (row) row.classList.toggle('is-selected', on);
    });
    updateFilesBulkBar();
}

function updateFilesBulkBar() {
    const count = (state.selectedFileIds && state.selectedFileIds.size) || 0;
    const bar = document.getElementById('files-bulk-bar');
    const countEl = document.getElementById('files-bulk-count');
    if (countEl) countEl.textContent = count;
    if (bar) bar.hidden = count === 0;
    // Cap-gate the bulk actions (matches the per-row buttons + require_vault_cap).
    const dl = document.getElementById('files-bulk-download');
    if (dl) dl.style.display = bulkDownloadAllowed() ? '' : 'none';
    const del = document.getElementById('files-bulk-delete');
    if (del) del.style.display = bulkDeleteAllowed() ? '' : 'none';
    const all = document.getElementById('files-select-all');
    if (all && all.parentElement) all.parentElement.style.display = allowBulkSelect() ? '' : 'none';
    if (all) {
        const selectable = (state.currentFiles || []).filter(i => i.type !== 'folder').length;
        all.checked = selectable > 0 && count >= selectable;
        all.indeterminate = count > 0 && count < selectable;
    }
}

// Wire the view-switch, select-all and bulk-bar controls exactly once.
function setupFilesViewControls() {
    if (state._filesCtrlWired) return;
    state._filesCtrlWired = true;
    document.querySelectorAll('[data-files-view]').forEach(btn => {
        btn.addEventListener('click', () => {
            state.filesView = btn.getAttribute('data-files-view') === 'grid' ? 'grid' : 'table';
            try { localStorage.setItem('filesView', state.filesView); } catch (_) {}
            renderVaultFiles();
        });
    });
    const all = document.getElementById('files-select-all');
    if (all) all.addEventListener('change', () => {
        if (!(state.selectedFileIds instanceof Set)) state.selectedFileIds = new Set();
        const files = (state.currentFiles || []).filter(i => i.type !== 'folder');
        if (all.checked) files.forEach(i => state.selectedFileIds.add(i.id));
        else state.selectedFileIds.clear();
        renderVaultFiles();
    });
    const dl = document.getElementById('files-bulk-download');
    if (dl) dl.addEventListener('click', bulkDownloadFiles);
    const del = document.getElementById('files-bulk-delete');
    if (del) del.addEventListener('click', bulkDeleteFiles);
    const clear = document.getElementById('files-bulk-clear');
    if (clear) clear.addEventListener('click', () => { if (state.selectedFileIds) state.selectedFileIds.clear(); renderVaultFiles(); });
}

async function bulkDownloadFiles() {
    const ids = Array.from(state.selectedFileIds || []);
    if (!ids.length) return;
    const byId = new Map((state.currentFiles || []).map(i => [i.id, i]));
    for (const id of ids) {
        const item = byId.get(id);
        if (item) { await downloadFile(id, item.name); await new Promise(r => setTimeout(r, 300)); }
    }
}

async function bulkDeleteFiles() {
    const ids = Array.from(state.selectedFileIds || []);
    if (!ids.length) return;
    const ok = await showConfirm(
        `Delete ${ids.length} selected file${ids.length > 1 ? 's' : ''}? This cannot be undone.`,
        'Confirm Delete');
    if (!ok) return;
    const headers = {};
    if (state.currentVault && state.currentVault.has_password && state.vaultPassword) headers['X-Vault-Password'] = state.vaultPassword;
    showInfo(`Deleting ${ids.length} file${ids.length > 1 ? 's' : ''}…`);
    let failed = 0;
    for (const id of ids) {
        try { await apiRequest(`/vaults/${state.currentVault.id}/files/${id}/delete`, { method: 'POST', headers }); }
        catch (_) { failed++; }
    }
    state.selectedFileIds.clear();
    if (failed) showError(`${failed} file(s) could not be deleted`); else showSuccess('Deleted selected files');
    await loadVaultFiles();
}

function getFileIcon(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const iconMap = {
        // Documents
        'pdf': 'file-text',
        'doc': 'file-text', 'docx': 'file-text',
        'txt': 'file-text',
        'md': 'file-text',
        // Images
        'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'gif': 'image', 'svg': 'image',
        // Videos
        'mp4': 'film', 'avi': 'film', 'mov': 'film', 'mkv': 'film',
        // Audio
        'mp3': 'music', 'wav': 'music', 'flac': 'music',
        // Archives
        'zip': 'archive', 'rar': 'archive', 'tar': 'archive', 'gz': 'archive', '7z': 'archive',
        // Code
        'js': 'code', 'py': 'code', 'java': 'code', 'cpp': 'code', 'c': 'code',
        'html': 'globe', 'css': 'code', 'json': 'code',
    };
    return iconSvg(iconMap[ext] || 'file');
}

// Update breadcrumb navigation
function updateBreadcrumb() {
    const breadcrumb = document.getElementById('vault-breadcrumb');
    if (!breadcrumb) return;
    
    let html = '<span class="breadcrumb-item active" data-folder-id="">Root</span>';
    
    if (state.currentPath && state.currentPath.length > 0) {
        state.currentPath.forEach((folder, index) => {
            const isLast = index === state.currentPath.length - 1;
            html += `<span class="breadcrumb-item ${isLast ? 'active' : ''}" data-folder-id="${folder.id}">${escapeHtml(folder.name)}</span>`;
        });
    }
    
    breadcrumb.innerHTML = html;
    
    // Add click handlers for breadcrumb items
    breadcrumb.querySelectorAll('.breadcrumb-item').forEach(item => {
        item.addEventListener('click', () => {
            const folderId = item.getAttribute('data-folder-id');
            navigateToFolder(folderId);
        });
    });
}

// Open folder
async function openFolder(folderId, folderName) {
    // Add to path
    state.currentPath.push({ id: folderId, name: folderName });
    state.currentFolderId = folderId;

    // Reload files
    await loadVaultFiles();
    saveNavState();  // remember the folder so a refresh restores it
}

// Navigate to folder by ID (used by breadcrumb)
async function navigateToFolder(folderId) {
    if (!folderId) {
        // Navigate to root
        state.currentPath = [];
        state.currentFolderId = null;
    } else {
        // Find folder in path and navigate there
        const folderIndex = state.currentPath.findIndex(f => f.id === folderId);
        if (folderIndex >= 0) {
            state.currentPath = state.currentPath.slice(0, folderIndex + 1);
            state.currentFolderId = folderId;
        }
    }

    // Reload files
    await loadVaultFiles();
    saveNavState();
}

// ===========================================================================
// Zero-knowledge (client-side encrypted) vaults
// ---------------------------------------------------------------------------
// For type=zero_knowledge vaults the server stores only opaque ciphertext. The
// browser holds the user's ECC private key (decrypted from a passphrase) and a
// per-vault DEK (unwrapped via ECDH); files are encrypted before upload and
// decrypted after download. The crypto primitives live in ecc_crypto.js
// (ECCCryptoLibrary); the server only ever WRAPS with public keys (never unwraps).
// ===========================================================================
let _eccLib = null;
function eccLib() {
    if (!_eccLib) {
        if (typeof ECCCryptoLibrary === 'undefined') {
            throw new Error('Encryption library failed to load — reload the page.');
        }
        _eccLib = new ECCCryptoLibrary();
    }
    return _eccLib;
}

// In-memory only; cleared on logout. privateKey: CryptoKey;
// vaultDeks: vaultId -> { [keyVersion]: CryptoKey } (forward-only DEK rotation means a
// vault can have several live DEK epochs — old files keep their epoch, new files use the
// current one — so the DEK cache is keyed by (vault, epoch), not just vault).
// teamKeys: vaultId -> { [team_key_version]: CryptoKey } — non-extractable team PRIVATE keys
// for hierarchical vaults (a separate cache from vaultDeks; MUST be cleared on logout too).
// pinnedHier: vaultId -> true once we've seen the vault is hierarchical (at create, or on the
// first hierarchical /keys read). A server that later serves a DIRECT key for a pinned-hierarchical
// vault is attempting a mode downgrade — zkGetVaultDek refuses rather than silently fail the
// (already fail-closed) unwrap. In-session only; the crypto fails closed regardless of the pin.
const zkState = { privateKey: null, vaultDeks: {}, teamKeys: {}, pinnedHier: {} };
function zkResetKeys() { zkState.privateKey = null; zkState.vaultDeks = {}; zkState.teamKeys = {}; zkState.pinnedHier = {}; }

function isZkVault(v) { return !!v && v.type === 'zero_knowledge'; }

// Unlock the user's ECC private key into memory (prompts for the passphrase once
// per session). Returns the CryptoKey.
async function zkEnsureUnlocked() {
    if (zkState.privateKey) return zkState.privateKey;
    const priv = await apiRequest('/ecc/keys/private', { silent: true });
    if (!priv || !priv.has_keypair || !priv.encrypted_private_key) {
        throw new Error('No encryption key is set up for your account.');
    }
    let bundle;
    try { bundle = JSON.parse(priv.encrypted_private_key); }
    catch (_) { throw new Error('Stored encryption key is in an unexpected format.'); }
    if (!bundle || !bundle.encrypted || !bundle.salt) {
        throw new Error('Stored encryption key is incomplete or corrupt — re-register your key.');
    }
    const pass = await showPrompt(
        'Enter your encryption passphrase to unlock zero-knowledge vaults.',
        'Unlock encryption key', { password: true }
    );
    if (pass === null) throw new Error('Unlock cancelled.');
    let pem;
    try {
        pem = await eccLib().decryptPrivateKey(bundle.encrypted, pass, bundle.salt, bundle.iterations);
    } catch (e) {
        // AES-GCM auth failure is indistinguishable from a wrong key, but log the
        // real cause so genuine corruption / unavailable-WebCrypto isn't masked.
        console.error('Private-key unlock failed:', e);
        throw new Error('Incorrect passphrase (or the stored key is corrupt).');
    }
    zkState.privateKey = await eccLib().importPrivateKeyPEM(pem, false);  // non-extractable runtime key
    return zkState.privateKey;
}

// Generate a fresh ECC keypair, protect the private key under a user passphrase,
// and register it (public key + opaque encrypted-private blob the server can't
// read). Leaves a NON-extractable runtime private key unlocked in memory. Shared
// by ZK vault creation (first time) and the standalone "set up key" action.
// Throws Error('Setup cancelled.') if the user backs out of either prompt.
async function zkRegisterNewKeypair() {
    // Prominent, acknowledged warning: the ZK passphrase is the ONLY key to the
    // user's zero-knowledge vaults, is never sent to the server, and cannot be reset or
    // recovered by anyone. Make the user ACTIVELY acknowledge irrecoverability (a dedicated
    // confirm dialog, not just a line in the passphrase prompt) BEFORE they set a passphrase.
    // Covers both setup paths (ZK vault creation + the standalone "set up my key" modal).
    const acknowledged = await showConfirm(
        'Your encryption passphrase is the ONLY key to your zero-knowledge vaults. '
        + 'It is never sent to the server and CANNOT be reset or recovered by anyone — not even an administrator. '
        + 'If you lose it, everything in your zero-knowledge vaults becomes permanently unrecoverable. '
        + 'Store it somewhere safe, such as a password manager. Do you understand and want to continue?',
        'Zero-knowledge: your passphrase cannot be recovered'
    );
    if (!acknowledged) throw new Error('Setup cancelled.');
    const pass = await showPrompt(
        'Create a passphrase to protect your encryption key. You will need it to open zero-knowledge vaults — it CANNOT be recovered if lost.',
        'Set up encryption key', { password: true }
    );
    if (pass === null) throw new Error('Setup cancelled.');
    if (!pass || pass.length < 8) throw new Error('Passphrase must be at least 8 characters.');
    const confirm = await showPrompt('Re-enter your passphrase to confirm.', 'Confirm passphrase', { password: true });
    if (confirm === null) throw new Error('Setup cancelled.');
    if (confirm !== pass) throw new Error('Passphrases do not match.');

    const lib = eccLib();
    const kp = await lib.generateKeypair();
    const publicPem = await lib.exportPublicKeyPEM(kp.publicKey);
    const privatePem = await lib.exportPrivateKeyPEM(kp.privateKey);
    const enc = await lib.encryptPrivateKey(privatePem, pass);  // {encrypted, salt, iterations}
    // Proof-of-possession: prove we hold this key's private half (ECDH key-confirmation) so the
    // server won't accept a substituted/unheld public key.
    const challenge = await apiRequest('/ecc/keys/register/challenge', { method: 'POST' });
    const mac = await lib.computeRegistrationPoP(
        challenge.server_ephemeral_public_key, challenge.nonce, publicPem, kp.privateKey);
    await apiRequest('/ecc/keys/register', {
        method: 'POST',
        body: JSON.stringify({
            public_key: publicPem,
            // Pack salt+iterations into the opaque blob so a later session can
            // decrypt it; the server stores this verbatim and cannot read it.
            encrypted_private_key: JSON.stringify(enc),
            key_salt: enc.salt,
            key_iterations: enc.iterations,
            pop: { challenge_id: challenge.challenge_id, mac },
        }),
    });
    // Hold a NON-extractable runtime copy (the generated key was extractable only
    // so we could export + password-encrypt it above).
    zkState.privateKey = await lib.importPrivateKeyPEM(privatePem, false);
}

// Change the encryption passphrase: unlock the private key with the CURRENT passphrase,
// re-wrap it under a NEW passphrase IN THE BROWSER, and PUT the new blob. The PUBLIC key is
// unchanged, so every vault DEK stays valid — the user just unlocks with the new passphrase
// from now on (this is a passphrase change, not a key rotation). Throws Error('Cancelled.')
// if the user backs out of any prompt.
async function zkChangePassphrase() {
    const priv = await apiRequest('/ecc/keys/private', { silent: true });
    if (!priv || !priv.has_keypair || !priv.encrypted_private_key) {
        throw new Error('No encryption key is set up for your account.');
    }
    let bundle;
    try { bundle = JSON.parse(priv.encrypted_private_key); }
    catch (_) { throw new Error('Stored encryption key is in an unexpected format.'); }
    if (!bundle || !bundle.encrypted || !bundle.salt) {
        throw new Error('Stored encryption key is incomplete or corrupt.');
    }
    const current = await showPrompt('Enter your CURRENT encryption passphrase.', 'Change passphrase', { password: true });
    if (current === null) throw new Error('Cancelled.');
    let pem;
    try {
        pem = await eccLib().decryptPrivateKey(bundle.encrypted, current, bundle.salt, bundle.iterations);
    } catch (e) {
        console.error('Passphrase-change unlock failed:', e);
        throw new Error('Incorrect current passphrase (or the stored key is corrupt).');
    }
    const next = await showPrompt('Enter a NEW passphrase. It protects your key and CANNOT be recovered if lost.', 'New passphrase', { password: true });
    if (next === null) throw new Error('Cancelled.');
    if (!next || next.length < 8) throw new Error('Passphrase must be at least 8 characters.');
    const confirm = await showPrompt('Re-enter your NEW passphrase to confirm.', 'Confirm new passphrase', { password: true });
    if (confirm === null) throw new Error('Cancelled.');
    if (confirm !== next) throw new Error('Passphrases do not match.');

    const enc = await eccLib().encryptPrivateKey(pem, next);  // {encrypted, salt, iterations}
    await apiRequest('/ecc/keys/private', {
        method: 'PUT',
        body: JSON.stringify({ encrypted_private_key: JSON.stringify(enc) }),
    });
    // Keep a NON-extractable runtime copy so the session stays unlocked with the same key.
    zkState.privateKey = await eccLib().importPrivateKeyPEM(pem, false);
}

// Export a recovery kit: re-wrap the private key under a SEPARATE recovery passphrase and download
// it as a file. The user stores it out-of-band; if they later forget their main passphrase they can
// restore access with the recovery passphrase (zkRestoreFromRecoveryKey). Everything happens in the
// browser — the kit holds only ciphertext the server never sees. Throws Error('Cancelled.') on
// back-out.
async function zkExportRecoveryKey() {
    const priv = await apiRequest('/ecc/keys/private', { silent: true });
    if (!priv || !priv.has_keypair || !priv.encrypted_private_key) throw new Error('No encryption key is set up for your account.');
    let bundle;
    try { bundle = JSON.parse(priv.encrypted_private_key); }
    catch (_) { throw new Error('Stored encryption key is in an unexpected format.'); }
    if (!bundle || !bundle.encrypted || !bundle.salt) throw new Error('Stored encryption key is incomplete or corrupt.');
    const current = await showPrompt('Enter your CURRENT encryption passphrase to export a recovery key.', 'Export recovery key', { password: true });
    if (current === null) throw new Error('Cancelled.');
    let pem;
    try { pem = await eccLib().decryptPrivateKey(bundle.encrypted, current, bundle.salt, bundle.iterations); }
    catch (e) { console.error('Recovery export unlock failed:', e); throw new Error('Incorrect current passphrase (or the stored key is corrupt).'); }
    const rec = await showPrompt('Choose a RECOVERY passphrase. Store it somewhere safe and SEPARATE from your normal passphrase — it protects the recovery key you are about to download.', 'Recovery passphrase', { password: true });
    if (rec === null) throw new Error('Cancelled.');
    if (!rec || rec.length < 8) throw new Error('Recovery passphrase must be at least 8 characters.');
    const confirm = await showPrompt('Re-enter your RECOVERY passphrase to confirm.', 'Confirm recovery passphrase', { password: true });
    if (confirm === null) throw new Error('Cancelled.');
    if (confirm !== rec) throw new Error('Passphrases do not match.');

    const enc = await eccLib().encryptPrivateKey(pem, rec);  // {encrypted, salt, iterations}
    const pub = await apiRequest('/ecc/keys/public', { silent: true });
    const kit = {
        type: 'dockvault-zk-recovery-key',
        version: 1,
        user_id: (typeof currentUser !== 'undefined' && currentUser && currentUser.id) || null,
        fingerprint: (pub && pub.fingerprint) || null,
        public_key: (pub && pub.public_key) || null,   // to verify the kit matches this account on restore
        recovery: enc,
    };
    const blob = new Blob([JSON.stringify(kit, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dockvault-recovery-key-${kit.fingerprint || 'key'}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

// Restore access from a recovery kit: decrypt the recovery-wrapped private key with the recovery
// passphrase, verify it belongs to THIS account (its public key must match the registered one),
// re-wrap it under a NEW main passphrase, and store it (PUT /ecc/keys/private). Used when the main
// passphrase was lost. Throws Error('Cancelled.') on back-out.
async function zkRestoreFromRecoveryKey(kitText) {
    let kit;
    try { kit = JSON.parse(kitText); }
    catch (_) { throw new Error('That file is not a valid recovery key.'); }
    if (!kit || kit.type !== 'dockvault-zk-recovery-key' || !kit.recovery || !kit.recovery.encrypted) {
        throw new Error('That file is not a DockVault recovery key.');
    }
    const pub = await apiRequest('/ecc/keys/public', { silent: true });
    if (!pub || !pub.has_keypair || !pub.public_key) throw new Error('This account has no encryption key to restore.');
    // Fast pre-check on the kit's ASSERTED public key (untrusted metadata — a nicety so an
    // obviously-wrong kit is rejected before asking for the recovery passphrase).
    if (kit.public_key && kit.public_key.trim() !== pub.public_key.trim()) {
        throw new Error('This recovery key is for a different account or keypair.');
    }
    const rec = await showPrompt('Enter the RECOVERY passphrase for this recovery key.', 'Restore access', { password: true });
    if (rec === null) throw new Error('Cancelled.');
    let pem;
    try { pem = await eccLib().decryptPrivateKey(kit.recovery.encrypted, rec, kit.recovery.salt, kit.recovery.iterations); }
    catch (e) { console.error('Recovery restore decrypt failed:', e); throw new Error('Incorrect recovery passphrase (or the recovery key is corrupt).'); }
    // SECURITY: verify the DECRYPTED private key actually matches this account's registered public
    // key. The kit's asserted public_key is untrusted metadata (a corrupt/forged/null-public_key
    // kit could carry a different private key), so derive the public key FROM the private key and
    // compare — adopting a mismatched key would silently orphan every wrapped DEK (permanent lockout).
    let derivedPub;
    try { derivedPub = await eccLib().derivePublicKeyPEMFromPrivatePEM(pem); }
    catch (e) { console.error('Recovery key derive failed:', e); throw new Error('The recovery key is corrupt or not a valid key.'); }
    if (derivedPub.trim() !== pub.public_key.trim()) {
        throw new Error("This recovery key does not match your account's encryption key and cannot be restored.");
    }
    const next = await showPrompt('Set a NEW encryption passphrase. It replaces your forgotten one and CANNOT be recovered if lost.', 'New passphrase', { password: true });
    if (next === null) throw new Error('Cancelled.');
    if (!next || next.length < 8) throw new Error('Passphrase must be at least 8 characters.');
    const confirm = await showPrompt('Re-enter your NEW passphrase to confirm.', 'Confirm new passphrase', { password: true });
    if (confirm === null) throw new Error('Cancelled.');
    if (confirm !== next) throw new Error('Passphrases do not match.');

    const enc = await eccLib().encryptPrivateKey(pem, next);
    await apiRequest('/ecc/keys/private', { method: 'PUT', body: JSON.stringify({ encrypted_private_key: JSON.stringify(enc) }) });
    zkState.privateKey = await eccLib().importPrivateKeyPEM(pem, false);
}

// Ensure the user has an ECC keypair: create + register one (first time) or just
// unlock the existing one. Leaves the private key unlocked in memory.
async function zkEnsureKeypair() {
    const pub = await apiRequest('/ecc/keys/public', { silent: true });
    if (pub && pub.has_keypair) { await zkEnsureUnlocked(); return; }
    try {
        await zkRegisterNewKeypair();
    } catch (e) {
        // Race: a keypair appeared (another tab/device) between the has_keypair
        // check and our register, so the server refused to overwrite (409). Unlock
        // the existing one instead of failing.
        if (e && e.status === 409) { await zkEnsureUnlocked(); return; }
        throw e;
    }
}

// --- Standalone "set up my encryption key" (account-level, profile menu) ------
// Lets any user create their ZK keypair WITHOUT first making a zero-knowledge
// vault, so others can share ZK vaults with them (per-user sharing wraps the DEK
// to the recipient's public key, which must already exist).
async function openEncryptionKeyModal() {
    const modal = document.getElementById('encryption-key-modal');
    if (!modal) return;
    modal.classList.add('active');
    await refreshEncryptionKeyStatus();
}

// SHA-256 fingerprint of the public-key PEM, grouped hex — lets a user verify a
// recipient's key out-of-band. Best-effort; returns '' on any failure.
async function zkKeyFingerprint(pem) {
    try {
        const data = new TextEncoder().encode((pem || '').trim());
        const digest = await crypto.subtle.digest('SHA-256', data);
        const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
        return hex.slice(0, 32).replace(/(.{4})/g, '$1 ').trim().toUpperCase();
    } catch (_) { return ''; }
}

async function refreshEncryptionKeyStatus() {
    const statusEl = document.getElementById('encryption-key-status');
    const hintEl = document.getElementById('encryption-key-hint');
    const setupBtn = document.getElementById('encryption-key-setup-btn');
    const changeBtn = document.getElementById('encryption-key-change-passphrase-btn');
    const recoveryEl = document.getElementById('encryption-key-recovery');
    if (!statusEl) return;
    statusEl.replaceChildren();
    if (changeBtn) changeBtn.style.display = 'none';   // only shown once a key exists
    if (recoveryEl) recoveryEl.style.display = 'none'; // ditto for the recovery-key actions
    let pub = null, lookupFailed = false;
    try { pub = await apiRequest('/ecc/keys/public', { silent: true }); } catch (_) { lookupFailed = true; }

    if (lookupFailed) {
        // Couldn't determine status — do NOT imply "no key" (that would push the
        // user toward re-creating a key they may already have). Keep setup hidden.
        const warn = document.createElement('div');
        warn.className = 'alert alert-warning';
        warn.textContent = "Couldn't check your encryption-key status. Check your connection and try again.";
        statusEl.appendChild(warn);
        if (hintEl) hintEl.style.display = 'none';
        if (setupBtn) { setupBtn.style.display = 'none'; setupBtn.disabled = true; }
    } else if (pub && pub.has_keypair) {
        // Already set up — show status + fingerprint. We deliberately do NOT offer
        // re-setup here: a new keypair would orphan every wrapped DEK and lock the
        // user out of their existing zero-knowledge vaults.
        const badge = document.createElement('div');
        badge.className = 'alert alert-success';
        badge.textContent = 'Your encryption key is set up and active.';
        statusEl.appendChild(badge);
        const fp = await zkKeyFingerprint(pub.public_key);
        if (fp) {
            const fpRow = document.createElement('div');
            fpRow.className = 'text-tertiary text-sm';
            fpRow.style.marginTop = '8px';
            const label = document.createElement('span');
            label.textContent = 'Key fingerprint: ';
            const code = document.createElement('code');
            code.textContent = fp;
            fpRow.append(label, code);
            statusEl.appendChild(fpRow);
        }
        if (hintEl) hintEl.style.display = 'none';
        if (setupBtn) setupBtn.style.display = 'none';
        if (changeBtn) changeBtn.style.display = '';    // offer a passphrase change
        if (recoveryEl) recoveryEl.style.display = '';  // offer recovery-key export / restore
    } else {
        const note = document.createElement('div');
        note.className = 'alert alert-info';
        note.textContent = "You don't have an encryption key yet. Set one up to use zero-knowledge "
            + "vaults and let others share them with you.";
        statusEl.appendChild(note);
        if (hintEl) hintEl.style.display = '';
        if (setupBtn) { setupBtn.style.display = ''; setupBtn.disabled = false; }
    }
}

async function setupEncryptionKey() {
    const setupBtn = document.getElementById('encryption-key-setup-btn');
    try {
        // Re-check server-side: never clobber an existing key (would orphan DEKs).
        const pub = await apiRequest('/ecc/keys/public', { silent: true });
        if (pub && pub.has_keypair) {
            showInfo('Your encryption key is already set up.');
            await refreshEncryptionKeyStatus();
            return;
        }
        if (setupBtn) setupBtn.disabled = true;
        await zkRegisterNewKeypair();
        showSuccess('Encryption key set up. You can now use and be granted zero-knowledge vaults.');
    } catch (e) {
        const msg = (e && e.message) || '';
        if (e && e.status === 409) {
            // A key already exists (e.g. created in another tab) — the server
            // refused to overwrite. Treat as success, not an error.
            showInfo('Your encryption key is already set up.');
        } else if (!/cancelled/i.test(msg)) {
            showError(msg || 'Failed to set up encryption key');
        }
    } finally {
        if (setupBtn) setupBtn.disabled = false;
        await refreshEncryptionKeyStatus();
    }
}

async function changeEncryptionPassphrase() {
    const btn = document.getElementById('encryption-key-change-passphrase-btn');
    try {
        if (btn) btn.disabled = true;
        await zkChangePassphrase();
        showSuccess('Encryption passphrase changed. Use your new passphrase from now on.');
    } catch (e) {
        const msg = (e && e.message) || '';
        if (!/cancelled/i.test(msg)) showError(msg || 'Failed to change passphrase');
    } finally {
        if (btn) btn.disabled = false;
        await refreshEncryptionKeyStatus();
    }
}

async function exportRecoveryKey() {
    const btn = document.getElementById('encryption-key-export-recovery-btn');
    try {
        if (btn) btn.disabled = true;
        await zkExportRecoveryKey();
        showSuccess('Recovery key downloaded. Store it somewhere safe and separate from your passphrase.');
    } catch (e) {
        const msg = (e && e.message) || '';
        if (!/cancelled/i.test(msg)) showError(msg || 'Failed to export recovery key');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function restoreFromRecoveryKeyFile(file) {
    if (!file) return;
    try {
        const text = await file.text();
        await zkRestoreFromRecoveryKey(text);
        showSuccess('Access restored. Use your new passphrase from now on.');
    } catch (e) {
        const msg = (e && e.message) || '';
        if (!/cancelled/i.test(msg)) showError(msg || 'Failed to restore from recovery key');
    } finally {
        await refreshEncryptionKeyStatus();
    }
}

// Get (and cache) the unwrapped AES DEK for a zero-knowledge vault at a given epoch.
// keyVersion null/undefined => the vault's CURRENT epoch (for upload/encrypt/share). To
// read an existing file, pass that file's epoch (item.key_version, defaulting to 1) so a
// file written before a rotation is decrypted with the DEK it was actually encrypted under.
async function zkGetVaultDek(vaultId, keyVersion = null) {
    const perVault = zkState.vaultDeks[vaultId] || (zkState.vaultDeks[vaultId] = {});
    if (keyVersion != null && perVault[keyVersion]) return perVault[keyVersion];
    const priv = await zkEnsureUnlocked();
    const q = keyVersion != null ? `?key_version=${encodeURIComponent(keyVersion)}` : '';
    const keys = await apiRequest(`/ecc/vaults/${vaultId}/keys${q}`, { silent: true });
    if (!keys || !keys.has_access || !keys.wrapped_dek) {
        throw new Error('You do not have a key for this zero-knowledge vault.');
    }
    // Resolve the epoch actually returned (the server echoes key_version) and cache under it.
    const version = keys.key_version != null ? keys.key_version : (keyVersion != null ? keyVersion : 1);
    if (perVault[version]) return perVault[version];
    // HIERARCHICAL: the DEK is wrapped to the TEAM public key, so unwrap the team PRIVATE key
    // first (with our identity key) and use IT to unwrap the DEK. The presence of a team-priv
    // blob — not the advisory `mode` string alone — drives this branch; if a hierarchical vault
    // were mis-served as direct the user-key unwrap would fail closed (the ephemeral agreed with
    // the team pubkey, not the user's), never leaking a key.
    let dek;
    if (keys.wrapped_team_privkey && keys.team_ephemeral_public_key) {
        zkState.pinnedHier[vaultId] = true;  // pin: this vault is hierarchical
        const teamPriv = await zkGetTeamPrivKey(
            vaultId, keys.team_key_version, keys.wrapped_team_privkey, keys.team_ephemeral_public_key);
        dek = await eccLib().unwrapVaultDEK(keys.wrapped_dek, keys.ephemeral_public_key, teamPriv);
    } else {
        // Downgrade defense: a vault we have seen as hierarchical must never be served a DIRECT
        // key. Refuse loudly rather than fall through (the direct unwrap would fail closed anyway).
        if (zkState.pinnedHier[vaultId]) {
            throw new Error('This zero-knowledge vault is hierarchical but the server returned a direct key — refusing (possible mode downgrade).');
        }
        dek = await eccLib().unwrapVaultDEK(keys.wrapped_dek, keys.ephemeral_public_key, priv);
    }
    perVault[version] = dek;
    return dek;
}

// Unwrap (and cache) a hierarchical vault's TEAM PRIVATE key at a given team epoch. The wrapped
// blob + its ephemeral come from the /keys response (no extra fetch). Cached per (vault, team
// epoch); the runtime key is non-extractable. Cleared on logout via zkResetKeys.
async function zkGetTeamPrivKey(vaultId, teamEpoch, wrappedTeamPrivkey, teamEphemeralPublicKey) {
    const perVault = zkState.teamKeys[vaultId] || (zkState.teamKeys[vaultId] = {});
    if (teamEpoch != null && perVault[teamEpoch]) return perVault[teamEpoch];
    const priv = await zkEnsureUnlocked();
    const teamPriv = await eccLib().unwrapPrivateKeyFromWrapped(
        wrappedTeamPrivkey, teamEphemeralPublicKey, priv, false);
    if (teamEpoch != null) perVault[teamEpoch] = teamPriv;
    return teamPriv;
}

// The vault's current DEK epoch — what new uploads must encrypt under and declare.
async function zkGetCurrentDekVersion(vaultId) {
    const keys = await apiRequest(`/ecc/vaults/${vaultId}/keys`, { silent: true });
    return (keys && keys.current_dek_version) || 1;
}

// Decrypt a downloaded blob when the given vault is zero-knowledge; else pass through.
// keyVersion is the file's DEK epoch (from the listing; null/absent => epoch 1).
async function zkMaybeDecryptBlob(blob, vault, keyVersion = null) {
    if (!isZkVault(vault)) return blob;
    const dek = await zkGetVaultDek(vault.id, keyVersion != null ? keyVersion : 1);
    const plain = await eccLib().decryptFile(await blob.arrayBuffer(), dek);
    return new Blob([plain], { type: blob.type || 'application/octet-stream' });
}

// Look up a file's DEK epoch from the loaded listing (state.currentFiles). Absent => 1.
function zkFileKeyVersion(fileId) {
    const item = (state.currentFiles || []).find(i => i.id === fileId);
    return item && item.key_version != null ? item.key_version : 1;
}

// The DEK epoch a listing item's NAME is encrypted under. Files: their content epoch
// (key_version). Folders: their own name_key_version. Absent => 1.
function zkNameEpoch(item) {
    if (!item) return 1;
    if (item.type === 'folder') return item.name_key_version != null ? item.name_key_version : 1;
    return item.key_version != null ? item.key_version : 1;
}

// A client-generated UUID for a new zero-knowledge file/folder. It is bound INTO the sealed
// name (v2 AAD) at seal time and sent back to the server as the row id, so the stored row id
// always matches the id the name was sealed under (the anti-transposition binding). Prefer
// crypto.randomUUID (secure contexts); fall back to a getRandomValues-based v4 so the id — and
// therefore the binding — is always available, and never undefined (encryptName requires it).
function zkNewObjId() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') return window.crypto.randomUUID();
    const b = new Uint8Array(16);
    window.crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;  // version 4
    b[8] = (b[8] & 0x3f) | 0x80;  // variant 10
    const h = [...b].map(x => x.toString(16).padStart(2, '0'));
    return `${h[0]}${h[1]}${h[2]}${h[3]}-${h[4]}${h[5]}-${h[6]}${h[7]}-${h[8]}${h[9]}-${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}`;
}

// Decrypt the browser-encrypted names/MIME in a zero-knowledge listing IN PLACE, so the
// rest of the UI keeps using item.name / item.mime_type unchanged. Rows still holding a
// plaintext name (legacy, not yet sealed) are left as-is (and later sealed). A row whose
// name epoch we lack a DEK for (e.g. a member added after a rotation) is shown as locked
// rather than failing the whole listing.
async function zkDecryptListingNames(items, vault) {
    // Nothing encrypted to decrypt (empty vault or only legacy plaintext rows) — don't prompt.
    if (!items.some(it => it.enc_name)) return;
    // Unlock the account key ONCE up front. A wrong passphrase (or a corrupt/absent key) throws
    // here; surface it as a single clear error instead of letting the per-item catch below swallow
    // it, which used to leave every row silently showing "Encrypted name" with no explanation.
    try {
        await zkEnsureUnlocked();
    } catch (e) {
        for (const it of items) {
            if (it.enc_name) { it.name = '🔒 Encrypted name'; it.zkLocked = true; }
        }
        if (!/cancel/i.test(e.message || '')) showError(e.message);
        return;
    }
    for (const it of items) {
        if (!it.enc_name) continue;  // legacy plaintext row (it.name already set) — leave it
        const epoch = zkNameEpoch(it);
        try {
            const dek = await zkGetVaultDek(vault.id, epoch);
            it.name = await eccLib().decryptName(it.enc_name, dek, vault.id, 'name', epoch, it.id);
            if (it.enc_mime) {
                try { it.mime_type = await eccLib().decryptName(it.enc_mime, dek, vault.id, 'mime', epoch, it.id); }
                catch (_) { /* keep whatever the server returned for mime */ }
            }
            it.zkLocked = false;
        } catch (e) {
            it.name = '🔒 Encrypted name';
            it.zkLocked = true;  // can't decrypt this epoch — block preview/rename/download
        }
    }
}

// Lazily migrate EXISTING zero-knowledge rows whose name is still plaintext server-side:
// encrypt the name under the right DEK epoch in the browser and post the blobs so the
// server can swap the plaintext for ciphertext. Fire-and-forget, best effort, idempotent
// — the next listing returns the sealed form. A row whose epoch DEK we lack is skipped
// (another member / the owner, who holds every epoch, will seal it).
async function zkSealLegacyNames(vault, items) {
    const legacy = (items || []).filter(it => !it.enc_name && it.name && !it.zkLocked);
    if (!legacy.length) return;
    const payload = [];
    for (const it of legacy) {
        try {
            // Files keep their content epoch; legacy folders (no epoch yet) seal under the
            // vault's current epoch (the sealing member necessarily holds it).
            const epoch = it.type === 'folder'
                ? await zkGetCurrentDekVersion(vault.id)
                : zkNameEpoch(it);
            const dek = await zkGetVaultDek(vault.id, epoch);
            const entry = {
                id: it.id, kind: it.type,
                // Seal bound to the existing row id (v2) — upgrades a legacy plaintext name
                // straight to the obj-id-bound format.
                enc_name: await eccLib().encryptName(it.name, dek, vault.id, 'name', epoch, it.id),
                name_bi: await eccLib().nameBlindIndex(it.name, dek, vault.id, epoch),
            };
            if (it.type === 'folder') entry.name_key_version = epoch;
            if (it.type === 'file' && it.mime_type) {
                entry.enc_mime = await eccLib().encryptName(it.mime_type, dek, vault.id, 'mime', epoch, it.id);
            }
            payload.push(entry);
        } catch (_) { /* missing epoch DEK — leave for a member who has it */ }
    }
    if (!payload.length) return;
    try {
        // Send the vault password like every other vault-mutating call — without it a
        // password-protected ZK vault 401s and its legacy names would never get sealed.
        const headers = {};
        if (vault.has_password && state.vaultPassword) headers['X-Vault-Password'] = state.vaultPassword;
        await apiRequest(`/vaults/${vault.id}/zk/seal-names`, {
            method: 'POST', headers, body: JSON.stringify({ items: payload }), silent: true,
        });
    } catch (_) { /* best effort; retried on the next vault open */ }
}

// Share a zero-knowledge vault with another user: unwrap the DEK locally, re-wrap
// it to THEIR public key in the browser, and store the wrapped copy. The server
// never sees the DEK. Throws if the recipient hasn't set up an encryption key.
async function zkShareVaultToUser(vaultId, userId) {
    const pk = await apiRequest(`/ecc/users/${userId}/public-key`, { silent: true });
    if (!pk || !pk.has_keypair || !pk.public_key) {
        // Team-onboarding: a zero-knowledge DEK can't be wrapped for a keyless
        // recipient, so record an invite (prompts them to set up a key) and report an
        // actionable message. Best-effort — a failed invite still yields a clear reason.
        let invited = false;
        try {
            await apiRequest(`/ecc/vaults/${vaultId}/invites`, {
                method: 'POST', body: JSON.stringify({ user_id: userId }), silent: true,
            });
            invited = true;
        } catch (_) { /* fall through to the plain message */ }
        throw new Error(invited
            ? "that user hasn't set up an encryption key yet — we've asked them to set one up. Share again once they have."
            : "that user hasn't set up an encryption key yet, so they can't open a zero-knowledge vault.");
    }
    const recipientPub = await eccLib().importPublicKeyPEM(pk.public_key);
    const keys = await apiRequest(`/ecc/vaults/${vaultId}/keys`, { silent: true });
    if (keys && keys.wrapped_team_privkey && keys.team_ephemeral_public_key) {
        // HIERARCHICAL: re-wrap the TEAM PRIVATE key to the recipient (O(1) — the DEK is not
        // touched, it stays wrapped to the team public key). Unwrap an EXTRACTABLE copy just to
        // re-wrap it; never cache the extractable form.
        const myPriv = await zkEnsureUnlocked();
        const teamPriv = await eccLib().unwrapPrivateKeyFromWrapped(
            keys.wrapped_team_privkey, keys.team_ephemeral_public_key, myPriv, true);
        const { wrappedKey, ephemeralPublicKey } = await eccLib().wrapPrivateKeyToPublic(teamPriv, recipientPub);
        await apiRequest(`/ecc/vaults/${vaultId}/members`, {
            method: 'POST',
            body: JSON.stringify({ user_id: userId, wrapped_team_privkey: wrappedKey, team_ephemeral_public_key: ephemeralPublicKey }),
        });
        return;
    }
    // DIRECT: wrap the DEK straight to the recipient.
    const dek = await zkGetVaultDek(vaultId);  // unwrap with my key (may prompt once)
    const { wrappedDEK, ephemeralPublicKey } = await eccLib().wrapVaultDEK(dek, recipientPub);
    await apiRequest(`/ecc/vaults/${vaultId}/members`, {
        method: 'POST',
        body: JSON.stringify({ user_id: userId, wrapped_dek: wrappedDEK, ephemeral_public_key: ephemeralPublicKey }),
    });
}

// Team-onboarding (recipient side): if a manager has invited this (keyless) user
// to a zero-knowledge vault, prompt them once per session to set up an encryption key so the
// share can complete. Fully no-op for users who already have a key or have no invites.
let _zkInvitePrompted = false;
async function zkMaybePromptPendingInvites() {
    if (_zkInvitePrompted) return;
    let data;
    try { data = await apiRequest('/ecc/keys/invites', { silent: true }); }
    catch (_) { return; }
    if (!data || !data.needs_keypair || !data.count) return;
    _zkInvitePrompted = true;  // don't nag again this session, even if they decline
    const inviter = (data.invites && data.invites[0] && data.invites[0].invited_by_username) || 'A vault manager';
    const n = data.count;
    const ok = await showConfirm(
        `${inviter} wants to share ${n === 1 ? 'a zero-knowledge vault' : n + ' zero-knowledge vaults'} with you. ` +
        `Set up your encryption key now to receive ${n === 1 ? 'it' : 'them'}? Your passphrase never leaves your ` +
        `browser and cannot be recovered if lost.`,
        'Set up encryption key'
    );
    if (ok) { try { await setupEncryptionKey(); } catch (_) { /* user cancelled / handled inside */ } }
}

// Forward-only DEK rotation when revoking a zero-knowledge member. Mints a fresh DEK in
// the browser, re-wraps it for every REMAINING member, and atomically bumps the vault
// epoch server-side — so the revoked member (who still holds the old DEK) can no longer
// read NEW content. Existing files keep their old epoch and remain readable by remaining
// members. The server never sees the DEK. Retries once on a concurrent-rekey 409.
// NOTE (claims discipline): this does NOT retroactively protect content the removed member
// could already read — the DEK was extractable in their browser. See the revoke UI copy.
async function zkRekeyForRevoke(vaultId, revokedUserId) {
    for (let attempt = 0; attempt < 3; attempt++) {
        // 1) Authoritative remaining-member set + current epoch.
        const info = await apiRequest(`/ecc/vaults/${vaultId}/member-keys`, { silent: true });
        const fromVersion = info.current_dek_version || 1;
        if (info.mode === 'hierarchical') {
            try {
                await zkRotateTeamForRevoke(vaultId, revokedUserId, info, fromVersion);
            } catch (e) {
                if (e && e.status === 409 && attempt < 2) continue;
                throw e;
            }
            delete zkState.vaultDeks[vaultId];
            delete zkState.teamKeys[vaultId];
            return;
        }
        const remaining = (info.members || []).filter(uid => String(uid) !== String(revokedUserId));

        // 2) Mint a new DEK (never leaves the browser).
        const newDek = await eccLib().generateVaultDEK();

        // 3) Wrap the new DEK to each remaining member's public key.
        const memberKeys = [];
        for (const uid of remaining) {
            const pk = await apiRequest(`/ecc/users/${uid}/public-key`, { silent: true });
            if (!pk || !pk.has_keypair || !pk.public_key) {
                throw new Error('A remaining member has no encryption key; cannot rotate. Resolve their key setup and retry.');
            }
            const recipientPub = await eccLib().importPublicKeyPEM(pk.public_key);
            const { wrappedDEK, ephemeralPublicKey } = await eccLib().wrapVaultDEK(newDek, recipientPub);
            memberKeys.push({ user_id: uid, wrapped_dek: wrappedDEK, ephemeral_public_key: ephemeralPublicKey });
        }

        // 4) Commit atomically (revoke + rotate + re-wrap).
        try {
            await apiRequest(`/ecc/vaults/${vaultId}/rekey`, {
                method: 'POST',
                body: JSON.stringify({
                    from_version: fromVersion,
                    to_version: fromVersion + 1,
                    revoke_user_id: revokedUserId,
                    member_keys: memberKeys,
                }),
            });
        } catch (e) {
            if (e && e.status === 409 && attempt < 2) continue;  // someone else rotated; refetch + retry
            throw e;
        }
        // 5) Drop cached DEKs for this vault so subsequent reads/writes refetch the new epoch.
        delete zkState.vaultDeks[vaultId];
        return;
    }
    throw new Error('Key rotation kept colliding with concurrent changes — please retry.');
}

// Hierarchical revoke (forward secrecy): the removed member saw the TEAM PRIVATE key, so we must
// rotate the whole team keypair — not just the DEK. Mint a NEW team keypair + a NEW DEK in the
// browser; wrap the new DEK to the new team PUBLIC key; wrap the new team PRIVATE key to every
// REMAINING member; the server swaps team_public_key, advances team_key_version, appends the new
// DEK epoch, and deactivates the revoked member at every epoch — in one transaction, never seeing
// a key. (member_keys carry the wrapped TEAM PRIVATE key in the generic wrapped_dek field.)
async function zkRotateTeamForRevoke(vaultId, revokedUserId, info, fromVersion) {
    const ecc = eccLib();
    const remaining = (info.members || []).filter(uid => String(uid) !== String(revokedUserId));
    const teamKp = await ecc.generateKeypair();         // new team keypair (browser-only)
    const newDek = await ecc.generateVaultDEK();         // new DEK (browser-only)
    const dekWrap = await ecc.wrapVaultDEK(newDek, teamKp.publicKey);  // DEK -> new team pubkey
    const memberKeys = [];
    for (const uid of remaining) {
        const pk = await apiRequest(`/ecc/users/${uid}/public-key`, { silent: true });
        if (!pk || !pk.has_keypair || !pk.public_key) {
            throw new Error('A remaining member has no encryption key; cannot rotate the team key.');
        }
        const recipientPub = await ecc.importPublicKeyPEM(pk.public_key);
        const { wrappedKey, ephemeralPublicKey } = await ecc.wrapPrivateKeyToPublic(teamKp.privateKey, recipientPub);
        memberKeys.push({ user_id: uid, wrapped_dek: wrappedKey, ephemeral_public_key: ephemeralPublicKey });
    }
    const teamPubPem = await ecc.exportPublicKeyPEM(teamKp.publicKey);
    await apiRequest(`/ecc/vaults/${vaultId}/rekey`, {
        method: 'POST',
        body: JSON.stringify({
            from_version: fromVersion,
            to_version: fromVersion + 1,
            revoke_user_id: revokedUserId,
            member_keys: memberKeys,
            team_public_key: teamPubPem,
            team_dek_wrapped: dekWrap.wrappedDEK,
            team_dek_ephemeral_public_key: dekWrap.ephemeralPublicKey,
        }),
    });
}

// Download file
async function downloadFile(fileId, fileName) {
    try {
        // Zero-knowledge: if we couldn't decrypt this item's NAME we also lack the DEK for
        // its content epoch, so a download can't be decrypted here — say so plainly.
        const locked = (state.currentFiles || []).find(i => i.id === fileId && i.zkLocked);
        if (locked) {
            showError("This file is encrypted under a key version you don't have, so it can't be downloaded here.");
            return;
        }
        showInfo(`Downloading "${fileName}"…`);   // immediate feedback (blob buffers fully before save)
        // Build headers with auth + vault password if needed
        const headers = { 'Authorization': `Bearer ${authToken}` };
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }

        // Fetch file
        const response = await fetch(`${API_BASE}/vaults/${state.currentVault.id}/files/${fileId}/download`, {
            headers
        });
        
        if (!response.ok) {
            throw new Error('Download failed');
        }
        
        // Get blob (decrypting in-browser for zero-knowledge vaults) and save it.
        let blob = await response.blob();
        if (isZkVault(state.currentVault)) {
            try { blob = await zkMaybeDecryptBlob(blob, state.currentVault, zkFileKeyVersion(fileId)); }
            catch (e) { showError('Failed to decrypt file: ' + e.message); return; }
        }
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        showSuccess('File downloaded successfully');
    } catch (error) {
        console.error('Download failed:', error);
        showError('Failed to download file');
    }
}

// In-browser file preview. The file stays encrypted at rest; the server decrypts
// on download (authorised by the vault password held in JS memory) and we render
// the bytes from an in-memory blob URL that is revoked when the modal closes — so
// nothing decrypted is ever written to disk.
let _previewUrl = null;

async function openFilePreview(fileId, fileName, mime) {
    const modal = document.getElementById('file-preview-modal');
    if (!modal) return;
    document.getElementById('file-preview-title').textContent = fileName;
    const bodyEl = document.getElementById('file-preview-body');
    bodyEl.innerHTML = '<div class="spinner"></div>';
    const dlBtn = document.getElementById('file-preview-download');
    if (dlBtn) dlBtn.onclick = () => downloadFile(fileId, fileName);
    modal.classList.add('active');

    try {
        const headers = { 'Authorization': `Bearer ${authToken}` };
        if (state.currentVault.has_password && state.vaultPassword) headers['X-Vault-Password'] = state.vaultPassword;
        const resp = await fetch(`${API_BASE}/vaults/${state.currentVault.id}/files/${fileId}/download`, { headers });
        if (!resp.ok) throw new Error('Could not load file (status ' + resp.status + ')');
        let blob = await resp.blob();
        // Zero-knowledge vault: decrypt the ciphertext in-browser before rendering.
        if (isZkVault(state.currentVault)) blob = await zkMaybeDecryptBlob(blob, state.currentVault, zkFileKeyVersion(fileId));

        if (_previewUrl) { URL.revokeObjectURL(_previewUrl); _previewUrl = null; }
        const type = (mime || blob.type || '').toLowerCase();
        const ext = (fileName.split('.').pop() || '').toLowerCase();
        const isImg = type.startsWith('image/') || ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp'].includes(ext);
        const isPdf = type.includes('pdf') || ext === 'pdf';
        const isVideo = type.startsWith('video/') || ['mp4', 'webm', 'mov'].includes(ext);
        const isAudio = type.startsWith('audio/') || ['mp3', 'wav', 'flac'].includes(ext);
        const isText = type.startsWith('text/') || ['txt', 'md', 'json', 'csv', 'log', 'xml', 'yml', 'yaml', 'js', 'css', 'html', 'py', 'sh', 'ini'].includes(ext);
        _previewUrl = URL.createObjectURL(blob);

        if (isText && blob.size < 2 * 1024 * 1024) {
            const pre = document.createElement('pre');
            pre.className = 'preview-text';
            pre.textContent = await blob.text();
            bodyEl.replaceChildren(pre);
        } else if (isImg || isPdf || isVideo || isAudio) {
            const tag = isImg ? 'img' : isPdf ? 'iframe' : isVideo ? 'video' : 'audio';
            const el = document.createElement(tag);
            el.src = _previewUrl;
            if (isImg) { el.className = 'preview-media'; el.alt = fileName; }
            else if (isPdf) { el.className = 'preview-frame'; el.title = fileName; }
            else if (isVideo) { el.className = 'preview-media'; el.controls = true; }
            else { el.controls = true; el.style.width = '100%'; }
            bodyEl.replaceChildren(el);
        } else {
            const wrap = document.createElement('div');
            wrap.className = 'preview-none text-center text-secondary p-xl';
            wrap.innerHTML = `${iconSvg('file', 'icon-lg')}<p class="mt-sm">No inline preview for this file type.</p><p class="text-sm">Use Download to save it.</p>`;
            bodyEl.replaceChildren(wrap);
        }
    } catch (e) {
        bodyEl.innerHTML = `<div class="alert alert-error">Failed to preview: ${escapeHtml(e.message)}</div>`;
    }
}

function closeFilePreview() {
    if (_previewUrl) { URL.revokeObjectURL(_previewUrl); _previewUrl = null; }
}

// Rename vault item (file or folder)
async function renameVaultItem(itemId, currentName, type) {
    // A zero-knowledge item whose name we couldn't decrypt (we lack its DEK epoch) can't
    // be renamed here — we'd have to encrypt under a key we don't hold.
    const lockedItem = (state.currentFiles || []).find(i => i.id === itemId && i.zkLocked);
    if (lockedItem) {
        showError("This item's name is encrypted under a key version you don't have, so it can't be renamed here.");
        return;
    }
    const newName = await showPrompt(
        `Enter a new name for this ${type}.`,
        'Rename item',
        { placeholder: 'New name', defaultValue: currentName }
    );
    if (newName === null || !newName.trim() || newName === currentName) {
        return;
    }

    try {
        showInfo('Renaming...');

        // Build headers with vault password if needed
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }

        let body;
        if (isZkVault(state.currentVault)) {
            // Zero-knowledge: encrypt the new name in the browser; the server never sees it.
            // A file keeps its CONTENT epoch (the name follows it); a folder keeps its own
            // name epoch — so we re-encrypt under that same epoch, which any member who can
            // currently read the item necessarily holds.
            try {
                const vid = state.currentVault.id;
                const item = (state.currentFiles || []).find(i => i.id === itemId);
                const epoch = zkNameEpoch(item);
                const dek = await zkGetVaultDek(vid, epoch);
                const lib = eccLib();
                body = {
                    enc_name: await lib.encryptName(newName.trim(), dek, vid, 'name', epoch, itemId),
                    name_bi: await lib.nameBlindIndex(newName.trim(), dek, vid, epoch),
                };
                if (type === 'folder') body.name_key_version = epoch;
            } catch (e) {
                showError('Zero-knowledge encryption failed: ' + e.message);
                return;
            }
        } else {
            body = { new_name: newName };
        }

        await apiRequest(`/vaults/${state.currentVault.id}/files/${itemId}/rename`, {
            method: 'PUT',
            headers,
            body: JSON.stringify(body)
        });
        
        showSuccess('Renamed successfully');
        
        // Reload files
        await loadVaultFiles();
    } catch (error) {
        console.error('Rename failed:', error);
        showError('Failed to rename item');
    }
}

// Delete vault item (file or folder)
async function deleteVaultItem(itemId, itemName, type) {
    const confirmed = await showConfirm(
        type === 'folder'
            ? `Delete the folder "${itemName}" and everything inside it? This cannot be undone.`
            : `Are you sure you want to delete "${itemName}"?`,
        'Confirm Delete'
    );
    if (!confirmed) return;

    try {
        showInfo('Deleting...');

        // Build headers with vault password if needed
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }

        const path = type === 'folder'
            ? `/vaults/${state.currentVault.id}/folders/${itemId}/delete`
            : `/vaults/${state.currentVault.id}/files/${itemId}/delete`;
        await apiRequest(path, { method: 'POST', headers });

        showSuccess('Deleted successfully');
        
        // Reload files
        await loadVaultFiles();
    } catch (error) {
        console.error('Delete failed:', error);
        showError('Failed to delete item');
    }
}

// Close vault and return to list
// Show/hide vault-view controls based on the caller's access.
function applyVaultViewPermissions(isOwner, canWrite, canManage) {
    const show = (el, on) => { if (el) el.style.display = on ? '' : 'none'; };
    // vaultCapAllowed() returns true for any non-scoped session, so this is a no-op
    // for regular users/admins; for a scoped temp cred it intersects with the caps
    // its scope grants on this vault (matching require_vault_cap server-side).
    show(document.getElementById('upload-file-btn'), canWrite && vaultCapAllowed('file.upload'));
    show(document.getElementById('create-folder-btn'), canWrite && vaultCapAllowed('folder.create'));
    // Permissions is open to the owner AND managers (delegated administration);
    // Settings stays owner-only (rename/password/rotate/delete). Don't show dead tabs.
    // Gate on see_permissions specifically — the tab's initial GET /permissions is
    // require_vault_cap('vault.see_permissions'), so a change-only scope would 403.
    show(document.querySelector('[data-vault-tab="permissions"]'),
         (canManage || isOwner) && vaultCapAllowed('vault.see_permissions'));
    // Settings needs at least one of its underlying caps (a scoped cred that owns the
    // vault must still hold a change_* / delete cap to see the tab).
    const canSeeSettings = ['vault.change_info', 'vault.change_password', 'vault.change_expiry', 'vault.delete']
        .some(c => vaultCapAllowed(c));
    show(document.querySelector('[data-vault-tab="settings"]'), isOwner && canSeeSettings);
}

// Poll for access revocation while a vault is open; if the owner revokes the
// caller's access, kick them out with an acknowledged modal.
function startVaultAccessWatch(vaultId) {
    if (state.accessCheckInterval) { clearInterval(state.accessCheckInterval); state.accessCheckInterval = null; }
    state.accessCheckInterval = setInterval(async () => {
        if (!state.currentVault || state.currentVault.id !== vaultId) return;
        // Only act while the vault view is the visible section (avoid popping a
        // revoked-modal over an unrelated page the user navigated to).
        const view = document.getElementById('vault-view-section');
        if (!view || !view.classList.contains('active')) return;
        try {
            const resp = await fetch(`${API_BASE}/vaults/${vaultId}`, {
                headers: { 'Authorization': `Bearer ${authToken}` }
            });
            if (resp.status === 403 || resp.status === 404) {
                clearInterval(state.accessCheckInterval);
                state.accessCheckInterval = null;
                await showAccessRevokedModal();
                closeVault();
            }
        } catch (_) { /* transient network error — try again next tick */ }
    }, 20000);
}

async function showAccessRevokedModal() {
    try {
        await showConfirm(
            'Your access to this vault has been revoked. You will be returned to the vault list.',
            'Access revoked'
        );
    } catch (_) { /* modal helper unavailable — fall through and just close */ }
}

// --- View persistence across page refresh ----------------------------------
// We remember which section / vault / folder the user is looking at so a refresh
// (F5) restores them there instead of dumping them on the dashboard.
function saveNavState(override) {
    let nav;
    if (override) {
        nav = override;
    } else if (state.currentVault) {
        nav = { section: 'vault', vaultId: state.currentVault.id,
                folderId: state.currentFolderId || null, path: state.currentPath || [] };
    } else {
        return;  // nothing meaningful to save
    }
    try { sessionStorage.setItem('dv_nav', JSON.stringify(nav)); } catch (_) {}
}
function getNavState() {
    try { return JSON.parse(sessionStorage.getItem('dv_nav') || 'null'); } catch (_) { return null; }
}

// Programmatically switch to a top-level section (mirror of the sidebar click).
function navigateToSection(section) {
    const item = document.querySelector(`.sidebar-item[data-section="${section}"]`);
    if (item) item.click();
}

// Restore the saved view on app load. Returns true if it handled navigation.
async function restoreLastView() {
    const nav = getNavState();
    if (!nav) return false;
    if (nav.section === 'vault' && nav.vaultId) {
        await openVault(nav.vaultId);
        if (!state.currentVault) { navigateToSection('vaults'); return true; }  // open cancelled/failed
        // Restore folder depth if we were inside one.
        if (nav.folderId && state.currentFolderId !== nav.folderId) {
            state.currentFolderId = nav.folderId;
            state.currentPath = Array.isArray(nav.path) ? nav.path : [];
            await loadVaultFiles();
            updateBreadcrumb();
        }
        return true;
    }
    if (nav.section && nav.section !== 'dashboard') {
        navigateToSection(nav.section);
        return true;
    }
    return false;
}

// --- Live file-list refresh (propagates other users' changes) ---------------
function filesSignature(items) {
    // Include enc_name so a zero-knowledge rename (which only changes the ciphertext name,
    // not size/modified) is still seen as a change by the live watcher.
    return (items || [])
        .map(i => `${i.id}:${i.type}:${i.size || 0}:${i.modified || ''}:${i.name}:${i.enc_name || ''}`)
        .sort()
        .join('|');
}
function startVaultFileWatch() {
    stopVaultFileWatch();
    state.fileWatchInterval = setInterval(refreshFilesIfChanged, 6000);
}
function stopVaultFileWatch() {
    if (state.fileWatchInterval) { clearInterval(state.fileWatchInterval); state.fileWatchInterval = null; }
}
async function refreshFilesIfChanged() {
    if (!state.currentVault) return;
    const view = document.getElementById('vault-view-section');
    const filesTab = document.getElementById('vault-files-tab');
    // Only poll while the Files tab of the vault view is actually showing.
    if (!view || !view.classList.contains('active')) return;
    if (!filesTab || !filesTab.classList.contains('active')) return;
    try {
        let url = `${API_BASE}/vaults/${state.currentVault.id}/files`;
        if (state.currentFolderId) url += `?folder_id=${state.currentFolderId}`;
        const headers = { 'Authorization': `Bearer ${authToken}` };
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        const resp = await fetch(url, { headers });
        if (!resp.ok) return;
        const data = await resp.json();
        const sig = filesSignature(data.items);
        if (state.lastFilesSignature !== null && sig !== state.lastFilesSignature) {
            await loadVaultFiles();  // something changed (another user) — re-render
        }
        state.lastFilesSignature = sig;
    } catch (_) { /* transient — retry next tick */ }
}

function closeVault() {
    if (state.accessCheckInterval) { clearInterval(state.accessCheckInterval); state.accessCheckInterval = null; }
    stopVaultFileWatch();
    state.lastFilesSignature = null;
    state.canWriteCurrentVault = true;
    state.tempVaultCaps = null;
    state.currentVault = null;
    state.currentVaultId = null;
    state.currentFolderId = null;
    state.currentPath = [];
    state.vaultPassword = null;
    saveNavState({ section: 'vaults' });  // a refresh now lands on the vault list, not inside

    // Switch back to the vaults CONTENT section. (Do NOT use showScreen here —
    // that toggles top-level .screen elements and would hide the whole
    // dashboard-screen, leaving a blank page.)
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    const vaultsSection = document.getElementById('vaults-section');
    if (vaultsSection) vaultsSection.classList.add('active');
    document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
    const vaultsItem = document.querySelector('.sidebar-item[data-section="vaults"]');
    if (vaultsItem) vaultsItem.classList.add('active');

    loadVaults();
}

// Upload files to vault
// ===========================================================================
// Resumable chunked upload manager
// ---------------------------------------------------------------------------
// Every upload is split into chunks and driven through the resumable backend
// (init → PUT chunk → complete). Each upload shows as a live entry in the
// upload tray with a progress bar and Pause / Resume / Cancel controls. The
// "transaction" lives on the server, so a paused upload can be resumed later —
// even after a reload or the next day — by re-selecting the same file.
// ===========================================================================
const CHUNK_SIZE = 5 * 1024 * 1024; // 5 MB — matches the server default

// ===========================================================================
// Zero-knowledge upload resume store (IndexedDB)
// ---------------------------------------------------------------------------
// A ZK upload encrypts the whole file in the browser (random-IV AES-GCM) and
// streams the resulting CIPHERTEXT through the chunked uploader. Re-encrypting
// after a reload would produce different bytes (a fresh IV) that can't line up
// with the chunks already buffered on the server, so a ZK upload cannot be
// resumed by simply re-picking the source file. Instead we persist the computed
// ciphertext blob here, keyed by the server upload-session id, so a reload can
// resume by replaying the SAME bytes for the chunks still missing.
//
// Zero-knowledge is preserved: only ciphertext (opaque without the DEK) is held
// at rest; the DEK and the plaintext are NEVER persisted, the server still only
// ever receives ciphertext, and resuming needs no DEK at all. Records are
// deleted on completion/cancel and pruned by TTL. Everything fails soft if
// IndexedDB is unavailable (private mode, quota, old browser) — uploads still
// work, they just can't resume across a reload.
// ===========================================================================
const zkUploadStore = (() => {
    const DB_NAME = 'dockvault-zk-uploads';
    const STORE = 'pending';
    const VERSION = 1;
    let _dbPromise = null;

    function _open() {
        if (_dbPromise) return _dbPromise;
        _dbPromise = new Promise((resolve) => {
            let req;
            try {
                if (typeof indexedDB === 'undefined' || !indexedDB) { resolve(null); return; }
                req = indexedDB.open(DB_NAME, VERSION);
            } catch (_) { resolve(null); return; }
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(STORE)) {
                    const os = db.createObjectStore(STORE, { keyPath: 'sessionId' });
                    os.createIndex('vaultId', 'vaultId', { unique: false });
                    os.createIndex('createdAt', 'createdAt', { unique: false });
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
            req.onblocked = () => resolve(null);
        });
        return _dbPromise;
    }

    // Resolve a single IDB request to its result (or undefined on error) without rejecting.
    function _reqProm(makeReq) {
        return new Promise((resolve) => {
            try {
                const r = makeReq();
                r.onsuccess = () => resolve(r.result);
                r.onerror = () => resolve(undefined);
            } catch (_) { resolve(undefined); }
        });
    }

    function _txDone(tx) {
        return new Promise((res) => { tx.oncomplete = res; tx.onerror = res; tx.onabort = res; });
    }

    // Is this a storage-quota error? Engines surface it as a DOMException named
    // 'QuotaExceededError' (legacy code 22) or, on Firefox, 'NS_ERROR_DOM_QUOTA_REACHED'.
    function _isQuotaErr(err) {
        if (!err) return false;
        const name = err.name || '';
        return name === 'QuotaExceededError'
            || name === 'NS_ERROR_DOM_QUOTA_REACHED'
            || err.code === 22;
    }

    function _putResult(err) {
        return { ok: false, quota: _isQuotaErr(err), error: err || null };
    }

    return {
        // Persist a record. Returns a STRUCTURED result so callers can tell whether the
        // ciphertext was actually saved (resume will work) or silently wasn't:
        //   { ok: true }                         — saved
        //   { ok: false, quota: true }           — out of browser storage (resume disabled)
        //   { ok: false, unavailable: true }     — IndexedDB not available at all (private
        //                                            mode etc.) — expected degrade, no resume
        //   { ok: false, quota: false }          — some other write failure
        // It still NEVER throws (fail-soft), but no longer fails SILENTLY: a quota/other
        // failure used to be swallowed here, so "resumable" silently wasn't.
        async put(rec) {
            const db = await _open();
            if (!db) return { ok: false, unavailable: true };
            return new Promise((resolve) => {
                let settled = false;
                const done = (r) => { if (!settled) { settled = true; resolve(r); } };
                let reqErr = null;
                try {
                    const tx = db.transaction(STORE, 'readwrite');
                    const req = tx.objectStore(STORE).put(rec);
                    // Record the request error, but DELIBERATELY do NOT preventDefault():
                    // an unhandled IndexedDB request error aborts its transaction, which is
                    // exactly what we want — the abort fires tx.onabort and we report the
                    // failure. Calling preventDefault() here would CANCEL that abort, let the
                    // transaction COMMIT, and resolve {ok:true} for a write that never landed
                    // (the silent failure this structured result exists to eliminate — and the
                    // path Chromium takes for QuotaExceededError, which surfaces async here).
                    req.onerror = () => { reqErr = (req && req.error) || null; };
                    tx.oncomplete = () => done({ ok: true });
                    tx.onerror = () => done(_putResult(reqErr || tx.error));
                    tx.onabort = () => done(_putResult(reqErr || tx.error));
                } catch (err) {
                    // Some engines raise QuotaExceededError synchronously from put()/
                    // transaction() rather than via the async request error event.
                    done(_putResult(err));
                }
            });
        },
        async get(sessionId) {
            const db = await _open();
            if (!db) return null;
            try {
                const tx = db.transaction(STORE, 'readonly');
                const out = await _reqProm(() => tx.objectStore(STORE).get(sessionId));
                return out || null;
            } catch (_) { return null; }
        },
        async delete(sessionId) {
            const db = await _open();
            if (!db) return;
            try {
                const tx = db.transaction(STORE, 'readwrite');
                tx.objectStore(STORE).delete(sessionId);
                await _txDone(tx);
            } catch (_) { /* fail soft */ }
        },
        async allForVault(vaultId) {
            const db = await _open();
            if (!db) return [];
            try {
                const tx = db.transaction(STORE, 'readonly');
                const out = await _reqProm(() => tx.objectStore(STORE).index('vaultId').getAll(vaultId));
                return out || [];
            } catch (_) { return []; }
        },
        // Wipe the whole store (used on logout so an interrupted upload's ciphertext
        // can't sit at rest on a shared/public machine after the user leaves).
        async clear() {
            const db = await _open();
            if (!db) return;
            try {
                const tx = db.transaction(STORE, 'readwrite');
                tx.objectStore(STORE).clear();
                await _txDone(tx);
            } catch (_) { /* fail soft */ }
        },
        // Drop records older than maxAgeMs (or with no timestamp) so the store can't
        // accumulate dead ciphertext from abandoned uploads.
        async pruneOlderThan(maxAgeMs) {
            const db = await _open();
            if (!db) return;
            const cutoff = Date.now() - maxAgeMs;
            try {
                const tx = db.transaction(STORE, 'readwrite');
                const store = tx.objectStore(STORE);
                const all = await _reqProm(() => store.getAll());
                for (const rec of (all || [])) {
                    if (!rec || typeof rec.createdAt !== 'number' || rec.createdAt < cutoff) {
                        try { store.delete(rec.sessionId); } catch (_) { /* skip */ }
                    }
                }
                await _txDone(tx);
            } catch (_) { /* fail soft */ }
        },
    };
})();

const uploadManager = {
    items: new Map(),   // uploadId -> item
    seq: 0,

    _vaultHeaders() {
        const h = { 'Authorization': `Bearer ${authToken}` };
        if (state.currentVault && state.currentVault.has_password && state.vaultPassword) {
            h['X-Vault-Password'] = state.vaultPassword;
        }
        return h;
    },

    _newId() { return `up_${Date.now()}_${++this.seq}`; },

    // Self-contained inline icons (the main SPA has no svgIcon sprite loaded).
    _icon(n) {
        const P = {
            pause: '<rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/>',
            play: '<path d="M7 4v16l13-8Z"/>',
            x: '<path d="M18 6 6 18M6 6l12 12"/>',
        };
        return `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${P[n] || ''}</svg>`;
    },

    // Enqueue freshly-picked File objects for the current vault/folder.
    enqueueFiles(files) {
        if (!files || !files.length || !state.currentVault) return;
        const vaultId = state.currentVault.id;
        const folderId = state.currentFolderId || null;
        for (const file of files) {
            const id = this._newId();
            const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
            this.items.set(id, {
                id, file, vaultId, folderId,
                fileName: file.name, totalSize: file.size,
                totalChunks, chunkSize: CHUNK_SIZE,
                sessionId: null, received: new Set(),
                status: 'queued', error: null, paused: false, cancelled: false,
            });
            this.run(id); // fire-and-forget; each item drives itself
        }
        this.render();
    },

    // Like enqueueFiles but each entry carries an explicit target name (used by
    // the upload-conflict resolver for auto-rename / rename).
    enqueueNamed(entries) {
        if (!entries || !entries.length || !state.currentVault) return;
        const vaultId = state.currentVault.id;
        const folderId = state.currentFolderId || null;
        for (const { file, name, keyVersion, encName, encMime, nameBi, clientFileId } of entries) {
            const id = this._newId();
            const totalChunks = Math.max(1, Math.ceil(file.size / CHUNK_SIZE));
            this.items.set(id, {
                id, file, vaultId, folderId,
                fileName: name || file.name, totalSize: file.size,
                totalChunks, chunkSize: CHUNK_SIZE,
                sessionId: null, received: new Set(),
                status: 'queued', error: null, paused: false, cancelled: false,
                zkKeyVersion: keyVersion != null ? keyVersion : null,  // ZK DEK epoch (declared at init)
                isZk: keyVersion != null,  // ZK uploads carry their ciphertext into IndexedDB for resume
                // ZK only: the browser-encrypted name/MIME + client blind index. Sent at init
                // instead of the plaintext name (the server never sees the name).
                encName: encName || null, encMime: encMime || null, nameBi: nameBi || null,
                // ZK v2: the client-generated file id the name was sealed under. Persisted to
                // IndexedDB and re-sent at complete so the final row id matches the sealed id.
                clientFileId: clientFileId || null,
            });
            this.run(id);
        }
        this.render();
    },

    // Rebuild the tray from the server's resumable sessions. Standard uploads need the
    // source file re-selected; zero-knowledge uploads auto-resume from the ciphertext
    // saved in IndexedDB (or, if it isn't on this device, surface as not-resumable here).
    async refreshResumable() {
        if (!state.currentVault) return;
        // Coalesce overlapping calls (loadVaultFiles fires this fire-and-forget on vault
        // open, on the 6s file-watcher, on focus, and after a completion). Without this,
        // two runs can each restore the SAME session before either registers its item —
        // two uploaders then race one server session.
        if (this._refreshing) return;
        this._refreshing = true;
        try {
            await this._refreshResumableInner();
        } finally {
            this._refreshing = false;
        }
    },

    async _refreshResumableInner() {
        if (!state.currentVault) return;
        const vaultId = state.currentVault.id;
        let sessions = [];
        try {
            const r = await fetch(`${API_BASE}/vaults/${vaultId}/uploads`, { headers: this._vaultHeaders() });
            if (!r.ok) return;
            sessions = await r.json();
        } catch (_) { return; }

        // Drop stale needs-file rows for this vault, then re-add from the server.
        for (const [id, it] of this.items) {
            if (it.vaultId === vaultId && it.status === 'needs-file') this.items.delete(id);
        }
        const activeSessionIds = new Set(
            [...this.items.values()].filter(it => it.sessionId).map(it => it.sessionId)
        );
        const zk = isZkVault(state.currentVault);
        const serverIds = new Set(sessions.map(s => s.session_id));
        const toResume = [];
        for (const s of sessions) {
            if (activeSessionIds.has(s.session_id)) continue; // already being uploaded here

            if (zk) {
                // Zero-knowledge: resume only if we still hold the encrypted bytes locally.
                const rec = await zkUploadStore.get(s.session_id);
                if (rec && rec.blob) {
                    const id = this._newId();
                    this.items.set(id, {
                        id, file: rec.blob, vaultId, folderId: s.folder_id || null,
                        // The server has no plaintext name for a ZK session — use the name
                        // saved locally (s.file_name is null for ZK).
                        fileName: rec.fileName || s.file_name || '(encrypted upload)',
                        totalSize: s.total_size,
                        totalChunks: s.total_chunks, chunkSize: rec.chunkSize || CHUNK_SIZE,
                        sessionId: s.session_id, received: new Set(),
                        status: 'paused', error: null, paused: true, cancelled: false,
                        percent: s.percent || 0, isZk: true,
                        zkKeyVersion: rec.keyVersion != null ? rec.keyVersion : null,
                        // Carry the encrypted name/blind index so a 410 re-init re-declares it.
                        encName: rec.encName || null, encMime: rec.encMime || null, nameBi: rec.nameBi || null,
                        // Restore the v2 obj-id binding so complete finishes under the sealed id.
                        clientFileId: rec.clientFileId || null,
                        needsServerSync: true,  // re-sync received chunks from the server before replaying
                    });
                    toResume.push(id);  // auto-resume below: replay the remaining ciphertext chunks
                    continue;
                }
                // No local ciphertext (different device/browser, or storage cleared): surface it
                // as resumable-but-stuck; resume() explains it can't be replayed here.
                const id = this._newId();
                this.items.set(id, {
                    id, file: null, vaultId, folderId: s.folder_id || null,
                    fileName: s.file_name || '(encrypted upload)', totalSize: s.total_size,
                    totalChunks: s.total_chunks, chunkSize: CHUNK_SIZE,
                    sessionId: s.session_id, received: new Set(),
                    status: 'needs-file', error: null, paused: true, cancelled: false,
                    percent: s.percent || 0, isZk: true,
                });
                continue;
            }

            // Standard vault: resumable by re-selecting the source file.
            const id = this._newId();
            this.items.set(id, {
                id, file: null, vaultId, folderId: s.folder_id || null,
                fileName: s.file_name, totalSize: s.total_size,
                totalChunks: s.total_chunks, chunkSize: CHUNK_SIZE,
                sessionId: s.session_id, received: new Set(),
                status: 'needs-file', error: null, paused: true, cancelled: false,
                percent: s.percent || 0,
            });
        }

        // Prune orphaned ciphertext for sessions the server no longer lists (completed or
        // expired elsewhere) so IndexedDB can't accumulate dead blobs for this vault.
        if (zk) {
            try {
                const graceMs = 2 * 60 * 1000;  // don't race a session that's mid-init
                for (const rec of await zkUploadStore.allForVault(vaultId)) {
                    const fresh = typeof rec.createdAt === 'number' && (Date.now() - rec.createdAt) < graceMs;
                    if (rec && rec.sessionId && !serverIds.has(rec.sessionId)
                            && !activeSessionIds.has(rec.sessionId) && !fresh) {
                        await zkUploadStore.delete(rec.sessionId);
                    }
                }
            } catch (_) { /* fail soft */ }
        }

        this.render();
        for (const id of toResume) this.run(id);  // fire-and-forget; each drives itself
    },

    async _init(it) {
        const r = await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads`, {
            method: 'POST',
            headers: { ...this._vaultHeaders(), 'Content-Type': 'application/json' },
            body: JSON.stringify({
                // ZK: never send the plaintext name/MIME — only the browser-encrypted blobs
                // + blind index. Standard: send the plaintext name/MIME as before.
                file_name: it.isZk ? null : it.fileName,
                mime_type: it.isZk ? null : (it.file ? (it.file.type || null) : null),
                enc_name: it.isZk ? it.encName : null,
                enc_mime: it.isZk ? it.encMime : null,
                name_bi: it.isZk ? it.nameBi : null,
                total_size: it.totalSize,
                total_chunks: it.totalChunks,
                chunk_size: it.chunkSize,
                folder_id: it.folderId,
                zk_key_version: it.zkKeyVersion != null ? it.zkKeyVersion : null,  // ZK only
            }),
        });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            throw new Error(typeof e.detail === 'string' ? e.detail : 'Could not start upload');
        }
        const data = await r.json();
        it.sessionId = data.session_id;
        it.received = new Set(data.received_chunks || []);
        if (data.chunk_size) it.chunkSize = data.chunk_size;

        // Zero-knowledge: persist the already-encrypted ciphertext so a reload can
        // resume this exact session by replaying the same bytes. Only ciphertext is
        // stored — never the DEK or plaintext. Done before the first chunk goes out,
        // so even an early reload is resumable. Fails soft if IndexedDB is unavailable.
        if (it.isZk && it.file) {
            const res = await zkUploadStore.put({
                sessionId: it.sessionId,
                vaultId: it.vaultId,
                fileName: it.fileName,
                totalSize: it.totalSize,
                mimeType: it.file.type || null,
                folderId: it.folderId,
                keyVersion: it.zkKeyVersion != null ? it.zkKeyVersion : null,
                totalChunks: it.totalChunks,
                chunkSize: it.chunkSize,
                blob: it.file,
                // The encrypted name/MIME + blind index, so a re-init after a server-side
                // session expiry (410) re-declares the same name without the plaintext.
                encName: it.encName || null,
                encMime: it.encMime || null,
                nameBi: it.nameBi || null,
                // ZK v2: the id the name was sealed under. Without it, a resumed upload would
                // complete under a fresh server id and the v2 name would be undecryptable.
                clientFileId: it.clientFileId || null,
                createdAt: Date.now(),
            });
            this._noteResumePersistence(it, res);
        }
    },

    // React to a zkUploadStore.put result. On success the upload is resumable across a
    // reload; on a quota/other failure it ISN'T — surface that once (a banner used to be
    // missing entirely, so "resumable" silently wasn't) and mark the item so its tray row
    // shows the upload will still finish but can't be resumed. IndexedDB being entirely
    // unavailable (private mode etc.) is the documented graceful degrade and stays quiet.
    _noteResumePersistence(it, res) {
        if (!res || res.ok) { it.resumePersisted = true; it.resumeWarning = null; return; }
        it.resumePersisted = false;
        if (res.unavailable) { it.resumeWarning = null; return; }  // expected, quiet degrade
        it.resumeWarning = res.quota
            ? "Not enough browser storage to save this upload for resuming — it will still finish uploading, but can't be resumed if you reload or close the tab."
            : "Couldn't save this upload for resuming in browser storage — it will still finish uploading, but can't be resumed after a reload.";
        try { showWarning(it.resumeWarning); } catch (_) { /* toast optional */ }
        try { this.render(); } catch (_) { /* a render hiccup must not fail the upload */ }
    },

    // Drive an item from wherever it is to completion (honouring pause/cancel).
    async run(id) {
        const it = this.items.get(id);
        if (!it || !it.file) return;
        // Never drive two uploaders against the same server session at once (a duplicate
        // restored item would race chunk PUTs + the server's byte accounting). If another
        // item already owns this session and is active, drop this duplicate.
        if (it.sessionId) {
            for (const [oid, other] of this.items) {
                if (oid !== id && other.sessionId === it.sessionId
                        && (other.status === 'uploading' || other.status === 'completing')) {
                    this.items.delete(id);
                    this.render();
                    return;
                }
            }
        }
        it.status = 'uploading';
        it.paused = false;
        it.error = null;
        this.render();
        try {
            if (!it.sessionId) {
                await this._init(it);
            } else if (it.needsServerSync) {
                // Restored across a reload: re-sync which chunks the server already has
                // so we only replay the missing ones.
                try {
                    const s = await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads/${it.sessionId}`, { headers: this._vaultHeaders() });
                    if (s.ok) { const sd = await s.json(); it.received = new Set(sd.received_chunks || []); }
                } catch (_) { /* fall back to re-sending all chunks (server is idempotent) */ }
                it.needsServerSync = false;
            }

            for (let i = 0; i < it.totalChunks; i++) {
                if (it.cancelled) return;
                if (it.paused) { it.status = 'paused'; this.render(); return; }
                if (it.received.has(i)) continue;

                const start = i * it.chunkSize;
                const blob = it.file.slice(start, Math.min(start + it.chunkSize, it.file.size));
                const buf = await blob.arrayBuffer();
                const r = await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads/${it.sessionId}/chunks/${i}`, {
                    method: 'PUT',
                    headers: { ...this._vaultHeaders(), 'Content-Type': 'application/octet-stream' },
                    body: buf,
                });
                if (r.status === 410) {  // session expired server-side — restart it
                    // Drop the stale ciphertext record; _init re-persists under the new session id.
                    if (it.isZk && it.sessionId) await zkUploadStore.delete(it.sessionId);
                    it.sessionId = null; it.received = new Set();
                    await this._init(it); i = -1; continue;
                }
                if (!r.ok) {
                    const e = await r.json().catch(() => ({}));
                    throw new Error(typeof e.detail === 'string' ? e.detail : `Chunk ${i + 1} failed`);
                }
                it.received.add(i);
                this.render();
            }

            it.status = 'completing';
            this.render();
            // ZK v2: send the client-generated file id the name was sealed under, so the server
            // uses it as the row id and the stored name binds the final row (anti-transposition).
            // Standard uploads (and any legacy ZK item without a client id) stay bodyless — the
            // server assigns the id.
            const zkComplete = it.isZk && it.clientFileId;
            const c = await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads/${it.sessionId}/complete`, {
                method: 'POST',
                headers: zkComplete
                    ? { ...this._vaultHeaders(), 'Content-Type': 'application/json' }
                    : this._vaultHeaders(),
                body: zkComplete ? JSON.stringify({ file_id: it.clientFileId }) : undefined,
            });
            if (!c.ok) {
                const e = await c.json().catch(() => ({}));
                // 409 incomplete: re-sync received list from the detail and retry.
                if (c.status === 409 && e.detail && e.detail.missing_chunks) {
                    for (const m of e.detail.missing_chunks) it.received.delete(m);
                    return this.run(id);
                }
                // 409 stale ZK epoch: the vault was re-keyed mid-upload. The buffered
                // ciphertext was encrypted under the old DEK and can't be salvaged (we
                // discarded the plaintext), so resuming would re-send doomed bytes forever.
                // Fail the item with a clear message and delete the server session so it
                // isn't falsely resumable — the user must re-pick the file (re-encrypted
                // under the current key).
                if (c.status === 409 && e.detail && e.detail.code === 'stale_zk_epoch') {
                    try {
                        await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads/${it.sessionId}`,
                            { method: 'DELETE', headers: this._vaultHeaders() });
                    } catch (_) { /* best effort */ }
                    if (it.isZk && it.sessionId) await zkUploadStore.delete(it.sessionId);  // ciphertext unsalvageable
                    it.sessionId = null;
                    it.cancelled = true;  // stop any resume path from re-running this item
                    it.status = 'error';
                    it.error = 'The vault key changed during upload — please upload this file again.';
                    this.render();
                    return;
                }
                const d = e.detail;
                throw new Error(typeof d === 'string' ? d : (d && d.message) || 'Finalising failed');
            }
            if (it.isZk && it.sessionId) await zkUploadStore.delete(it.sessionId);  // committed — drop the saved ciphertext
            it.status = 'done';
            this.render();
            // Refresh the file list so the new file appears; drop the row shortly after.
            if (state.currentVault && state.currentVault.id === it.vaultId) await loadVaultFiles();
            setTimeout(() => { this.items.delete(id); this.render(); }, 4000);
        } catch (err) {
            if (it.cancelled) return;
            it.status = 'error';
            it.error = err.message || String(err);
            this.render();
        }
    },

    pause(id) {
        const it = this.items.get(id);
        if (it) { it.paused = true; if (it.status === 'uploading') it.status = 'pausing'; this.render(); }
    },

    resume(id) {
        const it = this.items.get(id);
        if (!it) return;
        if (!it.file) {
            // Zero-knowledge: the ciphertext lives only in this browser's IndexedDB. If
            // it isn't here (another device/browser, or storage cleared) we can't replay
            // the exact bytes and re-encrypting won't match — so re-picking is futile.
            if (it.isZk) {
                showError("This zero-knowledge upload can't be resumed here — the encrypted data isn't available on this device or browser. Cancel it and upload the file again.");
                return;
            }
            this._reselect(id);  // standard vault: re-pick the source file
            return;
        }
        this.run(id);
    },

    // Ask the user to re-pick the source file for a server-side resumable session.
    _reselect(id) {
        const it = this.items.get(id);
        if (!it) return;
        let input = document.getElementById('upload-reselect-input');
        if (!input) {
            input = document.createElement('input');
            input.type = 'file';
            input.id = 'upload-reselect-input';
            input.style.display = 'none';
            document.body.appendChild(input);
        }
        input.value = '';
        input.onchange = async (e) => {
            const file = e.target.files && e.target.files[0];
            if (!file) return;
            // Defense-in-depth: zero-knowledge resume runs from the IndexedDB ciphertext
            // (see resume()), never by re-picking the plaintext — re-feeding plaintext here
            // would bypass the encrypt-before-upload hook and produce a fresh-IV mismatch.
            const v = (state.currentVault && state.currentVault.id === it.vaultId) ? state.currentVault : null;
            if ((v && isZkVault(v)) || it.isZk) {
                showError("This zero-knowledge upload can't be resumed here — the encrypted data isn't available on this device or browser. Cancel it and upload the file again.");
                return;
            }
            if (file.size !== it.totalSize) {
                showError(`That file doesn't match "${it.fileName}" (different size). Pick the original file to resume.`);
                return;
            }
            if (file.name !== it.fileName) {
                showWarning(`Resuming with a differently-named file ("${file.name}"). Make sure it's the same content.`);
            }
            it.file = file;
            it.received = new Set();  // re-sync from server below
            try {
                const s = await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads/${it.sessionId}`, { headers: this._vaultHeaders() });
                if (s.ok) {
                    const sd = await s.json();
                    it.received = new Set(sd.received_chunks || []);
                }
            } catch (_) {}
            this.run(it.id);
        };
        input.click();
    },

    async cancel(id) {
        const it = this.items.get(id);
        if (!it) return;
        it.cancelled = true;
        it.paused = true;
        if (it.sessionId) {
            try {
                await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads/${it.sessionId}`, {
                    method: 'DELETE', headers: this._vaultHeaders(),
                });
            } catch (_) {}
            if (it.isZk) await zkUploadStore.delete(it.sessionId);  // drop the saved ciphertext
        }
        this.items.delete(id);
        this.render();
    },

    _percent(it) {
        if (it.status === 'done') return 100;
        if (it.received && it.totalChunks) return Math.round(it.received.size * 100 / it.totalChunks);
        return Math.round(it.percent || 0);
    },

    render() {
        let tray = document.getElementById('upload-tray');
        if (!tray) {
            tray = document.createElement('div');
            tray.id = 'upload-tray';
            document.body.appendChild(tray);
        }
        const items = [...this.items.values()];
        if (!items.length) { tray.classList.remove('show'); tray.innerHTML = ''; return; }
        tray.classList.add('show');

        const rows = items.map(it => {
            const pct = this._percent(it);
            const size = formatBytes ? formatBytes(it.totalSize) : `${it.totalSize} B`;
            const statusLabel = {
                queued: 'Queued', uploading: 'Uploading', pausing: 'Pausing…',
                paused: 'Paused', completing: 'Finalising…', done: 'Done',
                error: 'Failed', 'needs-file': 'Resumable',
            }[it.status] || it.status;

            let controls = '';
            if (it.status === 'uploading' || it.status === 'queued' || it.status === 'completing' || it.status === 'pausing') {
                controls += `<button class="up-btn" data-up-action="pause" data-up-id="${it.id}" title="Pause">${this._icon('pause')}</button>`;
            }
            if (it.status === 'paused' || it.status === 'error') {
                controls += `<button class="up-btn" data-up-action="resume" data-up-id="${it.id}" title="Resume">${this._icon('play')}</button>`;
            }
            if (it.status === 'needs-file' && !it.isZk) {
                // Standard vaults resume by re-selecting the file; a ZK item with no local
                // ciphertext can't be replayed here, so it offers only Cancel (+ the note below).
                controls += `<button class="up-btn up-btn-text" data-up-action="resume" data-up-id="${it.id}">Resume…</button>`;
            }
            if (it.status !== 'done') {
                controls += `<button class="up-btn" data-up-action="cancel" data-up-id="${it.id}" title="Cancel">${this._icon('x')}</button>`;
            }

            const barClass = it.status === 'error' ? 'up-bar-fill error'
                : it.status === 'done' ? 'up-bar-fill done' : 'up-bar-fill';
            // For a ZK upload whose ciphertext couldn't be persisted (storage full / write
            // failure), flag that it won't survive a reload while it's still in flight.
            const noResume = it.isZk && it.resumePersisted === false && it.resumeWarning
                && it.status !== 'done' && it.status !== 'error' && it.status !== 'needs-file';
            const sub = it.status === 'error' ? `<div class="up-error">${escapeHtml ? escapeHtml(it.error || 'Upload failed') : (it.error || 'Upload failed')}</div>`
                : it.status === 'needs-file' ? `<div class="up-sub">${it.isZk ? 'Encrypted data isn\'t on this device — cancel and upload again' : 'Paused — click Resume and re-select the file'}</div>`
                : `<div class="up-sub">${statusLabel} · ${pct}% · ${size}${noResume ? ' · <span class="up-warn">not resumable</span>' : ''}</div>`;

            return `
              <div class="up-row" data-up-row="${it.id}">
                <div class="up-main">
                  <div class="up-name" title="${escapeHtml ? escapeHtml(it.fileName) : it.fileName}">${escapeHtml ? escapeHtml(it.fileName) : it.fileName}</div>
                  ${sub}
                  <div class="up-bar"><div class="${barClass}" style="width:${pct}%"></div></div>
                </div>
                <div class="up-controls">${controls}</div>
              </div>`;
        }).join('');

        // A failed item (e.g. a rejected 0-byte upload) is finished, not active — exclude 'error'
        // so it doesn't stick in the tray header as "N active" forever.
        const active = items.filter(i => i.status !== 'done' && i.status !== 'needs-file' && i.status !== 'error').length;
        tray.innerHTML = `
          <div class="up-tray-head">
            <span>Uploads${active ? ` · ${active} active` : ''}</span>
            <button class="up-btn" id="up-tray-clear" title="Clear finished">${this._icon('x')}</button>
          </div>
          <div class="up-tray-body">${rows}</div>`;

        tray.querySelectorAll('button[data-up-action]').forEach(b => {
            b.addEventListener('click', () => {
                const a = b.getAttribute('data-up-action');
                const id = b.getAttribute('data-up-id');
                if (a === 'pause') this.pause(id);
                else if (a === 'resume') this.resume(id);
                else if (a === 'cancel') this.cancel(id);
            });
        });
        const clear = tray.querySelector('#up-tray-clear');
        if (clear) clear.addEventListener('click', () => {
            for (const [id, it] of this.items) {
                if (it.status === 'done' || it.status === 'needs-file' || it.status === 'error') this.items.delete(id);
            }
            this.render();
        });
    },
};

// Append " - 1", " - 2", … before the extension until the name is unused.
function uniqueUploadName(name, existing) {
    if (!existing.has(name)) return name;
    const dot = name.lastIndexOf('.');
    const base = dot > 0 ? name.slice(0, dot) : name;
    const ext = dot > 0 ? name.slice(dot) : '';
    let n = 1, candidate;
    do { candidate = `${base} - ${n}${ext}`; n++; } while (existing.has(candidate));
    return candidate;
}

// Ask the user how to resolve a filename collision. Resolves to
// {action: 'autorename'|'overwrite'|'rename'|'skip', name, applyAll}.
function resolveUploadConflict(name, autoName) {
    return new Promise((resolve) => {
        const modal = document.getElementById('upload-conflict-modal');
        if (!modal) { resolve({ action: 'autorename', name: autoName }); return; }
        document.getElementById('uc-name').textContent = name;
        document.getElementById('uc-auto').textContent = autoName;
        const renameInput = document.getElementById('uc-rename');
        const applyAll = document.getElementById('uc-applyall');
        const radios = modal.querySelectorAll('input[name="uc-action"]');
        radios.forEach(r => { r.checked = (r.value === 'autorename'); });
        renameInput.value = autoName; renameInput.disabled = true;
        applyAll.checked = false;

        const confirmBtn = document.getElementById('uc-confirm');
        const skipBtn = document.getElementById('uc-skip');
        const closeBtn = document.getElementById('uc-close');
        const onRadio = () => {
            const v = modal.querySelector('input[name="uc-action"]:checked')?.value;
            renameInput.disabled = v !== 'rename';
            if (v === 'rename') { renameInput.focus(); renameInput.select(); }
        };
        const cleanup = () => {
            modal.classList.remove('active');
            radios.forEach(r => r.removeEventListener('change', onRadio));
            confirmBtn.removeEventListener('click', onConfirm);
            skipBtn.removeEventListener('click', onSkip);
            closeBtn.removeEventListener('click', onSkip);
        };
        const onConfirm = () => {
            const action = modal.querySelector('input[name="uc-action"]:checked')?.value || 'autorename';
            let chosen = name;
            if (action === 'autorename') chosen = autoName;
            else if (action === 'rename') chosen = (renameInput.value || '').trim() || autoName;
            const all = applyAll.checked;
            cleanup();
            resolve({ action, name: chosen, applyAll: all });
        };
        const onSkip = () => { cleanup(); resolve({ action: 'skip' }); };
        radios.forEach(r => r.addEventListener('change', onRadio));
        confirmBtn.addEventListener('click', onConfirm);
        skipBtn.addEventListener('click', onSkip);
        closeBtn.addEventListener('click', onSkip);
        modal.classList.add('active');
    });
}

// Public entry point kept for existing callers (button + drag-drop). Resolves any
// filename collisions in the current folder before enqueueing.
async function uploadFiles(files) {
    const arr = Array.from(files || []);
    if (!arr.length) return;
    if (!state.currentVault) { showError('Open a vault before uploading.'); return; }
    if (state.canWriteCurrentVault === false) { showError('You have read-only access to this vault.'); return; }

    const existing = new Set((state.currentFiles || []).filter(i => i.type !== 'folder').map(i => i.name));
    const idByName = new Map((state.currentFiles || []).filter(i => i.type !== 'folder').map(i => [i.name, i.id]));
    const toUpload = [];   // {file, name}
    const toDelete = [];   // existing file ids to remove (overwrite)
    let blanket = null;    // {action} once "apply to all" is chosen

    for (const file of arr) {
        if (!existing.has(file.name)) {
            toUpload.push({ file, name: file.name });
            existing.add(file.name);
            continue;
        }
        const autoName = uniqueUploadName(file.name, existing);
        let choice = blanket;
        if (!choice) {
            choice = await resolveUploadConflict(file.name, autoName);
            if (choice.applyAll && choice.action !== 'rename') blanket = { action: choice.action };
        }
        if (choice.action === 'skip') continue;
        if (choice.action === 'overwrite') {
            const id = idByName.get(file.name);
            if (id) toDelete.push(id);
            toUpload.push({ file, name: file.name });
        } else {
            let name = (choice.action === 'rename' && choice.name) ? choice.name : autoName;
            name = uniqueUploadName(name, existing);
            toUpload.push({ file, name });
            existing.add(name);
        }
    }

    // Remove overwritten files first so the new upload doesn't collide.
    for (const id of toDelete) {
        try {
            await fetch(`${API_BASE}/vaults/${state.currentVault.id}/files/${id}/delete`,
                { method: 'POST', headers: uploadManager._vaultHeaders() });
        } catch (_) { /* best effort */ }
    }
    if (toDelete.length) await loadVaultFiles();

    if (toUpload.length) {
        // Zero-knowledge vault: encrypt each file in the browser BEFORE it enters
        // the chunked uploader, so the server only ever receives ciphertext.
        if (isZkVault(state.currentVault)) {
            try {
                // Encrypt content AND the name/MIME under the CURRENT DEK epoch, and tag each
                // entry with it; the server re-checks the epoch at finalize (rejecting a
                // stale-epoch upload that raced a rotation) and stamps it onto the file. The
                // name never leaves the browser in the clear — only enc_name/enc_mime + a
                // client blind index (name_bi) are sent.
                const vid = state.currentVault.id;
                const keyVersion = await zkGetCurrentDekVersion(vid);
                const dek = await zkGetVaultDek(vid, keyVersion);
                const lib = eccLib();
                for (const entry of toUpload) {
                    const mime = entry.file.type || '';
                    // Client-generate this file's id and SEAL its name/MIME bound to it (v2), so the
                    // stored name can't be transposed to another row. The id is threaded through the
                    // uploader (incl. IndexedDB resume) and re-sent at upload-complete, where the
                    // server uses it as the row id — keeping the sealed id == the final row id.
                    const clientFileId = zkNewObjId();
                    entry.clientFileId = clientFileId;
                    const buf = await entry.file.arrayBuffer();
                    const enc = await lib.encryptFile(buf, dek);
                    entry.file = new File([enc], entry.name, { type: mime });
                    entry.keyVersion = keyVersion;
                    entry.encName = await lib.encryptName(entry.name, dek, vid, 'name', keyVersion, clientFileId);
                    entry.nameBi = await lib.nameBlindIndex(entry.name, dek, vid, keyVersion);
                    entry.encMime = mime ? await lib.encryptName(mime, dek, vid, 'mime', keyVersion, clientFileId) : null;
                }
            } catch (e) {
                showError('Zero-knowledge encryption failed: ' + e.message);
                return;
            }
        }
        uploadManager.enqueueNamed(toUpload);
    }
}

// Setup drag-and-drop file upload
function setupFileDragDrop() {
    const filesTab = document.getElementById('vault-files-tab');
    if (!filesTab) {
        console.warn('Files tab not found for drag-drop setup');
        return;
    }
    
    // Prevent default drag behaviors
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        filesTab.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    // Highlight drop zone when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        filesTab.addEventListener(eventName, () => {
            filesTab.classList.add('drag-over');
        }, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        filesTab.addEventListener(eventName, () => {
            filesTab.classList.remove('drag-over');
        }, false);
    });
    
    // Handle dropped files
    filesTab.addEventListener('drop', async (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length > 0) {
            console.log(`Dropped ${files.length} file(s)`);
            showInfo(`Uploading ${files.length} file(s)...`);
            await uploadFiles(files);
        }
    }, false);
    
    console.log('✓ Drag-and-drop setup complete');
}

// Create new folder
async function createFolder() {
    if (state.canWriteCurrentVault === false) {
        showError('You have read-only access to this vault.');
        return;
    }
    const folderName = await showPrompt(
        'Enter a name for the new folder.',
        'New folder',
        { placeholder: 'Folder name' }
    );
    if (!folderName) return;

    try {
        // Build headers with vault password if needed
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }

        const body = {};
        if (state.currentFolderId) {
            body.parent_folder_id = state.currentFolderId;
        }

        if (isZkVault(state.currentVault)) {
            // Zero-knowledge: encrypt the folder name in the browser under the current DEK
            // epoch and send only the ciphertext + blind index + epoch (never the name).
            try {
                const vid = state.currentVault.id;
                const epoch = await zkGetCurrentDekVersion(vid);
                const dek = await zkGetVaultDek(vid, epoch);
                const lib = eccLib();
                // Client-generate the folder id so the name is sealed BOUND to it (v2, can't be
                // transposed). The server uses this id for the row (validated + collision-checked).
                body.id = zkNewObjId();
                body.enc_name = await lib.encryptName(folderName, dek, vid, 'name', epoch, body.id);
                body.name_bi = await lib.nameBlindIndex(folderName, dek, vid, epoch);
                body.name_key_version = epoch;
            } catch (e) {
                showError('Zero-knowledge encryption failed: ' + e.message);
                return;
            }
        } else {
            body.name = folderName;
        }

        await apiRequest(`/vaults/${state.currentVault.id}/folders`, {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
        });
        
        showSuccess('Folder created successfully');
        
        // Reload files
        await loadVaultFiles();
    } catch (error) {
        console.error('Create folder failed:', error);
        showError('Failed to create folder: ' + error.message);
    }
}

// Load vault info tab. Element IDs here must match the #vault-info-tab markup.
async function loadVaultInfo() {
    if (!state.currentVault) return;

    try {
        const vault = state.currentVault;
        const setText = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };

        // Top stat tiles
        setText('info-file-count', vault.file_count || 0);
        setText('info-total-size', formatBytes(vault.total_size_bytes || 0));
        setText('info-vault-owner', vault.owner_username || currentUser.username);
        setText('info-vault-created-ago', vault.created_at ? formatTimeAgo(vault.created_at) : '-');

        // Details card
        setText('info-vault-name', vault.name);
        setText('info-vault-description', vault.description || 'No description');
        setText('info-vault-created', vault.created_at ? new Date(vault.created_at).toLocaleString() : '-');

        // Storage usage bar
        const storageBarFill = document.getElementById('info-storage-bar-fill');
        const storageText = document.getElementById('info-storage-text');
        const totalSize = vault.total_size_bytes || 0;
        if (vault.size_limit && vault.size_limit > 0) {
            const usagePercent = (totalSize / vault.size_limit) * 100;
            const displayPercent = Math.min(usagePercent, 100).toFixed(1);
            if (storageBarFill) {
                storageBarFill.style.width = `${displayPercent}%`;
                storageBarFill.style.background = usagePercent >= 90
                    ? 'linear-gradient(90deg, #ef4444, #dc2626)'
                    : usagePercent >= 75
                        ? 'linear-gradient(90deg, #f59e0b, #d97706)'
                        : 'linear-gradient(90deg, #10b981, #059669)';
            }
            if (storageText) storageText.textContent = `${formatBytes(totalSize)} of ${formatBytes(vault.size_limit)} (${displayPercent}%)`;
        } else {
            if (storageBarFill) storageBarFill.style.width = '0%';
            if (storageText) storageText.textContent = formatBytes(totalSize);
        }

        // Security card
        const hasPwEl = document.getElementById('info-has-password');
        if (hasPwEl) {
            hasPwEl.innerHTML = vault.has_password
                ? `<span class="badge badge-success">${iconSvg('lock', 'icon-sm')} Password protected</span>`
                : `<span class="badge badge-secondary">${iconSvg('unlock', 'icon-sm')} Open access</span>`;
        }
        setText('info-file-expiration', vault.expire_files_after_days
            ? `${vault.expire_files_after_days} ${vault.expire_files_unit || 'days'}`
            : 'Never');

    } catch (error) {
        console.error('Failed to load vault info:', error);
    }
}

// Load vault permissions tab
async function loadVaultPermissions() {
    if (!state.currentVault) return;

    // Department (group) access section is loaded alongside the per-user table.
    loadVaultGroupAccess();

    // Wire the "Grant access" button here so it works on the Permissions tab
    // (it was previously only wired when the Settings tab was opened).
    const addPermBtn = document.getElementById('add-permission-btn');
    if (addPermBtn) addPermBtn.onclick = () => openVaultGrantModal();

    const tbody = document.getElementById('permissions-table-body');
    if (!tbody) return;
    
    try {
        // Build headers with vault password if needed
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        
        const permissions = await apiRequest(`/vaults/${state.currentVault.id}/permissions`, { headers });
        
        if (!permissions || permissions.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 40px;">
                        <div class="empty-state">
                            <p style="font-size: 48px; margin: 0;">${iconSvg('users', 'icon-lg')}</p>
                            <h3 style="margin: 16px 0 8px 0;">No permissions yet</h3>
                            <p style="color: var(--text-secondary);">Grant access to users to share this vault</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = permissions.map(perm => {
            // The API returns booleans + added_at (not a "permission" string / granted_at).
            const isOwnerOrAdmin = (state.currentVault.owner_id === currentUser.id) || currentUser.role === 'admin';
            const isManagerRow = !!perm.manage_permission;
            const level = isManagerRow ? 'manage'
                : (perm.delete_permission ? 'delete' : (perm.write_permission ? 'write' : 'read'));
            // A Manager can't edit/revoke a peer Manager — lock those rows for non owner/admin viewers.
            const locked = isManagerRow && !isOwnerOrAdmin;
            // Offer "Manager" only to owner/admin; also render it to label an existing manager row.
            const managerOpt = (isOwnerOrAdmin || isManagerRow)
                ? `<option value="manage" ${level === 'manage' ? 'selected' : ''}>Manager</option>`
                : '';
            const addedDate = perm.added_at ? new Date(perm.added_at) : null;
            const added = (addedDate && !isNaN(addedDate)) ? addedDate.toLocaleDateString() : '—';
            return `
            <tr>
                <td>${escapeHtml(perm.username)}</td>
                <td>${escapeHtml(perm.email || '-')}</td>
                <td>
                    <select class="form-control form-control-sm perm-level-select" data-user-id="${perm.user_id}" style="max-width:170px" ${locked ? 'disabled' : ''}>
                        <option value="read" ${level === 'read' ? 'selected' : ''}>Read only</option>
                        <option value="write" ${level === 'write' || level === 'delete' ? 'selected' : ''}>Read &amp; write</option>
                        ${managerOpt}
                    </select>
                </td>
                <td>${added}</td>
                <td>
                    <button class="action-btn action-btn-danger" data-action="revoke-permission" data-user-id="${perm.user_id}" ${locked ? 'disabled' : ''}>
                        Revoke
                    </button>
                </td>
            </tr>
        `;
        }).join('');

        // Add event listeners for revoke buttons
        tbody.querySelectorAll('button[data-action="revoke-permission"]').forEach(btn => {
            btn.addEventListener('click', () => {
                const userId = btn.getAttribute('data-user-id');
                revokeVaultPermission(userId);
            });
        });

        // Inline level change — the grant endpoint upserts, so re-POSTing with a
        // new level updates the existing entry in place (no revoke/re-add dance).
        tbody.querySelectorAll('select.perm-level-select').forEach(sel => {
            sel.addEventListener('change', () => {
                changeVaultPermissionLevel(sel.getAttribute('data-user-id'), sel.value);
            });
        });

    } catch (error) {
        console.error('Failed to load permissions:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="5" style="text-align: center; padding: 20px; color: var(--error);">
                    Failed to load permissions
                </td>
            </tr>
        `;
    }
}

// Change an existing member's access level in place (read <-> read/write).
async function changeVaultPermissionLevel(userId, level) {
    try {
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }
        await apiRequest(`/vaults/${state.currentVault.id}/permissions`, {
            method: 'POST',
            headers,
            body: JSON.stringify({ user_id: userId, level })
        });
        showSuccess(`Access updated to ${level === 'write' ? 'Read & write' : 'Read only'}`);
    } catch (error) {
        console.error('Failed to update permission level:', error);
        showError('Failed to update access: ' + error.message);
        await loadVaultPermissions();  // re-sync the dropdown to the server truth
    }
}

// Revoke vault permission
async function revokeVaultPermission(userId) {
    const zk = isZkVault(state.currentVault);
    const confirmed = await showConfirm(
        zk
            ? 'Revoke access? The vault key will be rotated so this user can no longer open '
              + 'NEW files. Files they could already open should be treated as already seen '
              + '(their key cannot be un-shown).'
            : 'Are you sure you want to revoke access for this user?',
        'Revoke Permission'
    );
    if (!confirmed) return;

    try {
        // Build headers with vault password if needed
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }

        // Zero-knowledge: rotate the DEK FIRST (mint a new epoch, re-wrap for remaining
        // members, deactivate this user's keys) as a HARD step. If it fails, abort the
        // whole revoke — leaving access intact and consistent rather than half-revoked —
        // and surface the error. Only once the crypto cut-off is committed do we drop authz.
        if (zk) {
            try {
                await zkRekeyForRevoke(state.currentVault.id, userId);
            } catch (e) {
                showError('Access was NOT revoked: the vault key could not be rotated. Please retry. ('
                    + (e && e.message ? e.message : e) + ')');
                return;
            }
        }

        await apiRequest(`/vaults/${state.currentVault.id}/permissions/${userId}`, {
            method: 'DELETE',
            headers
        });

        showSuccess('Permission revoked successfully');

        // Reload permissions
        await loadVaultPermissions();
    } catch (error) {
        console.error('Failed to revoke permission:', error);
        showError('Failed to revoke permission: ' + error.message);
    }
}

// --- Vault department (group) access ----------------------------------------
async function loadVaultGroupAccess() {
    const el = document.getElementById('vault-group-access-list');
    if (!el || !state.currentVault) return;
    // Zero-knowledge vaults can't be shared to a department: a group has no key,
    // so the server rejects group grants. Explain it instead of showing dead UI;
    // sharing is per-user (the DEK is wrapped to each recipient).
    if (isZkVault(state.currentVault)) {
        el.replaceChildren();
        const note = document.createElement('div');
        note.className = 'text-tertiary text-sm p-sm';
        note.textContent = 'Department access isn’t available on zero-knowledge vaults — '
            + 'each member needs the encryption key shared to them directly. '
            + 'Add individual users above to share securely.';
        el.appendChild(note);
        return;
    }
    try {
        const [access, groups] = await Promise.all([
            apiRequest(`/vaults/${state.currentVault.id}/group-access`, { silent: true }).catch(() => []),
            apiRequest('/groups', { silent: true }).catch(() => [])
        ]);
        const accessList = Array.isArray(access) ? access : [];
        const accessIds = new Set(accessList.map(a => a.group_id));
        const addable = (Array.isArray(groups) ? groups : []).filter(g => !accessIds.has(g.id));
        el.innerHTML = `
            ${addable.length ? `
                <div class="group-add-member mb-md">
                    <select id="vga-group-select" class="form-control"><option value="">Add a department…</option>${addable.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join('')}</select>
                    <select id="vga-perm-select" class="form-control" style="max-width:160px"><option value="read">Read only</option><option value="write">Read &amp; write</option></select>
                    <button id="vga-add-btn" class="btn btn-secondary">${iconSvg('plus', 'icon-sm')} Add</button>
                </div>` : ''}
            <div class="member-list">
                ${accessList.length ? accessList.map(a => `
                    <div class="member-row">
                        <span class="tree-dot" style="--chip:${chipColorValue(a.color)}"></span>
                        <div class="cell-user-text"><span class="cell-user-name">${escapeHtml(a.name)}</span></div>
                        <span class="badge badge-${a.permission === 'write' ? 'success' : 'info'}">${a.permission === 'write' ? 'Read & write' : 'Read only'}</span>
                        <button class="btn btn-sm btn-ghost vga-remove" data-group-id="${a.group_id}" title="Revoke access">${iconSvg('x', 'icon-sm')}</button>
                    </div>`).join('') : '<div class="text-tertiary text-sm p-sm">No departments have access — only the owner and individually-added users can open this vault.</div>'}
            </div>`;
        const addBtn = document.getElementById('vga-add-btn');
        if (addBtn) addBtn.onclick = () => {
            const gid = document.getElementById('vga-group-select').value;
            const perm = document.getElementById('vga-perm-select').value;
            if (gid) addVaultGroupAccess(gid, perm);
        };
        el.querySelectorAll('.vga-remove').forEach(b => { b.onclick = () => removeVaultGroupAccess(b.dataset.groupId); });
    } catch (e) {
        el.innerHTML = `<div class="alert alert-error">Failed to load department access: ${escapeHtml(e.message)}</div>`;
    }
}

async function addVaultGroupAccess(groupId, permission) {
    try {
        await apiRequest(`/vaults/${state.currentVault.id}/group-access`, { method: 'POST', body: JSON.stringify({ group_id: groupId, permission }) });
        showSuccess('Department access granted');
        await loadVaultGroupAccess();
    } catch (e) { showError('Failed to grant access: ' + e.message); }
}

async function removeVaultGroupAccess(groupId) {
    try {
        await apiRequest(`/vaults/${state.currentVault.id}/group-access/${groupId}`, { method: 'DELETE' });
        showSuccess('Department access revoked');
        await loadVaultGroupAccess();
    } catch (e) { showError('Failed to revoke access: ' + e.message); }
}

// --- Searchable "Grant access" modal for individual users -------------------
const vaultGrantState = { results: [], groups: [], excluded: new Set() };
let vaultGrantSearchTimer = null;
let vaultGrantSearchSeq = 0;   // drops a stale/out-of-order search response (modal reopen, fast typing)

// Show a plain-text status message in the grant list (safe DOM, no innerHTML).
function grantListMessage(msg) {
    const el = document.getElementById('vault-grant-list');
    if (!el) return;
    const d = document.createElement('div');
    d.className = 'text-tertiary text-sm p-sm';
    d.textContent = msg;
    el.replaceChildren(d);
}

// Server-side user search (a non-admin owner can't read the admin-only /users list), scoped +
// rate-limited backend-side. Debounced by onVaultGrantSearchInput.
async function runVaultGrantSearch() {
    const seq = ++vaultGrantSearchSeq;
    const q = (document.getElementById('vault-grant-search')?.value || '').trim();
    if (q.length < 2) {
        vaultGrantState.results = [];
        grantListMessage('Type at least 2 characters to search for a user.');
        updateVaultGrantCount();
        return;
    }
    try {
        // Optional department narrow: the picker's dept <select> passes a group the caller belongs
        // to; the server ignores a foreign group id. Under the same_department org policy the server
        // already limits results to the caller's departments regardless.
        const gsel = document.getElementById('vault-grant-group-filter');
        const gid = gsel && gsel.value && gsel.value !== 'all' ? gsel.value : '';
        const url = `/users/search?q=${encodeURIComponent(q)}${gid ? `&group_id=${encodeURIComponent(gid)}` : ''}`;
        const users = await apiRequest(url, { silent: true });
        if (seq !== vaultGrantSearchSeq) return;  // a newer search (or modal reopen) superseded this one
        vaultGrantState.results = (Array.isArray(users) ? users : []).filter(u => !vaultGrantState.excluded.has(u.id));
        renderVaultGrantList();
    } catch (e) {
        if (seq !== vaultGrantSearchSeq) return;
        vaultGrantState.results = [];
        // A thrown error means the search itself failed (permission, rate-limit, server, network) —
        // NOT an empty result. The toast is suppressed (silent), so surface the reason here instead of
        // the "No matching users." copy the empty-success path uses (which would look like "no such user").
        grantListMessage(e && e.message ? e.message : 'Search failed.');
        updateVaultGrantCount();
    }
}

function onVaultGrantSearchInput() {
    clearTimeout(vaultGrantSearchTimer);
    vaultGrantSearchTimer = setTimeout(runVaultGrantSearch, 250);
}

async function openVaultGrantModal() {
    if (!state.currentVault) return;
    const modal = document.getElementById('vault-grant-modal');
    if (!modal) return;
    document.getElementById('vault-grant-search').value = '';
    vaultGrantSearchSeq++;   // invalidate any in-flight search from a previous open
    grantListMessage('Type at least 2 characters to search for a user.');
    // Only the owner / a global admin may grant the Manager role — managers can
    // delegate read/write but not mint peer managers.
    const isOwnerOrAdmin = (state.currentVault.owner_id === currentUser.id) || currentUser.role === 'admin';
    const levelSel = document.getElementById('vault-grant-level');
    const mgrOpt = levelSel ? levelSel.querySelector('option[value="manage"]') : null;
    if (mgrOpt) mgrOpt.hidden = !isOwnerOrAdmin;
    if (levelSel && levelSel.value === 'manage' && !isOwnerOrAdmin) levelSel.value = 'read';
    modal.classList.add('active');
    try {
        const headers = {};
        if (state.currentVault.has_password && state.vaultPassword) headers['X-Vault-Password'] = state.vaultPassword;
        // Non-admins can't read the admin-only /users list; the recipient picker searches the
        // scoped /users/search endpoint on input instead of preloading the whole directory. The
        // department filter is populated from the CALLER's own groups (the /groups list is
        // admin-only, and the server only honors a group id the caller belongs to anyway).
        const [me, perms] = await Promise.all([
            (Array.isArray(currentUser && currentUser.groups) && currentUser.groups.length)
                ? Promise.resolve({ groups: currentUser.groups })
                : apiRequest('/users/me', { silent: true }).catch(() => ({ groups: [] })),
            apiRequest(`/vaults/${state.currentVault.id}/permissions`, { headers, silent: true }).catch(() => [])
        ]);
        vaultGrantState.excluded = new Set((Array.isArray(perms) ? perms : []).map(p => p.user_id));
        if (state.currentVault.owner_id) vaultGrantState.excluded.add(state.currentVault.owner_id);
        vaultGrantState.results = [];
        vaultGrantState.groups = Array.isArray(me && me.groups) ? me.groups : [];
        const groupSel = document.getElementById('vault-grant-group-filter');
        if (groupSel) {
            groupSel.innerHTML = `<option value="all">All my departments</option>` +
                vaultGrantState.groups.slice().sort((a, b) => (a.name || '').localeCompare(b.name || ''))
                    .map(g => `<option value="${escapeHtml(g.id)}">${escapeHtml(g.name || 'Department')}</option>`).join('');
            // Show the filter only when the caller actually belongs to a department; otherwise there is
            // nothing to narrow by. Selecting one re-runs the (server-side, scoped) search.
            groupSel.style.display = vaultGrantState.groups.length ? '' : 'none';
            groupSel.value = 'all';
            groupSel.onchange = () => runVaultGrantSearch();
        }
        setTimeout(() => document.getElementById('vault-grant-search').focus(), 60);
    } catch (e) {
        document.getElementById('vault-grant-list').innerHTML = `<div class="alert alert-error">Failed to load users: ${escapeHtml(e.message)}</div>`;
    }
}

function renderVaultGrantList() {
    const listEl = document.getElementById('vault-grant-list');
    if (!listEl) return;
    const list = vaultGrantState.results;
    if (!list.length) { grantListMessage('No matching users.'); updateVaultGrantCount(); return; }
    const frag = document.createDocumentFragment();
    for (const u of list) {
        const label = document.createElement('label');
        label.className = 'pick-row';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = u.id;
        const avatar = document.createElement('span');
        avatar.className = 'avatar-sm';
        avatar.textContent = (u.username || '?').substring(0, 2).toUpperCase();
        const textWrap = document.createElement('div');
        textWrap.className = 'cell-user-text';
        const nameEl = document.createElement('span');
        nameEl.className = 'cell-user-name';
        nameEl.textContent = u.username || '';
        textWrap.appendChild(nameEl);
        label.append(cb, avatar, textWrap);
        frag.appendChild(label);
    }
    listEl.replaceChildren(frag);
    updateVaultGrantCount();
}

function updateVaultGrantCount() {
    const n = document.querySelectorAll('#vault-grant-list input:checked').length;
    const countEl = document.getElementById('vault-grant-count');
    if (countEl) countEl.textContent = n ? `${n} selected` : '';
    const btn = document.getElementById('vault-grant-confirm');
    if (btn) btn.disabled = n === 0;
}

async function confirmVaultGrant() {
    const ids = Array.from(document.querySelectorAll('#vault-grant-list input:checked')).map(c => c.value);
    const level = document.getElementById('vault-grant-level').value;
    if (!ids.length) return;
    const zk = isZkVault(state.currentVault);
    const results = await Promise.allSettled(ids.map(async uid => {
        // Zero-knowledge: re-wrap the DEK to each recipient first (skips the
        // permission grant for anyone without a keypair, surfaced as a failure).
        if (zk) await zkShareVaultToUser(state.currentVault.id, uid);
        return apiRequest(`/vaults/${state.currentVault.id}/permissions`, { method: 'POST', body: JSON.stringify({ user_id: uid, level }) });
    }));
    const ok = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.length - ok;
    if (ok) showSuccess(`Granted access to ${ok} user(s)`);
    if (failed) showError(`${failed} grant(s) failed`);
    closeModal();
    await loadVaultPermissions();
}

// Load vault settings tab
async function loadVaultSettings() {
    if (!state.currentVault) return;
    
    try {
        const vault = state.currentVault;
        
        // Vault name
        const nameEl = document.getElementById('settings-vault-name');
        if (nameEl) {
            nameEl.textContent = vault.name;
        }
        
        // Vault description
        const descEl = document.getElementById('settings-vault-description');
        if (descEl) {
            descEl.textContent = vault.description || 'No description';
        }
        
        // Created date
        const createdEl = document.getElementById('settings-vault-created');
        if (createdEl) {
            createdEl.textContent = new Date(vault.created_at).toLocaleString();
        }
        
        // Storage info
        const sizeEl = document.getElementById('settings-vault-size');
        if (sizeEl) {
            sizeEl.textContent = formatBytes(vault.total_size_bytes || 0);
        }
        
        const limitEl = document.getElementById('settings-vault-limit');
        if (limitEl) {
            limitEl.textContent = vault.size_limit ? formatBytes(vault.size_limit) : 'No limit';
        }
        
        const filesEl = document.getElementById('settings-vault-files');
        if (filesEl) {
            filesEl.textContent = vault.file_count || 0;
        }
        
        // Security settings
        const passwordStatusEl = document.getElementById('settings-has-password');
        if (passwordStatusEl) {
            if (vault.has_password) {
                passwordStatusEl.innerHTML = `<span class="badge badge-success">${iconSvg('lock', 'icon-sm')} Enabled</span>`;
            } else {
                passwordStatusEl.innerHTML = `<span class="badge badge-secondary">${iconSvg('unlock', 'icon-sm')} Disabled</span>`;
            }
        }
        
        const expiryEl = document.getElementById('settings-file-expiry');
        if (expiryEl) {
            if (vault.expire_files_after_days) {
                expiryEl.textContent = `${vault.expire_files_after_days} days`;
            } else {
                expiryEl.textContent = 'Never';
            }
        }
        
        // Setup button event listeners with permission checks
        setupVaultSettingsButtons();
        
    } catch (error) {
        console.error('Failed to load vault settings:', error);
    }
}

// Setup vault settings buttons with permission-based visibility
function setupVaultSettingsButtons() {
    if (!state.currentVault) return;
    
    // Determine user permissions
    const isOwner = state.currentVault.owner_id === currentUser.id;
    const isAdmin = currentUser.role === 'admin';
    const canManage = isOwner || isAdmin;
    
    // Edit Vault Info button
    const editVaultBtn = document.getElementById('edit-vault-info-btn');
    if (editVaultBtn) {
        if (!canManage) {
            editVaultBtn.style.display = 'none';
        } else {
            editVaultBtn.style.display = '';
            editVaultBtn.onclick = () => {
                // Pre-fill form with current vault data
                document.getElementById('edit-vault-name').value = state.currentVault.name;
                document.getElementById('edit-vault-description').value = state.currentVault.description || '';
                openModal('edit-vault-info-modal');
            };
        }
    }
    
    // Change Vault Password button
    const changePasswordBtn = document.getElementById('change-vault-password-btn');
    if (changePasswordBtn) {
        if (!canManage) {
            changePasswordBtn.style.display = 'none';
        } else {
            changePasswordBtn.style.display = '';
            changePasswordBtn.onclick = () => {
                document.getElementById('change-vault-password-form').reset();
                openModal('change-vault-password-modal');
            };
        }
    }
    
    // Set Expiry button
    const setExpiryBtn = document.getElementById('set-expiry-btn');
    if (setExpiryBtn) {
        if (!canManage) {
            setExpiryBtn.style.display = 'none';
        } else {
            setExpiryBtn.style.display = '';
            setExpiryBtn.onclick = () => {
                const currentExpiry = state.currentVault.expire_files_after_days || 0;
                const currentUnit = state.currentVault.expire_files_unit || 'days';
                document.getElementById('expire-files-value').value = currentExpiry;
                document.getElementById('expire-files-unit').value = currentUnit;
                const urmEl = document.getElementById('unlock-remember-minutes');
                if (urmEl) urmEl.value = (state.currentVault.unlock_remember_minutes ?? '');
                // Current max size (bytes -> GB) + remaining account headroom (excluding this vault).
                const sizeEl = document.getElementById('vault-size-limit-gb');
                if (sizeEl) sizeEl.value = state.currentVault.size_limit ? _bytesToGb(state.currentVault.size_limit) : '';
                renderVaultSizeAvailability('vault-size-limit-avail', sizeEl, state.currentVault.id,
                    "The most this vault may hold. Can't go below what's already stored.");
                openModal('set-expiry-modal');
            };
        }
    }
    
    // Delete Vault button
    const deleteVaultBtn = document.getElementById('delete-vault-from-settings-btn');
    if (deleteVaultBtn) {
        const canDelete = isOwner || isAdmin;
        if (!canDelete) {
            deleteVaultBtn.style.display = 'none';
        } else {
            deleteVaultBtn.style.display = '';
            deleteVaultBtn.onclick = () => {
                deleteVault(state.currentVault.id);
            };
        }
    }
    
    // Add Permission button
    const addPermBtn = document.getElementById('add-permission-btn');
    if (addPermBtn) {
        if (!canManage) {
            addPermBtn.style.display = 'none';
        } else {
            addPermBtn.style.display = '';
            addPermBtn.onclick = () => openVaultGrantModal();
        }
    }
}

// Delete Vault
async function deleteVault(vaultId) {
    const confirmed = await showConfirm(
        'This action cannot be undone. All files and settings will be permanently deleted.',
        'Delete this vault?'
    );
    if (!confirmed) return;

    // The real route is POST /vaults/{id}/delete (there is no DELETE /vaults/{id}).
    // A password-protected vault needs its password proven for the destructive delete; send it
    // via the X-Vault-Password header (matching every other password-gated vault route). Reuse
    // the cached password when deleting the currently-open vault; otherwise (e.g. the card trash
    // button on a vault we haven't unlocked) prompt for it.
    // Prefer state.currentVault when it's the target: it's kept in sync on an in-session password
    // add/remove, whereas the state.allVaults snapshot is only refreshed by a full loadVaults().
    const vault = (state.currentVault && state.currentVault.id === vaultId ? state.currentVault : null)
        || (state.allVaults || []).find(v => v.id === vaultId);
    const headers = {};
    if (vault && vault.has_password) {
        let pw = (state.currentVault && state.currentVault.id === vaultId) ? state.vaultPassword : null;
        if (!pw) {
            pw = await showPrompt(
                'This vault is password-protected. Enter its password to permanently delete it.',
                'Vault password',
                { password: true }
            );
            if (pw === null) return; // cancelled
        }
        headers['X-Vault-Password'] = pw;
    }

    try {
        await apiRequest(`/vaults/${vaultId}/delete`, {
            method: 'POST',
            headers
        });
        showSuccess('Vault deleted successfully');
        loadVaults();
    } catch (error) {
        showError('Failed to delete vault: ' + error.message);
    }
}

// Vault Settings Form Handlers
async function handleEditVaultInfo(e) {
    e.preventDefault();
    
    const name = document.getElementById('edit-vault-name').value.trim();
    const description = document.getElementById('edit-vault-description').value.trim();
    
    if (!name) {
        showError('Vault name cannot be empty');
        return;
    }
    
    try {
        const updatedVault = await apiRequest(`/vaults/${state.currentVault.id}`, {
            method: 'PATCH',
            body: JSON.stringify({
                name: name,
                description: description || null
            })
        });
        
        // Update local state
        state.currentVault.name = updatedVault.name;
        state.currentVault.description = updatedVault.description;
        
        // Update UI
        const vaultTitle = document.getElementById('vault-view-title');
        if (vaultTitle) vaultTitle.textContent = updatedVault.name;
        
        const vaultDesc = document.getElementById('vault-view-description');
        if (vaultDesc) vaultDesc.textContent = updatedVault.description || 'No description';
        
        showSuccess('Vault information updated successfully');
        closeModal('edit-vault-info-modal');
        await loadVaultSettings();
        
    } catch (error) {
        console.error('Failed to update vault info:', error);
        showError(error.message || 'Failed to update vault information');
    }
}

async function handleChangeVaultPassword(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('current-vault-password').value;
    const newPassword = document.getElementById('new-vault-password').value;
    const confirmPassword = document.getElementById('confirm-new-vault-password').value;
    
    // Validate passwords match
    if (newPassword !== confirmPassword) {
        showError('New passwords do not match');
        return;
    }
    
    try {
        await apiRequest(`/vaults/${state.currentVault.id}/password`, {
            method: 'PUT',
            body: JSON.stringify({
                current_password: currentPassword || null,
                new_password: newPassword || null
            })
        });
        
        // Update local state + the remembered password so the new one is reused
        // (and a removed password is forgotten).
        state.currentVault.has_password = !!newPassword;
        // Keep the vaults-grid snapshot in sync so a later card action (e.g. delete)
        // reads the correct has_password without a full reload.
        const snap = (state.allVaults || []).find(v => v.id === state.currentVault.id);
        if (snap) snap.has_password = !!newPassword;
        if (newPassword) {
            state.setVaultPassword(newPassword);
            state.rememberVaultPassword(state.currentVault.id, newPassword, state.currentVault.unlock_remember_minutes);
        } else {
            state.setVaultPassword(null);
            state.forgetVaultPassword(state.currentVault.id);
        }

        showSuccess(newPassword ? 'Vault password changed successfully' : 'Vault password removed');
        closeModal('change-vault-password-modal');
        document.getElementById('change-vault-password-form').reset();
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
    const urmRaw = document.getElementById('unlock-remember-minutes');
    const urm = (urmRaw && urmRaw.value !== '') ? Math.max(0, parseInt(urmRaw.value) || 0) : null;
    const sizeEl = document.getElementById('vault-size-limit-gb');
    const sizeGb = (sizeEl && sizeEl.value !== '') ? parseFloat(sizeEl.value) : null;

    try {
        const body = {
            expire_files_after_days: expireValue > 0 ? expireValue : null,
            expire_files_unit: expireValue > 0 ? expireUnit : 'days',
            unlock_remember_minutes: urm
        };
        // Only send size_limit when a positive value is entered AND it actually changed. Sent in
        // BYTES. Skipping an unchanged value means editing OTHER policies never re-validates the
        // size — so a vault grandfathered above a since-lowered ceiling can still have its expiry
        // edited (the server rejects a null/0; the field isn't clearable to unlimited).
        let newSizeBytes = null;
        if (sizeGb != null && sizeGb > 0) {
            const candidate = Math.round(sizeGb * (1024 ** 3));
            if (candidate !== (state.currentVault.size_limit || 0)) {
                newSizeBytes = candidate;
                body.size_limit = newSizeBytes;
            }
        }
        await apiRequest(`/vaults/${state.currentVault.id}/settings`, {
            method: 'PATCH',
            body: JSON.stringify(body)
        });

        // Update local state + drop any remembered password so the new window applies.
        state.currentVault.expire_files_after_days = expireValue > 0 ? expireValue : null;
        state.currentVault.expire_files_unit = expireValue > 0 ? expireUnit : 'days';
        state.currentVault.unlock_remember_minutes = urm;
        if (newSizeBytes != null) state.currentVault.size_limit = newSizeBytes;
        // Re-base the remember window on the new policy (applies to the next
        // re-entry; the currently-open vault stays open either way).
        state.forgetVaultPassword(state.currentVault.id);
        if (state.currentVault.has_password) {
            state.rememberVaultPassword(state.currentVault.id, state.vaultPassword, urm);
        }

        showSuccess('Vault policies saved');

        closeModal('set-expiry-modal');
        await loadVaultSettings();

    } catch (error) {
        console.error('Failed to save vault policies:', error);
        showError(error.message || 'Failed to save vault policies');
    }
}

async function handleAddPermission(e) {
    e.preventDefault();
    
    const userId = document.getElementById('permission-user-select').value;
    const level = document.getElementById('permission-level-select').value;
    
    if (!userId) {
        showError('Please select a user');
        return;
    }
    
    try {
        // For a zero-knowledge vault, re-wrap the DEK to the recipient FIRST so we
        // never grant access to someone who can't decrypt (throws if they have no key).
        if (isZkVault(state.currentVault)) {
            await zkShareVaultToUser(state.currentVault.id, userId);
        }

        await apiRequest(`/vaults/${state.currentVault.id}/permissions`, {
            method: 'POST',
            body: JSON.stringify({
                user_id: userId,
                level: level
            })
        });

        showSuccess('Permission granted successfully');
        closeModal('add-permission-modal');
        document.getElementById('add-permission-form').reset();
        await loadVaultPermissions();
        
    } catch (error) {
        console.error('Failed to add permission:', error);
        showError(error.message || 'Failed to add permission');
    }
}

async function loadUsersForPermission() {
    try {
        const users = await apiRequest('/users');
        const select = document.getElementById('permission-user-select');
        
        if (!select) return;
        
        // Clear existing options except the first one
        select.innerHTML = '<option value="">-- Select a user --</option>';
        
        users.forEach(user => {
            // Don't show current user or vault owner
            if (user.id !== state.currentVault.owner_id && user.id !== currentUser.id) {
                select.innerHTML += `<option value="${user.id}">${escapeHtml(user.username)} (${escapeHtml(user.email || 'No email')})</option>`;
            }
        });
    } catch (error) {
        console.error('Failed to load users:', error);
        showError('Failed to load users for permissions');
    }
}

// Open a modal by id (several handlers referenced openModal but it was undefined,
// so vault settings/permission buttons silently threw and did nothing).
function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add('active');
}

// Close Modal
function closeModal() {
    document.querySelectorAll('.modal').forEach(modal => {
        modal.classList.remove('active');
    });
    closeFilePreview(); // free any in-memory decrypted preview blob
}

// Copy to Clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        // Visual feedback
        const originalText = element.textContent;
        element.textContent = '✓ Copied!';
        setTimeout(() => {
            element.textContent = originalText;
        }, 2000);
    }).catch(err => {
        alert('Failed to copy: ' + err);
    });
}

// Utility: Escape HTML
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// ============================================================================
// VIEW CLEANUP & RESOURCE MANAGEMENT
// ============================================================================

// Clean up resources when leaving views
function cleanupPreviousView(newSection) {
    console.log('Cleaning up resources before switching to:', newSection);
    
    // Cleanup monitor (disconnect WebSocket, clear intervals)
    if (newSection !== 'monitor') {
        cleanupMonitor();
    }
    
    // Cleanup temp creds refresh intervals
    if (newSection !== 'temp-creds') {
        // Stop temp creds countdown timers if any
        if (window.tempCredsInterval) {
            clearInterval(window.tempCredsInterval);
            window.tempCredsInterval = null;
        }
    }
    
    // Leaving the open vault via the sidebar: stop its watchers and drop the
    // in-memory password. The remembered-unlock entry (sessionStorage) still lets
    // the user re-enter without a prompt while the unlock window is valid.
    if (state.currentVault) {
        if (state.accessCheckInterval) { clearInterval(state.accessCheckInterval); state.accessCheckInterval = null; }
        stopVaultFileWatch();
        state.lastFilesSignature = null;
        state.canWriteCurrentVault = true;
        state.currentVault = null;
        state.currentVaultId = null;
        state.currentFolderId = null;
        state.currentPath = [];
        state.vaultPassword = null;
    }
}

// ============================================================================
// SESSION BOOT + PREFERENCE SYNC
// ============================================================================

// Verify a cached session token with the server, then reveal the dashboard. Runs
// while the pre-paint boot splash (auth-boot.js) is showing, so an EXPIRED token
// bounces straight to login without ever flashing the app shell.
async function enterAuthedSession() {
    try {
        const resp = await fetch(`${API_BASE}/users/me`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (!resp.ok) { logout(); return; }   // 401/403/etc -> login, no dashboard flash
        const user = await resp.json();
        currentUser = user;
        try { storage.setItem('currentUser', JSON.stringify(user)); } catch (_) {}
    } catch (e) {
        // Couldn't reach the server to verify — fail safe to login rather than a
        // half-loaded app on a dead/expired session.
        console.error('Session verification failed:', e);
        logout();
        return;
    }

    console.log('Restoring session for:', currentUser.username);

    // Apply this account's server-saved UI preferences (may reload once if the saved
    // skin differs) BEFORE revealing, so the look is settled when the dashboard shows.
    let reloading = false;
    try { reloading = await applyServerPreferences(); } catch (_) {}
    if (reloading) return;   // page is reloading under the splash; don't touch the DOM

    // Token is valid — finish loading UNDER the splash, then release it and reveal the
    // dashboard in the SAME synchronous tick so the default-active login screen never
    // paints in the gap (removing data-auth before an await would flash it).
    await loadUserPermissions();
    updateProfileUI(currentUser);
    document.documentElement.removeAttribute('data-auth');
    showScreen('dashboard-screen');

    // Restore the section/vault/folder the user was on before a refresh.
    let restored = false;
    try { restored = await restoreLastView(); } catch (e) { console.error('Restore failed:', e); }
    if (!restored) loadDashboardStats();

    // Restrict the sidebar for a scoped temp credential AFTER any restore.
    await loadSessionAccess();

    // Prompt a keyless user who's been invited to a ZK vault to set up a key.
    zkMaybePromptPendingInvites();
}

// Pull the current user's server-saved UI preferences and apply them, so their
// theme / accent / background / skin follow their ACCOUNT across browsers and
// devices. localStorage stays the fast pre-paint cache; the server is the source
// of truth once logged in. A skin change must happen pre-paint (ui-boot.js), so if
// the saved skin differs from what booted we persist it locally and reload once.
// Returns true when a reload was triggered — the caller MUST stop (don't touch the
// DOM/screens) so no screen flashes before the page navigates away.
async function applyServerPreferences() {
    if (!authToken) return false;
    let prefs = null;
    try {
        const resp = await fetch(`${API_BASE}/users/me/preferences`, {
            headers: { 'Authorization': `Bearer ${authToken}` }
        });
        if (!resp.ok) return false;
        prefs = await resp.json();
    } catch (_) { return false; }
    if (!prefs || typeof prefs !== 'object') return false;

    const tm = window.themeManager;
    if (!tm) return false;
    // apply* write through to localStorage (the cache) but do NOT re-POST to the
    // server (only user actions persist), so there's no echo back.
    if (prefs.theme) tm.applyTheme(prefs.theme);
    if (prefs.accent) tm.applyAccent(prefs.accent);
    if (prefs.background) tm.applyBackground(prefs.background);
    if (prefs.ui && prefs.ui !== tm.currentUi) {
        // Only reload if the choice actually persisted to localStorage — ui-boot.js reads
        // localStorage pre-paint, so if the write is blocked (private mode) the skin can't
        // be applied and reloading would loop forever. Skip the reload in that case.
        let stored = false;
        try { localStorage.setItem('ui', prefs.ui); stored = localStorage.getItem('ui') === prefs.ui; } catch (_) {}
        if (stored) {
            window.location.reload();   // ui-boot.js re-applies the skin pre-paint on reload
            return true;                // reload pending — caller stops here
        }
    }
    return false;
}

// Persist a UI preference change to the server (fire-and-forget) so it follows the
// account. No-op when logged out — the pre-login theme is a local-only default.
// Exposed on window so theme.js's pickers can call it without importing app.js.
function saveUserPreference(patch) {
    if (!authToken) return Promise.resolve();
    return fetch(`${API_BASE}/users/me/preferences`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify(patch)
    }).catch(() => {});   // best-effort; localStorage already holds the local copy
}
window.saveUserPreference = saveUserPreference;

// ============================================================================
// APPLICATION INITIALIZATION
// ============================================================================

// Close modal when clicking outside
document.addEventListener('DOMContentLoaded', () => {
    // Drop any saved zero-knowledge upload ciphertext older than the server's 24h
    // session TTL (+1h slack) so abandoned uploads can't accumulate in IndexedDB.
    try { zkUploadStore.pruneOlderThan(25 * 60 * 60 * 1000); } catch (_) {}

    // Check for existing session BEFORE showing any screen.
    const hasSession = authToken && currentUser;

    if (hasSession) {
        // The pre-paint splash (auth-boot.js) is up. VERIFY the cached token with the
        // server before revealing anything, so an expired token routes to login
        // instead of flashing the dashboard shell.
        enterAuthedSession();
    } else {
        // No session — release the boot splash (if any) and show login.
        document.documentElement.removeAttribute('data-auth');
        showScreen('login-screen');
    }
    
    // Logout button (old - can be removed after testing)
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
    
    // Profile dropdown toggle
    const profileBtn = document.getElementById('profile-btn');
    const profileMenu = document.querySelector('.profile-menu');
    if (profileBtn && profileMenu) {
        profileBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            profileMenu.classList.toggle('active');
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!profileMenu.contains(e.target)) {
                profileMenu.classList.remove('active');
            }
        });
    }
    
    // Dropdown logout button
    const dropdownLogoutBtn = document.getElementById('dropdown-logout-btn');
    if (dropdownLogoutBtn) {
        dropdownLogoutBtn.addEventListener('click', logout);
    }

    // Encryption key (per-user zero-knowledge keypair) — available to all users.
    const encryptionKeyBtn = document.getElementById('encryption-key-btn');
    if (encryptionKeyBtn) {
        encryptionKeyBtn.addEventListener('click', () => {
            document.querySelector('.profile-menu')?.classList.remove('active');  // close dropdown
            openEncryptionKeyModal();
        });
    }
    const encryptionKeySetupBtn = document.getElementById('encryption-key-setup-btn');
    if (encryptionKeySetupBtn) {
        encryptionKeySetupBtn.addEventListener('click', setupEncryptionKey);
    }
    const encryptionKeyChangePassBtn = document.getElementById('encryption-key-change-passphrase-btn');
    if (encryptionKeyChangePassBtn) {
        encryptionKeyChangePassBtn.addEventListener('click', changeEncryptionPassphrase);
    }
    const encryptionKeyExportRecoveryBtn = document.getElementById('encryption-key-export-recovery-btn');
    if (encryptionKeyExportRecoveryBtn) {
        encryptionKeyExportRecoveryBtn.addEventListener('click', exportRecoveryKey);
    }
    const encryptionKeyRestoreBtn = document.getElementById('encryption-key-restore-btn');
    const encryptionKeyRestoreInput = document.getElementById('encryption-key-restore-input');
    if (encryptionKeyRestoreBtn && encryptionKeyRestoreInput) {
        encryptionKeyRestoreBtn.addEventListener('click', () => encryptionKeyRestoreInput.click());
        encryptionKeyRestoreInput.addEventListener('change', (e) => {
            const file = e.target.files && e.target.files[0];
            e.target.value = '';  // allow re-selecting the same file
            restoreFromRecoveryKeyFile(file);
        });
    }

    // Settings button — open the self-service "Your account" modal.
    const settingsBtn = document.getElementById('settings-btn');
    if (settingsBtn) {
        wireUserSettingsModal();
        settingsBtn.addEventListener('click', openUserSettingsModal);
    }
    
    // Sidebar navigation
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    if (sidebarToggle && sidebar) {
        // Restore sidebar state from localStorage
        const sidebarCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
        if (sidebarCollapsed) {
            sidebar.classList.add('collapsed');
        }
        
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
        });
    }
    
    // Sidebar item navigation
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.getAttribute('data-section');

            // Remember the section so a refresh restores it (and leaving a vault
            // this way correctly drops us back to that section, not inside it).
            saveNavState({ section });

            // Cleanup previous view before switching
            cleanupPreviousView(section);
            
            // Update active states
            document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            // Show corresponding content section
            document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
            const targetSection = document.getElementById(`${section}-section`);
            if (targetSection) {
                targetSection.classList.add('active');
                
                // Load data for specific sections
                if (section === 'vaults') {
                    loadVaults().catch(err => console.error('Failed to load vaults:', err));
                } else if (section === 'temp-creds') {
                    loadTempCreds().catch(err => console.error('Failed to load temp creds:', err));
                } else if (section === 'users') {
                    loadUsers().catch(err => console.error('Failed to load users:', err));
                } else if (section === 'groups') {
                    loadGroups().catch(err => console.error('Failed to load groups:', err));
                } else if (section === 'monitor') {
                    initMonitor();
                } else if (section === 'settings') {
                    initSettings();
                } else if (section === 'dashboard') {
                    loadDashboardStats();
                }
            }
        });
    });
    
    // Vault back button
    const vaultBackBtn = document.getElementById('vault-back-btn');
    if (vaultBackBtn) {
        vaultBackBtn.addEventListener('click', closeVault);
    }
    
    // Vault tab switching
    document.querySelectorAll('[data-vault-tab]').forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.getAttribute('data-vault-tab');
            
            // Update tab buttons
            document.querySelectorAll('[data-vault-tab]').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Update tab content (the panels are #vault-files-tab, #vault-info-tab, …)
            document.querySelectorAll('.vault-tab-content').forEach(content => content.classList.remove('active'));
            const panel = document.getElementById(`vault-${tabName}-tab`);
            if (panel) panel.classList.add('active');
            
            // Load tab data
            if (tabName === 'files') {
                loadVaultFiles();  // refresh in case it changed while on another tab
            } else if (tabName === 'info') {
                loadVaultInfo();
            } else if (tabName === 'permissions') {
                loadVaultPermissions();
            } else if (tabName === 'settings') {
                loadVaultSettings();
            }
        });
    });

    // Refresh the file list the moment the tab/window regains focus, so changes
    // made elsewhere show up immediately instead of waiting for the next poll.
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) refreshFilesIfChanged();
    });
    window.addEventListener('focus', () => refreshFilesIfChanged());
    
    // Upload file button
    const uploadFileBtn = document.getElementById('upload-file-btn');
    const fileUploadInput = document.getElementById('file-upload-input');
    if (uploadFileBtn && fileUploadInput) {
        uploadFileBtn.addEventListener('click', () => {
            fileUploadInput.click();
        });
        
        fileUploadInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                uploadFiles(e.target.files);
                // Reset input so same file can be uploaded again
                e.target.value = '';
            }
        });
    }
    
    // Close vault button (back to vaults list) — closeVault() handles state +
    // watcher cleanup + nav-state so a refresh lands on the list, not inside.
    const closeVaultBtn = document.getElementById('close-vault-btn');
    if (closeVaultBtn) {
        closeVaultBtn.addEventListener('click', closeVault);
    }
    
    // Create folder button
    const createFolderBtn = document.getElementById('create-folder-btn');
    if (createFolderBtn) {
        createFolderBtn.addEventListener('click', createFolder);
    }
    
    // Create vault button
    const createVaultBtn = document.getElementById('create-vault-btn');
    if (createVaultBtn) {
        createVaultBtn.addEventListener('click', showCreateVault);
    }
    
    // Generate temp creds button — opens the validity/expiry chooser modal
    const generateTempBtn = document.getElementById('generate-temp-creds-btn');
    if (generateTempBtn) {
        generateTempBtn.addEventListener('click', showGenerateTempCreds);
    }

    // Generate temp creds form submission
    const generateTempCredsForm = document.getElementById('generate-temp-creds-form');
    if (generateTempCredsForm) {
        generateTempCredsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            _tcHideError();  // clear any prior inline error at the start of each attempt

            const minutesInput = document.getElementById('temp-cred-validity-minutes');
            const endInput = document.getElementById('temp-cred-end-datetime');
            const MAX_MINUTES = 43200; // 30 days, must match the backend cap

            let validityMinutes = null;

            const endValue = endInput && endInput.value ? endInput.value : '';
            if (endValue) {
                // End date/time takes precedence — derive minutes from now.
                const endTime = new Date(endValue).getTime();
                if (isNaN(endTime)) {
                    _tcShowError('Please enter a valid end date and time.');
                    return;
                }
                validityMinutes = Math.ceil((endTime - Date.now()) / 60000);
                if (validityMinutes <= 0) {
                    _tcShowError('End date/time must be in the future.');
                    return;
                }
            } else if (minutesInput && minutesInput.value) {
                validityMinutes = parseInt(minutesInput.value, 10);
                if (isNaN(validityMinutes) || validityMinutes <= 0) {
                    _tcShowError('Validity must be a positive number of minutes.');
                    return;
                }
            }

            if (validityMinutes != null && validityMinutes > MAX_MINUTES) {
                _tcShowError('Maximum validity is 30 days (43200 minutes).');
                return;
            }

            const note = (document.getElementById('temp-cred-note')?.value || '').trim();
            const canCreate = !!(document.getElementById('temp-cred-can-create') && document.getElementById('temp-cred-can-create').checked);
            const scopeData = collectTempScope();
            // A credential scoped to the Vaults page but with no vaults selected can access
            // nothing — warn instead of silently minting a dead credential (mirrors the server
            // guard; keyed on the Vaults page, the only signal that governs selected-mode reach).
            if (scopeData && scopeData.vault_access_mode === 'selected'
                && scopeData.selected_vaults.length === 0
                && (scopeData.scope.pages || []).includes('vaults')) {
                _tcShowError("Select at least one vault, or switch to 'All vaults' — a credential scoped to vaults with none selected can't access anything.");
                return;
            }
            // Do NOT close here — generateTempCreds closes the modal only on success, and keeps it
            // open (with an inline error) on a recoverable failure so entered state isn't lost.
            generateTempCreds({
                validity_minutes: validityMinutes, note, can_create_temp_credentials: canCreate,
                scope: scopeData ? scopeData.scope : null,
                vault_access_mode: scopeData ? scopeData.vault_access_mode : null,
                selected_vaults: scopeData ? scopeData.selected_vaults : null,
            });
        });
    }
    
    // Create user button
    const createUserBtn = document.getElementById('create-user-btn');
    if (createUserBtn) {
        createUserBtn.addEventListener('click', showCreateUser);
    }
    
    // Close modal buttons
    document.querySelectorAll('.close-modal-btn').forEach(btn => {
        btn.addEventListener('click', closeModal);
    });
    
    // Copy to clipboard buttons
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const target = e.currentTarget.getAttribute('data-target');
            if (target) {
                copyToClipboard(target);
            }
        });
    });
    
    // Edit user form submission
    const editUserForm = document.getElementById('edit-user-form');
    if (editUserForm) {
        editUserForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const userId = document.getElementById('edit-user-id').value;
            const email = document.getElementById('edit-user-email').value;
            const role = document.getElementById('edit-user-role').value;
            const isActive = document.getElementById('edit-user-active').checked;
            
            try {
                await apiRequest(`/users/${userId}`, {
                    method: 'PATCH',
                    body: JSON.stringify({
                        email,
                        role,
                        is_active: isActive
                    })
                });

                showSuccess('User updated successfully');
                closeModal();
                loadUsers();
            } catch (error) {
                showError('Failed to update user: ' + error.message);
            }
        });
    }
    
    // Change password form submission
    const changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const userId = document.getElementById('change-password-user-id').value;
            const newPassword = document.getElementById('change-password-new').value;
            const confirmPassword = document.getElementById('change-password-confirm').value;

            // Validate passwords match
            if (newPassword !== confirmPassword) {
                showError('Passwords do not match!');
                return;
            }

            // Validate minimum length
            if (newPassword.length < 12) {
                showError('Password must be at least 12 characters long');
                return;
            }

            try {
                await apiRequest(`/users/${userId}`, {
                    method: 'PATCH',
                    body: JSON.stringify({ password: newPassword })
                });

                showSuccess('Password changed successfully');
                closeModal();
                changePasswordForm.reset();
            } catch (error) {
                showError('Failed to change password: ' + error.message);
            }
        });
    }

    // Vault settings form submissions
    const editVaultInfoForm = document.getElementById('edit-vault-info-form');
    if (editVaultInfoForm) {
        editVaultInfoForm.addEventListener('submit', handleEditVaultInfo);
    }

    const changeVaultPasswordForm = document.getElementById('change-vault-password-form');
    if (changeVaultPasswordForm) {
        changeVaultPasswordForm.addEventListener('submit', handleChangeVaultPassword);
    }

    const setExpiryForm = document.getElementById('set-expiry-form');
    if (setExpiryForm) {
        setExpiryForm.addEventListener('submit', handleSetExpiry);
    }

    const addPermissionForm = document.getElementById('add-permission-form');
    if (addPermissionForm) {
        addPermissionForm.addEventListener('submit', handleAddPermission);
    }

    // ---- Users table: search/filter toolbar + expandable rows ----------------
    ['users-search', 'users-role-filter', 'users-group-filter', 'users-status-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            const evt = el.tagName === 'SELECT' ? 'change' : 'input';
            el.addEventListener(evt, () => renderUsersTable());
        }
    });
    const usersListEl = document.getElementById('users-list');
    if (usersListEl) {
        usersListEl.addEventListener('click', (e) => {
            const removeBtn = e.target.closest('.chip-remove');
            if (removeBtn) {
                e.preventDefault();
                removeUserFromGroup(removeBtn.dataset.userId, removeBtn.dataset.groupId);
                return;
            }
            const addKeyBtn = e.target.closest('.ssh-key-add-btn');
            if (addKeyBtn) {
                e.preventDefault();
                addSshKey(addKeyBtn.dataset.userId);
                return;
            }
            // Clicks inside the expanded detail (toggles, inputs, SSH-key rows)
            // must not collapse the row; only the summary .exp-row toggles.
            if (e.target.closest('.exp-detail')) return;
            const row = e.target.closest('.exp-row');
            if (row && usersListEl.contains(row)) toggleUserRow(row.dataset.id);
        });
        usersListEl.addEventListener('change', (e) => {
            const sftpToggle = e.target.closest('.sftp-access-toggle');
            if (sftpToggle) {
                updateUserSftp(sftpToggle.dataset.userId, sftpToggle.dataset.field, sftpToggle.checked, sftpToggle);
                return;
            }
            const sel = e.target.closest('.add-group-select');
            if (sel && sel.value) addUserToGroup(sel.dataset.userId, sel.value);
        });
    }

    // ---- Temp credentials: expandable rows + filter + bulk ops ---------------
    const tempCredsEl = document.getElementById('active-temp-creds');
    if (tempCredsEl) {
        tempCredsEl.addEventListener('click', (e) => {
            const row = e.target.closest('.exp-row');
            if (row && tempCredsEl.contains(row)) toggleTempCredRow(row.dataset.id);
        });
    }
    const tcFilter = document.getElementById('tc-status-filter');
    if (tcFilter) tcFilter.addEventListener('change', () => { tempCredsLimit = 50; renderTempCreds(); });
    const tcCleanupBtn = document.getElementById('tc-cleanup-btn');
    const tcCleanupMenu = document.getElementById('tc-cleanup-menu');
    if (tcCleanupBtn && tcCleanupMenu) {
        tcCleanupBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            tcCleanupMenu.hidden = !tcCleanupMenu.hidden;
            tcCleanupBtn.classList.toggle('open', !tcCleanupMenu.hidden);
        });
        tcCleanupMenu.addEventListener('click', (e) => {
            const b = e.target.closest('[data-clean]');
            if (b) { tcCleanupMenu.hidden = true; tcCleanupBtn.classList.remove('open'); cleanupTempCreds(b.dataset.clean); }
        });
        document.addEventListener('click', () => { tcCleanupMenu.hidden = true; tcCleanupBtn.classList.remove('open'); });
    }
    const tcInvalidateBtn = document.getElementById('tc-invalidate-btn');
    if (tcInvalidateBtn) tcInvalidateBtn.addEventListener('click', invalidateAllActive);

    // ---- Groups & Roles: tree navigation + create/edit group -----------------
    const groupsTreeEl = document.getElementById('groups-tree');
    if (groupsTreeEl) {
        groupsTreeEl.addEventListener('click', (e) => {
            const node = e.target.closest('.tree-node');
            if (node) openGroupDetail(node.dataset.groupId);
        });
    }
    const createGroupBtn = document.getElementById('create-group-btn');
    if (createGroupBtn) {
        createGroupBtn.addEventListener('click', () => openGroupModal(null));
    }
    const groupForm = document.getElementById('group-form');
    if (groupForm) {
        groupForm.addEventListener('submit', submitGroupForm);
    }
    const groupColorSwatches = document.getElementById('group-color-swatches');
    if (groupColorSwatches) {
        groupColorSwatches.addEventListener('click', (e) => {
            const sw = e.target.closest('.accent-swatch');
            if (sw) {
                e.preventDefault();
                setGroupColor(sw.getAttribute('data-color') || '');
            }
        });
    }
    const groupColorCustom = document.getElementById('group-color-custom');
    if (groupColorCustom) {
        groupColorCustom.addEventListener('input', () => setGroupColor(groupColorCustom.value));
    }
    // Searchable "Add members" modal
    const addMembersSearch = document.getElementById('add-members-search');
    if (addMembersSearch) addMembersSearch.addEventListener('input', () => renderAddMembersList(addMembersSearch.value));
    const addMembersListEl = document.getElementById('add-members-list');
    if (addMembersListEl) addMembersListEl.addEventListener('change', updateAddMembersCount);
    const addMembersConfirm = document.getElementById('add-members-confirm');
    if (addMembersConfirm) addMembersConfirm.addEventListener('click', confirmAddMembers);

    // Searchable "Grant vault access" modal
    const vgSearch = document.getElementById('vault-grant-search');
    if (vgSearch) vgSearch.addEventListener('input', onVaultGrantSearchInput);
    const vgList = document.getElementById('vault-grant-list');
    if (vgList) vgList.addEventListener('change', updateVaultGrantCount);
    const vgConfirm = document.getElementById('vault-grant-confirm');
    if (vgConfirm) vgConfirm.addEventListener('click', confirmVaultGrant);

    // Close modal when clicking outside
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal();
            }
        });
    });
});
