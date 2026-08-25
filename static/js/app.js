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
    // in the vault. NOTE: this is a Standard-vault ACCESS password, not a
    // zero-knowledge secret -- it IS sent to the server (as the X-Vault-Password
    // header) to unlock the vault on each request, and it is held here in the
    // clear, so sessionStorage is trusted. Exposure is bounded by the unlock
    // window, the per-user opt-out, and the admin org floor, and it is wiped on
    // logout.
    rememberedVaults: {},
    // Per-user preference: when on, the browser never remembers a vault password (always re-ask),
    // regardless of the vault's unlock window. Loaded from server preferences on boot.
    neverRememberVaultPassword: false,
    // Deployment-wide org floor (admin-set): when on, remembering is forbidden for everyone and the
    // per-user toggle is shown forced-on. Mirrors the server-side unlock_remember_minutes clamp.
    forceNoRememberVaultPassword: false,
    rememberVaultPassword(vaultId, password, minutes) {
        // The deployment-wide org floor and the per-user opt-out both forbid remembering — a
        // stale/local unlock window from any call site can't override either.
        if (this.forceNoRememberVaultPassword || this.neverRememberVaultPassword) { delete this.rememberedVaults[vaultId]; this._persistRemembered(); return; }
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
    vaultFilter: 'all',
    // Vaults-list ordering. Hydrated from the account's saved preferences on login (falling back
    // to localStorage), so it follows the user across browsers — see applyVaultOrderPrefs.
    vaultSort: null,        // 'name' | 'size' | 'files' | 'created' | 'viewed'
    vaultSortDir: null,     // 'asc' | 'desc'
    vaultFavGroup: null,    // 'first' | 'last' | 'mixed'
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
const TEMP_FORBIDDEN_SECTIONS = ['users', 'groups', 'settings', 'monitor', 'roles', 'notes'];
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

    // Invite User — same admin surface, additionally gated on the org policy switch. `=== true`
    // fails closed while currentSettings is unpopulated (it rides admin-only GET /settings).
    setBtn(document.getElementById('invite-user-btn'),
           !scoped && hasPermission('USER_MANAGE') && currentSettings.invite_enabled === true);

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
        <button class="toast-close" type="button">×</button>
    `;

    // Wire the close button programmatically — an inline onclick= attribute is blocked by the
    // page CSP (script-src 'self', no unsafe-inline), which both spammed the console and left the
    // × dead. Remove the whole toast, matching the old this.parentElement.remove().
    const closeBtn = toast.querySelector('.toast-close');
    if (closeBtn) closeBtn.addEventListener('click', () => toast.remove());

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
            // Clear here too, not only in the branch that asks for typed input. This is the branch
            // a plain confirm takes, and it is what would otherwise carry a passphrase left by an
            // earlier prompt through any number of later dialogs.
            inputEl.value = '';
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
            // Clear here as well as in showPrompt, so "the field is empty once a dialog closes"
            // holds for both primitives rather than one. Today's requireInput callers pass a
            // username to type back, not a secret — but the two functions share one input, and an
            // invariant that holds only on alternate paths is one refactor from not holding.
            inputEl.value = '';
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
        // This one <input> is reused for every prompt, including the ZK master passphrase. Mark a
        // password prompt as a one-time code so password managers don't offer to SAVE/autofill the
        // master passphrase; reset for a plain text prompt. Set every attribute per-use (symmetric,
        // both branches) so nothing leaks from a prior prompt.
        inputEl.setAttribute('autocomplete', password ? 'one-time-code' : 'off');
        inputEl.setAttribute('autocapitalize', 'off');
        inputEl.setAttribute('autocorrect', 'off');
        inputEl.setAttribute('spellcheck', password ? 'false' : 'true');
        inputEl.placeholder = placeholder || '';
        inputEl.value = defaultValue || '';
        confirmBtn.disabled = false;

        modal.classList.add('active');
        setTimeout(() => inputEl.focus(), 50);

        const cleanup = () => {
            modal.classList.remove('active');
            // Clear before anything else. This one input is reused by every prompt, including the
            // zero-knowledge master passphrase — the value the interface itself calls unrecoverable
            // and the only key to every zero-knowledge vault. Hiding the field does not remove its
            // value, so without this the passphrase stays readable in the page as the value of a
            // hidden text input, and survives until some later dialog happens to overwrite it. A
            // plain confirm does not, so that can be an arbitrarily long time.
            inputEl.value = '';
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
            // Read text first so an EMPTY body (e.g. 204 No Content on a DELETE) yields null
            // instead of throwing "Unexpected end of JSON input".
            const raw = await response.text();
            data = raw ? JSON.parse(raw) : null;
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

    // Settle the dashboard's admin-only content in the same synchronous pass, for the same
    // reason. Both login paths call this before the dashboard screen is revealed, so the card
    // is already in its final state on the first paint rather than appearing and vanishing
    // when loadDashboardStats() later resolves.
    applyDashboardAdminGating();
}

// Label the identifier field to match the org's login policy. The login page is pre-auth and
// cannot read the admin-only /settings, so a tiny public endpoint exposes only which identifier
// to ask for. textContent only (no innerHTML — house XSS rule); the value comes from a fixed
// vocabulary regardless. Not cached: the policy can be flipped by an admin, and a stale label
// would mislabel the form. On any failure the static "Username" fallback stays.
async function applyLoginPolicyLabel() {
    try {
        const res = await fetch(`${API_BASE}/auth/policy`, { headers: { Accept: 'application/json' } });
        if (!res.ok) return;
        const policy = await res.json();
        const mode = policy.login_identifier;
        const label = document.getElementById('username-label');
        const input = document.getElementById('username');
        if (input) {
            if (mode === 'email') {
                if (label) label.textContent = 'Email';
                input.setAttribute('autocomplete', 'email');
                input.setAttribute('inputmode', 'email');
            } else if (mode === 'either') {
                if (label) label.textContent = 'Username or email';
                input.setAttribute('autocomplete', 'username');
                input.removeAttribute('inputmode');
            } else {
                if (label) label.textContent = 'Username';
                input.setAttribute('autocomplete', 'username');
                input.removeAttribute('inputmode');
            }
        }
        _initSignupAffordance(policy);
        _initForgotAffordance(policy);
    } catch (_) { /* keep the static fallback */ }
}
applyLoginPolicyLabel();

// ---- Forgot password (public self-service; the link shows only when the org enabled it) ----------
let _forgotWired = false;

function _initForgotAffordance(policy) {
    const toggle = document.getElementById('forgot-toggle');
    const form = document.getElementById('forgot-form');
    if (!toggle || !form) return;
    if (!policy || !policy.password_reset_enabled) { toggle.style.display = 'none'; form.style.display = 'none'; return; }
    toggle.style.display = '';
    if (_forgotWired) return;
    _forgotWired = true;
    const showLink = document.getElementById('show-forgot-link');
    const backLink = document.getElementById('forgot-back-link');
    const loginForm = document.getElementById('login-form');
    const msg = document.getElementById('forgot-message');
    const showForgot = (on) => {
        form.style.display = on ? '' : 'none';
        if (loginForm) loginForm.style.display = on ? 'none' : '';
        toggle.style.display = on ? 'none' : '';
        if (msg) { msg.style.display = 'none'; msg.textContent = ''; }
    };
    if (showLink) showLink.addEventListener('click', (e) => {
        e.preventDefault(); showForgot(true);
        const i = document.getElementById('forgot-identifier'); if (i) i.focus();
    });
    if (backLink) backLink.addEventListener('click', (e) => { e.preventDefault(); showForgot(false); });
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const ident = ((document.getElementById('forgot-identifier') || {}).value || '').trim();
        const btn = form.querySelector('button[type=submit]');
        if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
        try {
            await fetch(`${API_BASE}/auth/forgot-password`, {
                method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({ identifier: ident }) });
        } catch (_) { /* enumeration-safe: show the same message regardless */ }
        if (msg) { msg.textContent = 'If an account matches, a reset link has been sent to its email.'; msg.style.display = 'block'; }
        if (btn) { btn.disabled = false; btn.textContent = 'Send reset link'; }
    });
}

// ---- Self-signup (public, unauthenticated) --------------------------------
// The toggle + form are hidden until /auth/policy confirms signup_enabled. Email presence/required
// is driven by the same policy: the field is always PRESENT (so an optional address can be given),
// and `required` when the org requires email OR login is by email/either (an account with no email
// could never sign in under those identifiers). Bare fetch only; DOM values via textContent (house
// XSS rule); no token is stored — success returns to the sign-in form (it does NOT auto-sign-in).
let _signupWired = false;

function _initSignupAffordance(policy) {
    const toggle = document.getElementById('signup-toggle');
    const form = document.getElementById('signup-form');
    if (!toggle || !form) return;
    if (!policy || !policy.signup_enabled) {           // off → stay hidden, offer nothing
        toggle.style.display = 'none';
        form.style.display = 'none';
        return;
    }
    toggle.style.display = '';

    // Email field state per policy.
    const emailRequired = policy.email_requirement === 'required'
        || policy.login_identifier === 'email' || policy.login_identifier === 'either';
    const emailGroup = document.getElementById('signup-email-group');
    const emailInput = document.getElementById('signup-email');
    const emailLabel = document.getElementById('signup-email-label');
    if (emailGroup) emailGroup.style.display = '';       // present in both required/optional shapes
    if (emailInput) emailInput.required = emailRequired;
    if (emailLabel) emailLabel.textContent = emailRequired ? 'Email' : 'Email (optional)';

    // Password requirement hints, mirroring the enforced policy.
    const pol = policy.password_policy || {};
    const hint = document.getElementById('signup-password-hint');
    if (hint) {
        const parts = [];
        if (pol.min_length) parts.push(`at least ${pol.min_length} characters`);
        if (pol.require_uppercase) parts.push('an uppercase letter');
        if (pol.require_lowercase) parts.push('a lowercase letter');
        if (pol.require_numbers) parts.push('a number');
        if (pol.require_special) parts.push('a special character');
        hint.textContent = parts.length ? 'Must include ' + parts.join(', ') + '.' : '';
    }
    const pwInput = document.getElementById('signup-password');
    if (pwInput && pol.min_length) pwInput.minLength = pol.min_length;

    if (_signupWired) return;                            // attach listeners once
    _signupWired = true;
    const showSignup = document.getElementById('show-signup-link');
    const showLogin = document.getElementById('show-login-link');
    if (showSignup) showSignup.addEventListener('click', (e) => { e.preventDefault(); _showSignupForm(true); });
    if (showLogin) showLogin.addEventListener('click', (e) => { e.preventDefault(); _showSignupForm(false); });
    form.addEventListener('submit', _submitSignup);
}

function _showSignupForm(show) {
    const ids = ['login-form', 'login-error', 'signup-toggle'];
    ids.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = show ? 'none' : (id === 'login-error' ? 'none' : ''); });
    const form = document.getElementById('signup-form');
    if (form) form.style.display = show ? '' : 'none';
    // Clear any stale signup error so it never re-appears on a later reopen of the form.
    const serr = document.getElementById('signup-error');
    if (serr) { serr.textContent = ''; serr.style.display = 'none'; }
    if (show) { const u = document.getElementById('signup-username'); if (u) u.focus(); }
    else { const u = document.getElementById('username'); if (u) u.focus(); }
}

async function _submitSignup(e) {
    e.preventDefault();
    const err = document.getElementById('signup-error');
    const btn = e.target.querySelector('button[type="submit"]');
    const uname = (document.getElementById('signup-username') || {}).value || '';
    const emailInput = document.getElementById('signup-email');
    const pw = (document.getElementById('signup-password') || {}).value || '';
    if (err) err.style.display = 'none';
    if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }
    const restore = () => { if (btn) { btn.disabled = false; btn.textContent = 'Create account'; } };
    try {
        const payload = { username: uname.trim(), password: pw };
        const emailVal = emailInput ? emailInput.value.trim() : '';
        if (emailVal) payload.email = emailVal;
        const res = await fetch(`${API_BASE}/auth/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            const data = await res.json().catch(() => ({}));
            if (err) {
                err.textContent = (data && data.detail) ? data.detail : 'Could not create the account. Please try again.';
                err.style.display = 'block';
            }
            restore();
            return;
        }
        _signupSucceeded(uname.trim());
    } catch (_) {
        if (err) { err.textContent = 'Could not create the account. Please try again.'; err.style.display = 'block'; }
        restore();
    }
}

function _signupSucceeded(username) {
    const form = document.getElementById('signup-form');
    if (form) form.style.display = 'none';
    const login = document.getElementById('login-form');
    if (login) login.style.display = '';
    const toggle = document.getElementById('signup-toggle');
    if (toggle) toggle.style.display = '';
    // Prefill the username and surface a success note in the login error box (reused as a banner).
    const u = document.getElementById('username');
    if (u && username) u.value = username;
    const note = document.getElementById('login-error');
    if (note) {
        note.className = 'alert alert-success mt-md';
        note.textContent = 'Account created. Sign in with your new password.';
        note.style.display = 'block';
    }
    const pw = document.getElementById('password');
    if (pw) pw.focus();
}

// ---- Invitation acceptance (public, unauthenticated) -----------------------
// Reached via /?invite=<token>. Bare fetch only (never apiRequest — it would attach a stale Bearer
// token to an unauth endpoint); DOM built with _el/textContent (no innerHTML); no token is ever
// stored (success routes to the login screen, it does NOT sign the visitor in). Every failure shows
// ONE generic message so the page can't be used to probe which tokens are valid.
const _INVITE_GENERIC_ERROR = 'This invitation link is invalid or has expired.';

function _inviteCard() {
    return document.getElementById('invite-card-body');
}

function _inviteMessage(text, kind) {
    const body = _inviteCard();
    if (!body) return;
    body.replaceChildren();
    body.appendChild(_el('div', 'alert alert-' + (kind || 'error'), text));
}

async function initInviteFlow(token) {
    showScreen('invite-screen');
    let info;
    try {
        const res = await fetch(`${API_BASE}/invites/${encodeURIComponent(token)}`,
                                { headers: { Accept: 'application/json' } });
        if (!res.ok) { _inviteMessage(_INVITE_GENERIC_ERROR); return; }
        info = await res.json();
    } catch (_) {
        _inviteMessage(_INVITE_GENERIC_ERROR);
        return;
    }
    _renderInviteForm(token, info);
}

function _renderInviteForm(token, info) {
    const body = _inviteCard();
    if (!body) return;
    body.replaceChildren();
    body.appendChild(_el('h2', 'text-xl font-bold mb-sm', 'Accept your invitation'));
    const sub = _el('p', 'text-secondary mb-lg');
    sub.appendChild(document.createTextNode('You are claiming the username '));
    sub.appendChild(_el('strong', null, info.username || ''));
    sub.appendChild(document.createTextNode('. Set a password to finish.'));
    body.appendChild(sub);

    const form = _el('form');
    // email only when the org requires one and the invite didn't carry it
    let emailInput = null;
    if (info.email_required) {
        const g = _el('div', 'form-group');
        g.appendChild(_el('label', null, 'Email'));
        emailInput = _el('input', 'form-control');
        emailInput.type = 'email';
        emailInput.required = true;
        emailInput.setAttribute('autocomplete', 'email');
        g.appendChild(emailInput);
        form.appendChild(g);
    }
    const pg = _el('div', 'form-group');
    pg.appendChild(_el('label', null, 'Password'));
    const pw = _el('input', 'form-control');
    pw.type = 'password';
    pw.required = true;
    pw.setAttribute('autocomplete', 'new-password');
    const pol = info.password_policy || {};
    if (pol.min_length) pw.minLength = pol.min_length;
    pg.appendChild(pw);
    // requirement hints, mirroring the enforced policy
    const hints = [];
    if (pol.min_length) hints.push(`at least ${pol.min_length} characters`);
    if (pol.require_uppercase) hints.push('an uppercase letter');
    if (pol.require_lowercase) hints.push('a lowercase letter');
    if (pol.require_numbers) hints.push('a number');
    if (pol.require_special) hints.push('a special character');
    if (hints.length) pg.appendChild(_el('small', 'form-help', 'Must include ' + hints.join(', ') + '.'));
    form.appendChild(pg);

    const err = _el('div', 'alert alert-error mt-md');
    err.style.display = 'none';
    form.appendChild(err);

    const btn = _el('button', 'btn btn-primary btn-block', 'Create account');
    btn.type = 'submit';
    form.appendChild(btn);

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        err.style.display = 'none';
        btn.disabled = true;
        btn.textContent = 'Creating…';
        try {
            const payload = { password: pw.value };
            if (emailInput) payload.email = emailInput.value.trim();
            const res = await fetch(`${API_BASE}/invites/${encodeURIComponent(token)}/accept`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                err.textContent = data.detail || _INVITE_GENERIC_ERROR;
                err.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Create account';
                return;
            }
            _inviteAccepted(info.username);
        } catch (_) {
            err.textContent = _INVITE_GENERIC_ERROR;
            err.style.display = 'block';
            btn.disabled = false;
            btn.textContent = 'Create account';
        }
    });
    body.appendChild(form);
    if (emailInput) emailInput.focus(); else pw.focus();
}

function _inviteAccepted(username) {
    // Strip the token from the URL so a reload of a now-consumed link doesn't show "invalid",
    // release the invite screen gate, and route to login — the visitor is NOT auto-signed-in.
    try { history.replaceState(null, '', location.pathname); } catch (_) {}
    document.documentElement.removeAttribute('data-invite');
    const body = _inviteCard();
    if (body) {
        body.replaceChildren();
        body.appendChild(_el('h2', 'text-xl font-bold mb-sm', 'Account created'));
        body.appendChild(_el('p', 'text-secondary mb-lg',
            'Your account is ready. Sign in with your new password to continue.'));
        const go = _el('button', 'btn btn-primary btn-block', 'Go to sign in');
        go.addEventListener('click', () => showScreen('login-screen'));
        body.appendChild(go);
    }
    setTimeout(() => { showScreen('login-screen'); }, 2500);
}

// Reached via /?reset=<token>. Bare fetch only; DOM built with _el/textContent; every failure shows
// ONE generic message so the page can't probe which tokens are valid; success does NOT sign the
// visitor in — it routes to login.
const _RESET_GENERIC_ERROR = 'This reset link is invalid or has expired.';

function _resetCard() { return document.getElementById('reset-card-body'); }

function _resetMessage(text, kind) {
    const body = _resetCard(); if (!body) return;
    body.replaceChildren(); body.appendChild(_el('div', 'alert alert-' + (kind || 'error'), text));
}

async function initResetFlow(token) {
    showScreen('reset-screen');
    let info;
    try {
        const res = await fetch(`${API_BASE}/reset/${encodeURIComponent(token)}`, { headers: { Accept: 'application/json' } });
        if (!res.ok) { _resetMessage(_RESET_GENERIC_ERROR); return; }
        info = await res.json();
    } catch (_) { _resetMessage(_RESET_GENERIC_ERROR); return; }
    _renderResetForm(token, info);
}

function _renderResetForm(token, info) {
    const body = _resetCard(); if (!body) return;
    body.replaceChildren();
    body.appendChild(_el('h2', 'text-xl font-bold mb-sm', 'Set a new password'));
    const sub = _el('p', 'text-secondary mb-lg');
    if (info && info.username) {
        sub.appendChild(document.createTextNode('For the account '));
        sub.appendChild(_el('strong', null, info.username));
        sub.appendChild(document.createTextNode('.'));
    } else { sub.textContent = 'Choose a new password to finish.'; }
    body.appendChild(sub);

    const form = _el('form');
    const pg = _el('div', 'form-group');
    pg.appendChild(_el('label', null, 'New password'));
    const pw = _el('input', 'form-control'); pw.type = 'password'; pw.required = true;
    pw.setAttribute('autocomplete', 'new-password');
    pg.appendChild(pw); form.appendChild(pg);
    const err = _el('div', 'alert alert-error mt-md'); err.style.display = 'none'; form.appendChild(err);
    const btn = _el('button', 'btn btn-primary btn-block', 'Set password'); btn.type = 'submit'; form.appendChild(btn);
    form.addEventListener('submit', async (e) => {
        e.preventDefault(); err.style.display = 'none'; btn.disabled = true; btn.textContent = 'Saving…';
        try {
            const res = await fetch(`${API_BASE}/reset/${encodeURIComponent(token)}`, {
                method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify({ new_password: pw.value }) });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                err.textContent = data.detail || _RESET_GENERIC_ERROR; err.style.display = 'block';
                btn.disabled = false; btn.textContent = 'Set password'; return;
            }
            _resetDone();
        } catch (_) {
            err.textContent = _RESET_GENERIC_ERROR; err.style.display = 'block';
            btn.disabled = false; btn.textContent = 'Set password';
        }
    });
    body.appendChild(form); pw.focus();
}

function _resetDone() {
    try { history.replaceState(null, '', location.pathname); } catch (_) {}
    document.documentElement.removeAttribute('data-reset');
    const body = _resetCard();
    if (body) {
        body.replaceChildren();
        body.appendChild(_el('h2', 'text-xl font-bold mb-sm', 'Password updated'));
        body.appendChild(_el('p', 'text-secondary mb-lg',
            'Your password has been changed. Sign in with your new password to continue.'));
        const go = _el('button', 'btn btn-primary btn-block', 'Go to sign in');
        go.addEventListener('click', () => showScreen('login-screen'));
        body.appendChild(go);
    }
    setTimeout(() => { showScreen('login-screen'); }, 2500);
}

// Login
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('login-error');

    // Hide previous errors. Reset the class too: self-signup success reuses this box as a green
    // success banner (alert-success), so restore alert-error before a login failure renders here.
    errorDiv.style.display = 'none';
    errorDiv.className = 'alert alert-error mt-md';

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

        // The credentials have been accepted and are no longer needed. Without this the account
        // password sits in the login field for the whole session — every session, every user, no
        // user action required — on a screen that is merely deactivated rather than unloaded.
        // logout() already resets this form; this closes the window from the other end.
        const loginForm = document.getElementById('login-form');
        if (loginForm) loginForm.reset();

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

        // Load the notification bell (persistent counterpart to the live temp-login toast)
        initNotifications();

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

    // Drop the Live Monitor feed + backfill state. The feed is now kept across section re-entry
    // ("keep old results"), so it MUST be scrubbed here or the previous user's live activity — and
    // the admin-only /audit/log history it may have backfilled (usernames, IPs, vault names) —
    // would show to the NEXT user who logs in on this same tab (no page refresh). Re-arming
    // monitorHistoryLoaded makes the next user's backfill run fresh under THEIR own permissions;
    // cleanupMonitor closes this session's socket (the next initMonitor reconnects with the new
    // token). monitorListenersAttached is intentionally left set — the filter/clear/reconnect DOM
    // nodes are static and survive the SPA screen swap, so re-attaching would duplicate handlers.
    monitorEvents = [];
    monitorMetrics.totalEvents = 0;
    monitorHistoryLoaded = false;
    cleanupMonitor();

    // Wipe the notification bell so a prior user's notifications never show to the next user on this
    // same tab, and stop the unread-count poll.
    resetNotifications();

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
    // Dismiss any dialog still standing, and empty what it was holding.
    //
    // showScreen only swaps `.screen` elements; a modal is not one, so a dialog open at logout is
    // never dismissed and its cleanup never runs. That matters most for the longest-lived dialog
    // in the app: the zero-knowledge unlock prompt. A session can expire from a background poll
    // while the user has typed their master passphrase and not yet submitted, and the login screen
    // would then appear with that passphrase still in the page — which is exactly the shared-tab
    // hand-off this function's own storage scrub exists to prevent.
    closeModal();
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
        
        // Personal lanes (shown to every account). The vault list is already in hand; pull the
        // shared-with-me list too (silent — the endpoint is fine for any account). Notifications
        // come from the global bell state loaded at login. A failure here must not blank the rest
        // of the dashboard, so it is caught inside renderDashboardLanes.
        let sharedWithMe = [];
        try {
            sharedWithMe = await apiRequest('/shares/shared-with-me', { silent: true }) || [];
        } catch (error) {
            console.log('Shared-with-me not available:', error);
        }
        renderDashboardLanes(vaults, sharedWithMe);

        // Update system status (the gating also runs at profile-render time, before first paint;
        // repeating it here keeps the card correct if the dashboard is re-entered later.)
        applyDashboardAdminGating();
        updateSystemStatus();

    } catch (error) {
        console.error('Failed to load dashboard stats:', error);
    }
}

// ---- Dashboard personal lanes ----------------------------------------------------------------
// Three at-a-glance lists for the signed-in account: what has been shared with you and still needs
// action, your favourite vaults, and the vaults you opened most recently. All rows are built with
// createElement + textContent (via _el), so a vault name or another user's name is never HTML.
// Notes join these lanes when the Notes feature ships.
const _DASHBOARD_LANE_LIMIT = 6;

function renderDashboardLanes(vaults, sharedWithMe) {
    try {
        const list = Array.isArray(vaults) ? vaults.slice() : [];
        // Last-opened first; a vault never opened (no last_viewed_at) sorts to the end.
        const byViewed = (a, b) => {
            const ta = parseServerTime(a.last_viewed_at);
            const tb = parseServerTime(b.last_viewed_at);
            return (tb ? tb.getTime() : 0) - (ta ? ta.getTime() : 0);
        };
        const favourites = list.filter(v => v.is_favorite).sort(byViewed);
        const recent = list.filter(v => !v.is_favorite).sort(byViewed).slice(0, _DASHBOARD_LANE_LIMIT);

        _fillLane('lane-favourites', favourites.slice(0, _DASHBOARD_LANE_LIMIT).map(_laneVaultRow),
                  'No favourites yet. Tap the star on a vault to pin it here.');
        _fillLane('lane-recent', recent.map(_laneVaultRow),
                  'Vaults you open will show up here.');
        renderWaitingLane(sharedWithMe);
    } catch (error) {
        console.error('Failed to render dashboard lanes:', error);
    }
}

// "What's waiting for you": unread notifications (who shared with you), then any items pushed to you
// that still need claiming, then items already shared with you that you can open — capped together.
function renderWaitingLane(sharedWithMe) {
    const rows = [];
    const unread = (typeof notifItems !== 'undefined' && Array.isArray(notifItems))
        ? notifItems.filter(n => !n.is_read) : [];
    unread.slice(0, _DASHBOARD_LANE_LIMIT).forEach(n => rows.push(_laneNotifRow(n)));

    const shared = Array.isArray(sharedWithMe) ? sharedWithMe : [];
    const remaining = () => _DASHBOARD_LANE_LIMIT - rows.length;
    if (remaining() > 0) {
        shared.filter(s => s.status === 'available').slice(0, remaining())
              .forEach(s => rows.push(_laneSharedRow(s)));
    }
    if (remaining() > 0) {
        shared.filter(s => s.status === 'active').slice(0, remaining())
              .forEach(s => rows.push(_laneSharedRow(s)));
    }
    _fillLane('lane-waiting', rows, "You're all caught up.");
}

function _fillLane(id, rows, emptyText) {
    const box = document.getElementById(id);
    if (!box) return;
    if (!rows.length) { box.replaceChildren(_laneEmpty(emptyText)); return; }
    box.replaceChildren(...rows);
}

function _laneEmpty(text) {
    return _el('p', 'dashboard-lane-empty text-secondary', text);
}

// A clickable vault row (favourites / most-recent lanes) — opens the vault browser.
function _laneVaultRow(v) {
    const row = _el('button', 'dashboard-lane-item');
    row.type = 'button';
    const icon = _el('span', 'dashboard-lane-icon');
    icon.appendChild(_svgIcon('vault', 'icon-sm'));
    row.appendChild(icon);
    const main = _el('div', 'dashboard-lane-main');
    main.appendChild(_el('div', 'dashboard-lane-title', v.name || 'Vault'));
    const t = parseServerTime(v.last_viewed_at);
    main.appendChild(_el('div', 'dashboard-lane-sub text-secondary',
        t ? ('Last opened ' + formatTimeAgo(v.last_viewed_at)) : 'Not opened yet'));
    row.appendChild(main);
    row.addEventListener('click', () => openVault(v.id));
    return row;
}

// A notification row — opens the target section (mirrors the bell panel's onNotifClick).
function _laneNotifRow(n) {
    const row = _el('button', 'dashboard-lane-item' + (n.is_read ? '' : ' unread'));
    row.type = 'button';
    const icon = _el('span', 'dashboard-lane-icon');
    icon.appendChild(_svgIcon('bell', 'icon-sm'));
    row.appendChild(icon);
    const main = _el('div', 'dashboard-lane-main');
    main.appendChild(_el('div', 'dashboard-lane-title', n.title || ''));
    if (n.body) main.appendChild(_el('div', 'dashboard-lane-sub text-secondary', n.body));
    row.appendChild(main);
    row.addEventListener('click', () => onNotifClick(n));
    return row;
}

// A shared-with-me row — Open (active) or lands you in the Shared section to claim (available).
function _laneSharedRow(s) {
    const row = _el('button', 'dashboard-lane-item');
    row.type = 'button';
    const icon = _el('span', 'dashboard-lane-icon');
    icon.appendChild(_svgIcon(s.target_type === 'file' ? 'file' : (s.target_type === 'folder' ? 'folder' : 'vault'), 'icon-sm'));
    row.appendChild(icon);
    const main = _el('div', 'dashboard-lane-main');
    const title = s.target_type === 'vault' ? (s.vault_name || 'Shared vault')
        : (s.target_name || 'Shared item');
    main.appendChild(_el('div', 'dashboard-lane-title', title));
    main.appendChild(_el('div', 'dashboard-lane-sub text-secondary',
        s.status === 'available' ? 'Shared with you — claim to open' : 'Shared with you'));
    row.appendChild(main);
    if (s.status === 'available') {
        row.addEventListener('click', () => { const el = document.querySelector('.sidebar-item[data-section="shared"]'); if (el) el.click(); });
    } else {
        row.addEventListener('click', () => openSharedItem(s.vault_id, s.target_folder_id || ''));
    }
    return row;
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

// Who may see the dashboard's System Status card.
//
// A scoped temporary credential authenticates AS its owning account, so its role is the owner's
// role — an admin-minted one reads as 'admin' here. Exclude it explicitly, the same way the
// sidebar does (hideAdminNavForTempSession), or a temp session inherits the owner's view.
function canSeeSystemStatus() {
    return !!(currentUser && currentUser.role === 'admin' && !isScopedTemp);
}

// Show/hide the System Status card and reflow the row it sits in.
//
// Both branches are set explicitly rather than only hiding, because the same tab can move between
// accounts (log out and back in, or a session restore) and a one-way toggle would strand the
// previous account's layout. The grid's own default is the single-column, card-hidden state, so
// the reveal is the exception and any failure leaves the safe layout in place.
//
// Note this is presentation only. GET /health is deliberately unauthenticated — it answers from a
// fixed vocabulary with no paths or capacities — so hiding the card removes clutter a non-admin
// cannot act on. It is not a confidentiality boundary and must not be described as one.
function applyDashboardAdminGating() {
    const card = document.getElementById('dashboard-system-status');
    const grid = document.getElementById('dashboard-lower-grid');
    const usersCard = document.getElementById('dashboard-users-card');
    const show = canSeeSystemStatus();
    // The Active Users tile and the whole Recent-Events/System-Status row are administrator ops
    // content. Reveal them only for an interactive admin; a non-admin (or a scoped temp session
    // reading as its admin owner) sees the personal lanes instead. Both branches set display
    // explicitly so the same tab moving between accounts never strands the previous layout.
    if (usersCard) usersCard.style.display = show ? '' : 'none';
    if (card) card.style.display = show ? '' : 'none';
    if (grid) {
        grid.style.display = show ? '' : 'none';
        grid.style.gridTemplateColumns = show ? '2fr 1fr' : '1fr';
    }
}

// Update system status indicators
async function updateSystemStatus() {
    // Don't fire the request for someone who cannot see the result: a pointless round trip whose
    // only visible effect would be console noise.
    if (!canSeeSystemStatus()) return;
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

// Parse a timestamp that came from the API.
//
// The server stores and reports UTC, but serialises it naively — .isoformat()
// yields "2026-08-13T11:25:12.951177" with no trailing Z and no offset.
// ECMAScript parses a date-TIME string in that form as LOCAL time (date-ONLY
// strings are the opposite: those are defined as UTC). So on a UTC+3 machine a
// record written a second ago parses three hours into the past: it displays as
// "3h ago", and any countdown computed from it is three hours out — a
// correctness bug, not only a cosmetic one.
//
// Attaching the UTC designator the server omitted fixes the instant; the
// browser then renders it in the viewer's own zone via toLocale*(). Values that
// already carry a zone (Z or +hh:mm), epoch numbers and Date objects pass
// through untouched, so this keeps working if the API later starts emitting a
// designator itself.
//
// Do NOT use this for a value read from <input type="datetime-local">: that is
// local wall-clock by definition and must not be reinterpreted as UTC.
function parseServerTime(value) {
    if (value === null || value === undefined || value === '') return null;
    if (value instanceof Date) return isNaN(value.getTime()) ? null : value;
    if (typeof value === 'number') {
        const n = new Date(value);
        return isNaN(n.getTime()) ? null : n;
    }
    const s = String(value).trim();
    const isDateTime = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s);
    // Accepts Z, ±hh:mm, ±hhmm and the hour-only ±hh that ISO 8601 also allows.
    // Python never emits the hour-only form, but missing it would append a
    // second designator and turn a valid instant into an unparseable one.
    const hasZone = /(?:[zZ]|[+-]\d{2}(?::?\d{2})?)$/.test(s);
    const d = new Date(isDateTime && !hasZone ? s.replace(' ', 'T') + 'Z' : s);
    return isNaN(d.getTime()) ? null : d;
}

// An absolute API timestamp rendered in the viewer's own timezone.
function formatServerTime(value, fallback) {
    const d = parseServerTime(value);
    return d ? d.toLocaleString() : (fallback === undefined ? '—' : fallback);
}

// Format timestamp to relative time (rendered in the viewer's local zone).
function formatTimeAgo(timestamp) {
    const date = parseServerTime(timestamp);
    if (!date) return '—';
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

// ---- Vault-list ordering -------------------------------------------------------------------
// Sorting is done here rather than server-side because GET /vaults already returns every field
// involved, so re-ordering costs no request and the list never flickers through a refetch.

const VAULT_SORT_KEYS = ['name', 'size', 'files', 'created', 'viewed'];
const VAULT_FAV_GROUPS = ['first', 'last', 'mixed'];

// Comparable value per sort key. Null means "no value" and is always ordered LAST regardless of
// direction — a vault you have never opened is not the "most recently viewed" one, and flipping to
// ascending should not float every never-viewed vault to the top.
function vaultSortValue(v, key) {
    switch (key) {
        case 'size': return v.total_size_bytes == null ? null : Number(v.total_size_bytes);
        case 'files': return v.file_count == null ? null : Number(v.file_count);
        case 'created': {
            const d = parseServerTime(v.created_at);
            return d ? d.getTime() : null;
        }
        case 'viewed': {
            const d = parseServerTime(v.last_viewed_at);
            return d ? d.getTime() : null;
        }
        case 'name':
        default:
            return (v.name || '').toLowerCase();
    }
}

// Order a COPY of the list. Stable: equal keys fall back to name and then id, so a re-render never
// reshuffles rows that compare the same — Array.prototype.sort is only guaranteed stable for the
// comparator's own equal cases, and "same size" is a very common tie here.
function sortVaults(list, key, dir, favGroup) {
    key = VAULT_SORT_KEYS.includes(key) ? key : 'name';
    favGroup = VAULT_FAV_GROUPS.includes(favGroup) ? favGroup : 'first';
    const sign = dir === 'desc' ? -1 : 1;

    const cmpValues = (a, b) => {
        if (typeof a === 'string' || typeof b === 'string') {
            return String(a).localeCompare(String(b));
        }
        return a < b ? -1 : (a > b ? 1 : 0);
    };

    return list.slice().sort((x, y) => {
        if (favGroup !== 'mixed') {
            const fx = x.is_favorite ? 1 : 0;
            const fy = y.is_favorite ? 1 : 0;
            if (fx !== fy) return favGroup === 'first' ? fy - fx : fx - fy;
        }
        const vx = vaultSortValue(x, key);
        const vy = vaultSortValue(y, key);
        // Nulls are resolved BEFORE the direction is applied, or `* sign` would flip them to the
        // front in descending order — putting every never-viewed vault above the ones you actually
        // opened, which is the opposite of what "sort by last viewed" should ever show.
        if (vx === null || vy === null) {
            if (vx !== null || vy !== null) return vx === null ? 1 : -1;
        } else {
            const primary = cmpValues(vx, vy);
            if (primary !== 0) return primary * sign;
        }
        // Deterministic tie-breaks, NOT multiplied by `sign`: flipping direction should not also
        // reshuffle rows that were already equal on the sort key.
        const byName = String(x.name || '').localeCompare(String(y.name || ''));
        if (byName !== 0) return byName;
        return String(x.id).localeCompare(String(y.id));
    });
}

// Read the persisted ordering out of a server preferences payload, falling back to localStorage.
//
// The fallback covers a never-configured account and the window before the preferences fetch
// resolves. It deliberately does NOT override a stored server value — so if a write fails, the
// choice survives in this tab but is lost at the next login. Making the local copy win would
// require versioning the two against each other; noted rather than silently implied.
function applyVaultOrderPrefs(prefs) {
    const pick = (value, allowed, fallbackKey, dflt) => {
        if (typeof value === 'string' && allowed.includes(value)) return value;
        try {
            const local = localStorage.getItem(fallbackKey);
            if (local && allowed.includes(local)) return local;
        } catch (_) { /* storage blocked */ }
        return dflt;
    };
    const p = prefs || {};
    state.vaultSort = pick(p.vault_sort, VAULT_SORT_KEYS, 'vaultSort', 'name');
    state.vaultSortDir = pick(p.vault_sort_dir, ['asc', 'desc'], 'vaultSortDir', 'asc');
    state.vaultFavGroup = pick(p.vault_fav_group, VAULT_FAV_GROUPS, 'vaultFavGroup', 'first');
}

// Persist to the account, and to localStorage as an immediate local fallback. Best-effort: an
// ordering preference is not worth surfacing an error toast for.
//
// Debounced, because changing key, direction and grouping in quick succession would otherwise fire
// three PUTs carrying the whole triple. The server merges under a row lock so nothing is lost
// there, but the requests can still land out of order and let an earlier one overwrite the newer
// choice.
let _vaultOrderPersistTimer = null;
function persistVaultOrderPrefs() {
    if (_vaultOrderPersistTimer) clearTimeout(_vaultOrderPersistTimer);
    _vaultOrderPersistTimer = setTimeout(_persistVaultOrderPrefsNow, 250);
}

function _persistVaultOrderPrefsNow() {
    _vaultOrderPersistTimer = null;
    try {
        localStorage.setItem('vaultSort', state.vaultSort);
        localStorage.setItem('vaultSortDir', state.vaultSortDir);
        localStorage.setItem('vaultFavGroup', state.vaultFavGroup);
    } catch (_) { /* storage blocked */ }
    apiRequest('/users/me/preferences', {
        method: 'PUT',
        body: JSON.stringify({
            vault_sort: state.vaultSort,
            vault_sort_dir: state.vaultSortDir,
            vault_fav_group: state.vaultFavGroup,
        }),
        silent: true,
    }).catch(() => { /* the local fallback already holds this browser's choice */ });
}

// Reflect state into the controls and wire them exactly once.
function setupVaultSortControls() {
    const sortEl = document.getElementById('vault-sort');
    const dirEl = document.getElementById('vault-sort-dir');
    const favEl = document.getElementById('vault-fav-group');
    if (!sortEl || !dirEl || !favEl) return;

    if (!state.vaultSort) applyVaultOrderPrefs(null);
    sortEl.value = state.vaultSort;
    favEl.value = state.vaultFavGroup;
    const asc = state.vaultSortDir !== 'desc';
    dirEl.dataset.dir = asc ? 'asc' : 'desc';
    dirEl.textContent = asc ? '↑' : '↓';
    dirEl.title = asc ? 'Ascending' : 'Descending';
    dirEl.setAttribute('aria-label', asc ? 'Sort ascending' : 'Sort descending');

    if (state._vaultSortWired) return;
    state._vaultSortWired = true;
    const onChange = () => {
        state.vaultSort = sortEl.value;
        state.vaultFavGroup = favEl.value;
        persistVaultOrderPrefs();
        renderVaults();
    };
    sortEl.addEventListener('change', onChange);
    favEl.addEventListener('change', onChange);
    dirEl.addEventListener('click', () => {
        state.vaultSortDir = state.vaultSortDir === 'desc' ? 'asc' : 'desc';
        persistVaultOrderPrefs();
        renderVaults();
    });
}

function renderVaults() {
    const container = document.getElementById('vaults-list');
    if (!container) return;
    applyVaultsView();
    setupVaultsViewControls();
    setupVaultSortControls();
    const all = state.allVaults || [];
    const favOnly = state.vaultFilter === 'favorites';
    const filtered = favOnly ? all.filter(v => v.is_favorite) : all;
    const vaults = sortVaults(filtered, state.vaultSort, state.vaultSortDir, state.vaultFavGroup);

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

// ---- Shared with me (recipient tab) ----
// Built with DOM APIs (no innerHTML) so all recipient/creator-controlled strings go through
// textContent and can never inject markup.
const _SVGNS = 'http://www.w3.org/2000/svg';
function _svgIcon(name, cls) {
    const svg = document.createElementNS(_SVGNS, 'svg');
    svg.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
    const use = document.createElementNS(_SVGNS, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    return svg;
}
function _el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
}

async function loadShared() {
    setupSharedTabsOnce();
    switchSharedTab('with-me');  // entering the section always lands on "Shared with me"
    const container = document.getElementById('shared-list');
    if (container) container.replaceChildren(_el('div', 'spinner'));
    wireClaimLinkBox();
    try {
        state.sharedWithMe = await apiRequest('/shares/shared-with-me');
        renderShared();
    } catch (error) {
        if (container) container.replaceChildren(_el('div', 'alert alert-error', 'Failed to load shared items: ' + (error.message || '')));
    }
}

// Wire the claim-a-link box once (the section markup is static, so guard against re-binding).
function wireClaimLinkBox() {
    const btn = document.getElementById('claim-link-btn');
    const input = document.getElementById('claim-link-input');
    if (!btn || !input || btn.dataset.wired) return;
    btn.dataset.wired = '1';
    const submit = () => claimShareLink(input.value);
    btn.addEventListener('click', submit);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
}

// A share link may be a full URL (…?token=XYZ or …/something/XYZ) or a bare token; pull out the token.
function extractShareToken(raw) {
    const v = (raw || '').trim();
    if (!v) return '';
    const m = v.match(/[?&]token=([^&\s]+)/);
    // decodeURIComponent throws URIError on a malformed percent sequence (e.g. "%zz"); fall back to
    // the raw match so a mangled paste still produces a token attempt (that then fails cleanly).
    if (m) { try { return decodeURIComponent(m[1]); } catch (e) { return m[1]; } }
    if (v.includes('/')) { const parts = v.split(/[/?#]/).filter(Boolean); return parts[parts.length - 1] || v; }
    return v;
}

async function claimShareLink(raw) {
    const btn = document.getElementById('claim-link-btn');
    if (btn && btn.disabled) return;  // a claim is already in flight (guards the Enter-key path too)
    const token = extractShareToken(raw);
    if (!token) { showToast('Paste a share link or token first', 'error'); return; }
    if (btn) btn.disabled = true;
    try {
        await apiRequest('/shares/claim', { method: 'POST', body: JSON.stringify({ token }) });
        showToast('Share claimed', 'success');
        const input = document.getElementById('claim-link-input');
        if (input) input.value = '';
        await loadShared();
    } catch (error) {
        showToast(error.message || 'Could not claim that link', 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

function _sharedKindLabel(t) { return t === 'vault' ? 'Vault' : (t === 'folder' ? 'Folder' : 'File'); }

function _sharedCard(it) {
    const active = it.status === 'active';
    const title = it.target_type === 'vault' ? (it.vault_name || 'Shared vault') : (it.target_name || _sharedKindLabel(it.target_type));
    const tileIcon = it.target_type === 'file' ? 'file' : (it.target_type === 'folder' ? 'folder' : 'vault');

    const card = _el('div', 'card card-interactive vault-card');
    card.setAttribute('data-share-id', it.share_id);
    const body = _el('div', 'vault-card-body');

    const tile = _el('div', 'vault-tile');
    tile.appendChild(_svgIcon(tileIcon));
    body.appendChild(tile);

    const main = _el('div', 'vault-card-main');
    const h = _el('h3', 'vault-name', title);
    if (it.status === 'available') {
        h.appendChild(document.createTextNode(' '));
        h.appendChild(_el('span', 'badge badge-info', 'Available'));
    } else if (it.status === 'expired' || it.status === 'revoked') {
        h.appendChild(document.createTextNode(' '));
        h.appendChild(_el('span', it.status === 'expired' ? 'badge badge-warning' : 'badge badge-error',
                          it.status === 'expired' ? 'Expired' : 'Revoked'));
    }
    main.appendChild(h);
    main.appendChild(_el('p', 'vault-desc', it.target_type === 'vault'
        ? 'Whole vault' : (_sharedKindLabel(it.target_type) + ' in ' + (it.vault_name || 'a vault'))));

    const meta = _el('div', 'vault-meta');
    if (it.view_only) {
        const s = _el('span'); s.appendChild(_svgIcon('eye', 'icon-sm')); s.appendChild(document.createTextNode(' View only'));
        meta.appendChild(s);
    }
    if (it.max_downloads != null) {
        const s = _el('span'); s.appendChild(_svgIcon('download', 'icon-sm'));
        s.appendChild(document.createTextNode(' ' + it.download_count + '/' + it.max_downloads + ' downloads'));
        meta.appendChild(s);
    }
    if (it.status === 'available') meta.appendChild(_el('span', 'text-secondary', 'Shared with you — claim to open'));
    else if (!active) meta.appendChild(_el('span', 'text-secondary', 'Access ' + it.status));
    main.appendChild(meta);
    body.appendChild(main);

    if (active) {
        const openBtn = _el('button', 'open-shared-btn btn btn-primary btn-sm', 'Open');
        openBtn.addEventListener('click', (e) => { e.stopPropagation(); openSharedItem(it.vault_id, it.target_folder_id || ''); });
        body.appendChild(openBtn);
    } else if (it.status === 'available') {
        const claimBtn = _el('button', 'btn btn-primary btn-sm', 'Claim');
        claimBtn.addEventListener('click', (e) => { e.stopPropagation(); claimPushedShare(it.share_id); });
        body.appendChild(claimBtn);
    }
    card.appendChild(body);
    return card;
}

// Claim a share you were directly pushed (a named users/departments audience) — by id, no link needed.
async function claimPushedShare(shareId) {
    try {
        await apiRequest('/shares/' + shareId + '/claim', { method: 'POST' });
        showToast('Share claimed', 'success');
        await loadShared();
    } catch (e) { showToast(e.message || 'Could not claim this share', 'error'); }
}

function renderShared() {
    const container = document.getElementById('shared-list');
    if (!container) return;
    const items = state.sharedWithMe || [];
    if (items.length === 0) {
        const wrap = _el('div', 'empty-state-center p-xl');
        const icon = _el('div'); icon.style.fontSize = '3rem'; icon.style.marginBottom = 'var(--space-md)';
        icon.appendChild(_svgIcon('link', 'icon-lg'));
        wrap.appendChild(icon);
        wrap.appendChild(_el('h3', 'text-xl font-bold mb-xs', 'Nothing shared with you yet'));
        wrap.appendChild(_el('p', 'text-secondary', 'Paste a share link above to claim access to a shared file, folder, or vault.'));
        container.replaceChildren(wrap);
        return;
    }
    container.replaceChildren(...items.map(_sharedCard));
}

// Open a shared item: reuse the standard vault browser (the backend scopes the listing to the shared
// subtree), then drop into the shared folder when the share targets one.
async function openSharedItem(vaultId, folderId) {
    await openVault(vaultId);
    if (folderId) { try { await navigateToFolder(folderId); } catch (e) { /* root listing still shows the path down */ } }
}

// ---- Shared sub-tabs + "Shared by me" management (creator) ----
function setupSharedTabsOnce() {
    const bar = document.querySelector('#shared-section .tabs');
    if (!bar || bar.dataset.wired) return;
    bar.dataset.wired = '1';
    bar.querySelectorAll('.tab-btn[data-shared-tab]').forEach(btn => {
        btn.addEventListener('click', () => switchSharedTab(btn.getAttribute('data-shared-tab')));
    });
}

function switchSharedTab(which) {
    document.querySelectorAll('#shared-section .tab-btn[data-shared-tab]').forEach(
        b => b.classList.toggle('active', b.getAttribute('data-shared-tab') === which));
    const withMe = document.getElementById('shared-tab-with-me');
    const byMe = document.getElementById('shared-tab-by-me');
    if (withMe) withMe.style.display = which === 'with-me' ? '' : 'none';
    if (byMe) byMe.style.display = which === 'by-me' ? '' : 'none';
    if (which === 'by-me') loadSharedByMe().catch(err => console.error('Failed to load shared-by-me:', err));
}

async function loadSharedByMe() {
    const container = document.getElementById('shared-by-me-list');
    if (container) container.replaceChildren(_el('div', 'spinner'));
    try {
        state.sharedByMe = await apiRequest('/shares');
        renderSharedByMe();
    } catch (error) {
        if (container) container.replaceChildren(_el('div', 'alert alert-error', 'Failed to load your shares: ' + (error.message || '')));
    }
}

function _byMeStatusBadge(st) {
    if (st === 'expired') return _el('span', 'badge badge-warning', 'Expired');
    if (st === 'revoked') return _el('span', 'badge badge-error', 'Revoked');
    return _el('span', 'badge badge-success', 'Active');
}

function _sharedByMeCard(sh) {
    const active = sh.status === 'active';
    const kind = sh.target_type === 'vault' ? 'Vault' : (sh.target_type === 'folder' ? 'Folder' : 'File');
    const title = sh.target_type === 'vault' ? (sh.vault_name || 'Vault') : (sh.target_name || kind);
    const tileIcon = sh.target_type === 'file' ? 'file' : (sh.target_type === 'folder' ? 'folder' : 'vault');

    const card = _el('div', 'card vault-card');
    card.setAttribute('data-share-id', sh.id);
    const body = _el('div', 'vault-card-body');
    const tile = _el('div', 'vault-tile'); tile.appendChild(_svgIcon(tileIcon)); body.appendChild(tile);
    const main = _el('div', 'vault-card-main');
    const h = _el('h3', 'vault-name', title);
    h.appendChild(document.createTextNode(' ')); h.appendChild(_byMeStatusBadge(sh.status));
    main.appendChild(h);
    const sub = _el('div', 'flex items-center gap-sm'); sub.style.flexWrap = 'wrap'; sub.style.margin = '.1rem 0 .45rem';
    if (sh.tag_name) sub.appendChild(_el('span', 'badge badge-secondary', sh.tag_name));
    sub.appendChild(_el('span', 'text-sm text-secondary',
        sh.target_type === 'vault' ? 'Whole vault' : (kind + ' in ' + (sh.vault_name || 'a vault'))));
    main.appendChild(sub);
    const meta = _el('div', 'vault-meta');
    meta.appendChild(_el('span', null, (sh.claim_count || 0) + (sh.max_recipients != null ? '/' + sh.max_recipients : '') + ' recipients'));
    if (sh.view_only) meta.appendChild(_el('span', null, 'View only'));
    if (sh.max_downloads != null) meta.appendChild(_el('span', null, sh.max_downloads + ' downloads/recipient'));
    main.appendChild(meta);
    body.appendChild(main);
    card.appendChild(body);

    const actions = _el('div', 'flex items-center gap-sm');
    if (active) {
        const revokeBtn = _el('button', 'btn btn-sm', 'Revoke'); revokeBtn.type = 'button'; revokeBtn.style.color = '#dc2626';
        revokeBtn.addEventListener('click', () => revokeShare(sh.id, title));
        actions.appendChild(revokeBtn);
    }
    let recipWrap = null;
    if ((sh.claim_count || 0) > 0) {
        recipWrap = _el('div'); recipWrap.style.display = 'none';
        const recipBtn = _el('button', 'btn btn-secondary btn-sm', 'Recipients (' + sh.claim_count + ')'); recipBtn.type = 'button';
        recipBtn.addEventListener('click', () => {
            if (recipWrap.style.display === 'none') { recipWrap.style.display = ''; loadShareClaims(sh.id, recipWrap); }
            else recipWrap.style.display = 'none';
        });
        actions.appendChild(recipBtn);
    }
    // Append the action row (only when it has buttons) + the recipients disclosure INTO the padded
    // .vault-card-body (a flex column) instead of the padding-less .card, so they align under the
    // body content in both skins — and an action-less card gets no stray empty row.
    if (actions.childElementCount) body.appendChild(actions);
    if (recipWrap) body.appendChild(recipWrap);
    return card;
}

function renderSharedByMe() {
    const container = document.getElementById('shared-by-me-list');
    if (!container) return;
    const items = state.sharedByMe || [];
    if (items.length === 0) {
        const wrap = _el('div', 'empty-state-center p-xl');
        wrap.appendChild(_el('h3', 'text-xl font-bold mb-xs', 'You have not shared anything yet'));
        wrap.appendChild(_el('p', 'text-secondary', 'Open a vault, file, or folder and use Share to create a share.'));
        container.replaceChildren(wrap);
        return;
    }
    container.replaceChildren(...items.map(_sharedByMeCard));
}

async function revokeShare(shareId, title) {
    const ok = await showConfirm('Revoke the share of "' + title + '"? Everyone will lose access.', 'Revoke share');
    if (!ok) return;
    try {
        await apiRequest('/shares/' + shareId + '/revoke', { method: 'POST' });
        showToast('Share revoked', 'success');
        await loadSharedByMe();
    } catch (e) { showToast(e.message || 'Could not revoke the share', 'error'); }
}

async function loadShareClaims(shareId, wrap) {
    wrap.replaceChildren(_el('div', 'spinner'));
    try {
        const claims = await apiRequest('/shares/' + shareId + '/claims', { silent: true });
        renderShareClaims(shareId, claims, wrap);
    } catch (e) {
        wrap.replaceChildren(_el('div', 'alert alert-error', 'Failed to load recipients: ' + (e.message || '')));
    }
}

function renderShareClaims(shareId, claims, wrap) {
    if (!claims || claims.length === 0) { wrap.replaceChildren(_el('p', 'text-secondary text-sm', 'No recipients yet.')); return; }
    wrap.replaceChildren(...claims.map(c => {
        const row = _el('div', 'flex items-center justify-between'); row.style.padding = '2px 0';
        row.appendChild(_el('span', 'text-sm',
            c.username + (c.revoked ? ' (removed)' : '') + ' · ' + (c.download_count || 0) + ' downloads'));
        if (!c.revoked) {
            const kick = _el('button', 'btn btn-sm', 'Remove'); kick.type = 'button'; kick.style.color = '#dc2626';
            kick.addEventListener('click', () => kickShareRecipient(shareId, c.user_id, c.username, wrap));
            row.appendChild(kick);
        }
        return row;
    }));
}

async function kickShareRecipient(shareId, userId, username, wrap) {
    const ok = await showConfirm('Remove ' + username + ' from this share? They lose access immediately.', 'Remove recipient');
    if (!ok) return;
    try {
        await apiRequest('/shares/' + shareId + '/claims/' + userId + '/revoke', { method: 'POST' });
        showToast('Recipient removed', 'success');
        await loadShareClaims(shareId, wrap);  // refresh the expanded recipient list in place
    } catch (e) { showToast(e.message || 'Could not remove the recipient', 'error'); }
}

// ---- Create-share modal (creator) ----
// DOM-built (no innerHTML). Reuses the existing openModal/closeModal, copyToClipboard, and the
// department chip picker (_renderGroupPickerInto); the user picker is a small /users/search wrapper.
const _shareCreate = { targetType: null, targetId: null, vaultId: null, targetName: null,
                       policy: null, userIds: [], usersById: {}, deptIds: [], lastLink: '' };

// A share requires a Standard, non-password vault (the backend refuses zero-knowledge + password-
// protected). Hide the Share affordances for those so they aren't a dead-end.
function vaultShareable() {
    const v = state.currentVault;
    return !!(v && (v.type || 'standard') !== 'zero_knowledge' && !v.has_password);
}

async function openCreateShareModal(targetType, targetId, targetName) {
    const vaultId = state.currentVault && state.currentVault.id;
    if (!vaultId) { showToast('Open a vault first', 'error'); return; }
    _shareCreate.targetType = targetType;
    _shareCreate.targetId = (targetType === 'vault') ? null : targetId;
    _shareCreate.vaultId = vaultId;
    _shareCreate.userIds = []; _shareCreate.deptIds = []; _shareCreate.usersById = {};

    const label = document.getElementById('share-target-label');
    if (label) label.textContent = targetType === 'vault' ? (state.currentVault.name || 'this vault') : (targetName || targetType);
    document.getElementById('share-create-fields').style.display = '';
    document.getElementById('share-create-result').style.display = 'none';
    const submitBtn = document.getElementById('share-create-submit');
    if (submitBtn) { submitBtn.style.display = ''; submitBtn.disabled = true; }
    // Reset the reused singleton's inputs so a prior share's values don't leak into this one.
    _shareCreate.lastLink = '';
    ['share-lifetime-days', 'share-max-recipients', 'share-max-downloads', 'share-user-search'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
    });
    // Clear any red flag / hint left from a prior share so it doesn't briefly show on the emptied
    // inputs while /share-policy loads (the tag load then re-derives the baseline hints).
    ['share-lifetime-days', 'share-max-recipients', 'share-max-downloads'].forEach(id => {
        const el = document.getElementById(id); if (el) el.classList.remove('is-invalid');
    });
    ['share-lifetime-hint', 'share-recipients-hint', 'share-downloads-hint'].forEach(id => {
        const h = document.getElementById(id); if (h) { h.textContent = ''; h.classList.remove('form-error'); }
    });
    const results = document.getElementById('share-user-results'); if (results) results.replaceChildren();
    _shareSetError('');
    openModal('create-share-modal');
    setupShareCreateModalOnce();

    const tagSel = document.getElementById('share-tag-select');
    tagSel.replaceChildren(_el('option', null, 'Loading…'));
    tagSel.disabled = true;
    try { _shareCreate.policy = await apiRequest('/share-policy', { silent: true }); }
    catch (e) { _shareCreate.policy = { sharing_enabled: false, tags: [] }; }
    await loadSftpPolicyGroups().catch(() => {});  // for the department picker (idempotent)
    populateShareTags();
}

function populateShareTags() {
    const tagSel = document.getElementById('share-tag-select');
    const submitBtn = document.getElementById('share-create-submit');
    const tags = (_shareCreate.policy && _shareCreate.policy.tags) || [];
    tagSel.disabled = false;
    if (!_shareCreate.policy || !_shareCreate.policy.sharing_enabled || tags.length === 0) {
        tagSel.replaceChildren(_el('option', null, 'No tags available'));
        _shareSetError((!_shareCreate.policy || !_shareCreate.policy.sharing_enabled)
            ? 'Sharing is not enabled on this deployment.'
            : 'You do not have permission to create shares here.');
        if (submitBtn) submitBtn.disabled = true;
        _shareToggleRecipientGroups(null);
        return;
    }
    tagSel.replaceChildren(...tags.map(t => { const o = _el('option', null, t.name); o.value = t.id; return o; }));
    if (submitBtn) submitBtn.disabled = false;
    onShareTagChange();
}

function currentShareTag() {
    const id = document.getElementById('share-tag-select').value;
    return ((_shareCreate.policy && _shareCreate.policy.tags) || []).find(t => t.id === id) || null;
}

const _SHARE_AUD_LABEL = { anyone_internal: 'Anyone internal with the link', users: 'Specific users', departments: 'Departments' };

function onShareTagChange() {
    const t = currentShareTag();
    const audSel = document.getElementById('share-audience-select');
    if (!t) { audSel.replaceChildren(); _shareToggleRecipientGroups(null); return; }
    const auds = t.allowed_audiences || [];
    audSel.replaceChildren(...auds.map(a => { const o = _el('option', null, _SHARE_AUD_LABEL[a] || a); o.value = a; return o; }));
    const voGroup = document.getElementById('share-viewonly-group');
    const voInput = document.getElementById('share-view-only');
    if (t.force_view_only) {
        // The tag MANDATES view-only: show it, force it on, and lock it (the server enforces this too).
        voGroup.style.display = '';
        voInput.checked = true;
        voInput.disabled = true;
    } else {
        voGroup.style.display = t.allow_view_only ? '' : 'none';
        voInput.checked = !!(t.allow_view_only && t.default_view_only);
        // The backend only honors a custom view_only when the tag allows customization; otherwise it
        // forces default_view_only. Reflect that: editable only when allow_custom, else read-only.
        voInput.disabled = !t.allow_custom;
    }
    document.getElementById('share-limits-group').style.display = t.allow_custom ? '' : 'none';
    if (t.allow_custom) _shareRefreshLimitHints(); else _shareLimitSpec = null;
    _shareCreate.userIds = []; _shareCreate.deptIds = [];
    onShareAudienceChange();
}

function onShareAudienceChange() {
    _shareToggleRecipientGroups(document.getElementById('share-audience-select').value);
}

function _shareToggleRecipientGroups(aud) {
    document.getElementById('share-users-group').style.display = aud === 'users' ? '' : 'none';
    document.getElementById('share-depts-group').style.display = aud === 'departments' ? '' : 'none';
    if (aud === 'users') renderShareUserChips();
    if (aud === 'departments') renderShareDeptPicker();
}

function renderShareUserChips() {
    const host = document.getElementById('share-user-chips');
    host.replaceChildren(..._shareCreate.userIds.map(id => {
        const chip = _el('span', 'chip', _shareCreate.usersById[id] || id);
        const x = _el('button', 'chip-remove'); x.type = 'button'; x.setAttribute('aria-label', 'Remove');
        x.appendChild(_svgIcon('x', 'icon-sm'));
        x.addEventListener('click', () => { _shareCreate.userIds = _shareCreate.userIds.filter(i => i !== id); renderShareUserChips(); });
        chip.appendChild(x);
        return chip;
    }));
}

let _shareUserSearchTimer = null, _shareUserSearchSeq = 0;
async function shareUserSearch(q) {
    q = (q || '').trim();
    const results = document.getElementById('share-user-results');
    if (!q) { results.replaceChildren(); return; }
    const seq = ++_shareUserSearchSeq;
    try {
        const users = await apiRequest('/users/search?q=' + encodeURIComponent(q), { silent: true });
        if (seq !== _shareUserSearchSeq) return;  // a newer keystroke superseded this result
        results.replaceChildren(...(users || []).slice(0, 8).map(u => {
            const row = _el('button', 'pick-row', u.username); row.type = 'button';
            row.addEventListener('click', () => {
                if (!_shareCreate.userIds.includes(u.id)) { _shareCreate.userIds.push(u.id); _shareCreate.usersById[u.id] = u.username; }
                document.getElementById('share-user-search').value = '';
                results.replaceChildren();
                renderShareUserChips();
            });
            return row;
        }));
    } catch (e) { /* transient search error — ignore */ }
}

function renderShareDeptPicker() {
    _renderGroupPickerInto('share-dept-picker',
        () => _shareCreate.deptIds, v => { _shareCreate.deptIds = v; },
        'No departments selected', renderShareDeptPicker, 'share-dept-add', 'share-dept-remove');
}

function _shareSetError(msg) {
    const e = document.getElementById('share-create-error');
    if (!e) return;
    if (msg) { e.textContent = msg; e.style.display = ''; } else { e.textContent = ''; e.style.display = 'none'; }
}

// The server's hard integer ceiling for share limits (ShareCreate: ge=1, le=_INT4_MAX). Mirror it so
// the client flags an over-cap value BEFORE the round-trip instead of surfacing a 400 after Create.
const _SHARE_INT4_MAX = 2147483647;
// Per-field validation spec for the currently-selected tag; rebuilt on each tag change.
let _shareLimitSpec = null;

// Effective caps for a tag. The /share-policy payload already carries these per tag
// (tag_effective_limits): max_lifetime_minutes, and max_recipients_cap / max_downloads_cap where
// null means "unlimited" (only the hard INT4 ceiling applies). Return the caps the create-share
// inputs must respect — lifetime expressed in whole DAYS, to match the day-based input.
function _shareEffectiveCaps(t) {
    const maxLifetimeMin = Math.min(Number(t && t.max_lifetime_minutes) || _SHARE_INT4_MAX, _SHARE_INT4_MAX);
    const recCap = (t && t.max_recipients_cap != null) ? Number(t.max_recipients_cap) : _SHARE_INT4_MAX;
    const dlCap = (t && t.max_downloads_cap != null) ? Number(t.max_downloads_cap) : _SHARE_INT4_MAX;
    return {
        maxDays: Math.floor(maxLifetimeMin / 1440),   // server compares days*1440 to max_lifetime_minutes
        maxRecipients: Math.min(recCap, _SHARE_INT4_MAX),
        maxDownloads: Math.min(dlCap, _SHARE_INT4_MAX),
    };
}

// Validate one optional positive-integer limit field against [1, cap]. Empty is valid (the tag
// default applies server-side). Toggles the .is-invalid border + the hint message; returns validity.
function _shareValidateLimitField(spec) {
    const input = document.getElementById(spec.input);
    const hint = document.getElementById(spec.hint);
    if (!input) return true;
    const raw = (input.value || '').trim();
    let valid = true, msg = spec.base;
    if (raw !== '') {
        if (!/^\d+$/.test(raw)) { valid = false; msg = 'Enter a whole number.'; }
        else if (parseInt(raw, 10) < 1) { valid = false; msg = 'Must be at least 1.'; }
        else if (parseInt(raw, 10) > spec.cap) { valid = false; msg = spec.over; }
    }
    input.classList.toggle('is-invalid', !valid);
    if (hint) { hint.textContent = msg; hint.classList.toggle('form-error', !valid); }
    return valid;
}

// Rebuild the limit specs + baseline hints for the current tag, and clear any prior invalid state.
function _shareRefreshLimitHints() {
    const t = currentShareTag();
    if (!t) { _shareLimitSpec = null; return; }
    const caps = _shareEffectiveCaps(t);
    const noDayExpiry = 'Custom day-based expiry is not available for this tag.';
    _shareLimitSpec = [
        {
            input: 'share-lifetime-days', hint: 'share-lifetime-hint', cap: caps.maxDays,
            base: caps.maxDays >= 1 ? `Up to ${caps.maxDays.toLocaleString()} day${caps.maxDays === 1 ? '' : 's'} (optional).` : noDayExpiry,
            over: caps.maxDays >= 1 ? `Maximum ${caps.maxDays.toLocaleString()} days.` : noDayExpiry,
        },
        {
            input: 'share-max-recipients', hint: 'share-recipients-hint', cap: caps.maxRecipients,
            base: caps.maxRecipients < _SHARE_INT4_MAX ? `1–${caps.maxRecipients.toLocaleString()} recipients (optional).` : 'Any number of recipients (optional).',
            over: `Maximum ${caps.maxRecipients.toLocaleString()} recipients.`,
        },
        {
            input: 'share-max-downloads', hint: 'share-downloads-hint', cap: caps.maxDownloads,
            base: caps.maxDownloads < _SHARE_INT4_MAX ? `1–${caps.maxDownloads.toLocaleString()} downloads per recipient (optional).` : 'Any number of downloads per recipient (optional).',
            over: `Maximum ${caps.maxDownloads.toLocaleString()} downloads per recipient.`,
        },
    ];
    _shareLimitSpec.forEach(s => {
        const hint = document.getElementById(s.hint);
        const input = document.getElementById(s.input);
        if (hint) { hint.textContent = s.base; hint.classList.remove('form-error'); }
        if (input) input.classList.remove('is-invalid');
    });
    // Re-flag any value carried over from a previous tag against the NEW tag's caps, so switching to
    // a stricter tag flags a now-over-cap value immediately rather than only on the next keystroke.
    _shareValidateAllLimits();
}

// Validate all limit fields for the current tag; returns true when every field is within its cap.
function _shareValidateAllLimits() {
    if (!_shareLimitSpec) return true;
    return _shareLimitSpec.reduce((ok, s) => _shareValidateLimitField(s) && ok, true);
}

let _shareCreateWired = false;
function setupShareCreateModalOnce() {
    if (_shareCreateWired) return;
    _shareCreateWired = true;
    document.getElementById('share-tag-select').addEventListener('change', onShareTagChange);
    document.getElementById('share-audience-select').addEventListener('change', onShareAudienceChange);
    const search = document.getElementById('share-user-search');
    search.addEventListener('input', () => {
        clearTimeout(_shareUserSearchTimer);
        _shareUserSearchTimer = setTimeout(() => shareUserSearch(search.value), 250);
    });
    // Live-validate each optional limit field against the current tag's effective cap as the user
    // types, so an over-cap value shows a red flag before Create instead of a 400 after the round-trip.
    ['share-lifetime-days', 'share-max-recipients', 'share-max-downloads'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', () => {
            const s = _shareLimitSpec && _shareLimitSpec.find(x => x.input === id);
            if (s) _shareValidateLimitField(s);
        });
    });
    document.getElementById('share-create-submit').addEventListener('click', submitCreateShare);
    // Copy from the STORED token, not the element text (copyToClipboard swaps the element to a
    // "Copied!" label for 2s; on a show-once link a re-read would copy that label and lose the token).
    document.getElementById('share-link-copy').addEventListener('click', () => {
        const tok = _shareCreate.lastLink || '';
        if (!tok) return;
        navigator.clipboard.writeText(tok).then(() => showToast('Link copied', 'success')).catch(() => {});
    });
}

async function submitCreateShare() {
    const t = currentShareTag();
    if (!t) { _shareSetError('Pick a classification tag.'); return; }
    const aud = document.getElementById('share-audience-select').value;
    const payload = {
        vault_id: _shareCreate.vaultId, tag_id: t.id, target_type: _shareCreate.targetType,
        claim_audience: aud, with_link: true,
    };
    if (_shareCreate.targetType === 'folder') payload.target_folder_id = _shareCreate.targetId;
    if (_shareCreate.targetType === 'file') payload.target_file_id = _shareCreate.targetId;
    if (aud === 'users') {
        if (!_shareCreate.userIds.length) { _shareSetError('Pick at least one recipient.'); return; }
        payload.audience_user_ids = _shareCreate.userIds;
    }
    if (aud === 'departments') {
        if (!_shareCreate.deptIds.length) { _shareSetError('Pick at least one department.'); return; }
        payload.audience_department_ids = _shareCreate.deptIds;
    }
    // view_only is only honored server-side when the tag allows customization (else the tag default
    // is forced); only send it then, matching the UI's read-only state for non-custom tags.
    if (t.allow_view_only && t.allow_custom) payload.view_only = document.getElementById('share-view-only').checked;
    if (t.allow_custom) {
        // Block submit on an over-cap / malformed limit so the user gets an immediate red flag
        // instead of a server 400 after the round-trip (mirrors ShareCreate + resolve_share_limits).
        if (!_shareValidateAllLimits()) { _shareSetError('Please fix the highlighted limits.'); return; }
        const days = parseInt(document.getElementById('share-lifetime-days').value, 10);
        const mr = parseInt(document.getElementById('share-max-recipients').value, 10);
        const md = parseInt(document.getElementById('share-max-downloads').value, 10);
        if (days > 0) payload.lifetime_minutes = days * 1440;
        if (mr > 0) payload.max_recipients = mr;
        if (md > 0) payload.max_downloads = md;
    }
    const submitBtn = document.getElementById('share-create-submit');
    submitBtn.disabled = true;
    _shareSetError('');
    try {
        const res = await apiRequest('/shares', { method: 'POST', body: JSON.stringify(payload) });
        _shareCreate.lastLink = res.link_token || '';
        document.getElementById('share-link-value').textContent = res.link_token || '';
        document.getElementById('share-create-fields').style.display = 'none';
        document.getElementById('share-create-result').style.display = '';
        submitBtn.style.display = 'none';
        showToast('Share created', 'success');
    } catch (e) {
        const msg = (e && e.message) || '';
        // create_share fails closed for a vault the user only reached via a claim (not owner /
        // member / group) — surface a clearer reason than the raw "You do not have access…".
        const friendly = /do not have access to this vault/i.test(msg)
            ? 'You can only create shares in a vault you own or are a member of.'
            : (msg || 'Could not create the share.');
        _shareSetError(friendly);
        submitBtn.disabled = false;
    }
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

// The create-vault size hint, with the "you can change this later" clause only for a reader who
// actually will be able to.
//
// Changing a vault's size limit afterwards is PATCH /vaults/{id}/settings — NOT PATCH /vaults/{id},
// which only edits name and description and merely echoes size_limit back. That endpoint is gated
// by the VAULT_SETTINGS group, the vault.change_expiry cap, and an OWNER-ONLY check with no admin
// arm: a non-owning administrator cannot change someone else's vault size. Here that last check is
// satisfied by construction, because whoever creates the vault becomes its owner. So for this
// dialog VAULT_SETTINGS is the whole question, and hasPermission() already returns true for an
// admin.
//
// Worth knowing before "tightening" this: VAULT_SETTINGS is a role default for BOTH `user` and
// `admin` (app/core/api_catalog.py), exactly like VAULT_CREATE. So on a default deployment every
// account that can reach this dialog can also change the limit later, and the clause is simply
// true for them. It is withheld only where an administrator has deliberately revoked the group —
// which is the case this exists for. Making the clause admin-only would hide a true and useful
// statement from ordinary users.
//
// A scoped temporary credential is never promised "later", whatever its owner's groups say. It
// authenticates AS the owning account, so hasPermission() would report the OWNER's authority
// rather than the credential's — the same trap the action buttons avoid by testing scope caps
// instead (see updateActionButtonPermissions). Rather than reproduce that per-vault cap lookup for
// a vault that does not exist yet, the promise is simply withheld: the credential expires, so a
// claim about what its holder may do later is one this dialog cannot honestly make.
//
// The static copy in index.html is the WITHOUT-clause variant, so the promise is added by this
// function rather than rendered and then withdrawn.
const _SIZE_HINT_BASE = 'The most this vault may hold. Default 1 GB.';
const _SIZE_HINT_EDITABLE =
    "The most this vault may hold. Default 1 GB; you can change it later in the vault's policies.";

function createVaultSizeHintBase() {
    if (isScopedTemp) return _SIZE_HINT_BASE;
    return hasPermission('VAULT_SETTINGS') ? _SIZE_HINT_EDITABLE : _SIZE_HINT_BASE;
}

// Create Vault Modal
async function fetchAccountStorage(excludeVaultId) {
    const qs = excludeVaultId ? `?exclude_vault_id=${encodeURIComponent(excludeVaultId)}` : '';
    try { return await apiRequest('/account/storage' + qs, { silent: true }); }
    catch (_) { return null; }
}
function _bytesToGb(bytes) { return bytes / (1024 ** 3); }
// Fill a "how much you can allocate" note + set the size input's soft max.
//
// For an EXISTING vault the bound comes from that vault's own storage endpoint, because on a
// shared vault the largest total you may set includes what other contributors already put in —
// the account endpoint alone would understate it and the input's max would block a legitimate
// value. For a new vault there is no vault yet, so the account headroom is the whole story.
async function renderVaultSizeAvailability(noteId, inputEl, excludeVaultId, baseText) {
    const note = document.getElementById(noteId);
    if (!note) return;
    const base = baseText || 'The most this vault may hold.';
    const fmt = g => g.toFixed(g < 10 ? 2 : 0);

    if (excludeVaultId) {
        let info = null;
        try { info = await apiRequest(`/vaults/${excludeVaultId}/storage`, { silent: true }); }
        catch (_) { info = null; }
        if (info) {
            if (info.max_total_bytes == null) {
                note.textContent = base + (info.budget_exempt ? ' No account storage limit.' : '');
                if (inputEl) inputEl.removeAttribute('max');
            } else {
                const maxGb = _bytesToGb(info.max_total_bytes);
                const others = info.others_grant_bytes || 0;
                note.textContent = `${base} You can set it up to ${fmt(maxGb)} GB`
                    + (others > 0 ? `, including ${formatBytes(others)} other people contributed.` : '.');
                if (inputEl) inputEl.max = String(Math.max(0.1, maxGb));
            }
            return;
        }
    }

    const s = await fetchAccountStorage(excludeVaultId);
    if (!s) return;
    if (s.available_bytes == null) {  // unlimited on both axes (or budget-exempt admin)
        note.textContent = s.budget_exempt ? base + ' No account storage limit.' : base;
        if (inputEl) inputEl.removeAttribute('max');
        return;
    }
    const availGb = _bytesToGb(s.available_bytes);
    const usedGb = _bytesToGb(s.reserved_bytes || 0);
    note.textContent = `${base} You can allocate up to ${fmt(availGb)} GB (${fmt(usedGb)} GB already allocated on your account).`;
    if (inputEl) inputEl.max = String(Math.max(0.1, availGb));
}

async function showCreateVault() {
    // Clear whatever a previous, abandoned open left behind. Only a SUCCESSFUL create reset the
    // form, so cancelling and reopening used to show the old name, description and password.
    // reset() restores the markup defaults (including size = 1 GB), so it has to run before the
    // explicit field setup below rather than after it.
    //
    // This matters more now the description is one row tall: stale text that used to be obvious
    // in a three-row box can sit mostly out of sight in a one-row one.
    const form = document.getElementById('create-vault-form');
    if (form) form.reset();

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
            setZkIdleLockMinutes(f && f.zk_idle_lock_minutes);  // keep the idle-lock policy fresh
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
    renderVaultSizeAvailability('vault-size-avail', sizeInput, null, createVaultSizeHintBase());

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
                // Both halves come from the same response: the public key to wrap to, and the
                // account id the server says that key belongs to. The id is needed because a
                // version-2 lock stamps the account it was made for.
                const identity = await zkEnsurePublicKeyForCreate();
                const lib = eccLib();
                const myPub = await lib.importPublicKeyPEM(identity.pem);
                const myUserId = identity.userId;
                const dek = await lib.generateVaultDEK();
                payload.type = 'zero_knowledge';

                // Choose the vault's id here, before anything is locked, and send it with the
                // request. A version-2 lock stamps the key with the vault it belongs to, and the
                // key travels in this same request -- so waiting for the server to assign an id
                // would be too late to stamp anything with it.
                //
                // Both wrapping modes need this, and the team mode needs it more. A direct vault
                // created on the older format converts wholesale at its first rotation, because a
                // rotation re-wraps every member. A team vault does not: sharing writes only the
                // new member's wrap, and the stored team wrap is rewritten only when someone is
                // REVOKED. A team vault that never removes anyone would otherwise keep unstamped
                // wraps forever.
                //
                // Choosing it is safe, for two reasons worth separating. A vault id grants no
                // access -- that comes from membership rows and the crypto -- and two vaults can
                // never share one, because the server refuses a taken id and the primary key backs
                // that up. It is not inert, though: it feeds at-rest key derivation for a Standard
                // vault, which is why the server accepts a chosen id only for a zero-knowledge one.
                // It also names a directory, and that is true of every vault including this one;
                // what makes it safe is that the server types the field as a UUID, so what reaches
                // the filesystem is always canonical and never a path.
                payload.id = zkNewObjId();

                const hcb = document.getElementById('vault-hierarchical');
                if (hcb && hcb.checked) {
                    // HIERARCHICAL: mint a per-vault TEAM keypair, wrap the DEK to the team PUBLIC
                    // key, and wrap the team PRIVATE key to the owner. The server holds only public
                    // keys + opaque wraps; it never sees the DEK or the team private key.
                    const teamKp = await lib.generateKeypair();
                    const dekWrap = await zkWrapTeamDek(dek, teamKp.publicKey,
                        { vaultId: payload.id, dekEpoch: 1 });
                    const privWrap = await zkWrapTeamPrivateKey(teamKp.privateKey, myPub,
                        { vaultId: payload.id, recipientUserId: myUserId });
                    payload.key_wrapping_mode = 'hierarchical';
                    payload.team_public_key = await lib.exportPublicKeyPEM(teamKp.publicKey);
                    payload.team_wrapped_dek = dekWrap.wrappedDEK;
                    payload.team_dek_ephemeral_public_key = dekWrap.ephemeralPublicKey;
                    payload.wrapped_team_privkey = privWrap.wrappedKey;
                    payload.team_privkey_ephemeral_public_key = privWrap.ephemeralPublicKey;
                } else {
                    const { wrappedDEK, ephemeralPublicKey } = await zkWrapDekForRecipient(
                        dek, myPub,
                        { vaultId: payload.id, recipientUserId: myUserId, dekEpoch: 1 });
                    payload.wrapped_dek = wrappedDEK;
                    payload.ephemeral_public_key = ephemeralPublicKey;
                }
                zkPendingDek = dek;
            } catch (err) {
                if (err && err.code === 'zk_no_encryption_key') {
                    // First ZK vault with no encryption key yet: guide the user to set the key up
                    // deliberately (and open that flow for them), rather than confusing the key
                    // passphrase with a vault password. Abort this create; they re-create afterward.
                    showWarning(err.message);
                    try { openEncryptionKeyModal(); } catch (_) { /* modal optional */ }
                    return;
                }
                showError(isCodedCryptoError(err)
                    ? safeMessageForCode(err.code, 'unlock')
                    : 'Encryption key setup failed.');
                return;
            }
        }

        const created = await apiRequest('/vaults', {
            method: 'POST',
            body: JSON.stringify(payload)
        });
        // Cache the just-generated DEK (epoch 1) so the first upload needn't round-trip to
        // unwrap. zkState.vaultDeks is keyed {vaultId: {epoch: dek}} — store under epoch 1.
        if (zkPendingDek && payload.id && created && created.id !== payload.id) {
            // The lock was stamped with the id we chose. If the vault came back under a
            // different one, the stamp names a vault that does not exist -- and nothing would
            // go wrong until a reload, by which time the key is gone and the vault cannot be
            // opened by anyone. Refuse now, while the failure is still legible.
            throw new Error('The server created this vault under a different id; its key '
                          + 'would not be readable. Nothing was lost -- please try again.');
        }
        if (zkPendingDek && created && created.id) {
            zkState.vaultDeks[created.id] = { 1: zkPendingDek };
            if (payload.key_wrapping_mode === 'hierarchical') zkState.pinnedHier[created.id] = true;
            // Mint the vault's name-index key (rotation-independent same-name matching). Awaited so
            // the key is in place before the first upload, but non-fatal -- the vault falls back to
            // legacy indices if it fails.
            await zkMintOwnIndexKey(created.id);
        }

        closeModal();
        document.getElementById('create-vault-form').reset();
        loadVaults();
    } catch (error) {
        showError(isCodedCryptoError(error)
            ? safeMessageForCode(error.code, 'unlock')
            : 'Failed to create vault: ' + error.message);
    }
});

// Keep the password + team-mode visibility in step with the vault-type choice.
// (app.js runs after the DOM is parsed, so the select already exists here.)
(function bindVaultTypeSync() {
    const sel = document.getElementById('vault-type');
    if (sel) sel.addEventListener('change', syncCreateVaultForm);
})();

// Open the modal that lets the user choose the credential's validity/expiry
let _tcModalLoadSeq = 0;
async function showGenerateTempCreds() {
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
    const submitBtn = modal.querySelector('button[type="submit"]');
    const loadSeq = ++_tcModalLoadSeq;
    if (submitBtn) {
        submitBtn.disabled = true;
        delete submitBtn.dataset.tempScopeReady;
    }
    _tcVaultObjs = {};           // never let a prior modal session influence this mint
    modal.classList.add('active');

    const [policyLoaded, vaultsLoaded] = await Promise.all([
        _tcLoadPasscodePolicy(),
        populateTempScopeVaults(),
    ]);
    if (loadSeq !== _tcModalLoadSeq || !modal.classList.contains('active')) return;
    if (policyLoaded && vaultsLoaded) {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.dataset.tempScopeReady = 'true';
        }
    } else {
        _tcShowError('Could not load the current vault policy. Close and try again before generating credentials.');
    }
}

// Effective temp-passcode policy (from GET /temp-passcode-policy) — shapes the mint controls:
// whether the feature is offered at all, whether custom passcodes are allowed, etc. Null until loaded.
let _tcPasscodePolicy = null;
async function _tcLoadPasscodePolicy() {
    _tcPasscodePolicy = null;  // clear the prior session's policy so the section stays hidden until the fresh fetch lands
    _tcSyncPasscodeUI();
    let loaded = false;
    try {
        _tcPasscodePolicy = await apiRequest('/temp-passcode-policy', { silent: true });
        loaded = !!_tcPasscodePolicy && typeof _tcPasscodePolicy === 'object';
        if (!loaded) _tcPasscodePolicy = null;
    } catch (_) {
        _tcPasscodePolicy = null;  // fail closed: no policy => passcode controls stay hidden
    }
    _tcSyncPasscodeUI();
    return loaded;
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
        _tcSyncPasscodeUI();  // passcodes attach to per-vault grants -> only in selected mode
    }));
    // Temporary-passcode controls: reflect the toggle + same-for-all state onto the rows.
    const pcEnable = document.getElementById('tc-passcode-enable');
    if (pcEnable) pcEnable.addEventListener('change', _tcSyncPasscodeUI);
    const pcSame = document.getElementById('tc-passcode-same');
    if (pcSame) pcSame.addEventListener('change', _tcSyncPasscodeUI);
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
        _tcSyncPasscodeUI();  // the per-vault passcode input + ZK note follow the toggle AND the filter
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
    // Reset the temporary-passcode controls (off; same-for-all on; shared custom cleared).
    const pcEnable = document.getElementById('tc-passcode-enable'); if (pcEnable) pcEnable.checked = false;
    const pcSame = document.getElementById('tc-passcode-same'); if (pcSame) pcSame.checked = true;
    const pcShared = document.getElementById('tc-passcode-shared-value'); if (pcShared) pcShared.value = '';
    _tcSyncPasscodeUI();
    _tcRestrictReset();
}

async function populateTempScopeVaults() {
    const list = document.getElementById('tc-vault-list');
    _tcVaultObjs = {};
    if (!list) return false;
    list.innerHTML = '<div class="text-tertiary text-sm p-sm">Loading vaults…</div>';
    try {
        const vaults = await apiRequest('/vaults', { silent: true });
        if (!Array.isArray(vaults)) throw new Error('Invalid vault response');
        vaults.forEach(v => { _tcVaultObjs[v.id] = v; });
        if (!vaults.length) {
            list.innerHTML = '<div class="text-tertiary text-sm p-sm">No vaults available to grant.</div>';
            return true;
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
        _tcDecoratePasscodeRows(vaults);   // append per-vault passcode controls via DOM (no innerHTML)
        _tcSyncPasscodeUI();               // reflect the current passcode-toggle state onto the rows
        return true;
    } catch (_) {
        _tcVaultObjs = {};
        list.innerHTML = '<div class="text-tertiary text-sm p-sm">Could not load vaults.</div>';
        return false;
    }
}

// After the vault list renders, append the per-vault passcode controls via DOM (createElement, no
// innerHTML): a custom-passcode input for each eligible (standard + password-protected) vault, and a
// "not available" note for each zero-knowledge vault. Hidden until the passcode toggle is on.
function _tcDecoratePasscodeRows(vaults) {
    const list = document.getElementById('tc-vault-list');
    if (!list || !Array.isArray(vaults)) return;
    vaults.forEach(v => {
        const cb = list.querySelector(`.tc-vault-pick[value="${v.id}"]`);  // v.id is a UUID (selector-safe)
        if (!cb) return;
        const row = cb.closest('.member-pick-item');
        if (!row) return;
        const isZk = v.type === 'zero_knowledge';
        const eligible = !isZk && !!v.has_password;  // a passcode is a second gate on a password-protected standard vault
        cb.dataset.eligible = eligible ? '1' : '0';
        // Insert after the row's password input if present, else after the row itself.
        const anchor = list.querySelector(`.tc-vault-pw[data-vault="${v.id}"]`) || row;
        if (eligible) {
            const inp = document.createElement('input');
            inp.type = 'text';
            inp.className = 'tc-vault-passcode form-control';
            inp.dataset.vault = v.id;
            inp.placeholder = 'Custom passcode for this vault (blank = auto-generate)';
            inp.autocomplete = 'off';
            inp.style.cssText = 'display:none;margin:0 0 10px 26px;max-width:340px;';
            anchor.insertAdjacentElement('afterend', inp);
        } else if (isZk) {
            // Two hidden notes; _tcSyncPasscodeUI shows whichever applies per the current policy: the
            // passcode "not available" note (when ZK is allowed in a temp-cred scope) OR the org-policy
            // "not allowed" note (when ZK is denied, alongside disabling the row's checkbox).
            const pNote = document.createElement('div');
            pNote.className = 'tc-passcode-zk-note text-tertiary text-sm';
            pNote.dataset.vault = v.id;  // so the search filter can hide it with its row
            pNote.style.cssText = 'display:none;margin:0 0 10px 26px;';
            pNote.textContent = "Passcodes aren't available for zero-knowledge vaults — add a member or use a disposable standard vault.";
            anchor.insertAdjacentElement('afterend', pNote);
            const dNote = document.createElement('div');
            dNote.className = 'tc-zk-deny-note text-tertiary text-sm';
            dNote.dataset.vault = v.id;
            dNote.style.cssText = 'display:none;margin:0 0 10px 26px;';
            dNote.textContent = 'Not allowed in temporary credentials by organization policy.';
            anchor.insertAdjacentElement('afterend', dNote);
        }
    });
}

// True when a vault's picker row is currently filtered out (hidden) by the search box, so its
// passcode input / ZK note should stay hidden regardless of the passcode-toggle state.
function _tcRowHidden(vid) {
    const cb = document.querySelector(`.tc-vault-pick[value="${vid}"]`);
    const row = cb && cb.closest('.member-pick-item');
    return !!(row && row.style.display === 'none');
}

// Show/hide the passcode controls per the effective policy + toggles + vault mode.
function _tcSyncPasscodeUI() {
    const section = document.getElementById('tc-passcode-section');
    if (!section) return;
    const policyOn = !!(_tcPasscodePolicy && _tcPasscodePolicy.temp_passcodes_enabled);
    const modeSelected = document.querySelector('input[name="tc-vault-mode"]:checked')?.value !== 'all';
    // The section rides the scope-builder (shown only when scoping is on); offer it only when the
    // feature is enabled AND we're in selected-vault mode (passcodes attach to per-vault grants).
    section.hidden = !(policyOn && modeSelected);
    const enable = document.getElementById('tc-passcode-enable');
    const on = !!(enable && enable.checked) && policyOn && modeSelected;
    const opts = document.getElementById('tc-passcode-opts');
    if (opts) opts.hidden = !on;
    const allowCustom = !!(_tcPasscodePolicy && _tcPasscodePolicy.temp_passcode_allow_custom);
    const same = document.getElementById('tc-passcode-same');
    const sameOn = !!(same && same.checked);
    const sharedRow = document.getElementById('tc-passcode-shared-row');
    if (sharedRow) sharedRow.hidden = !(on && allowCustom && sameOn);   // one shared custom input
    document.querySelectorAll('.tc-vault-passcode').forEach(el => {      // per-vault custom inputs
        el.style.display = (on && allowCustom && !sameOn && !_tcRowHidden(el.dataset.vault)) ? '' : 'none';
    });
    // Zero-knowledge vault handling per the org policy. DENY: disable + grey the ZK row and show the
    // "not allowed" note. ALLOW: keep it selectable; the passcode "not available" note shows when the
    // passcode toggle is on. (The server independently enforces the deny at the mint chokepoint.)
    // Fail closed: a null policy (pre-load / fetch failure) is treated as DENY, matching the
    // passcode section's fail-closed posture — the server is the authority either way.
    const denyZk = !(_tcPasscodePolicy && _tcPasscodePolicy.temp_cred_allow_zk_vaults !== false);
    document.querySelectorAll('.tc-zk-deny-note').forEach(dn => {
        const vid = dn.dataset.vault;
        const cb = document.querySelector(`.tc-vault-pick[value="${vid}"]`);
        const row = cb && cb.closest('.member-pick-item');
        if (cb) { cb.disabled = denyZk; if (denyZk) cb.checked = false; }
        if (row) row.style.opacity = denyZk ? '0.55' : '';
        dn.style.display = (denyZk && !_tcRowHidden(vid)) ? '' : 'none';
    });
    document.querySelectorAll('.tc-passcode-zk-note').forEach(el => {    // passcode not-available note (ALLOW only)
        el.style.display = (on && !denyZk && !_tcRowHidden(el.dataset.vault)) ? '' : 'none';
    });
    const minLen = (_tcPasscodePolicy && _tcPasscodePolicy.temp_passcode_min_length) || 16;
    const oneTime = !(_tcPasscodePolicy && _tcPasscodePolicy.temp_passcode_one_time_default === false);
    const note = document.getElementById('tc-passcode-note');
    if (note) note.textContent = on
        ? `Shown once on create. ${allowCustom ? 'Custom passcodes must be' : 'Generated passcodes are'} at least ${minLen} characters; ${oneTime ? 'one-time use by default' : 'multi-use by default'}. Only password-protected standard vaults get one.`
        : '';
    const help = document.getElementById('tc-passcode-shared-help');
    if (help) help.textContent = `At least ${minLen} characters (blank to auto-generate).`;
}

// Acknowledge-to-proceed modal shown when the scope includes a zero-knowledge vault (allow policy):
// a passcode isn't available for it, so the holder must enter the real account passphrase (master
// key). The mint proceeds only on explicit acknowledgment. Static content -> XSS-safe.
function _tcConfirmZkAck(onProceed) {
    const existing = document.getElementById('tc-zk-ack-modal');
    if (existing) existing.remove();
    const html = `
        <div id="tc-zk-ack-modal" class="modal active">
            <div class="modal-content" style="max-width:520px;">
                <div class="modal-header"><h3>Zero-knowledge vault in scope</h3></div>
                <div class="modal-body">
                    <div class="alert alert-warning">This credential's scope includes a zero-knowledge vault. Temporary passcodes aren't available for them — the holder must enter the real account passphrase (your master key) to decrypt their contents. Only issue this where you trust the device the passphrase will be typed on.</div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" id="tc-zk-ack-cancel">Cancel</button>
                    <button type="button" class="btn btn-primary" id="tc-zk-ack-proceed">I understand — continue</button>
                </div>
            </div>
        </div>`;
    document.body.insertAdjacentHTML('beforeend', html);
    const modal = document.getElementById('tc-zk-ack-modal');
    modal.querySelector('#tc-zk-ack-cancel').addEventListener('click', () => modal.remove());
    modal.querySelector('#tc-zk-ack-proceed').addEventListener('click', () => { modal.remove(); onProceed(); });
}

// --- File/folder restriction picker (produces selected_vaults[].scope_ids) ------------------
// A restriction targets exactly ONE selected Standard vault (file/folder sharing is inherently
// single-vault). Zero-knowledge grants are whole-vault only; with 0 or 2+ vaults selected, or
// "all my vaults", this picker is disabled and the credential is whole-vault.
const _tcRestrict = { vaultId: null, files: new Set(), folders: new Set(), crumbs: [{ id: null, name: 'Root' }] };
let _tcVaultObjs = {};  // id -> vault object from the picker fetch (including its confidentiality type)
let _tcRestrictSeq = 0; // monotonic load token: only the latest _tcRestrictLoad may paint (last-click-wins)

function _tcRestrictReset() {
    ++_tcRestrictSeq;  // invalidate any listing request still in flight from an earlier selection/modal
    _tcRestrict.vaultId = null;
    _tcRestrict.files.clear();
    _tcRestrict.folders.clear();
    _tcRestrict.crumbs = [{ id: null, name: 'Root' }];
    const en = document.getElementById('tc-restrict-enable');
    if (en) { en.checked = false; en.disabled = true; }
    const panel = document.getElementById('tc-restrict-panel'); if (panel) panel.hidden = true;
    const hint = document.getElementById('tc-restrict-hint');
    if (hint) {
        hint.style.display = '';
        hint.textContent = 'Select a single Standard vault above to enable.';
    }
    _tcRestrictRenderSummary();
}

function _tcRestrictSyncAvailability() {
    const en = document.getElementById('tc-restrict-enable');
    const hint = document.getElementById('tc-restrict-hint');
    if (!en) return;
    const picks = Array.from(document.querySelectorAll('.tc-vault-pick:checked'));
    const isSelected = document.querySelector('input[name="tc-vault-mode"]:checked')?.value === 'selected';
    const vid = isSelected && picks.length === 1 ? picks[0].value : null;
    const vault = vid ? _tcVaultObjs[vid] : null;
    const isSingleStandard = !!vault && vault.type === 'standard';
    if (isSingleStandard) {
        en.disabled = false;
        if (hint) hint.style.display = 'none';
        if (_tcRestrict.vaultId !== vid) {
            // The single selected vault changed — drop any prior selection (ids are per-vault).
            _tcRestrict.vaultId = vid;
            _tcRestrict.files.clear();
            _tcRestrict.folders.clear();
            _tcRestrict.crumbs = [{ id: null, name: 'Root' }];
            if (en.checked) _tcRestrictLoad(null);
        }
    } else {
        ++_tcRestrictSeq;  // a superseded load must not repaint after this state has been cleared
        en.disabled = true;
        en.checked = false;
        _tcRestrict.vaultId = null;
        _tcRestrict.files.clear();
        _tcRestrict.folders.clear();
        _tcRestrict.crumbs = [{ id: null, name: 'Root' }];
        const panel = document.getElementById('tc-restrict-panel'); if (panel) panel.hidden = true;
        if (hint) {
            hint.style.display = '';
            hint.textContent = isSelected && vault && vault.type === 'zero_knowledge'
                ? 'Zero-knowledge vaults can only be granted with whole-vault scope.'
                : 'Select a single Standard vault above to enable.';
        }
    }
    _tcRestrictRenderSummary();
}

async function _tcRestrictLoad(folderId) {
    const panel = document.getElementById('tc-restrict-panel');
    const list = document.getElementById('tc-restrict-list');
    if (!panel || !list || !_tcRestrict.vaultId) return;
    const vaultId = _tcRestrict.vaultId;
    const vault = _tcVaultObjs[vaultId];
    // Defense in depth: stale/programmatic state must never make this picker fetch or unlock a ZK
    // listing. The server remains authoritative, but the browser should not attempt the operation.
    if (!vault || vault.type !== 'standard') {
        _tcRestrictSyncAvailability();
        return;
    }
    // Last-click-wins: a slower earlier load must not paint over a
    // newer navigation, which would show one folder's contents under another's breadcrumb.
    const seq = ++_tcRestrictSeq;
    panel.hidden = false;
    list.innerHTML = '<div class="text-tertiary text-sm p-sm">Loading…</div>';
    let items = [];
    try {
        const q = folderId ? `?folder_id=${encodeURIComponent(folderId)}` : '';
        const res = await apiRequest(`/vaults/${encodeURIComponent(vaultId)}/files${q}`, { silent: true });
        items = (res && res.items) || [];
    } catch (_) {
        if (seq === _tcRestrictSeq) list.innerHTML = '<div class="text-tertiary text-sm p-sm">Could not load files.</div>';
        return;
    }
    if (seq !== _tcRestrictSeq) return;  // superseded by a newer navigation
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
        // A single-Standard-vault file/folder restriction attaches scope_ids to that vault's entry. Only when
        // at least one file/folder is chosen — an empty {files:[],folders:[]} means deny-all on the
        // server, so "restrict enabled but nothing picked" is treated as whole-vault (scope omitted).
        const restrictEnable = document.getElementById('tc-restrict-enable');
        const restrictEntry = selected_vaults.length === 1 ? selected_vaults[0] : null;
        const restrictVault = restrictEntry ? _tcVaultObjs[restrictEntry.vault_id] : null;
        if (restrictEnable && restrictEnable.checked && _tcRestrict.vaultId
            && restrictEntry && restrictEntry.vault_id === _tcRestrict.vaultId
            && restrictVault && restrictVault.type === 'standard'
            && (_tcRestrict.files.size + _tcRestrict.folders.size) > 0) {
            restrictEntry.scope_ids = {
                files: Array.from(_tcRestrict.files),
                folders: Array.from(_tcRestrict.folders),
            };
        }
    }
    // Temporary passcodes: attach issue_passcode (+ an optional custom value) to each ELIGIBLE
    // (standard, password-protected) selected vault. ZK / no-password vaults never get one.
    let passcode_same_for_all = false;
    const pcEnable = document.getElementById('tc-passcode-enable');
    if (mode === 'selected' && pcEnable && pcEnable.checked
        && _tcPasscodePolicy && _tcPasscodePolicy.temp_passcodes_enabled) {
        const same = document.getElementById('tc-passcode-same');
        passcode_same_for_all = !!(same && same.checked);
        const allowCustom = !!_tcPasscodePolicy.temp_passcode_allow_custom;
        const sharedVal = (allowCustom && passcode_same_for_all)
            ? ((document.getElementById('tc-passcode-shared-value') || {}).value || '').trim() : '';
        selected_vaults.forEach(sv => {
            const vobj = _tcVaultObjs[sv.vault_id] || {};
            if (vobj.type === 'zero_knowledge' || !vobj.has_password) return;  // ineligible
            sv.issue_passcode = true;
            if (allowCustom) {
                if (passcode_same_for_all) {
                    if (sharedVal) sv.passcode = sharedVal;
                } else {
                    const el = document.querySelector(`.tc-vault-passcode[data-vault="${sv.vault_id}"]`);
                    const val = ((el && el.value) || '').trim();
                    if (val) sv.passcode = val;
                }
            }
        });
    }
    return { scope: { v: 1, pages, caps, vault_caps_default: vaultCaps, temp }, vault_access_mode: mode, selected_vaults, passcode_same_for_all };
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
            if (options.passcode_same_for_all) body.passcode_same_for_all = true;
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
    const expires = formatServerTime(creds.expires_at, 'N/A');
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

    // Temporary vault passcodes minted with this credential — shown ONCE (like the password). The
    // vault NAME goes in the field LABEL which field() does NOT escape, so escapeHtml it here; the
    // passcode itself is the value, which field() escapes.
    const hasPasscodes = Array.isArray(creds.passcodes) && creds.passcodes.length > 0;
    const passcodesHtml = hasPasscodes
        ? creds.passcodes.map(p => {
            const nm = (_tcVaultObjs[p.vault_id] || {}).name || p.vault_id || 'vault';
            return field(`Vault passcode — ${escapeHtml(nm)}`, p.passcode || '');
          }).join('')
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
                        ${iconSvg('alert-triangle', 'icon-sm')} <strong>Copy these now.</strong> The password${hasPasscodes ? ' and vault passcode(s)' : ''} ${hasPasscodes ? 'are' : 'is'} shown once and can't be retrieved later.
                    </div>
                    ${field('Username', creds.temp_username || 'N/A')}
                    ${field('Password', creds.credential || 'N/A')}
                    ${passcodesHtml}
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
    const exp = parseServerTime(cred.expires_at);
    if (cred.is_used) return 'used';
    // An expiry that cannot be read is reported as expired, never as active:
    // this describes remaining access, so the conservative reading is the safe
    // one. Stated explicitly rather than leaning on `now > null` coercing the
    // null to epoch 0 and arriving at the same answer by accident.
    if (!exp || now > exp) return 'expired';
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
        tempCredsAll.sort((a, b) => parseServerTime(b.created_at) - parseServerTime(a.created_at));
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
    const expiresAt = parseServerTime(cred.expires_at);

    let status, statusBadge, dataStatus;
    if (cred.is_used) {
        status = 'Used'; statusBadge = 'secondary'; dataStatus = 'used';
    } else if (!expiresAt || now > expiresAt) {   // unreadable expiry -> expired, see credStatus
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
            <td><span class="mono cred-expires" id="countdown-${uname}">${formatServerTime(cred.expires_at)}</span></td>
        </tr>
        <tr class="exp-detail${open ? ' is-open' : ''}" data-id="${uname}">
            <td colspan="5">
                <div class="row-detail">
                    <div class="detail-meta">
                        <span class="meta-item">${iconSvg('calendar', 'icon-sm')}<span class="meta-label">Created</span><span class="meta-value">${formatServerTime(cred.created_at)}</span></span>
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
        const expires = parseServerTime(expiresAt);
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
        // The Invite affordances key off the org policy, which rides admin-only GET /settings.
        // Refetch it on every Users view so an admin who just enabled invitations (here or in another
        // session) sees the button without having to open the Settings tab first. On a failed fetch
        // the prior value is kept, and the button gate is fail-closed (=== true) either way.
        try {
            currentSettings = await apiRequest('/settings', { silent: true });
        } catch (_) { /* keep the prior currentSettings */ }
        updateActionButtonPermissions();
        loadInvites();
    } catch (error) {
        console.error('Failed to load users:', error);
        container.innerHTML = `<div class="alert alert-error">Failed to load users: ${escapeHtml(error.message)}</div>`;
    }
}

// ---- Account invitations (admin) -------------------------------------------
// Built with DOM APIs (no innerHTML); the plaintext invite link is shown once and copied from a
// stored variable, never re-read from the DOM.
let _lastInviteLink = null;
let _inviteFormWired = false;

function openInviteModal() {
    const fields = document.getElementById('invite-user-fields');
    const result = document.getElementById('invite-link-result');
    const footer = document.getElementById('invite-user-footer');
    const doneFooter = document.getElementById('invite-done-footer');
    // Reset to the fields step on OPEN — closeModal only scrubs password inputs.
    if (fields) fields.style.display = '';
    if (result) result.style.display = 'none';
    if (footer) footer.style.display = '';
    if (doneFooter) doneFooter.style.display = 'none';
    document.getElementById('invite-username').value = '';
    document.getElementById('invite-email').value = '';
    document.getElementById('invite-role').value = 'user';
    _lastInviteLink = null;
    // Email requiredness follows the org policy.
    const req = currentSettings.email_requirement === 'required';
    const emailInput = document.getElementById('invite-email');
    const emailLabel = document.getElementById('invite-email-label');
    if (emailInput) emailInput.required = req;
    if (emailLabel) emailLabel.textContent = req ? 'Email' : 'Email (optional)';
    if (!_inviteFormWired) {
        _inviteFormWired = true;
        document.getElementById('invite-user-form').addEventListener('submit', submitInvite);
        document.getElementById('invite-link-copy').addEventListener('click', copyInviteLink);
    }
    openModal('invite-user-modal');
}

async function submitInvite(e) {
    e.preventDefault();
    const btn = document.getElementById('invite-submit-btn');
    const payload = {
        username: document.getElementById('invite-username').value.trim(),
        role: document.getElementById('invite-role').value,
    };
    const email = document.getElementById('invite-email').value.trim();
    if (email) payload.email = email;
    try {
        btn.disabled = true;
        const res = await apiRequest('/invites', { method: 'POST', body: JSON.stringify(payload) });
        _lastInviteLink = res.invite_url || res.token;
        document.getElementById('invite-link-value').textContent = _lastInviteLink;
        let _inviteNote = 'This link expires ' + formatServerTime(res.expires_at) + '.';
        if (email) {
            _inviteNote += res.email_sent
                ? ' We emailed the invitation to ' + email + '.'
                : ' We couldn’t email it — copy the link above and send it yourself.';
        }
        document.getElementById('invite-link-expiry').textContent = _inviteNote;
        document.getElementById('invite-user-fields').style.display = 'none';
        document.getElementById('invite-user-footer').style.display = 'none';
        document.getElementById('invite-link-result').style.display = '';
        document.getElementById('invite-done-footer').style.display = '';
        loadInvites();
    } catch (err) {
        showError('Could not create the invitation: ' + err.message);
    } finally {
        btn.disabled = false;
    }
}

function copyInviteLink() {
    // Copy the STORED link, not the element text — the button swaps its own label to a confirmation,
    // and re-reading the DOM could copy the wrong thing.
    if (!_lastInviteLink) return;
    navigator.clipboard.writeText(_lastInviteLink).then(() => {
        const b = document.getElementById('invite-link-copy');
        const orig = b.textContent;
        b.textContent = '✓ Copied';
        setTimeout(() => { b.textContent = orig; }, 2000);
    });
}

async function loadInvites() {
    const block = document.getElementById('invites-block');
    const list = document.getElementById('invites-list');
    if (!block || !list) return;
    if (currentSettings.invite_enabled !== true || !hasPermission('USER_VIEW')) {
        block.style.display = 'none';
        return;
    }
    try {
        const invites = await apiRequest('/invites', { silent: true });
        renderInvites(Array.isArray(invites) ? invites : []);
    } catch (_) {
        block.style.display = 'none';
    }
}

function renderInvites(invites) {
    const block = document.getElementById('invites-block');
    const list = document.getElementById('invites-list');
    list.replaceChildren();
    if (!invites.length) {
        block.style.display = 'none';
        return;
    }
    block.style.display = '';
    const canManage = hasPermission('USER_MANAGE') && !isScopedTemp;
    invites.forEach(inv => {
        const row = _el('div', 'invite-row');
        row.setAttribute('data-invite-id', inv.id);
        row.setAttribute('style', 'display:flex; gap:var(--space-md); align-items:center; padding:var(--space-sm) 0; border-bottom:1px solid var(--border);');
        row.appendChild(_el('strong', null, inv.username));
        if (inv.email) row.appendChild(_el('span', 'text-muted', inv.email));
        row.appendChild(_el('span', 'invite-status', inv.status));
        row.appendChild(_el('span', 'text-muted', 'expires ' + formatServerTime(inv.expires_at)));
        if (canManage && inv.status === 'pending') {
            const revoke = _el('button', 'btn btn-sm btn-secondary', 'Revoke');
            revoke.style.marginLeft = 'auto';
            revoke.addEventListener('click', () => revokeInvite(inv.id));
            row.appendChild(revoke);
        }
        list.appendChild(row);
    });
}

async function revokeInvite(id) {
    try {
        await apiRequest('/invites/' + encodeURIComponent(id), { method: 'DELETE' });
        loadInvites();
    } catch (err) {
        showError('Could not revoke the invitation: ' + err.message);
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
    const lastLogin = formatServerTime(u.last_login, 'Never');
    const created = formatServerTime(u.created_at);
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
                ${u.email ? `<button class="btn btn-sm btn-secondary send-reset-link-btn" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">${iconSvg('key', 'icon-sm')} Send reset link</button>` : ''}
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
function _usShowEmailCodeRow(email) {
    const row = document.getElementById('us-email-code-row');
    if (row) row.style.display = '';
    const hint = document.getElementById('us-email-code-hint');
    if (hint) hint.textContent = 'Enter the code sent to ' + email + ' to confirm the change.';
    const inp = document.getElementById('us-email-code');
    if (inp) { inp.value = ''; inp.focus(); }
}
function _usHideEmailCodeRow() {
    const row = document.getElementById('us-email-code-row');
    if (row) row.style.display = 'none';
    const inp = document.getElementById('us-email-code');
    if (inp) inp.value = '';
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
    set('us-last-login', formatServerTime(currentUser.last_login));

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

    // Privacy: "never remember vault password". Reflect the user's own preference immediately,
    // then fetch the deployment-wide org floor and, if set, force the toggle on + disabled.
    const nrEl = document.getElementById('us-never-remember-pw');
    const nrForced = document.getElementById('us-never-remember-forced');
    if (nrEl) {
        nrEl.checked = !!state.neverRememberVaultPassword;
        nrEl.disabled = false;
        if (nrForced) nrForced.style.display = 'none';
        apiRequest('/temp-passcode-policy', { silent: true }).then(p => {
            const forced = !!(p && p.force_no_remember_vault_password === true);
            state.forceNoRememberVaultPassword = forced;
            if (forced) { nrEl.checked = true; nrEl.disabled = true; if (nrForced) nrForced.style.display = ''; }
        }).catch(() => {});
    }

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
        if (!cur) { _usShowError('Enter your current password.'); return; }
        // An empty box CLEARS the address rather than being rejected: an account may have no
        // email. Sent as an explicit null, because the backend reads an omitted field as "leave
        // it alone" and "" is not a valid address. Requiring the current password above is what
        // keeps this deliberate, so it needs no second confirmation.
        try {
            const updated = await apiRequest('/users/me', { method: 'PATCH', body: JSON.stringify({ current_password: cur, email: email || null }) });
            // Note the missing `&& updated.email`: guarding on the new value meant a successful
            // CLEAR left the old address on screen, looking as though nothing had happened.
            if (updated) {
                currentUser.email = updated.email || null;
                document.getElementById('us-email-display').textContent = updated.email || 'Not set';
                document.getElementById('us-new-email').value = '';
            }
            showSuccess('Email updated');
            document.getElementById('us-email-cur-pw').value = '';
            _usHideEmailCodeRow();
        } catch (err) {
            // When the organization requires it, CHANGING (not clearing) the address must be proved
            // with a code sent to the new address. A regular user can't read that org policy, so the
            // server refuses the direct change and says so — switch to the code flow here.
            if (email && /verification/i.test(err.message || '')) {
                try {
                    await apiRequest('/users/me/request-email-change', {
                        method: 'POST', body: JSON.stringify({ new_email: email, current_password: cur }) });
                    _usShowEmailCodeRow(email);
                    showSuccess('We sent a verification code to ' + email + '.');
                } catch (e2) { _usShowError(e2.message || 'Could not send a verification code.'); }
                return;
            }
            _usShowError(err.message || 'Could not update email.');
        }
    });
    document.getElementById('us-email-confirm-btn')?.addEventListener('click', async () => {
        _usHideError();
        const code = document.getElementById('us-email-code').value.trim();
        if (!code) { _usShowError('Enter the verification code.'); return; }
        try {
            const updated = await apiRequest('/users/me/confirm-email-change', {
                method: 'POST', body: JSON.stringify({ code }) });
            if (updated) {
                currentUser.email = updated.email || null;
                document.getElementById('us-email-display').textContent = updated.email || 'Not set';
                document.getElementById('us-new-email').value = '';
            }
            document.getElementById('us-email-cur-pw').value = '';
            _usHideEmailCodeRow();
            showSuccess('Email updated');
        } catch (err) { _usShowError(err.message || 'That code was not accepted.'); }
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
    document.getElementById('us-never-remember-pw')?.addEventListener('change', (e) => {
        if (state.forceNoRememberVaultPassword) { e.target.checked = true; return; }  // org floor: not user-changeable
        const on = !!e.target.checked;
        state.neverRememberVaultPassword = on;
        if (on) { state.rememberedVaults = {}; state._persistRemembered(); }  // drop anything already held
        if (window.saveUserPreference) window.saveUserPreference({ never_remember_vault_password: on ? 'on' : 'off' });
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

    // Send password-reset link buttons
    document.querySelectorAll('.send-reset-link-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const userId = btn.getAttribute('data-user-id');
            const username = btn.getAttribute('data-username') || 'this user';
            if (!confirm('Email a password-reset link to ' + username + '?')) return;
            btn.disabled = true;
            try {
                const r = await apiRequest('/users/' + encodeURIComponent(userId) + '/send-reset-link', { method: 'POST' });
                if (r && r.email_sent) showSuccess('Reset link sent to ' + username + '.');
                else showError('Could not send the reset link (check email configuration).');
            } catch (e) {
                showError('Could not send the reset link: ' + (e.message || ''));
            } finally { btn.disabled = false; }
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
                            <span class="perm-desc">${escapeHtml(g.description || '')}${g.dependencies && g.dependencies.length ? ` · also grants ${g.dependencies.map(dep => escapeHtml(dep)).join(', ')}` : ''}</span>
                        </span>
                    </label>`).join('')}
            </div>`).join('')}`;

    body.querySelectorAll('.perm-toggle').forEach(cb => {
        cb.addEventListener('change', () => togglePermission(userId, cb.dataset.group, cb.checked, cb));
    });
}

async function togglePermission(userId, group, grant, cb) {
    try {
        let result;
        if (grant) {
            result = await apiRequest(`/permissions/users/${userId}/grant`, { method: 'POST', body: JSON.stringify({ endpoint_group: group }) });
        } else {
            result = await apiRequest(`/permissions/users/${userId}/revoke/${group}`, { method: 'DELETE' });
        }
        const changedGroups = new Set(grant ? result.granted_groups : result.revoked_groups);
        document.querySelectorAll('.perm-toggle').forEach(toggle => {
            if (changedGroups.has(toggle.dataset.group)) toggle.checked = grant;
        });
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
            document.getElementById('edit-user-email').value = user.email || '';
            document.getElementById('edit-user-role').value = user.role;
            document.getElementById('edit-user-active').checked = user.is_active;
            renderUserQuotaField(user);

            // Show modal
            document.getElementById('edit-user-modal').classList.add('active');
        })
        .catch(error => {
            showError('Failed to load user: ' + error.message);
        });
}

// The per-account quota is a three-way choice, because "no override" and "unlimited" are
// genuinely different: an account with no override follows the deployment default as it moves,
// while an exempt account keeps its exemption. The GB box only appears for the middle answer.
function renderUserQuotaField(user) {
    const mode = document.getElementById('edit-user-quota-mode');
    const gb = document.getElementById('edit-user-quota-gb');
    const help = document.getElementById('edit-user-quota-help');
    if (!mode || !gb) return;

    const override = user.storage_quota_bytes;
    if (override === null || override === undefined) {
        mode.value = 'inherit';
        gb.value = '';
    } else if (override < 0) {
        mode.value = 'unlimited';
        gb.value = '';
    } else {
        mode.value = 'custom';
        gb.value = String(_gbFromBytes(override));
    }
    gb.hidden = mode.value !== 'custom';
    mode.onchange = () => {
        gb.hidden = mode.value !== 'custom';
        if (mode.value === 'custom' && !gb.value) gb.value = '';
    };

    if (help) {
        help.textContent = 'Loading storage usage…';
        apiRequest(`/users/${user.id}/storage`, { silent: true })
            .then(s => {
                const effective = (s.effective_quota_bytes === null || s.effective_quota_bytes === undefined)
                    ? 'no limit' : formatBytes(s.effective_quota_bytes);
                const dflt = s.default_quota_bytes ? formatBytes(s.default_quota_bytes) : 'unlimited';
                help.textContent = s.budget_exempt
                    ? `Administrators are exempt from storage quotas. Allocated so far: ${formatBytes(s.allocated_bytes)}.`
                    : `Allocated ${formatBytes(s.allocated_bytes)} of ${effective}. `
                      + `The deployment default is ${dflt}.`;
            })
            .catch(() => { help.textContent = ''; });
    }
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
        // A blank box means "no email", so the field is OMITTED rather than sent as "".
        // An empty string is not a valid address and would come back as a 422.
        const payload = { username, password, role };
        if (email.trim()) payload.email = email.trim();

        await apiRequest('/users', {
            method: 'POST',
            body: JSON.stringify(payload)
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
let monitorHistoryLoaded = false;     // one-time persisted-history backfill per page load
let monitorListenersAttached = false; // guard: initMonitor runs on every section entry

// Initialize Live Monitor
function initMonitor() {
    console.log('🔴 Initializing Live Monitor...');

    // Keep whatever already accumulated this session ("keep old results and show them but also
    // fetch new ones live") — re-render what we have instead of wiping on every re-entry.
    updateMonitorUI();

    // Connect to WebSocket for real-time events
    connectMonitorWebSocket();

    // Attach event listeners (once — this runs on every navigation to the section)
    attachMonitorListeners();

    // Fetch initial statistics
    fetchMonitorStats();

    // Seed persisted history so the feed isn't empty until the next live event (admin only).
    backfillMonitorHistory();
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
    // Emitted types: login, logout, upload, download, security_incident, error (+ Path A operation_cancelled).
    // Server broadcasts wrap the event under `event`; unwrap for inspection. (The historic bug read the
    // row fields off the TOP-LEVEL `data`, so wrapped Path-A frames rendered as type:'unknown' with an
    // empty message and were then filtered out — the whole feed looked dead. Build the row from `ev`.)
    const ev = (data && data.event) ? data.event : data;

    // Stats frames are top-level (never wrapped) — update metrics and stop.
    if (data.type === 'stats') {
        monitorMetrics.activeUsers = data.active_users || 0;
        monitorMetrics.activeSessions = data.active_sessions || 0;
        updateMonitorMetrics();
        return;
    }

    // Control frames from the auth handshake / keepalive are not activity — the status dot already
    // reflects the connection (ws.onopen), so don't render them as feed rows.
    if (data.type === 'connected' || data.type === 'pong') {
        return;
    }

    // Live notification nudge: the server broadcasts one per recipient when it writes an in-app
    // notification, so the bell (and an open target section, e.g. Notes) updates without a refresh.
    // It carries no content — re-fetch via the authenticated endpoints. NEVER render it in the
    // activity feed (an admin's socket sees every recipient's nudge; act only on my own).
    if (ev && ev.type === 'notification') {
        if (currentUser && String(ev.owner_user_id) === String(currentUser.id) && !isScopedTemp) {
            try { refreshNotifUnread(); } catch (_) {}
            // Refresh the notes lists so a newly-received note appears live. Cheap + safe when the
            // Notes section isn't the visible one (it just repopulates hidden lists + the badge).
            if (ev.target === '#notes' && typeof loadNotes === 'function') {
                try { loadNotes(); } catch (_) {}
            }
        }
        return;
    }

    // Owner notification: a temporary credential I created just signed in.
    if (ev && ev.type === 'login' && ev.is_temporary && currentUser &&
        String(ev.owner_user_id) === String(currentUser.id)) {
        showWarning(`Temporary credential ${ev.temp_username || ''} just signed in${ev.ip ? ' from ' + ev.ip : ''}`.trim());
        // Reflect it on the bell right away — the durable row is persisted server-side and the exact
        // list reconciles on the next poll / when the panel opens.
        if (!isScopedTemp) { notifUnread = (notifUnread || 0) + 1; updateNotifBadge(); }
    }

    // Path B (ProgressTracker) publishes UNWRAPPED operation_start/complete/cancelled frames that
    // duplicate the richer Path A upload/download lifecycle (same operation_id). Don't render them.
    if (!(data && data.event) && typeof ev.type === 'string' && ev.type.indexOf('operation_') === 0) {
        return;
    }

    ingestMonitorEvent(ev, 'live');
    updateMonitorUI();
}

// Normalize a raw event (a live WS frame, or a backfilled audit row already shaped like one) into
// the monitor's row model. Repeated frames of one operation (upload start -> progress -> complete)
// share an operation_id and COALESCE into a single row that updates in place, so one transfer is one
// row instead of a wall of progress lines.
function ingestMonitorEvent(ev, source) {
    const evt = {
        id: Date.now() + Math.random(),
        operationId: ev.operation_id || null,
        timestamp: ev.timestamp || new Date().toISOString(),
        type: ev.type || 'unknown',
        user: ev.user || 'System',
        // Server frames carry `description`/`title`; audit-backfill rows are pre-mapped to `description`.
        message: ev.description || ev.title || '',
        ip: ev.ip || '',
        vaultName: ev.vault_name || '',
        vaultType: ev.vault_type || '',        // 'zero_knowledge' | 'standard'
        isTemporary: !!ev.is_temporary,
        tempUsername: ev.temp_username || '',
        fileName: ev.file_name || '',
        completed: ev.completed === true,
        cancelled: ev.cancelled === true,
        source: source || 'live',
        icon: getEventIcon(ev.type)
    };

    if (evt.operationId) {
        const idx = monitorEvents.findIndex(e => e.operationId && e.operationId === evt.operationId);
        if (idx !== -1) {
            const prev = monitorEvents[idx];
            evt.id = prev.id;         // keep the row's identity
            evt.source = prev.source; // a live op stays "live" even as it updates
            // MERGE, don't blindly replace: a follow-up frame for the same operation can be thin
            // (the /api/operations/{id}/cancel endpoint emits a generic `operation_cancelled` with
            // no vault fields and no specific type). Carry forward the enrichment it omits so the
            // row doesn't lose its Vault/ZK/temp badges, and keep the specific transfer type rather
            // than letting a generic operation_* status frame flip it out of the upload/download
            // filter — just record the cancellation.
            evt.vaultName = evt.vaultName || prev.vaultName;
            evt.vaultType = evt.vaultType || prev.vaultType;
            evt.isTemporary = evt.isTemporary || prev.isTemporary;
            evt.tempUsername = evt.tempUsername || prev.tempUsername;
            evt.fileName = evt.fileName || prev.fileName;
            if (!evt.user || evt.user === 'System') evt.user = prev.user;
            if (evt.type.indexOf('operation_') === 0 && prev.type.indexOf('operation_') !== 0) {
                if (evt.type === 'operation_cancelled') evt.cancelled = true;
                evt.type = prev.type;
                evt.icon = getEventIcon(evt.type);
            }
            monitorEvents.splice(idx, 1);           // drop the old position; re-add at the top
        }
    }

    monitorEvents.unshift(evt);
    if (monitorEvents.length > 200) {
        monitorEvents = monitorEvents.slice(0, 200);
    }

    monitorMetrics.totalEvents = monitorEvents.length;
    // Events/min counts distinct LIVE rows seen in the last minute (history rows don't inflate it).
    const oneMinuteAgo = new Date(Date.now() - 60000).toISOString();
    monitorMetrics.eventsRate = monitorEvents.filter(e => e.source === 'live' && e.timestamp > oneMinuteAgo).length;
}

// Map a persisted audit action name to a monitor event type (the audit log and the live feed use
// different vocabularies: `file_upload` vs `upload`, `login_success` vs `login`, etc.).
function auditActionToType(action) {
    const a = String(action || '').toLowerCase();
    if (a.indexOf('login') === 0) return 'login';
    if (a.indexOf('logout') === 0) return 'logout';
    if (a.indexOf('file_upload') === 0 || a === 'upload') return 'upload';
    if (a.indexOf('file_download') === 0 || a.indexOf('file.download') === 0 || a === 'download') return 'download';
    if (a.indexOf('size_limit') === 0) return 'security_incident';
    if (a.indexOf('fail') !== -1 || a.indexOf('error') !== -1 || a.indexOf('denied') !== -1 || a.indexOf('violation') !== -1) return 'error';
    return 'info';
}

// One-line description for a backfilled audit row.
function auditRowDescription(r, type) {
    const det = (r && r.details) || {};
    const fileName = det.file_name || '';
    const label = String(r.action || type).replace(/_/g, ' ');
    const status = (r.status && r.status !== 'success') ? ` (${r.status})` : '';
    return (fileName ? fileName + ' — ' : '') + label + status;
}

// Seed the feed with persisted history so re-opening the monitor shows past activity, not just
// live-from-now. The endpoint is admin-only; non-admins (403) or a transient error just get live.
async function backfillMonitorHistory() {
    if (monitorHistoryLoaded) return;
    monitorHistoryLoaded = true;   // one attempt per page load, even on failure
    try {
        const rows = await apiRequest('/audit/log?limit=100', { silent: true });
        if (!Array.isArray(rows) || rows.length === 0) return;
        // Oldest first so the successive unshifts leave newest at the top; history sits below live.
        rows.slice().reverse().forEach(r => {
            const type = auditActionToType(r.action);
            const det = r.details || {};
            ingestMonitorEvent({
                type: type,
                timestamp: r.timestamp,
                user: r.username || 'System',
                description: auditRowDescription(r, type),
                ip: r.ip_address || '',
                vault_name: det.vault_name || '',
                is_temporary: !!r.temp_credential_id,
                file_name: det.file_name || ''
            }, 'history');
        });
        updateMonitorUI();
    } catch (e) {
        console.log('Monitor history backfill unavailable (non-admin or transient)');
    }
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
        'security_incident': 'alert-triangle',
        'operation_cancelled': 'info',
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

// A filter chip may cover more than one raw event type (e.g. "Security" = error + size-limit
// incidents). Types not listed here filter by exact equality (login/upload/download/logout).
const MONITOR_FILTER_GROUPS = {
    security: ['error', 'security_incident']
};

function monitorFilterMatches(eventType, filter) {
    if (filter === 'all') return true;
    const wanted = MONITOR_FILTER_GROUPS[filter] || [filter];
    return wanted.indexOf(eventType) !== -1;
}

// Update monitor UI
function updateMonitorUI() {
    updateMonitorMetrics();

    const eventsList = document.getElementById('monitor-events-list');
    const eventCount = document.getElementById('monitor-event-count');

    if (!eventsList) return;

    // Filter events (chip may map to a group of raw types)
    const filteredEvents = monitorEvents.filter(e => monitorFilterMatches(e.type, monitorCurrentFilter));

    // Update count
    if (eventCount) {
        eventCount.textContent = `${filteredEvents.length} event${filteredEvents.length === 1 ? '' : 's'}`;
    }

    // Render events
    if (filteredEvents.length === 0) {
        const waitingFor = monitorCurrentFilter === 'all' ? 'activity' : monitorCurrentFilter + ' events';
        eventsList.innerHTML = `
            <div class="empty-state-center">
                ${iconSvg('activity', 'icon-lg')}
                <h3>No events yet</h3>
                <p>Live ${escapeHtml(waitingFor)} will appear here as it happens.</p>
            </div>
        `;
        return;
    }

    // Type -> border/badge colour
    const typeColors = {
        'login': 'success',
        'logout': 'secondary',
        'upload': 'primary',
        'download': 'info',
        'security_incident': 'danger',
        'operation_cancelled': 'secondary',
        'error': 'danger'
    };

    eventsList.innerHTML = filteredEvents.map(event => {
        const time = parseServerTime(event.timestamp);
        const timeStr = time ? time.toLocaleTimeString() : '—';
        const badgeClass = typeColors[event.type] || 'secondary';

        // Which-account (main vs temp) badge
        const tempBadge = event.isTemporary
            ? `<span class="badge badge-info" title="Acted via a temporary credential">temp${event.tempUsername ? ': ' + escapeHtml(event.tempUsername) : ''}</span>`
            : '';
        // Standard vs zero-knowledge vault badge
        const zk = event.vaultType === 'zero_knowledge';
        const vaultBadge = event.vaultType
            ? `<span class="badge badge-${zk ? 'warning' : 'secondary'}" title="${zk ? 'Zero-knowledge vault' : 'Standard vault'}">${zk ? 'ZK' : 'Standard'}</span>`
            : '';
        // History (backfilled from the audit log) vs live
        const histBadge = event.source === 'history'
            ? `<span class="badge badge-secondary" title="From audit history">history</span>`
            : '';

        // Metadata line: vault name + client IP (file name is already in the message)
        const meta = [];
        if (event.vaultName) meta.push(`Vault: ${escapeHtml(event.vaultName)}`);
        if (event.ip) meta.push(`IP: ${escapeHtml(event.ip)}`);
        const metaLine = meta.length
            ? `<div class="text-xs text-secondary mt-xs flex gap-md flex-wrap">${meta.map(m => `<span>${m}</span>`).join('')}</div>`
            : '';

        return `
            <div class="monitor-event-item" style="border-left: 4px solid var(--${badgeClass}); padding: 0.6rem 0.85rem; margin-bottom: 0.4rem; background: var(--surface-1); border-radius: 8px;">
                <div class="flex items-start gap-md">
                    <span style="font-size: 1.25rem; line-height: 1.4;">${event.icon}</span>
                    <div class="flex-1" style="min-width: 0;">
                        <div class="flex items-center gap-sm mb-xs flex-wrap">
                            <span class="font-semibold">${escapeHtml(event.user)}</span>
                            <span class="badge badge-${badgeClass}">${escapeHtml(event.type.replace(/_/g, ' '))}</span>
                            ${tempBadge}
                            ${vaultBadge}
                            ${histBadge}
                            <span class="text-xs text-secondary ml-auto">${timeStr}</span>
                        </div>
                        <p class="text-sm text-secondary" style="word-break: break-word;">${escapeHtml(event.message || `${event.type} event`)}</p>
                        ${metaLine}
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
    // initMonitor() runs on every navigation to the section; attach the click handlers only once so
    // the filter/clear/reconnect buttons don't accumulate duplicate listeners across re-entries.
    if (monitorListenersAttached) return;
    monitorListenersAttached = true;

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

// Cleanup monitor (on LOGOUT). The socket is app-wide, so this is intentionally NOT called on
// ordinary navigation any more -- only when the session ends.
function cleanupMonitor() {
    if (monitorWebSocket) {
        monitorWebSocket.close();
        monitorWebSocket = null;
    }
}

// (Re)open the app-wide activity socket if it isn't currently open. A cheap no-op when it's already
// connected; covers a socket that dropped while the user was on a page that doesn't manage it, so
// live notifications keep working across navigation.
function ensureMonitorSocket() {
    if (!authToken) return;
    const ws = monitorWebSocket;
    if (!ws || ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
        connectMonitorWebSocket();
    }
}

// ============================================================================
// NOTIFICATIONS (bell + dropdown; the persistent counterpart to the live toast)
// ============================================================================
let notifPollTimer = null;
let notifItems = [];
let notifUnread = 0;

// Map a server-supplied notification target to an in-app section. Targets are short server-controlled
// tokens, and we only ever navigate to a KNOWN sidebar section — never inject an arbitrary href.
const _NOTIF_TARGET_SECTION = { '#shared': 'shared', '#temp-creds': 'temp-creds', '#vaults': 'vaults', '#notes': 'notes' };

async function initNotifications() {
    // Idempotent — called on login AND on refresh-restore. A temp session owns no notifications.
    if (!authToken || isScopedTemp) return;
    await loadNotifications();
    startNotifPoll();
}

async function loadNotifications() {
    if (!authToken) return;
    try {
        const data = await apiRequest('/notifications?limit=20', { silent: true });
        notifItems = (data && data.notifications) || [];
        notifUnread = (data && data.unread_count) || 0;
        renderNotifications();
    } catch (e) { /* transient — keep the last rendered state */ }
}

async function refreshNotifUnread() {
    if (!authToken) return;
    try {
        const data = await apiRequest('/notifications/unread-count', { silent: true });
        const n = (data && data.count) || 0;
        const panelOpen = !!document.querySelector('.notif-menu.active');
        if (n !== notifUnread || panelOpen) { await loadNotifications(); }  // count moved (or panel open) -> refresh
        else { updateNotifBadge(); }
    } catch (e) { /* ignore a transient poll error */ }
}

function startNotifPoll() {
    stopNotifPoll();
    notifPollTimer = setInterval(refreshNotifUnread, 60000);  // unread-count heartbeat
}
function stopNotifPoll() {
    if (notifPollTimer) { clearInterval(notifPollTimer); notifPollTimer = null; }
}

function updateNotifBadge() {
    const badge = document.getElementById('notif-badge');
    if (!badge) return;
    if (notifUnread > 0) { badge.textContent = notifUnread > 99 ? '99+' : String(notifUnread); badge.hidden = false; }
    else { badge.hidden = true; }
}

function renderNotifications() {
    updateNotifBadge();
    const list = document.getElementById('notif-list');
    const empty = document.getElementById('notif-empty');
    if (!list) return;
    list.replaceChildren();
    if (!notifItems.length) { if (empty) empty.style.display = ''; return; }
    if (empty) empty.style.display = 'none';
    notifItems.forEach(n => list.appendChild(buildNotifRow(n)));
}

function buildNotifRow(n) {
    // Built with createElement + textContent (via _el) so notification title/body — which can carry
    // another user's name or a file name — is never interpolated as HTML.
    const row = _el('div', 'notif-item' + (n.is_read ? '' : ' unread'));
    row.dataset.id = n.id;
    const body = _el('div', 'notif-item-body');
    body.appendChild(_el('div', 'notif-item-title', n.title || ''));
    if (n.body) body.appendChild(_el('div', 'notif-item-text', n.body));
    const t = parseServerTime(n.created_at);
    body.appendChild(_el('div', 'notif-item-time', t ? t.toLocaleString() : ''));
    row.appendChild(body);
    const x = _el('button', 'notif-item-dismiss'); x.type = 'button'; x.setAttribute('aria-label', 'Dismiss');
    x.appendChild(_svgIcon('x', 'icon-sm'));
    x.addEventListener('click', (e) => { e.stopPropagation(); dismissNotif(n.id); });
    row.appendChild(x);
    row.addEventListener('click', () => onNotifClick(n));
    return row;
}

async function onNotifClick(n) {
    if (!n.is_read) await markNotifRead(n.id);
    const section = _NOTIF_TARGET_SECTION[n.target];
    const menu = document.querySelector('.notif-menu'); if (menu) menu.classList.remove('active');
    if (section) {
        const item = document.querySelector('.sidebar-item[data-section="' + section + '"]');
        if (item) item.click();
    }
}

async function markNotifRead(id) {
    try { await apiRequest('/notifications/' + id + '/read', { method: 'POST', silent: true }); }
    catch (e) { return; }
    const it = notifItems.find(x => x.id === id);
    if (it && !it.is_read) { it.is_read = true; notifUnread = Math.max(0, notifUnread - 1); }
    renderNotifications();
}

async function markAllNotifRead() {
    try { await apiRequest('/notifications/read-all', { method: 'POST', silent: true }); }
    catch (e) { return; }
    notifItems.forEach(x => { x.is_read = true; });
    notifUnread = 0;
    renderNotifications();
}

async function dismissNotif(id) {
    try { await apiRequest('/notifications/' + id, { method: 'DELETE', silent: true }); }
    catch (e) { return; }
    const it = notifItems.find(x => x.id === id);
    if (it && !it.is_read) notifUnread = Math.max(0, notifUnread - 1);
    notifItems = notifItems.filter(x => x.id !== id);
    renderNotifications();
}

// Wipe the bell state on logout so a prior user's notifications never show to the next user on the
// same tab (mirrors the remembered-vault / monitor scrub in logout()).
function resetNotifications() {
    stopNotifPoll();
    notifItems = []; notifUnread = 0;
    renderNotifications();
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
    setupUpdateControls();  // "check for updates" + interval controls

    // Wire the branding color pickers <-> text inputs + logo/favicon uploads
    wireBrandColorInputs();
    wireBrandAssetUploads();

    // Attach handlers before loading begins, but keep Save inert until every
    // asynchronous settings dependency has finished populating the form.
    const saveBtn = document.getElementById('save-all-settings-btn');
    if (saveBtn) {
        saveBtn.disabled = true;
        delete saveBtn.dataset.settingsReady;
    }
    attachSettingsListeners();
    try {
        await loadSettings();
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.dataset.settingsReady = 'true';
        }
    }
    loadLogSettings();  // silent; no-op for non-admins
    
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
            if (tabId === 'sharing') { setupShareTagsUI(); loadShareTags(); }  // wire (idempotent) + refresh
            if (tabId === 'notelinks') { setupNoteLinkTagsUI(); loadNoteLinkTags(); loadAdminNoteLinks(); }  // wire + refresh
            if (tabId === 'accounts') { setupAccountsPolicyUI(); refreshAccountsPolicyUI(); }  // wire + reflect deps
            if (tabId === 'email') { loadEmailProfiles(); loadEmailTemplates(); loadEmailActions(); }  // refresh profiles + templates + actions on tab open
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
    const genBtn = document.getElementById('log-token-generate-btn');
    const anyEnabled = (data.components || []).some(c => (data.flags || {})[c]);
    // Components the admin has TICKED that are serveable but have no writer. Restricted to the
    // serveable set on purpose: db-diag/redis-diag 404 for a different reason entirely, and
    // blaming the deployment shape for those would send an admin down the wrong path.
    const sinkMap = data.sink_available || {};
    const uncollected = (data.serveable || []).filter(
        c => (data.flags || {})[c] && !sinkMap[c]);
    if (note) {
        if (!data.ceiling) {
            // Self-host-correct guidance: the endpoint 404s until BOTH env vars are set. Don't
            // advertise a token/curl that is guaranteed to 404.
            note.textContent = 'The log endpoint is currently disabled, so a token cannot return logs '
                + '(every request returns 404). To enable it: set PLAN_LOG_PULL=true and a 32+ character '
                + 'LOG_TOKEN_PEPPER in this deployment’s .env, restart, then tick a component below.';
            note.style.display = '';
        } else if (!anyEnabled) {
            // Ceiling on but nothing exposed yet — the second, easy-to-miss reason /logs 404s.
            note.textContent = 'The endpoint is enabled, but no component is exposed to /logs yet — '
                + 'tick Web (and/or SFTP) below and a token scoped to it will return logs.';
            note.style.display = '';
        } else if (uncollected.length) {
            // The third reason, and the only one that does NOT surface as a 404: every gate
            // passes, the request succeeds, and the answer is an empty list — because nothing is
            // writing that component's lines. Named per component, because the two differ: the
            // whole deployment shape can lack a writer, or SFTP alone can, when the launcher runs
            // without it. Saying "web and sftp" when only one is affected sends an admin looking
            // in the wrong place.
            const which = uncollected.length > 1
                ? uncollected.join(' and ') + ' logs are'
                : uncollected[0] + ' logs are';
            note.textContent = which + ' not being collected in this deployment, so a token scoped '
                + 'to it returns no new lines rather than an error. Lines are collected only by the '
                + 'combined launcher — a deployment that starts the API directly, such as the '
                + 'development stack or the "split" profile, collects nothing, and SFTP lines are '
                + 'collected only when SFTP runs in the same container. Note a pull may still '
                + 'return older lines left in the log volume by a previous configuration.';
            note.style.display = '';
        } else {
            note.style.display = 'none';
        }
    }
    if (genBtn) {
        // Don't let an admin mint a token + copy a curl that cannot work — whether because the
        // endpoint 404s (no ceiling / nothing ticked) or because it answers 200 with nothing.
        // The title must name the SAME reason the note shows, or it points at a message that
        // isn't there.
        // Deliberately NOT gated on "no component ticked": minting before ticking one has always
        // been allowed (the note nudges instead), and a token minted now works as soon as the
        // component is switched on. Blocking it would be a behaviour change beyond this fix.
        let why = '';
        if (!data.ceiling) why = 'Enable the log endpoint first (see the note above).';
        else if (uncollected.length) why = 'This deployment does not collect those logs (see the note above).';
        genBtn.disabled = !!why;
        genBtn.title = why;
        if (why) toggleLogTokenGenerate(false);  // collapse the mint panel if it was open
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
    // Defense-in-depth: never mint a token + curl the endpoint can't answer (the button is also disabled).
    if (window._logSettings && !window._logSettings.ceiling) {
        showError('The log endpoint is disabled — set PLAN_LOG_PULL and LOG_TOKEN_PEPPER in .env and restart first.');
        return;
    }
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
    box.className = 'cred-field-row';                 // shrinks the long code (min-width:0) so it can't
    const code = document.createElement('code');      // push the sidebar; house pattern, both skins
    code.id = 'log-token-value';
    code.className = 'cred-code mono';
    code.textContent = res.token;
    const copy = document.createElement('button');
    copy.className = 'btn btn-sm btn-secondary cred-copy-btn';
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
        row.className = 'cred-field-row mb-sm';
        const c = document.createElement('code');
        c.className = 'cred-code mono';
        c.textContent = cmd;
        const b = document.createElement('button');
        b.className = 'btn btn-sm btn-secondary cred-copy-btn';
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

    // Distinct, actionable hint for the scope-vs-enable mismatch: a component the token is scoped for
    // but NOT enabled above returns 404 even though the token is valid — the second common 404 cause.
    const flags = (window._logSettings && window._logSettings.flags) || {};
    const notEnabled = granted.filter(s => !flags[s]);
    if (notEnabled.length) {
        const warn2 = document.createElement('p');
        warn2.className = 'text-sm';
        warn2.style.color = 'var(--warning)';
        warn2.style.marginTop = '.5rem';
        const many = notEnabled.length > 1;
        warn2.textContent = notEnabled.map(s => LOG_COMPONENT_LABELS[s] || s).join(', ')
            + (many ? ' are' : ' is') + ' not enabled under “Components exposed to /logs” above, so this '
            + 'token returns 404 for ' + (many ? 'them' : 'it') + ' until you tick '
            + (many ? 'them' : 'it') + '.';
        usage.appendChild(warn2);
    }

    host.append(warn, box, usage);
}

// Load settings from API
function renderUpdateBanner(us) {
    const banner = document.getElementById('update-banner');
    if (!banner) return;
    if (!us || !us.update_available || !us.latest) { banner.style.display = 'none'; return; }
    // Honour a per-version dismissal (re-shows when a NEWER version appears).
    if (localStorage.getItem('dv-update-dismissed') === us.latest) { banner.style.display = 'none'; return; }
    const text = document.getElementById('update-banner-text');
    if (text) {
        // Normalize any leading 'v' so a v-prefixed release tag doesn't render "vv0.6.1".
        const latest = String(us.latest).replace(/^v/i, '');
        const current = String(us.current || '?').replace(/^v/i, '');
        // What the update costs, not only that it exists. An operator reading "available" and
        // pressing update has no way to tell a drop-in from a one-way schema change, and after
        // the fact is the wrong time to find out. An upgrade the server could not describe says
        // so rather than staying quiet, because a gap is where nobody has considered the hop.
        const hop = us.upgrade;
        let cost = '';
        if (hop && hop.known === false) {
            cost = ' This release does not describe what upgrading involves — read its notes and back up first.';
        } else if (hop && hop.blocked) {
            // The matrix says this one must not be taken. The tool refuses it outright, so a
            // banner calling it a drop-in would have the two surfaces contradicting each other --
            // and the banner is the one an operator reads first.
            cost = ' The project advises against taking this upgrade directly — read its notes.';
        } else if (hop) {
            const needs = [];
            if (hop.requires_backup) { needs.push('a backup'); }
            if (hop.irreversible) { needs.push('no rollback'); }
            cost = needs.length
                ? ` Upgrading requires ${needs.join(' and ')}.`
                : ' Upgrading is a drop-in change.';
            // Still one command. Said explicitly because "3 stages" otherwise reads as three
            // things to do, when it is one thing that takes longer.
            if (hop.stages > 1) {
                cost += ` It runs in ${hop.stages} stages and will take longer, but it is still a single update.`;
            }
        }
        text.textContent = `A newer version (v${latest}) is available — you’re on v${current}.${cost}`;
    }
    const link = document.getElementById('update-banner-link');
    if (link) {
        // Only trust a github.com https URL from the (network-sourced) response — never a
        // javascript:/data: link.
        if (us.url && /^https:\/\/github\.com\//.test(us.url)) { link.href = us.url; link.style.display = ''; }
        else { link.style.display = 'none'; }
    }
    const dismiss = document.getElementById('update-banner-dismiss');
    if (dismiss) dismiss.onclick = () => {
        localStorage.setItem('dv-update-dismissed', us.latest);
        banner.style.display = 'none';
    };
    banner.style.display = '';
}

// --- Update-check controls (opt-in; admin-only endpoint) --------------------------------------
let _updatePollId = null;

function renderUpdateStatus(us) {
    renderUpdateBanner(us);
    const controls = document.getElementById('update-controls');
    if (!controls) return;
    // Only expose the check-now + interval controls when the check is enabled and not managed.
    const show = !!(us && us.enabled && !us.managed);
    controls.style.display = show ? '' : 'none';
    if (!show) { if (_updatePollId) { clearInterval(_updatePollId); _updatePollId = null; } return; }
    const last = document.getElementById('update-last-checked');
    if (last) {
        last.textContent = us.checked_at
            ? 'Last checked ' + new Date(us.checked_at * 1000).toLocaleString()
            : 'Not checked yet';
    }
    const input = document.getElementById('update-interval-input');
    // Don't clobber a value the admin is mid-edit.
    if (input && document.activeElement !== input && us.interval_minutes != null) {
        input.value = us.interval_minutes;
    }
    scheduleUpdatePoll(us.interval_minutes);
}

function scheduleUpdatePoll(intervalMinutes) {
    if (_updatePollId) { clearInterval(_updatePollId); _updatePollId = null; }
    // The client polls at most every 5 min; the SERVER-side cache is what actually bounds outbound
    // GitHub requests, so this only refreshes the banner for an open settings page.
    const mins = Math.max(5, parseInt(intervalMinutes, 10) || 360);
    _updatePollId = setInterval(() => {
        apiRequest('/api/update-status', { silent: true }).then(renderUpdateStatus).catch(() => {});
    }, mins * 60 * 1000);
}

async function checkForUpdatesNow() {
    const btn = document.getElementById('update-check-now-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }
    try {
        const us = await apiRequest('/api/update-status?force=1', { silent: true });
        renderUpdateStatus(us);
        showSuccess(us && us.update_available ? 'A newer version is available' : 'Checked — you’re up to date');
    } catch (e) {
        showError('Could not check for updates');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Check for updates'; }
    }
}

async function saveUpdateInterval() {
    const input = document.getElementById('update-interval-input');
    if (!input) return;
    const minutes = parseInt(input.value, 10);
    if (!minutes || minutes < 15) { showError('Interval must be at least 15 minutes'); return; }
    try {
        const res = await apiRequest('/api/update-settings',
            { method: 'PUT', body: JSON.stringify({ interval_minutes: minutes }) });
        if (res && res.interval_minutes != null) input.value = res.interval_minutes;  // reflect the clamped value
        showSuccess('Update interval saved');
        scheduleUpdatePoll(res && res.interval_minutes);
    } catch (e) {
        showError('Could not save the update interval');
    }
}

function setupUpdateControls() {
    // Guard against stacked listeners: initSettings() re-runs on every Settings navigation, and a
    // duplicate handler would fire duplicate /api/update-status?force=1 + PUT requests per click.
    const btn = document.getElementById('update-check-now-btn');
    if (btn && !btn.dataset.wired) { btn.dataset.wired = '1'; btn.addEventListener('click', checkForUpdatesNow); }
    const save = document.getElementById('update-interval-save-btn');
    if (save && !save.dataset.wired) { save.dataset.wired = '1'; save.addEventListener('click', saveUpdateInterval); }
}

// ---- Accounts & Access policy (Settings tab) --------------------------------------
// Mirrors the effective org-onboarding policy from GET /settings and keeps dependent
// controls honest. The server (PUT /settings) is authoritative and re-validates everything.
let accountsDomains = [];
let accountsSmtpConfigured = false;
let _accountsPolicyWired = false;

function setupAccountsPolicyUI() {
    if (_accountsPolicyWired) return;
    _accountsPolicyWired = true;
    ['setting-invite-enabled', 'setting-signup-enabled', 'setting-signup-domain-mode',
     'setting-email-requirement', 'setting-login-identifier', 'setting-email-change-verification']
        .forEach(id => { const el = document.getElementById(id); if (el) el.addEventListener('change', refreshAccountsPolicyUI); });
    const ttl = document.getElementById('setting-invite-ttl-hours');
    if (ttl) ttl.addEventListener('input', updateAccountsSummary);
    const addBtn = document.getElementById('setting-signup-domain-add');
    if (addBtn) addBtn.addEventListener('click', addAccountsDomain);
    const input = document.getElementById('setting-signup-domain-input');
    if (input) input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addAccountsDomain(); } });
}

function addAccountsDomain() {
    const input = document.getElementById('setting-signup-domain-input');
    if (!input) return;
    let d = (input.value || '').trim();
    if (d.startsWith('@')) d = d.slice(1);
    d = d.trim().toLowerCase();
    if (!d) return;
    // Light client-side shape check; PUT /settings is authoritative and rejects anything else.
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) {
        showError(`"${input.value.trim()}" is not a valid domain`);
        return;
    }
    if (!accountsDomains.includes(d)) accountsDomains.push(d);
    input.value = '';
    renderAccountsDomains();
    updateAccountsSummary();
    input.focus();
}

function renderAccountsDomains() {
    const list = document.getElementById('setting-signup-domains-list');
    if (!list) return;
    if (!accountsDomains.length) {
        list.replaceChildren(_el('span', 'text-secondary text-sm', 'No domains added.'));
        return;
    }
    list.replaceChildren(...accountsDomains.map(d => {
        const chip = _el('span', 'chip', d);
        chip.setAttribute('role', 'listitem');
        const x = _el('button', 'chip-remove'); x.type = 'button'; x.setAttribute('aria-label', `Remove ${d}`);
        x.appendChild(_svgIcon('x', 'icon-sm'));
        x.addEventListener('click', () => { accountsDomains = accountsDomains.filter(v => v !== d); renderAccountsDomains(); updateAccountsSummary(); });
        chip.appendChild(x);
        return chip;
    }));
}

function refreshAccountsPolicyUI() {
    const on = id => { const el = document.getElementById(id); return !!(el && el.checked); };
    const setDisabled = (id, disabled) => { const el = document.getElementById(id); if (el) el.disabled = disabled; };
    const dim = (id, active) => { const el = document.getElementById(id); if (el) el.style.opacity = active ? '' : '0.6'; };

    const inviteOn = on('setting-invite-enabled');
    setDisabled('setting-invite-ttl-hours', !inviteOn);
    dim('accounts-invite-card', inviteOn);

    const signupOn = on('setting-signup-enabled');
    setDisabled('setting-signup-domain-mode', !signupOn);
    dim('accounts-signup-card', signupOn);
    const modeEl = document.getElementById('setting-signup-domain-mode');
    const domainsActive = signupOn && modeEl && modeEl.value !== 'off';
    setDisabled('setting-signup-domain-input', !domainsActive);
    setDisabled('setting-signup-domain-add', !domainsActive);

    // Email-change verification can only be toggled when SMTP is configured (server-enforced too).
    const ecv = document.getElementById('setting-email-change-verification');
    if (ecv) ecv.disabled = !accountsSmtpConfigured;
    const help = document.getElementById('accounts-email-verify-help');
    if (help) {
        help.textContent = accountsSmtpConfigured
            ? "A user changing their own email must confirm a one-time code sent to the new address; administrators setting an email are exempt."
            : "A user changing their own email must confirm a one-time code sent to the new address; administrators setting an email are exempt. Configure email (SMTP) on the Email tab to enable this.";
    }
    renderLoginIdentifierWarning();
    updateAccountsSummary();
}

// Live warning under the Sign-in method select: when "Email only" is chosen, show WHO would lose
// access. Admins are few -> the complete list, in red (serious), with a stronger note if the current
// user is among them. Users can be many -> a generic count, in orange. Fed by the readiness endpoint.
let _loginWarnSeq = 0;
async function renderLoginIdentifierWarning() {
    const box = document.getElementById('login-identifier-warning');
    const sel = document.getElementById('setting-login-identifier');
    if (!box || !sel) return;
    // Bump the token on EVERY call (before the early return too) so switching away — or a late
    // settings reload — cancels any in-flight email render that would otherwise resolve and re-show
    // a stale panel.
    const seq = ++_loginWarnSeq;
    if (sel.value !== 'email') { box.style.display = 'none'; box.replaceChildren(); return; }
    let data;
    try {
        data = await apiRequest('/settings/login-identifier-readiness', { silent: true });
    } catch (_) { return; }            // leave whatever is shown; the save is still server-guarded
    if (seq !== _loginWarnSeq || sel.value !== 'email') return;   // superseded by a newer change
    box.replaceChildren();
    if (data.blocks) {
        // Hard stop: no admin has an email, so email-only login would lock everyone out (server 400s).
        box.appendChild(_el('div', 'alert alert-error',
            'Email-only sign-in can’t be enabled: no administrator has an email address, so everyone '
            + 'would be locked out. Give at least one admin an email first — this save will be refused.'));
        box.style.display = '';
        return;
    }
    const admins = Array.isArray(data.admins_without_email) ? data.admins_without_email : [];
    if (admins.length) {
        const panel = _el('div', 'alert alert-error');   // serious (red): admins losing access
        panel.appendChild(_el('strong', null,
            admins.length === 1 ? 'This administrator will not be able to sign in (no email):'
                                : 'These administrators will not be able to sign in (no email):'));
        panel.appendChild(_el('div', 'text-sm mt-sm', admins.join(', ')));
        if (data.current_user_without_email) {
            const self = _el('div', 'text-sm mt-sm');
            self.appendChild(_el('strong', null, '⚠️ This includes your account — you will lose the ability to sign in. '));
            self.appendChild(document.createTextNode('Add your email before saving.'));
            panel.appendChild(self);
        }
        box.appendChild(panel);
    }
    const n = data.users_without_email_count || 0;
    if (n > 0) {
        box.appendChild(_el('div', 'alert alert-warning' + (admins.length ? ' mt-sm' : ''),
            `${n} user account${n === 1 ? '' : 's'} without an email will not be able to sign in.`));
    }
    box.style.display = (admins.length || n > 0) ? '' : 'none';
}

function updateAccountsSummary() {
    const el = document.getElementById('accounts-policy-summary');
    if (!el) return;
    const val = id => { const e = document.getElementById(id); return e ? e.value : ''; };
    const on = id => { const e = document.getElementById(id); return !!(e && e.checked); };
    const parts = [];
    parts.push(val('setting-email-requirement') === 'required'
        ? 'Every account must have an email address.' : 'An email address is optional.');
    const lid = val('setting-login-identifier');
    parts.push(lid === 'email' ? 'People sign in with their email.'
        : lid === 'either' ? 'People sign in with their username or email.'
        : 'People sign in with their username.');
    parts.push(on('setting-invite-enabled') ? 'Admins can invite people by link.' : 'Invitations are off.');
    parts.push(on('setting-signup-enabled') ? 'Anyone can sign themselves up.' : 'Self-signup is off.');
    if (on('setting-signup-enabled') && val('setting-signup-domain-mode') !== 'off') {
        const verb = val('setting-signup-domain-mode') === 'allowlist' ? 'restricted to' : 'blocked for';
        parts.push(`Signup email is ${verb} ${accountsDomains.length} listed domain(s).`);
    }
    if (on('setting-email-change-verification')) {
        parts.push('Changing one’s own email requires a code sent to the new address.');
    }
    el.textContent = parts.join(' ');
}

function populateAccountsPolicy(settings) {
    const setChk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = v === true; };
    const setVal = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
    setChk('setting-invite-enabled', settings.invite_enabled);
    setChk('setting-signup-enabled', settings.signup_enabled);
    setVal('setting-invite-ttl-hours', settings.invite_ttl_hours != null ? settings.invite_ttl_hours : 24);
    setVal('setting-signup-domain-mode', settings.signup_email_domain_mode || 'off');
    setVal('setting-email-requirement', settings.email_requirement || 'required');
    setVal('setting-login-identifier', settings.login_identifier || 'username');
    setChk('setting-email-change-verification', settings.email_change_requires_verification);
    setVal('setting-email-change-otp-ttl-minutes', settings.email_change_otp_ttl_minutes != null ? settings.email_change_otp_ttl_minutes : 5);
    setChk('setting-password-reset-enabled', settings.password_reset_enabled);
    setVal('setting-password-reset-ttl-minutes', settings.password_reset_ttl_minutes != null ? settings.password_reset_ttl_minutes : 5);
    accountsDomains = Array.isArray(settings.signup_email_domains) ? settings.signup_email_domains.slice() : [];
    // Profile-aware: the backend reports whether a usable sending profile (or legacy config) exists.
    accountsSmtpConfigured = settings.smtp_configured === true;
    setupAccountsPolicyUI();
    renderAccountsDomains();
    refreshAccountsPolicyUI();
}

function collectAccountsPolicy(settings) {
    const val = id => { const el = document.getElementById(id); return el ? el.value : undefined; };
    const on = id => { const el = document.getElementById(id); return el ? el.checked : undefined; };
    settings.invite_enabled = on('setting-invite-enabled');
    settings.signup_enabled = on('setting-signup-enabled');
    const ttl = parseInt(val('setting-invite-ttl-hours'), 10);
    if (!Number.isNaN(ttl)) settings.invite_ttl_hours = ttl;
    settings.signup_email_domain_mode = val('setting-signup-domain-mode');
    settings.email_requirement = val('setting-email-requirement');
    settings.login_identifier = val('setting-login-identifier');
    settings.signup_email_domains = accountsDomains.slice();
    // Only send the verification flag when SMTP is configured (the only state in which it's
    // settable). Otherwise omit it so a whole-object save can't trip the server's SMTP gate and
    // can't silently flip a stored value.
    if (accountsSmtpConfigured) {
        settings.email_change_requires_verification = on('setting-email-change-verification');
    }
    const otpTtl = parseInt(val('setting-email-change-otp-ttl-minutes'), 10);
    if (!Number.isNaN(otpTtl)) settings.email_change_otp_ttl_minutes = otpTtl;
    settings.password_reset_enabled = on('setting-password-reset-enabled');
    const prTtl = parseInt(val('setting-password-reset-ttl-minutes'), 10);
    if (!Number.isNaN(prTtl)) settings.password_reset_ttl_minutes = prTtl;
}

async function loadSettings() {
    try {
        const settings = await apiRequest('/settings', { silent: true });
        currentSettings = settings;
        
        // Populate form fields
        // General
        document.getElementById('setting-app-name').value = settings.app_name || '';
        document.getElementById('setting-app-description').value = settings.app_description || '';
        // Blank when unset/0 — the backend then applies the deployment's MAX_FILE_SIZE_MB cap
        // (see upload_policy.effective_max_file_bytes). Rendering 100 for a stored 0 made "Save All
        // Changes" persist 100 and silently clamp a 1024MB deployment to 100MB.
        document.getElementById('setting-max-file-size').value = (settings.max_file_size > 0) ? settings.max_file_size : '';
        document.getElementById('setting-allowed-types').value = (settings.allowed_file_types || []).join(', ');

        // App version (read-only; from the public /version endpoint)
        try {
            const ver = await apiRequest('/version', { silent: true });
            const vEl = document.getElementById('setting-app-version');
            if (vEl && ver && ver.version) vEl.textContent = 'v' + ver.version;
        } catch (e) { /* version display is non-essential */ }

        // Update-available banner + check-now/interval controls (opt-in, admin-only endpoint;
        // fail-soft). Fire-and-forget so a slow/unreachable GitHub never delays the settings form.
        apiRequest('/api/update-status', { silent: true }).then(renderUpdateStatus).catch(() => {});

        // Security
        document.getElementById('setting-password-min-length').value = settings.password_min_length || 8;  // 8 = the enforced floor
        // `=== true`, not `!== false`. An unset toggle is undefined, and `undefined !== false` is
        // true, so a deployment that had never configured a password policy rendered all four of
        // these CHECKED -- claiming a policy the server was not enforcing, since
        // password_policy_errors treats a missing toggle as off. Worse, "Save All Changes" then
        // submitted the rendered state, so an admin who opened Settings to change something else
        // silently turned the whole policy on. This is the same footgun as the auth limits below,
        // which were fixed; these four were not.
        document.getElementById('setting-require-uppercase').checked = settings.require_uppercase === true;
        document.getElementById('setting-require-lowercase').checked = settings.require_lowercase === true;
        document.getElementById('setting-require-numbers').checked = settings.require_numbers === true;
        document.getElementById('setting-require-special').checked = settings.require_special === true;
        // Auth limits: 0/unset means "use the deployment's env value" (JWT_ACCESS_TOKEN_EXPIRE_MINUTES /
        // RATE_LIMIT_LOGIN_ATTEMPTS / ACCOUNT_LOCKOUT_MINUTES — see auth_service._global_setting), so
        // render BLANK, never the shipped default. `|| 5` displayed 5 for a stored 0 and "Save All
        // Changes" then PERSISTED 5, dropping an operator who set RATE_LIMIT_LOGIN_ATTEMPTS=50 in .env
        // back to 5 without touching a field. Same footgun as the old `|| 1` share lifetime.
        document.getElementById('setting-session-timeout').value = (settings.session_timeout > 0) ? settings.session_timeout : '';
        document.getElementById('setting-max-login-attempts').value = (settings.max_login_attempts > 0) ? settings.max_login_attempts : '';
        document.getElementById('setting-lockout-duration').value = (settings.lockout_duration > 0) ? settings.lockout_duration : '';
        const apiRateDefaults = settings.rate_limit_api_deployment_defaults || {};
        const apiRateFields = [
            ['rate_limit_api_default', 'setting-rate-limit-api-default'],
            ['rate_limit_api_default_window', 'setting-rate-limit-api-default-window'],
            ['rate_limit_api_auth', 'setting-rate-limit-api-auth'],
            ['rate_limit_api_auth_window', 'setting-rate-limit-api-auth-window'],
            ['rate_limit_api_upload', 'setting-rate-limit-api-upload'],
            ['rate_limit_api_upload_window', 'setting-rate-limit-api-upload-window'],
            ['rate_limit_api_upload_chunk', 'setting-rate-limit-api-upload-chunk'],
            ['rate_limit_api_upload_chunk_window', 'setting-rate-limit-api-upload-chunk-window'],
            ['rate_limit_api_download', 'setting-rate-limit-api-download'],
            ['rate_limit_api_download_window', 'setting-rate-limit-api-download-window'],
            ['rate_limit_api_poll', 'setting-rate-limit-api-poll'],
            ['rate_limit_api_poll_window', 'setting-rate-limit-api-poll-window'],
        ];
        for (const [key, id] of apiRateFields) {
            const el = document.getElementById(id);
            if (!el) continue;
            el.value = (settings[key] > 0) ? settings[key] : '';
            if (apiRateDefaults[key] > 0) el.placeholder = `Deployment default: ${apiRateDefaults[key]}`;
        }
        const apiRateStatus = document.getElementById('setting-rate-limit-api-status');
        if (apiRateStatus) {
            apiRateStatus.textContent = settings.rate_limit_api_enabled
                ? 'General API rate limiting is enabled by the deployment; saved changes apply live.'
                : 'General API rate limiting is disabled by the deployment; saved values remain inactive until an operator enables it.';
        }
        
        // Storage
        // Show the actual stored quota, or BLANK when unset/0 (which the backend treats as
        // unlimited) — don't render 10/100 as if a limit were enforced.
        document.getElementById('setting-default-quota').value = (settings.default_user_quota > 0) ? settings.default_user_quota : '';
        document.getElementById('setting-max-vault-size').value = (settings.max_vault_size > 0) ? settings.max_vault_size : '';
        document.getElementById('setting-storage-path').value = settings.storage_path || '';
        renderDeploymentStorageSetting(settings);
        
        // Email — sending profiles are managed on their own (see loadEmailProfiles), not via the
        // central settings save.

        // SFTP & Encryption
        const zkEl = document.getElementById('setting-zero-knowledge-enabled');
        if (zkEl) zkEl.checked = settings.zero_knowledge_enabled === true;
        const fzkEl = document.getElementById('setting-force-zero-knowledge');
        if (fzkEl) fzkEl.checked = settings.force_zero_knowledge === true;
        const dssEl = document.getElementById('setting-directory-search-scope');
        if (dssEl) dssEl.value = (settings.directory_search_scope === 'same_department') ? 'same_department' : 'deployment';
        const fnrEl = document.getElementById('setting-force-no-remember-vault-password');
        if (fnrEl) fnrEl.checked = settings.force_no_remember_vault_password === true;
        const zilEl = document.getElementById('setting-zk-idle-lock-minutes');
        if (zilEl) zilEl.value = Number(settings.zk_idle_lock_minutes) || 0;

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

        // Sharing: master switch + the Share Tags manager
        const shEl = document.getElementById('setting-sharing-enabled');
        if (shEl) shEl.checked = settings.sharing_enabled === true;
        setupShareTagsUI();
        loadShareTags();

        // Note Links: master switch + per-user cap + the note-link tag manager
        const nlEn = document.getElementById('setting-public-note-links-enabled');
        if (nlEn) nlEn.checked = settings.public_note_links_enabled === true;
        const nlCap = document.getElementById('setting-public-note-link-user-cap');
        if (nlCap) nlCap.value = settings.public_note_link_user_cap != null ? settings.public_note_link_user_cap : 50;
        const nMax = document.getElementById('setting-note-max-chars');
        if (nMax) nMax.value = settings.note_max_chars != null ? settings.note_max_chars : 100000;
        setupNoteLinkTagsUI();
        loadNoteLinkTags();

        // Accounts & Access: the org-onboarding policy block.
        populateAccountsPolicy(settings);

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
            // Blank -> 0 (use the deployment's MAX_FILE_SIZE_MB cap); the backend ignores 0.
            max_file_size: parseInt(document.getElementById('setting-max-file-size').value) || 0,
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
            // Blank -> 0 (keep the deployment's env value); the backend ignores 0. NEVER substitute
            // the shipped default here — that is what silently overrode a configured .env limit.
            session_timeout: parseInt(document.getElementById('setting-session-timeout').value) || 0,
            max_login_attempts: parseInt(document.getElementById('setting-max-login-attempts').value) || 0,
            lockout_duration: parseInt(document.getElementById('setting-lockout-duration').value) || 0,
            rate_limit_api_default: parseInt(document.getElementById('setting-rate-limit-api-default').value) || 0,
            rate_limit_api_default_window: parseInt(document.getElementById('setting-rate-limit-api-default-window').value) || 0,
            rate_limit_api_auth: parseInt(document.getElementById('setting-rate-limit-api-auth').value) || 0,
            rate_limit_api_auth_window: parseInt(document.getElementById('setting-rate-limit-api-auth-window').value) || 0,
            rate_limit_api_upload: parseInt(document.getElementById('setting-rate-limit-api-upload').value) || 0,
            rate_limit_api_upload_window: parseInt(document.getElementById('setting-rate-limit-api-upload-window').value) || 0,
            rate_limit_api_upload_chunk: parseInt(document.getElementById('setting-rate-limit-api-upload-chunk').value) || 0,
            rate_limit_api_upload_chunk_window: parseInt(document.getElementById('setting-rate-limit-api-upload-chunk-window').value) || 0,
            rate_limit_api_download: parseInt(document.getElementById('setting-rate-limit-api-download').value) || 0,
            rate_limit_api_download_window: parseInt(document.getElementById('setting-rate-limit-api-download-window').value) || 0,
            rate_limit_api_poll: parseInt(document.getElementById('setting-rate-limit-api-poll').value) || 0,
            rate_limit_api_poll_window: parseInt(document.getElementById('setting-rate-limit-api-poll-window').value) || 0,
            
            // Storage
            // Blank -> 0 (unlimited); the backend enforces a positive value and ignores 0.
            default_user_quota: parseInt(document.getElementById('setting-default-quota').value) || 0,
            max_vault_size: parseInt(document.getElementById('setting-max-vault-size').value) || 0,
            // The deployment limit is the one field where 0 is a real answer (accept no more
            // bytes), so blank must send null — "run at the deployment maximum" — rather than
            // collapsing to 0 the way the two quotas above do.
            deployment_storage_limit_gb: (function () {
                const raw = (document.getElementById('setting-deployment-storage') || {}).value;
                if (raw === undefined || raw === null || String(raw).trim() === '') return null;
                const n = Number(raw);
                return Number.isFinite(n) ? n : null;
            })(),

            // Email SMTP config now lives in sending profiles (Settings → Email), managed on their
            // own, so it is no longer part of the central settings save.

            // SFTP & Encryption
            zero_knowledge_enabled: document.getElementById('setting-zero-knowledge-enabled').checked,
            force_zero_knowledge: document.getElementById('setting-force-zero-knowledge').checked,
            directory_search_scope: (document.getElementById('setting-directory-search-scope') || {}).value || 'deployment',
            force_no_remember_vault_password: document.getElementById('setting-force-no-remember-vault-password').checked,
            zk_idle_lock_minutes: parseInt(document.getElementById('setting-zk-idle-lock-minutes').value) || 0,

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

        // Sharing master switch (the per-tag policy lives in the Share Tags manager, not here)
        const shEnEl = document.getElementById('setting-sharing-enabled');
        if (shEnEl) settings.sharing_enabled = shEnEl.checked;

        // Note Links master switch + per-user cap (tag policy lives in the Note-link tag manager)
        const nlEnEl = document.getElementById('setting-public-note-links-enabled');
        if (nlEnEl) settings.public_note_links_enabled = nlEnEl.checked;
        const nlCapEl = document.getElementById('setting-public-note-link-user-cap');
        if (nlCapEl && nlCapEl.value !== '') settings.public_note_link_user_cap = parseInt(nlCapEl.value, 10);
        const nMaxEl = document.getElementById('setting-note-max-chars');
        if (nMaxEl && nMaxEl.value !== '') settings.note_max_chars = parseInt(nMaxEl.value, 10);

        // Accounts & Access: the org-onboarding policy block.
        collectAccountsPolicy(settings);

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

// ---- Share Tags manager (admin Settings -> Sharing) ------------------------
// The per-tag policy + create-allowlist backing the Sharing feature. The list is rendered
// from GET /share-tags; add/edit/deactivate go through the interactive-admin /share-tags CRUD.
// This editor covers the policy, the audiences, and the DEPARTMENT allowlist + auto-enroll;
// the per-user allow/block lists are managed separately. All controls build via DOM (no innerHTML).
let shareTagsCache = [];
let shareTagEditorDeptIds = [];
let shareTagEditorAllowUserIds = [];
let shareTagEditorBlockUserIds = [];
let shareTagUsersById = {};          // id -> username, for rendering the user chips
let shareTagsUIWired = false;
const _tagUserSearchTimer = { allow: null, block: null };
const _tagUserSearchSeq = { allow: 0, block: 0 };
const _tagUserActive = { allow: -1, block: -1 };   // highlighted option index per picker (combobox keyboard nav)

// Combobox helpers for the allowed/blocked user-search autocompletes.
function _collapseTagUser(kind) {
    const { search } = _tagUserPickerIds(kind);
    const input = _stEl(search);
    _tagUserActive[kind] = -1;
    if (input) { input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); }
}
function _setTagUserActive(kind, idx) {
    const { search, results } = _tagUserPickerIds(kind);
    const host = _stEl(results), input = _stEl(search);
    const opts = host ? Array.from(host.querySelectorAll('[role="option"]')) : [];
    _tagUserActive[kind] = idx;
    opts.forEach((o, i) => o.setAttribute('aria-selected', i === idx ? 'true' : 'false'));
    if (input) {
        if (idx >= 0 && opts[idx]) { input.setAttribute('aria-activedescendant', opts[idx].id); opts[idx].scrollIntoView({ block: 'nearest' }); }
        else input.removeAttribute('aria-activedescendant');
    }
}
function _tagUserKeydown(kind, e) {
    const { search, results } = _tagUserPickerIds(kind);
    const host = _stEl(results);
    const opts = host ? Array.from(host.querySelectorAll('[role="option"]')) : [];
    if (e.key === 'Escape') { if (host) host.replaceChildren(); _collapseTagUser(kind); return; }
    if (!opts.length) return;
    const cur = _tagUserActive[kind];   // -1 = no selection yet
    if (e.key === 'ArrowDown') { e.preventDefault(); _setTagUserActive(kind, cur >= opts.length - 1 ? 0 : cur + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); _setTagUserActive(kind, cur <= 0 ? opts.length - 1 : cur - 1); }
    else if (e.key === 'Enter') { const i = _tagUserActive[kind]; if (i >= 0 && opts[i]) { e.preventDefault(); opts[i].click(); } }
}

function _stEl(id) { return document.getElementById(id); }
function _stChecked(id) { const e = _stEl(id); return !!(e && e.checked); }
function _stNumOrNull(id) {
    const e = _stEl(id);
    if (!e || e.value === '' || e.value == null) return null;
    const n = parseInt(e.value, 10);
    return Number.isFinite(n) ? n : null;
}

// Keep the view-only DEFAULT consistent with whether view-only is ALLOWED (mirrors the backend
// invariant default_view_only requires allow_view_only) so the admin can't submit the invalid pair.
function _stSyncViewOnly() {
    const allow = _stEl('share-tag-allow-view-only');
    const def = _stEl('share-tag-default-view-only');
    const force = _stEl('share-tag-force-view-only');
    if (!allow) return;
    // Forcing view-only requires allowing it — checking force auto-enables allow (mirrors the backend
    // invariant force_view_only requires allow_view_only), so the admin can't submit the invalid pair.
    if (force && force.checked && !allow.checked) allow.checked = true;
    if (def) { if (!allow.checked) def.checked = false; def.disabled = !allow.checked; }
    if (force) force.disabled = !allow.checked;
}

function setupShareTagsUI() {
    if (shareTagsUIWired) return;
    const add = _stEl('share-tag-add-btn');
    const save = _stEl('share-tag-save-btn');
    const cancel = _stEl('share-tag-cancel-btn');
    if (!add || !save || !cancel) return;  // sharing tab markup not present
    add.addEventListener('click', () => openShareTagEditor(null));
    save.addEventListener('click', saveShareTag);
    cancel.addEventListener('click', closeShareTagEditor);
    const allowVO = _stEl('share-tag-allow-view-only');
    if (allowVO) allowVO.addEventListener('change', _stSyncViewOnly);
    const forceVO = _stEl('share-tag-force-view-only');
    if (forceVO) forceVO.addEventListener('change', _stSyncViewOnly);
    const allowSearch = _stEl('share-tag-allow-user-search');
    if (allowSearch) {
        allowSearch.addEventListener('input', () => {
            clearTimeout(_tagUserSearchTimer.allow);
            _tagUserSearchTimer.allow = setTimeout(() => _tagUserSearch('allow'), 250);
        });
        allowSearch.addEventListener('keydown', (e) => _tagUserKeydown('allow', e));
    }
    const blockSearch = _stEl('share-tag-block-user-search');
    if (blockSearch) {
        blockSearch.addEventListener('input', () => {
            clearTimeout(_tagUserSearchTimer.block);
            _tagUserSearchTimer.block = setTimeout(() => _tagUserSearch('block'), 250);
        });
        blockSearch.addEventListener('keydown', (e) => _tagUserKeydown('block', e));
    }
    shareTagsUIWired = true;
}

async function loadShareTags() {
    const host = _stEl('share-tags-list');
    if (!host) return;
    try {
        const tags = await apiRequest('/share-tags', { silent: true });
        shareTagsCache = Array.isArray(tags) ? tags : [];
    } catch (_) {
        shareTagsCache = [];
    }
    renderShareTagsList();
}

function renderShareTagsList() {
    const host = _stEl('share-tags-list');
    if (!host) return;
    host.replaceChildren();
    if (!shareTagsCache.length) {
        const empty = document.createElement('p');
        empty.className = 'text-tertiary text-sm';
        empty.textContent = 'No share tags yet. Add one to let users create shares.';
        host.appendChild(empty);
        return;
    }
    shareTagsCache.slice().sort((a, b) => a.name.localeCompare(b.name)).forEach(tag => {
        const row = document.createElement('div');
        row.className = 'share-tag-row flex justify-between items-center mb-sm';
        row.setAttribute('data-tag-id', tag.id);

        const left = document.createElement('div');
        const title = document.createElement('span');
        title.className = 'font-medium';
        title.textContent = tag.name;
        left.appendChild(title);
        const badge = document.createElement('span');
        badge.className = 'chip ml-sm';
        badge.textContent = tag.is_active ? 'active' : 'inactive';
        left.appendChild(badge);
        const summary = document.createElement('div');
        summary.className = 'text-tertiary text-sm';
        const parts = [
            `lifetime max ${tag.max_lifetime_minutes}m (default ${tag.default_lifetime_minutes}m)`,
            `recipients ${tag.max_recipients_cap == null ? '∞' : tag.max_recipients_cap}`,
            `downloads ${tag.max_downloads_cap == null ? '∞' : tag.max_downloads_cap}`,
        ];
        if (Array.isArray(tag.allowed_audiences) && tag.allowed_audiences.length) {
            parts.push(`audiences: ${tag.allowed_audiences.join(', ')}`);
        }
        if (tag.force_view_only) parts.push('view-only forced');
        else if (tag.default_view_only) parts.push('view-only default');
        if (tag.auto_enroll_new_users) parts.push('everyone (except blocked)');
        summary.textContent = parts.join(' · ');
        left.appendChild(summary);
        row.appendChild(left);

        const actions = document.createElement('div');
        actions.className = 'flex gap-sm';
        const edit = document.createElement('button');
        edit.type = 'button';
        edit.className = 'btn btn-secondary';
        edit.textContent = 'Edit';
        edit.addEventListener('click', () => openShareTagEditor(tag));
        actions.appendChild(edit);
        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'btn btn-secondary';
        toggle.textContent = tag.is_active ? 'Deactivate' : 'Reactivate';
        toggle.addEventListener('click', () => (tag.is_active ? deactivateShareTag(tag.id) : reactivateShareTag(tag.id)));
        actions.appendChild(toggle);
        row.appendChild(actions);

        host.appendChild(row);
    });
}

function renderShareTagDeptPicker() {
    _renderGroupPickerInto(
        'share-tag-dept-picker',
        () => shareTagEditorDeptIds,
        v => { shareTagEditorDeptIds = v; },
        'No departments selected',
        renderShareTagDeptPicker,
        'share-tag-dept-add',
        'share-tag-dept-remove'
    );
}

// Per-user create-allowlist pickers (allowed_user_ids / blocked_user_ids). Search is server-side
// (/users/search, scoped + rate-limited); the admin /users list is fetched once only to resolve the
// stored ids of an existing tag into usernames for the chips. All rendering is textContent/DOM.
async function loadShareTagUsers() {
    try {
        const users = await apiRequest('/users', { silent: true });
        (Array.isArray(users) ? users : []).forEach(u => {
            shareTagUsersById[u.id] = u.username || u.email || String(u.id).slice(0, 8);
        });
    } catch (_) { /* names fall back to the id */ }
}

function _tagUserName(id) { return shareTagUsersById[id] || String(id).slice(0, 8); }

function _renderTagUserChips(chipsId, ids, onRemove) {
    const host = _stEl(chipsId);
    if (!host) return;
    host.replaceChildren();
    if (!ids.length) {
        const none = document.createElement('span');
        none.className = 'text-tertiary text-sm';
        none.textContent = 'None';
        host.appendChild(none);
        return;
    }
    ids.forEach(id => {
        const chip = document.createElement('span');
        chip.className = 'chip';
        chip.append(_tagUserName(id));
        const rm = document.createElement('button');
        rm.type = 'button';
        rm.className = 'chip-remove';
        rm.setAttribute('aria-label', `Remove ${_tagUserName(id)}`);
        rm.appendChild(svgUseIcon('x', 'icon-sm'));
        rm.addEventListener('click', () => onRemove(id));
        chip.appendChild(rm);
        host.appendChild(chip);
    });
}

function _renderTagAllowChips() {
    _renderTagUserChips('share-tag-allow-user-chips', shareTagEditorAllowUserIds, id => {
        shareTagEditorAllowUserIds = shareTagEditorAllowUserIds.filter(x => x !== id);
        _renderTagAllowChips();
    });
}
function _renderTagBlockChips() {
    _renderTagUserChips('share-tag-block-user-chips', shareTagEditorBlockUserIds, id => {
        shareTagEditorBlockUserIds = shareTagEditorBlockUserIds.filter(x => x !== id);
        _renderTagBlockChips();
    });
}

function _tagUserPickerIds(kind) {
    return {
        search: kind === 'allow' ? 'share-tag-allow-user-search' : 'share-tag-block-user-search',
        results: kind === 'allow' ? 'share-tag-allow-user-results' : 'share-tag-block-user-results',
    };
}

function _tagUserSearch(kind) {
    const { search, results } = _tagUserPickerIds(kind);
    const seq = ++_tagUserSearchSeq[kind];
    const host = _stEl(results);
    if (!host) return;
    const q = (_stEl(search)?.value || '').trim();
    if (q.length < 2) { host.replaceChildren(); _collapseTagUser(kind); return; }
    apiRequest(`/users/search?q=${encodeURIComponent(q)}`, { silent: true }).then(users => {
        if (seq !== _tagUserSearchSeq[kind]) return;  // a newer keystroke superseded this one
        _renderTagUserResults(kind, Array.isArray(users) ? users : []);
    }).catch(() => {
        if (seq !== _tagUserSearchSeq[kind]) return;
        host.replaceChildren();
    });
}

function _renderTagUserResults(kind, users) {
    const { search, results } = _tagUserPickerIds(kind);
    const host = _stEl(results), input = _stEl(search);
    if (!host) return;
    host.replaceChildren();
    _tagUserActive[kind] = -1;
    if (input) input.removeAttribute('aria-activedescendant');
    const already = kind === 'allow' ? shareTagEditorAllowUserIds : shareTagEditorBlockUserIds;
    const fresh = users.filter(u => !already.includes(u.id));
    if (!fresh.length) {
        const none = document.createElement('div');
        none.className = 'text-tertiary text-sm';
        none.textContent = 'No matching users.';
        host.appendChild(none);
        if (input) input.setAttribute('aria-expanded', 'true');   // listbox is shown (with a message)
        return;
    }
    fresh.forEach((u, i) => {
        shareTagUsersById[u.id] = u.username || u.email || String(u.id).slice(0, 8);
        const row = document.createElement('button');
        row.type = 'button';
        row.id = `${results}-opt-${i}`;
        row.setAttribute('role', 'option');
        row.setAttribute('aria-selected', 'false');
        row.className = 'pick-row';
        row.style.width = '100%';
        row.style.textAlign = 'left';
        row.textContent = u.username || u.email || u.id;
        row.addEventListener('click', () => _addTagUser(kind, u.id));
        host.appendChild(row);
    });
    if (input) input.setAttribute('aria-expanded', 'true');
}

function _addTagUser(kind, id) {
    // allowed and blocked are mutually exclusive in the editor (the backend blocklist wins regardless).
    shareTagEditorAllowUserIds = shareTagEditorAllowUserIds.filter(x => x !== id);
    shareTagEditorBlockUserIds = shareTagEditorBlockUserIds.filter(x => x !== id);
    if (kind === 'allow') shareTagEditorAllowUserIds.push(id);
    else shareTagEditorBlockUserIds.push(id);
    _renderTagAllowChips();
    _renderTagBlockChips();
    const { search, results } = _tagUserPickerIds(kind);
    if (_stEl(search)) _stEl(search).value = '';
    if (_stEl(results)) _stEl(results).replaceChildren();
    _collapseTagUser(kind);
}

// Reflect a stored tag colour (a CHIP_COLORS name, a #hex, or '') onto the swatch picker:
// set the hidden #share-tag-color the save path reads, highlight the matching swatch, and seed
// the custom picker from a hex value. Mirrors setGroupColor.
function setShareTagColor(color) {
    const hidden = _stEl('share-tag-color');
    if (hidden) hidden.value = color || '';
    document.querySelectorAll('#share-tag-color-swatches .accent-swatch').forEach(s => {
        s.classList.toggle('selected', (s.getAttribute('data-color') || '') === (color || ''));
    });
    const custom = _stEl('share-tag-color-custom');
    if (custom && color && color.charAt(0) === '#') custom.value = color;
}

// "(~N days)" hint for a minutes value (blank/<=0 => no hint). 1440 -> "~1 day", 10080 -> "~7 days".
function shareTagDaysHint(minutes) {
    const m = parseInt(minutes, 10);
    if (!m || m <= 0) return '';
    const days = m / 1440;
    const n = days < 10 ? Math.round(days * 10) / 10 : Math.round(days);
    if (n <= 0) return '(< 1 day)';   // sub-day lifetime — avoid a misleading "~0 days"
    return `(~${n} day${n === 1 ? '' : 's'})`;
}

// Refresh the live day hints beside the Lifetime maximum + default inputs.
function updateShareTagLifetimeHints() {
    [['share-tag-max-lifetime', 'share-tag-max-lifetime-days'],
     ['share-tag-default-lifetime', 'share-tag-default-lifetime-days']].forEach(([inId, hintId]) => {
        const hint = _stEl(hintId), input = _stEl(inId);
        if (hint) hint.textContent = shareTagDaysHint(input ? input.value : '');
    });
}

function openShareTagEditor(tag) {
    const editor = _stEl('share-tag-editor');
    if (!editor) return;
    const t = tag || {};
    _stEl('share-tag-editor-title').textContent = tag ? 'Edit tag' : 'Add tag';
    _stEl('share-tag-editor-id').value = tag ? t.id : '';
    _stEl('share-tag-name').value = t.name || '';
    _stEl('share-tag-description').value = t.description || '';
    setShareTagColor(t.color || '');
    _stEl('share-tag-max-lifetime').value = t.max_lifetime_minutes != null ? t.max_lifetime_minutes : 10080;
    _stEl('share-tag-default-lifetime').value = t.default_lifetime_minutes != null ? t.default_lifetime_minutes : 1440;
    updateShareTagLifetimeHints();
    const _stErr = _stEl('share-tag-editor-error');
    if (_stErr) { _stErr.textContent = ''; _stErr.style.display = 'none'; }
    _stEl('share-tag-max-recipients-cap').value = t.max_recipients_cap != null ? t.max_recipients_cap : '';
    _stEl('share-tag-max-recipients-default').value = t.max_recipients_default != null ? t.max_recipients_default : '';
    _stEl('share-tag-max-downloads-cap').value = t.max_downloads_cap != null ? t.max_downloads_cap : '';
    _stEl('share-tag-max-downloads-default').value = t.max_downloads_default != null ? t.max_downloads_default : '';
    const aud = Array.isArray(t.allowed_audiences) ? t.allowed_audiences
        : (tag ? [] : ['users', 'departments', 'anyone_internal']);
    _stEl('share-tag-aud-users').checked = aud.includes('users');
    _stEl('share-tag-aud-departments').checked = aud.includes('departments');
    _stEl('share-tag-aud-anyone').checked = aud.includes('anyone_internal');
    _stEl('share-tag-allow-view-only').checked = tag ? !!t.allow_view_only : true;
    _stEl('share-tag-default-view-only').checked = !!t.default_view_only;
    _stEl('share-tag-force-view-only').checked = !!t.force_view_only;
    _stEl('share-tag-allow-custom').checked = tag ? !!t.allow_custom : true;
    _stEl('share-tag-auto-enroll').checked = !!t.auto_enroll_new_users;
    shareTagEditorDeptIds = (t.allowed_department_ids || []).map(String);
    renderShareTagDeptPicker();
    shareTagEditorAllowUserIds = (t.allowed_user_ids || []).map(String);
    shareTagEditorBlockUserIds = (t.blocked_user_ids || []).map(String);
    ['share-tag-allow-user-search', 'share-tag-block-user-search'].forEach(id => { if (_stEl(id)) _stEl(id).value = ''; });
    ['share-tag-allow-user-results', 'share-tag-block-user-results'].forEach(id => { if (_stEl(id)) _stEl(id).replaceChildren(); });
    _collapseTagUser('allow'); _collapseTagUser('block');   // clear stale aria-expanded / aria-activedescendant on reopen
    _renderTagAllowChips();
    _renderTagBlockChips();
    // resolve the stored ids of an existing tag into usernames (fetch the admin user list once)
    if (shareTagEditorAllowUserIds.length || shareTagEditorBlockUserIds.length) {
        loadShareTagUsers().then(() => { _renderTagAllowChips(); _renderTagBlockChips(); });
    }
    _stSyncViewOnly();
    editor.style.display = '';
    editor.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function closeShareTagEditor() {
    const editor = _stEl('share-tag-editor');
    if (editor) editor.style.display = 'none';
}

async function saveShareTag() {
    const id = _stEl('share-tag-editor-id').value;
    const aud = [];
    if (_stChecked('share-tag-aud-users')) aud.push('users');
    if (_stChecked('share-tag-aud-departments')) aud.push('departments');
    if (_stChecked('share-tag-aud-anyone')) aud.push('anyone_internal');
    // Validate client-side with inline errors — no server round-trip on an obvious mistake, and
    // NEVER coerce an empty/0 lifetime to 1 (the old `|| 1` silently expired every share in a minute).
    const _err = _stEl('share-tag-editor-error');
    const _fail = (msg, focusId) => {
        if (_err) { _err.textContent = msg; _err.style.display = ''; }
        if (focusId && _stEl(focusId)) _stEl(focusId).focus();
        return true;
    };
    if (_err) { _err.textContent = ''; _err.style.display = 'none'; }
    const name = _stEl('share-tag-name').value.trim();
    const maxLife = _stNumOrNull('share-tag-max-lifetime');
    const defLife = _stNumOrNull('share-tag-default-lifetime');
    const maxRcp = _stNumOrNull('share-tag-max-recipients-cap');
    const defRcp = _stNumOrNull('share-tag-max-recipients-default');
    const maxDl = _stNumOrNull('share-tag-max-downloads-cap');
    const defDl = _stNumOrNull('share-tag-max-downloads-default');
    if (!name && _fail('A tag name is required.', 'share-tag-name')) return;
    if ((!maxLife || maxLife < 1) && _fail('Maximum lifetime must be at least 1 minute.', 'share-tag-max-lifetime')) return;
    if ((!defLife || defLife < 1) && _fail('Default lifetime must be at least 1 minute.', 'share-tag-default-lifetime')) return;
    if (defLife > maxLife && _fail('Default lifetime cannot exceed the maximum.', 'share-tag-default-lifetime')) return;
    if (maxRcp != null && defRcp != null && defRcp > maxRcp && _fail('Default recipients cannot exceed the maximum.', 'share-tag-max-recipients-default')) return;
    if (maxDl != null && defDl != null && defDl > maxDl && _fail('Default downloads cannot exceed the maximum.', 'share-tag-max-downloads-default')) return;
    const body = {
        name: name,
        description: _stEl('share-tag-description').value.trim() || null,
        color: _stEl('share-tag-color').value.trim() || null,
        max_lifetime_minutes: maxLife,
        default_lifetime_minutes: defLife,
        max_recipients_cap: maxRcp,
        max_recipients_default: defRcp,
        max_downloads_cap: maxDl,
        max_downloads_default: defDl,
        allowed_audiences: aud,
        allow_view_only: _stChecked('share-tag-allow-view-only'),
        default_view_only: _stChecked('share-tag-default-view-only'),
        force_view_only: _stChecked('share-tag-force-view-only'),
        allow_custom: _stChecked('share-tag-allow-custom'),
        auto_enroll_new_users: _stChecked('share-tag-auto-enroll'),
        allowed_department_ids: shareTagEditorDeptIds.slice(),
        allowed_user_ids: shareTagEditorAllowUserIds.slice(),
        blocked_user_ids: shareTagEditorBlockUserIds.slice(),
    };
    try {
        if (id) {
            await apiRequest(`/share-tags/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
            showSuccess('Tag updated');
        } else {
            await apiRequest('/share-tags', { method: 'POST', body: JSON.stringify(body) });
            showSuccess('Tag created');
        }
        closeShareTagEditor();
        await loadShareTags();
    } catch (error) {
        showError('Could not save tag: ' + (error && error.message ? error.message : 'unknown error'));
    }
}

async function deactivateShareTag(id) {
    try {
        await apiRequest(`/share-tags/${id}`, { method: 'DELETE' });
        showSuccess('Tag deactivated');
        await loadShareTags();
    } catch (error) {
        showError('Could not deactivate tag: ' + (error && error.message ? error.message : 'unknown error'));
    }
}

async function reactivateShareTag(id) {
    try {
        await apiRequest(`/share-tags/${id}`, { method: 'PATCH', body: JSON.stringify({ is_active: true }) });
        showSuccess('Tag reactivated');
        await loadShareTags();
    } catch (error) {
        showError('Could not reactivate tag: ' + (error && error.message ? error.message : 'unknown error'));
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

const GIB_BYTES = 1024 ** 3;

// The deployment storage limit is a BOUNDED control, not a free-text number: the input's max is
// the deployment's own ceiling (MAX_STORAGE_GB) and the label says what that ceiling is, so an
// admin can see the room they have instead of being told to type -1 for "unlimited".
function renderDeploymentStorageSetting(settings) {
    const input = document.getElementById('setting-deployment-storage');
    const maxLabel = document.getElementById('setting-deployment-storage-max');
    const help = document.getElementById('setting-deployment-storage-help');
    const bar = document.getElementById('deployment-storage-bar-fill');
    if (!input) return;

    const maxGb = settings.deployment_storage_max_gb;   // null => no deployment ceiling
    const limitBytes = settings.deployment_storage_limit_bytes;
    const usedBytes = settings.deployment_storage_used_bytes || 0;

    if (maxGb > 0) {
        input.max = String(maxGb);
        if (maxLabel) maxLabel.textContent = `of ${maxGb} GB maximum`;
    } else {
        input.removeAttribute('max');
        if (maxLabel) maxLabel.textContent = 'no deployment maximum configured';
    }
    // Blank means "run at the deployment maximum"; a saved number is shown as saved, including 0.
    const saved = settings.deployment_storage_limit_gb;
    input.value = (saved === null || saved === undefined || saved === '') ? '' : saved;
    input.placeholder = maxGb > 0 ? String(maxGb) : 'Unlimited';

    if (bar) {
        const pct = (limitBytes > 0) ? Math.min(100, (usedBytes / limitBytes) * 100) : 0;
        bar.style.width = `${pct}%`;
        bar.classList.toggle('is-danger', pct >= 90);
    }
    if (help) {
        const limitText = (limitBytes === null || limitBytes === undefined)
            ? 'no limit' : formatBytes(limitBytes);
        help.textContent =
            `${formatBytes(usedBytes)} stored of ${limitText}. Only files actually stored count `
            + 'toward this — empty vaults cost nothing. '
            + (maxGb > 0
                ? `Blank runs at the ${maxGb} GB deployment maximum; 0 stops new uploads.`
                : 'Blank means unlimited; 0 stops new uploads.');
    }
}

// Load storage statistics
async function loadStorageStats() {
    try {
        const stats = await apiRequest('/storage/stats', { silent: true });

        document.getElementById('storage-stat-total').textContent = formatBytes(stats.total || 0);
        document.getElementById('storage-stat-used').textContent = formatBytes(stats.used || 0);
        document.getElementById('storage-stat-available').textContent = formatBytes(stats.available || 0);
        const allocated = document.getElementById('storage-stat-allocated');
        if (allocated) {
            // Allocated is reported, never enforced against the deployment limit: vaults may
            // promise more than the disk holds because most of that promise is never filled.
            allocated.textContent =
                `${formatBytes(stats.allocated_bytes || 0)} allocated across ${stats.vault_count || 0} vault(s)`
                + (stats.limit_bytes ? ` · limit ${formatBytes(stats.limit_bytes)}` : '');
        }
    } catch (error) {
        console.log('Storage stats endpoint not available');
        // Show defaults
        document.getElementById('storage-stat-total').textContent = 'N/A';
        document.getElementById('storage-stat-used').textContent = 'N/A';
        document.getElementById('storage-stat-available').textContent = 'N/A';
    }
}

// Test email configuration
// ============================================================================
// Email Studio — sending profiles (Settings → Email)
// ============================================================================
let _editingEmailProfileId = null;

async function loadEmailProfiles() {
    const grid = document.getElementById('email-profiles-grid');
    if (!grid) return;
    try {
        const data = await apiRequest('/email/profiles', { silent: true });
        renderEmailProfilesGrid((data && data.profiles) || []);
    } catch (e) {
        grid.replaceChildren();
        const err = document.createElement('div');
        err.className = 'text-sm text-secondary';
        err.textContent = 'Could not load sending profiles.';
        grid.appendChild(err);
    }
}

function renderEmailProfilesGrid(profiles) {
    const grid = document.getElementById('email-profiles-grid');
    if (!grid) return;
    grid.replaceChildren();
    profiles.forEach(p => grid.appendChild(buildEmailProfileCard(p)));
    const add = document.createElement('button');
    add.type = 'button';
    add.className = 'email-card-add';
    add.id = 'email-profile-add';
    add.textContent = '+ Create profile';
    add.addEventListener('click', () => openEmailProfileModal(null));
    grid.appendChild(add);
}

function buildEmailProfileCard(p) {
    const card = document.createElement('div');
    card.className = 'email-profile-card';
    card.setAttribute('role', 'listitem');
    card.dataset.profileId = p.id;

    const title = document.createElement('div');
    title.className = 'epc-title';
    const name = document.createElement('span');
    name.textContent = p.name || '(untitled)';
    title.appendChild(name);
    if (p.is_default) {
        const badge = document.createElement('span');
        badge.className = 'epc-badge';
        badge.textContent = 'Default';
        title.appendChild(badge);
    }
    card.appendChild(title);

    const desc = document.createElement('div');
    desc.className = 'epc-desc';
    desc.textContent = p.description || '';
    card.appendChild(desc);

    const meta = document.createElement('div');
    meta.className = 'epc-meta';
    meta.textContent = [p.from_email, p.smtp_server].filter(Boolean).join(' · ');
    card.appendChild(meta);

    const actions = document.createElement('div');
    actions.className = 'epc-actions';
    const edit = document.createElement('button');
    edit.type = 'button';
    edit.className = 'btn btn-secondary btn-sm epc-edit';
    edit.textContent = 'Edit';
    edit.addEventListener('click', () => openEmailProfileModal(p));
    actions.appendChild(edit);
    const del = document.createElement('button');
    del.type = 'button';
    del.className = 'btn btn-secondary btn-sm epc-delete';
    del.textContent = 'Delete';
    del.addEventListener('click', () => deleteEmailProfile(p));
    actions.appendChild(del);
    card.appendChild(actions);
    return card;
}

function openEmailProfileModal(profile) {
    _editingEmailProfileId = profile ? profile.id : null;
    document.getElementById('email-profile-modal-title').textContent =
        profile ? 'Edit sending profile' : 'New sending profile';
    const val = (id, v) => { document.getElementById(id).value = v; };
    val('ep-name', profile ? (profile.name || '') : '');
    val('ep-description', profile ? (profile.description || '') : '');
    val('ep-server', profile ? (profile.smtp_server || '') : '');
    val('ep-port', profile ? (profile.smtp_port || 587) : 587);
    val('ep-username', profile ? (profile.smtp_username || '') : '');
    val('ep-password', '');
    val('ep-from-email', profile ? (profile.from_email || '') : '');
    val('ep-from-name', profile ? (profile.from_name || '') : '');
    document.getElementById('ep-default').checked = profile ? !!profile.is_default : false;
    document.getElementById('ep-insecure-tls').checked = profile ? !!profile.smtp_allow_insecure_tls : false;
    document.getElementById('ep-password-hint').textContent =
        (profile && profile.has_password) ? 'Password is set — leave blank to keep it'
                                          : 'Enter a password if your server requires authentication';
    const result = document.getElementById('email-profile-result');
    result.textContent = '';
    document.getElementById('email-profile-modal').classList.add('active');
    document.getElementById('ep-name').focus();
}

function closeEmailProfileModal() {
    document.getElementById('email-profile-modal').classList.remove('active');
    _editingEmailProfileId = null;
}

function _collectEmailProfileForm() {
    const g = id => document.getElementById(id).value;
    const body = {
        name: g('ep-name').trim(),
        description: g('ep-description').trim() || null,
        smtp_server: g('ep-server').trim(),
        smtp_port: parseInt(g('ep-port')) || 587,
        smtp_username: g('ep-username').trim() || null,
        from_email: g('ep-from-email').trim(),
        from_name: g('ep-from-name').trim() || null,
        is_default: document.getElementById('ep-default').checked,
        smtp_allow_insecure_tls: document.getElementById('ep-insecure-tls').checked,
    };
    const pw = g('ep-password');
    if (pw) body.smtp_password = pw;
    return body;
}

async function saveEmailProfile() {
    const btn = document.getElementById('ep-save');
    const result = document.getElementById('email-profile-result');
    const body = _collectEmailProfileForm();
    try {
        btn.disabled = true;
        if (_editingEmailProfileId) {
            await apiRequest('/email/profiles/' + _editingEmailProfileId,
                             { method: 'PUT', body: JSON.stringify(body) });
        } else {
            await apiRequest('/email/profiles', { method: 'POST', body: JSON.stringify(body) });
        }
        closeEmailProfileModal();
        await loadEmailProfiles();
        showSuccess('Sending profile saved');
    } catch (e) {
        result.textContent = '✗ ' + (e.message || 'Save failed');
        result.style.color = 'var(--error)';
    } finally {
        btn.disabled = false;
    }
}

async function sendEmailProfileTest() {
    const btn = document.getElementById('ep-send-test');
    const result = document.getElementById('email-profile-result');
    const body = _collectEmailProfileForm();   // send WITHOUT saving
    const payload = {
        profile_id: _editingEmailProfileId || null,   // use the stored password when the field is blank
        smtp_server: body.smtp_server, smtp_port: body.smtp_port,
        smtp_username: body.smtp_username || '', from_email: body.from_email,
        from_name: body.from_name || '',
    };
    if (body.smtp_password) payload.smtp_password = body.smtp_password;
    try {
        btn.disabled = true;
        result.textContent = 'Sending test…';
        result.style.color = 'var(--text-secondary)';
        const r = await apiRequest('/email/profiles/test', { method: 'POST', body: JSON.stringify(payload) });
        result.textContent = '✓ ' + ((r && r.message) || 'Test email sent');
        result.style.color = 'var(--success)';
    } catch (e) {
        result.textContent = '✗ ' + (e.message || 'Test failed');
        result.style.color = 'var(--error)';
    } finally {
        btn.disabled = false;
    }
}

async function deleteEmailProfile(p) {
    if (!confirm('Delete the sending profile "' + (p.name || '') +
                 '"? Templates using it will fall back to the default.')) return;
    try {
        await apiRequest('/email/profiles/' + p.id, { method: 'DELETE' });
        await loadEmailProfiles();
        showSuccess('Sending profile deleted');
    } catch (e) {
        showError('Could not delete profile: ' + (e.message || ''));
    }
}

// ============================================================================
// Email Studio — templates (grid + inline code/render/split editor + send)
// ============================================================================
let _editingTemplateId = null;
let _sendTemplateId = null;
let _etPreviewTimer = null;
let _loadFromDefaults = null;   // cached GET /email/default-templates payload

async function loadEmailTemplates() {
    const grid = document.getElementById('email-templates-grid');
    if (!grid) return;
    try {
        const data = await apiRequest('/email/templates', { silent: true });
        renderEmailTemplatesGrid((data && data.templates) || []);
    } catch (e) {
        grid.replaceChildren();
    }
}

function renderEmailTemplatesGrid(templates) {
    const grid = document.getElementById('email-templates-grid');
    if (!grid) return;
    grid.replaceChildren();
    templates.forEach(t => grid.appendChild(buildEmailTemplateCard(t)));
    const add = document.createElement('button');
    add.type = 'button'; add.className = 'email-card-add'; add.id = 'email-template-add';
    add.textContent = '+ Create template';
    add.addEventListener('click', () => openTemplateEditor(null));
    grid.appendChild(add);
}

function buildEmailTemplateCard(t) {
    const card = document.createElement('div');
    card.className = 'email-profile-card'; card.setAttribute('role', 'listitem'); card.dataset.templateId = t.id;
    const title = document.createElement('div'); title.className = 'epc-title';
    const name = document.createElement('span'); name.textContent = t.name || '(untitled)'; title.appendChild(name);
    if (t.is_default) {
        const db = document.createElement('span');
        db.className = 'epc-badge epc-badge-default'; db.textContent = 'Default';
        db.title = 'A built-in default template. Edit it to customize; use “Load From” to reset it.';
        title.appendChild(db);
    }
    if (t.bound_action) {
        const isSys = t.bound_action.category === 'system';
        const badge = document.createElement('span');
        badge.className = 'epc-badge ' + (isSys ? 'epc-badge-system' : 'epc-badge-inuse');
        badge.textContent = isSys ? 'System' : 'In use';
        badge.title = 'Used by the ' + (isSys ? 'system' : 'automated') + ' email “' + t.bound_action.name +
            '” — change that action first to delete this template.';
        title.appendChild(badge);
    }
    card.appendChild(title);
    const desc = document.createElement('div'); desc.className = 'epc-desc'; desc.textContent = t.description || ''; card.appendChild(desc);
    const meta = document.createElement('div'); meta.className = 'epc-meta';
    if (t.profile) {
        const parts = [t.profile.from_email, t.profile.smtp_server].filter(Boolean).join(' · ');
        meta.textContent = 'via ' + parts + (t.profile.from_name ? ' (' + t.profile.from_name + ')' : '');
    } else {
        meta.textContent = 'No sending profile assigned';
    }
    card.appendChild(meta);
    const actions = document.createElement('div'); actions.className = 'epc-actions';
    const rowDefs = [['Edit', 'etc-edit', () => openTemplateEditor(t)],
                     ['Send', 'etc-send', () => openSendModal(t)]];
    // Non-removable when bound to an action OR a built-in default (both refuse deletion server-side).
    if (!t.bound_action && !t.is_default) rowDefs.push(['Delete', 'etc-delete', () => deleteTemplate(t)]);
    for (const [label, cls, fn] of rowDefs) {
        const b = document.createElement('button'); b.type = 'button';
        b.className = 'btn btn-secondary btn-sm ' + cls; b.textContent = label;
        b.addEventListener('click', fn); actions.appendChild(b);
    }
    card.appendChild(actions);
    return card;
}

// ---- Automated emails (actions) ------------------------------------------------------------------
async function loadEmailActions() {
    const list = document.getElementById('email-actions-list');
    if (!list) return;
    try {
        const [actions, templates] = await Promise.all([
            apiRequest('/email/actions', { silent: true }),
            apiRequest('/email/templates', { silent: true }),
        ]);
        renderEmailActions((actions && actions.actions) || [], (templates && templates.templates) || []);
    } catch (e) { list.replaceChildren(); }
}

function renderEmailActions(actions, templates) {
    const list = document.getElementById('email-actions-list');
    list.replaceChildren();
    actions.forEach(a => list.appendChild(buildActionRow(a, templates)));
}

function _earNotifyLabel(cb) {
    if (cb.checked) return 'Notify by email · On';
    return cb.disabled ? 'Notify by email · pick a template' : 'Notify by email · Off';
}

function buildActionRow(a, templates) {
    const row = document.createElement('div');
    row.className = 'email-action-row'; row.setAttribute('role', 'listitem'); row.dataset.actionKey = a.key;

    const head = document.createElement('div'); head.className = 'ear-head';
    const nm = document.createElement('span'); nm.className = 'ear-name'; nm.textContent = a.name; head.appendChild(nm);
    const badge = document.createElement('span');
    badge.className = 'ear-badge ' + (a.category === 'system' ? 'ear-badge-system' : 'ear-badge-optional');
    badge.textContent = a.category === 'system' ? 'System' : 'Optional';
    head.appendChild(badge);
    row.appendChild(head);

    const desc = document.createElement('div'); desc.className = 'ear-desc'; desc.textContent = a.description || ''; row.appendChild(desc);

    const controls = document.createElement('div'); controls.className = 'ear-controls';
    // template picker
    const tplWrap = document.createElement('label'); tplWrap.className = 'ear-field';
    tplWrap.appendChild(document.createTextNode('Template'));
    const sel = document.createElement('select'); sel.className = 'form-control ear-template';
    const optDefault = document.createElement('option');
    optDefault.value = '';
    optDefault.textContent = a.category === 'system' ? 'Built-in default' : '(none — don’t send)';
    sel.appendChild(optDefault);
    templates.forEach(t => {
        const o = document.createElement('option'); o.value = t.id; o.textContent = t.name || '(untitled)';
        if (a.template_id === t.id) o.selected = true;
        sel.appendChild(o);
    });
    sel.addEventListener('change', () => {
        const picked = sel.value || null;
        // Only reflect the SAFE direction immediately: no template => the switch turns off + disables.
        // Re-ENABLING waits for the reload after the bind is saved, so a click can't race the template
        // PUT and fire a premature enable (which the server would 400). The reload is server-authoritative.
        if (!picked) {
            const swCb = controls.querySelector('.ear-notify input');
            if (swCb) {
                swCb.checked = false; swCb.disabled = true;
                const st = controls.querySelector('.ear-notify-state');
                if (st) st.textContent = _earNotifyLabel(swCb);
            }
        }
        saveAction(a.key, { template_id: picked });
    });
    tplWrap.appendChild(sel); controls.appendChild(tplWrap);

    // Notify switch (optional actions only): a clear on/off, DISABLED until a template is chosen —
    // an email with no template has nothing to send, so it can't be turned on.
    if (a.category !== 'system') {
        const hasTpl = !!a.template_id;
        const field = document.createElement('div'); field.className = 'ear-notify';
        const sw = document.createElement('label'); sw.className = 'dv-switch';
        const cb = document.createElement('input'); cb.type = 'checkbox';
        cb.checked = !!a.enabled && hasTpl; cb.disabled = !hasTpl;
        cb.setAttribute('aria-label', 'Notify by email for ' + a.name);
        const track = document.createElement('span'); track.className = 'dv-switch-track'; track.setAttribute('aria-hidden', 'true');
        sw.appendChild(cb); sw.appendChild(track);
        const state = document.createElement('span'); state.className = 'ear-notify-state';
        state.id = 'ear-state-' + a.key; cb.setAttribute('aria-describedby', state.id);   // expose the reason to AT
        state.textContent = _earNotifyLabel(cb);
        sw.title = cb.disabled ? 'Choose a template to enable this email' : (cb.checked ? 'On — this email will send' : 'Off');
        cb.addEventListener('change', () => {
            state.textContent = _earNotifyLabel(cb);
            sw.title = cb.checked ? 'On — this email will send' : 'Off';
            saveAction(a.key, { enabled: cb.checked });
        });
        field.appendChild(sw); field.appendChild(state);
        controls.appendChild(field);
    }

    const test = document.createElement('button'); test.type = 'button';
    test.className = 'btn btn-secondary btn-sm ear-test'; test.textContent = '📧 Send test';
    test.addEventListener('click', () => openTestModal(a.key, a.name));
    controls.appendChild(test);

    const msg = document.createElement('span'); msg.className = 'ear-msg text-sm'; msg.setAttribute('role', 'status'); controls.appendChild(msg);
    row.appendChild(controls);
    return row;
}

async function saveAction(key, patch) {
    try {
        await apiRequest('/email/actions/' + encodeURIComponent(key), { method: 'PUT', body: JSON.stringify(patch) });
        await loadEmailActions();          // reflect the new binding + re-badge templates
        await loadEmailTemplates();
    } catch (e) {
        showError((e && e.message) || 'Could not update the automated email.');
        await loadEmailActions();          // revert the control to the stored state
    }
}

// ---- Send-test modal (styled recipient picker: search a user, or type an address) ----------------
let _testActionKey = null;
let _testUserId = null;
let _testSearchTimer = null;
let _testSearchSeq = 0;

function openTestModal(key, name) {
    _testActionKey = key; _testUserId = null;
    clearTimeout(_testSearchTimer); _testSearchSeq++;   // cancel any pending/in-flight search from a prior open
    document.getElementById('email-test-modal-title').textContent = 'Send a test: ' + name;
    document.getElementById('et-test-search').value = '';
    document.getElementById('et-test-addr').value = '';
    document.getElementById('et-test-results').replaceChildren();
    const sel = document.getElementById('et-test-selected'); sel.hidden = true; sel.replaceChildren();
    document.getElementById('et-test-msg').textContent = '';
    document.getElementById('email-test-modal').classList.add('active');
    document.getElementById('et-test-search').focus();
}

async function _testUserSearch(q) {
    const results = document.getElementById('et-test-results');
    const search = document.getElementById('et-test-search');
    q = (q || '').trim();
    if (q.length < 2) { results.replaceChildren(); search.setAttribute('aria-expanded', 'false'); return; }
    const seq = ++_testSearchSeq;
    try {
        const data = await apiRequest('/users/search?q=' + encodeURIComponent(q), { silent: true });
        if (seq !== _testSearchSeq) return;   // drop a stale/out-of-order response
        results.replaceChildren();
        (data || []).slice(0, 8).forEach(u => {
            const b = document.createElement('button'); b.type = 'button'; b.className = 'pick-row';
            b.setAttribute('role', 'option'); b.textContent = u.username;
            b.addEventListener('click', () => _testSelectUser(u.id, u.username));
            results.appendChild(b);
        });
        search.setAttribute('aria-expanded', results.childElementCount ? 'true' : 'false');
    } catch (e) {}
}

function _testSelectUser(id, username) {
    _testUserId = id;
    clearTimeout(_testSearchTimer); _testSearchSeq++;   // a pending search must not re-open the dropdown
    document.getElementById('et-test-results').replaceChildren();
    document.getElementById('et-test-search').value = username;
    document.getElementById('et-test-search').setAttribute('aria-expanded', 'false');
    document.getElementById('et-test-addr').value = '';           // user + address are mutually exclusive
    const sel = document.getElementById('et-test-selected'); sel.hidden = false; sel.replaceChildren();
    const txt = document.createElement('span');
    txt.textContent = 'Will send to ' + username + '’s email address. ';
    const change = document.createElement('button'); change.type = 'button';
    change.className = 'btn btn-secondary btn-sm'; change.textContent = 'Change';
    change.addEventListener('click', () => {
        _testUserId = null; clearTimeout(_testSearchTimer); sel.hidden = true; sel.replaceChildren();
        const s = document.getElementById('et-test-search'); s.value = ''; s.focus();
    });
    sel.appendChild(txt); sel.appendChild(change);
}

async function sendActionTest() {
    if (!_testActionKey) return;
    const msg = document.getElementById('et-test-msg');
    const addr = document.getElementById('et-test-addr').value.trim();
    // Picked user wins; else a typed address; else the server falls back to the admin's own email.
    const body = _testUserId ? { to_user_id: _testUserId } : (addr ? { to_addr: addr } : {});
    const btn = document.getElementById('et-test-send');
    try {
        btn.disabled = true; msg.textContent = 'Sending…'; msg.style.color = 'var(--text-secondary)';
        const r = await apiRequest('/email/actions/' + encodeURIComponent(_testActionKey) + '/test',
            { method: 'POST', body: JSON.stringify(body) });
        msg.textContent = '✓ ' + ((r && r.message) || 'Test sent'); msg.style.color = 'var(--success)';
    } catch (e) {
        msg.textContent = '✗ ' + ((e && e.message) || 'Test failed'); msg.style.color = 'var(--error)';
    } finally { btn.disabled = false; }
}

async function openTemplateEditor(t) {
    _editingTemplateId = t ? t.id : null;
    const sel = document.getElementById('et-profile');
    sel.replaceChildren();
    const none = document.createElement('option'); none.value = ''; none.textContent = '(none — uses the default profile)'; sel.appendChild(none);
    try {
        const data = await apiRequest('/email/profiles', { silent: true });
        (data && data.profiles || []).forEach(p => {
            const o = document.createElement('option'); o.value = p.id;
            o.textContent = p.name + (p.is_default ? ' (default)' : ''); sel.appendChild(o);
        });
    } catch (e) {}
    document.getElementById('et-editor-title').textContent = t ? 'Edit template' : 'New template';
    document.getElementById('et-name').value = t ? (t.name || '') : '';
    document.getElementById('et-description').value = t ? (t.description || '') : '';
    document.getElementById('et-subject').value = t ? (t.subject || '') : '';
    sel.value = (t && t.profile_id) ? t.profile_id : '';
    document.getElementById('et-editor-msg').textContent = '';
    let body = '';
    if (t) {
        // The list endpoint omits body_html; fetch the full row. If that fails, REFUSE to open — an
        // editor showing an empty body over a populated name/subject would silently overwrite the
        // stored body on Save.
        let full = null;
        try { full = await apiRequest('/email/templates/' + t.id, { silent: true }); } catch (e) {}
        if (!full) {
            // closeTemplateEditor() (not just nulling the id) also HIDES the editor, so if it was
            // already open on another template this failed edit can't leave a half-populated form
            // whose Save would create a mismatched new template.
            closeTemplateEditor();
            showError('Could not load the template for editing. Please try again.');
            return;
        }
        body = full.body_html || '';
    }
    document.getElementById('et-body').value = body;
    setEditorView('code');
    const ed = document.getElementById('email-template-editor');
    ed.hidden = false;
    ed.scrollIntoView({ behavior: 'smooth', block: 'start' });
    refreshTemplatePreview();
    document.getElementById('et-name').focus();
}

function closeTemplateEditor() {
    document.getElementById('email-template-editor').hidden = true;
    _editingTemplateId = null;
    closeDynMenu();   // dismiss the body-level flyout submenu so it can't orphan
    closeLoadFromMenu();
}

function setEditorView(view) {
    const panes = document.getElementById('et-panes');
    panes.classList.remove('et-view-code', 'et-view-render', 'et-view-split');
    panes.classList.add('et-view-' + view);
    document.querySelectorAll('.et-view').forEach(b => b.classList.toggle('active', b.dataset.view === view));
    if (view !== 'code') refreshTemplatePreview();
}

async function refreshTemplatePreview() {
    const iframe = document.getElementById('et-preview');
    if (!iframe) return;
    const body = document.getElementById('et-body').value;
    const subject = document.getElementById('et-subject').value;
    try {
        const r = await apiRequest('/email/templates/preview',
            { method: 'POST', body: JSON.stringify({ body_html: body, subject: subject }), silent: true });
        // The ONLY html sink: a SANDBOXED iframe (sandbox="" => scripts disabled), fed the
        // server-sanitized preview. Never innerHTML on the main document.
        iframe.srcdoc = (r && r.html) || '';
    } catch (e) {
        iframe.srcdoc = '';
    }
}

function scheduleTemplatePreview() {
    clearTimeout(_etPreviewTimer);
    _etPreviewTimer = setTimeout(refreshTemplatePreview, 400);
}

// UX-only pre-check; the server is authoritative (it re-sanitizes + raises a security event).
function _clientMaliciousCheck(html) {
    return /<\s*script\b/i.test(html) || /<[a-z][^>]*?[\s/]on[a-z]+\s*=/i.test(html) || /javascript\s*:/i.test(html);
}

async function saveTemplate() {
    const msg = document.getElementById('et-editor-msg');
    const body = document.getElementById('et-body').value;
    if (_clientMaliciousCheck(body)) {
        msg.textContent = '✗ The template contains scripts or event handlers, which are not allowed. Remove them before saving.';
        msg.style.color = 'var(--error)';
        return;
    }
    const payload = {
        name: document.getElementById('et-name').value.trim(),
        description: document.getElementById('et-description').value.trim() || null,
        profile_id: document.getElementById('et-profile').value || null,
        subject: document.getElementById('et-subject').value,
        body_html: body,
    };
    const btn = document.getElementById('et-save');
    try {
        btn.disabled = true;
        if (_editingTemplateId) {
            await apiRequest('/email/templates/' + _editingTemplateId, { method: 'PUT', body: JSON.stringify(payload) });
        } else {
            await apiRequest('/email/templates', { method: 'POST', body: JSON.stringify(payload) });
        }
        closeTemplateEditor();
        await loadEmailTemplates();
        showSuccess('Template saved');
    } catch (e) {
        msg.textContent = '✗ ' + (e.message || 'Save failed');
        msg.style.color = 'var(--error)';
    } finally {
        btn.disabled = false;
    }
}

async function deleteTemplate(t) {
    if (!confirm('Delete the template "' + (t.name || '') + '"?')) return;
    try {
        await apiRequest('/email/templates/' + t.id, { method: 'DELETE' });
        if (_editingTemplateId === t.id) closeTemplateEditor();
        await loadEmailTemplates();
        showSuccess('Template deleted');
    } catch (e) {
        showError('Could not delete template: ' + (e.message || ''));
    }
}

// --- toolbar: wrap the selection / insert at the cursor in the source textarea ---
function _etWrap(before, after, placeholder) {
    const ta = document.getElementById('et-body');
    const s = ta.selectionStart, e = ta.selectionEnd;
    const sel = ta.value.slice(s, e) || (placeholder || '');
    ta.value = ta.value.slice(0, s) + before + sel + (after || '') + ta.value.slice(e);
    ta.focus();
    ta.selectionStart = s + before.length;
    ta.selectionEnd = s + before.length + sel.length;
    scheduleTemplatePreview();
}

function _etInsertText(text) {
    const ta = document.getElementById('et-body');
    const s = ta.selectionStart, e = ta.selectionEnd;
    ta.value = ta.value.slice(0, s) + text + ta.value.slice(e);
    ta.focus();
    ta.selectionStart = ta.selectionEnd = s + text.length;
    scheduleTemplatePreview();
}

function applyEditorFormat(fmt) {
    const map = {
        bold: ['<strong>', '</strong>', 'bold text'],
        italic: ['<em>', '</em>', 'italic text'],
        h1: ['<h1>', '</h1>', 'Heading'],
        h2: ['<h2>', '</h2>', 'Heading'],
        h3: ['<h3>', '</h3>', 'Heading'],
        ul: ['<ul>\n  <li>', '</li>\n</ul>', 'item'],
        ol: ['<ol>\n  <li>', '</li>\n</ol>', 'item'],
    };
    const m = map[fmt];
    if (m) _etWrap(m[0], m[1], m[2]);
}

let _dynGroups = null;   // cached [{group, actions:[{token,label,description}]}]

function _groupsFromFlat(data) {
    // Fallback if the server returns only the flat `actions` list (older backend).
    return [{ group: 'Tokens', actions: (data && data.actions) || [] }];
}

function closeDynMenu() {
    const menu = document.getElementById('et-dyn-menu');
    if (menu) menu.hidden = true;
    const btn = document.getElementById('et-add-dynamic');
    if (btn) btn.setAttribute('aria-expanded', 'false');
    _closeDynSubmenu();
}

function _closeDynSubmenu() {
    const sub = document.getElementById('et-dyn-submenu');
    if (sub) sub.remove();
    document.querySelectorAll('.et-dyn-group.active').forEach(r => r.classList.remove('active'));
}

async function toggleDynamicMenu() {
    const menu = document.getElementById('et-dyn-menu');
    const btn = document.getElementById('et-add-dynamic');
    if (!menu.hidden) { closeDynMenu(); return; }
    closeLoadFromMenu();   // don't leave the other toolbar dropdown open behind this one
    menu.replaceChildren();
    _closeDynSubmenu();
    try {
        if (!_dynGroups) {
            const data = await apiRequest('/email/dynamic-actions', { silent: true });
            _dynGroups = (data && Array.isArray(data.groups) && data.groups.length) ? data.groups : _groupsFromFlat(data);
        }
        _dynGroups.forEach(g => {
            const row = document.createElement('button');
            row.type = 'button'; row.className = 'et-dyn-group'; row.setAttribute('role', 'menuitem');
            row.setAttribute('aria-haspopup', 'true'); row.setAttribute('aria-expanded', 'false');
            const name = document.createElement('span'); name.textContent = g.group;
            const chev = document.createElement('span'); chev.className = 'et-dyn-chevron'; chev.textContent = '▸';
            row.appendChild(name); row.appendChild(chev);
            row.addEventListener('click', (e) => { e.stopPropagation(); openDynGroupSubmenu(row, g); });
            menu.appendChild(row);
        });
    } catch (e) {}
    menu.hidden = false; btn.setAttribute('aria-expanded', 'true');
}

function openDynGroupSubmenu(row, group) {
    const existing = document.getElementById('et-dyn-submenu');
    if (existing && existing.dataset.group === group.group) { _closeDynSubmenu(); return; }  // toggle
    _closeDynSubmenu();
    const sub = document.createElement('div');
    sub.id = 'et-dyn-submenu'; sub.className = 'et-dyn-submenu'; sub.dataset.group = group.group;
    sub.setAttribute('role', 'menu');
    (group.actions || []).forEach(a => {
        const b = document.createElement('button'); b.type = 'button'; b.setAttribute('role', 'menuitem');
        if (a.description) b.title = a.description;
        const lbl = document.createElement('div'); lbl.textContent = a.label;
        const tok = document.createElement('div'); tok.className = 'et-dyn-token'; tok.textContent = '{{' + a.token + '}}';
        b.appendChild(lbl); b.appendChild(tok);
        b.addEventListener('click', (e) => { e.stopPropagation(); _etInsertText('{{' + a.token + '}}'); closeDynMenu(); });
        sub.appendChild(b);
    });
    document.body.appendChild(sub);     // body-level so no ancestor overflow can clip it
    row.classList.add('active'); row.setAttribute('aria-expanded', 'true');
    _positionDynSubmenu(sub, row);
}

function _positionDynSubmenu(sub, row) {
    // Flyout beside the group row; flip LEFT if it would overflow the right edge, and flip UP
    // (bottom-align to the row) if it would overflow the viewport bottom. position:fixed => the
    // getBoundingClientRect coordinates are already viewport-relative.
    const rr = row.getBoundingClientRect();
    const sw = sub.offsetWidth, sh = sub.offsetHeight;
    const vw = window.innerWidth, vh = window.innerHeight, m = 8;
    let left = rr.right + 4;
    if (left + sw > vw - m) left = Math.max(m, rr.left - sw - 4);   // no room right -> go left
    let top = rr.top;
    if (top + sh > vh - m) top = Math.max(m, rr.bottom - sh);       // no room below -> flip up
    sub.style.left = Math.round(left) + 'px';
    sub.style.top = Math.round(top) + 'px';
}

// ---- Load From (reset to a default template, or copy an existing one) ----------------------------
function closeLoadFromMenu() {
    const menu = document.getElementById('et-loadfrom-menu');
    if (menu) menu.hidden = true;
    const btn = document.getElementById('et-load-from');
    if (btn) btn.setAttribute('aria-expanded', 'false');
}

function _loadFromRow(label, onPick) {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'et-loadfrom-item'; b.setAttribute('role', 'menuitem');
    b.textContent = label;
    b.addEventListener('click', (e) => { e.stopPropagation(); onPick(); });
    return b;
}

function _loadFromApply(name, subject, body) {
    // Replacing the current editor content is destructive, so confirm first.
    if (!confirm('Replace the current subject and body with “' + name + '”?')) return;
    document.getElementById('et-subject').value = subject || '';
    document.getElementById('et-body').value = body || '';
    closeLoadFromMenu();
    refreshTemplatePreview();
    const msg = document.getElementById('et-editor-msg');
    if (msg) { msg.textContent = 'Loaded “' + name + '”. Review, then Save to keep it.'; msg.style.color = 'var(--text-secondary)'; }
}

function _loadFromSection(menu, label) {
    const h = document.createElement('div'); h.className = 'et-loadfrom-section'; h.textContent = label;
    menu.appendChild(h);
}

async function toggleLoadFromMenu() {
    const menu = document.getElementById('et-loadfrom-menu');
    const btn = document.getElementById('et-load-from');
    if (!menu.hidden) { closeLoadFromMenu(); return; }
    closeDynMenu();   // don't leave the other toolbar dropdown open behind this one
    menu.replaceChildren();
    // 1) Default templates (from code — always available, even after a seeded row was edited).
    try {
        if (!_loadFromDefaults) {
            const d = await apiRequest('/email/default-templates', { silent: true });
            _loadFromDefaults = (d && d.templates) || [];
        }
    } catch (e) { _loadFromDefaults = _loadFromDefaults || []; }
    _loadFromSection(menu, 'Default templates');
    if (_loadFromDefaults.length) {
        _loadFromDefaults.forEach(t => menu.appendChild(
            _loadFromRow(t.name || t.key, () => _loadFromApply(t.name || t.key, t.subject, t.body_html))));
    } else {
        const e = document.createElement('div'); e.className = 'et-loadfrom-empty'; e.textContent = 'None available'; menu.appendChild(e);
    }
    // 2) Your templates (existing rows; exclude built-in defaults — already listed above — and the one
    // being edited, since loading itself is a no-op).
    let mine = [];
    try {
        const r = await apiRequest('/email/templates', { silent: true });
        mine = ((r && r.templates) || []).filter(t => !t.is_default && t.id !== _editingTemplateId);
    } catch (e) {}
    const sep = document.createElement('div'); sep.className = 'et-loadfrom-sep'; menu.appendChild(sep);
    _loadFromSection(menu, 'Your templates');
    if (mine.length) {
        mine.forEach(t => menu.appendChild(_loadFromRow(t.name || '(untitled)', async () => {
            // The list omits the body; fetch the full row before applying.
            let full = null;
            try { full = await apiRequest('/email/templates/' + t.id, { silent: true }); } catch (e) {}
            if (!full) { showError('Could not load that template.'); return; }
            _loadFromApply(t.name || '(untitled)', full.subject, full.body_html);
        })));
    } else {
        const e = document.createElement('div'); e.className = 'et-loadfrom-empty'; e.textContent = 'No other templates yet'; menu.appendChild(e);
    }
    menu.hidden = false; btn.setAttribute('aria-expanded', 'true');
}

async function openImagePicker() {
    document.getElementById('et-image-upload-msg').textContent = '';
    await loadImageResources();
    document.getElementById('email-image-modal').classList.add('active');
}

async function loadImageResources() {
    const grid = document.getElementById('et-image-grid');
    grid.replaceChildren();
    try {
        const data = await apiRequest('/email/resources', { silent: true });
        const resources = (data && data.resources) || [];
        for (const res of resources) grid.appendChild(await buildImageThumb(res));
        if (!resources.length) {
            const empty = document.createElement('div'); empty.className = 'text-sm text-secondary';
            empty.textContent = 'No images yet — upload one above.'; grid.appendChild(empty);
        }
    } catch (e) {}
}

async function buildImageThumb(res) {
    const item = document.createElement('div'); item.className = 'et-image-item'; item.setAttribute('role', 'listitem');
    const img = document.createElement('img'); img.alt = res.filename || '';
    // An <img src> can't send an Authorization header, so fetch the bytes with the bearer token and
    // use a blob URL for the thumbnail.
    try {
        const resp = await fetch(`${API_BASE}/email/resources/${res.id}`, { headers: { 'Authorization': `Bearer ${authToken}` } });
        if (resp.ok) {
            const url = URL.createObjectURL(await resp.blob());
            // Free the blob once the browser has decoded it (the picker can reopen many times, each
            // loading up to 1000 images, so an un-revoked URL pins the full bytes for the session).
            img.onload = img.onerror = () => URL.revokeObjectURL(url);
            img.src = url;
        }
    } catch (e) {}
    const name = document.createElement('div'); name.className = 'et-image-name'; name.textContent = res.filename || res.id;
    item.appendChild(img); item.appendChild(name);
    // Insert only the UUID reference (no path/URL); alt is added by the admin if wanted.
    item.addEventListener('click', () => { _etInsertText(_etImageMarkup(res.id)); closeModal(); });
    return item;
}

// Build the <img> markup for an inserted resource, honoring the size picker. Emits a `width` (which
// the sanitizer allows and the preview/send both render) unless "Original" (0) is chosen. Never emits
// a path/URL — only the UUID reference.
function _etImageMarkup(resourceId) {
    let w = 0;
    const sizeSel = document.getElementById('et-image-size');
    if (sizeSel) {
        if (sizeSel.value === 'custom') {
            const c = document.getElementById('et-image-custom-width');
            w = c ? parseInt(c.value, 10) : 0;
        } else {
            w = parseInt(sizeSel.value, 10);
        }
    }
    if (Number.isFinite(w) && w > 0) {
        w = Math.min(2000, Math.max(1, w));
        return '<img data-resource-id="' + resourceId + '" width="' + w + '">';
    }
    return '<img data-resource-id="' + resourceId + '">';
}

async function uploadImageResource(file) {
    const msg = document.getElementById('et-image-upload-msg');
    const fd = new FormData(); fd.append('file', file);
    try {
        msg.textContent = 'Uploading…';
        // FormData must set its own multipart boundary, so fetch directly (apiRequest forces JSON).
        const resp = await fetch(`${API_BASE}/email/resources`, {
            method: 'POST', headers: { 'Authorization': `Bearer ${authToken}` }, body: fd });
        if (!resp.ok) {
            const d = await resp.json().catch(() => ({}));
            // detail is usually a string, but a 422 makes it a list of error objects — coerce so the
            // message never renders as "[object Object]".
            const detail = typeof d.detail === 'string' ? d.detail : '';
            throw new Error(detail || `Upload failed (${resp.status})`);
        }
        msg.textContent = '✓ Uploaded';
        await loadImageResources();
    } catch (e) {
        msg.textContent = '✗ ' + (e.message || 'Upload failed');
    }
}

async function openSendModal(t) {
    _sendTemplateId = t.id;
    document.getElementById('email-send-modal-title').textContent = 'Send: ' + (t.name || 'template');
    document.getElementById('et-send-results').replaceChildren();
    document.getElementById('et-send-addresses').value = '';
    const sel = document.getElementById('et-send-users'); sel.replaceChildren();
    try {
        const users = await apiRequest('/users', { silent: true });
        (Array.isArray(users) ? users : []).filter(u => u.email).forEach(u => {
            const o = document.createElement('option'); o.value = u.id;
            o.textContent = u.username + ' <' + u.email + '>'; sel.appendChild(o);
        });
    } catch (e) {}
    document.getElementById('email-send-modal').classList.add('active');
}

async function sendTemplateNow() {
    const results = document.getElementById('et-send-results');
    const sel = document.getElementById('et-send-users');
    const userIds = Array.from(sel.selectedOptions).map(o => o.value);
    const addresses = document.getElementById('et-send-addresses').value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (!userIds.length && !addresses.length) {
        results.replaceChildren(); results.textContent = 'Select at least one recipient.'; results.style.color = 'var(--error)'; return;
    }
    const btn = document.getElementById('et-send-go');
    try {
        btn.disabled = true;
        results.replaceChildren(); results.textContent = 'Sending…'; results.style.color = 'var(--text-secondary)';
        const r = await apiRequest('/email/templates/' + _sendTemplateId + '/send',
            { method: 'POST', body: JSON.stringify({ user_ids: userIds, addresses: addresses }) });
        renderSendResults(r);
    } catch (e) {
        results.replaceChildren(); results.textContent = '✗ ' + (e.message || 'Send failed'); results.style.color = 'var(--error)';
    } finally {
        btn.disabled = false;
    }
}

function renderSendResults(r) {
    const box = document.getElementById('et-send-results');
    box.replaceChildren();
    box.style.color = '';
    const rows = r.results || [];
    const sent = r.sent || 0;
    const failed = rows.length - sent;   // total shown minus succeeded — invalid/no-email rows included
    const summary = document.createElement('div');
    summary.textContent = failed > 0
        ? `Sent ${sent} of ${rows.length}, ${failed} failed.`
        : `Sent ${sent} of ${rows.length}.`;
    box.appendChild(summary);
    rows.forEach(row => {
        const li = document.createElement('div'); li.className = 'text-xs';
        li.textContent = (row.ok ? '✓ ' : '✗ ') + row.recipient + (row.error ? ' — ' + row.error : '');
        box.appendChild(li);
    });
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
            // Audit rows are a security record: an unreadable timestamp must not
            // render as the current instant, which would make an old or corrupted
            // event look like it just happened.
            const timestampText = formatServerTime(log.timestamp);
            const statusClass = log.status === 'success' ? 'success' : 'danger';
            
            return `
                <tr>
                    <td>${timestampText}</td>
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
    
    // Email Studio — sending-profile modal buttons (Cancel uses the shared close-modal-btn handler).
    const epSave = document.getElementById('ep-save');
    if (epSave) epSave.addEventListener('click', saveEmailProfile);
    const epTest = document.getElementById('ep-send-test');
    if (epTest) epTest.addEventListener('click', sendEmailProfileTest);

    // Email Studio — template editor + toolbar + image picker + send. Wire ONCE: initSettings() (and
    // thus attachSettingsListeners) runs on every navigation to Settings, and the arrow-wrapped
    // listeners below create a fresh function each time, so without this guard they would stack
    // (double-formatting, duplicate uploads, an unremovable document click handler per visit).
    const etEditor = document.getElementById('email-template-editor');
    if (etEditor && !etEditor.dataset.wired) {
        etEditor.dataset.wired = '1';
        const etSave = document.getElementById('et-save');
        if (etSave) etSave.addEventListener('click', saveTemplate);
        const etCancel = document.getElementById('et-cancel');
        if (etCancel) etCancel.addEventListener('click', closeTemplateEditor);
        document.querySelectorAll('.et-view').forEach(b => b.addEventListener('click', () => setEditorView(b.dataset.view)));
        document.querySelectorAll('.et-toolbar [data-fmt]').forEach(b => b.addEventListener('click', () => applyEditorFormat(b.dataset.fmt)));
        const etBody = document.getElementById('et-body');
        if (etBody) etBody.addEventListener('input', scheduleTemplatePreview);
        const etSubject = document.getElementById('et-subject');
        if (etSubject) etSubject.addEventListener('input', scheduleTemplatePreview);
        const etAddImg = document.getElementById('et-add-image');
        if (etAddImg) etAddImg.addEventListener('click', openImagePicker);
        const etAddDyn = document.getElementById('et-add-dynamic');
        if (etAddDyn) etAddDyn.addEventListener('click', (e) => { e.stopPropagation(); toggleDynamicMenu(); });
        const etLoadFrom = document.getElementById('et-load-from');
        if (etLoadFrom) etLoadFrom.addEventListener('click', (e) => { e.stopPropagation(); toggleLoadFromMenu(); });
        const etImgUpload = document.getElementById('et-image-upload');
        if (etImgUpload) etImgUpload.addEventListener('change', (e) => { if (e.target.files[0]) uploadImageResource(e.target.files[0]); });
        const etImgSize = document.getElementById('et-image-size');
        if (etImgSize) etImgSize.addEventListener('change', () => {
            const c = document.getElementById('et-image-custom-width');
            if (c) c.hidden = (etImgSize.value !== 'custom');
        });
        const etSendGo = document.getElementById('et-send-go');
        if (etSendGo) etSendGo.addEventListener('click', sendTemplateNow);
        // Send-test modal: debounced user search + send.
        const etTestSearch = document.getElementById('et-test-search');
        if (etTestSearch) etTestSearch.addEventListener('input', () => {
            _testUserId = null;                  // typing = re-searching, so drop any prior selection
            const sel = document.getElementById('et-test-selected'); if (sel) { sel.hidden = true; sel.replaceChildren(); }
            clearTimeout(_testSearchTimer);
            _testSearchTimer = setTimeout(() => _testUserSearch(etTestSearch.value), 250);
        });
        const etTestAddr = document.getElementById('et-test-addr');
        if (etTestAddr) etTestAddr.addEventListener('input', () => {
            // Typing a specific address supersedes a picked user (they're mutually exclusive), so clear
            // the selection + banner rather than silently ignoring the typed address.
            if (etTestAddr.value.trim()) {
                _testUserId = null;
                const sel = document.getElementById('et-test-selected'); if (sel) { sel.hidden = true; sel.replaceChildren(); }
            }
        });
        const etTestSend = document.getElementById('et-test-send');
        if (etTestSend) etTestSend.addEventListener('click', sendActionTest);
        // Close the dynamic-action menu (and its body-level flyout submenu) on an outside click.
        document.addEventListener('click', (e) => {
            const menu = document.getElementById('et-dyn-menu');
            if (menu && !menu.hidden && !e.target.closest('.et-dyn-wrap') && !e.target.closest('#et-dyn-submenu')) {
                closeDynMenu();
            }
            const lf = document.getElementById('et-loadfrom-menu');
            if (lf && !lf.hidden && !e.target.closest('.et-loadfrom-wrap')) {
                closeLoadFromMenu();
            }
        });
        // The flyout submenu is position:fixed, so a scroll/resize would detach it from its row —
        // close it (the admin reopens with one click). Capture-phase catches scrolls in any container.
        window.addEventListener('resize', _closeDynSubmenu);
        window.addEventListener('scroll', _closeDynSubmenu, true);
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

        // Zero-knowledge vaults: require the encryption-key unlock BEFORE entering. The unlock used to
        // be lazy — triggered only when a file with an encrypted name was listed — so an empty ZK
        // vault (or one holding only legacy-plaintext rows) opened with no passphrase prompt at all,
        // leaving the user "inside" a vault they never unlocked. Gate it here, mirroring the password
        // path: zkEnsureUnlocked() prompts + decrypts + verifies against the registered public key,
        // and throws on cancel / wrong passphrase / mismatch.
        if (isZkVault(vault)) {
            try {
                await zkEnsureUnlocked();
            } catch (e) {
                state.currentVault = null;
                state.currentVaultId = null;
                const msg = (e && e.message) || 'Vault unlock cancelled';
                // A user cancelling the prompt is a gentle warning; a WRONG passphrase / key mismatch
                // is a real failure and must surface clearly (this is the "surfaces a clear error"
                // guarantee — a wrong passphrase used to be swallowed).
                if (/cancel/i.test(msg)) showWarning(msg);
                else showError(msg);
                return;
            }
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
    const d = parseServerTime(iso);
    if (!d) return '—';
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
    updateMoveCopyBar();
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
        // Copy/Move a folder needs folder.create (the structural cap); a recursive copy also
        // reads + writes files, gated server-side. Mirrors require_vault_cap on the endpoints.
        const canStructure = canWrite && vaultCapAllowed('folder.create');
        if (slot !== 'primary') {  // folders have no download -> primary (left) is empty
            if (canRename) out.push(btn('rename-folder', 'edit', 'Rename'));
            if (canStructure) out.push(btn('copy-folder', 'copy', 'Copy'));
            if (canStructure) out.push(btn('move-folder', 'move', 'Move'));
            if (canDelete) out.push(btn('delete-folder', 'trash', 'Delete', true));
            if (vaultShareable()) out.push(btn('share-folder', 'link', 'Share'));
        }
        if (out.length === 0 && !slot && (!opts || !opts.grid)) out.push('<span class="text-tertiary text-sm">—</span>');
    } else {
        const canDownload = vaultCapAllowed('file.download');
        const canRename = canWrite && vaultCapAllowed('file.rename');
        const canDelete = canWrite && vaultCapAllowed('file.delete');
        if (slot !== 'primary') {
            if (canRename) out.push(btn('rename-file', 'edit', 'Rename'));
            // Copy needs read (file.download); Move removes from the source (file.delete). The
            // destination write is authorized at paste time, matching the endpoints.
            if (canDownload) out.push(btn('copy-file', 'copy', 'Copy'));
            if (canDelete) out.push(btn('move-file', 'move', 'Move'));
            if (canDelete) out.push(btn('delete-file', 'trash', 'Delete', true));
            if (vaultShareable()) out.push(btn('share-file', 'link', 'Share'));
            // Download last so it renders on the far RIGHT of the action cluster (grid + table).
            if (canDownload) out.push(btn('download', 'download', 'Download'));
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
        // The name (the primary open action) comes first in DOM so it is the first tab stop and the
        // destructive Delete is last. The action row is an IN-FLOW row below the icon/name/meta
        // (checkbox left, Rename/Delete/Share/Download right) so the controls never paint over the icon.
        return `
            <div class="file-tile ${isFolder ? 'is-folder' : ''} ${selected ? 'is-selected' : ''}">
                <div class="tile-icon">${icon}</div>
                <div class="file-name tile-name" ${nameAttrs} role="button" tabindex="0" aria-label="${openLabel}">${escapeHtml(item.name)}${lockIcon}</div>
                <div class="tile-meta">${meta}</div>
                <div class="tile-actions">
                    <div class="tile-tl">${check}${primary}</div>
                    <div class="tile-tr file-actions">${secondary}</div>
                </div>
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
            if (e.target.closest('button, input, a, .tile-actions, .file-actions, .tile-tl, .tile-tr, .file-check, .file-name')) return;
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
            else if (action === 'share-file' || action === 'share-folder') openCreateShareModal(action === 'share-folder' ? 'folder' : 'file', id, name);
            else if (action === 'copy-file' || action === 'move-file')
                stageForMoveCopy(id, name, 'file', action === 'move-file' ? 'move' : 'copy');
            else if (action === 'copy-folder' || action === 'move-folder')
                stageForMoveCopy(id, name, 'folder', action === 'move-folder' ? 'move' : 'copy');
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

// ---- Move / Copy clipboard --------------------------------------------------------------------
// A small staging list: Copy/Move on an item adds it here (remembering which vault it came from);
// "Paste here" drops the staged items into the vault + folder currently open. Copies stay staged so
// they can be pasted in several places; moves leave once relocated. The source and destination vault
// passwords are pulled from the per-vault remembered-unlock cache, so a paste into or out of a
// password-protected vault works while it is unlocked (and fails cleanly with a prompt otherwise).
function _moveCopyClip() {
    if (!Array.isArray(state.moveCopyClip)) state.moveCopyClip = [];
    return state.moveCopyClip;
}

function stageForMoveCopy(id, name, type, action) {
    const clip = _moveCopyClip();
    // Re-staging the same item replaces its pending action (Copy then Move, or vice-versa).
    const existing = clip.find(e => e.id === id);
    if (existing) { existing.action = action; existing.name = name; existing.type = type; }
    else clip.push({ id, name, type, action, sourceVaultId: state.currentVaultId });
    updateMoveCopyBar();
    showToast(`${action === 'move' ? 'Moving' : 'Copying'}: ${name}. Open a folder or vault and Paste here.`, 'info');
}

function clearMoveCopy() {
    state.moveCopyClip = [];
    updateMoveCopyBar();
}

function updateMoveCopyBar() {
    const clip = _moveCopyClip();
    const bar = document.getElementById('move-copy-bar');
    const countEl = document.getElementById('move-copy-count');
    if (countEl) countEl.textContent = clip.length;
    if (bar) bar.hidden = clip.length === 0;
}

function _vaultPasswordFor(vaultId) {
    // The current vault's live password, else any per-vault remembered unlock (null if neither).
    if (vaultId && state.currentVaultId && String(vaultId) === String(state.currentVaultId)) {
        return state.vaultPassword || state.getRememberedVaultPassword(vaultId) || null;
    }
    return state.getRememberedVaultPassword(vaultId) || null;
}

async function pasteMoveCopy() {
    const clip = _moveCopyClip();
    if (!clip.length) return;
    const destVaultId = state.currentVaultId;
    if (!destVaultId) { showError('Open a vault to paste into.'); return; }
    const destFolderId = state.currentFolderId || null;
    const destPassword = _vaultPasswordFor(destVaultId);
    const pasteBtn = document.getElementById('move-copy-paste');
    if (pasteBtn) pasteBtn.disabled = true;

    let ok = 0;
    const failures = [];
    const relocated = new Set();  // moved items that succeeded (leave the clipboard)
    for (const entry of clip) {
        const isFolder = entry.type === 'folder';
        const verb = entry.action;  // 'copy' | 'move'
        const base = `/vaults/${entry.sourceVaultId}/${isFolder ? 'folders' : 'files'}/${entry.id}/${verb}`;
        const body = isFolder
            ? { dest_vault_id: destVaultId, dest_parent_folder_id: destFolderId }
            : { dest_vault_id: destVaultId, dest_folder_id: destFolderId };
        const headers = {};
        const srcPw = _vaultPasswordFor(entry.sourceVaultId);
        if (srcPw) headers['X-Vault-Password'] = srcPw;
        if (destPassword) headers['X-Dest-Vault-Password'] = destPassword;
        try {
            await apiRequest(base, { method: 'POST', body: JSON.stringify(body), headers, silent: true });
            ok++;
            if (verb === 'move') relocated.add(entry.id);
        } catch (e) {
            failures.push(`${entry.name}: ${(e && e.message) || 'failed'}`);
        }
    }

    // Copies stay staged (paste again elsewhere); successful moves leave; failures stay.
    state.moveCopyClip = clip.filter(e => !relocated.has(e.id));
    updateMoveCopyBar();
    if (pasteBtn) pasteBtn.disabled = false;
    if (ok) showSuccess(`Pasted ${ok} item${ok > 1 ? 's' : ''}`);
    if (failures.length) showError(`Could not paste ${failures.length}: ${failures.slice(0, 3).join('; ')}`);
    await loadVaultFiles();
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
    const paste = document.getElementById('move-copy-paste');
    if (paste) paste.addEventListener('click', pasteMoveCopy);
    const clipClear = document.getElementById('move-copy-clear');
    if (clipClear) clipClear.addEventListener('click', clearMoveCopy);
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
            // A ZK breadcrumb restored from storage has no label (names are never persisted); show a
            // neutral, clickable placeholder rather than an empty span until the user navigates.
            html += `<span class="breadcrumb-item ${isLast ? 'active' : ''}" data-folder-id="${folder.id}">${escapeHtml(folder.name || '\u2026')}</span>`;
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
const zkState = { privateKey: null, vaultDeks: {}, teamKeys: {}, pinnedHier: {}, vaultIndexKeys: {} };
function zkResetKeys() { zkState.privateKey = null; zkState.vaultDeks = {}; zkState.teamKeys = {}; zkState.pinnedHier = {}; zkState.vaultIndexKeys = {}; }

// --- ZK idle auto-lock -------------------------------------------------------------------------
// Optional org policy (zk_idle_lock_minutes, from /zk-enabled): drop the in-memory ZK key after N
// minutes of inactivity so the user must re-enter their passphrase. 0 = disabled. Enforced here
// because the key never leaves the browser; the server only supplies the threshold.
let _zkIdleLockMinutes = 0;
let _zkIdleTimer = null;
let _zkActivityWired = false;

function zkIdleLock() {
    if (_zkIdleTimer) { clearTimeout(_zkIdleTimer); _zkIdleTimer = null; }
    if (!zkState.privateKey) return;          // already locked
    zkResetKeys();                            // drop the ECC key + per-vault DEKs; next op re-prompts
    try { showInfo('Encryption locked after inactivity — you\'ll be asked for your passphrase again.'); } catch (_) {}
}

// (Re)arm the idle timer. No-op unless the policy is on AND a key is currently unlocked.
function zkArmIdleLock() {
    if (_zkIdleTimer) { clearTimeout(_zkIdleTimer); _zkIdleTimer = null; }
    if (_zkIdleLockMinutes > 0 && zkState.privateKey) {
        _zkIdleTimer = setTimeout(zkIdleLock, _zkIdleLockMinutes * 60 * 1000);
        if (!_zkActivityWired) {
            _zkActivityWired = true;
            // Reset the countdown on real user activity while a key is unlocked (passive listeners).
            ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(ev =>
                document.addEventListener(ev, () => { if (zkState.privateKey && _zkIdleLockMinutes > 0) zkArmIdleLock(); },
                    { passive: true }));
        }
    }
}

// Apply a policy value from /zk-enabled and (re)arm.
function setZkIdleLockMinutes(n) {
    _zkIdleLockMinutes = (typeof n === 'number' && isFinite(n) && n > 0) ? Math.min(Math.floor(n), 1440) : 0;
    zkArmIdleLock();
}

function isZkVault(v) { return !!v && v.type === 'zero_knowledge'; }

// Replace the stored private-key envelope, proving we hold the CURRENTLY REGISTERED key.
//
// Without this proof any session for the account could overwrite the envelope and permanently
// destroy access to every vault: registration refuses a second keypair, and removing the first
// would orphan every wrapped key. See docs/design/vault-private-key-update-pop-v1.md.
//
// `privateKey` must be the key just recovered on this path - which is by definition the
// registered one, because both callers verify it against the registered public key first.
async function zkPutPrivateEnvelope(envelope, privateKey, registeredPublicKeyPem, userId,
                                    newPassphrase, expectedPem) {
    const body = JSON.stringify(envelope);
    // Read the re-wrapped envelope back and confirm it really recovers the same key BEFORE
    // replacing the only copy, and before spending one of the few challenges the rate budget
    // allows. The server cannot do this check - it cannot read the envelope - so a client bug
    // that produced an undecryptable blob would otherwise look exactly like a correct one, and
    // would be discovered at the next unlock, when it is too late.
    let readBack = null;
    try {
        readBack = await eccLib().decryptPrivateEnvelope(body, newPassphrase);
    } catch (e) {
        // Operation and code only: the error now retains the platform exception as its cause, and
        // developer tools expand that.
        console.error('crypto rewrapReadBack', (e && e.code) || 'UNCODED');
    }
    if (readBack !== expectedPem) {
        throw new Error('Internal error preparing the new encryption key — nothing was changed.');
    }
    const challenge = await apiRequest('/ecc/keys/private/challenge', { method: 'POST' });
    const mac = await eccLib().computeKeyUpdatePoP(
        challenge.server_ephemeral_public_key, challenge.nonce, challenge.challenge_id,
        userId, registeredPublicKeyPem, body, privateKey
    );
    await apiRequest('/ecc/keys/private', {
        method: 'PUT',
        body: JSON.stringify({
            encrypted_private_key: body,
            pop: { challenge_id: challenge.challenge_id, mac },
        }),
    });
}

// Turn a crypto failure code into the sentence a user should read, for the flow they are in.
//
// This is the only place that decides wording. Individual catch blocks branch on `.code` and
// delegate here; they never compose their own message and they never render `error.message` --
// that string is deliberately not a sentence, so if it reaches a user it reads as a bug.
//
// `flow` exists because the same code means different things depending on what the user just
// did: an authentication failure during a passphrase change is about the CURRENT passphrase,
// the identical code during a recovery restore is about the RECOVERY passphrase. The code says
// what happened; the flow knows which secret was typed.
//
// See docs/design/vault-client-crypto-errors-v1.md.
// A recovered key that is not this account's. Distinct from an unusable one: the remedy is a
// different key, not a repaired one. Worded per flow because what the user just did determines
// what was NOT done as a result.
const ZK_MISMATCH_SENTENCE = {
    unlock: 'The stored encryption key does not match this account\u2019s registered public key.',
    change: 'The stored key does not match this account\u2019s registered public key; '
          + 'passphrase not changed.',
    export: 'The stored key does not match this account\u2019s registered public key; '
          + 'no recovery key was written.',
    restore: 'That recovery key belongs to a different account; nothing was changed.',
};

const ZK_AUTH_SENTENCE = {
    unlock: 'Incorrect passphrase (or the stored key is corrupt).',
    change: 'Incorrect current passphrase (or the stored key is corrupt).',
    export: 'Incorrect current passphrase (or the stored key is corrupt).',
    restore: 'Incorrect recovery passphrase (or the recovery key is corrupt).',
};

// The codes are compared as literals rather than read off the library, deliberately. A classic
// script's top-level `class` is a global LEXICAL binding, not a property of `window` -- which is
// why every other reference to it here goes through a `typeof` guard -- so a
// `window.ECCCryptoLibrary` lookup would be undefined and would quietly send every failure to the
// default branch. A test pins these literals against the library's exported set, which catches a
// typo without making the lookup itself a point of failure. It also keeps this function working
// when the library is the thing that failed to load.
function safeMessageForCode(code, flow) {
    switch (code) {
        case 'CRYPTO_UNAVAILABLE':
            return 'This browser cannot perform encryption here. Use a current browser over a '
                 + 'secure (https) connection.';
        case 'AUTH_FAILED':
            return ZK_AUTH_SENTENCE[flow] || ZK_AUTH_SENTENCE.unlock;
        case 'CONTENT_UNSUPPORTED':
            // The file is intact. This build cannot read the format it was written in, and
            // saying "damaged" would send someone looking for a backup they do not need.
            return 'This item was saved by a newer version of DockVault and cannot be read here. '
                 + 'Update this deployment. The item itself is fine.';
        case 'CONTENT_INVALID':
            // Structurally wrong rather than failing authentication: not a tampered file, and
            // not a format from the future either.
            return 'This item is not in a format DockVault recognises.';
        case 'WRAP_UNSUPPORTED':
            return 'Your access to this vault was granted by a newer version of DockVault and '
                 + 'cannot be read here. Update this deployment.';
        case 'WRAP_INVALID':
            return 'Your access to this vault is recorded in a form DockVault does not '
                 + 'recognise. Ask an owner to share the vault with you again.';
        case 'CONTENT_AUTH_FAILED':
            // Reached only after the passphrase already succeeded, so this must never suggest
            // the passphrase is at fault.
            return 'This item could not be decrypted — it appears damaged. Your passphrase is '
                 + 'not the problem.';
        case 'ENVELOPE_UNSUPPORTED':
            // The envelope is FINE and the passphrase is FINE; this build is behind. Emphatically
            // not an invitation to re-register: the server refuses that while a key exists, and
            // it would orphan every vault key if it did not.
            return 'Your encryption key was saved by a newer version of DockVault and cannot be '
                 + 'read here. Update this deployment. Do not re-register your key.';
        case 'RECOVERY_KIT_UNSUPPORTED':
            return 'This recovery key file was written by a newer version of DockVault. Update '
                 + 'this deployment to use it.';
        case 'RECOVERY_KIT_INVALID':
            return 'That file is not a valid DockVault recovery key.';
        case 'ENVELOPE_INVALID':
            return 'Your stored encryption key is damaged and cannot be read. Restore it from a '
                 + 'recovery key file.';
        case 'WORK_FACTOR_REJECTED':
            return 'Your stored encryption key declares an unreasonable amount of work to open '
                 + 'and was refused.';
        case 'KEY_MISMATCH':
            return ZK_MISMATCH_SENTENCE[flow] || ZK_MISMATCH_SENTENCE.unlock;
        case 'KEY_UNUSABLE':
            return 'That key could not be read — it appears damaged or is not a supported key.';
        case 'WRAP_FAILED':
            return 'This vault\u2019s key could not be opened for your account. Ask an owner to '
                 + 'share the vault with you again.';
        default:
            // Includes INVALID_INPUT, CRYPTO_OPERATION_FAILED, an unrecognised code, and no code
            // at all. Never guess a more specific cause, and never fall through to a passphrase
            // prompt: guessing is how an unreadable envelope became "wrong passphrase".
            return 'The encryption operation could not be completed.';
    }
}

// True when an error carries a code from the crypto contract. Checked as an own property rather
// than with instanceof, which does not survive the classic-script / require split.
function isCodedCryptoError(e) {
    return !!(e && e.isCryptoError === true && e.code);
}

// The single writer for every private-key envelope this app produces: first registration,
// passphrase change, recovery-kit export and recovery restore.
//
// It emits the versioned v1 shape only when the deployment has switched the writer on, and the
// legacy shape otherwise. Readers accept both either way, which is what lets readers roll out
// everywhere before any writer produces bytes an older client cannot read. Enabling v1 is
// FORWARD-ONLY for a deployment: once a v1 envelope exists, rolling the image back to a reader
// that predates it makes that envelope unreadable, and registration refuses a second keypair so
// there is no self-service recovery. See docs/design/vault-private-key-envelope-v1.md §8.1.
async function zkWrapPrivateKey(pem, passphrase) {
    const lib = eccLib();
    return lib.PRIV_ENVELOPE_WRITE_V1
        ? await lib.encryptPrivateKeyV1(pem, passphrase)
        : await lib.encryptPrivateKey(pem, passphrase);
}

// Unlock the user's ECC private key into memory (prompts for the passphrase once
// per session). Returns the CryptoKey.
async function zkEnsureUnlocked() {
    if (zkState.privateKey) return zkState.privateKey;
    const priv = await apiRequest('/ecc/keys/private', { silent: true });
    if (!priv || !priv.has_keypair || !priv.encrypted_private_key) {
        throw new Error('No encryption key is set up for your account.');
    }
    // Validate shape and bounds BEFORE asking for a passphrase, so a corrupt or hostile blob
    // fails immediately rather than after the user has typed one. Accepts legacy and v1 alike.
    try {
        eccLib().parsePrivateEnvelope(priv.encrypted_private_key);
    } catch (e) {
        // Distinguishing damaged from merely-newer matters here more than anywhere: the advice
        // differs, and the advice this used to give -- re-register -- is refused by the server
        // and would orphan every wrapped vault key if it were not.
        throw new Error(safeMessageForCode(e && e.code, 'unlock'));
    }
    // The registered public key, for the consistency check below. Fetched before the prompt so a
    // server that cannot supply it fails the unlock early rather than after the passphrase.
    const pub = await apiRequest('/ecc/keys/public', { silent: true });
    const pass = await showPrompt(
        'Enter your encryption passphrase to unlock zero-knowledge vaults.',
        'Unlock encryption key', { password: true }
    );
    if (pass === null) throw new Error('Unlock cancelled.');
    let pem;
    try {
        pem = await eccLib().decryptPrivateEnvelope(priv.encrypted_private_key, pass);
    } catch (e) {
        // A wrong passphrase and tampered ciphertext are one outcome to AES-GCM. Everything
        // else -- an unsupported envelope, an unusable key, no WebCrypto at all -- is NOT, and
        // reporting it as a bad passphrase sends the user to re-type a passphrase that is right.
        throw new Error(safeMessageForCode(e && e.code, 'unlock'));
    }
    // Decrypting proves the passphrase; it does not prove this is the ACCOUNT's key. Compare the
    // recovered key with the registered public key as canonical raw points, and FAIL CLOSED when
    // the comparison cannot be made — treating "cannot check" as "passed" would make this
    // optional in exactly the circumstances an attacker controls. Nothing is cached until it does.
    const consistent = await eccLib().privateKeyMatchesRegisteredPublicKey(
        pem, pub && pub.public_key
    );
    if (!consistent) {
        throw new Error(
            'The stored encryption key does not match this account’s registered public key. ' +
            'This is not a passphrase problem — nothing has been unlocked.'
        );
    }
    zkState.privateKey = await eccLib().importPrivateKeyPEM(pem, false);  // non-extractable runtime key
    zkArmIdleLock();  // start the inactivity auto-lock countdown now a key is in memory
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
    const enc = await zkWrapPrivateKey(privatePem, pass);  // legacy shape, or v1 when enabled
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
            pop: { challenge_id: challenge.challenge_id, mac },
        }),
    });
    // Hold a NON-extractable runtime copy (the generated key was extractable only
    // so we could export + password-encrypt it above).
    zkState.privateKey = await lib.importPrivateKeyPEM(privatePem, false);
    zkArmIdleLock();
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
    try {
        eccLib().parsePrivateEnvelope(priv.encrypted_private_key);
    } catch (e) {
        throw new Error(safeMessageForCode(e && e.code, 'change'));
    }
    const current = await showPrompt('Enter your CURRENT encryption passphrase.', 'Change passphrase', { password: true });
    if (current === null) throw new Error('Cancelled.');
    let pem;
    try {
        pem = await eccLib().decryptPrivateEnvelope(priv.encrypted_private_key, current);
    } catch (e) {
        throw new Error(safeMessageForCode(e && e.code, 'change'));
    }
    // Re-wrapping replaces the account's only copy, so confirm this really is the account's key
    // before writing over it. Fails closed.
    const pubForChange = await apiRequest('/ecc/keys/public', { silent: true });
    if (!await eccLib().privateKeyMatchesRegisteredPublicKey(pem, pubForChange && pubForChange.public_key)) {
        throw new Error(safeMessageForCode('KEY_MISMATCH', 'change'));
    }
    const next = await showPrompt('Enter a NEW passphrase. It protects your key and CANNOT be recovered if lost.', 'New passphrase', { password: true });
    if (next === null) throw new Error('Cancelled.');
    if (!next || next.length < 8) throw new Error('Passphrase must be at least 8 characters.');
    const confirm = await showPrompt('Re-enter your NEW passphrase to confirm.', 'Confirm new passphrase', { password: true });
    if (confirm === null) throw new Error('Cancelled.');
    if (confirm !== next) throw new Error('Passphrases do not match.');

    const enc = await zkWrapPrivateKey(pem, next);  // legacy shape, or v1 when enabled
    // Re-wrapping replaces the account's only copy, so prove possession of the registered key.
    // `pem` was already checked against that key above, so it can answer the challenge.
    const provingKey = await eccLib().importPrivateKeyPEM(pem, false);
    await zkPutPrivateEnvelope(enc, provingKey, pubForChange.public_key,
                               pubForChange.user_id, next, pem);
    // Keep a NON-extractable runtime copy so the session stays unlocked with the same key.
    zkState.privateKey = await eccLib().importPrivateKeyPEM(pem, false);
    zkArmIdleLock();
}

// Export a recovery kit: re-wrap the private key under a SEPARATE recovery passphrase and download
// it as a file. The user stores it out-of-band; if they later forget their main passphrase they can
// restore access with the recovery passphrase (zkRestoreFromRecoveryKey). Everything happens in the
// browser — the kit holds only ciphertext the server never sees. Throws Error('Cancelled.') on
// back-out.
async function zkExportRecoveryKey() {
    const priv = await apiRequest('/ecc/keys/private', { silent: true });
    if (!priv || !priv.has_keypair || !priv.encrypted_private_key) throw new Error('No encryption key is set up for your account.');
    try {
        eccLib().parsePrivateEnvelope(priv.encrypted_private_key);
    } catch (e) {
        throw new Error(safeMessageForCode(e && e.code, 'export'));
    }
    const current = await showPrompt('Enter your CURRENT encryption passphrase to export a recovery key.', 'Export recovery key', { password: true });
    if (current === null) throw new Error('Cancelled.');
    let pem;
    try { pem = await eccLib().decryptPrivateEnvelope(priv.encrypted_private_key, current); }
    catch (e) { throw new Error(safeMessageForCode(e && e.code, 'export')); }
    // Not required by the consistency rule, which scopes the check to paths that CACHE a key or
    // replace the stored one. Done anyway because a kit minted from a key that does not match the
    // account is useless, and catching it here turns an unrecoverable surprise at restore into a
    // recoverable error at export.
    const pubForExport = await apiRequest('/ecc/keys/public', { silent: true });
    if (!await eccLib().privateKeyMatchesRegisteredPublicKey(pem, pubForExport && pubForExport.public_key)) {
        throw new Error(safeMessageForCode('KEY_MISMATCH', 'export'));
    }
    const rec = await showPrompt('Choose a RECOVERY passphrase. Store it somewhere safe and SEPARATE from your normal passphrase — it protects the recovery key you are about to download.', 'Recovery passphrase', { password: true });
    if (rec === null) throw new Error('Cancelled.');
    if (!rec || rec.length < 8) throw new Error('Recovery passphrase must be at least 8 characters.');
    const confirm = await showPrompt('Re-enter your RECOVERY passphrase to confirm.', 'Confirm recovery passphrase', { password: true });
    if (confirm === null) throw new Error('Cancelled.');
    if (confirm !== rec) throw new Error('Passphrases do not match.');

    const enc = await zkWrapPrivateKey(pem, rec);  // legacy shape, or v1 when enabled
    // Reuse the response fetched above rather than asking again. The read is not free (it stamps
    // last_used and commits), and reusing it guarantees the kit records the very public key the
    // private key was just checked against, rather than a second read that could disagree with
    // the one the check passed on.
    const kit = {
        type: 'dockvault-zk-recovery-key',
        version: 1,
        // Server-sourced, for the same reason the proof transcripts are: currentUser is hydrated
        // from localStorage, whose loader tolerates corrupt data, and a kit stamped with the wrong
        // account is precisely the unrecoverable surprise the check above exists to prevent.
        user_id: (pubForExport && pubForExport.user_id) || null,
        fingerprint: (pubForExport && pubForExport.fingerprint) || null,
        public_key: (pubForExport && pubForExport.public_key) || null,  // verified on restore
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
    // This file is the only fully attacker-supplied envelope the app reads, so the wrapper AND
    // the envelope inside it are bounded here — before the passphrase prompt and before any key
    // derivation. See docs/design/vault-private-key-envelope-v1.md §1.1.
    let kit;
    try { kit = eccLib().parseRecoveryKitFile(kitText).kit; }
    catch (e) {
        // Which artifact is wrong matters here more than anywhere else in the app. A kit written
        // by a NEWER build is perfectly good and the remedy is to update this deployment; calling
        // it invalid invites the user to discard the only copy of their key.
        throw new Error(safeMessageForCode(e && e.code, 'restore'));
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
    try { pem = await eccLib().decryptPrivateEnvelope(kit.recovery, rec); }
    catch (e) { throw new Error(safeMessageForCode(e && e.code, 'restore')); }
    // SECURITY: verify the DECRYPTED private key actually matches this account's registered public
    // key. The kit's asserted public_key is untrusted metadata (a corrupt/forged/null-public_key
    // kit could carry a different private key), so derive the public key FROM the private key and
    // compare — adopting a mismatched key would silently orphan every wrapped DEK (permanent lockout).
    // Corruptness first, so a structurally invalid key reports as corrupt rather than as a
    // mismatch — they send the user to different remedies.
    try { await eccLib().derivePublicKeyPEMFromPrivatePEM(pem); }
    catch (_) { throw new Error('The recovery key is corrupt or not a valid key.'); }
    // Compare as canonical raw points, not as PEM text. A string comparison reports a mismatch
    // between two encodings of the SAME key — line endings, wrap width, a trailing newline — and
    // this is the one path reached only after the main passphrase is already lost, so a false
    // mismatch here has no way back.
    if (!await eccLib().privateKeyMatchesRegisteredPublicKey(pem, pub.public_key)) {
        throw new Error("This recovery key does not match your account's encryption key and cannot be restored.");
    }
    const next = await showPrompt('Set a NEW encryption passphrase. It replaces your forgotten one and CANNOT be recovered if lost.', 'New passphrase', { password: true });
    if (next === null) throw new Error('Cancelled.');
    if (!next || next.length < 8) throw new Error('Passphrase must be at least 8 characters.');
    const confirm = await showPrompt('Re-enter your NEW passphrase to confirm.', 'Confirm new passphrase', { password: true });
    if (confirm === null) throw new Error('Cancelled.');
    if (confirm !== next) throw new Error('Passphrases do not match.');

    const enc = await zkWrapPrivateKey(pem, next);
    // Recovery works precisely because a valid kit reconstructs the SAME key: the key recovered
    // above is the registered one (verified against it), so it can answer the challenge.
    const recoveredKey = await eccLib().importPrivateKeyPEM(pem, false);
    await zkPutPrivateEnvelope(enc, recoveredKey, pub.public_key,
                               pub.user_id, next, pem);
    zkState.privateKey = await eccLib().importPrivateKeyPEM(pem, false);
    zkArmIdleLock();
}

// Return the server-authoritative public identity key needed to create a zero-knowledge vault.
// An existing keypair is deliberately PUBLIC-ONLY here: vault creation mints a fresh DEK and
// wraps it to this key, so fetching or unlocking the private identity envelope would add exposure
// without granting any capability the operation needs. First registration remains interactive.
// Returns { pem, userId }. The account id comes back from the same response as the key, and
// the caller needs it: a version-2 lock stamps the account it was made for, and the only other
// source is local session state, which this app deliberately does not trust for this (see the
// recovery-kit writer, which refuses it for the same reason).
async function zkEnsurePublicKeyForCreate() {
    const pub = await apiRequest('/ecc/keys/public', { silent: true });
    if (pub && pub.has_keypair) {
        if (!pub.public_key) throw new Error('Your public key is unavailable.');
        // Checked as strictly as the key. Not because an unchecked id would silently produce
        // a bad lock -- the transcript builder rejects anything that is not a canonical uuid,
        // so it would throw -- but because it would throw deep inside the crypto with a
        // message about the wrong thing, when the real fault is a response missing a field.
        if (!pub.user_id) throw new Error('Your account identity is unavailable.');
        return { pem: pub.public_key, userId: pub.user_id };
    }
    // REFUSE + GUIDE — do NOT silently register a keypair here. Registering mid-vault-create presents
    // the account encryption-KEY passphrase prompt at the exact moment the user is creating a vault,
    // so they read it as "the vault's password" and set the two to the same value. The encryption key
    // is account-level, the only key to every ZK vault, and irrecoverable — it must be set up
    // deliberately, once, via the profile "Set up encryption key" flow. Refuse here and route them
    // there; they re-create the vault afterward. (The server also refuses create for a keyless user.)
    const err = new Error('Set up your encryption key before creating a zero-knowledge vault. Use '
        + '"Set up encryption key" in your profile menu (top-right), create your key, then create the '
        + 'vault. Your encryption-key passphrase is NOT the vault password.');
    err.code = 'zk_no_encryption_key';
    throw err;
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
            showError(isCodedCryptoError(e)
                ? safeMessageForCode(e.code, 'unlock')
                : (msg || 'Failed to set up encryption key'));
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
        if (!/cancelled/i.test(msg)) {
            showError(isCodedCryptoError(e)
                ? safeMessageForCode(e.code, 'change')
                : (msg || 'Failed to change passphrase'));
        }
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
        if (!/cancelled/i.test(msg)) {
            showError(isCodedCryptoError(e)
                ? safeMessageForCode(e.code, 'export')
                : (msg || 'Failed to export recovery key'));
        }
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
        if (!/cancelled/i.test(msg)) {
            showError(isCodedCryptoError(e)
                ? safeMessageForCode(e.code, 'restore')
                : (msg || 'Failed to restore from recovery key'));
        }
    } finally {
        await refreshEncryptionKeyStatus();
    }
}

// The set of blind indices a name could already be STORED under, sent with an upload so the
// server matches a same-name file sealed before a rotation (whose index sits at an old epoch the
// current one can't equal). One entry per epoch 1..currentEpoch, using the current epoch's DEK
// (already unwrapped for this upload) and the per-epoch cache for the rest.
//
// Best-effort by contract: a member who joined after a rotation holds no old-epoch wrap, and any
// derivation failure here must NOT block the upload -- it falls back to the single current-epoch
// index, which is exactly the single-value behaviour (the server then matches that one). Never
// throws.
async function zkUploadNameCandidates(lib, name, vaultId, currentEpoch, currentDek) {
    const epoch = Number(currentEpoch) || 1;
    try {
        const deks = [];
        for (let e = 1; e <= epoch; e++) {
            const d = (e === epoch) ? currentDek : await zkGetVaultDek(vaultId, e);
            if (d) deks.push({ epoch: e, dek: d });
        }
        const out = deks.length ? (await lib.nameBlindIndexCandidates(name, vaultId, deks)).slice() : [];
        // The rotation-independent index, if this vault has a name-index key. Added to the match
        // set so a row written under it is found. Today NOTHING writes one (a later increment does),
        // so it simply matches nothing. Purely additive: it never removes a legacy candidate, and a vault
        // with no index key (or an unwrap that fails) sends exactly what it did before.
        const K = await zkGetVaultIndexKey(vaultId).catch(() => null);
        if (K) {
            const idx = await lib.nameIndexKeyBlindIndex(name, K, vaultId);
            if (!out.includes(idx)) out.push(idx);
        }
        return out.length ? out : null;
    } catch (_) {
        // An epoch we cannot unwrap, or any other hiccup: send nothing extra and let the server
        // fall back to the single name_bi. A missed old-epoch clash is the pre-existing behaviour,
        // not a regression, and it is never worth failing an upload over.
        return null;
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
            vaultId, keys.team_key_version, keys.wrapped_team_privkey,
            keys.team_ephemeral_public_key, keys.recipient_user_id);
        // teamMode says which purpose this caller will accept. The payload's own byte never
        // gets to choose; it is compared against this and rejected if it disagrees.
        dek = await eccLib().unwrapVaultDEK(
            keys.wrapped_dek, keys.ephemeral_public_key, teamPriv,
            { vaultId, dekEpoch: version, teamMode: true });
    } else {
        // Downgrade defense: a vault we have seen as hierarchical must never be served a DIRECT
        // key. Refuse loudly rather than fall through (the direct unwrap would fail closed anyway).
        if (zkState.pinnedHier[vaultId]) {
            throw new Error('This zero-knowledge vault is hierarchical but the server returned a direct key — refusing (possible mode downgrade).');
        }
        // v2 wraps bind the vault, the recipient and the epoch into their transcript. All
        // three come from this response rather than from local state: `recipient_user_id` is
        // the account the server says it selected the row for, which is a better source than
        // `currentUser` -- that is hydrated from localStorage by a loader that tolerates
        // corrupt data, and the recovery-kit writer already refuses it for the same reason.
        // A legacy wrap ignores the context entirely, so passing it is always safe.
        dek = await eccLib().unwrapVaultDEK(
            keys.wrapped_dek, keys.ephemeral_public_key, priv,
            { vaultId, recipientUserId: keys.recipient_user_id, dekEpoch: version });
    }
    perVault[version] = dek;
    return dek;
}

// Mint this vault's NAME INDEX key and wrap it for the current user. Called once at vault
// creation. The key never rotates, so there is one per vault for its whole life; the server
// stores only the opaque wrap. BEST-EFFORT: a vault whose index key was not minted simply keeps
// matching same-name rows on the legacy per-epoch indices, so a failure here must not fail the
// create -- it is swallowed and the vault works.
async function zkMintOwnIndexKey(vaultId) {
    try {
        const identity = await zkEnsurePublicKeyForCreate();
        const lib = eccLib();
        const pub = await lib.importPublicKeyPEM(identity.pem);
        const K = await lib.generateVaultDEK();            // a fresh 32-byte AES key
        const w = await lib.wrapNameIndexKeyV2(K, pub, { vaultId, recipientUserId: identity.userId });
        await apiRequest(`/ecc/vaults/${vaultId}/index-key`, {
            method: 'PUT', silent: true,
            body: JSON.stringify({ wraps: [{
                user_id: identity.userId,
                encrypted_index_key: w.wrappedKey,
                ephemeral_public_key: w.ephemeralPublicKey,
            }] }),
        });
        zkState.vaultIndexKeys[vaultId] = K;   // cache so a later write need not round-trip
        return K;
    } catch (_) {
        // Non-fatal by contract. A 409 (another client minted first) or any other hiccup just
        // means this vault will use legacy indices until a client reads and adopts the key.
        return null;
    }
}

// Get (and cache) the unwrapped name-index key for a vault, or null if the vault has none. Mirrors
// zkGetVaultDek: the wrap + its ephemeral come from GET /index-key, and the recipient id comes from
// that same response (the account the server selected the row for), never from local state -- the
// unwrap transcript binds it, and localStorage identity tolerates corrupt data.
async function zkGetVaultIndexKey(vaultId) {
    const cached = zkState.vaultIndexKeys[vaultId];
    if (cached) return cached;
    const resp = await apiRequest(`/ecc/vaults/${vaultId}/index-key`, { silent: true });
    if (!resp || !resp.index_key) return null;   // no key minted for this vault yet
    const priv = await zkEnsureUnlocked();
    const K = await eccLib().unwrapNameIndexKeyV2(
        resp.index_key, resp.ephemeral_public_key, priv,
        { vaultId, recipientUserId: resp.recipient_user_id });
    zkState.vaultIndexKeys[vaultId] = K;
    return K;
}

// Unwrap (and cache) a hierarchical vault's TEAM PRIVATE key at a given team epoch. The wrapped
// blob + its ephemeral come from the /keys response (no extra fetch). Cached per (vault, team
// epoch); the runtime key is non-extractable. Cleared on logout via zkResetKeys.
async function zkGetTeamPrivKey(vaultId, teamEpoch, wrappedTeamPrivkey, teamEphemeralPublicKey,
                                recipientUserId) {
    const perVault = zkState.teamKeys[vaultId] || (zkState.teamKeys[vaultId] = {});
    if (teamEpoch != null && perVault[teamEpoch]) return perVault[teamEpoch];
    const priv = await zkEnsureUnlocked();
    // The account this wrap was made for. It has to come from the caller: this function is
    // handed the vault, the epoch and the two blobs, and an absent id would be encoded as
    // nothing rather than refused -- a wrap that authenticates against nothing.
    const teamPriv = await eccLib().unwrapPrivateKeyFromWrapped(
        wrappedTeamPrivkey, teamEphemeralPublicKey, priv, false,
        { vaultId, recipientUserId });
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
//
// The vault id, the file's own id and its epoch are passed through: a version-2 content file
// derives its key from all three and authenticates them, so a reader cannot open one without
// knowing which object it is reading. The older whole-file format ignores them.
// Work out which key a file was sealed under, and fetch it. Shared by the two decrypt paths
// below so that the awkward part -- a listing too stale to name the epoch -- has one answer
// rather than two that drift.
async function zkResolveKey(vault, keyVersion, fileId) {
    // A caller that named a file but could not say which epoch it used does not know enough to
    // decrypt it. Guessing 1 is what the lookup stopped doing, and coercing the null back into a 1
    // here would put the guess straight back.
    //
    // But the usual reason for a miss is a stale listing, not a missing file -- a download begun
    // before the six-second refresh, say. That is worth one reload before giving up, because the
    // alternative is telling someone their intact file failed to decrypt.
    if (fileId && keyVersion == null) {
        try { await loadVaultFiles(); } catch (_) { /* the retry below reports it */ }
        keyVersion = zkFileKeyVersion(fileId);
    }
    if (fileId && keyVersion == null) {
        const e = new Error('zk.epoch.unknown');
        // Carried separately from `message`: the catches show a fixed sentence for anything
        // without a crypto code, and "failed to decrypt" is damage wording for a file that is
        // perfectly intact and one refresh away.
        e.userMessage = 'This file is no longer in the current listing, so the app cannot tell '
                      + 'which key it was saved under. Reopen the folder and try again.';
        throw e;
    }
    const epoch = keyVersion != null ? keyVersion : 1;
    return {
        dek: await zkGetVaultDek(vault.id, epoch),
        context: { vaultId: vault.id, objectId: fileId, dekEpoch: epoch },
    };
}

// Decrypt a downloaded blob when the given vault is zero-knowledge; else pass through.
async function zkMaybeDecryptBlob(blob, vault, keyVersion = null, fileId = null) {
    if (!isZkVault(vault)) return blob;
    const { dek, context } = await zkResolveKey(vault, keyVersion, fileId);
    const lib = eccLib();
    const type = blob.type || 'application/octet-stream';

    // Chunk-framed content can be read a record at a time, so no single buffer ever holds the
    // whole plaintext. That is worth having, but it is a smaller claim than it sounds: the parts
    // are real bytes, and measurement puts the tab's resident memory at roughly one copy of the
    // file regardless. See the download-sink design note for the numbers.
    //
    // The older whole-file format cannot even do this much: its tag covers everything, so nothing
    // can be released until all of it has arrived, and that is a property of the file rather than
    // of this code.
    const head = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
    if (lib.decryptBlobV2 && lib._inspectV2Header(head) === 'UNSUPPORTED') {
        const parts = [];
        await lib.decryptBlobV2(blob, dek, context, p => { parts.push(new Blob([p])); });
        return new Blob(parts, { type });
    }

    const plain = await lib.decryptFile(await blob.arrayBuffer(), dek, context);
    return new Blob([plain], { type });
}

// Decrypt a download AS IT ARRIVES, so the ciphertext is never materialised whole.
//
// The blob form above still needs the entire response to exist as one object before it can start.
// Reading from the body removes that object: the ciphertext arrives as records and is consumed as
// it arrives.
//
// What this does NOT do is keep the file out of the tab, and an earlier version of this comment
// said it did. Measured on Chromium at 16, 64 and 128 MiB, resident memory grows by about one
// copy of the plaintext whichever way the parts are accumulated -- as Blob parts, or staged in
// the origin-private file system, which was the alternative built to beat it and did not. One
// copy of the plaintext is the floor for any sink that ends in an object URL.
//
// Three things have to be true, and any of them missing is a reason to fall back rather than an
// error: a body to read, a declared length to derive the framing from, and a header that says
// this is the chunk-framed format. A response served without Content-Length -- a proxy
// re-encoding it, a compressed transfer -- simply takes the older path.
//
// Nothing is shown before it authenticates. The reader resolves only once the final record
// verifies, and the caller builds the object URL from what this returns, so a failure throws with
// the parts still unreferenced.
// How many times a dropped connection is resumed before the transfer is called failed. Small on
// purpose: each attempt costs a request, and a link that drops four times in one file is not
// going to deliver it.
const ZK_RESUME_ATTEMPTS = 3;

function zkDownloadHeaders() {
    const headers = { 'Authorization': `Bearer ${authToken}` };
    if (state.currentVault && state.currentVault.has_password && state.vaultPassword) {
        headers['X-Vault-Password'] = state.vaultPassword;
    }
    return headers;
}

// --- streaming download sink ------------------------------------------------------------------
//
// Writes decrypted records straight into a download instead of accumulating them. Used only when
// the resolved policy says `streaming` -- see app/core/download_sink.py for who decides, and
// docs/design/vault-download-sink-and-policy.md for what it costs.

let _sinkWorker = null;

async function dvSinkWorker() {
    // Registered lazily, never at boot. A service worker is origin-wide and persistent; installing
    // one on every visitor to support a mode most deployments do not enable would be a large,
    // invisible change for no benefit.
    if (_sinkWorker) return _sinkWorker;
    if (!('serviceWorker' in navigator) || !window.isSecureContext) return null;
    try {
        const registration = await navigator.serviceWorker.register('/download-sw.js', { scope: '/' });
        await navigator.serviceWorker.ready;
        _sinkWorker = registration.active || navigator.serviceWorker.controller;
        return _sinkWorker;
    } catch (_) {
        // A deployment that cannot register one simply does not stream. The caller falls back.
        return null;
    }
}

/**
 * Open a download the page can write into. Resolves to null when streaming is unavailable, which
 * the caller must treat as "use the buffered path" rather than as an error.
 *
 * Returns `{ write, done, abort }`. `write` takes a Uint8Array and transfers it, so the caller
 * must not reuse the buffer afterwards.
 */
async function dvOpenDownloadSink({ filename, size, mime }) {
    const worker = await dvSinkWorker();
    if (!worker) return null;

    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    const channel = new MessageChannel();

    const url = await new Promise(resolve => {
        const timer = setTimeout(() => resolve(null), 5000);
        channel.port1.onmessage = event => {
            const data = event.data || {};
            if (data.type === 'dv-sink-ready') { clearTimeout(timer); resolve(data.url); }
        };
        worker.postMessage(
            { type: 'dv-sink-open', id, filename, size, mime }, [channel.port2]);
    });
    if (!url) return null;

    // A hidden same-origin iframe, NOT an anchor, and this is not a style choice. An anchor
    // navigates the document; if the stream then errors, the browser follows that navigation to
    // an error page and the application is gone. Measured: Chromium tolerates it, Firefox does
    // not -- the page was destroyed. An iframe confines a failure to the frame. CSP already
    // allows it (frame-src 'self').
    const frame = document.createElement('iframe');
    frame.style.display = 'none';
    frame.src = url;
    document.body.appendChild(frame);

    const cleanup = () => { try { frame.remove(); } catch (_) { /* already gone */ } };

    return {
        write(bytes) {
            const copy = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
            channel.port1.postMessage({ type: 'chunk', bytes: copy.buffer }, [copy.buffer]);
        },
        done() {
            channel.port1.postMessage({ type: 'done' });
            setTimeout(cleanup, 2000);
        },
        abort(reason) {
            // Erroring the stream is what makes the browser mark the download failed rather than
            // complete-but-short. On Firefox it may surface nothing at all, which is why the
            // caller must also tell the user itself.
            channel.port1.postMessage({ type: 'abort', reason: String(reason || 'failed') });
            setTimeout(cleanup, 2000);
        },
    };
}

/**
 * Decrypt a zero-knowledge download straight into a browser download.
 *
 * Three outcomes, and the caller must distinguish them:
 *   `true`     - the download is under way; nothing more to do.
 *   `false`    - streaming was never entered: no sink was opened and nothing was written. Fall
 *                back, but note the response body has been read from, so the caller must
 *                re-fetch. Returned ONLY before the sink exists. Once it does, a failure is
 *                `'failed'` however few records went out -- the stream has been errored, so a
 *                failed download entry already exists, and reporting "nothing was written" would
 *                send the caller off to fetch the whole object again to retry a failure that
 *                will repeat.
 *   `'failed'` - bytes were written and the transfer then failed. There may be a partial file in
 *                the user's downloads, and the app must say so, because the browser may not.
 *
 * The distinction between `false` and `'failed'` is the whole contract. Collapsing them would
 * either hide a real failure or re-download a file that is already arriving.
 */
async function zkTryStreamedDownload(response, vault, keyVersion, fileId, fileName) {
    const lib = eccLib();
    const declared = Number(response.headers.get('Content-Length'));
    if (!response.body || typeof lib.decryptStreamV2 !== 'function'
        || !Number.isSafeInteger(declared) || declared <= 0) {
        return false;
    }

    // The header tells us both whether this is the chunk-framed format and how long the plaintext
    // is -- and the length has to be known BEFORE the sink is opened, because it becomes the
    // download's Content-Length and is what lets the browser call a short body a failure.
    const peeked = await lib._peekStream(response.body, 28);
    if (lib._inspectV2Header(peeked.head) !== 'UNSUPPORTED') return false;

    let framing;
    try {
        framing = lib.v2ContentResumeOffset(peeked.head, declared, 0);
    } catch (_) {
        return false;                      // not framing we can read; the buffered path will say why
    }
    const plaintextLength = framing.totalPlaintext;
    if (!Number.isSafeInteger(plaintextLength) || plaintextLength <= 0) return false;

    const sink = await dvOpenDownloadSink({
        filename: fileName,
        size: plaintextLength,
        mime: response.headers.get('Content-Type') || 'application/octet-stream',
    });
    if (!sink) return false;

    const { dek, context } = await zkResolveKey(vault, keyVersion, fileId);
    const etag = response.headers.get('ETag');

    let records = 0;                       // records HANDED OVER, which is what may be resumed from
    let stream = peeked.stream;
    let startRecord = 0;
    let attempts = 0;

    for (;;) {
        try {
            await lib.decryptStreamV2(stream, declared, dek, context, piece => {
                records += 1;
                sink.write(piece);
            }, startRecord > 0 ? { startRecord, header: peeked.head } : undefined);
            sink.done();
            return true;
        } catch (error) {
            // Retry only what a retry can fix. A coded failure means the bytes that arrived do
            // not authenticate under the key and index they claim -- re-requesting the same range
            // returns the same bytes and fails identically, so a loop here would spin while
            // looking, from outside, like a flaky network.
            const transport = !isCodedCryptoError(error);
            if (!transport || attempts >= ZK_RESUME_ATTEMPTS || !etag) {
                sink.abort(error && error.code ? error.code : 'failed');
                return 'failed';
            }

            attempts += 1;
            let resume;
            try {
                resume = lib.v2ContentResumeOffset(peeked.head, declared, records);
            } catch (_) {
                sink.abort('resume-offset');
                return 'failed';
            }
            if (resume.done) { sink.done(); return true; }

            let next;
            try {
                next = await fetch(
                    `${API_BASE}/vaults/${vault.id}/files/${fileId}/download`,
                    { headers: { ...zkDownloadHeaders(), 'Range': `bytes=${resume.offset}-`,
                                 'If-Range': etag } });
            } catch (_) {
                sink.abort('reconnect-failed');
                return 'failed';
            }

            // A 200 where a range was asked for means the entity tag no longer matches: the object
            // changed under the resume. Bytes are already in the download and a stream cannot be
            // rewound, so this cannot restart -- it can only fail honestly. Appending the new
            // version to the old one is the splice the tag exists to prevent.
            if (next.status !== 206 || !next.body) {
                sink.abort('object-changed');
                return 'failed';
            }

            stream = next.body;
            startRecord = records;
        }
    }
}

async function zkMaybeDecryptResponse(response, vault, keyVersion = null, fileId = null) {
    if (!isZkVault(vault)) return response.blob();
    const lib = eccLib();
    const declared = Number(response.headers.get('Content-Length'));
    const streamable = response.body && typeof lib.decryptStreamV2 === 'function'
        && Number.isSafeInteger(declared) && declared > 0;
    if (!streamable) {
        return zkMaybeDecryptBlob(await response.blob(), vault, keyVersion, fileId);
    }

    // Peeking would normally cost the bytes it looks at; this hands back a stream that still
    // begins with them, so a file in the older format loses nothing by having been inspected.
    const { head, stream } = await lib._peekStream(response.body, 8);
    if (lib._inspectV2Header(head) !== 'UNSUPPORTED') {
        return zkMaybeDecryptBlob(await new Response(stream).blob(), vault, keyVersion, fileId);
    }

    const { dek, context } = await zkResolveKey(vault, keyVersion, fileId);
    const type = response.headers.get('Content-Type') || 'application/octet-stream';
    const parts = [];
    await lib.decryptStreamV2(stream, declared, dek, context, p => { parts.push(new Blob([p])); });
    return new Blob(parts, { type });
}

// Look up a file's DEK epoch from the loaded listing (state.currentFiles).
//
// Returns null when the file is not in the loaded listing, and the caller must treat that as a
// failure. This used to answer 1 for a miss, which was harmless while the epoch only chose which
// key to unwrap -- a wrong guess failed loudly at the next step. It is now an input to the content
// key derivation, so a confident wrong 1 would produce an authentication failure reported as a
// damaged file.
function zkFileKeyVersion(fileId) {
    const item = (state.currentFiles || []).find(i => i.id === fileId);
    if (!item) return null;
    return item.key_version != null ? item.key_version : 1;
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
    if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
        // The same availability failure the library reports, reported the same way, rather than
        // a TypeError from the next line.
        throw new (eccLib().constructor.CryptoError)(
            eccLib().constructor.CODES.CRYPTO_UNAVAILABLE, 'zkNewObjId');
    }
    const b = new Uint8Array(16);
    window.crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;  // version 4
    b[8] = (b[8] & 0x3f) | 0x80;  // variant 10
    const h = [...b].map(x => x.toString(16).padStart(2, '0'));
    return `${h[0]}${h[1]}${h[2]}${h[3]}-${h[4]}${h[5]}-${h[6]}${h[7]}-${h[8]}${h[9]}-${h[10]}${h[11]}${h[12]}${h[13]}${h[14]}${h[15]}`;
}

// 16 random bytes naming ONE encryption attempt, as 32 lowercase hex characters.
//
// Distinct from the object id above, and needed alongside it. The object id stays the same when an
// interrupted upload resumes -- it has to, because the file's name is sealed against it -- so it
// cannot tell two ATTEMPTS at the same file apart. This can. Two encryptions of one file are not
// interchangeable, and a stored object built from a chunk of each will never decrypt.
function zkNewBlobId() {
    if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
        // The same availability failure the library reports, reported the same way.
        throw new (eccLib().constructor.CryptoError)(
            eccLib().constructor.CODES.CRYPTO_UNAVAILABLE, 'zkNewBlobId');
    }
    const b = new Uint8Array(16);
    window.crypto.getRandomValues(b);
    return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
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
        if (isCodedCryptoError(e)) {
            showError(safeMessageForCode(e.code, 'unlock'));
        } else if (!/cancel/i.test(e.message || '')) {
            showError(e.message);
        }
        return;
    }
    // A per-row failure below is swallowed into a placeholder on purpose -- one damaged name
    // must not take down a listing. An unusable platform is different in kind: it fails EVERY
    // row, and swallowing it leaves a directory of padlocks and no explanation. Report it once.
    let unavailable = false;
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
            if (e && e.code === 'CRYPTO_UNAVAILABLE') unavailable = true;
        }
    }
    if (unavailable) showError(safeMessageForCode('CRYPTO_UNAVAILABLE', 'unlock'));
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

// The ONE place that decides which format to write for a DEK wrapped to a TEAM key.
async function zkWrapTeamDek(dek, teamPub, transcript) {
    const lib = eccLib();
    return lib.ZK_WRAP_WRITE_V2
        ? lib.wrapTeamDEKV2(dek, teamPub, transcript)
        : lib.wrapVaultDEK(dek, teamPub);
}

// And for the team PRIVATE key wrapped to one member.
async function zkWrapTeamPrivateKey(teamPriv, recipientPub, transcript) {
    const lib = eccLib();
    return lib.ZK_WRAP_WRITE_V2
        ? lib.wrapTeamPrivateKeyV2(teamPriv, recipientPub, transcript)
        : lib.wrapPrivateKeyToPublic(teamPriv, recipientPub);
}

// The ONE place that decides which DEK-wrap format to write.
//
// A single choke point rather than the gate being consulted at each call site: a third write
// site added later inherits the decision instead of having to remember it, and forgetting is
// not a visible bug -- it just quietly keeps writing the old format while everything else
// moves on. The transcript is required either way, so a caller cannot supply half of it.
async function zkWrapDekForRecipient(dek, recipientPub, transcript) {
    const lib = eccLib();
    return lib.ZK_WRAP_WRITE_V2
        ? lib.wrapVaultDEKV2(dek, recipientPub, transcript)
        : lib.wrapVaultDEK(dek, recipientPub);
}

// Share a zero-knowledge vault with another user: unwrap the DEK locally, re-wrap
// it to THEIR public key in the browser, and store the wrapped copy. The server
// never sees the DEK. Throws if the recipient hasn't set up an encryption key.
async function zkShareVaultToUser(vaultId, userId) {
    const pk = await apiRequest(`/ecc/users/${userId}/public-key`, { silent: true });
    if (!pk || !pk.has_keypair || !pk.public_key) {
        // Team-onboarding: a zero-knowledge DEK can't be wrapped for a keyless recipient yet, so
        // record an invite (which prompts them to set up a key) and report PENDING — do NOT throw.
        // The caller still creates the authz membership row (the server permits a keyless member);
        // the wrapped key follows automatically once the recipient sets up their encryption key.
        // Best-effort invite: the membership row + pending state stand even if the invite POST fails.
        let invited = false;
        try {
            await apiRequest(`/ecc/vaults/${vaultId}/invites`, {
                method: 'POST', body: JSON.stringify({ user_id: userId }), silent: true,
            });
            invited = true;
        } catch (_) { /* the membership row + pending state still stand */ }
        return { pending: true, invited };
    }
    const recipientPub = await eccLib().importPublicKeyPEM(pk.public_key);
    const keys = await apiRequest(`/ecc/vaults/${vaultId}/keys`, { silent: true });
    if (keys && keys.wrapped_team_privkey && keys.team_ephemeral_public_key) {
        // HIERARCHICAL: re-wrap the TEAM PRIVATE key to the recipient (O(1) — the DEK is not
        // touched, it stays wrapped to the team public key). Unwrap an EXTRACTABLE copy just to
        // re-wrap it; never cache the extractable form.
        const myPriv = await zkEnsureUnlocked();
        // Two different accounts, three lines apart. The read opens a wrap made for ME, so it
        // names my account; the write makes one for the person being shared with, so it names
        // theirs. Swapping them fails as an authentication error that looks like tampering.
        const teamPriv = await eccLib().unwrapPrivateKeyFromWrapped(
            keys.wrapped_team_privkey, keys.team_ephemeral_public_key, myPriv, true,
            { vaultId, recipientUserId: keys.recipient_user_id });
        const { wrappedKey, ephemeralPublicKey } = await zkWrapTeamPrivateKey(
            teamPriv, recipientPub, { vaultId, recipientUserId: userId });
        await apiRequest(`/ecc/vaults/${vaultId}/members`, {
            method: 'POST',
            body: JSON.stringify({ user_id: userId, wrapped_team_privkey: wrappedKey, team_ephemeral_public_key: ephemeralPublicKey }),
        });
        return { pending: false };
    }
    // DIRECT: wrap the DEK straight to the recipient.
    // Pin the DEK to the epoch we already read above. Called with no epoch this refetches
    // /keys independently, so the key could come back at a DIFFERENT epoch than the one we
    // are about to declare -- and declaring an epoch the blob does not match is precisely
    // the failure this change exists to stop.
    const dek = await zkGetVaultDek(vaultId, keys && keys.key_version);  // may prompt once
    // ONE value, used in both places below. An earlier version computed the epoch twice with
    // different fallbacks -- 1 for the wrap, absent for the declaration -- which is two different
    // answers to the same question on adjacent lines, and the shape of a bug where the recipient
    // ends up holding a key labelled as something it is not.
    const shareEpoch = keys && keys.key_version != null ? keys.key_version : null;
    const { wrappedDEK, ephemeralPublicKey } = await zkWrapDekForRecipient(
        dek, recipientPub, { vaultId, recipientUserId: userId, dekEpoch: shareEpoch });
    // Tell the server which epoch this blob wraps. Without it the server stamps whatever the
    // vault's epoch is when the request lands, so a rotation arriving in between labels our
    // old-DEK blob as the new epoch AND overwrites the correct row the rotation just wrote --
    // leaving the recipient unable to read anything written after it, with no error anywhere.
    await apiRequest(`/ecc/vaults/${vaultId}/members`, {
        method: 'POST',
        body: JSON.stringify({
            user_id: userId,
            wrapped_dek: wrappedDEK,
            ephemeral_public_key: ephemeralPublicKey,
            dek_version: shareEpoch != null ? shareEpoch : undefined,
        }),
    });
    return { pending: false };
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
            // Every remaining member is re-wrapped here, so a rotation is where a vault
            // converts wholesale to v2, the owner's own wrap included. That is what keeps the
            // legacy wrap written at creation from mattering much -- but only for vaults that
            // ever rotate: this path runs on member revocation, so a vault that never removes
            // anyone keeps its original wrap indefinitely. Harmless, since the reader takes
            // both, but it is a mixed state rather than a passing one.
            const { wrappedDEK, ephemeralPublicKey } = await zkWrapDekForRecipient(
                newDek, recipientPub,
                { vaultId, recipientUserId: uid, dekEpoch: fromVersion + 1 });
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
    const dekWrap = await zkWrapTeamDek(newDek, teamKp.publicKey,      // DEK -> new team pubkey
        { vaultId, dekEpoch: fromVersion + 1 });
    const memberKeys = [];
    for (const uid of remaining) {
        const pk = await apiRequest(`/ecc/users/${uid}/public-key`, { silent: true });
        if (!pk || !pk.has_keypair || !pk.public_key) {
            throw new Error('A remaining member has no encryption key; cannot rotate the team key.');
        }
        const recipientPub = await ecc.importPublicKeyPEM(pk.public_key);
        const { wrappedKey, ephemeralPublicKey } = await zkWrapTeamPrivateKey(
            teamKp.privateKey, recipientPub, { vaultId, recipientUserId: uid });
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
// Downloads share the page's transfer gate with uploads, so a user who starts a batch of
// downloads while files are uploading does not run both sets at once.
async function downloadFile(fileId, fileName) {
    return transferGate.run(() => _downloadFile(fileId, fileName));
}

async function _downloadFile(fileId, fileName) {
    try {
        // Zero-knowledge: if we couldn't decrypt this item's NAME we also lack the DEK for
        // its content epoch, so a download can't be decrypted here — say so plainly.
        const locked = (state.currentFiles || []).find(i => i.id === fileId && i.zkLocked);
        if (locked) {
            showError("This file is encrypted under a key version you don't have, so it can't be downloaded here.");
            return;
        }
        // Immediate feedback, because nothing reports progress between here and the save. That
        // used to be because the whole response was buffered first; now the records are decrypted
        // as they arrive and it is the accumulated parts that are held until the end. The reader
        // does hand over each record, so a byte count is available to whoever wants to show one.
        showInfo(`Downloading "${fileName}"…`);
        // Build headers with auth + vault password if needed
        const headers = { 'Authorization': `Bearer ${authToken}` };
        if (state.currentVault.has_password && state.vaultPassword) {
            headers['X-Vault-Password'] = state.vaultPassword;
        }

        // Fetch file. Not const: a streaming attempt that cannot proceed has already consumed
        // this body, so the buffered fallback replaces it.
        let response = await fetch(`${API_BASE}/vaults/${state.currentVault.id}/files/${fileId}/download`, {
            headers
        });
        
        if (!response.ok) {
            throw new Error('Download failed');
        }
        
        // Decrypting in-browser for zero-knowledge vaults, from the body rather than from a
        // materialised copy of it. A standard vault still takes the blob, which the server has
        // already decrypted.
        // Streaming writes each decrypted record straight into a download, so nothing
        // accumulates and size stops being a limit. Attempted only when the resolved policy asks
        // for it; anything that does not line up falls through to the buffered path rather than
        // failing, because a download that works is worth more than the mode it used.
        if (isZkVault(state.currentVault) && state.downloadSink === 'streaming') {
            const streamed = await zkTryStreamedDownload(
                response, state.currentVault, zkFileKeyVersion(fileId), fileId, fileName);
            if (streamed === true) {
                showSuccess(`Downloading "${fileName}"`);
                return;
            }
            if (streamed === 'failed') {
                // The browser may show nothing at all for an aborted stream -- measured on
                // Firefox -- so the app has to say it itself or the user sees silence.
                showError(`Download of "${fileName}" failed part-way. `
                          + `Any partial file in your downloads is incomplete.`);
                return;
            }
            // streamed === false: streaming was not possible, and nothing was written. The
            // response body is spent, so the buffered path below re-fetches.
            response = await fetch(
                `${API_BASE}/vaults/${state.currentVault.id}/files/${fileId}/download`,
                { headers });
            if (!response.ok) throw new Error('Download failed');
        }

        let blob;
        if (isZkVault(state.currentVault)) {
            try { blob = await zkMaybeDecryptResponse(response, state.currentVault,
                zkFileKeyVersion(fileId), fileId); }
            catch (e) {
                showError(isCodedCryptoError(e) ? safeMessageForCode(e.code, 'unlock')
                    : (e && e.userMessage) || 'Failed to decrypt file.');
                return;
            }
        } else {
            blob = await response.blob();
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
        // Zero-knowledge vault: decrypt the ciphertext in-browser before rendering, reading from
        // the body rather than a materialised copy. Preview needs the whole plaintext in the end
        // -- it becomes an object URL for an image or a video element -- but it does not need the
        // ciphertext and the plaintext to exist as whole buffers on the way there, and a video is
        // exactly the size where that matters.
        let blob = isZkVault(state.currentVault)
            ? await zkMaybeDecryptResponse(resp, state.currentVault,
                zkFileKeyVersion(fileId), fileId)
            : await resp.blob();

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
        // Built as DOM rather than assigned as markup, and the text is chosen from the contract's
        // fixed set rather than taken from the failure -- a crypto error's message is not a
        // sentence, and rendering one here would read to the user as advice.
        console.error('preview failed', (e && e.code) || 'UNCODED');
        const alert = document.createElement('div');
        alert.className = 'alert alert-error';
        alert.textContent = isCodedCryptoError(e) ? safeMessageForCode(e.code, 'unlock')
            : (e && e.userMessage) || 'This file could not be previewed.';
        bodyEl.replaceChildren(alert);
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
                // Clash detection must consider a same-name row at ANY epoch, not just this
                // item's: renaming INTO a name sealed before a rotation would otherwise miss it and
                // create a duplicate. Candidates span 1..current; best-effort (never blocks).
                const curEpoch = await zkGetCurrentDekVersion(vid);
                const curDek = (curEpoch === epoch) ? dek : await zkGetVaultDek(vid, curEpoch);
                body = {
                    enc_name: await lib.encryptName(newName.trim(), dek, vid, 'name', epoch, itemId),
                    name_bi: await lib.nameBlindIndex(newName.trim(), dek, vid, epoch),
                    name_bi_candidates: await zkUploadNameCandidates(lib, newName.trim(), vid, curEpoch, curDek),
                };
                if (type === 'folder') body.name_key_version = epoch;
            } catch (e) {
                showError(isCodedCryptoError(e)
                    ? safeMessageForCode(e.code, 'unlock')
                    : 'Zero-knowledge encryption failed.');
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
        // Operation and code only: this catch is downstream of crypto calls, and a coded
        // failure retains the platform exception as its cause.
        console.error('rename failed', (error && error.code) || 'UNCODED');
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
    // Share is only for Standard, non-password vaults (the backend refuses zero-knowledge + password-
    // protected); hide the affordance otherwise so it isn't a dead-end.
    show(document.getElementById('share-vault-btn'), vaultShareable());
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
                headers: {
                    'Authorization': `Bearer ${authToken}`,
                    // This is a liveness probe, not the user opening the vault. Without the marker
                    // a vault left open in a background tab would re-stamp its own "last viewed"
                    // three times a minute and sit permanently at the top of that ordering.
                    'X-Access-Check': '1',
                }
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
// A breadcrumb entry inside a ZERO-KNOWLEDGE vault carries the folder's client-decrypted name.
// Persisting it to sessionStorage would write that plaintext to disk, defeating the vault's whole
// promise (the server never sees these names; neither should the disk). Strip the labels from the
// path we persist for a ZK vault -- the ids still restore the folder and drive the clickable
// breadcrumb, and the labels repopulate as the user navigates. A standard vault's names are already
// server-known, so nothing is gained by dropping them and the fuller breadcrumb is kept.
function navPathForStorage(path, isZeroKnowledge) {
    if (!Array.isArray(path)) return [];
    if (!isZeroKnowledge) return path;
    return path.map(f => ({ id: f && f.id }));
}
function saveNavState(override) {
    let nav;
    if (override) {
        nav = override;
    } else if (state.currentVault) {
        const isZk = !!(state.currentVault && state.currentVault.type === 'zero_knowledge');
        nav = { section: 'vault', vaultId: state.currentVault.id,
                folderId: state.currentFolderId || null,
                path: navPathForStorage(state.currentPath || [], isZk) };
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
            // openVault above reset dv_nav to root; re-persist the restored depth so a second
            // refresh lands in the same folder rather than silently at the vault root. Names stay
            // stripped for a zero-knowledge vault (saveNavState routes through navPathForStorage).
            saveNavState();
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

// Hex SHA-256 of a buffer. Used to check a resumed upload's own chunks against what the
// server stored, so a file edited since the interruption re-sends only what changed.
async function sha256Hex(buf) {
    const d = await crypto.subtle.digest('SHA-256', buf);
    return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}

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
// at rest, and it is held as a NEUTRAL blob. That last part is load-bearing and was
// once wrong: the bytes were encrypted but wrapped in a File built from the plaintext
// name and MIME, and a File keeps `name`, `type` and `lastModified` across the
// structured clone into IndexedDB. So an interrupted upload of a sensitively-named
// document left that name sitting on disk in the clear, beside the sealed copy of the
// very same name. The DEK and the plaintext bytes were never persisted and still are
// not; what leaked was the metadata. Records are
// deleted on completion/cancel and pruned by TTL. Everything fails soft if
// IndexedDB is unavailable (private mode, quota, old browser) — uploads still
// work, they just can't resume across a reload.
// ===========================================================================
const zkUploadStore = (() => {
    const DB_NAME = 'dockvault-zk-uploads';
    const STORE = 'pending';
    // v2 drops plaintext name/MIME and stores ciphertext as a neutral blob. The bump exists to
    // run the migration below over records v1 already wrote; a reader that only ever saw v2
    // would not need it.
    const VERSION = 2;
    const NEUTRAL_TYPE = 'application/octet-stream';
    let _dbPromise = null;
    // Set when an upgrade could not run because another tab holds the old connection open. That
    // tab is still using the v1 schema, so plaintext metadata stays on disk until it closes --
    // which the operator has to be told, not left to guess.
    let _upgradeBlocked = false;
    // Set when the stored database is NEWER than this page's code -- another tab upgraded it.
    let _versionTooOld = false;

    /**
     * Strip a File down to opaque bytes.
     *
     * `new Blob([file])` copies no data -- it references the same underlying bytes -- but the
     * result is a plain Blob, so `name` and `lastModified` are gone and `type` is whatever we
     * say it is. Passing a File straight into IndexedDB is what leaked the name.
     */
    function _neutralBlob(fileOrBlob) {
        if (!fileOrBlob) return null;
        return new Blob([fileOrBlob], { type: NEUTRAL_TYPE });
    }

    function _open() {
        if (_dbPromise) return _dbPromise;
        // Reset per ATTEMPT, not only on success: leaving it set after a failed retry means the
        // user keeps being told to close other tabs long after they have.
        _upgradeBlocked = false;
        _versionTooOld = false;
        const myPromise = new Promise((resolve) => {
            let req;
            try {
                if (typeof indexedDB === 'undefined' || !indexedDB) { resolve(null); return; }
                req = indexedDB.open(DB_NAME, VERSION);
            } catch (_) { resolve(null); return; }
            req.onupgradeneeded = (ev) => {
                const db = req.result;
                if (!db.objectStoreNames.contains(STORE)) {
                    const os = db.createObjectStore(STORE, { keyPath: 'sessionId' });
                    os.createIndex('vaultId', 'vaultId', { unique: false });
                    os.createIndex('createdAt', 'createdAt', { unique: false });
                    return;  // nothing written yet, so nothing to migrate
                }
                // Rewrite each existing record IN PLACE. Deleting and recreating would put the
                // only copy of the ciphertext at risk for the width of the transaction, and this
                // migration must never be able to cost someone their upload -- the plaintext name
                // is the problem, the bytes are the thing being protected.
                try {
                    const os = req.transaction.objectStore(STORE);
                    const cursorReq = os.openCursor();
                    // Swallow a cursor-level failure rather than let it abort the upgrade.
                    cursorReq.onerror = (e) => { e.preventDefault(); };
                    cursorReq.onsuccess = (cev) => {
                        const cur = cev.target.result;
                        if (!cur) return;
                        try {
                            const rec = cur.value;
                            const cleaned = _stripPlaintextMetadata(rec);
                            if (cleaned) {
                                const upd = cur.update(cleaned);
                                // The realistic failure here is asynchronous -- a quota breach
                                // while the rewritten blob is materialised, or an unreadable
                                // backing file. Unhandled, that error propagates to the
                                // versionchange transaction and ABORTS the whole upgrade, which
                                // would leave the database on the old schema permanently and
                                // disable the TTL sweep and the logout wipe with it. Contain it:
                                // this record stays v1-shaped on disk and is stripped on read.
                                upd.onerror = (e) => { e.preventDefault(); };
                            }
                        } catch (_) { /* same containment for a synchronous throw */ }
                        cur.continue();
                    };
                } catch (_) { /* an unmigrated record is handled defensively on read */ }
            };
            req.onsuccess = () => {
                const db = req.result;
                // This attempt may already have been abandoned: onblocked resolves null and drops
                // the memo, but does NOT cancel the request, so it can still succeed later. A
                // connection nobody references is never closed and is missed by the logout wipe.
                if (_dbPromise !== myPromise) { try { db.close(); } catch (_) {} return; }
                // Another tab asking to upgrade must not be blocked by this connection: hold it
                // open and the other tab is stuck on v1, still writing plaintext metadata.
                db.onversionchange = () => {
                    try { db.close(); } catch (_) {}
                    // Only forget the memo if it still points at THIS connection; a newer one may
                    // already have replaced it.
                    if (_dbPromise === myPromise) _dbPromise = null;
                };
                _upgradeBlocked = false;
                resolve(db);
            };
            req.onerror = () => {
                // A VersionError means ANOTHER tab already upgraded past us: this page is running
                // older code against a newer database and cannot resume anything until it
                // reloads. Distinguishing it matters because the alternative advice -- the quiet
                // degrade -- would leave the user with silently non-resumable uploads.
                // Only speak for this attempt. onblocked already resolves and abandons an
                // attempt without cancelling its request, so a superseded one can still fail
                // later -- and letting that late failure clear the memo or set a flag would
                // disable storage for the rest of the page on behalf of a connection nobody is
                // waiting for. Same guard as onsuccess and onversionchange.
                const current = (_dbPromise === myPromise);
                const err = req.error;
                if (current && err && err.name === 'VersionError') _versionTooOld = true;
                // Clear the memo the way onblocked does. Caching a failure for the lifetime of
                // the page would also disable the TTL sweep and the logout wipe, because both
                // short-circuit when the database is unavailable.
                if (current) _dbPromise = null;
                resolve(null);
            };
            req.onblocked = () => {
                // An older tab is holding the previous schema open. Record it, and drop the
                // memoised promise so the next call retries rather than caching the failure for
                // the lifetime of the page -- but again, only for the current attempt.
                if (_dbPromise === myPromise) {
                    _upgradeBlocked = true;
                    _dbPromise = null;
                }
                resolve(null);
            };
        });
        // Assigned AFTER construction so the handlers above can compare against it: the executor
        // runs synchronously, but its callbacks fire later, and each needs to know whether this
        // attempt is still the current one.
        _dbPromise = myPromise;
        return myPromise;
    }

    /**
     * Return a v2-shaped copy of a record, or null if it is already clean.
     *
     * Used by the migration and again when reading, because a record can reach a reader
     * unmigrated: the upgrade may have been blocked by another tab, or its cursor pass may have
     * skipped a row. Reading defensively means a stale row is never handed onward with its
     * plaintext attached.
     */
    function _stripPlaintextMetadata(rec) {
        if (!rec || typeof rec !== 'object') return null;
        // A record that declares this schema or newer was written by code that already knew the
        // rule. Trusting the marker keeps a FUTURE version's legitimately-typed blob from being
        // rewritten by today's shape heuristic on every read.
        if (typeof rec.schema === 'number' && rec.schema >= VERSION) return null;
        const hasPlaintextFields = ('fileName' in rec) || ('mimeType' in rec);
        const blobIsFile = typeof File !== 'undefined' && rec.blob instanceof File;
        const blobHasType = rec.blob && rec.blob.type && rec.blob.type !== NEUTRAL_TYPE;
        if (!hasPlaintextFields && !blobIsFile && !blobHasType) return null;
        const out = { ...rec, schema: VERSION };
        delete out.fileName;
        delete out.mimeType;
        if (rec.blob) out.blob = _neutralBlob(rec.blob);
        return out;
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
        // True when an upgrade could not run because another tab holds the old schema open.
        // Callers surface this: until that tab closes, plaintext metadata stays on disk.
        upgradeBlocked() { return _upgradeBlocked; },

        // Exposed so the writer cannot accidentally hand a File to put(). One definition of
        // "neutral" for the whole path.
        neutralBlob(fileOrBlob) { return _neutralBlob(fileOrBlob); },

        // So the writer stamps the same number the migration compares against, rather than a
        // literal that drifts at the next bump.
        schemaVersion() { return VERSION; },

        // True when this page is running older code against a database another tab has already
        // upgraded. Nothing here can work until the page reloads.
        versionTooOld() { return _versionTooOld; },

        async get(sessionId) {
            const db = await _open();
            if (!db) return null;
            try {
                const tx = db.transaction(STORE, 'readonly');
                const out = await _reqProm(() => tx.objectStore(STORE).get(sessionId));
                if (!out) return null;
                // A record can arrive unmigrated -- blocked upgrade, or a row the cursor missed.
                // Strip on the way out so nothing downstream ever sees the plaintext, even if it
                // is still on disk.
                return _stripPlaintextMetadata(out) || out;
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
                const rows = await _reqProm(() => tx.objectStore(STORE).index('vaultId').getAll(vaultId));
                // Same defensive strip as get(): a row can still be v1-shaped on disk, and this
                // is a public read method -- a future caller building a list from it must not be
                // handed the plaintext.
                const out = Array.isArray(rows)
                    ? rows.map((r) => _stripPlaintextMetadata(r) || r)
                    : rows;
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

// One gate for every transfer this page runs, uploads and downloads alike. The server cap
// protects the deployment; this protects the browser, which otherwise starts every queued item
// the moment it is queued -- twenty dropped files opened twenty concurrent uploads in one tab.
//
// Shared deliberately: two gates of five would be a cap of ten, and someone downloading while
// uploads run is exactly the case worth bounding.
const transferGate = new TransferGate(5);

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
        // This path builds a queue entry with no encryption flag and no object id. The upload
        // would not actually get far -- the server refuses a zero-knowledge upload arriving
        // without an encrypted name -- but the request that gets refused carries the file's
        // PLAINTEXT NAME, to a server whose whole promise is that it never sees one.
        //
        // Nothing calls this today. Refusing here rather than deleting it keeps the sibling
        // paths' shape intact while making the gap impossible to reintroduce by accident: a
        // future caller gets a loud stop rather than a leak on a path that looks fine.
        // Throws rather than returning: a future caller has to catch this to show it, the way
        // the sibling upload paths throw inside `run()` and render the message into the tray.
        if (isZkVault(state.currentVault)) {
            throw new Error('This upload path does not encrypt and cannot be used for a '
                          + 'zero-knowledge vault.');
        }
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
        for (const { file, name, keyVersion, encName, encMime, nameBi, nameBiCandidates, clientFileId, blobId }
                of entries) {
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
                // Per-epoch candidate set, so a same-name file sealed before a rotation is matched.
                nameBiCandidates: nameBiCandidates || null,
                // ZK v2: the client-generated file id the name was sealed under. Persisted to
                // IndexedDB and re-sent at complete so the final row id matches the sealed id.
                clientFileId: clientFileId || null,
                // ZK v2: which encryption attempt these bytes came from. Persisted and re-declared
                // on resume; a fresh encryption mints a new one and the server refuses to let it
                // adopt this attempt's chunks.
                blobId: blobId || null,
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
                        // Neither side has a plaintext name to offer: the server never had one
                        // for a zero-knowledge session, and the local record deliberately no
                        // longer keeps one. Decrypting the sealed name needs the vault DEK, and
                        // prompting for a passphrase merely to label a tray row is a worse trade.
                        //
                        // But two interrupted uploads must not be indistinguishable: Cancel
                        // deletes the server session AND the local ciphertext, which is the only
                        // copy, so choosing the wrong row cannot be undone. The session's short
                        // id discriminates without revealing anything.
                        fileName: s.file_name
                            || `(encrypted upload \u00b7 ${String(s.session_id).slice(0, 8)})`,
                        totalSize: s.total_size,
                        totalChunks: s.total_chunks, chunkSize: rec.chunkSize || CHUNK_SIZE,
                        sessionId: s.session_id, received: new Set(),
                        status: 'paused', error: null, paused: true, cancelled: false,
                        percent: s.percent || 0, isZk: true,
                        zkKeyVersion: rec.keyVersion != null ? rec.keyVersion : null,
                        // Carry the encrypted name/blind index so a 410 re-init re-declares it.
                        encName: rec.encName || null, encMime: rec.encMime || null, nameBi: rec.nameBi || null,
                        nameBiCandidates: rec.nameBiCandidates || null,
                        // Restore the v2 obj-id binding so complete finishes under the sealed id.
                        clientFileId: rec.clientFileId || null,
                        blobId: rec.blobId || null,
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
                name_bi_candidates: it.isZk ? (it.nameBiCandidates || null) : null,
                total_size: it.totalSize,
                total_chunks: it.totalChunks,
                chunk_size: it.chunkSize,
                folder_id: it.folderId,
                zk_key_version: it.zkKeyVersion != null ? it.zkKeyVersion : null,  // ZK only
                // The id this file's encrypted material is bound to, declared up front. The
                // name is already sealed against it and the content will be too, so an upload
                // that finishes under a different id produces material nothing can open.
                // Declared here rather than only at the end because the end cannot tell a
                // client that lost its id from one that never had one.
                file_id: it.isZk && it.clientFileId ? it.clientFileId : null,
                // Which encryption attempt these bytes are from. The server compares it and refuses
                // to hand this attempt the chunks of a different one.
                blob_id: it.isZk && it.blobId ? it.blobId : null,
            }),
        });
        if (!r.ok) {
            const e = await r.json().catch(() => ({}));
            // Read the sentence out of a structured refusal too. Only string details were
            // being forwarded, so a structured one arrived as 'Could not start upload' -- a
            // generic failure in place of the one explanation that says what to do.
            const d = e.detail;
            // A refusal naming another session is no longer reachable from here: this client
            // never asks to continue one, so an upload of a file already in flight simply opens
            // its own session. The server still refuses a mismatched resume for callers that do
            // name a session -- there is just no browser state to render for it.
            throw new Error(typeof d === 'string' ? d
                : (d && d.message) || 'Could not start upload');
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
                // No fileName and no mimeType. The sealed encName/encMime/nameBi below carry the
                // same information for the only consumer that needs it -- a re-init after the
                // server expires the session -- and they carry it encrypted.
                totalSize: it.totalSize,
                folderId: it.folderId,
                keyVersion: it.zkKeyVersion != null ? it.zkKeyVersion : null,
                totalChunks: it.totalChunks,
                chunkSize: it.chunkSize,
                // A neutral Blob, never the File. The bytes are the same ciphertext either
                // way; the File wrapper is what carried the plaintext name and MIME onto disk.
                blob: zkUploadStore.neutralBlob(it.file),
                schema: zkUploadStore.schemaVersion(),
                // The encrypted name/MIME + blind index, so a re-init after a server-side
                // session expiry (410) re-declares the same name without the plaintext.
                encName: it.encName || null,
                encMime: it.encMime || null,
                nameBi: it.nameBi || null,
                // Persist the candidate set too, or a resumed upload's re-init would lose it and
                // silently drop back to single-value matching after a reload.
                nameBiCandidates: it.nameBiCandidates || null,
                // ZK v2: the id the name was sealed under. Without it, a resumed upload would
                // complete under a fresh server id and the v2 name would be undecryptable.
                clientFileId: it.clientFileId || null,
                // And which attempt produced the blob above. A resume must re-declare it or the
                // server will not let it continue -- correctly, since it could not prove these
                // bytes belong to that session.
                blobId: it.blobId || null,
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
        if (res.unavailable) {
            // "Unavailable" has two very different causes. Private mode or an old browser is the
            // documented quiet degrade. Another TAB holding the previous schema open is not: the
            // upgrade that removes plaintext filenames from disk cannot run while it is there,
            // so the user is the only one who can resolve it and has to be told.
            if (zkUploadStore.versionTooOld()) {
                it.resumeWarning = 'DockVault was updated in another tab. Reload this page: until '
                    + 'you do, uploads here cannot be saved for resuming.';
                try { showWarning(it.resumeWarning); } catch (_) { /* toast optional */ }
                try { this.render(); } catch (_) { /* a render hiccup must not fail the upload */ }
                return;
            }
            if (zkUploadStore.upgradeBlocked()) {
                it.resumeWarning = 'Another DockVault tab is open and is holding browser storage '
                    + 'on an older format. Close the other tabs and reload: until then this '
                    + 'upload cannot be saved for resuming, and older saved uploads keep their '
                    + 'file names in browser storage.';
                try { showWarning(it.resumeWarning); } catch (_) { /* toast optional */ }
                try { this.render(); } catch (_) { /* a render hiccup must not fail the upload */ }
                return;
            }
            it.resumeWarning = null;
            return;
        }
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
        // Queued rather than started. The slot is held for the whole transfer and given back
        // however it ends, so a failure cannot cost one permanently.
        return transferGate.run(() => this._run(id));
    },

    async _run(id) {
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
                let detail = null;
                try {
                    const s = await fetch(`${API_BASE}/vaults/${it.vaultId}/uploads/${it.sessionId}`, { headers: this._vaultHeaders() });
                    if (s.ok) { detail = await s.json(); it.received = new Set(detail.received_chunks || []); }
                } catch (_) { /* fall back to re-sending all chunks (server is idempotent) */ }
                it.needsServerSync = false;

                // The server reports which indices it holds AND a digest of each. Skipping an
                // index on the strength of its presence alone is what let an edited file join the
                // previous attempt's chunks: same name, same length, so nothing else noticed and
                // the stored file was part old and part new, with a 200.
                //
                // Only the chunks the server claims are re-read. Any that no longer match come out
                // of the received set and go up with the rest, so an edit costs the chunks it
                // touched rather than the whole file. Encrypted uploads are excluded: their local
                // copy is ciphertext the server already has byte-for-byte, and a re-encryption is
                // refused earlier as a different attempt.
                if (detail && !it.isZk && it.file) {
                    // Absent, not merely empty: an older server sends no digests at all, and
                    // gating the whole check on the field being present meant trusting every
                    // chunk in exactly that case. Treat it as nothing verifiable, which sends
                    // them all again -- the same answer as a single missing digest, for the
                    // same reason.
                    const sums = detail.chunk_checksums || {};
                    const stale = [];
                    for (const idx of [...it.received]) {
                        const want = sums[idx];
                        if (!want) {
                            // No digest recorded, so there is nothing to check this chunk
                            // against -- send it again rather than trust it. `continue` here
                            // left it in the received set, which SKIPS it: the whole defect
                            // back, in every degraded state. Chunks stored before this
                            // shipped have no digest at all, so the sessions most likely to
                            // be mid-resume when it lands were exactly the unprotected ones.
                            it.received.delete(idx);
                            stale.push(idx);
                            continue;
                        }
                        const start = idx * it.chunkSize;
                        const part = it.file.slice(start,
                            Math.min(start + it.chunkSize, it.file.size));
                        if (await sha256Hex(await part.arrayBuffer()) !== want) {
                            it.received.delete(idx);
                            stale.push(idx);
                        }
                    }
                    if (stale.length) {
                        it.changedLocally = stale.length;
                        this.render();
                    }
                }
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
            // A zero-knowledge upload without an object id cannot be completed safely: its
            // name is sealed against an id, and the server would assign a different one. That
            // state is reachable -- a queued upload stored before this field existed comes
            // back without it -- so stop rather than finish it into something unopenable.
            if (it.isZk && !it.clientFileId) {
                throw new Error('This upload was prepared by an older version and cannot be '
                              + 'completed. Nothing was lost -- please add the file again.');
            }
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
            // A resumed upload that found some of its chunks no longer match says so. It is
            // the only signal that the file changed since the interruption, and without it
            // the re-upload looks like an ordinary slow resume.
            const changed = it.changedLocally
                ? ` · <span class="up-warn">file changed, re-sending ${it.changedLocally} part${it.changedLocally === 1 ? '' : 's'}</span>`
                : '';
            const sub = it.status === 'error' ? `<div class="up-error">${escapeHtml(it.error || 'Upload failed')}</div>`
                : it.status === 'needs-file' ? `<div class="up-sub">${it.isZk ? 'Encrypted data isn\'t on this device — cancel and upload again' : 'Paused — click Resume and re-select the file'}</div>`
                : `<div class="up-sub">${statusLabel} · ${pct}% · ${size}${changed}${noResume ? ' · <span class="up-warn">not resumable</span>' : ''}</div>`;

            return `
              <div class="up-row" data-up-row="${it.id}">
                <div class="up-main">
                  <div class="up-name" title="${escapeHtml(it.fileName)}">${escapeHtml(it.fileName)}</div>
                  ${sub}
                  <div class="up-bar"><div class="${barClass}" style="width:${pct}%"></div></div>
                </div>
                <div class="up-controls">${controls}</div>
              </div>`;
        }).join('');

        // A failed item (e.g. a rejected 0-byte upload) is finished, not active — exclude 'error'
        // so it doesn't stick in the tray header as "N active" forever.
        const active = items.filter(i => i.status !== 'done' && i.status !== 'needs-file'
            && i.status !== 'error').length;
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
                const finished = it.status === 'done' || it.status === 'needs-file'
                    || it.status === 'error';
                // Keep a row whose server session is still open, even when it looks finished.
                // Dropping it hid an upload that still existed, and the next attempt at the same
                // file was refused by a session the user could no longer see or act on.
                const stillOnServer = it.status !== 'done' && it.sessionId;
                if (finished && !stillOnServer) this.items.delete(id);
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
    let toUpload = [];   // {file, name}
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
            // The name travels with the id: if the delete fails, the replacement that would have
            // taken this name has to be dropped, and it is identified by name rather than id.
            if (id) toDelete.push({ id, name: file.name });
            toUpload.push({ file, name: file.name });
        } else {
            let name = (choice.action === 'rename' && choice.name) ? choice.name : autoName;
            name = uniqueUploadName(name, existing);
            toUpload.push({ file, name });
            existing.add(name);
        }
    }

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
                    // Minted HERE, in the same iteration as the encryption below, so the token and
                    // the bytes it names are produced together and cannot drift apart. A resumed
                    // upload replays these same bytes and re-declares this same token; only a fresh
                    // encryption gets a new one, which is exactly what the server refuses to merge.
                    let enc;
                    if (lib.ZK_CONTENT_WRITE_V2) {
                        // Chunk-framed content, encrypted FROM THE FILE rather than from a copy of
                        // it. Reading the file first would put the plaintext in the heap, the
                        // sealed copy would join it, and a large upload would peak near three
                        // times the file for no reason -- the writer only ever needs one chunk at
                        // a time, and everything the header binds is known from the file's size.
                        //
                        // The token comes back FROM the writer, which is why the legacy branch
                        // below mints its own instead of both sharing one line: under this branch
                        // the token is sealed into the file's header, and a value minted out here
                        // could drift from the one the bytes actually carry.
                        const written = await lib.encryptBlobV2(entry.file, dek, {
                            vaultId: vid, objectId: clientFileId, dekEpoch: keyVersion,
                        });
                        entry.blobId = written.blobId;
                        enc = written.blob;
                    } else {
                        // The legacy writer takes the whole plaintext and has no chunked form, so
                        // this branch still reads the file. Its cost is stated rather than hidden:
                        // it is the reason the branch above exists.
                        entry.blobId = zkNewBlobId();
                        enc = await lib.encryptFile(await entry.file.arrayBuffer(), dek);
                    }
                    entry.file = new File([enc], entry.name, { type: mime });
                    entry.keyVersion = keyVersion;
                    entry.encName = await lib.encryptName(entry.name, dek, vid, 'name', keyVersion, clientFileId);
                    entry.nameBi = await lib.nameBlindIndex(entry.name, dek, vid, keyVersion);
                    // Every epoch's index for this name, so the server can spot a same-name file
                    // sealed BEFORE a rotation (whose index sits at an old epoch the current-epoch
                    // value can't equal). Best-effort: an epoch this member can't unwrap a DEK for
                    // is one whose files they couldn't read anyway, and a derivation failure must
                    // never block the upload -- fall back to the single current value, which is the
                    // single-value behaviour. The current epoch's DEK is already `dek`; older ones come
                    // from the per-epoch cache.
                    entry.nameBiCandidates = await zkUploadNameCandidates(
                        lib, entry.name, vid, keyVersion, dek);
                    entry.encMime = mime ? await lib.encryptName(mime, dek, vid, 'mime', keyVersion, clientFileId) : null;
                }
            } catch (e) {
                showError(isCodedCryptoError(e)
                    ? safeMessageForCode(e.code, 'unlock')
                    : 'Zero-knowledge encryption failed.');
                return;
            }
        }
        // The originals go LAST, and only for replacements that are ready to send.
        //
        // They used to go first, "so the new upload doesn't collide" -- before the replacement was
        // encrypted, and with the result of the delete discarded. Any failure in between lost the
        // original with nothing to recover from, and the failure is not exotic: the encryption
        // above ends in `return`, so one file throwing abandoned the whole batch after every
        // original had already been deleted.
        if (toDelete.length) {
            const survived = [];
            for (const target of toDelete) {
                let gone = false;
                try {
                    const r = await fetch(
                        `${API_BASE}/vaults/${state.currentVault.id}/files/${target.id}/delete`,
                        { method: 'POST', headers: uploadManager._vaultHeaders() });
                    gone = r.ok;
                } catch (_) {
                    gone = false;
                }
                if (!gone) survived.push(target);
            }
            if (survived.length) {
                // The original is still there, so uploading its replacement under the same name
                // would either be refused or produce a duplicate. Better to say so and change
                // nothing than to guess: the user still has their file.
                const stuck = new Set(survived.map(t => t.name));
                toUpload = toUpload.filter(e => !stuck.has(e.name));
                showError(`Could not replace ${survived.length} existing file`
                          + `${survived.length === 1 ? '' : 's'}; `
                          + `the original${survived.length === 1 ? '' : 's'} are unchanged.`);
            }
            await loadVaultFiles();
        }

        if (toUpload.length) uploadManager.enqueueNamed(toUpload);
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
                // Same-name folder detection across every epoch, so a folder created before a
                // rotation is still seen as a duplicate. Best-effort; never blocks the create.
                body.name_bi_candidates = await zkUploadNameCandidates(lib, folderName, vid, epoch, dek);
                body.name_key_version = epoch;
            } catch (e) {
                showError(isCodedCryptoError(e)
                    ? safeMessageForCode(e.code, 'unlock')
                    : 'Zero-knowledge encryption failed.');
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
        // Operation and code only, for the same reason as the rename path above.
        console.error('createFolder failed', (error && error.code) || 'UNCODED');
        showError(isCodedCryptoError(error)
            ? safeMessageForCode(error.code, 'unlock')
            : 'Failed to create folder: ' + error.message);
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
        setText('info-vault-created', formatServerTime(vault.created_at, '-'));

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

        // Who paid for this vault's size, and the caller's own share of it.
        await loadVaultStorageCard();

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
            const addedDate = parseServerTime(perm.added_at);
            const added = (addedDate && !isNaN(addedDate)) ? addedDate.toLocaleDateString() : '—';
            // ZK vaults: a member granted access before setting up their encryption key holds the
            // authz row but can't open the vault until they create their key. Flag it so the manager
            // knows the access is real but not yet usable by that member.
            const pendingBadge = perm.pending_key_setup
                ? ` <span class="badge badge-warning" title="Access granted, but this member hasn't set up their encryption key yet — they can't open this zero-knowledge vault until they do.">Pending encryption key setup</span>`
                : '';
            return `
            <tr>
                <td>${escapeHtml(perm.username)}${pendingBadge}</td>
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
        // Zero-knowledge: try to wrap the DEK to each recipient. A keyless recipient returns
        // {pending:true} (an invite is recorded) rather than throwing — we STILL create the authz
        // membership row below (the server permits a keyless member); the wrapped key follows once
        // they set up their encryption key.
        let pending = false;
        if (zk) {
            const r = await zkShareVaultToUser(state.currentVault.id, uid);
            pending = !!(r && r.pending);
        }
        await apiRequest(`/vaults/${state.currentVault.id}/permissions`, { method: 'POST', body: JSON.stringify({ user_id: uid, level }) });
        return { pending };
    }));
    const settled = results.filter(r => r.status === 'fulfilled');
    const pendingCount = settled.filter(r => r.value && r.value.pending).length;
    const ok = settled.length - pendingCount;
    const failed = results.length - settled.length;
    if (ok) showSuccess(`Granted access to ${ok} user(s)`);
    if (pendingCount) showWarning(`${pendingCount} user(s) added — pending their encryption key setup`);
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
            createdEl.textContent = formatServerTime(vault.created_at);
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

// ---------------------------------------------------------------------------
// Vault storage: who paid for the size, and the caller's own share
//
// A vault's size limit is the SUM of what its owner and managers allocated out of their own
// account quotas. The card therefore shows two different things: the vault's total (everyone's
// business) and YOUR share of it (the only part you can move). Reclaiming is capped at your own
// contribution, so the input's floor is 0 and its ceiling is your remaining account headroom.
//
// It lives in the vault's Info tab, not Settings: Settings is owner-only, and a MANAGER who may
// fund the vault has to be able to reach the control. Every write is authorised server-side, so
// the editor's visibility follows the server's own can_contribute answer rather than a
// client-side guess about roles.
// ---------------------------------------------------------------------------
function _gbFromBytes(bytes) { return (bytes || 0) / GIB_BYTES; }

async function loadVaultStorageCard() {
    if (!state.currentVault) return;
    const editor = document.getElementById('vault-storage-editor');
    const list = document.getElementById('vault-storage-contributors');
    if (!editor && !list) return;
    let info;
    try {
        info = await apiRequest(`/vaults/${state.currentVault.id}/storage`, { silent: true });
    } catch (e) {
        if (editor) editor.hidden = true;
        if (list) list.textContent = '';
        return;
    }

    // Contributor breakdown — present only for people who administer the vault (the server
    // omits it for everyone else, so an absent list is a permission answer, not an error).
    if (list) {
        list.textContent = '';
        if (Array.isArray(info.contributors) && info.contributors.length > 1) {
            const heading = document.createElement('p');
            heading.className = 'text-secondary mb-xs';
            heading.textContent = 'Contributed by';
            list.appendChild(heading);
            info.contributors.forEach(c => {
                const row = document.createElement('div');
                row.className = 'flex justify-between';
                const who = document.createElement('span');
                who.textContent = c.username + (c.is_owner ? ' (owner)' : '') + (c.is_you ? ' — you' : '');
                const much = document.createElement('span');
                much.className = 'font-medium';
                much.textContent = formatBytes(c.granted_bytes);
                row.appendChild(who);
                row.appendChild(much);
                list.appendChild(row);
            });
        }
    }

    const input = document.getElementById('vault-storage-input');
    const help = document.getElementById('vault-storage-help');
    if (editor) editor.hidden = !info.can_contribute;
    if (input && info.can_contribute) {
        // GB is what a person wants to type, but bytes are what was allocated, and 2 decimal
        // places do not survive the round trip: re-saving an untouched field would silently
        // rewrite the allocation (and on a full vault the rounded-down value is refused
        // outright). Remember the exact figure and re-send THAT when the text is unchanged.
        input.value = _gbFromBytes(info.my_grant_bytes).toFixed(2).replace(/\.?0+$/, '');
        input.dataset.exactBytes = String(info.my_grant_bytes);
        input.dataset.renderedValue = input.value;
        if (info.my_max_grant_bytes === null || info.my_max_grant_bytes === undefined) {
            input.removeAttribute('max');
        } else {
            input.max = String(_gbFromBytes(info.my_max_grant_bytes));
        }
    }
    if (help && info.can_contribute) {
        const parts = [];
        if (info.others_grant_bytes > 0) {
            parts.push(`Others contribute ${formatBytes(info.others_grant_bytes)} to this vault.`);
        }
        if (info.my_max_grant_bytes === null || info.my_max_grant_bytes === undefined) {
            parts.push('You have no account storage limit.');
        } else {
            parts.push(`You can contribute up to ${formatBytes(info.my_max_grant_bytes)}.`);
        }
        parts.push('Lowering it returns the difference to your quota; the vault can never go below what it already stores.');
        help.textContent = parts.join(' ');
    }

    // Bound here rather than with the Settings-tab buttons: this card lives in the Info tab, which
    // a Manager can reach and Settings is not. Assigning onclick keeps it idempotent across reloads.
    const saveBtn = document.getElementById('vault-storage-save-btn');
    if (saveBtn) saveBtn.onclick = saveVaultStorage;
}

async function saveVaultStorage() {
    if (!state.currentVault) return;
    const input = document.getElementById('vault-storage-input');
    const btn = document.getElementById('vault-storage-save-btn');
    if (!input) return;
    const gb = parseFloat(input.value);
    if (!Number.isFinite(gb) || gb < 0) {
        showError('Enter how much storage you want to contribute, in GB (0 to withdraw yours).');
        return;
    }
    // An untouched field means "leave my allocation where it is", so send back the exact byte
    // figure rather than the GB text's rounding of it.
    const bytes = (input.value === input.dataset.renderedValue && input.dataset.exactBytes)
        ? Number(input.dataset.exactBytes)
        : Math.round(gb * GIB_BYTES);
    if (btn) btn.disabled = true;
    try {
        await apiRequest(`/vaults/${state.currentVault.id}/storage`, {
            method: 'PUT',
            body: JSON.stringify({ granted_bytes: bytes }),
        });
        showSuccess('Vault storage updated');
        // The vault object in memory carries the old limit; refresh it so the usage bar and any
        // later save read the value the server just settled on, then redraw the whole Info tab
        // (which owns the bar) rather than only the contribution controls.
        try {
            state.currentVault = await apiRequest(`/vaults/${state.currentVault.id}`, { silent: true });
        } catch (_) { /* the card reload below still shows the authoritative numbers */ }
        await loadVaultInfo();
    } catch (error) {
        // apiRequest surfaces the server's reason (quota exceeded, below stored bytes, ...).
    } finally {
        if (btn) btn.disabled = false;
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
        const saved = await apiRequest(`/vaults/${state.currentVault.id}/settings`, {
            method: 'PATCH',
            body: JSON.stringify(body)
        });
        // Trust the server's stored window (clamped to 0 when the org floor is set), not the submitted one.
        const effectiveUrm = (saved && typeof saved.unlock_remember_minutes === 'number') ? saved.unlock_remember_minutes : urm;

        // Update local state + drop any remembered password so the new window applies.
        state.currentVault.expire_files_after_days = expireValue > 0 ? expireValue : null;
        state.currentVault.expire_files_unit = expireValue > 0 ? expireUnit : 'days';
        state.currentVault.unlock_remember_minutes = effectiveUrm;
        if (newSizeBytes != null) state.currentVault.size_limit = newSizeBytes;
        // Re-base the remember window on the new policy (applies to the next
        // re-entry; the currently-open vault stays open either way).
        state.forgetVaultPassword(state.currentVault.id);
        if (state.currentVault.has_password) {
            state.rememberVaultPassword(state.currentVault.id, state.vaultPassword, effectiveUrm);
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
        // Zero-knowledge: wrap the DEK to the recipient. A keyless recipient returns {pending:true}
        // (an invite is recorded) instead of throwing — we STILL create the membership row below
        // (the server permits a keyless member); the wrapped key follows once they set up their key.
        let pending = false;
        if (isZkVault(state.currentVault)) {
            const r = await zkShareVaultToUser(state.currentVault.id, userId);
            pending = !!(r && r.pending);
        }

        await apiRequest(`/vaults/${state.currentVault.id}/permissions`, {
            method: 'POST',
            body: JSON.stringify({
                user_id: userId,
                level: level
            })
        });

        if (pending) {
            showWarning('User added — pending their encryption key setup. They can open the vault once they create their encryption key.');
        } else {
            showSuccess('Permission granted successfully');
        }
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
// ---- Note-link tags manager (admin Settings -> Note Links) --------------------------------------
// Admin CRUD for the public-note-link policy tags (GET/POST/PATCH/DELETE /note-link-tags). A tag is a
// security FLOOR. This editor covers the policy + the "everyone may use" auto-enroll switch; granular
// per-user/department allowlists are API-managed for now. All controls build via DOM (no innerHTML).
let noteLinkTagsCache = [];
let noteLinkTagsUIWired = false;

function _nlEl(id) { return document.getElementById(id); }
function _nlNumOrNull(id) {
    const e = _nlEl(id);
    if (!e || e.value === '' || e.value == null) return null;
    const n = parseInt(e.value, 10);
    return Number.isFinite(n) ? n : null;
}

function setupNoteLinkTagsUI() {
    if (noteLinkTagsUIWired) return;
    const add = _nlEl('nl-tag-add-btn'), save = _nlEl('nl-tag-save-btn'), cancel = _nlEl('nl-tag-cancel-btn');
    if (!add || !save || !cancel) return;  // tab markup not present
    add.addEventListener('click', () => openNoteLinkTagEditor(null));
    save.addEventListener('click', saveNoteLinkTag);
    cancel.addEventListener('click', () => { const ed = _nlEl('nl-tag-editor'); if (ed) ed.style.display = 'none'; });
    // Colour swatches + custom picker + icon grid (mirrors the share-tag colour picker).
    const sw = _nlEl('nl-tag-color-swatches');
    if (sw) sw.addEventListener('click', (e) => {
        const b = e.target.closest('.accent-swatch');
        if (b) { e.preventDefault(); setNoteLinkTagColor(b.getAttribute('data-color') || ''); }
    });
    const cu = _nlEl('nl-tag-color-custom');
    if (cu) cu.addEventListener('input', () => setNoteLinkTagColor(cu.value));
    const ig = _nlEl('nl-tag-icon-grid');
    if (ig) ig.addEventListener('click', (e) => {
        const b = e.target.closest('.icon-choice');
        if (b) { e.preventDefault(); setNoteLinkTagIcon(b.getAttribute('data-icon') || ''); }
    });
    const refresh = _nlEl('nl-admin-refresh');
    if (refresh) refresh.addEventListener('click', loadAdminNoteLinks);
    const revokeAll = _nlEl('nl-admin-revoke-all');
    if (revokeAll) revokeAll.addEventListener('click', adminRevokeAllNoteLinks);
    noteLinkTagsUIWired = true;
}

// ---- Admin oversight: all public links across users (Settings -> Note Links) -----------------
async function loadAdminNoteLinks() {
    const host = _nlEl('nl-admin-links');
    const summary = _nlEl('nl-admin-summary');
    if (!host) return;
    host.replaceChildren(_el('div', 'spinner'));
    try {
        const data = await apiRequest('/admin/note-links', { silent: true });
        renderAdminNoteLinks(data || { links: [] });
        if (summary) {
            const total = (data && data.total) || 0, active = (data && data.active_count) || 0;
            summary.textContent = total + ' link(s), ' + active + ' active'
                + (data && data.capped ? ' (showing the newest 1000)' : '');
        }
    } catch (e) {
        host.replaceChildren(_el('p', 'text-secondary text-sm', 'Could not load links: ' + ((e && e.message) || '')));
    }
}

function renderAdminNoteLinks(data) {
    const host = _nlEl('nl-admin-links');
    if (!host) return;
    const links = (data && data.links) || [];
    if (!links.length) { host.replaceChildren(_el('p', 'text-tertiary text-sm', 'No public links exist.')); return; }
    const table = _el('table', 'data-table');
    const thead = _el('thead');
    const hr = _el('tr');
    ['Owner', 'Type', 'Note', 'Status', 'Protection', 'Expires', 'Views', ''].forEach(h => hr.appendChild(_el('th', '', h)));
    thead.appendChild(hr); table.appendChild(thead);
    const tb = _el('tbody');
    links.forEach(l => {
        const tr = _el('tr');
        tr.appendChild(_el('td', '', l.owner || '—'));
        const typeTd = _el('td', 'nl-tag-idlead');
        const hex = (typeof noteLinkColorHex === 'function') ? noteLinkColorHex(l.tag_border_color) : '';
        if (hex) { const dot = _el('span', 'nl-color-dot'); dot.style.background = hex; typeTd.appendChild(dot); }
        typeTd.appendChild(_el('span', '', l.tag_name || '—'));
        tr.appendChild(typeTd);
        tr.appendChild(_el('td', '', l.title || 'Untitled note'));
        tr.appendChild(_el('td', '', _NOTE_LINK_STATUS_LABEL[l.status] || l.status));
        tr.appendChild(_el('td', '', l.secret_kind === 'password' ? 'Password' : (l.secret_kind === 'pin' ? 'PIN' : 'None')));
        tr.appendChild(_el('td', '', l.expires_at ? _fmtLinkExpiry(l.expires_at).replace(/^Expires /, '') : 'Never'));
        tr.appendChild(_el('td', '', (l.max_uses != null) ? (l.view_count + '/' + l.max_uses) : String(l.view_count)));
        const actTd = _el('td');
        if (l.status === 'active') {
            const rv = _el('button', 'btn btn-ghost btn-sm', 'Revoke');
            rv.type = 'button';
            rv.addEventListener('click', () => adminRevokeNoteLink(l.id));
            actTd.appendChild(rv);
        }
        tr.appendChild(actTd);
        tb.appendChild(tr);
    });
    table.appendChild(tb);
    host.replaceChildren(table);
}

async function adminRevokeNoteLink(id) {
    const ok = await showConfirm('Revoke this public link? Anyone holding it will no longer be able to open it.');
    if (!ok) return;
    try {
        await apiRequest('/admin/note-links/' + id + '/revoke', { method: 'POST' });
        showSuccess('Link revoked');
        await loadAdminNoteLinks();
    } catch (e) { showError((e && e.message) || 'Could not revoke the link'); }
}

async function adminRevokeAllNoteLinks() {
    const ok = await showConfirm('Revoke ALL currently-active public links across every user? This cannot be undone.');
    if (!ok) return;
    try {
        const r = await apiRequest('/admin/note-links/revoke-all', { method: 'POST' });
        showSuccess('Revoked ' + ((r && r.revoked_count) || 0) + ' link(s)');
        await loadAdminNoteLinks();
    } catch (e) { showError((e && e.message) || 'Could not revoke links'); }
}

// Named tile colours for note-link tags -> hex (also accepts a raw #hex). Superset of the seeded
// green/amber/red plus the shared chip palette, so a seeded tag's colour resolves in the list.
const NOTELINK_TILE_COLORS = {
    green: '#16a34a', amber: '#d97706', red: '#dc2626', teal: '#0d9488', emerald: '#059669',
    sky: '#0284c7', indigo: '#4f46e5', violet: '#7c3aed', rose: '#e11d48', orange: '#ea580c',
};
function noteLinkColorHex(c) {
    if (!c) return '';
    if (c.charAt(0) === '#') return /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(c) ? c : '';
    return NOTELINK_TILE_COLORS[c] || '';
}
// Icons offered in the editor grid (sprite names; '' = no icon). All exist in the #i-* sprite.
const _NL_ICON_CHOICES = ['globe', 'clock', 'lock', 'link', 'shield', 'key', 'eye', 'unlock',
                          'file-text', 'star', 'calendar', 'bell', 'info'];

function setNoteLinkTagColor(color) {
    const hidden = _nlEl('nl-tag-color');
    if (hidden) hidden.value = color || '';
    document.querySelectorAll('#nl-tag-color-swatches .accent-swatch').forEach(s => {
        s.classList.toggle('selected', (s.getAttribute('data-color') || '') === (color || ''));
    });
    const custom = _nlEl('nl-tag-color-custom');
    if (custom && color && color.charAt(0) === '#') custom.value = color;
}

function _nlBuildIconGrid() {
    const grid = _nlEl('nl-tag-icon-grid');
    if (!grid || grid._built) return;
    grid.replaceChildren();
    const none = _el('button', 'icon-choice', 'None');
    none.type = 'button'; none.setAttribute('data-icon', ''); none.setAttribute('title', 'No icon');
    none.style.fontSize = '11px';
    grid.appendChild(none);
    _NL_ICON_CHOICES.forEach(name => {
        const b = _el('button', 'icon-choice');
        b.type = 'button';
        b.setAttribute('data-icon', name);
        b.setAttribute('title', name);
        b.setAttribute('aria-label', name);
        b.appendChild(_svgIcon(name, 'icon-sm'));
        grid.appendChild(b);
    });
    grid._built = true;
}

function setNoteLinkTagIcon(icon) {
    const hidden = _nlEl('nl-tag-icon');
    if (hidden) hidden.value = icon || '';
    document.querySelectorAll('#nl-tag-icon-grid .icon-choice').forEach(c => {
        c.classList.toggle('selected', (c.getAttribute('data-icon') || '') === (icon || ''));
    });
}

async function loadNoteLinkTags() {
    const host = _nlEl('nl-tags-list');
    if (!host) return;
    try {
        const tags = await apiRequest('/note-link-tags', { silent: true });
        noteLinkTagsCache = Array.isArray(tags) ? tags : [];
    } catch (_) { noteLinkTagsCache = []; }
    renderNoteLinkTagsList();
}

function _nlSecretLabel(t) {
    if (t.require_secret === 'password') return 'password required';
    if (t.require_secret === 'pin') return 'PIN required (' + t.min_pin_len + ')';
    return 'no secret';
}

function renderNoteLinkTagsList() {
    const host = _nlEl('nl-tags-list');
    if (!host) return;
    host.replaceChildren();
    if (!noteLinkTagsCache.length) {
        host.appendChild(_el('p', 'text-tertiary text-sm', 'No note-link tags yet. Add one to let users create public links.'));
        return;
    }
    noteLinkTagsCache.slice().sort((a, b) => a.name.localeCompare(b.name)).forEach(tag => {
        const row = _el('div', 'share-tag-row flex justify-between items-center mb-sm');
        const left = _el('div');
        // Colour dot + icon + name (the tile's presentation, so an admin sees it at a glance).
        const lead = _el('div', 'nl-tag-idlead');
        const hex = noteLinkColorHex(tag.border_color);
        if (hex) { const dot = _el('span', 'nl-color-dot'); dot.style.background = hex; lead.appendChild(dot); }
        if (tag.icon) lead.appendChild(_svgIcon(tag.icon, 'icon-sm'));
        lead.appendChild(_el('span', 'font-medium', tag.name + (tag.is_active ? '' : ' (inactive)')));
        left.appendChild(lead);
        const ttl = tag.max_ttl_hours ? (tag.max_ttl_hours + 'h max') : 'no expiry';
        const uses = tag.max_uses_cap ? (tag.max_uses_cap + ' views') : 'unlimited views';
        left.appendChild(_el('div', 'text-secondary text-sm',
            `token ≥ ${tag.min_token_len} · ${_nlSecretLabel(tag)} · ${ttl} · ${uses}`));
        row.appendChild(left);
        const actions = _el('div', 'flex gap-sm');
        const edit = _el('button', 'btn btn-ghost btn-sm', 'Edit'); edit.type = 'button';
        edit.addEventListener('click', () => openNoteLinkTagEditor(tag));
        actions.appendChild(edit);
        if (tag.is_active) {
            const del = _el('button', 'btn btn-ghost btn-sm', 'Deactivate'); del.type = 'button';
            del.addEventListener('click', () => deactivateNoteLinkTag(tag));
            actions.appendChild(del);
        }
        row.appendChild(actions);
        host.appendChild(row);
    });
}

function openNoteLinkTagEditor(tag) {
    const ed = _nlEl('nl-tag-editor');
    if (!ed) return;
    const t = tag || {};
    _nlEl('nl-tag-editor-id').value = t.id || '';
    _nlEl('nl-tag-editor-title').textContent = tag ? 'Edit tag' : 'Add tag';
    _nlEl('nl-tag-name').value = t.name || '';
    _nlEl('nl-tag-description').value = t.description || '';
    _nlBuildIconGrid();
    setNoteLinkTagColor(t.border_color || '');
    setNoteLinkTagIcon(t.icon || '');
    _nlEl('nl-tag-min-token-len').value = t.min_token_len != null ? t.min_token_len : 10;
    _nlEl('nl-tag-max-ttl').value = t.max_ttl_hours != null ? t.max_ttl_hours : '';
    _nlEl('nl-tag-default-ttl').value = t.default_ttl_hours != null ? t.default_ttl_hours : '';
    _nlEl('nl-tag-require-secret').value = t.require_secret || 'none';
    _nlEl('nl-tag-min-pin-len').value = String(t.min_pin_len || 4);
    _nlEl('nl-tag-password-min-len').value = t.password_min_len != null ? t.password_min_len : 8;
    _nlEl('nl-tag-password-alnum').checked = t.password_require_alnum === true;
    _nlEl('nl-tag-max-uses').value = t.max_uses_cap != null ? t.max_uses_cap : '';
    _nlEl('nl-tag-auto-enroll').checked = tag ? (t.auto_enroll_new_users === true) : true;
    _nlEl('nl-tag-active').checked = tag ? (t.is_active !== false) : true;
    const err = _nlEl('nl-tag-editor-error'); if (err) err.style.display = 'none';
    ed.style.display = '';
}

function _nlEditorPayload() {
    return {
        name: (_nlEl('nl-tag-name').value || '').trim(),
        description: (_nlEl('nl-tag-description').value || '').trim() || null,
        border_color: _nlEl('nl-tag-color').value || null,
        icon: _nlEl('nl-tag-icon').value || null,
        min_token_len: _nlNumOrNull('nl-tag-min-token-len') != null ? _nlNumOrNull('nl-tag-min-token-len') : 10,
        max_ttl_hours: _nlNumOrNull('nl-tag-max-ttl'),
        default_ttl_hours: _nlNumOrNull('nl-tag-default-ttl'),
        require_secret: _nlEl('nl-tag-require-secret').value || 'none',
        min_pin_len: parseInt(_nlEl('nl-tag-min-pin-len').value, 10) || 4,
        password_min_len: _nlNumOrNull('nl-tag-password-min-len') != null ? _nlNumOrNull('nl-tag-password-min-len') : 8,
        password_require_alnum: _nlEl('nl-tag-password-alnum').checked,
        max_uses_cap: _nlNumOrNull('nl-tag-max-uses'),
        auto_enroll_new_users: _nlEl('nl-tag-auto-enroll').checked,
        is_active: _nlEl('nl-tag-active').checked,
    };
}

async function saveNoteLinkTag() {
    const id = _nlEl('nl-tag-editor-id').value;
    const err = _nlEl('nl-tag-editor-error');
    const payload = _nlEditorPayload();
    if (!payload.name) { if (err) { err.textContent = 'Name is required'; err.style.display = ''; } return; }
    try {
        if (id) await apiRequest('/note-link-tags/' + id, { method: 'PATCH', body: JSON.stringify(payload) });
        else await apiRequest('/note-link-tags', { method: 'POST', body: JSON.stringify(payload) });
        const ed = _nlEl('nl-tag-editor'); if (ed) ed.style.display = 'none';
        showSuccess('Note-link tag saved');
        await loadNoteLinkTags();
    } catch (e) {
        if (err) { err.textContent = (e && e.message) || 'Could not save the tag'; err.style.display = ''; }
    }
}

async function deactivateNoteLinkTag(tag) {
    const ok = await showConfirm(`Deactivate note-link tag "${tag.name}"? New links can't use it; existing links keep their policy.`);
    if (!ok) return;
    try { await apiRequest('/note-link-tags/' + tag.id, { method: 'DELETE' }); showSuccess('Tag deactivated'); await loadNoteLinkTags(); }
    catch (e) { showError((e && e.message) || 'Could not deactivate the tag'); }
}


// ================= Notes =====================================================================
// Personal server-side notes + "send note" (a snapshot copy to another user). Note text can be
// masked with the "Hide note text" toggle (a local privacy screen, remembered per browser); the
// per-note eye reveals one. All names/text render via _el (textContent) — never HTML.
function _notesState() {
    if (!state.notes) state.notes = [];
    if (!state.notesReceived) state.notesReceived = [];
    if (!(state.notesRevealed instanceof Set)) state.notesRevealed = new Set();
    if (typeof state.notesHideText !== 'boolean') {
        try { state.notesHideText = localStorage.getItem('notesHideText') === '1'; }
        catch (_) { state.notesHideText = false; }
    }
    if (!state.notesTab) {
        // Restore the last-viewed tab across a page reload (mine / received / shared).
        let saved = 'mine';
        try { saved = localStorage.getItem('notesTab') || 'mine'; } catch (_) {}
        state.notesTab = ['mine', 'received', 'shared'].includes(saved) ? saved : 'mine';
    }
}

async function loadNotes() {
    _notesState();
    wireNotesOnce();
    const mine = document.getElementById('notes-list');
    if (mine) mine.replaceChildren(_el('div', 'spinner'));
    try {
        // Public links are best-effort: if the endpoint is unavailable the notes still render.
        const [a, b, c] = await Promise.all([
            apiRequest('/notes'),
            apiRequest('/notes/received'),
            apiRequest('/note-links', { silent: true }).catch(() => ({ links: [] })),
        ]);
        state.notes = (a && a.notes) || [];
        state.notesReceived = (b && b.notes) || [];
        state.noteLinks = (c && c.links) || [];
        renderNotes();
    } catch (e) {
        if (mine) mine.replaceChildren(_el('div', 'alert alert-error', 'Failed to load notes: ' + ((e && e.message) || '')));
    }
}

function renderNotes() {
    _notesState();
    const hideToggle = document.getElementById('notes-hide-toggle');
    if (hideToggle) hideToggle.checked = state.notesHideText;
    // Tabs
    document.querySelectorAll('#notes-section .tab-btn[data-notes-tab]').forEach(
        b => b.classList.toggle('active', b.getAttribute('data-notes-tab') === state.notesTab));
    const mineTab = document.getElementById('notes-tab-mine');
    const recvTab = document.getElementById('notes-tab-received');
    const sharedTab = document.getElementById('notes-tab-shared');
    if (mineTab) mineTab.style.display = state.notesTab === 'mine' ? '' : 'none';
    if (recvTab) recvTab.style.display = state.notesTab === 'received' ? '' : 'none';
    if (sharedTab) sharedTab.style.display = state.notesTab === 'shared' ? '' : 'none';
    // My-notes count badge
    const mineBadge = document.getElementById('notes-mine-count');
    if (mineBadge) {
        mineBadge.textContent = String(state.notes.length);
        mineBadge.hidden = state.notes.length === 0;
    }
    // Received count badge
    const badge = document.getElementById('notes-received-count');
    if (badge) {
        badge.textContent = String(state.notesReceived.length);
        badge.hidden = state.notesReceived.length === 0;
    }
    // Shared (active links) count badge
    const links = state.noteLinks || [];
    const sharedBadge = document.getElementById('notes-shared-count');
    if (sharedBadge) {
        const activeLinks = links.filter(l => l.status === 'active').length;
        sharedBadge.textContent = String(activeLinks);
        sharedBadge.hidden = activeLinks === 0;
    }
    // Shared (by me)
    const shared = document.getElementById('notes-shared-list');
    if (shared) {
        if (!links.length) {
            shared.replaceChildren(_el('p', 'text-secondary p-md', 'No public links yet. Use Share → Public link on a note to create one.'));
        } else {
            shared.replaceChildren(...links.map(_noteLinkCard));
        }
    }
    // My notes
    const mine = document.getElementById('notes-list');
    if (mine) {
        if (!state.notes.length) {
            mine.replaceChildren(_el('p', 'text-secondary p-md', 'No notes yet. Create one to get started.'));
        } else {
            mine.replaceChildren(...state.notes.map(n => _noteCard(n, false)));
        }
    }
    // Received
    const recv = document.getElementById('notes-received-list');
    if (recv) {
        if (!state.notesReceived.length) {
            recv.replaceChildren(_el('p', 'text-secondary p-md', 'Notes other people send you will appear here.'));
        } else {
            recv.replaceChildren(...state.notesReceived.map(n => _noteCard(n, true)));
        }
    }
}

function _noteCard(n, received) {
    const source = received ? 'received' : 'mine';
    const card = _el('div', 'card note-card');
    // The whole tile opens the note. Ignore clicks that land on an inner control (the action
    // buttons / star / eye) so those keep their own behaviour.
    card.addEventListener('click', (e) => {
        if (e.target.closest('button')) return;
        openNoteView(n.id, source);
    });
    const bodyWrap = _el('div', 'card-body');
    const head = _el('div', 'flex justify-between items-center gap-sm');
    // The title is the accessible open control (keyboard users tab to it); the card click above is
    // a mouse convenience. A heading wrapping a button keeps both semantics and focusability without
    // making the whole card a (nested-interactive) button.
    const titleH = _el('h3', 'text-lg font-bold note-title');
    const titleBtn = _el('button', 'note-open-title', n.title || 'Untitled note');
    titleBtn.type = 'button';
    titleBtn.addEventListener('click', () => openNoteView(n.id, source));
    titleH.appendChild(titleBtn);
    head.appendChild(titleH);
    if (!received) {
        // A plain inline button (NOT .vault-fav, which is position:absolute and would escape the
        // card). The gold fill on the star marks the favourited state; the is-fav class is a hook.
        const star = _el('button', 'btn btn-ghost btn-sm note-fav' + (n.is_favorite ? ' is-fav' : ''));
        star.type = 'button';
        star.setAttribute('aria-label', n.is_favorite ? 'Remove from favourites' : 'Add to favourites');
        const ic = _svgIcon('star', 'icon-sm');
        if (n.is_favorite) { ic.style.fill = '#f5b301'; ic.style.stroke = '#f5b301'; }
        star.appendChild(ic);
        star.addEventListener('click', () => toggleNoteFavorite(n.id, !n.is_favorite));
        head.appendChild(star);
    }
    bodyWrap.appendChild(head);

    if (received && n.sent_from) {
        bodyWrap.appendChild(_el('div', 'text-secondary text-sm', 'Sent from ' + n.sent_from));
    }

    // Body — masked when the global hide is on and this note isn't individually revealed.
    const masked = state.notesHideText && !state.notesRevealed.has(n.id);
    const bodyRow = _el('div', 'flex items-center gap-sm mt-sm');
    if (masked) {
        bodyRow.appendChild(_el('span', 'text-tertiary', '•••••• hidden'));
    } else {
        bodyRow.appendChild(_el('div', 'note-body', n.body || ''));
    }
    if (state.notesHideText) {
        const eye = _el('button', 'btn btn-ghost btn-sm');
        eye.type = 'button';
        eye.setAttribute('aria-label', masked ? 'Show note text' : 'Hide note text');
        eye.appendChild(_svgIcon('eye', 'icon-sm'));
        eye.addEventListener('click', () => {
            if (state.notesRevealed.has(n.id)) state.notesRevealed.delete(n.id);
            else state.notesRevealed.add(n.id);
            renderNotes();
        });
        bodyRow.appendChild(eye);
    }
    bodyWrap.appendChild(bodyRow);

    const actions = _el('div', 'flex gap-sm mt-md note-actions');
    if (received) {
        // The tile itself opens the read modal (where the recipient reads before adopting).
        const adopt = _el('button', 'btn btn-primary btn-sm', 'Add to my notes');
        adopt.type = 'button';
        adopt.addEventListener('click', () => adoptNote(n.id));
        actions.appendChild(adopt);
    } else {
        const edit = _el('button', 'btn btn-secondary btn-sm', 'Edit');
        edit.type = 'button';
        edit.addEventListener('click', () => openNoteEditor(n));
        actions.appendChild(edit);
        const share = _el('button', 'btn btn-ghost btn-sm', 'Share');
        share.type = 'button';
        share.addEventListener('click', () => openNoteShare(n.id));
        actions.appendChild(share);
        const del = _el('button', 'btn btn-ghost btn-sm', 'Delete');
        del.type = 'button';
        del.addEventListener('click', () => deleteNoteItem(n.id, n.title));
        actions.appendChild(del);
    }
    bodyWrap.appendChild(actions);
    card.appendChild(bodyWrap);
    return card;
}

// ---- "Shared (by me)" tab: a card per public note link ---------------------------------------
const _NOTE_LINK_STATUS_LABEL = { active: 'Active', revoked: 'Revoked', expired: 'Expired', exhausted: 'Used up' };

function _fmtLinkExpiry(iso) {
    // parseServerTime reads the API's UTC timestamp correctly (the bare Date constructor would
    // misread it as local time — and the offline UI-time guard test forbids that).
    const d = parseServerTime(iso);
    if (!d || isNaN(d)) return 'No expiry';
    return 'Expires ' + d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function _noteLinkCard(l) {
    const card = _el('div', 'card note-link-card');
    const hex = (typeof noteLinkColorHex === 'function') ? noteLinkColorHex(l.tag_border_color) : '';
    if (hex) card.style.borderLeft = '4px solid ' + hex;
    const body = _el('div', 'card-body');
    const head = _el('div', 'flex justify-between items-center gap-sm');
    const lead = _el('div', 'nl-tag-idlead');
    if (l.tag_icon) lead.appendChild(_svgIcon(l.tag_icon, 'icon-sm'));
    lead.appendChild(_el('span', 'text-secondary text-sm', l.tag_name || 'Link'));
    head.appendChild(lead);
    head.appendChild(_el('span', 'badge ' + (l.status === 'active' ? 'badge-success' : 'badge-secondary'),
        _NOTE_LINK_STATUS_LABEL[l.status] || l.status));
    body.appendChild(head);
    body.appendChild(_el('h3', 'text-base font-bold mt-sm note-link-title', l.title || 'Untitled note'));
    const secret = l.secret_kind === 'password' ? 'Password' : (l.secret_kind === 'pin' ? 'PIN' : 'No code');
    const exp = l.expires_at ? _fmtLinkExpiry(l.expires_at) : 'No expiry';
    const views = (l.max_uses != null) ? (l.view_count + ' / ' + l.max_uses + ' views') : (l.view_count + ' views');
    body.appendChild(_el('div', 'text-secondary text-sm mt-sm', secret + ' · ' + exp + ' · ' + views));
    const actions = _el('div', 'flex gap-sm mt-md flex-wrap note-actions');
    // View the frozen snapshot this link serves (always available, even once revoked/expired).
    const view = _el('button', 'btn btn-secondary btn-sm', 'View');
    view.type = 'button';
    view.addEventListener('click', () => openNoteLinkSnapshot(l));
    actions.appendChild(view);
    if (l.status === 'active') {
        const copy = _el('button', 'btn btn-ghost btn-sm', 'Copy link');
        copy.type = 'button';
        copy.addEventListener('click', () => copyNoteLinkUrl(l));
        actions.appendChild(copy);
        const revoke = _el('button', 'btn btn-ghost btn-sm', 'Revoke');
        revoke.type = 'button';
        revoke.addEventListener('click', () => revokeNoteLink(l.id));
        actions.appendChild(revoke);
    }
    const del = _el('button', 'btn btn-ghost btn-sm', 'Delete');
    del.type = 'button';
    del.addEventListener('click', () => deleteNoteLink(l.id));
    actions.appendChild(del);
    body.appendChild(actions);
    card.appendChild(body);
    return card;
}

function openNoteLinkSnapshot(l) {
    // Show the frozen snapshot this link serves (title + body), so the owner can recall what's in it.
    const titleEl = document.getElementById('note-link-snapshot-title');
    const bodyEl = document.getElementById('note-link-snapshot-body');
    if (titleEl) titleEl.textContent = l.title || 'Untitled note';
    if (bodyEl) bodyEl.textContent = (l.body != null) ? l.body : '(snapshot text unavailable)';
    openModal('note-link-snapshot-modal');
}

function copyNoteLinkUrl(l) {
    const url = window.location.origin + (l.url_path || ('/l/' + l.token));
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(() => showSuccess('Link copied'))
            .catch(() => showError('Copy failed — ' + url));
    } else {
        showError('Copy not supported — ' + url);
    }
}

async function revokeNoteLink(id) {
    const ok = await showConfirm('Revoke this link? Anyone holding it will no longer be able to open it.');
    if (!ok) return;
    try {
        await apiRequest('/note-links/' + id + '/revoke', { method: 'POST' });
        showSuccess('Link revoked');
        await loadNotes();
    } catch (e) { showError((e && e.message) || 'Could not revoke the link'); }
}

async function deleteNoteLink(id) {
    const ok = await showConfirm('Delete this link permanently? This removes the shared snapshot.');
    if (!ok) return;
    try {
        await apiRequest('/note-links/' + id, { method: 'DELETE' });
        showSuccess('Link deleted');
        await loadNotes();
    } catch (e) { showError((e && e.message) || 'Could not delete the link'); }
}

// ---- Note read modal (rendered note + a left rail to switch between notes) --------------------
// One modal serves both "my notes" (source='mine') and received notes (source='received', shown
// with a Preview button before adopting). The rail lists the notes from the same source so the
// reader can jump between them without closing. Body renders with textContent (pre-wrap) — the
// note text is server-side plaintext and must never be interpreted as HTML.
function _noteViewList() {
    return state.noteViewSource === 'received' ? (state.notesReceived || []) : (state.notes || []);
}

function openNoteView(id, source) {
    _notesState();
    state.noteViewSource = source === 'received' ? 'received' : 'mine';
    state.noteViewId = id;
    openModal('note-view-modal');
    renderNoteView();
}

function renderNoteView() {
    const list = _noteViewList();
    const cur = list.find(n => n.id === state.noteViewId) || list[0] || null;
    if (cur) state.noteViewId = cur.id;
    // Left rail: every note from this source, current one highlighted.
    const rail = document.getElementById('note-view-rail');
    if (rail) {
        rail.replaceChildren();
        list.forEach(n => {
            const item = _el('button', 'note-view-rail-item' + (cur && n.id === cur.id ? ' active' : ''),
                             n.title || 'Untitled note');
            item.type = 'button';
            item.addEventListener('click', () => { state.noteViewId = n.id; renderNoteView(); });
            rail.appendChild(item);
        });
        if (!list.length) rail.appendChild(_el('p', 'text-tertiary text-sm p-sm', 'No notes'));
    }
    const titleEl = document.getElementById('note-view-title');
    if (titleEl) titleEl.textContent = cur ? (cur.title || 'Untitled note') : 'Note';
    const meta = document.getElementById('note-view-meta');
    if (meta) {
        meta.textContent = (cur && state.noteViewSource === 'received' && cur.sent_from)
            ? ('Sent from ' + cur.sent_from) : '';
        meta.style.display = meta.textContent ? '' : 'none';
    }
    const bodyEl = document.getElementById('note-view-content-body');
    if (bodyEl) bodyEl.textContent = cur ? (cur.body || '') : '';
    // Footer actions depend on the source.
    const actions = document.getElementById('note-view-actions');
    if (actions) {
        actions.replaceChildren();
        if (!cur) return;
        if (state.noteViewSource === 'received') {
            const adopt = _el('button', 'btn btn-primary', 'Add to my notes');
            adopt.type = 'button';
            adopt.addEventListener('click', async () => { await adoptNote(cur.id); closeModal(); });
            actions.appendChild(adopt);
        } else {
            const edit = _el('button', 'btn btn-secondary', 'Edit');
            edit.type = 'button';
            edit.addEventListener('click', () => { closeModal(); openNoteEditor(cur); });
            actions.appendChild(edit);
            const share = _el('button', 'btn btn-ghost', 'Share');
            share.type = 'button';
            share.addEventListener('click', () => { closeModal(); openNoteShare(cur.id); });
            actions.appendChild(share);
        }
        const close = _el('button', 'btn btn-ghost', 'Close');
        close.type = 'button';
        close.addEventListener('click', closeModal);
        actions.appendChild(close);
    }
}

function openNoteEditor(note) {
    _notesState();
    state.editingNoteId = note ? note.id : null;
    const t = document.getElementById('note-editor-title-input');
    const b = document.getElementById('note-editor-body-input');
    const h = document.getElementById('note-editor-title');
    if (t) t.value = note ? (note.title || '') : '';
    if (b) b.value = note ? (note.body || '') : '';
    if (h) h.textContent = note ? 'Edit note' : 'New note';
    openModal('note-editor-modal');
    if (t) t.focus();
}

async function saveNote() {
    const t = document.getElementById('note-editor-title-input');
    const b = document.getElementById('note-editor-body-input');
    const title = (t && t.value) || '';
    const body = (b && b.value) || '';
    if (!title.trim() && !body.trim()) { showError('A note needs a title or some text'); return; }
    try {
        if (state.editingNoteId) {
            await apiRequest('/notes/' + state.editingNoteId, { method: 'PATCH', body: JSON.stringify({ title, body }) });
        } else {
            await apiRequest('/notes', { method: 'POST', body: JSON.stringify({ title, body }) });
        }
        closeModal();
        showSuccess('Note saved');
        await loadNotes();
    } catch (e) { showError((e && e.message) || 'Could not save the note'); }
}

async function toggleNoteFavorite(id, on) {
    const n = (state.notes || []).find(x => x.id === id);
    if (n) n.is_favorite = on;   // optimistic
    renderNotes();
    try { await apiRequest('/notes/' + id, { method: 'PATCH', body: JSON.stringify({ is_favorite: on }) }); await loadNotes(); }
    catch (e) { if (n) n.is_favorite = !on; renderNotes(); showError((e && e.message) || 'Could not update the note'); }
}

async function deleteNoteItem(id, title) {
    const ok = await showConfirm(`Delete note "${title || 'Untitled'}"? This cannot be undone.`);
    if (!ok) return;
    try { await apiRequest('/notes/' + id, { method: 'DELETE' }); showSuccess('Note deleted'); await loadNotes(); }
    catch (e) { showError((e && e.message) || 'Could not delete the note'); }
}

async function adoptNote(id) {
    try { await apiRequest('/notes/' + id + '/adopt', { method: 'POST' }); showSuccess('Added to your notes'); await loadNotes(); }
    catch (e) { showError((e && e.message) || 'Could not add the note'); }
}

function openSendNote(id) {
    state.sendingNoteId = id;
    state.sendRecipientId = null;
    const search = document.getElementById('note-send-search');
    const results = document.getElementById('note-send-results');
    const chosen = document.getElementById('note-send-chosen');
    const confirm = document.getElementById('note-send-confirm');
    if (search) search.value = '';
    if (results) results.replaceChildren();
    if (chosen) { chosen.hidden = true; chosen.textContent = ''; }
    if (confirm) confirm.disabled = true;
    openModal('note-send-modal');
    if (search) search.focus();
}

let _noteSearchTimer = null;
function onNoteRecipientSearch() {
    const search = document.getElementById('note-send-search');
    const results = document.getElementById('note-send-results');
    if (!search || !results) return;
    const q = search.value.trim();
    if (_noteSearchTimer) clearTimeout(_noteSearchTimer);
    if (q.length < 2) { results.replaceChildren(); return; }
    _noteSearchTimer = setTimeout(async () => {
        try {
            const users = await apiRequest('/users/search?q=' + encodeURIComponent(q), { silent: true });
            results.replaceChildren();
            (users || []).slice(0, 8).forEach(u => {
                const row = _el('button', 'btn btn-ghost btn-sm', u.username || u.email || u.id);
                row.type = 'button';
                row.style.display = 'block';
                row.style.width = '100%';
                row.style.textAlign = 'left';
                row.addEventListener('click', () => {
                    state.sendRecipientId = u.id;
                    const chosen = document.getElementById('note-send-chosen');
                    if (chosen) { chosen.hidden = false; chosen.textContent = 'Sending to: ' + (u.username || u.email || u.id); }
                    const confirm = document.getElementById('note-send-confirm');
                    if (confirm) confirm.disabled = false;
                });
                results.appendChild(row);
            });
            if (!users || !users.length) results.replaceChildren(_el('p', 'text-tertiary text-sm', 'No matching users'));
        } catch (e) { results.replaceChildren(_el('p', 'text-tertiary text-sm', 'Search unavailable')); }
    }, 250);
}

async function confirmSendNote() {
    if (!state.sendingNoteId || !state.sendRecipientId) return;
    const btn = document.getElementById('note-send-confirm');
    if (btn) btn.disabled = true;
    try {
        await apiRequest('/notes/' + state.sendingNoteId + '/send',
            { method: 'POST', body: JSON.stringify({ recipient_user_id: state.sendRecipientId }) });
        closeModal();
        showSuccess('Note sent');
    } catch (e) { showError((e && e.message) || 'Could not send the note'); if (btn) btn.disabled = false; }
}

// ---- Share note: a two-tile chooser (Send to a member / Public link) -------------------------
function openNoteShare(id) {
    state.shareNoteId = id;
    const pubTile = document.getElementById('note-share-public');
    const disabledNote = document.getElementById('note-share-public-disabled');
    if (pubTile) pubTile.disabled = false;          // refined once the policy loads
    if (disabledNote) disabledNote.hidden = true;
    openModal('note-share-modal');
    // Learn whether public links are enabled + which tags this user may create with.
    apiRequest('/note-link-policy', { silent: true }).then(p => {
        state._noteLinkPolicy = p || { enabled: false, tags: [] };
        const enabled = !!(p && p.enabled);
        if (pubTile) pubTile.disabled = !enabled;
        if (disabledNote) disabledNote.hidden = enabled;
    }).catch(() => {
        state._noteLinkPolicy = { enabled: false, tags: [] };
        if (pubTile) pubTile.disabled = true;
        if (disabledNote) disabledNote.hidden = false;
    });
}

function _npEl(id) { return document.getElementById(id); }

async function openNotePublicLink(id) {
    state.shareNoteId = id;
    if (!state._noteLinkPolicy) {
        try { state._noteLinkPolicy = await apiRequest('/note-link-policy', { silent: true }); }
        catch (_) { state._noteLinkPolicy = { enabled: false, tags: [] }; }
    }
    const policy = state._noteLinkPolicy || { enabled: false, tags: [] };
    _npEl('note-public-form').hidden = false;
    _npEl('note-public-result').hidden = true;
    _npEl('note-public-create').hidden = false;
    if (_npEl('note-public-cancel')) _npEl('note-public-cancel').hidden = false;
    if (_npEl('note-public-done')) _npEl('note-public-done').hidden = true;
    const err = _npEl('note-public-error'); if (err) err.hidden = true;
    const sel = _npEl('note-public-tag');
    sel.replaceChildren();
    const tags = policy.tags || [];
    if (!tags.length) {
        const o = _el('option', '', policy.enabled ? 'No link types available to you' : 'Public links are turned off');
        o.value = '';
        sel.appendChild(o);
        _npEl('note-public-create').disabled = true;
    } else {
        _npEl('note-public-create').disabled = false;
        tags.forEach(t => { const o = _el('option', '', t.name); o.value = t.id; sel.appendChild(o); });
    }
    openModal('note-public-link-modal');
    onNotePublicTagChange();
}

function _notePublicSelectedTag() {
    const sel = _npEl('note-public-tag');
    const id = sel ? sel.value : '';
    return (((state._noteLinkPolicy || {}).tags) || []).find(t => t.id === id) || null;
}

function _npSecretPhrase(kind) {
    return kind === 'password' ? 'a password' : (kind === 'pin' ? 'a PIN' : 'no code');
}

const _NP_SECRET_STRENGTH = { none: 0, pin: 1, password: 2 };

function onNotePublicTagChange() {
    const t = _notePublicSelectedTag();
    const floor = _npEl('note-public-tag-floor');
    if (!t) { if (floor) floor.textContent = ''; return; }
    const ttlTxt = t.max_ttl_hours ? ('expires within ' + t.max_ttl_hours + 'h') : 'no expiry required';
    const useTxt = t.max_uses_cap ? ('up to ' + t.max_uses_cap + ' view(s)') : 'unlimited views';
    if (floor) floor.textContent = 'This type requires at least: a ' + t.min_token_len + '-char link, '
        + _npSecretPhrase(t.require_secret) + ', ' + ttlTxt + ', ' + useTxt + '. You can only make it stricter.';
    // Token length floor.
    const tok = _npEl('note-public-token-len');
    tok.min = t.min_token_len; tok.value = t.min_token_len;
    // Secret: disable anything weaker than the floor; default to the floor.
    const secret = _npEl('note-public-secret');
    Array.from(secret.options).forEach(o => {
        o.disabled = (_NP_SECRET_STRENGTH[o.value] || 0) < (_NP_SECRET_STRENGTH[t.require_secret] || 0);
    });
    secret.value = t.require_secret;
    onNotePublicSecretChange();
    // PIN length options >= the floor.
    const pinLen = _npEl('note-public-pin-len');
    pinLen.replaceChildren();
    [4, 6, 8].filter(n => n >= (t.min_pin_len || 4)).forEach(n => {
        const o = _el('option', '', n + ' digits'); o.value = String(n); pinLen.appendChild(o);
    });
    const pwHelp = _npEl('note-public-password-help');
    if (pwHelp) pwHelp.textContent = 'At least ' + (t.password_min_len || 8) + ' characters'
        + (t.password_require_alnum ? ', including letters and numbers.' : '.');
    // Expiry: the tag's max is the ceiling. "Never expires" is only allowed when the tag sets no
    // ceiling — so it's always VISIBLE but DISABLED (greyed) under a capped tag, rather than hidden,
    // so the operator can see it's an option that this tag forbids.
    const ttl = _npEl('note-public-ttl');
    const never = _npEl('note-public-never');
    if (t.max_ttl_hours) {
        ttl.max = t.max_ttl_hours;
        ttl.value = t.default_ttl_hours || t.max_ttl_hours;
        ttl.disabled = false;
        if (never) { never.checked = false; never.disabled = true; never.title = 'This link type caps the lifetime, so it cannot be set to never expire.'; }
    } else {
        ttl.removeAttribute('max');
        if (never) { never.disabled = false; never.title = ''; }
        if (t.default_ttl_hours) { ttl.value = t.default_ttl_hours; if (never) never.checked = false; ttl.disabled = false; }
        else { if (never) never.checked = true; ttl.value = ''; ttl.disabled = true; }
    }
    // Max uses: the tag's cap is the ceiling; unlimited only when the tag sets no cap.
    const uses = _npEl('note-public-max-uses');
    if (t.max_uses_cap) { uses.max = t.max_uses_cap; uses.value = t.max_uses_cap; uses.placeholder = 'up to ' + t.max_uses_cap; }
    else { uses.removeAttribute('max'); uses.value = ''; uses.placeholder = 'unlimited'; }
}

function onNotePublicSecretChange() {
    const kind = _npEl('note-public-secret').value;
    _npEl('note-public-pin-group').hidden = (kind !== 'pin');
    _npEl('note-public-password-group').hidden = (kind !== 'password');
}

function _npNeverChecked() {
    const n = _npEl('note-public-never');
    return !!(n && !n.disabled && n.checked);   // "never" counts only when the tag allows it
}

function _notePublicPayload() {
    const t = _notePublicSelectedTag();
    const p = { note_id: state.shareNoteId, tag_id: t.id };
    const tok = parseInt(_npEl('note-public-token-len').value, 10);
    if (Number.isFinite(tok)) p.token_len = tok;
    const kind = _npEl('note-public-secret').value;
    p.secret_kind = kind;
    if (kind === 'pin') p.pin = (_npEl('note-public-pin').value || '').trim();
    if (kind === 'password') p.password = _npEl('note-public-password').value || '';
    if (_npNeverChecked()) { p.ttl_hours = null; }
    else { const h = parseInt(_npEl('note-public-ttl').value, 10); if (Number.isFinite(h)) p.ttl_hours = h; }
    const mu = parseInt(_npEl('note-public-max-uses').value, 10);
    p.max_uses = Number.isFinite(mu) ? mu : null;
    return p;
}

async function submitNotePublicLink() {
    const t = _notePublicSelectedTag();
    const err = _npEl('note-public-error');
    if (err) err.hidden = true;
    if (!t) { if (err) { err.textContent = 'Choose a link type first.'; err.hidden = false; } return; }
    const btn = _npEl('note-public-create');
    btn.disabled = true;
    try {
        const link = await apiRequest('/note-links', { method: 'POST', body: JSON.stringify(_notePublicPayload()) });
        const url = window.location.origin + (link.url_path || ('/l/' + link.token));
        state._lastPublicLinkUrl = url;
        _npEl('note-public-form').hidden = true;
        _npEl('note-public-result').hidden = false;
        _npEl('note-public-link-value').value = url;
        btn.hidden = true;
        if (_npEl('note-public-cancel')) _npEl('note-public-cancel').hidden = true;
        if (_npEl('note-public-done')) _npEl('note-public-done').hidden = false;
        // Refresh so the new link shows on the "Shared" tab without a page reload.
        loadNotes();
    } catch (e) {
        if (err) { err.textContent = (e && e.message) || 'Could not create the link.'; err.hidden = false; }
        btn.disabled = false;
    }
}

function copyNotePublicLink() {
    const inp = _npEl('note-public-link-value');
    const val = (inp && inp.value) || state._lastPublicLinkUrl || '';
    if (!val) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(val).then(() => showSuccess('Link copied'))
            .catch(() => { if (inp) { inp.select(); } showError('Copy failed — select the link and copy it.'); });
    } else if (inp) {
        inp.select();
        try { document.execCommand('copy'); showSuccess('Link copied'); } catch (_) { showError('Copy failed.'); }
    }
}

function wireNotesOnce() {
    if (state._notesWired) return;
    state._notesWired = true;
    const nw = document.getElementById('note-new-btn');
    if (nw) nw.addEventListener('click', () => openNoteEditor(null));
    document.querySelectorAll('#notes-section .tab-btn[data-notes-tab]').forEach(b =>
        b.addEventListener('click', () => {
            state.notesTab = b.getAttribute('data-notes-tab');
            try { localStorage.setItem('notesTab', state.notesTab); } catch (_) {}   // survive a page reload
            renderNotes();
        }));
    const hide = document.getElementById('notes-hide-toggle');
    if (hide) hide.addEventListener('change', () => {
        state.notesHideText = hide.checked;
        try { localStorage.setItem('notesHideText', hide.checked ? '1' : '0'); } catch (_) {}
        state.notesRevealed = new Set();  // a fresh mask reveals nothing
        renderNotes();
    });
    const save = document.getElementById('note-editor-save');
    if (save) save.addEventListener('click', saveNote);
    const sendConfirm = document.getElementById('note-send-confirm');
    if (sendConfirm) sendConfirm.addEventListener('click', confirmSendNote);
    const sendSearch = document.getElementById('note-send-search');
    if (sendSearch) sendSearch.addEventListener('input', onNoteRecipientSearch);
    // Share chooser tiles.
    const shareInternal = document.getElementById('note-share-internal');
    if (shareInternal) shareInternal.addEventListener('click', () => { closeModal(); openSendNote(state.shareNoteId); });
    const sharePublic = document.getElementById('note-share-public');
    if (sharePublic) sharePublic.addEventListener('click', () => { closeModal(); openNotePublicLink(state.shareNoteId); });
    // Public-link form.
    const pubTag = document.getElementById('note-public-tag');
    if (pubTag) pubTag.addEventListener('change', onNotePublicTagChange);
    const pubSecret = document.getElementById('note-public-secret');
    if (pubSecret) pubSecret.addEventListener('change', onNotePublicSecretChange);
    const pubNever = document.getElementById('note-public-never');
    if (pubNever) pubNever.addEventListener('change', () => {
        const ttl = document.getElementById('note-public-ttl'); if (ttl) ttl.disabled = pubNever.checked;
    });
    const pubCreate = document.getElementById('note-public-create');
    if (pubCreate) pubCreate.addEventListener('click', submitNotePublicLink);
    const pubCopy = document.getElementById('note-public-copy');
    if (pubCopy) pubCopy.addEventListener('click', copyNotePublicLink);
    document.querySelectorAll('[data-note-close], [data-note-send-close], [data-note-view-close], '
        + '[data-note-share-close], [data-note-public-close], [data-note-snapshot-close]').forEach(el =>
        el.addEventListener('click', closeModal));
}

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
    clearCredentialInputsOnClose();
}

// Empty the credential fields of any dialog that just closed.
//
// Several dialogs reset themselves when they OPEN, which bounds how long a typed password lingers
// — but only until the next open. Someone who types one, cancels, and never returns leaves it in
// the page for the rest of the session, and two dialogs (create-user, admin change-password) have
// no reset on open at all. Clearing on the way out makes that window zero for all of them.
//
// Found BY TYPE rather than from a hand-kept list of ids, so a dialog added later cannot quietly
// opt out of this simply by existing. Scoped to dialogs on purpose: the login field and the SMTP
// settings field are not in modals, and the SMTP one is a stored deployment credential that is
// meant to persist in its form.
function clearCredentialInputsOnClose() {
    document.querySelectorAll('.modal input[type="password"]').forEach(el => { el.value = ''; });
    // The shared prompt input is switched back to type=text as it closes, so the selector above
    // cannot see it even though it is the field most likely to be holding a passphrase.
    const shared = document.getElementById('confirm-modal-input');
    if (shared) shared.value = '';
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


// ============================================================================
// VIEW CLEANUP & RESOURCE MANAGEMENT
// ============================================================================

// Clean up resources when leaving views
function cleanupPreviousView(newSection) {
    console.log('Cleaning up resources before switching to:', newSection);
    
    // The activity socket is app-wide (it delivers live notifications on ANY page, e.g. a note you
    // were just sent), so navigation must NOT close it -- it is torn down only on logout. Previously
    // this closed it on every non-monitor navigation, which silently disabled live notifications
    // after the first page change. Just make sure it's connected in case a prior drop left it closed.
    if (newSection !== 'monitor') {
        ensureMonitorSocket();
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

    // Load the notification bell after a refresh too.
    initNotifications();

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

    // Vault-list ordering. Applied before any early-return below so the list is ordered the
    // account's way on first paint rather than jumping after a later refresh.
    applyVaultOrderPrefs(prefs);

    // Per-user "never remember my vault password" preference (stored as 'on'/'off'). Apply it
    // before any early-return below so the opt-out always takes effect.
    if (typeof prefs.never_remember_vault_password === 'string') {
        state.neverRememberVaultPassword = (prefs.never_remember_vault_password === 'on');
        if (state.neverRememberVaultPassword) { state.rememberedVaults = {}; state._persistRemembered(); }
    }
    // Load the deployment-wide org floor at boot (not just when the account modal opens) so the
    // client remember-guard is reliably armed before any vault is opened. Server-side the floor
    // already clamps every vault's unlock window to 0; this closes the client cache path too.
    try {
        const pol = await apiRequest('/temp-passcode-policy', { silent: true });
        state.forceNoRememberVaultPassword = !!(pol && pol.force_no_remember_vault_password === true);
        if (state.forceNoRememberVaultPassword) { state.rememberedVaults = {}; state._persistRemembered(); }
    } catch (_) { /* best-effort; the server clamp is the authoritative enforcement */ }
    // Load the ZK-key idle auto-lock policy at boot so any later unlock arms the countdown.
    try {
        const zk = await apiRequest('/zk-enabled', { silent: true });
        setZkIdleLockMinutes(zk && zk.zk_idle_lock_minutes);
        // Where this account's decrypted downloads go, already resolved server-side: the
        // organisation's policy, this user's preference when the organisation delegates, and
        // whether the browser can register a worker here at all. Absent or unreadable means the
        // buffered path, which is what shipped before any of this existed.
        state.downloadSink = (zk && zk.download_sink && zk.download_sink.sink === 'streaming')
            ? 'streaming' : 'buffered';
    } catch (_) { /* best-effort; default = no idle lock, buffered downloads */ }

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

    // An /?invite=... link is the invitation-acceptance flow: an anonymous visitor sets a password
    // and claims a pre-created account. It takes precedence over any cached session and never enters
    // the app — run it and stop here so the login/session bootstrap below is skipped.
    const inviteToken = new URLSearchParams(location.search).get('invite');
    if (inviteToken) {
        // Strip ?invite=<token> from the URL immediately (keep the token only in JS memory), so the
        // single-use token can't leak via the Referer header of any sub-resource this page loads, or
        // sit in browser/proxy history. Done before initInviteFlow fetches anything.
        try { history.replaceState(null, '', location.pathname); } catch (_) {}
        document.documentElement.removeAttribute('data-auth');
        initInviteFlow(inviteToken);
        return;
    }

    // A /?reset=<token> link is the password-reset flow: set a new password, then route to login. Like
    // invite, it takes precedence over any cached session and strips the token from the URL first.
    const resetToken = new URLSearchParams(location.search).get('reset');
    if (resetToken) {
        try { history.replaceState(null, '', location.pathname); } catch (_) {}
        document.documentElement.removeAttribute('data-auth');
        initResetFlow(resetToken);
        return;
    }

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

    // Notification bell toggle (mirrors the profile dropdown)
    const notifBtn = document.getElementById('notif-btn');
    const notifMenu = document.getElementById('notif-menu');
    if (notifBtn && notifMenu) {
        notifBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const opening = !notifMenu.classList.contains('active');
            notifMenu.classList.toggle('active');
            notifBtn.setAttribute('aria-expanded', opening ? 'true' : 'false');
            if (opening) loadNotifications();  // pull the freshest list when the panel opens
        });
        document.addEventListener('click', (e) => {
            if (!notifMenu.contains(e.target)) {
                notifMenu.classList.remove('active');
                notifBtn.setAttribute('aria-expanded', 'false');
            }
        });
        const markAll = document.getElementById('notif-mark-all');
        if (markAll) markAll.addEventListener('click', (e) => { e.stopPropagation(); markAllNotifRead(); });
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
                } else if (section === 'shared') {
                    loadShared().catch(err => console.error('Failed to load shared items:', err));
                } else if (section === 'notes') {
                    loadNotes().catch(err => console.error('Failed to load notes:', err));
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

    // Share the whole vault
    const shareVaultBtn = document.getElementById('share-vault-btn');
    if (shareVaultBtn) {
        shareVaultBtn.addEventListener('click', () => {
            const v = state.currentVault;
            if (v) openCreateShareModal('vault', v.id, v.name);
        });
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
            const submitBtn = generateTempCredsForm.querySelector('button[type="submit"]');
            if (!submitBtn || submitBtn.dataset.tempScopeReady !== 'true') {
                _tcShowError('Wait for the current vault policy to finish loading before generating credentials.');
                return;
            }

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
            // Passcode fail-closed: a passcode rides the vault-password proof, so an eligible vault
            // must be selected AND its password entered before we mint (the server also enforces this).
            const pcEnable = document.getElementById('tc-passcode-enable');
            const pcSection = document.getElementById('tc-passcode-section');
            if (scopeData && pcEnable && pcEnable.checked && pcSection && !pcSection.hidden) {
                const withPc = (scopeData.selected_vaults || []).filter(sv => sv.issue_passcode);
                if (!withPc.length) {
                    _tcShowError('To issue a temporary passcode, select at least one password-protected standard vault.');
                    return;
                }
                const unproven = withPc.find(sv => !sv.password);
                if (unproven) {
                    const nm = (_tcVaultObjs[unproven.vault_id] || {}).name || 'the selected vault';
                    _tcShowError(`Enter the vault password for “${nm}” to issue its passcode.`);
                    return;
                }
            }
            // Do NOT close here — generateTempCreds closes the modal only on success, and keeps it
            // open (with an inline error) on a recoverable failure so entered state isn't lost.
            const doMint = () => generateTempCreds({
                validity_minutes: validityMinutes, note, can_create_temp_credentials: canCreate,
                scope: scopeData ? scopeData.scope : null,
                vault_access_mode: scopeData ? scopeData.vault_access_mode : null,
                selected_vaults: scopeData ? scopeData.selected_vaults : null,
                passcode_same_for_all: scopeData ? scopeData.passcode_same_for_all : false,
            });
            // ZK-in-scope (allow policy): if the scope includes a zero-knowledge vault, a passcode
            // isn't available for it — require an explicit acknowledgment that the holder must type the
            // master passphrase before we mint. (Deny policy disables ZK rows / rejects server-side.)
            // An unrestricted (no scope) or all-vaults mint reaches EVERY vault, so it counts as
            // "ZK in scope" when the account owns/holds any zero-knowledge vault.
            const allowZk = !(_tcPasscodePolicy && _tcPasscodePolicy.temp_cred_allow_zk_vaults === false);
            const _mode = scopeData ? scopeData.vault_access_mode : null;
            const _unrestrictedOrAll = !scopeData || _mode === 'all';
            const zkSelected = _unrestrictedOrAll
                ? Object.keys(_tcVaultObjs).some(id => (_tcVaultObjs[id] || {}).type === 'zero_knowledge')
                : (scopeData.selected_vaults || []).some(sv => (_tcVaultObjs[sv.vault_id] || {}).type === 'zero_knowledge');
            if (allowZk && zkSelected) { _tcConfirmZkAck(doMint); return; }
            doMint();
        });
    }
    
    // Create user button
    const createUserBtn = document.getElementById('create-user-btn');
    if (createUserBtn) {
        createUserBtn.addEventListener('click', showCreateUser);
    }

    // Invite user button
    const inviteUserBtn = document.getElementById('invite-user-btn');
    if (inviteUserBtn) {
        inviteUserBtn.addEventListener('click', openInviteModal);
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

            // Storage quota: 'inherit' clears the override (null), 'unlimited' exempts the
            // account, a number sets an exact budget. A blank custom box is treated as
            // 'inherit' rather than 0, which would otherwise strand the account at no storage.
            const quotaMode = (document.getElementById('edit-user-quota-mode') || {}).value;
            let storageQuotaGb = null;
            if (quotaMode === 'unlimited') {
                storageQuotaGb = 'unlimited';
            } else if (quotaMode === 'custom') {
                const raw = (document.getElementById('edit-user-quota-gb') || {}).value;
                storageQuotaGb = (raw === '' || raw === undefined || raw === null) ? null : Number(raw);
            }

            try {
                await apiRequest(`/users/${userId}`, {
                    method: 'PATCH',
                    body: JSON.stringify({
                        // Clearing the box CLEARS the address, so send an explicit null rather
                        // than "". The backend distinguishes an omitted field (leave alone) from
                        // an explicit null (clear); "" is neither, and fails validation.
                        email: email.trim() ? email.trim() : null,
                        role,
                        is_active: isActive,
                        storage_quota_gb: storageQuotaGb
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
    // Share-tag colour picker: named swatches + a custom <input type=color> (mirrors the Groups editor).
    const shareTagColorSwatches = document.getElementById('share-tag-color-swatches');
    if (shareTagColorSwatches) {
        shareTagColorSwatches.addEventListener('click', (e) => {
            const sw = e.target.closest('.accent-swatch');
            if (sw) {
                e.preventDefault();
                setShareTagColor(sw.getAttribute('data-color') || '');
            }
        });
    }
    const shareTagColorCustom = document.getElementById('share-tag-color-custom');
    if (shareTagColorCustom) {
        shareTagColorCustom.addEventListener('input', () => setShareTagColor(shareTagColorCustom.value));
    }
    // Live "(~N days)" hints beside the share-tag Lifetime inputs.
    ['share-tag-max-lifetime', 'share-tag-default-lifetime'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('input', updateShareTagLifetimeHints);
    });
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
