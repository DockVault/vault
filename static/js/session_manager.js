/**
 * Global Session Manager
 * Handles authentication state, polling intervals, and automatic logout on session expiration
 */

class SessionManager {
    constructor() {
        this.intervals = [];
        this.timeouts = [];
        this.isAuthenticated = false;
        this.token = null;
        this.user = null;
    }

    /**
     * Initialize session manager
     */
    init() {
        console.log('[SESSION] Initializing session manager');
        this.loadSession();
    }

    /**
     * Load session from storage
     */
    loadSession() {
        this.token = localStorage.getItem('psftp_token') || sessionStorage.getItem('psftp_token');
        const userJson = localStorage.getItem('psftp_user') || sessionStorage.getItem('psftp_user');
        this.user = userJson ? JSON.parse(userJson) : null;
        this.isAuthenticated = !!(this.token && this.user);
        
        if (this.isAuthenticated) {
            console.log('[SESSION] Session loaded:', this.user.username);
        } else {
            console.log('[SESSION] No active session');
        }
    }

    /**
     * Save session to storage
     */
    saveSession(token, user) {
        console.log('[SESSION] Saving session for:', user.username);
        this.token = token;
        this.user = user;
        this.isAuthenticated = true;

        try {
            localStorage.setItem('psftp_token', token);
            localStorage.setItem('psftp_user', JSON.stringify(user));
        } catch (e) {
            // Private mode fallback
            sessionStorage.setItem('psftp_token', token);
            sessionStorage.setItem('psftp_user', JSON.stringify(user));
        }
    }

    /**
     * Clear session and cleanup
     */
    async clearSession(reason = 'manual') {
        console.log('[SESSION] Clearing session:', reason);
        
        // Stop all polling intervals and timeouts
        this.stopAllPolling();
        
        // Clear storage
        this.clearStorage();
        
        // Call logout endpoint if we have a token
        if (this.token && reason !== 'expired') {
            try {
                await fetch('/api/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                console.warn('[SESSION] Logout API call failed:', error);
            }
        }
        
        // Reset state
        this.token = null;
        this.user = null;
        this.isAuthenticated = false;
        
        // Redirect to login
        console.log('[SESSION] Redirecting to login screen');
        this.redirectToLogin();
    }

    /**
     * Clear all storage (cookies, localStorage, sessionStorage)
     */
    clearStorage() {
        console.log('[SESSION] Clearing all storage');
        
        // Clear localStorage
        localStorage.removeItem('psftp_token');
        localStorage.removeItem('psftp_user');
        
        // Clear sessionStorage
        sessionStorage.removeItem('psftp_token');
        sessionStorage.removeItem('psftp_user');
        
        // Clear cookies
        document.cookie = 'psftp_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
        document.cookie = 'psftp_user=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    }

    /**
     * Register an interval to be managed
     */
    registerInterval(intervalId) {
        if (intervalId) {
            this.intervals.push(intervalId);
            console.log('[SESSION] Registered interval, total:', this.intervals.length);
        }
    }

    /**
     * Register a timeout to be managed
     */
    registerTimeout(timeoutId) {
        if (timeoutId) {
            this.timeouts.push(timeoutId);
            console.log('[SESSION] Registered timeout, total:', this.timeouts.length);
        }
    }

    /**
     * Stop all polling intervals and timeouts
     */
    stopAllPolling() {
        console.log('[SESSION] Stopping all polling - intervals:', this.intervals.length, 'timeouts:', this.timeouts.length);
        
        // Clear all intervals
        this.intervals.forEach(id => {
            try {
                clearInterval(id);
            } catch (e) {
                console.warn('[SESSION] Failed to clear interval:', e);
            }
        });
        this.intervals = [];
        
        // Clear all timeouts
        this.timeouts.forEach(id => {
            try {
                clearTimeout(id);
            } catch (e) {
                console.warn('[SESSION] Failed to clear timeout:', e);
            }
        });
        this.timeouts = [];
        
        console.log('[SESSION] All polling stopped');
    }

    /**
     * Handle authentication error (401/403)
     */
    handleAuthError(response) {
        console.warn('[SESSION] Authentication error:', response.status);
        
        // Check if Clear-Site-Data header is present
        const clearData = response.headers.get('Clear-Site-Data');
        if (clearData) {
            console.log('[SESSION] Clear-Site-Data header received:', clearData);
        }
        
        // Clear session and redirect
        this.clearSession('expired');
    }

    /**
     * Redirect to login screen
     */
    redirectToLogin() {
        // Check if we're already on login screen
        const loginScreen = document.getElementById('login-screen');
        const appScreen = document.getElementById('app-screen');
        
        if (loginScreen && appScreen) {
            // Hide app, show login
            appScreen.style.display = 'none';
            loginScreen.classList.add('active');
            loginScreen.style.display = 'flex';
            
            // Clear any error messages
            const loginError = document.getElementById('login-error');
            if (loginError) {
                loginError.style.display = 'none';
                loginError.textContent = '';
            }
            
            // Reset login form
            const loginForm = document.getElementById('login-form');
            if (loginForm) {
                loginForm.reset();
            }
            
            console.log('[SESSION] Switched to login screen');
        } else {
            // Fallback: reload page
            console.log('[SESSION] Reloading page to show login');
            window.location.reload();
        }
    }

    /**
     * Wrap fetch to automatically handle auth errors
     */
    async fetch(url, options = {}) {
        // Add authorization header if we have a token
        if (this.token && !options.headers?.Authorization) {
            options.headers = {
                ...options.headers,
                'Authorization': `Bearer ${this.token}`
            };
        }
        
        try {
            const response = await fetch(url, options);
            
            // Check for authentication errors
            if (response.status === 401 || response.status === 403) {
                console.warn('[SESSION] Auth error in fetch:', url, response.status);
                this.handleAuthError(response);
                throw new Error('Session expired');
            }
            
            return response;
        } catch (error) {
            // Check if it's a network error or our session expired error
            if (error.message === 'Session expired') {
                throw error;
            }
            
            console.error('[SESSION] Fetch error:', url, error);
            throw error;
        }
    }
}

// Create global instance
window.sessionManager = new SessionManager();
console.log('[SESSION] Session manager created');
