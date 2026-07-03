/**
 * DockVault Theme Switcher
 * Handles light/dark theme toggling with smooth transitions and persistence
 */

const ACCENTS = ['teal', 'indigo', 'violet', 'rose', 'orange', 'sky'];
const BACKGROUNDS = ['slate', 'graphite', 'navy', 'warm', 'forest', 'plum'];
// UI skins: 'v1' = Classic (redesign.css), 'v2' = Console (ui-v2.css).
// The stylesheet swap itself happens pre-paint in ui-boot.js; ThemeManager
// only owns persistence + the profile-dropdown switcher. Remove this axis
// (and the switcher) when v1 is retired.
const UIS = ['v1', 'v2'];

class ThemeManager {
    constructor() {
        this.currentTheme = this.getStoredTheme() || this.getSystemTheme();
        this.currentAccent = this.getStoredAccent();
        this.currentBackground = this.getStoredBackground();
        this.currentUi = this.getStoredUi();
        this.init();
    }

    init() {
        // Apply theme + accent + background immediately to prevent flash
        this.applyTheme(this.currentTheme);
        this.applyAccent(this.currentAccent);
        this.applyBackground(this.currentBackground);

        // Listen for system theme changes
        this.watchSystemTheme();

        // Setup theme toggle button + pickers
        this.setupToggleButton();
        this.setupAccentPicker();
        this.setupBackgroundPicker();
        this.setupUiPicker();
    }

    getSystemTheme() {
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return 'dark';
        }
        return 'light';
    }

    // All storage access is guarded: with storage blocked (e.g. private
    // browsing) the pickers still initialise on defaults instead of the
    // constructor throwing before init() runs.
    getStoredTheme() {
        try { return localStorage.getItem('theme'); } catch (_) { return null; }
    }

    setStoredTheme(theme) {
        try { localStorage.setItem('theme', theme); } catch (_) {}
    }

    applyTheme(theme) {
        this.currentTheme = theme;
        document.documentElement.setAttribute('data-theme', theme);
        this.updateToggleButton();
        this.setStoredTheme(theme);
    }

    toggle() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    }

    // -- Accent color -----------------------------------------------------
    getStoredAccent() {
        let stored = null;
        try { stored = localStorage.getItem('accent'); } catch (_) {}
        return ACCENTS.includes(stored) ? stored : 'teal';
    }

    setStoredAccent(accent) {
        try { localStorage.setItem('accent', accent); } catch (_) {}
    }

    applyAccent(accent) {
        if (!ACCENTS.includes(accent)) accent = 'teal';
        this.currentAccent = accent;
        document.documentElement.setAttribute('data-accent', accent);
        this.setStoredAccent(accent);
        this.updateAccentPicker();
    }

    setupAccentPicker() {
        // Only the profile accent swatches carry data-accent; the group-colour
        // swatches (data-color) are handled in app.js — don't bind those here.
        document.querySelectorAll('.accent-swatch[data-accent]').forEach(swatch => {
            swatch.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const accent = swatch.getAttribute('data-accent');
                if (accent) this.applyAccent(accent);
            });
        });
        this.updateAccentPicker();
    }

    updateAccentPicker() {
        document.querySelectorAll('.accent-swatch[data-accent]').forEach(swatch => {
            const isSel = swatch.getAttribute('data-accent') === this.currentAccent;
            swatch.classList.toggle('selected', isSel);
            if (isSel) {
                swatch.setAttribute('aria-current', 'true');
            } else {
                swatch.removeAttribute('aria-current');
            }
        });
    }

    // -- Background palette ------------------------------------------------
    // Retints the surface ramp via [data-bg] on <html>. 'slate' is the default
    // (no attribute), matching :root. See §18b in redesign.css.
    getStoredBackground() {
        let stored = null;
        try { stored = localStorage.getItem('background'); } catch (_) {}
        return BACKGROUNDS.includes(stored) ? stored : 'slate';
    }

    setStoredBackground(bg) {
        try { localStorage.setItem('background', bg); } catch (_) {}
    }

    applyBackground(bg) {
        if (!BACKGROUNDS.includes(bg)) bg = 'slate';
        this.currentBackground = bg;
        if (bg === 'slate') {
            document.documentElement.removeAttribute('data-bg');
        } else {
            document.documentElement.setAttribute('data-bg', bg);
        }
        this.setStoredBackground(bg);
        this.updateBackgroundPicker();
    }

    setupBackgroundPicker() {
        document.querySelectorAll('.bg-swatch[data-bg]').forEach(swatch => {
            swatch.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const bg = swatch.getAttribute('data-bg');
                if (bg) this.applyBackground(bg);
            });
        });
        this.updateBackgroundPicker();
    }

    updateBackgroundPicker() {
        document.querySelectorAll('.bg-swatch[data-bg]').forEach(swatch => {
            const isSel = swatch.getAttribute('data-bg') === this.currentBackground;
            swatch.classList.toggle('selected', isSel);
            if (isSel) {
                swatch.setAttribute('aria-current', 'true');
            } else {
                swatch.removeAttribute('aria-current');
            }
        });
    }

    // -- UI skin (Classic v1 / Console v2) ----------------------------------
    // The active stylesheet is chosen pre-paint by ui-boot.js; switching here
    // persists the choice and reloads so the boot script re-applies it and
    // skin-specific behaviour (ui-v2.js) re-initialises cleanly. The session
    // token + nav state live in local/sessionStorage, so a reload is lossless.
    getStoredUi() {
        let stored = null;
        try { stored = localStorage.getItem('ui'); } catch (_) {}
        return UIS.includes(stored) ? stored : 'v1';
    }

    setUi(ui) {
        if (!UIS.includes(ui) || ui === this.currentUi) return;
        try { localStorage.setItem('ui', ui); } catch (_) { return; }
        window.location.reload();
    }

    setupUiPicker() {
        document.querySelectorAll('.ui-choice[data-ui-choice]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const ui = btn.getAttribute('data-ui-choice');
                if (ui) this.setUi(ui);
            });
        });
        this.updateUiPicker();
    }

    updateUiPicker() {
        document.querySelectorAll('.ui-choice[data-ui-choice]').forEach(btn => {
            const isSel = btn.getAttribute('data-ui-choice') === this.currentUi;
            btn.classList.toggle('selected', isSel);
            if (isSel) {
                btn.setAttribute('aria-current', 'true');
            } else {
                btn.removeAttribute('aria-current');
            }
        });
    }

    watchSystemTheme() {
        if (!window.matchMedia) return;
        
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        mediaQuery.addEventListener('change', (e) => {
            // Only auto-switch if user hasn't manually set a preference
            if (!this.getStoredTheme()) {
                this.applyTheme(e.matches ? 'dark' : 'light');
            }
        });
    }

    setupToggleButton() {
        // Create theme toggle button if it doesn't exist
        let toggleBtn = document.getElementById('theme-toggle');
        
        if (!toggleBtn) {
            toggleBtn = document.createElement('button');
            toggleBtn.id = 'theme-toggle';
            toggleBtn.className = 'theme-toggle';
            toggleBtn.setAttribute('aria-label', 'Toggle theme');
            toggleBtn.innerHTML = `
                <span class="theme-toggle-slider">
                    <span class="theme-toggle-icon"></span>
                </span>
            `;
            
            // Add to navbar if it exists
            const navbar = document.querySelector('.navbar-menu');
            if (navbar) {
                navbar.appendChild(toggleBtn);
            }
        }

        // Add click handler
        toggleBtn.addEventListener('click', () => {
            this.toggle();
        });

        this.updateToggleButton();
    }

    updateToggleButton() {
        const toggleBtn = document.getElementById('theme-toggle');
        if (!toggleBtn) return;

        const icon = toggleBtn.querySelector('.theme-toggle-icon');
        if (icon) {
            const id = this.currentTheme === 'light' ? '#i-sun' : '#i-moon';
            let use = icon.querySelector('use');
            if (!use) {
                const svgNS = 'http://www.w3.org/2000/svg';
                const svg = document.createElementNS(svgNS, 'svg');
                svg.setAttribute('class', 'icon icon-sm');
                use = document.createElementNS(svgNS, 'use');
                svg.appendChild(use);
                icon.textContent = '';
                icon.appendChild(svg);
            }
            use.setAttribute('href', id);
        }

        if (this.currentTheme === 'dark') {
            toggleBtn.classList.add('active');
        } else {
            toggleBtn.classList.remove('active');
        }
    }

    // Public API
    getCurrentTheme() {
        return this.currentTheme;
    }

    setTheme(theme) {
        if (theme === 'light' || theme === 'dark') {
            this.applyTheme(theme);
        }
    }
}

// Initialize theme manager
const themeManager = new ThemeManager();

// Export for use in other scripts
if (typeof window !== 'undefined') {
    window.themeManager = themeManager;
}
