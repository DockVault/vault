/**
 * Branding boot — applies effective branding (GET /branding) to the app shell.
 *
 * Loaded synchronously in <head> (after ui-boot.js). It:
 *   1. paints from a localStorage cache immediately (no "flash of default brand" on
 *      repeat visits) — title + :root theme colours + favicon in <head>; header/sidebar
 *      name + logo on DOMContentLoaded (those elements don't exist yet at head time);
 *   2. fetches fresh /branding, re-applies, and re-caches.
 *
 * Branding is data-driven from here so a deployment can override it (BRAND_* env at deploy,
 * or the admin editor at runtime); the static HTML carries the DockVault DEFAULT that this
 * overwrites when an override exists. Hooks in the markup:
 *   [data-brand-name]     -> textContent := app_name
 *   [data-brand-tagline]  -> textContent := app_full_name
 *   [data-brand-template] -> textContent := attr value with {name} -> app_name
 *   [data-brand-logo]     -> src := logo_small (alt := app_name)
 *   #powered-by           -> persistent attribution: [data-powered-by-name] text + link;
 *                            hidden only when powered_by.show is false (a deploy-level flag,
 *                            NOT the tenant editor, so a customizing tenant can't remove it)
 *
 * Security: branding values are admin-editable and could be hostile. Text is set
 * via textContent only (never innerHTML — also hook-enforced). Asset URLs are
 * scheme-sanitised (only a same-origin path or an http(s) URL — javascript:/data: are
 * rejected). Theme colours are accepted only as strict hex.
 */
(function () {
    'use strict';

    var CACHE_KEY = 'dv_branding';

    // Allow only a same-origin path ("/...") or an absolute http(s) URL; reject
    // javascript:, data:, vbscript:, protocol-relative ("//host"), etc.
    // Browsers normalise '\' to '/' and strip \t/\n/\r when parsing URLs, so
    // "/\host" or "/<TAB>/host" would slip past the leading-slash check yet
    // resolve protocol-relative (cross-origin) — reject those chars anywhere.
    function safeUrl(u) {
        if (typeof u !== 'string') return null;
        var s = u.trim();
        if (!s) return null;
        if (/[\\\u0000-\u001F]/.test(s)) return null;
        if (s.charAt(0) === '/' && s.charAt(1) !== '/') return s;   // same-origin path
        if (/^https?:\/\//i.test(s)) return s;                       // absolute http(s)
        return null;
    }

    var HEX = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
    var COLOR_VAR = /^--[a-z-]+-color$/;

    function applyColors(colors) {
        if (!colors || typeof colors !== 'object') return;
        var root = document.documentElement;
        Object.keys(colors).forEach(function (k) {
            var v = colors[k];
            // NOTE: these are the 8 --*-color custom properties from get_theme_css_vars().
            // The v1 "Classic" chrome (redesign.css) uses a separate --brand-* token set
            // with light/dark variants, so we deliberately do NOT override those here
            // (an inline :root value would clobber the dark-mode variant). Mapping brand
            // colours onto the chrome tokens is a larger design-integration task.
            if (COLOR_VAR.test(k) && typeof v === 'string' && HEX.test(v)) {
                root.style.setProperty(k, v);
            }
        });
    }

    // <head>-safe pieces (elements that exist before <body> parses).
    function applyHead(b) {
        if (!b || typeof b !== 'object') return;
        if (b.app_name) {
            document.title = b.app_full_name
                ? (b.app_name + ' - ' + b.app_full_name)
                : b.app_name;
        }
        applyColors(b.colors);
        var favUrl = b.assets && safeUrl(b.assets.favicon);
        if (favUrl) {
            var link = document.querySelector('link[rel="icon"]');
            if (link) link.setAttribute('href', favUrl);
        }
    }

    // <body> pieces (header/sidebar name, tagline, templated copy, logos).
    function applyBody(b) {
        if (!b || typeof b !== 'object') return;
        var name = b.app_name;
        if (name) {
            document.querySelectorAll('[data-brand-name]').forEach(function (el) {
                el.textContent = name;
            });
            document.querySelectorAll('[data-brand-template]').forEach(function (el) {
                var tpl = el.getAttribute('data-brand-template') || '';
                el.textContent = tpl.split('{name}').join(name);
            });
        }
        if (b.app_full_name) {
            document.querySelectorAll('[data-brand-tagline]').forEach(function (el) {
                el.textContent = b.app_full_name;
            });
        }
        var logoUrl = b.assets && (safeUrl(b.assets.logo_small) || safeUrl(b.assets.logo));
        if (logoUrl) {
            document.querySelectorAll('[data-brand-logo]').forEach(function (img) {
                img.setAttribute('src', logoUrl);
                if (name) img.setAttribute('alt', name);
            });
        }
        applyPoweredBy(b);
    }

    // Persistent "powered by" attribution. Visible by default (static HTML); only a
    // deploy-level flag (powered_by.show === false) hides it — the tenant editor can't.
    function applyPoweredBy(b) {
        var el = document.getElementById('powered-by');
        if (!el) return;
        var pb = b && b.powered_by;
        if (pb && pb.show === false) {
            el.style.display = 'none';
            return;
        }
        el.style.display = '';
        if (pb && pb.name) {
            el.querySelectorAll('[data-powered-by-name]').forEach(function (n) {
                n.textContent = pb.name;  // textContent only -> XSS-safe
            });
        }
        var link = el.querySelector('[data-powered-by-link]');
        var url = pb && safeUrl(pb.url);
        if (link && url) link.setAttribute('href', url);
    }

    function apply(b) {
        applyHead(b);
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function () { applyBody(b); });
        } else {
            applyBody(b);
        }
    }

    // 1. paint from cache synchronously (flash-free on repeat visits)
    try {
        var cached = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
        if (cached) apply(cached);
    } catch (e) { /* no/blocked/corrupt cache -> fall through to fetch */ }

    // 2. fetch fresh, apply + cache
    fetch('/branding', { headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (b) {
            if (!b) return;
            apply(b);
            try { localStorage.setItem(CACHE_KEY, JSON.stringify(b)); } catch (e) { /* ignore */ }
        })
        .catch(function () { /* offline / error -> keep static + cached defaults */ });
})();
