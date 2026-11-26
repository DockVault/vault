/*
 * Settings in the side menu. While the Settings section is open, the rail (the drawer on a phone) shows the
 * Settings pages instead of the app's sections: a head row with Back (to the section open before Settings),
 * the title and the Advanced switch (static/js/settings-levels.js), then the pages under their group headings.
 *
 * The menu is drawn from the page's own list, #settings-section .settings-nav (static/index.html), which stays
 * in the page, hidden. Each item clicks its page's button there, so every page keeps its data-tab, and the
 * switching code (setupSettingsTabs in app.js) and the search are the same as before. The open page, and a
 * group the page hides, follow that list: it is watched, and the menu is drawn again only when its pages or
 * groups change.
 *
 * The pages have no icons, so a rail saved collapsed opens in full while Settings is open; leaving Settings
 * puts back what is saved ('sidebarCollapsed', app.js). Settings never writes that value: on a wide screen
 * the top-bar menu button is disabled while Settings is open (app.js).
 *
 * Every way into Settings (its sidebar item, a link or a restored view, a dashboard action) ends with the
 * Settings section marked active, so the sections are watched rather than each way in.
 *
 * Builds everything with createElement, createElementNS and textContent.
 */
(function () {
    'use strict';

    const SVG = 'http://www.w3.org/2000/svg';
    const PHONE = window.matchMedia('(max-width: 860px)');
    const S = { nav: null, list: null, sign: '', on: false, before: 'dashboard' };

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function icon(name) {
        const svg = document.createElementNS(SVG, 'svg');
        svg.setAttribute('class', 'icon');
        svg.setAttribute('aria-hidden', 'true');
        const use = document.createElementNS(SVG, 'use');
        use.setAttribute('href', `#i-${name}`);
        svg.appendChild(use);
        return svg;
    }

    // A value inside a selector: the page names are plain words, but a selector never trusts that.
    function q(value) { return window.CSS && CSS.escape ? CSS.escape(String(value)) : String(value); }

    function rail() { return document.getElementById('sidebar'); }
    function section() { return document.getElementById('settings-section'); }
    function source() {
        const root = section();
        return root ? root.querySelector(':scope > .settings-nav') : null;
    }

    function savedCollapsed() {
        try { return localStorage.getItem('sidebarCollapsed') === 'true'; } catch (_) { return false; }
    }

    // ------------------------------------------------------------------ the menu

    function groups() {
        const src = source();
        if (!src) return [];
        return Array.from(src.querySelectorAll('.settings-nav-group')).map((group) => {
            const title = group.querySelector('.settings-nav-title');
            return {
                name: group.dataset.settingsGroup || '',
                title: title ? title.textContent.trim() : '',
                hidden: group.hidden,
                pages: Array.from(group.querySelectorAll('.tab-btn[data-tab]')).map((btn) => ({
                    tab: btn.dataset.tab, text: btn.textContent.trim(), btn,
                })),
            };
        });
    }

    function pick(tab) {
        const src = source();
        const btn = src && src.querySelector(`.tab-btn[data-tab="${q(tab)}"]`);
        if (btn) btn.click();
        // On a phone the drawer closes once a page is chosen, as it does for a section.
        if (PHONE.matches && typeof window.closeNavDrawer === 'function') window.closeNavDrawer();
    }

    function draw(list) {
        const active = document.activeElement;
        const focused = active && S.list.contains(active) ? active.dataset.tab : null;
        S.list.replaceChildren(...list.map((group, i) => {
            const box = el('div', 'sidebar-settings-group');
            box.dataset.settingsGroup = group.name;
            box.setAttribute('role', 'group');
            const label = el('div', 'nav-group-label', group.title);
            label.id = `sidebar-settings-group-${i}`;
            box.setAttribute('aria-labelledby', label.id);
            box.appendChild(label);
            group.pages.forEach((page) => {
                const item = el('button', 'sidebar-item sidebar-settings-item');
                item.type = 'button';
                item.dataset.tab = page.tab;
                item.appendChild(el('span', 'sidebar-text', page.text));
                item.addEventListener('click', () => pick(page.tab));
                box.appendChild(item);
            });
            box.hidden = group.hidden;
            return box;
        }));
        if (focused) {
            const again = S.list.querySelector(`.sidebar-settings-item[data-tab="${q(focused)}"]`);
            if (again) again.focus({ preventScroll: true });
        }
    }

    // Draw the menu again only when the list's pages or groups changed; mark the open page every time (only
    // while Settings is open, so the rail never holds two active items).
    function render() {
        if (!S.list) return;
        const list = groups();
        const sign = JSON.stringify(list.map((g) => [g.name, g.title, g.hidden, g.pages.map((p) => [p.tab, p.text])]));
        if (sign !== S.sign) {
            S.sign = sign;
            draw(list);
        }
        list.forEach((group) => group.pages.forEach((page) => {
            const item = S.list.querySelector(`.sidebar-settings-item[data-tab="${q(page.tab)}"]`);
            if (!item) return;
            const active = S.on && page.btn.classList.contains('active');
            if (item.classList.contains('active') !== active) item.classList.toggle('active', active);
            if (active && item.getAttribute('aria-current') !== 'page') item.setAttribute('aria-current', 'page');
            else if (!active && item.hasAttribute('aria-current')) item.removeAttribute('aria-current');
        }));
    }

    function build() {
        const sidebar = rail();
        const src = source();
        if (!sidebar || !src || S.nav) return false;
        const nav = el('nav', 'sidebar-nav sidebar-settings-nav');
        nav.id = 'sidebar-settings-nav';
        nav.setAttribute('aria-label', 'Settings');
        nav.hidden = true;
        const head = el('div', 'sidebar-settings-head');
        const back = el('button', 'sidebar-back');
        back.type = 'button';
        back.id = 'sidebar-settings-back';
        back.setAttribute('aria-label', 'Back');
        back.title = 'Back';
        back.appendChild(icon('chevron-left'));
        back.addEventListener('click', leave);
        head.append(back, el('span', 'sidebar-settings-title', 'Settings'));
        if (window.SettingsLevels && typeof SettingsLevels.switchControl === 'function') {
            head.appendChild(SettingsLevels.switchControl());
        }
        S.list = el('div', 'sidebar-settings-list');
        nav.append(head, S.list);
        sidebar.appendChild(nav);
        S.nav = nav;
        // The page's own list is hidden now that the rail carries it (components.css).
        document.body.classList.add('has-settings-menu');
        render();
        new MutationObserver(render).observe(src, {
            childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['class', 'hidden'],
        });
        return true;
    }

    // ------------------------------------------------------------------ entering and leaving

    // Focus follows the menu only when it was in the rail already. A reload that restores Settings leaves
    // focus on the page (the body), where it stays.
    function focusInRail() {
        const active = document.activeElement;
        const sidebar = rail();
        return !!(active && active !== document.body && sidebar && sidebar.contains(active));
    }

    function sync() {
        const root = section();
        if (!root || !S.nav) return;
        const on = root.classList.contains('active');
        if (on === S.on) {
            // Settings opened again while it was open: a section click cleared every rail item's mark, these
            // too, so the open page is marked again.
            if (on) render();
            return;
        }
        S.on = on;
        const moveFocus = focusInRail() && !PHONE.matches;
        const sidebar = rail();
        S.nav.hidden = !on;
        document.body.classList.toggle('settings-mode', on);
        render();
        if (sidebar) {
            if (on) sidebar.classList.remove('collapsed');
            else sidebar.classList.toggle('collapsed', savedCollapsed());
        }
        if (!moveFocus) return;
        // Focus follows the menu: to the open page on the way in, to the section returned to on the way out.
        const target = on
            ? S.nav.querySelector('.sidebar-settings-item.active') || S.nav.querySelector('.sidebar-back')
            : sidebar && sidebar.querySelector('.sidebar-nav:not(.sidebar-settings-nav) .sidebar-item.active');
        if (target) target.focus({ preventScroll: true });
    }

    // Back: the section open before Settings, opened as its sidebar item would open it.
    function leave() {
        const name = S.before || 'dashboard';
        if (typeof window.navigateToSection === 'function') {
            window.navigateToSection(name);
            return;
        }
        const item = document.querySelector(`.sidebar-item[data-section="${q(name)}"]`);
        if (item) item.click();
    }

    // Remember the last section other than Settings that has an item in the sidebar. A vault's own page has
    // none: Back then returns to the list of vaults it was opened from.
    function watchSections() {
        const sections = Array.from(document.querySelectorAll('.content-section[id$="-section"]'));
        const seen = () => {
            sections.forEach((s) => {
                if (s.id === 'settings-section' || !s.classList.contains('active')) return;
                const name = s.id.slice(0, -'-section'.length);
                if (document.querySelector(`.sidebar-item[data-section="${q(name)}"]`)) S.before = name;
            });
            sync();
        };
        const watcher = new MutationObserver(seen);
        sections.forEach((s) => watcher.observe(s, { attributes: true, attributeFilter: ['class'] }));
        seen();
    }

    function start() {
        if (build()) watchSections();
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();

    window.SettingsMenu = { render, sync, leave };
})();
