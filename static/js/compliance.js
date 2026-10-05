/*
 * Compliance access in the web app.
 *
 * The step-ups no switch of the step-up matrix changes (GET /second-factor/actions, "fixed"): listed read-only
 * below the matrix in Settings -> Security, each with what it always asks for. The compliance steps (proposing
 * or approving an auditor grant, requesting, approving or exporting from a case, placing or releasing a legal
 * hold) always ask for the password and an authenticator or recovery code.
 *
 * Builds the page with createElement and textContent only.
 */
(function () {
    'use strict';

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function renderFixedStepUps(fixed) {
        const table = document.getElementById('mfa-actions-table');
        if (!table) return;
        let box = document.getElementById('mfa-fixed-table');
        if (!box) {
            box = el('div');
            box.id = 'mfa-fixed-table';
            table.insertAdjacentElement('afterend', box);
        }
        box.replaceChildren();
        if (!Array.isArray(fixed) || !fixed.length) return;
        box.appendChild(el('p', 'text-tertiary text-sm mt-md mb-xs',
            'Always required: these steps ask for the same thing every time, whatever the switches above say.'));
        fixed.forEach((a) => {
            const row = el('div', 'flex gap-sm items-center mfa-fixed-row');
            row.dataset.fixedKey = a.key || '';
            row.style.padding = '6px 0';
            row.style.borderTop = '1px solid var(--border, #e5e7eb)';
            row.style.flexWrap = 'wrap';
            const name = el('div', 'text-sm', a.name || a.key || '');
            name.style.flex = '1 1 200px';
            const requires = el('div', 'text-sm text-secondary mfa-fixed-requires', a.requires || '');
            requires.style.flex = '1 1 260px';
            row.appendChild(name);
            row.appendChild(requires);
            box.appendChild(row);
        });
    }

    window.renderFixedStepUps = renderFixedStepUps;
})();
