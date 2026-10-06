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

    function sizeText(bytes) {
        if (typeof window.formatBytes === 'function') return window.formatBytes(bytes || 0);
        return String(bytes || 0) + ' B';
    }

    // Settings -> Storage: what legal holds keep after their deletion (GET /storage/stats, kept_for_cases). Those
    // bytes are on the disk but in no vault's size, so the line says so beside the totals.
    function renderKeptForCases(stats) {
        const anchor = document.getElementById('storage-stat-allocated');
        if (!anchor) return;
        let line = document.getElementById('storage-stat-kept');
        const kept = (stats && stats.kept_for_cases) || null;
        if (!kept || !(kept.files || kept.folders)) {
            if (line) line.remove();
            return;
        }
        if (!line) {
            line = el('small', 'text-secondary');
            line.id = 'storage-stat-kept';
            line.style.display = 'block';
            anchor.insertAdjacentElement('afterend', line);
        }
        line.textContent = 'Kept for cases: ' + kept.files + (kept.files === 1 ? ' file, ' : ' files, ')
            + sizeText(kept.bytes) + ' (deleted under a legal hold; on this disk, in no vault\'s size)';
    }

    window.renderKeptForCases = renderKeptForCases;
})();
