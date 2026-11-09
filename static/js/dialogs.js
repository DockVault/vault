// How the page's dialogs (.modal elements) open and close, the same way for all of them.
//
// Every dialog is a dialog to assistive technology: role="dialog", aria-modal, and a name taken from its
// heading. Focus moves into a dialog when it opens (the first field, else the first button, else the
// dialog itself) and back to the control that opened it when it closes; Tab and Shift+Tab stay inside the
// top dialog while one is open.
//
// A dialog opens scrolled to the top. Escape closes the top dialog only. A press on a dialog's backdrop
// that is released on the same backdrop closes that dialog only, and only when it is the top one and
// its form holds nothing typed since it opened; a press that began inside the dialog (a text selection
// dragged out of a field) closes nothing. A confirm or prompt closed either way is answered as cancelled,
// so whoever asked it gets its answer. A dialog closed while it is the only one open closes as it always
// did (closeModal: the preview's decrypted bytes are freed, credential fields are emptied, a pending
// step-up is cancelled); a dialog closed while another stands under it leaves that one standing.
//
// The dialogs are found by class and watched for their 'active' class, so one added later, or built by a
// script, behaves the same without registering. Nothing here reads a dialog's text.
(function () {
    'use strict';

    const openedAt = new WeakMap();   // dialog -> the order it opened in (a counter)
    const snapshots = new WeakMap();  // dialog -> its fields' values when it opened
    const openers = new WeakMap();    // dialog -> the element that had focus when it opened
    let labelCounter = 0;

    const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), '
        + 'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

    function visible(el) {
        return !!(el && el.offsetParent !== null || (el && getComputedStyle(el).position === 'fixed' && getComputedStyle(el).display !== 'none'));
    }

    function focusables(dialog) {
        return Array.from(dialog.querySelectorAll(FOCUSABLE)).filter((el) => visible(el) && !el.closest('[hidden]'));
    }

    // The dialog's name for assistive technology: its heading, given an id when it has none.
    function label(dialog) {
        if (!dialog.getAttribute('role')) dialog.setAttribute('role', 'dialog');
        if (!dialog.getAttribute('aria-modal')) dialog.setAttribute('aria-modal', 'true');
        if (dialog.getAttribute('aria-labelledby') || dialog.getAttribute('aria-label')) return;
        const heading = dialog.querySelector('.modal-header h1, .modal-header h2, .modal-header h3, h1, h2, h3');
        if (heading) {
            if (!heading.id) heading.id = (dialog.id || 'dialog') + '-title-' + (++labelCounter);
            dialog.setAttribute('aria-labelledby', heading.id);
        } else {
            dialog.setAttribute('aria-label', 'Dialog');
        }
    }

    function focusInto(dialog) {
        const list = focusables(dialog);
        const preferred = dialog.querySelector('[autofocus]')
            || list.find((el) => /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName))
            || list.find((el) => !el.classList.contains('modal-close') && !el.classList.contains('close-modal-btn'))
            || list[0];
        if (preferred) { preferred.focus({ preventScroll: true }); return; }
        const box = dialog.querySelector('.modal-content') || dialog;
        if (!box.hasAttribute('tabindex')) box.setAttribute('tabindex', '-1');
        box.focus({ preventScroll: true });
    }

    function focusBack(dialog) {
        const opener = openers.get(dialog);
        openers.delete(dialog);
        if (!opener || !document.contains(opener) || !visible(opener)) return;
        if (opener.closest('.modal') && !isOpen(opener.closest('.modal'))) return;
        try { opener.focus({ preventScroll: true }); } catch (_) {}
    }
    let counter = 0;
    let pressedOn = null;             // the dialog whose backdrop the last mouse press began on

    function isDialog(el) {
        return !!(el && el.classList && el.classList.contains('modal'));
    }

    function isOpen(el) {
        return isDialog(el) && el.classList.contains('active') && !el.hidden;
    }

    function fields(dialog) {
        return Array.from(dialog.querySelectorAll('input, textarea, select'))
            .filter((el) => el.type !== 'hidden' && el.type !== 'file' && el.type !== 'button' && el.type !== 'submit');
    }

    function valueOf(el) {
        if (el.type === 'checkbox' || el.type === 'radio') return el.checked ? '1' : '0';
        return String(el.value == null ? '' : el.value);
    }

    function snapshot(dialog) {
        const taken = new Map();
        fields(dialog).forEach((el) => taken.set(el, valueOf(el)));
        snapshots.set(dialog, taken);
    }

    // Whether anything was typed or chosen in the dialog since it opened.
    function hasEdits(dialog) {
        const taken = snapshots.get(dialog);
        if (!taken) return false;
        return fields(dialog).some((el) => {
            const was = taken.get(el);
            return was !== undefined && was !== valueOf(el);
        });
    }

    function opened(dialog) {
        openedAt.set(dialog, ++counter);
        snapshot(dialog);
        label(dialog);
        // Scrolled to the top: the scroller is the dialog's body where it has one, else its content box.
        dialog.querySelectorAll('.modal-content, .modal-body').forEach((box) => { box.scrollTop = 0; });
        // Focus: remembered from where it was, moved in. A dialog that opens its own field (the shared
        // prompt focuses its input a moment later) keeps that; this only fills in when nothing did.
        const active = document.activeElement;
        if (active && active !== document.body && !dialog.contains(active)) openers.set(dialog, active);
        if (!dialog.contains(document.activeElement)) {
            // A dialog that must not take a choice by accident (data-no-autofocus) gets focus on its box,
            // not on a button: Tab still stays inside it, Enter and Space choose nothing.
            if (dialog.hasAttribute('data-no-autofocus')) {
                const box = dialog.querySelector('.modal-content') || dialog;
                if (!box.hasAttribute('tabindex')) box.setAttribute('tabindex', '-1');
                box.focus({ preventScroll: true });
            } else focusInto(dialog);
        }
    }

    function closed(dialog) {
        focusBack(dialog);
    }

    // Tab and Shift+Tab stay inside the top dialog.
    function trapTab(e) {
        if (e.key !== 'Tab') return;
        const dialog = top();
        if (!dialog) return;
        const list = focusables(dialog);
        if (!list.length) { e.preventDefault(); return; }
        const first = list[0];
        const last = list[list.length - 1];
        const inside = dialog.contains(document.activeElement);
        if (!inside) { e.preventDefault(); (e.shiftKey ? last : first).focus(); return; }
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }

    function open() {
        return Array.from(document.querySelectorAll('.modal.active')).filter(isOpen);
    }

    // The top dialog: the one painted over the others (the highest z-index), and among those the one
    // opened last (a dialog never seen opening, such as one built already open by a script, counts as
    // later than any seen one, in page order). Paint order and this order agree, so a dialog raised above
    // the rest (the session warning, the step-up) is also the one Escape and the Tab trap act on.
    function layerOf(d) {
        const z = parseInt(window.getComputedStyle(d).zIndex, 10);
        return Number.isFinite(z) ? z : 0;
    }

    function top() {
        const all = open();
        if (!all.length) return null;
        let best = null;
        let bestLayer = -Infinity;
        let bestKey = -1;
        all.forEach((d, index) => {
            const layer = layerOf(d);
            const key = openedAt.has(d) ? openedAt.get(d) : Number.MAX_SAFE_INTEGER - all.length + index;
            if (layer > bestLayer || (layer === bestLayer && key >= bestKey)) { bestLayer = layer; bestKey = key; best = d; }
        });
        return best;
    }

    // Close the top dialog. One dialog open: the page's own closeModal, with everything it does.
    // Several: only the top one, with what its own kind needs.
    function closeTop() {
        const dialog = top();
        if (!dialog) return false;
        const others = open().filter((d) => d !== dialog);
        if (dialog.id === 'confirm-modal' && typeof settleConfirmModal === 'function') {
            // The confirm or prompt is answered as cancelled; its own cleanup closes it.
            settleConfirmModal();
            if (dialog.classList.contains('active')) dialog.classList.remove('active');
            return true;
        }
        if (!others.length || dialog.id === 'stepup-modal') {
            if (typeof closeModal === 'function') closeModal();
            else dialog.classList.remove('active');
            return true;
        }
        dialog.classList.remove('active');
        if (dialog.id === 'file-preview-modal' && typeof closeFilePreview === 'function') closeFilePreview();
        if (typeof clearCredentialInputsOnClose === 'function') clearCredentialInputsOnClose();
        return true;
    }

    // Whether a click on `dialog`'s backdrop should close it: the press began there too, it is the
    // top dialog, and nothing was typed in it since it opened.
    function backdropRelease(event, dialog) {
        if (!event || event.target !== dialog) return false;
        if (pressedOn !== dialog) return false;
        if (top() !== dialog) return false;
        return !hasEdits(dialog);
    }

    function backdropClick(event) {
        const dialog = event && event.target;
        if (!isDialog(dialog) || !backdropRelease(event, dialog)) return false;
        return closeTop();
    }

    document.addEventListener('mousedown', (e) => { pressedOn = isDialog(e.target) ? e.target : null; }, true);
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Tab') { trapTab(e); return; }
        if (e.key !== 'Escape' || e.defaultPrevented) return;
        if (!top()) return;
        if (closeTop()) e.preventDefault();
    });

    // Watch every dialog for opening: those on the page now, and any added later (built by a script).
    const seen = new WeakMap();  // dialog -> whether it was open at the last look
    function look(dialog) {
        const now = isOpen(dialog);
        if (now && !seen.get(dialog)) opened(dialog);
        else if (!now && seen.get(dialog)) closed(dialog);
        seen.set(dialog, now);
    }
    function start() {
        // Every dialog on the page is named before any of them opens.
        document.querySelectorAll('.modal').forEach(label);
        document.querySelectorAll('.modal').forEach(look);
        new MutationObserver((records) => {
            records.forEach((r) => {
                if (r.type === 'attributes' && isDialog(r.target)) look(r.target);
                if (r.type === 'childList') {
                    r.addedNodes.forEach((n) => {
                        if (isDialog(n)) { label(n); look(n); }
                        if (n.querySelectorAll) n.querySelectorAll('.modal').forEach((d) => { label(d); look(d); });
                    });
                }
            });
        }).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'hidden'] });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();

    window.Dialogs = { top, closeTop, backdropClick, backdropRelease, hasEdits, focusables, label };
})();
