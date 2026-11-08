// How the page's dialogs (.modal elements) open and close, the same way for all of them.
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
        // Scrolled to the top: the scroller is the dialog's body where it has one, else its content box.
        dialog.querySelectorAll('.modal-content, .modal-body').forEach((box) => { box.scrollTop = 0; });
    }

    function open() {
        return Array.from(document.querySelectorAll('.modal.active')).filter(isOpen);
    }

    // The top dialog: the one opened last (a dialog never seen opening, such as one built already
    // open by a script, counts as later than any seen one, in page order).
    function top() {
        const all = open();
        if (!all.length) return null;
        let best = null;
        let bestKey = -1;
        all.forEach((d, index) => {
            const key = openedAt.has(d) ? openedAt.get(d) : Number.MAX_SAFE_INTEGER - all.length + index;
            if (key >= bestKey) { bestKey = key; best = d; }
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
        if (e.key !== 'Escape' || e.defaultPrevented) return;
        if (!top()) return;
        if (closeTop()) e.preventDefault();
    });

    // Watch every dialog for opening: those on the page now, and any added later (built by a script).
    const seen = new WeakMap();  // dialog -> whether it was open at the last look
    function look(dialog) {
        const now = isOpen(dialog);
        if (now && !seen.get(dialog)) opened(dialog);
        seen.set(dialog, now);
    }
    function start() {
        document.querySelectorAll('.modal').forEach(look);
        new MutationObserver((records) => {
            records.forEach((r) => {
                if (r.type === 'attributes' && isDialog(r.target)) look(r.target);
                if (r.type === 'childList') {
                    r.addedNodes.forEach((n) => {
                        if (isDialog(n)) look(n);
                        if (n.querySelectorAll) n.querySelectorAll('.modal').forEach(look);
                    });
                }
            });
        }).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'hidden'] });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();

    window.Dialogs = { top, closeTop, backdropClick, backdropRelease, hasEdits };
})();
