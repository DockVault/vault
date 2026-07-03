/**
 * DockVault UI skin boot — runs synchronously in <head>, before first paint.
 *
 * Two peer skins share the same base stylesheets (theme/components/utilities):
 *   v1 "Classic"  -> css/redesign.css   (link#skin-v1)
 *   v2 "Console"  -> css/ui-v2.css     (link#skin-v2, ships disabled)
 * The choice is persisted in localStorage key `ui` ('v1' default). This script
 * enables exactly one skin stylesheet and mirrors the choice as `data-ui` on
 * <html> so behavioural scripts (ui-v2.js) and CSS can key off it.
 *
 * ADOPTING v2 / REMOVING v1 later: make ui-v2.css the only skin <link>, delete
 * redesign.css + this file + the Interface switcher in the profile dropdown,
 * and drop the `ui` axis from theme.js. Nothing else references v1.
 */
(function () {
    'use strict';
    var ui = 'v1';
    try {
        if (localStorage.getItem('ui') === 'v2') ui = 'v2';
    } catch (e) { /* storage blocked -> default skin */ }

    var v1 = document.getElementById('skin-v1');
    var v2 = document.getElementById('skin-v2');
    if (!v1 || !v2) return;

    if (ui === 'v2') {
        // Order matters: enable the target before disabling the fallback so
        // there is never a frame with no skin applied.
        v2.disabled = false;
        v1.disabled = true;
        document.documentElement.setAttribute('data-ui', 'v2');
    } else {
        v1.disabled = false;
        v2.disabled = true;
        document.documentElement.removeAttribute('data-ui');
    }
})();
