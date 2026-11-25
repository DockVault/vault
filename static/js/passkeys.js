// Passkeys in the browser: the two WebAuthn ceremonies the vault's passkey routes ask for, with no library.
//
// The server sends the options as WebAuthn Level 3 JSON (under "publicKey") and takes the credential back as Level 3
// JSON. Where the browser has PublicKeyCredential.parseCreationOptionsFromJSON / parseRequestOptionsFromJSON and
// credential.toJSON(), they are used; otherwise the binary fields are converted here (base64url to ArrayBuffer and
// back). Nothing here shows anything or calls the server: the callers in app.js own the page and the requests.
(function () {
    'use strict';

    // Whether this browser and page can use passkeys at all: the API, and a secure context (https, or localhost).
    function supported() {
        return !!(window.PublicKeyCredential && window.isSecureContext && navigator.credentials
            && typeof navigator.credentials.get === 'function');
    }

    // Whether the browser can offer the person's passkeys on the username field (conditional mediation).
    async function conditionalAvailable() {
        if (!supported() || typeof window.PublicKeyCredential.isConditionalMediationAvailable !== 'function') return false;
        try { return !!(await window.PublicKeyCredential.isConditionalMediationAvailable()); } catch (_) { return false; }
    }

    function toBuffer(value) {
        const b64 = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
        const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
        const raw = atob(padded);
        const out = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
        return out.buffer;
    }

    function toBase64url(buffer) {
        if (buffer == null) return null;
        const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer)
            : new Uint8Array(buffer.buffer, buffer.byteOffset || 0, buffer.byteLength);
        let raw = '';
        for (let i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
        return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function withIds(list) {
        return (list || []).map((d) => Object.assign({}, d, { id: toBuffer(d.id) }));
    }

    function creationOptions(json) {
        const P = window.PublicKeyCredential;
        if (P && typeof P.parseCreationOptionsFromJSON === 'function') return P.parseCreationOptionsFromJSON(json);
        return Object.assign({}, json, {
            challenge: toBuffer(json.challenge),
            user: Object.assign({}, json.user, { id: toBuffer(json.user.id) }),
            excludeCredentials: withIds(json.excludeCredentials),
        });
    }

    function requestOptions(json) {
        const P = window.PublicKeyCredential;
        if (P && typeof P.parseRequestOptionsFromJSON === 'function') return P.parseRequestOptionsFromJSON(json);
        return Object.assign({}, json, { challenge: toBuffer(json.challenge), allowCredentials: withIds(json.allowCredentials) });
    }

    // The credential as the Level 3 JSON the server reads.
    function credentialJSON(cred) {
        if (typeof cred.toJSON === 'function') {
            try { return cred.toJSON(); } catch (_) { /* converted below */ }
        }
        const r = cred.response;
        const out = {
            id: cred.id, rawId: toBase64url(cred.rawId), type: cred.type,
            authenticatorAttachment: cred.authenticatorAttachment || null,
            clientExtensionResults: typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {},
            response: { clientDataJSON: toBase64url(r.clientDataJSON) },
        };
        if (r.attestationObject) {
            out.response.attestationObject = toBase64url(r.attestationObject);
            out.response.transports = typeof r.getTransports === 'function' ? r.getTransports() : [];
        } else {
            out.response.authenticatorData = toBase64url(r.authenticatorData);
            out.response.signature = toBase64url(r.signature);
            out.response.userHandle = r.userHandle ? toBase64url(r.userHandle) : null;
        }
        return out;
    }

    // Make a passkey from the server's registration options ({publicKey: ...}); answers the credential JSON.
    async function create(options) {
        const cred = await navigator.credentials.create({ publicKey: creationOptions(options.publicKey) });
        if (!cred) throw new DOMException('No passkey was made.', 'NotAllowedError');
        return credentialJSON(cred);
    }

    // Prove a passkey for the server's request options ({publicKey: ...}). conditional: offer the person's passkeys on
    // the username field (the browser waits until one is chosen; abort it with signal). Answers the credential JSON.
    async function get(options, { conditional = false, signal } = {}) {
        const request = { publicKey: requestOptions(options.publicKey) };
        if (conditional) request.mediation = 'conditional';
        if (signal) request.signal = signal;
        const cred = await navigator.credentials.get(request);
        if (!cred) throw new DOMException('No passkey was chosen.', 'NotAllowedError');
        return credentialJSON(cred);
    }

    // A browser that refuses passkeys on a page whose certificate it does not trust (Chrome and Edge, on a self-signed
    // certificate that was clicked through) says so as a NotAllowedError that names the certificate.
    function certificateRefused(error) {
        return !!error && error.name === 'NotAllowedError' && /certificate/i.test(error.message || '');
    }

    // Whether an error is the person cancelling (or the browser's own timeout, which it reports the same way) or a
    // ceremony aborted by the page: nothing to show. A refusal for the certificate is not one: it says why.
    function cancelled(error) {
        if (certificateRefused(error)) return false;
        return !!error && (error.name === 'NotAllowedError' || error.name === 'AbortError');
    }

    // The sentence for a ceremony that failed for another reason.
    function failureText(error) {
        if (certificateRefused(error)) {
            return 'Passkeys need this vault\'s certificate to be trusted by this browser. Ask whoever runs the vault '
                + 'for a certificate your browser trusts.';
        }
        if (error && error.name === 'InvalidStateError') return 'This device already holds a passkey for your account.';
        if (error && error.name === 'SecurityError') return 'Passkeys need this vault opened at its own address over https.';
        if (error && error.name === 'NotSupportedError') return 'This device cannot make a passkey the vault accepts.';
        return 'The passkey did not work. Try again.';
    }

    window.Passkeys = { supported, conditionalAvailable, create, get, cancelled, failureText,
        _codec: { toBuffer, toBase64url, credentialJSON } };
})();
