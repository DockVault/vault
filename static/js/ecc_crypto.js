/**
 * ECC Zero-Trust Crypto Library
 * 
 * Client-side cryptographic operations for Zero-Trust vault encryption.
 * Uses Web Crypto API for ECC P-384 (SECP384R1) operations.
 * 
 * Features:
 * - ECC keypair generation (P-384)
 * - ECDH key agreement
 * - AES-GCM encryption/decryption
 * - Vault DEK wrapping/unwrapping
 * - Password-based private key protection
 * 
 * @author DockVault Team
 * @version 1.0.0
 * @date October 13, 2025
 */

/**
 * Stable failure codes. Frozen by docs/design/vault-client-crypto-errors-v1.md -- change that
 * document first. Callers branch on these; they never branch on a message string, because a
 * message is prose and prose gets reworded.
 *
 * Two failures share a code only when no user could act differently on them. That is why a
 * wrong passphrase and tampered ciphertext share AUTH_FAILED -- AES-GCM fails identically for
 * both, so the distinction does not exist to report -- while authenticating vault-key-encrypted
 * CONTENT is separate, because by then the passphrase has already succeeded and the user typed
 * nothing.
 */
const CRYPTO_ERROR_CODES = Object.freeze({
    CRYPTO_UNAVAILABLE: 'CRYPTO_UNAVAILABLE',
    ENVELOPE_INVALID: 'ENVELOPE_INVALID',
    ENVELOPE_UNSUPPORTED: 'ENVELOPE_UNSUPPORTED',
    WORK_FACTOR_REJECTED: 'WORK_FACTOR_REJECTED',
    AUTH_FAILED: 'AUTH_FAILED',
    CONTENT_AUTH_FAILED: 'CONTENT_AUTH_FAILED',
    KEY_UNUSABLE: 'KEY_UNUSABLE',
    KEY_MISMATCH: 'KEY_MISMATCH',
    WRAP_FAILED: 'WRAP_FAILED',
    RECOVERY_KIT_INVALID: 'RECOVERY_KIT_INVALID',
    RECOVERY_KIT_UNSUPPORTED: 'RECOVERY_KIT_UNSUPPORTED',
    INVALID_INPUT: 'INVALID_INPUT',
    CRYPTO_OPERATION_FAILED: 'CRYPTO_OPERATION_FAILED',
});

/**
 * A failure with a code a caller can branch on.
 *
 * `message` is deliberately NOT a sentence. If one of these ever reaches a user it must read as
 * a bug, not as plausible advice -- the whole point of the contract is that wording is chosen by
 * the flow that knows the context, never by the layer that detected the failure.
 *
 * `cause` keeps the original platform exception for diagnostics. It is retained on the object and
 * rendered only under the module's debug flag; see the diagnostics section of the design.
 */
class CryptoError extends Error {
    constructor(code, operation, cause) {
        super(`CryptoError(${code}@${operation})`);
        this.name = 'CryptoError';
        this.code = code;
        this.operation = operation;
        if (cause !== undefined) this.cause = cause;
        // Callers test this, not `instanceof`: the module is a classic script in the browser and
        // a CommonJS require in the test harnesses, and a prototype identity does not survive
        // both. A plain own property does.
        this.isCryptoError = true;
    }
}

/**
 * Pass a coded failure through unchanged; give anything else the caller's default code.
 *
 * Transport failures pass through too, and that is not a convenience: a crypto code must never be
 * derived from a server response. The decompression endpoint is authenticated and rate limited,
 * and a method with its own catch would otherwise convert its 401/403/429 into a crypto failure
 * before the operation boundary could apply the exclusion. Every catch in this module funnels
 * through here, so this is the one place the rule can be stated once.
 */
function _coerceCryptoError(err, code, operation) {
    if (err && err.isCryptoError === true) return err;
    if (err && err.isTransportError === true) return err;
    return new CryptoError(code, operation, err);
}

class ECCCryptoLibrary {
    constructor() {
        // ECC curve parameters (P-384 / SECP384R1)
        this.CURVE = 'P-384';
        this.KEY_USAGES_PRIVATE = ['deriveKey', 'deriveBits'];
        this.KEY_USAGES_PUBLIC = [];
        
        // AES-GCM parameters
        this.AES_ALGORITHM = 'AES-GCM';
        this.AES_KEY_LENGTH = 256; // bits
        this.AES_IV_LENGTH = 12; // bytes
        this.AES_TAG_LENGTH = 128; // bits
        
        // PBKDF2 parameters for password protection
        this.PBKDF2_ITERATIONS = 600000; // OWASP 2025 recommendation
        this.PBKDF2_HASH = 'SHA-256';
        this.PBKDF2_SALT_LENGTH = 32; // bytes
        
        // Key wrapping
        this.HKDF_INFO = new TextEncoder().encode('vault-key-wrapping');

        // --- Versioned private-key envelope. The v1 grammar, its bounds and its authenticated
        // transcript are frozen by docs/design/vault-private-key-envelope-v1.md. Change that
        // document first; these constants only mirror it.
        this.PRIV_ENVELOPE_VERSION = 1;
        this.PRIV_ENVELOPE_KDF = 'PBKDF2-SHA256';
        this.PRIV_ENVELOPE_CIPHER = 'AES-256-GCM';
        this.PRIV_ENVELOPE_AAD_LABEL = 'dockvault-private-key-envelope-v1';
        // Denial-of-service ceiling, applied to BOTH formats because any envelope may arrive from
        // an untrusted file. There is deliberately NO policy floor: a read-side floor protects
        // nothing (a forged envelope cannot authenticate at any work factor) while rejecting a
        // genuine one is unrecoverable — registration refuses a second keypair, and removing the
        // first would orphan every vault wrap.
        this.PRIV_ENVELOPE_MAX_ITER = 10000000;
        this.PRIV_ENVELOPE_MAX_SERIALIZED = 16384;
        this.PRIV_ENVELOPE_MAX_CT = 8192;
        this.PRIV_ENVELOPE_MIN_CT = 17;   // one plaintext byte plus the 16-byte tag
        this.RECOVERY_KIT_TYPE = 'dockvault-zk-recovery-key';
        this.RECOVERY_KIT_MAX_FILE = 65536;
        this.RECOVERY_KIT_MAX_FIELD = 4096;
        // The v1 WRITER is off by default; readers accept v1 regardless, which is what makes a
        // readers-first rollout possible. Enabling the writer is a forward-only decision for a
        // deployment: once a v1 envelope exists, an image whose reader predates v1 cannot read it
        // and there is no self-service recovery.
        this.PRIV_ENVELOPE_WRITE_V1 = false;

        // Raw platform exceptions are diagnostics, not user-facing detail. Off in production;
        // a source constant rather than anything a deployment can flip at runtime, so turning
        // verbose diagnostics on is a reviewable change. A test pins this false.
        this.DEBUG = false;
    }

    /**
     * The WebCrypto entry point every operation goes through.
     *
     * Checking once, here, is what makes CRYPTO_UNAVAILABLE a real code rather than an aspiration:
     * without it an insecure origin or an old browser surfaces as a TypeError on `undefined` from
     * whichever line happened to touch it first, and an availability problem gets reported as
     * whatever that operation's failure normally means -- for the decrypt paths, as a wrong
     * passphrase.
     * @private
     */
    _subtle() {
        const c = (typeof window !== 'undefined' && window.crypto) || null;
        if (!c || !c.subtle) {
            throw new CryptoError(CRYPTO_ERROR_CODES.CRYPTO_UNAVAILABLE, 'subtle');
        }
        return c.subtle;
    }

    /**
     * Random bytes, through the same availability gate.
     * @private
     */
    _randomBytes(n) {
        const c = (typeof window !== 'undefined' && window.crypto) || null;
        if (!c || typeof c.getRandomValues !== 'function') {
            throw new CryptoError(CRYPTO_ERROR_CODES.CRYPTO_UNAVAILABLE, 'getRandomValues');
        }
        return c.getRandomValues(new Uint8Array(n));
    }

    /** Raise a coded failure. @private */
    _fail(code, operation, cause) {
        throw new CryptoError(code, operation, cause);
    }

    /**
     * The only place this module writes a failure to the console, called only from the
     * operation boundary -- so the code it prints is the code the caller actually received.
     *
     * Production output is the operation and the code and nothing else: no platform exception,
     * no envelope bytes, no key material, no passphrase, no ciphertext, no account identifier.
     * The cause is printed only under the debug flag.
     * @private
     */
    _diag(operation, err) {
        const code = (err && err.code) || (err && err.isTransportError ? 'TRANSPORT' : 'UNCODED');
        if (this.DEBUG) {
            console.error(`crypto ${operation} ${code}`, err);
        } else {
            console.error(`crypto ${operation} ${code}`);
        }
    }
    
    // =========================================================================
    // ECC KEYPAIR GENERATION
    // =========================================================================
    
    /**
     * Generate ECC P-384 keypair for Zero-Trust encryption.
     * 
     * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}>}
     */
    async generateKeypair() {
        try {
            const keypair = await this._subtle().generateKey(
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                true, // extractable
                this.KEY_USAGES_PRIVATE
            );
            
            return keypair;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED, 'generateKeypair');
        }
    }
    
    /**
     * Export public key to PEM format for server registration.
     * 
     * @param {CryptoKey} publicKey - Public key to export
     * @returns {Promise<string>} PEM-encoded public key
     */
    async exportPublicKeyPEM(publicKey) {
        try {
            const exported = await this._subtle().exportKey('spki', publicKey);
            const base64 = this._arrayBufferToBase64(exported);
            const pem = this._formatPEM(base64, 'PUBLIC KEY');
            
            return pem;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED, 'exportPublicKeyPEM');
        }
    }
    
    /**
     * Export private key to PEM format (unencrypted - use with caution!).
     * 
     * @param {CryptoKey} privateKey - Private key to export
     * @returns {Promise<string>} PEM-encoded private key
     */
    async exportPrivateKeyPEM(privateKey) {
        try {
            const exported = await this._subtle().exportKey('pkcs8', privateKey);
            const base64 = this._arrayBufferToBase64(exported);
            const pem = this._formatPEM(base64, 'PRIVATE KEY');
            
            return pem;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED, 'exportPrivateKeyPEM');
        }
    }
    
    /**
     * Import public key from PEM format.
     * 
     * @param {string} pem - PEM-encoded public key
     * @returns {Promise<CryptoKey>} Imported public key
     */
    async importPublicKeyPEM(pem) {
        try {
            const base64 = this._extractPEMContent(pem);
            const der = this._base64ToArrayBuffer(base64);
            
            const publicKey = await this._subtle().importKey(
                'spki',
                der,
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                true,
                []
            );
            
            return publicKey;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.KEY_UNUSABLE, 'importPublicKeyPEM');
        }
    }
    
    /**
     * Import private key from PEM format.
     * 
     * @param {string} pem - PEM-encoded private key
     * @returns {Promise<CryptoKey>} Imported private key
     */
    async importPrivateKeyPEM(pem, extractable = true) {
        try {
            const base64 = this._extractPEMContent(pem);
            const der = this._base64ToArrayBuffer(base64);

            // For runtime use (ECDH deriveBits/deriveKey) the key need not be
            // extractable; callers pass extractable=false to shrink the XSS target.
            const privateKey = await this._subtle().importKey(
                'pkcs8',
                der,
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                extractable,
                this.KEY_USAGES_PRIVATE
            );

            return privateKey;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.KEY_UNUSABLE, 'importPrivateKeyPEM');
        }
    }

    /**
     * Derive the PUBLIC key PEM that corresponds to a private key, from the private key's PEM.
     * Used to verify a recovery key's private key actually belongs to a registered public key
     * before adopting it — trusting a supplied/asserted public-key string is not enough, since it
     * is not cryptographically bound to the private key.
     * @param {string} privateKeyPEM - PEM-encoded private key
     * @returns {Promise<string>} PEM-encoded matching public key
     */
    async derivePublicKeyPEMFromPrivatePEM(privateKeyPEM) {
        const base64 = this._extractPEMContent(privateKeyPEM);
        const der = this._base64ToArrayBuffer(base64);
        // Import EXTRACTABLE so the public point (x/y) can be read out of the JWK.
        const priv = await this._subtle().importKey(
            'pkcs8', der, { name: 'ECDH', namedCurve: this.CURVE }, true, this.KEY_USAGES_PRIVATE);
        const jwk = await this._subtle().exportKey('jwk', priv);
        const pub = await this._subtle().importKey(
            'jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
            { name: 'ECDH', namedCurve: this.CURVE }, true, []);
        return await this.exportPublicKeyPEM(pub);
    }

    // =========================================================================
    // PASSWORD-BASED PRIVATE KEY ENCRYPTION
    // =========================================================================
    
    /**
     * Encrypt private key with password for secure storage/recovery.
     * Uses PBKDF2 (600k iterations) + AES-256-GCM.
     * 
     * @param {string} privateKeyPEM - PEM-encoded private key
     * @param {string} password - User's password
     * @returns {Promise<{encrypted: string, salt: string, iterations: number}>}
     */
    async encryptPrivateKey(privateKeyPEM, password) {
        try {
            // Generate random salt
            const salt = this._randomBytes((this.PBKDF2_SALT_LENGTH));
            
            // Derive AES key from password
            const passwordKey = await this._deriveKeyFromPassword(password, salt);
            
            // Generate IV
            const iv = this._randomBytes((this.AES_IV_LENGTH));
            
            // Encrypt private key PEM
            const privateKeyBytes = new TextEncoder().encode(privateKeyPEM);
            const encrypted = await this._subtle().encrypt(
                {
                    name: this.AES_ALGORITHM,
                    iv: iv,
                    tagLength: this.AES_TAG_LENGTH
                },
                passwordKey,
                privateKeyBytes
            );
            
            // Combine IV + ciphertext
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encrypted), iv.length);
            
            
            return {
                encrypted: this._arrayBufferToBase64(combined),
                salt: this._arrayBufferToBase64(salt),
                iterations: this.PBKDF2_ITERATIONS
            };
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED, 'encryptPrivateKey');
        }
    }
    
    /**
     * Decrypt password-protected private key.
     * 
     * @param {string} encryptedBase64 - Base64-encoded encrypted private key (IV + ciphertext)
     * @param {string} password - User's password
     * @param {string} saltBase64 - Base64-encoded salt
     * @param {number} iterations - PBKDF2 iterations (default 600000)
     * @returns {Promise<string>} Decrypted PEM-encoded private key
     */
    async decryptPrivateKey(encryptedBase64, password, saltBase64, iterations = 600000) {
        try {
            const combined = this._base64ToArrayBuffer(encryptedBase64);
            const salt = this._base64ToArrayBuffer(saltBase64);
            
            // Derive AES key from password
            const passwordKey = await this._deriveKeyFromPassword(password, salt, iterations);
            
            // Extract IV and ciphertext
            const iv = combined.slice(0, this.AES_IV_LENGTH);
            const ciphertext = combined.slice(this.AES_IV_LENGTH);
            
            // Decrypt
            const decrypted = await this._subtle().decrypt(
                {
                    name: this.AES_ALGORITHM,
                    iv: iv,
                    tagLength: this.AES_TAG_LENGTH
                },
                passwordKey,
                ciphertext
            );
            
            const privateKeyPEM = new TextDecoder().decode(decrypted);
            
            return privateKeyPEM;
        } catch (error) {
            // Same rule as the versioned reader: only an authentication failure earns
            // AUTH_FAILED. This body encloses key derivation as well as the decrypt, so a
            // fallback of AUTH_FAILED would blame the passphrase for a derivation failure.
            throw _coerceCryptoError(
                error,
                error && error.name === 'OperationError'
                    ? CRYPTO_ERROR_CODES.AUTH_FAILED
                    : CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
                'decryptPrivateKey');
        }
    }
    
    // =========================================================================
    // VERSIONED PRIVATE-KEY ENVELOPE (v1)
    //
    // Specified by docs/design/vault-private-key-envelope-v1.md. Two shapes are readable:
    //   legacy  {encrypted: b64(iv12||ct||tag16), salt: b64(32), iterations?}   - no AAD
    //   v1      {v,kdf,iter,cipher,salt,iv,ct}                                  - AAD-bound
    // encryptPrivateKey()/decryptPrivateKey() above are the LEGACY pair and are deliberately
    // left untouched: a pinned writer vector asserts they still emit exactly the published bytes.
    // =========================================================================

    /**
     * UTF-8 byte length of a string.
     *
     * Both designs specify their size caps in BYTES, and the server measures bytes. A plain
     * `.length` counts UTF-16 code units, which is up to three times smaller for a character in
     * the U+0800-U+FFFF range -- so a code-unit check silently admits payloads well past the
     * documented bound, and the client and server would disagree about the same blob.
     * @private
     */
    _utf8Len(value) {
        return new TextEncoder().encode(String(value)).byteLength;
    }

    /**
     * Decode canonical standard base64, or throw. Rejects the URL-safe alphabet, whitespace,
     * bad padding, and any string that decodes but is not the canonical encoding of its own
     * bytes. Optionally pins the decoded length.
     * @private
     */
    _b64Strict(value, field, expectedBytes = null) {
        if (typeof value !== 'string')
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, `envelope.${field}.type`);
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4 !== 0) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, `envelope.${field}.charset`);
        }
        let bytes;
        try {
            bytes = new Uint8Array(this._base64ToArrayBuffer(value));
        } catch (e) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, `envelope.${field}.decode`, e);
        }
        // Re-encoding catches non-canonical trailing bits, which the charset test cannot.
        if (this._arrayBufferToBase64(bytes) !== value) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, `envelope.${field}.canonical`);
        }
        if (expectedBytes !== null && bytes.length !== expectedBytes) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, `envelope.${field}.length`);
        }
        return bytes;
    }

    /**
     * The v1 AES-GCM additional authenticated data.
     *
     * This provides VERSION AND FORMAT domain separation - it stops a v1 ciphertext being
     * repackaged into the legacy shape, which derives the same key from the same salt and
     * iterations but authenticates nothing. It does NOT add substitution resistance for the
     * salt or the work factor: both are PBKDF2 inputs, so tampering with either already yields
     * a different key and a failing tag. The cheap-rejection property comes from the validation
     * below, never from this.
     * @private
     */
    _privEnvelopeAAD(iter, saltB64) {
        return new TextEncoder().encode(
            `${this.PRIV_ENVELOPE_AAD_LABEL}|${this.PRIV_ENVELOPE_KDF}|${iter}|` +
            `${this.PRIV_ENVELOPE_CIPHER}|${saltB64}`
        );
    }

    /** A JSON integer, not merely a number that happens to be whole. @private */
    _isInt(n) {
        return typeof n === 'number' && Number.isInteger(n);
    }

    /**
     * Parse and fully validate an envelope, WITHOUT deriving anything. Every check here is
     * cheap, so a malformed or hostile envelope costs nothing - which is the point, since a
     * recovery kit's fields come from a file the user selected.
     *
     * @param {object|string} raw - the envelope object, or the JSON string holding it
     * @returns {{format: 'v1'|'legacy', iter: number, salt: Uint8Array, iv: Uint8Array,
     *            ct: Uint8Array, aad: Uint8Array|null}}
     */
    parsePrivateEnvelope(raw) {
        let obj = raw;
        if (typeof raw === 'string') {
            // Bound before parsing: this cap applies to BOTH shapes, being a denial-of-service
            // bound of the same kind as the iteration ceiling. A genuine legacy envelope is
            // ~534 bytes, so it cannot reject a real one.
            if (this._utf8Len(raw) > this.PRIV_ENVELOPE_MAX_SERIALIZED) {
                this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.size');
            }
            try { obj = JSON.parse(raw); }
            catch (e) { this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.json', e); }
        }
        if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.shape');
        }
        if (typeof raw !== 'string' &&
            this._utf8Len(JSON.stringify(obj)) > this.PRIV_ENVELOPE_MAX_SERIALIZED) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.size');
        }

        if (Object.prototype.hasOwnProperty.call(obj, 'v')) return this._parseV1(obj);
        if (Object.prototype.hasOwnProperty.call(obj, 'encrypted') &&
            Object.prototype.hasOwnProperty.call(obj, 'salt')) {
            return this._parseLegacy(obj);
        }
        this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.discriminator');
    }

    /** @private */
    _parseV1(obj) {
        const allowed = ['v', 'kdf', 'iter', 'cipher', 'salt', 'iv', 'ct'];
        const keys = Object.keys(obj);
        if (keys.length !== allowed.length || !allowed.every(k => keys.includes(k))) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.v1.fieldset');
        }
        if (obj.v !== this.PRIV_ENVELOPE_VERSION)
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_UNSUPPORTED, 'envelope.v1.version');
        if (obj.kdf !== this.PRIV_ENVELOPE_KDF)
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_UNSUPPORTED, 'envelope.v1.kdf');
        if (obj.cipher !== this.PRIV_ENVELOPE_CIPHER)
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_UNSUPPORTED, 'envelope.v1.cipher');
        if (!this._isInt(obj.iter) || obj.iter < 1)
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.v1.iter.shape');
        if (obj.iter > this.PRIV_ENVELOPE_MAX_ITER)
            this._fail(CRYPTO_ERROR_CODES.WORK_FACTOR_REJECTED, 'envelope.v1.iter.ceiling');
        const salt = this._b64Strict(obj.salt, 'salt', this.PBKDF2_SALT_LENGTH);
        const iv = this._b64Strict(obj.iv, 'iv', this.AES_IV_LENGTH);
        const ct = this._b64Strict(obj.ct, 'ct');
        if (ct.length < this.PRIV_ENVELOPE_MIN_CT || ct.length > this.PRIV_ENVELOPE_MAX_CT) {
            this._fail(CRYPTO_ERROR_CODES.ENVELOPE_INVALID, 'envelope.v1.ct.length');
        }
        return {
            format: 'v1', iter: obj.iter, salt, iv, ct,
            aad: this._privEnvelopeAAD(obj.iter, obj.salt),
        };
    }

    /**
     * Legacy parsing stays exactly as permissive as the original reader, with two additions -
     * the iteration ceiling and the serialized size cap, both denial-of-service bounds that any
     * untrusted file can trip. Encoding strictness and length rules are v1-only ON PURPOSE:
     * tightening a deployed format can only reject envelopes that work today.
     * @private
     */
    _parseLegacy(obj) {
        let iter = obj.iterations;
        if (iter === undefined || iter === null || iter === '') {
            iter = this.PBKDF2_ITERATIONS;
        }
        iter = Number(iter);
        // A non-numeric value keeps its historical lenient treatment: fall back rather than
        // reject. It simply derives the wrong key and fails authentication.
        if (!Number.isFinite(iter) || iter < 1) iter = this.PBKDF2_ITERATIONS;
        if (iter > this.PRIV_ENVELOPE_MAX_ITER)
            this._fail(CRYPTO_ERROR_CODES.WORK_FACTOR_REJECTED, 'envelope.legacy.iterations');

        const combined = new Uint8Array(this._base64ToArrayBuffer(obj.encrypted));
        const salt = new Uint8Array(this._base64ToArrayBuffer(obj.salt));
        return {
            format: 'legacy', iter,
            salt,
            iv: combined.slice(0, this.AES_IV_LENGTH),
            ct: combined.slice(this.AES_IV_LENGTH),
            aad: null,
        };
    }

    /**
     * Write a v1 envelope. A fresh salt and IV are drawn per write and are never carried
     * forward from a previous envelope - the re-wrap paths hold the old values, and reusing an
     * IV under a derived key over this highly structured PEM plaintext would leak it.
     *
     * @param {string} privateKeyPEM
     * @param {string} password
     * @returns {Promise<object>} the v1 envelope object
     */
    async encryptPrivateKeyV1(privateKeyPEM, password) {
        const salt = this._randomBytes((this.PBKDF2_SALT_LENGTH));
        const iv = this._randomBytes((this.AES_IV_LENGTH));
        const saltB64 = this._arrayBufferToBase64(salt);
        const iter = this.PBKDF2_ITERATIONS;

        const key = await this._deriveKeyFromPassword(password, salt, iter);
        const ct = await this._subtle().encrypt(
            {
                name: this.AES_ALGORITHM,
                iv,
                tagLength: this.AES_TAG_LENGTH,
                additionalData: this._privEnvelopeAAD(iter, saltB64),
            },
            key,
            new TextEncoder().encode(privateKeyPEM)
        );

        return {
            v: this.PRIV_ENVELOPE_VERSION,
            kdf: this.PRIV_ENVELOPE_KDF,
            iter,
            cipher: this.PRIV_ENVELOPE_CIPHER,
            salt: saltB64,
            iv: this._arrayBufferToBase64(iv),
            ct: this._arrayBufferToBase64(new Uint8Array(ct)),
        };
    }

    /**
     * Read either envelope shape. This is the single reader every unlock path should use.
     *
     * @param {object|string} envelope
     * @param {string} password
     * @returns {Promise<string>} the PKCS#8 PEM private key
     */
    async decryptPrivateEnvelope(envelope, password) {
        const p = this.parsePrivateEnvelope(envelope);
        const key = await this._deriveKeyFromPassword(password, p.salt, p.iter);
        const params = { name: this.AES_ALGORITHM, iv: p.iv, tagLength: this.AES_TAG_LENGTH };
        if (p.aad) params.additionalData = p.aad;
        // Resolved BEFORE the try, so an unavailable platform cannot be caught below and reported
        // as a bad passphrase.
        const subtle = this._subtle();
        let plain;
        try {
            plain = await subtle.decrypt(params, key, p.ct);
        } catch (e) {
            // Wrong passphrase and tampered ciphertext are one outcome and are reported
            // identically. Everything else is NOT: this is the single path whose wording blames
            // the user's passphrase, so it must not absorb a failure that means something else.
            //
            // A coded failure keeps its own code. Of the rest, only an authentication failure --
            // which Web Crypto reports as OperationError -- earns AUTH_FAILED; an unsupported
            // algorithm or malformed input falls to the generic code and the generic sentence.
            // The trade is deliberate: a platform that names an authentication failure something
            // else would degrade to a vaguer message, which is recoverable, rather than tell a
            // user their correct passphrase is wrong, which is not. The wrong-passphrase and
            // tampered-ciphertext tests hold this honest on every platform a round runs.
            if (e && e.isCryptoError === true) throw e;
            if (e && e.isTransportError === true) throw e;
            this._fail(
                e && e.name === 'OperationError'
                    ? CRYPTO_ERROR_CODES.AUTH_FAILED
                    : CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
                'decryptPrivateEnvelope', e);
        }
        return new TextDecoder().decode(plain);
    }

    /**
     * Parse a recovery-kit FILE and return the envelope it carries. The kit is a wrapper around
     * an envelope, not an envelope, and on restore every one of its fields comes from a file the
     * user selected - so the wrapper needs bounds of its own.
     *
     * @param {string} text - the raw file contents
     * @returns {{kit: object, envelope: object}}
     */
    parseRecoveryKitFile(text) {
        if (typeof text !== 'string')
            this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID, 'kit.type');
        if (this._utf8Len(text) > this.RECOVERY_KIT_MAX_FILE)
            this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID, 'kit.size');
        let kit;
        try { kit = JSON.parse(text); }
        catch (e) { this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID, 'kit.json', e); }
        if (kit === null || typeof kit !== 'object' || Array.isArray(kit)) {
            this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID, 'kit.shape');
        }
        if (kit.type !== this.RECOVERY_KIT_TYPE)
            this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID, 'kit.marker');
        if (kit.version !== 1)
            this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_UNSUPPORTED, 'kit.version');
        for (const f of ['user_id', 'fingerprint', 'public_key']) {
            const v = kit[f];
            if (v === null || v === undefined) continue;
            if (typeof v !== 'string' || this._utf8Len(v) > this.RECOVERY_KIT_MAX_FIELD) {
                this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID, `kit.field.${f}`);
            }
        }
        if (kit.recovery === null || typeof kit.recovery !== 'object') {
            this._fail(CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID, 'kit.envelope.missing');
        }
        // Unknown wrapper members are ignored on purpose, so a future field does not break an
        // older reader. That is the opposite of the envelope itself, where an extra member is a
        // structural error.
        this.parsePrivateEnvelope(kit.recovery);
        return { kit, envelope: kit.recovery };
    }

    /**
     * The raw uncompressed P-384 point (97 bytes: 0x04 || X || Y) of a public key.
     * Exporting to a point is what makes a comparison canonical - it normalises away PEM line
     * wrapping, whitespace, trailing newlines, base64 padding and SPKI header encoding, none of
     * which are key material.
     * @private
     */
    async _rawPointFromPublicPEM(pem) {
        const key = await this.importPublicKeyPEM(pem);
        return new Uint8Array(await this._subtle().exportKey('raw', key));
    }

    /**
     * The raw uncompressed public point belonging to a private key. WebCrypto cannot derive a
     * public key from a private one directly, so this goes via JWK: export, drop the private
     * component, re-import the remainder as a public key. The extractable import is used only
     * here and the handle is discarded.
     * @private
     */
    async _rawPointFromPrivatePEM(pem) {
        const priv = await this.importPrivateKeyPEM(pem, true);
        const jwk = await this._subtle().exportKey('jwk', priv);
        delete jwk.d;
        jwk.key_ops = [];
        delete jwk.ext;
        const pub = await this._subtle().importKey(
            'jwk', jwk, { name: 'ECDH', namedCurve: this.CURVE }, true, []
        );
        return new Uint8Array(await this._subtle().exportKey('raw', pub));
    }

    /**
     * Does this private key belong to this registered public key?
     *
     * Decrypting proves the passphrase was right; it does not prove the recovered key is the
     * ACCOUNT's key. An ordinary comparison is correct here - both operands are public, so there
     * is no secret for a timing difference to leak.
     *
     * FAILS CLOSED: if the registered key is absent or unusable the check cannot be performed and
     * this returns false. Treating "cannot check" as "check passed" would make the whole thing
     * optional in exactly the circumstances an attacker controls.
     *
     * The limit, honestly: this proves consistency with the public key the SERVER RETURNED. It
     * does not defend against a server substituting both halves at once.
     *
     * @returns {Promise<boolean>}
     */
    async privateKeyMatchesRegisteredPublicKey(privateKeyPEM, registeredPublicKeyPEM) {
        if (typeof registeredPublicKeyPEM !== 'string' || !registeredPublicKeyPEM.trim()) {
            return false;
        }
        let derived, registered;
        try {
            derived = await this._rawPointFromPrivatePEM(privateKeyPEM);
            registered = await this._rawPointFromPublicPEM(registeredPublicKeyPEM);
        } catch (e) {
            return false;
        }
        if (derived.length !== registered.length || derived.length === 0) return false;
        let diff = 0;
        for (let i = 0; i < derived.length; i++) diff |= derived[i] ^ registered[i];
        return diff === 0;
    }

    // =========================================================================
    // VAULT DEK WRAPPING/UNWRAPPING (ECDH + AES-KW simulation)
    // =========================================================================
    
    /**
     * Unwrap vault DEK using user's private key.
     * Uses ECDH to derive shared secret, then decrypts the wrapped DEK.
     * 
     * @param {string} wrappedDEKBase64 - Base64-encoded wrapped DEK
     * @param {string} ephemeralPublicKeyBase64 - Base64-encoded ephemeral public key
     * @param {CryptoKey} userPrivateKey - User's private key
     * @returns {Promise<CryptoKey>} Unwrapped vault DEK as AES-GCM key
     */
    async unwrapVaultDEK(wrappedDEKBase64, ephemeralPublicKeyBase64, userPrivateKey) {
        try {
            // Import ephemeral public key (X.962 point format).
            const ephemeralPublicKeyBytes = this._base64ToArrayBuffer(ephemeralPublicKeyBase64);
            const ephemeralPublicKey = await this._importRawPublicKey(ephemeralPublicKeyBytes);

            // ECDH -> shared secret -> HKDF wrapping key -> AES-KW unwrap.
            const sharedSecret = await this._subtle().deriveBits(
                { name: 'ECDH', public: ephemeralPublicKey },
                userPrivateKey,
                384 // P-384 produces a 384-bit shared secret
            );
            const wrappingKey = await this._deriveWrappingKey(sharedSecret);
            const wrappedDEKBytes = this._base64ToArrayBuffer(wrappedDEKBase64);
            const vaultDEK = await this._unwrapKeyWithAESKW(wrappedDEKBytes, wrappingKey);

            return vaultDEK;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.WRAP_FAILED, 'unwrapVaultDEK');
        }
    }

    /**
     * Wrap a vault DEK FOR ANOTHER MEMBER using their public key (client-side
     * re-share). The inverse of unwrapVaultDEK: a fresh ephemeral ECDH keypair
     * agrees with the recipient's public key, HKDF derives the AES-KW key, and
     * the DEK is wrapped (RFC 3394). The ephemeral public key is exported
     * UNCOMPRESSED (97 bytes for P-384) so the recipient imports it directly.
     *
     * @param {CryptoKey} vaultDEK - the (extractable) AES-GCM vault DEK
     * @param {CryptoKey} recipientPublicKey - recipient's ECDH public key
     * @returns {Promise<{wrappedDEK: string, ephemeralPublicKey: string}>} base64
     */
    async wrapVaultDEK(vaultDEK, recipientPublicKey) {
        const ephemeral = await this._subtle().generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            true,                 // extractable: we export the ephemeral PUBLIC key
            ['deriveBits']
        );
        const sharedSecret = await this._subtle().deriveBits(
            { name: 'ECDH', public: recipientPublicKey },
            ephemeral.privateKey,
            384
        );
        const wrappingKey = await this._deriveWrappingKey(sharedSecret);
        const wrapped = await this._subtle().wrapKey('raw', vaultDEK, wrappingKey, { name: 'AES-KW' });
        const ephRaw = await this._subtle().exportKey('raw', ephemeral.publicKey); // uncompressed
        return {
            wrappedDEK: this._arrayBufferToBase64(wrapped),
            ephemeralPublicKey: this._arrayBufferToBase64(ephRaw),
        };
    }

    /**
     * Registration proof-of-possession (ECDH key-confirmation). Proves to the server that
     * this client holds the PRIVATE key for the public key being registered, so a
     * substituted / not-held key can't be registered. Does ECDH(userPrivateKey,
     * serverEphemeralPublicKey) -> HKDF -> HMAC over (nonce || publicKeyPem). Exact mirror
     * of the server's app/services/ecc_pop.py (salt 'dv-ecc-pop-v1', info 'registration-pop', SHA-256).
     *
     * @param {string} serverEphemeralPublicKeyPem - server ephemeral public key (SPKI PEM)
     * @param {string} nonceBase64 - base64 nonce from the challenge
     * @param {string} publicKeyPem - the PEM public key being registered (bound into the MAC)
     * @param {CryptoKey} userPrivateKey - the user's ECDH private key (deriveBits)
     * @returns {Promise<string>} base64 HMAC-SHA256
     */
    async computeRegistrationPoP(serverEphemeralPublicKeyPem, nonceBase64, publicKeyPem, userPrivateKey) {
        const serverPub = await this.importPublicKeyPEM(serverEphemeralPublicKeyPem);
        const shared = await this._subtle().deriveBits(
            { name: 'ECDH', public: serverPub }, userPrivateKey, 384);
        const hkdfKey = await this._subtle().importKey('raw', shared, 'HKDF', false, ['deriveBits']);
        const macKeyBits = await this._subtle().deriveBits(
            {
                name: 'HKDF', hash: 'SHA-256',
                salt: new TextEncoder().encode('dv-ecc-pop-v1'),
                info: new TextEncoder().encode('registration-pop'),
            },
            hkdfKey, 256);
        const macKey = await this._subtle().importKey(
            'raw', macKeyBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const nonce = new Uint8Array(this._base64ToArrayBuffer(nonceBase64));
        const pubBytes = new TextEncoder().encode(publicKeyPem);
        const msg = new Uint8Array(nonce.byteLength + pubBytes.byteLength);
        msg.set(nonce, 0);
        msg.set(pubBytes, nonce.byteLength);
        const mac = await this._subtle().sign('HMAC', macKey, msg);
        return this._arrayBufferToBase64(mac);
    }

    /**
     * Proof of possession for REPLACING the stored private-key envelope.
     *
     * Specified by docs/design/vault-private-key-update-pop-v1.md. Deliberately shares the shape
     * of computeRegistrationPoP above but NOT its domain: a different HKDF salt and info, so a
     * proof for one protocol can never validate for the other.
     *
     * The transcript binds the exact replacement bytes, so a captured proof cannot authorise a
     * different replacement. Digests contribute 32 RAW bytes, the nonce is base64-DECODED, and
     * both ids are lowercase canonical UUIDs — pinned so this and the server cannot drift.
     *
     * @param {string} serverEphemeralPublicKeyPem  from the challenge
     * @param {string} nonceBase64                  from the challenge
     * @param {string} challengeId                  from the challenge
     * @param {string} userId                       this account's UUID
     * @param {string} registeredPublicKeyPem       the account's REGISTERED public key
     * @param {string} envelopeJson                 the exact UTF-8 string about to be uploaded
     * @param {CryptoKey} userPrivateKey            the recovered private key (ECDH, deriveBits)
     * @returns {Promise<string>} base64 MAC
     */
    async computeKeyUpdatePoP(
        serverEphemeralPublicKeyPem, nonceBase64, challengeId, userId,
        registeredPublicKeyPem, envelopeJson, userPrivateKey
    ) {
        const serverPub = await this.importPublicKeyPEM(serverEphemeralPublicKeyPem);
        const shared = await this._subtle().deriveBits(
            { name: 'ECDH', public: serverPub }, userPrivateKey, 384);
        const hkdfKey = await this._subtle().importKey('raw', shared, 'HKDF', false, ['deriveBits']);
        const macKeyBits = await this._subtle().deriveBits(
            {
                name: 'HKDF', hash: 'SHA-256',
                salt: new TextEncoder().encode('dv-ecc-update-pop-v1'),
                info: new TextEncoder().encode('private-key-update-pop'),
            },
            hkdfKey, 256);
        const macKey = await this._subtle().importKey(
            'raw', macKeyBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

        // The registered key as its canonical uncompressed point (97 bytes), NOT its PEM, so a
        // cosmetically re-encoded stored key cannot invalidate a genuine proof.
        const registered = await this.importPublicKeyPEM(registeredPublicKeyPem);
        const point = new Uint8Array(await this._subtle().exportKey('raw', registered));

        const enc = new TextEncoder();
        const sha256 = async bytes =>
            new Uint8Array(await this._subtle().digest('SHA-256', bytes));

        const parts = [
            enc.encode('dockvault-private-key-update-pop-v1'),
            enc.encode(String(challengeId).toLowerCase()),
            new Uint8Array(this._base64ToArrayBuffer(nonceBase64)),
            enc.encode(String(userId).toLowerCase()),
            await sha256(point),
            await sha256(enc.encode(envelopeJson)),
        ];
        // 0x00-separated, so the concatenation is unambiguous.
        const total = parts.reduce((n, p) => n + p.byteLength, 0) + (parts.length - 1);
        const joined = new Uint8Array(total);
        let at = 0;
        parts.forEach((p, i) => {
            if (i > 0) joined[at++] = 0x00;
            joined.set(p, at);
            at += p.byteLength;
        });

        const transcript = await sha256(joined);
        return this._arrayBufferToBase64(
            await this._subtle().sign('HMAC', macKey, transcript));
    }

    // =========================================================================
    // HIERARCHICAL MODE — wrap/unwrap a TEAM PRIVATE KEY to/from a member pubkey
    // =========================================================================
    // wrapVaultDEK above uses wrapKey('raw',…)+AES-KW, which exports SYMMETRIC keys only and
    // THROWS on an ECC private key. The team private key must therefore be carried as pkcs8
    // under AES-GCM, with a DISTINCT HKDF info ('team-privkey-wrapping-v1') so a team-priv blob
    // can never be unwrapped by — or confused with — the AES-KW DEK path (domain separation).

    /** Derive an AES-GCM wrapping key for the team-private-key path (distinct info from the
     * DEK path's AES-KW key). @private */
    async _deriveTeamPrivWrappingKey(sharedSecretBits) {
        const sharedSecretKey = await this._subtle().importKey(
            'raw', sharedSecretBits, 'HKDF', false, ['deriveKey']
        );
        return await this._subtle().deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(),
              info: new TextEncoder().encode('team-privkey-wrapping-v1') },
            sharedSecretKey,
            { name: this.AES_ALGORITHM, length: this.AES_KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Wrap a per-vault TEAM PRIVATE key to a recipient's public key (hierarchical sharing).
     * MINTS A FRESH ephemeral ECDH keypair (and therefore a fresh AES-GCM key) on EVERY call —
     * one per recipient. Ephemerals/derived keys MUST NEVER be reused across recipients (the
     * random 12-byte GCM IV is only safe under per-call key freshness).
     *
     * @param {CryptoKey} teamPrivateKey - the EXTRACTABLE team ECDH private key
     * @param {CryptoKey} recipientPublicKey - recipient's ECDH public key
     * @returns {Promise<{wrappedKey: string, ephemeralPublicKey: string}>} base64 (wrappedKey = iv||ct)
     */
    async wrapPrivateKeyToPublic(teamPrivateKey, recipientPublicKey) {
        const ephemeral = await this._subtle().generateKey(
            { name: 'ECDH', namedCurve: this.CURVE }, true, ['deriveBits']
        );
        const sharedSecret = await this._subtle().deriveBits(
            { name: 'ECDH', public: recipientPublicKey }, ephemeral.privateKey, 384
        );
        const wrappingKey = await this._deriveTeamPrivWrappingKey(sharedSecret);
        const pkcs8 = await this._subtle().exportKey('pkcs8', teamPrivateKey);
        const iv = this._randomBytes((this.AES_IV_LENGTH));
        const ct = await this._subtle().encrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH }, wrappingKey, pkcs8
        );
        const combined = new Uint8Array(iv.length + ct.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ct), iv.length);
        const ephRaw = await this._subtle().exportKey('raw', ephemeral.publicKey); // uncompressed
        return {
            wrappedKey: this._arrayBufferToBase64(combined.buffer),
            ephemeralPublicKey: this._arrayBufferToBase64(ephRaw),
        };
    }

    /**
     * Inverse of wrapPrivateKeyToPublic. Returns the team private key as a NON-EXTRACTABLE
     * ECDH CryptoKey (deriveBits only) so it can unwrap the vault DEK but can't be re-exported.
     *
     * @param {string} wrappedKeyBase64 - base64 of iv||ciphertext+tag
     * @param {string} ephemeralPublicKeyBase64 - base64 uncompressed ephemeral point
     * @param {CryptoKey} memberPrivateKey - the member's identity ECDH private key
     * @returns {Promise<CryptoKey>} the team private key (non-extractable)
     */
    async unwrapPrivateKeyFromWrapped(wrappedKeyBase64, ephemeralPublicKeyBase64, memberPrivateKey, extractable = false) {
        const ephemeralPublicKey = await this._importRawPublicKey(
            this._base64ToArrayBuffer(ephemeralPublicKeyBase64)
        );
        const sharedSecret = await this._subtle().deriveBits(
            { name: 'ECDH', public: ephemeralPublicKey }, memberPrivateKey, 384
        );
        const wrappingKey = await this._deriveTeamPrivWrappingKey(sharedSecret);
        const raw = new Uint8Array(this._base64ToArrayBuffer(wrappedKeyBase64));
        const iv = raw.slice(0, this.AES_IV_LENGTH);
        const ct = raw.slice(this.AES_IV_LENGTH);
        const pkcs8 = await this._subtle().decrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH }, wrappingKey, ct
        );
        // Least privilege: the team private key is only ever used to ECDH-unwrap the vault DEK
        // (deriveBits), never deriveKey — so import it with deriveBits only, not the identity
        // keypair's broader KEY_USAGES_PRIVATE.
        return await this._subtle().importKey(
            'pkcs8', pkcs8, { name: 'ECDH', namedCurve: this.CURVE }, extractable, ['deriveBits']
        );
    }

    // =========================================================================
    // FILE ENCRYPTION/DECRYPTION
    // =========================================================================
    
    /**
     * Encrypt file content with vault DEK.
     * 
     * @param {ArrayBuffer|Uint8Array} fileContent - File content to encrypt
     * @param {CryptoKey} vaultDEK - Vault Data Encryption Key
     * @returns {Promise<ArrayBuffer>} Encrypted file content (IV + ciphertext)
     */
    async encryptFile(fileContent, vaultDEK) {
        try {
            const iv = this._randomBytes((this.AES_IV_LENGTH));
            
            const encrypted = await this._subtle().encrypt(
                {
                    name: this.AES_ALGORITHM,
                    iv: iv,
                    tagLength: this.AES_TAG_LENGTH
                },
                vaultDEK,
                fileContent
            );
            
            // Combine IV + ciphertext
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encrypted), iv.length);
            
            return combined.buffer;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED, 'encryptFile');
        }
    }
    
    /**
     * Decrypt file content with vault DEK.
     * 
     * @param {ArrayBuffer|Uint8Array} encryptedContent - Encrypted file content (IV + ciphertext)
     * @param {CryptoKey} vaultDEK - Vault Data Encryption Key
     * @returns {Promise<ArrayBuffer>} Decrypted file content
     */
    async decryptFile(encryptedContent, vaultDEK) {
        try {
            const data = new Uint8Array(encryptedContent);
            const iv = data.slice(0, this.AES_IV_LENGTH);
            const ciphertext = data.slice(this.AES_IV_LENGTH);
            
            const decrypted = await this._subtle().decrypt(
                {
                    name: this.AES_ALGORITHM,
                    iv: iv,
                    tagLength: this.AES_TAG_LENGTH
                },
                vaultDEK,
                ciphertext
            );
            
            return decrypted;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CONTENT_AUTH_FAILED, 'decryptFile');
        }
    }
    
    // =========================================================================
    // ZERO-KNOWLEDGE NAME / MIME ENCRYPTION + BLIND INDEX
    // =========================================================================
    // File and folder names (and a file's MIME type) are metadata that must NOT leak to
    // the server in a zero-knowledge vault. They are encrypted here IN THE BROWSER under
    // the same per-vault DEK as the content, and the server stores only the opaque blob
    // plus a blind index it cannot reverse. The server keeps these verbatim and decrypts
    // nothing. Format/AAD/HKDF here MUST match app/core/security.py (ZK_NAME_PREFIX) and the test
    // helpers — changing any of them silently breaks decryption of existing names.

    // Marker prefix on every ZK-sealed name blob so the SERVER can tell a browser-encrypted
    // name from a Standard (server-key) one and never try to decrypt it. Must equal
    // security.ZK_NAME_PREFIX.
    get ZK_NAME_PREFIX() { return 'zk1:'; }        // legacy v1 blobs (decrypt-only; obj id NOT bound)
    get ZK_NAME_PREFIX_V2() { return 'zk2:'; }     // v2 blobs: AAD also binds the object id

    // v1 AAD binds a name blob to its vault, field ('name'|'mime') and DEK epoch. It does NOT
    // bind the object id, so a v1 blob CAN be transposed between same-vault/same-epoch objects.
    // Kept only to decrypt pre-existing v1 blobs.
    _zkNameAad(vaultId, field, epoch) {
        return new TextEncoder().encode(`dv-zk-name-v1|${vaultId}|${field}|${epoch}`);
    }

    // v2 AAD ALSO binds the object id (file/folder UUID), so a sealed name can't be moved to a
    // different object — the GCM auth fails on decrypt with the wrong id. New seals use this.
    _zkNameAadV2(vaultId, field, epoch, objId) {
        return new TextEncoder().encode(`dv-zk-name-v2|${vaultId}|${field}|${epoch}|${objId}`);
    }

    /**
     * Encrypt a file/folder name or MIME string for a zero-knowledge vault (v2: obj-id-bound).
     * @param {string} plaintext  the name (or MIME) to seal
     * @param {CryptoKey} vaultDEK the vault DEK (AES-GCM) at `epoch`
     * @param {string} vaultId
     * @param {string} field 'name' | 'mime'
     * @param {number} epoch the DEK epoch the name is sealed under
     * @param {string} objId the file/folder id the name belongs to. REQUIRED — the name is
     *   always sealed v2 (obj-id-bound, so a blob can't be transposed to a different object). A
     *   missing id is a caller bug; legacy v1 blobs are read-only (decryptName still reads them).
     * @returns {Promise<string>} ZK_NAME_PREFIX_V2 + base64(iv||ct+tag)
     */
    async encryptName(plaintext, vaultDEK, vaultId, field, epoch, objId) {
        // Every new sealed name MUST bind its object id (v2) so a blob can't be transposed to a
        // different row. Refuse to emit an unbound (v1) blob — a missing id is a caller bug.
        if (objId === undefined || objId === null || objId === '') {
            this._fail(CRYPTO_ERROR_CODES.INVALID_INPUT, 'encryptName.objId');
        }
        const aad = this._zkNameAadV2(vaultId, field, epoch, objId);
        const iv = this._randomBytes((this.AES_IV_LENGTH));
        const ct = await this._subtle().encrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH, additionalData: aad },
            vaultDEK,
            new TextEncoder().encode(String(plaintext)),
        );
        const combined = new Uint8Array(iv.length + ct.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ct), iv.length);
        return this.ZK_NAME_PREFIX_V2 + this._arrayBufferToBase64(combined.buffer);
    }

    /**
     * Inverse of encryptName. Branches on the blob version: v2 (zk2:) binds objId; v1 (zk1:,
     * legacy) does not. Throws on a wrong DEK/epoch/field/objId (GCM auth failure).
     */
    async decryptName(token, vaultDEK, vaultId, field, epoch, objId) {
        const t = String(token);
        let b64, aad;
        if (t.startsWith(this.ZK_NAME_PREFIX_V2)) {
            b64 = t.slice(this.ZK_NAME_PREFIX_V2.length);
            aad = this._zkNameAadV2(vaultId, field, epoch, objId);
        } else {
            b64 = t.startsWith(this.ZK_NAME_PREFIX) ? t.slice(this.ZK_NAME_PREFIX.length) : t;
            aad = this._zkNameAad(vaultId, field, epoch);  // legacy v1 (obj id not bound)
        }
        const data = new Uint8Array(this._base64ToArrayBuffer(b64));
        const iv = data.slice(0, this.AES_IV_LENGTH);
        const ct = data.slice(this.AES_IV_LENGTH);
        const pt = await this._subtle().decrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH, additionalData: aad },
            vaultDEK,
            ct,
        );
        return new TextDecoder().decode(pt);
    }

    /**
     * Deterministic blind index of a name for a zero-knowledge vault: a keyed HMAC under a
     * per-(vault,epoch) key derived from the DEK, so the SERVER can match same-name rows
     * (replace / no-clobber / rename uniqueness) without ever seeing the name. Same
     * (DEK, vault, epoch, name) -> same hex digest. Reversible only by a DEK holder.
     * @returns {Promise<string>} hex
     */
    async nameBlindIndex(name, vaultDEK, vaultId, epoch) {
        const raw = await this._subtle().exportKey('raw', vaultDEK);
        const hkdf = await this._subtle().importKey('raw', raw, 'HKDF', false, ['deriveBits']);
        const biKeyBits = await this._subtle().deriveBits(
            { name: 'HKDF', hash: 'SHA-256',
              salt: new TextEncoder().encode('dv-zk-name-bi-v1'),
              info: new TextEncoder().encode(`${vaultId}|${epoch}`) },
            hkdf, 256,
        );
        const hmacKey = await this._subtle().importKey(
            'raw', biKeyBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await this._subtle().sign('HMAC', hmacKey, new TextEncoder().encode(String(name)));
        return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /**
     * Calculate SHA-256 fingerprint of public key (for verification).
     * 
     * @param {CryptoKey} publicKey - Public key
     * @returns {Promise<string>} Hex-encoded fingerprint (first 16 chars)
     */
    async calculateFingerprint(publicKey) {
        try {
            const exported = await this._subtle().exportKey('raw', publicKey);
            const hash = await this._subtle().digest('SHA-256', exported);
            const hex = Array.from(new Uint8Array(hash))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            return hex.substring(0, 16);
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED, 'calculateFingerprint');
        }
    }
    
    /**
     * Generate random vault DEK (for vault creation).
     * 
     * @returns {Promise<CryptoKey>} Generated AES-256-GCM key
     */
    async generateVaultDEK() {
        try {
            const dek = await this._subtle().generateKey(
                {
                    name: this.AES_ALGORITHM,
                    length: this.AES_KEY_LENGTH
                },
                true,
                ['encrypt', 'decrypt']
            );
            
            return dek;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED, 'generateVaultDEK');
        }
    }
    
    // =========================================================================
    // INTERNAL HELPER FUNCTIONS
    // =========================================================================
    
    /**
     * Derive AES key from password using PBKDF2.
     * @private
     */
    async _deriveKeyFromPassword(password, salt, iterations = null) {
        const iters = iterations || this.PBKDF2_ITERATIONS;
        
        const passwordKey = await this._subtle().importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        return await this._subtle().deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iters,
                hash: this.PBKDF2_HASH
            },
            passwordKey,
            {
                name: this.AES_ALGORITHM,
                length: this.AES_KEY_LENGTH
            },
            false,
            ['encrypt', 'decrypt']
        );
    }
    
    /**
     * Derive wrapping key from shared secret using HKDF.
     * @private
     */
    async _deriveWrappingKey(sharedSecretBits) {
        const sharedSecretKey = await this._subtle().importKey(
            'raw',
            sharedSecretBits,
            'HKDF',
            false,
            ['deriveKey']
        );
        // Derive an AES-KW wrapping key (RFC 3394) so it matches server aes_key_wrap
        return await this._subtle().deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(),
                info: this.HKDF_INFO
            },
            sharedSecretKey,
            {
                name: 'AES-KW',
                length: this.AES_KEY_LENGTH
            },
            false,
            ['wrapKey', 'unwrapKey']
        );
    }
    
    /**
     * Unwrap key using AES-KW simulation (AES-GCM).
     * @private
     */
    async _unwrapKeyWithAESKW(wrappedKeyBytes, wrappingKey) {
        try {

            // Ensure we have an ArrayBuffer
            let wrappedBuf;
            if (wrappedKeyBytes instanceof ArrayBuffer) {
                wrappedBuf = wrappedKeyBytes;
            } else if (ArrayBuffer.isView(wrappedKeyBytes)) {
                wrappedBuf = wrappedKeyBytes.buffer.slice(wrappedKeyBytes.byteOffset, wrappedKeyBytes.byteOffset + wrappedKeyBytes.byteLength);
            } else {
                // Try to coerce
                wrappedBuf = (new Uint8Array(wrappedKeyBytes)).buffer;
            }

            // Use SubtleCrypto.unwrapKey to unwrap RFC 3394 (AES-KW) wrapped key
            const unwrappedKey = await this._subtle().unwrapKey(
                'raw', // format of the unwrapped key material
                wrappedBuf, // wrapped key bytes (RFC3394)
                wrappingKey, // the AES-KW CryptoKey derived via HKDF
                { name: 'AES-KW' }, // wrapping algorithm
                { name: this.AES_ALGORITHM, length: this.AES_KEY_LENGTH }, // result key algorithm (AES-GCM DEK)
                true, // extractable
                ['encrypt', 'decrypt'] // usages
            );

            return unwrappedKey;
        } catch (err) {
            throw _coerceCryptoError(err, CRYPTO_ERROR_CODES.WRAP_FAILED, 'unwrapKeyWithAESKW');
        }
    }
    
    /**
     * Import raw public key (X.962 compressed or uncompressed point format).
     * Converts compressed points to uncompressed for Web Crypto API compatibility.
     * @private
     */
    async _importRawPublicKey(rawKeyBytes) {
        const bytes = new Uint8Array(rawKeyBytes);
        
        // Check if it's compressed (49 bytes for P-384)
        if (bytes.length === 49 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
            // For P-384, we need to decompress the point
            // This is complex, so we'll import as SPKI (PEM) instead
            // Create a minimal SPKI structure for the compressed point
            const uncompressedBytes = await this._decompressP384Point(bytes);
            rawKeyBytes = uncompressedBytes;
        }
        
        return await this._subtle().importKey(
            'raw',
            rawKeyBytes,
            {
                name: 'ECDH',
                namedCurve: this.CURVE
            },
            true,
            []
        );
    }
    
    /**
     * Decompress P-384 compressed point to uncompressed format.
     * Compressed: 0x02/0x03 + x (48 bytes) = 49 bytes
     * Uncompressed: 0x04 + x (48 bytes) + y (48 bytes) = 97 bytes
     * @private
     */
    async _decompressP384Point(compressedBytes) {
        // Simpler approach: Use Python to do the conversion
        // Since Web Crypto doesn't natively support compressed points,
        // we'll need to ask the server to convert it
        
        
        try {
            // Convert to base64 for transmission
            const compressedBase64 = this._arrayBufferToBase64(compressedBytes.buffer);
            
            const response = await fetch('/ecc/decompress-point', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('access_token')}`
                },
                body: JSON.stringify({
                    compressed_point: compressedBase64,
                    curve: 'P-384'
                })
            });
            
            if (!response.ok) {
                // Deliberately NOT a CryptoError: see the transport exclusion in
                // docs/design/vault-client-crypto-errors-v1.md. A rate-limit or authorization
                // response must not be reportable through the crypto code channel.
                const transport = new Error('point decompression request failed');
                transport.isTransportError = true;
                transport.status = response.status;
                throw transport;
            }
            
            const result = await response.json();
            const uncompressed = this._base64ToArrayBuffer(result.uncompressed_point);
            
            return uncompressed;
        } catch (error) {
            if (error && error.isTransportError) throw error;
            const transport = new Error('point decompression failed');
            transport.isTransportError = true;
            transport.cause = error;
            throw transport;
        }
    }
    
    /**
     * Convert ArrayBuffer to Base64.
     * @private
     */
    _arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    /**
     * Convert Base64 to ArrayBuffer.
     * @private
     */
    _base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    /**
     * Format binary data as PEM.
     * @private
     */
    _formatPEM(base64, label) {
        const lines = [];
        lines.push(`-----BEGIN ${label}-----`);
        for (let i = 0; i < base64.length; i += 64) {
            lines.push(base64.substring(i, i + 64));
        }
        lines.push(`-----END ${label}-----`);
        return lines.join('\n');
    }
    
    /**
     * Extract Base64 content from PEM.
     * @private
     */
    _extractPEMContent(pem) {
        return pem
            .replace(/-----BEGIN [A-Z ]+-----/, '')
            .replace(/-----END [A-Z ]+-----/, '')
            .replace(/\s/g, '');
    }
}

/**
 * Default code for each public operation, applied at its boundary.
 *
 * A method that already raised a CryptoError keeps it; anything else -- a DOMException from
 * WebCrypto, a TypeError from a malformed argument -- is converted here. This exists because most
 * of the methods below have no try block of their own: they reject with whatever the platform
 * threw, and a caller branching on `.code` would see `undefined`.
 *
 * Read the value as the answer to "if this operation fails for a reason nothing more specific
 * caught, what should the user be told?"
 */
const _OPERATION_DEFAULT_CODE = Object.freeze({
    // Key material in, key material out. A failure here means the bytes are not a usable key.
    importPublicKeyPEM: CRYPTO_ERROR_CODES.KEY_UNUSABLE,
    importPrivateKeyPEM: CRYPTO_ERROR_CODES.KEY_UNUSABLE,
    derivePublicKeyPEMFromPrivatePEM: CRYPTO_ERROR_CODES.KEY_UNUSABLE,
    // Listed for completeness: this one catches everything internally and returns a boolean,
    // so the boundary is a no-op today. It stays so the table remains a full statement of the
    // public surface rather than a list of whichever methods happened to need it.
    privateKeyMatchesRegisteredPublicKey: CRYPTO_ERROR_CODES.KEY_UNUSABLE,

    // Passphrase-derived. An authentication failure here is a wrong passphrase or tampering, and
    // the two are indistinguishable to AES-GCM.
    // Legacy reader, reached only by the compatibility fixtures -- the app parses first, so a
    // malformed blob yields ENVELOPE_INVALID there rather than arriving here. Anything wired to
    // call this directly should parse first for the same reason.
    decryptPrivateKey: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    // NOT AUTH_FAILED. Key derivation runs before the decrypt, and a fallback of AUTH_FAILED
    // would report a derivation failure as a wrong passphrase -- the mislabel this contract
    // exists to remove. Authentication failure is raised where it is observed, not defaulted to.
    decryptPrivateEnvelope: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,

    // Envelope grammar, no key involved.
    parsePrivateEnvelope: CRYPTO_ERROR_CODES.ENVELOPE_INVALID,
    parseRecoveryKitFile: CRYPTO_ERROR_CODES.RECOVERY_KIT_INVALID,

    // Data-key wrapping.
    unwrapVaultDEK: CRYPTO_ERROR_CODES.WRAP_FAILED,
    wrapVaultDEK: CRYPTO_ERROR_CODES.WRAP_FAILED,
    wrapPrivateKeyToPublic: CRYPTO_ERROR_CODES.WRAP_FAILED,
    unwrapPrivateKeyFromWrapped: CRYPTO_ERROR_CODES.WRAP_FAILED,

    // Vault-key-encrypted content. The user supplied no secret to reach here, so a failure is
    // never a passphrase problem and must never be reported as one.
    decryptFile: CRYPTO_ERROR_CODES.CONTENT_AUTH_FAILED,
    decryptName: CRYPTO_ERROR_CODES.CONTENT_AUTH_FAILED,

    // Everything else: a primitive rejected for a reason that is not authentication, not policy
    // and not input.
    generateKeypair: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    exportPublicKeyPEM: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    exportPrivateKeyPEM: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    encryptPrivateKey: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    encryptPrivateKeyV1: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    computeRegistrationPoP: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    computeKeyUpdatePoP: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    encryptFile: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    encryptName: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    nameBlindIndex: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    calculateFingerprint: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
    generateVaultDEK: CRYPTO_ERROR_CODES.CRYPTO_OPERATION_FAILED,
});

for (const [_name, _code] of Object.entries(_OPERATION_DEFAULT_CODE)) {
    const _inner = ECCCryptoLibrary.prototype[_name];
    if (typeof _inner !== 'function') {
        throw new Error(`crypto boundary names a method that does not exist: ${_name}`);
    }
    // Convert whatever was thrown; shared by both wrappers below.
    const _handle = function (self, err) {
        const out = (err && err.isTransportError)
            ? err                                    // keeps its own identity; see the exclusion
            : _coerceCryptoError(err, _code, _name);
        // Defensive: a method pulled off the instance and called unbound would leave `self`
        // undefined, and a boundary whose whole job is "no failure escapes uncoded" must not
        // become the thing that throws. Diagnose when we can; always return the coded failure.
        // Prefer the label the error already carries: a parse failure knows it was
        // `envelope.v1.kdf`, and the envelope contract promises that rule identity survives as a
        // diagnostic. Falling back to the method name would discard it at the last step.
        if (self && typeof self._diag === 'function') self._diag(out.operation || _name, out);
        return out;
    };

    // A SYNCHRONOUS method must stay synchronous. Two of these -- envelope and recovery-kit
    // parsing -- are called for their throw, inside a plain try/catch, with the result used on
    // the next line. An async wrapper would hand back a pending promise instead: the catch would
    // never fire, so the corrupt-envelope guard would pass everything, and the caller reading a
    // field off the result would get undefined. Detect and preserve.
    const _isAsync = _inner.constructor && _inner.constructor.name === 'AsyncFunction';

    Object.defineProperty(ECCCryptoLibrary.prototype, _name, {
        configurable: true,
        writable: true,
        value: _isAsync
            ? async function (...args) {
                try {
                    return await _inner.apply(this, args);
                } catch (err) {
                    throw _handle(this, err);
                }
            }
            : function (...args) {
                try {
                    return _inner.apply(this, args);
                } catch (err) {
                    throw _handle(this, err);
                }
            },
    });
}

// The code set and the error type travel with the class, so a `require` of this module and the
// classic-script global expose one shape. The default export is unchanged on purpose: seven test
// harnesses do `module.exports`-style construction against it.
ECCCryptoLibrary.CryptoError = CryptoError;
ECCCryptoLibrary.CODES = CRYPTO_ERROR_CODES;

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ECCCryptoLibrary;
}
