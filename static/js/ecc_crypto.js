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
    // Content and wraps need the same unsupported-vs-damaged split the envelope already has.
    // Without it, anything a newer build wrote is reported as damaged -- and "your file is
    // damaged" sends someone hunting for a backup, when the file is fine and the build is old.
    CONTENT_UNSUPPORTED: 'CONTENT_UNSUPPORTED',
    CONTENT_INVALID: 'CONTENT_INVALID',
    WRAP_UNSUPPORTED: 'WRAP_UNSUPPORTED',
    WRAP_INVALID: 'WRAP_INVALID',
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

        // --- version-2 envelope family -----------------------------------------------
        // Header: magic(4) version(1) purpose(1) reserved(2). A v2 DEK wrap is exactly 68
        // bytes -- 8 header + 12 nonce + 32 key + 16 tag -- against a legacy wrap's 40, and
        // both are fixed, which is what lets a reader dispatch on length before parsing.
        this.V2_MAGIC = new Uint8Array([0x44, 0x56, 0x5A, 0x32]);  // "DVZ2"
        this.V2_VERSION = 0x02;
        this.V2_PURPOSE_DIRECT_DEK = 0x01;
        this.V2_PURPOSE_TEAM_DEK = 0x02;
        this.V2_PURPOSE_TEAM_PRIV = 0x03;
        this.V2_DIRECT_WRAP_BYTES = 68;
        // A team private key is a PKCS8 blob, so unlike the two DEK wraps this payload has no
        // fixed size. Bounded on both sides instead: below the floor it cannot be this format
        // at all, and the ceiling is forty times a P-384 key with room to spare.
        this.V2_TEAMPRIV_MIN_BYTES = 36;   // 8 header + 12 nonce + 16 tag, empty plaintext
        this.V2_TEAMPRIV_MAX_BYTES = 8192;
        this.V2_HKDF_SALT = new TextEncoder().encode('dockvault-zk-envelope-v2-salt-01');
        this.V2_INFO_DEK_DIRECT = 'dockvault-zk-dek-direct-v2';
        this.V2_INFO_DEK_TEAM = 'dockvault-zk-dek-team-v2';
        this.V2_INFO_TEAMPRIV = 'dockvault-zk-teampriv-v2';

        // Content framing. Unlike the three wraps, a file is many independently authenticated
        // chunks under one derived key, so it carries its own 28-byte header before the first
        // of them: the 8 shared bytes, the chunk size, and 16 bytes naming the encryption
        // attempt that produced it.
        this.V2_PURPOSE_CONTENT = 0x04;
        this.V2_INFO_CONTENT = 'dockvault-zk-content-v2';
        this.V2_CONTENT_HEADER_BYTES = 28;      // 8 shared + 4 chunk size + 16 attempt token
        this.V2_CONTENT_CHUNK_OVERHEAD = 28;    // 12-byte nonce + 16-byte tag, per chunk
        // The smallest possible file is the header plus one empty chunk. Anything shorter is
        // not a short file, it is not this format.
        this.V2_CONTENT_MIN_BYTES = 56;
        // The floor keeps the per-chunk overhead from dominating and puts the nonce-collision
        // budget beyond any realistic object; the ceiling is the largest transport chunk in
        // use, so an implementer may align the two without the grammar forbidding it.
        this.V2_CONTENT_CHUNK_MIN = 4096;
        this.V2_CONTENT_CHUNK_MAX = 8388608;

        // The v2 WRITER is off by default, same mechanism and same reasoning as the envelope
        // above -- but the blast radius is larger. That envelope is read only by the account
        // that wrote it; a DEK wrap is minted by one member's browser and read by others. One
        // user on a v2-writing build performing one rekey locks out every member still on an
        // older bundle, and there is no server-side recovery. Readers accept v2 regardless,
        // which is what makes shipping them first useful.
        //
        // BEFORE ENABLING THIS, an operator needs all of the following to be true:
        //   * every browser that will read this deployment's vaults is serving a bundle whose
        //     reader understands v2 -- the cache-buster in the page's script tags is how you
        //     force that, and a tab left open since before the upgrade is the case that bites;
        //   * the server writes the matching algorithm label. It does not yet: the canonical
        //     write constant in app/core/key_wrap_algorithms.py is still the v1 label, so
        //     turning this on alone would store v2 bytes under a name that says otherwise.
        //     That is a second, independent one-line change and it belongs in the same commit.
        // There is no way back: once a v2 wrap exists, a reader that predates it cannot open
        // the vault and the server holds nothing it could re-wrap from.
        this.ZK_WRAP_WRITE_V2 = false;

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
     * Build the version-2 direct-DEK header, HKDF info, and AAD from one place.
     *
     * They have to agree field-for-field, and the surest way to make that true is to have a
     * single function that cannot produce one without the other.
     *
     * Encoding is fixed-width by rule: UUIDs as their 36-byte lowercase hyphenated ASCII form
     * (never the raw 16-byte form -- a different grammar in this product uses that, and mixing
     * them is a footgun), epochs as 4-byte big-endian. Injectivity comes from those fixed widths
     * alone; the 0x00 separators are readability, not delimiters, since the integer encoding is
     * full of zero bytes.
     * @private
     */
    _v2DirectTranscript(vaultId, recipientUserId, dekEpoch) {
        const enc = new TextEncoder();
        // The same three encoders every construction uses. They were inline here once, when
        // this was the only construction; two copies of a canonical encoding means a future
        // tightening of one silently forks this wrap from the others.
        const header = this._v2Header(this.V2_PURPOSE_DIRECT_DEK);
        const z = new Uint8Array([0]);
        const context = this._concatBytes([
            this._v2Uuid(vaultId, 'v2Transcript.uuid'), z,
            this._v2Uuid(recipientUserId, 'v2Transcript.uuid'), z,
            this._v2Epoch(dekEpoch, 'v2Transcript.epoch'),
        ]);
        return {
            header,
            info: this._concatBytes([enc.encode(this.V2_INFO_DEK_DIRECT), z, context]),
            aad: this._concatBytes([header, context]),
        };
    }

    /** @private */
    _concatBytes(parts) {
        let n = 0;
        for (const p of parts) n += p.length;
        const out = new Uint8Array(n);
        let o = 0;
        for (const p of parts) { out.set(p, o); o += p.length; }
        return out;
    }

    /**
     * Derive the version-2 wrapping key. Distinct from _deriveWrappingKey in every input --
     * different salt, different info, and an AES-GCM key rather than an AES-KW one -- so the two
     * cannot be confused for each other even though both start from an ECDH shared secret.
     * @private
     */
    async _deriveV2WrappingKey(sharedSecretBits, info) {
        const base = await this._subtle().importKey('raw', sharedSecretBits, 'HKDF', false, ['deriveKey']);
        return this._subtle().deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt: this.V2_HKDF_SALT, info },
            base,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Wrap a vault DEK to a recipient in the version-2 format.
     *
     * A NEW method rather than a change to wrapVaultDEK, and that is not tidiness: the legacy
     * helper's own output is pinned byte-for-byte by the frozen DIRECT-wrap vector, and it is
     * also the writer that every hierarchical vault still holds wraps from, because the newer
     * team writers are gated off. (Those team wraps have no pinned vector of their own -- the
     * team fixture covers a different function -- so that second reason rests on the stored
     * data, not on a test.)
     */
    async wrapVaultDEKV2(vaultDEK, recipientPublicKey, context) {
        const { vaultId, recipientUserId, dekEpoch } = context || {};
        const t = this._v2DirectTranscript(vaultId, recipientUserId, dekEpoch);
        try {
            const ephemeral = await this._subtle().generateKey(
                { name: 'ECDH', namedCurve: this.CURVE }, true, ['deriveBits']);
            const shared = await this._subtle().deriveBits(
                { name: 'ECDH', public: recipientPublicKey }, ephemeral.privateKey, 384);
            const key = await this._deriveV2WrappingKey(shared, t.info);
            const raw = await this._subtle().exportKey('raw', vaultDEK);
            const nonce = this._randomBytes(12);
            const ct = await this._subtle().encrypt(
                { name: 'AES-GCM', iv: nonce, additionalData: t.aad, tagLength: 128 }, key, raw);
            const out = this._concatBytes([t.header, nonce, new Uint8Array(ct)]);
            if (out.length !== this.V2_DIRECT_WRAP_BYTES) {
                // Cannot happen with a 32-byte DEK; if it ever does, a wrap of the wrong length
                // would be rejected by every reader, so fail here where the cause is visible.
                this._fail(CRYPTO_ERROR_CODES.WRAP_FAILED, 'wrapVaultDEKV2.length');
            }
            const ephRaw = await this._subtle().exportKey('raw', ephemeral.publicKey);
            return {
                wrappedDEK: this._arrayBufferToBase64(out.buffer),
                ephemeralPublicKey: this._arrayBufferToBase64(ephRaw),
            };
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.WRAP_FAILED, 'wrapVaultDEKV2');
        }
    }

    /**
     * Read a version-2 direct DEK wrap. Structural problems are rejected before any decryption is
     * attempted, so a malformed payload is never reported as a tampering signal.
     * @private
     */
    async _unwrapVaultDEKV2(wrappedBytes, ephemeralPublicKeyBase64, userPrivateKey, context) {
        const { vaultId, recipientUserId, dekEpoch } = context || {};
        if (wrappedBytes.length !== this.V2_DIRECT_WRAP_BYTES) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.v2.length');
        }
        if (wrappedBytes[6] !== 0 || wrappedBytes[7] !== 0) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.v2.reserved');
        }
        const ephBytes = new Uint8Array(this._base64ToArrayBuffer(ephemeralPublicKeyBase64));
        // An uncompressed P-384 point is 97 bytes starting 0x04. Checked here rather than in the
        // shared import helper, which also serves the frozen team path and its compressed-point
        // branch.
        if (ephBytes.length !== 97 || ephBytes[0] !== 0x04) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.v2.point');
        }
        const t = this._v2DirectTranscript(vaultId, recipientUserId, dekEpoch);
        // Imported OUTSIDE the try: a point of the right length that is not on the curve is a
        // malformed input, and letting it fall into the catch below would report it as an
        // authentication failure -- telling an operator their grant was tampered with when it
        // was merely the wrong shape.
        let ephemeralPublicKey;
        try {
            ephemeralPublicKey = await this._importRawPublicKey(ephBytes.buffer);
        } catch (error) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.v2.curve');
        }
        try {
            const shared = await this._subtle().deriveBits(
                { name: 'ECDH', public: ephemeralPublicKey }, userPrivateKey, 384);
            const key = await this._deriveV2WrappingKey(shared, t.info);
            const nonce = wrappedBytes.slice(8, 20);
            const body = wrappedBytes.slice(20);
            const plain = await this._subtle().decrypt(
                { name: 'AES-GCM', iv: nonce, additionalData: t.aad, tagLength: 128 }, key, body);
            // AES-KW enforced a 32-byte result structurally; AES-GCM returns whatever it was
            // given. Without this check a writer bug or a hostile database row could hand back a
            // 16-byte "DEK" that importKey would accept as AES-128.
            if (plain.byteLength !== 32) {
                this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.v2.keylen');
            }
            return this._subtle().importKey('raw', plain, { name: 'AES-GCM', length: 256 },
                                            true, ['encrypt', 'decrypt']);
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.WRAP_FAILED, 'unwrapVaultDEK.v2');
        }
    }

    /**
     * Transcript for the team DEK wrap. The recipient is the vault's team keypair, which the key
     * agreement already binds, so there is no per-user field here -- one wrap serves every member,
     * which is the whole reason this mode exists.
     *
     * The epoch bound is the DEK epoch, not the team epoch. They are different columns on
     * different axes and only one of them can be bound: the rotating client proposes the DEK epoch
     * and the server verifies it under a lock, whereas the team epoch is assigned server-side and
     * a writer cannot know the value its row will carry.
     * @private
     */
    _v2TeamDekTranscript(vaultId, dekEpoch) {
        const enc = new TextEncoder();
        const header = this._v2Header(this.V2_PURPOSE_TEAM_DEK);
        const context = this._concatBytes([
            this._v2Uuid(vaultId, 'v2TeamDek.vault'), new Uint8Array([0]),
            this._v2Epoch(dekEpoch, 'v2TeamDek.epoch'),
        ]);
        return {
            header,
            info: this._concatBytes([enc.encode(this.V2_INFO_DEK_TEAM), new Uint8Array([0]), context]),
            aad: this._concatBytes([header, context]),
        };
    }

    /**
     * Transcript for the team PRIVATE key wrap. This one does bind a recipient: it is wrapped to a
     * specific member, and both ends can name that member.
     *
     * No epoch. The team epoch is the only one that would mean anything here, and it is the one the
     * server assigns.
     * @private
     */
    _v2TeamPrivTranscript(vaultId, recipientUserId) {
        const enc = new TextEncoder();
        const header = this._v2Header(this.V2_PURPOSE_TEAM_PRIV);
        const context = this._concatBytes([
            this._v2Uuid(vaultId, 'v2TeamPriv.vault'), new Uint8Array([0]),
            this._v2Uuid(recipientUserId, 'v2TeamPriv.recipient'),
        ]);
        return {
            header,
            info: this._concatBytes([enc.encode(this.V2_INFO_TEAMPRIV), new Uint8Array([0]), context]),
            aad: this._concatBytes([header, context]),
        };
    }

    /** @private */
    _v2Header(purpose) {
        const header = new Uint8Array(8);
        header.set(this.V2_MAGIC, 0);
        header[4] = this.V2_VERSION;
        header[5] = purpose;
        return header;  // bytes 6-7 stay zero; a reader rejects anything else
    }

    /** @private */
    _v2Uuid(value, where, code) {
        const s = String(value == null ? '' : value).toLowerCase();
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s)) {
            // Wrap-shaped by default, because every caller until now was one. Content passes
            // INVALID_INPUT instead: telling someone to ask an owner to re-share the vault is
            // the right advice about a broken key wrap and the wrong advice about a file.
            this._fail(code || CRYPTO_ERROR_CODES.WRAP_INVALID, where);
        }
        return new TextEncoder().encode(s);
    }

    /**
     * Eight bytes, big-endian, unsigned. Zero is valid -- an empty file has zero plaintext.
     *
     * Assembled from two 32-bit halves because this module has no 64-bit integer writer and no
     * BigInt anywhere; `Number.MAX_SAFE_INTEGER` is the honest ceiling, and it is four orders of
     * magnitude above any object this product will store.
     * @private
     */
    _v2U64(value, where, code) {
        const n = (typeof value === 'number' || typeof value === 'string') ? Number(value) : NaN;
        if (!Number.isInteger(n) || n < 0 || n > Number.MAX_SAFE_INTEGER) {
            this._fail(code || CRYPTO_ERROR_CODES.WRAP_INVALID, where);
        }
        const out = new Uint8Array(8);
        const view = new DataView(out.buffer);
        view.setUint32(0, Math.floor(n / 0x100000000), false);
        view.setUint32(4, n >>> 0, false);
        return out;
    }

    /** One byte, 0x00 or 0x01. No other value is ever emitted. @private */
    _v2Flag(value) {
        return new Uint8Array([value ? 0x01 : 0x00]);
    }

    /**
     * The attempt token, passed through as 16 RAW bytes.
     *
     * Section 4.1's "UUIDs are never the raw 16-byte form" rule does not reach this: it is not a
     * uuid, it has no textual form, and the header it sits in is fixed-width. Encoding it as text
     * would produce a 48-byte header nothing else can read.
     * @private
     */
    _v2BlobId(bytes, where) {
        const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
        if (b.length !== 16) {
            this._fail(CRYPTO_ERROR_CODES.INVALID_INPUT, where);
        }
        return b;
    }

    /**
     * The content transcript: one 28-byte file header, one `info` for the key derivation, and a
     * function producing the per-chunk AAD.
     *
     * The three wrap builders each return a single `aad`, because their payload is one sealed
     * blob. Content cannot: every chunk binds its own index and whether it is the last, and the
     * last one also binds the totals. What must not change is the reason those builders return
     * both channels from one place -- `info` and `aad` are built from the SAME `context` bytes, so
     * they cannot drift. `aadFor` closes over that same `context`, which is why it lives in here
     * rather than as a free function taking the fields again.
     * @private
     */
    _v2ContentTranscript(vaultId, objectId, dekEpoch, chunkSize, blobIdBytes) {
        const W = 'content.transcript';
        const BAD = CRYPTO_ERROR_CODES.INVALID_INPUT;
        const size = Number(chunkSize);
        if (!Number.isInteger(size)
                || size < this.V2_CONTENT_CHUNK_MIN || size > this.V2_CONTENT_CHUNK_MAX) {
            this._fail(BAD, W + '.chunkSize');
        }
        const blob = this._v2BlobId(blobIdBytes, W + '.blobId');

        const sizeBytes = new Uint8Array(4);
        new DataView(sizeBytes.buffer).setUint32(0, size, false);
        const fileHeader = this._concatBytes([
            this._v2Header(this.V2_PURPOSE_CONTENT), sizeBytes, blob,
        ]);

        const z = new Uint8Array([0]);
        const context = this._concatBytes([
            this._v2Uuid(vaultId, W + '.vaultId', BAD), z,
            this._v2Uuid(objectId, W + '.objectId', BAD), z,
            this._v2Epoch(dekEpoch, W + '.dekEpoch', BAD),
        ]);

        const enc = new TextEncoder();
        return {
            fileHeader,
            info: this._concatBytes([enc.encode(this.V2_INFO_CONTENT), z, context, z, blob]),
            aadFor: (index, isFinal, totals) => {
                const parts = [
                    fileHeader, context,
                    this._v2U64(index, W + '.index', BAD),
                    this._v2Flag(isFinal),
                ];
                if (isFinal) {
                    // Only the last chunk carries them. Putting them in every chunk would force a
                    // writer to know the length before it writes anything, which forecloses a
                    // streaming producer; truncation is still caught, because a truncated stream
                    // simply never reaches a chunk that claims to be the last.
                    parts.push(this._v2U64(totals.totalChunks, W + '.totalChunks', BAD));
                    parts.push(this._v2U64(totals.totalPlaintext, W + '.totalPlaintext', BAD));
                }
                return this._concatBytes(parts);
            },
        };
    }

    /**
     * One content key per file, never per chunk.
     *
     * The DEK arrives as a non-extractable-by-habit CryptoKey, so it is exported to raw bytes to
     * seed HKDF -- the same thing `nameBlindIndex` does, for the same reason.
     * @private
     */
    async _deriveV2ContentKey(dekCryptoKey, info) {
        const raw = await this._subtle().exportKey('raw', dekCryptoKey);
        return this._deriveV2WrappingKey(raw, info);
    }

    /** @private */
    _v2Epoch(value, where, code) {
        const epoch = (typeof value === 'number' || typeof value === 'string') ? Number(value) : NaN;
        if (!Number.isInteger(epoch) || epoch < 1 || epoch > 0x7FFFFFFF) {
            this._fail(code || CRYPTO_ERROR_CODES.WRAP_INVALID, where);
        }
        const out = new Uint8Array(4);
        new DataView(out.buffer).setUint32(0, epoch, false);
        return out;
    }

    /**
     * Wrap a vault DEK to the vault's TEAM public key, version 2.
     *
     * A new method, not a change to wrapVaultDEK. That helper writes the legacy form of both this
     * and the direct wrap, and its bytes are pinned.
     */
    async wrapTeamDEKV2(vaultDEK, teamPublicKey, context) {
        const { vaultId, dekEpoch } = context || {};
        const t = this._v2TeamDekTranscript(vaultId, dekEpoch);
        try {
            const out = await this._v2SealToPublicKey(vaultDEK, teamPublicKey, t, true);
            return out;
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.WRAP_FAILED, 'wrapTeamDEKV2');
        }
    }

    /**
     * Wrap the team PRIVATE key to one member's public key, version 2.
     */
    async wrapTeamPrivateKeyV2(teamPrivateKey, recipientPublicKey, context) {
        const { vaultId, recipientUserId } = context || {};
        const t = this._v2TeamPrivTranscript(vaultId, recipientUserId);
        try {
            const pkcs8 = await this._subtle().exportKey('pkcs8', teamPrivateKey);
            const sealed = await this._v2SealBytes(new Uint8Array(pkcs8), recipientPublicKey, t);
            if (sealed.bytes.length > this.V2_TEAMPRIV_MAX_BYTES) {
                this._fail(CRYPTO_ERROR_CODES.WRAP_FAILED, 'wrapTeamPrivateKeyV2.length');
            }
            return {
                wrappedKey: this._arrayBufferToBase64(sealed.bytes.buffer),
                ephemeralPublicKey: sealed.ephemeralPublicKey,
            };
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.WRAP_FAILED, 'wrapTeamPrivateKeyV2');
        }
    }

    /**
     * Shared sealing: fresh ephemeral, agree with the recipient, derive under the transcript's
     * info, encrypt under its aad. Returns raw bytes plus the exported ephemeral point.
     * @private
     */
    async _v2SealBytes(plaintext, recipientPublicKey, t) {
        const ephemeral = await this._subtle().generateKey(
            { name: 'ECDH', namedCurve: this.CURVE }, true, ['deriveBits']);
        const shared = await this._subtle().deriveBits(
            { name: 'ECDH', public: recipientPublicKey }, ephemeral.privateKey, 384);
        const key = await this._deriveV2WrappingKey(shared, t.info);
        const nonce = this._randomBytes(12);
        const ct = await this._subtle().encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: t.aad, tagLength: 128 }, key, plaintext);
        const ephRaw = await this._subtle().exportKey('raw', ephemeral.publicKey);
        return {
            bytes: this._concatBytes([t.header, nonce, new Uint8Array(ct)]),
            ephemeralPublicKey: this._arrayBufferToBase64(ephRaw),
        };
    }

    /** @private */
    async _v2SealToPublicKey(cryptoKey, recipientPublicKey, t, fixedLength) {
        const raw = await this._subtle().exportKey('raw', cryptoKey);
        const sealed = await this._v2SealBytes(new Uint8Array(raw), recipientPublicKey, t);
        if (fixedLength && sealed.bytes.length !== this.V2_DIRECT_WRAP_BYTES) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_FAILED, 'v2Seal.length');
        }
        return {
            wrappedDEK: this._arrayBufferToBase64(sealed.bytes.buffer),
            ephemeralPublicKey: sealed.ephemeralPublicKey,
        };
    }

    /**
     * Open a version-2 payload. Structural faults are rejected before any key agreement, so a
     * malformed input is never reported as an authentication failure.
     * @private
     */
    async _v2Open(wrapBytes, ephemeralPublicKeyBase64, privateKey, t, where) {
        if (wrapBytes[6] !== 0 || wrapBytes[7] !== 0) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, where + '.reserved');
        }
        const ephBytes = new Uint8Array(this._base64ToArrayBuffer(ephemeralPublicKeyBase64));
        if (ephBytes.length !== 97 || ephBytes[0] !== 0x04) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, where + '.point');
        }
        let ephemeralPublicKey;
        try {
            ephemeralPublicKey = await this._importRawPublicKey(ephBytes.buffer);
        } catch (error) {
            // On the right curve or not is a shape question, not an authentication one.
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, where + '.curve');
        }
        const shared = await this._subtle().deriveBits(
            { name: 'ECDH', public: ephemeralPublicKey }, privateKey, 384);
        const key = await this._deriveV2WrappingKey(shared, t.info);
        return this._subtle().decrypt(
            { name: 'AES-GCM', iv: wrapBytes.slice(8, 20), additionalData: t.aad, tagLength: 128 },
            key, wrapBytes.slice(20));
    }

    /**
     * Read a version-2 team DEK wrap. Opened with the team PRIVATE key, not the member's own.
     * @private
     */
    async _unwrapTeamDEKV2(wrapBytes, ephemeralPublicKeyBase64, teamPrivateKey, context) {
        const { vaultId, dekEpoch } = context || {};
        if (wrapBytes.length !== this.V2_DIRECT_WRAP_BYTES) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapTeamDEK.v2.length');
        }
        const t = this._v2TeamDekTranscript(vaultId, dekEpoch);
        try {
            const plain = await this._v2Open(wrapBytes, ephemeralPublicKeyBase64,
                                             teamPrivateKey, t, 'unwrapTeamDEK.v2');
            // The wrapping used to be a key-wrap primitive that could only ever yield 32 bytes.
            // Authenticated encryption returns whatever it was given, so a writer bug or a hostile
            // row could otherwise hand back a short "key" that imports happily at half strength.
            if (plain.byteLength !== 32) {
                this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapTeamDEK.v2.keylen');
            }
            return this._subtle().importKey('raw', plain, { name: 'AES-GCM', length: 256 },
                                            true, ['encrypt', 'decrypt']);
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.WRAP_FAILED, 'unwrapTeamDEK.v2');
        }
    }

    /**
     * Read a version-2 team PRIVATE key wrap.
     *
     * This payload has no fixed length, so length cannot discriminate it from the legacy form the
     * way it can for the two DEK wraps -- the whole header has to validate instead, and the size
     * is merely bounded on both sides before anything is allocated.
     * @private
     */
    async _unwrapTeamPrivateKeyV2(wrapBytes, ephemeralPublicKeyBase64, memberPrivateKey,
                                  context, extractable) {
        const { vaultId, recipientUserId } = context || {};
        if (wrapBytes.length < this.V2_TEAMPRIV_MIN_BYTES
            || wrapBytes.length > this.V2_TEAMPRIV_MAX_BYTES) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapTeamPriv.v2.length');
        }
        const t = this._v2TeamPrivTranscript(vaultId, recipientUserId);
        try {
            const pkcs8 = await this._v2Open(wrapBytes, ephemeralPublicKeyBase64,
                                             memberPrivateKey, t, 'unwrapTeamPriv.v2');
            // Least privilege: this key exists only to agree with an ephemeral and open the
            // vault DEK, so key agreement is its only permitted use and it is non-extractable
            // by default. Every cached copy is a default one.
            //
            // `extractable` is the caller's to ask for, and exactly one caller does: re-sharing
            // a team key to a new member means exporting it to wrap for them, which cannot be
            // done with a key that will not leave the browser. That copy is a local in one
            // function and is never cached. Any new caller passing true needs the same
            // justification, in writing, at its own call site.
            return this._subtle().importKey(
                'pkcs8', pkcs8, { name: 'ECDH', namedCurve: this.CURVE }, extractable, ['deriveBits']);
        } catch (error) {
            throw _coerceCryptoError(error, CRYPTO_ERROR_CODES.WRAP_FAILED, 'unwrapTeamPriv.v2');
        }
    }

    /**
     * Report whether these bytes announce themselves as a version-2 envelope, and if so whether
     * this build could ever read them.
     *
     * Returns null for anything that is not a v2 payload, so a caller can fall through to its
     * existing legacy handling. Returns a code otherwise:
     *
     *   UNSUPPORTED — a well-formed v2 header. This is a statement about the HEADER, not a
     *                 verdict: one purpose (direct DEK) is now readable, and that caller
     *                 checks the purpose itself. A caller that reads no v2 purpose can still
     *                 treat it as "the payload is fine and this build is behind".
     *   INVALID     — the marker is present but the header is malformed, so it is not a payload
     *                 from the future, it is not a payload at all.
     *
     * The distinction matters because the two send a person somewhere different: one to the
     * update notes, the other to a backup.
     * @private
     */
    _inspectV2Header(bytes) {
        const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
        if (b.length < 8) return null;
        // "DVZ2"
        if (b[0] !== 0x44 || b[1] !== 0x56 || b[2] !== 0x5A || b[3] !== 0x32) return null;
        const version = b[4];
        const purpose = b[5];
        const reserved = (b[6] << 8) | b[7];
        // Reserved bytes are a breaking-change channel, not an extension channel: a non-zero
        // value means bytes this build cannot reason about, so it is malformed rather than new.
        if (reserved !== 0) return 'INVALID';
        if (purpose < 0x01 || purpose > 0x04) return 'INVALID';
        // Any version, including a future one, is "we recognise this and cannot read it".
        if (version < 0x02) return 'INVALID';
        return 'UNSUPPORTED';
    }

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
    async unwrapVaultDEK(wrappedDEKBase64, ephemeralPublicKeyBase64, userPrivateKey, context) {
        const wrapBytes = new Uint8Array(this._base64ToArrayBuffer(wrappedDEKBase64));
        // Dispatch on LENGTH first. Both formats are fixed size -- 68 for v2, 40 for the
        // legacy RFC 3394 wrap of a 32-byte key -- and that is what keeps a legacy wrap whose
        // random leading bytes happen to spell a v2 header from being committed to the wrong
        // reader. Getting that wrong costs a member their access permanently, because no
        // server-side re-wrap exists.
        if (wrapBytes.length === this.V2_DIRECT_WRAP_BYTES) {
            const wrapV2 = this._inspectV2Header(wrapBytes);
            if (wrapV2 !== 'UNSUPPORTED') {
                // Right length, but the header does not validate: malformed, not from the
                // future, and not something to hand to the legacy reader either.
                this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.v2');
            }
            // The version on the WIRE, not the one we would reconstruct. The transcript is
            // built from canonical bytes, so this field is the one part of the header the AAD
            // does not actually pin -- without this check a wrap relabelled to any other
            // version decrypts happily under the v2 grammar.
            if (wrapBytes[4] !== this.V2_VERSION) {
                this._fail(CRYPTO_ERROR_CODES.WRAP_UNSUPPORTED, 'unwrapVaultDEK.v2.version');
            }
            if (!context) {
                // The transcript inputs are not optional for v2. Reaching here means a caller
                // was not updated; say so structurally rather than letting it surface as an
                // authentication failure, which reads as tampering.
                this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.v2.context');
            }
            // Which purpose is acceptable is the CALLER's statement, not the payload's. A
            // hierarchical read passes the team private key and expects a team-DEK wrap; a
            // direct read passes the member's own key and expects a direct one. Reading the
            // purpose off the wire to pick a transcript is exactly the steering the header's
            // authentication denies -- so compare, never select.
            const expected = context.teamMode
                ? this.V2_PURPOSE_TEAM_DEK : this.V2_PURPOSE_DIRECT_DEK;
            if (wrapBytes[5] !== expected) {
                this._fail(CRYPTO_ERROR_CODES.WRAP_UNSUPPORTED, 'unwrapVaultDEK.v2.purpose');
            }
            // Committed to v2 from here. A tag failure is NOT retried as legacy -- retrying is
            // what turns a tampering signal into a parser oracle.
            if (context.teamMode) {
                return this._unwrapTeamDEKV2(wrapBytes, ephemeralPublicKeyBase64,
                                             userPrivateKey, context);
            }
            return this._unwrapVaultDEKV2(wrapBytes, ephemeralPublicKeyBase64, userPrivateKey, context);
        }
        if (wrapBytes.length !== 40) {
            // Neither format. Saying so is better than letting AES-KW fail on it and calling
            // the result damaged.
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapVaultDEK.length');
        }
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
    async unwrapPrivateKeyFromWrapped(wrappedKeyBase64, ephemeralPublicKeyBase64, memberPrivateKey, extractable = false, context = null) {
        // Judge the size BEFORE materialising it. Base64 is four characters per three bytes,
        // so the encoded length bounds the decoded one without decoding anything -- and a
        // ceiling applied after the decode has already let a hostile server hand us as much
        // memory as it liked.
        if (typeof wrappedKeyBase64 === 'string'
            && wrappedKeyBase64.length > 4 * Math.ceil(this.V2_TEAMPRIV_MAX_BYTES / 3)) {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapPrivateKeyFromWrapped.size');
        }
        const wrapBytes = new Uint8Array(this._base64ToArrayBuffer(wrappedKeyBase64));
        const teamV2 = this._inspectV2Header(wrapBytes);
        if (teamV2 === 'INVALID') {
            this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID, 'unwrapPrivateKeyFromWrapped.v2');
        }
        if (teamV2 === 'UNSUPPORTED') {
            if (wrapBytes[4] !== this.V2_VERSION
                || wrapBytes[5] !== this.V2_PURPOSE_TEAM_PRIV) {
                this._fail(CRYPTO_ERROR_CODES.WRAP_UNSUPPORTED,
                           'unwrapPrivateKeyFromWrapped.v2.purpose');
            }
            if (!context) {
                this._fail(CRYPTO_ERROR_CODES.WRAP_INVALID,
                           'unwrapPrivateKeyFromWrapped.v2.context');
            }
            return this._unwrapTeamPrivateKeyV2(wrapBytes, ephemeralPublicKeyBase64,
                                                memberPrivateKey, context, extractable);
        }
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
    /**
     * Read a version-2 chunk-framed file.
     *
     * The framing is parsed from the stored LENGTH, not from a count on the wire. Successive chunk
     * counts occupy disjoint length windows separated by a 28-byte gap, and a zero-length final
     * chunk is forbidden except for the empty file, so exactly one (count, length) pair can
     * explain any valid input -- and a length in one of the gaps explains none, which is why the
     * check at step 4 is not optional.
     *
     * Nothing is handed back until the chunk marked final has authenticated. Each chunk
     * authenticates on its own, so a truncated file decrypts perfectly up to the cut; the only
     * thing that reveals the cut is the absent terminator. Releasing bytes as they verify would
     * mean handing over attacker-chosen-length output and detecting it afterwards.
     */
    async decryptFileV2(encryptedContent, vaultDEK, context) {
        const W = 'decryptFileV2';
        const bytes = encryptedContent instanceof Uint8Array
            ? encryptedContent : new Uint8Array(encryptedContent || []);
        const L = bytes.length;
        if (L < this.V2_CONTENT_MIN_BYTES) {
            this._fail(CRYPTO_ERROR_CODES.CONTENT_INVALID, W + '.length');
        }

        const H = this.V2_CONTENT_HEADER_BYTES;
        const O = this.V2_CONTENT_CHUNK_OVERHEAD;
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const chunkSize = view.getUint32(8, false);
        if (chunkSize < this.V2_CONTENT_CHUNK_MIN || chunkSize > this.V2_CONTENT_CHUNK_MAX) {
            this._fail(CRYPTO_ERROR_CODES.CONTENT_INVALID, W + '.chunkSize');
        }
        const blobId = bytes.slice(12, 28);

        const S = chunkSize + O;                 // a full chunk's stored size
        const M = L - H;                         // everything after the header
        const n = Math.max(1, Math.ceil(M / S));
        const last = M - (n - 1) * S;            // the final chunk's stored size
        // A valid final chunk holds between one and chunkSize plaintext bytes -- or zero, and then
        // only when it is also the first. Every length in the gap between two chunk counts fails
        // here rather than producing a confident wrong answer.
        if (last < O || last > S || (last === O && n !== 1)) {
            this._fail(CRYPTO_ERROR_CODES.CONTENT_INVALID, W + '.framing');
        }
        const totalPlaintext = (n - 1) * chunkSize + (last - O);

        const ctx = context || {};
        const t = this._v2ContentTranscript(
            ctx.vaultId, ctx.objectId, ctx.dekEpoch, chunkSize, blobId);
        // The header this reader authenticates is REBUILT -- a constant purpose byte plus the
        // chunk size and attempt token parsed out of the input -- so the AAD says nothing
        // about the magic, the version, the purpose or the reserved bytes as they actually
        // arrived. This comparison is the only thing that does.
        //
        // Called through `decryptFile` the seam has already checked those four, so removing
        // this loop changes nothing and it reads as redundant. It is not: this method is
        // public, a streaming reader is the caller this grammar exists for, and called
        // directly with the loop gone a file relabelled to any version or purpose decrypts.
        for (let i = 0; i < H; i++) {
            if (bytes[i] !== t.fileHeader[i]) {
                this._fail(CRYPTO_ERROR_CODES.CONTENT_INVALID, W + '.header');
            }
        }

        // Once per file. Deriving per chunk would be correct and ruinous.
        const key = await this._deriveV2ContentKey(vaultDEK, t.info);

        const out = new Uint8Array(totalPlaintext);
        let written = 0;
        for (let i = 0; i < n; i++) {
            const start = H + i * S;
            const end = (i === n - 1) ? L : start + S;
            const isFinal = (i === n - 1);
            let plain;
            try {
                plain = await this._subtle().decrypt(
                    {
                        name: this.AES_ALGORITHM,
                        iv: bytes.slice(start, start + 12),
                        additionalData: t.aadFor(i, isFinal,
                            { totalChunks: n, totalPlaintext }),
                    },
                    key,
                    bytes.slice(start + 12, end),
                );
            } catch (e) {
                this._fail(CRYPTO_ERROR_CODES.CONTENT_AUTH_FAILED, W + '.chunk', e);
            }
            const p = new Uint8Array(plain);
            // A chunk that authenticates but is the wrong length means the writer and this reader
            // disagree about the framing, which the length arithmetic above should have caught.
            if (p.length !== (isFinal ? last - O : chunkSize)) {
                this._fail(CRYPTO_ERROR_CODES.CONTENT_INVALID, W + '.chunkLength');
            }
            out.set(p, written);
            written += p.length;
        }
        return out.buffer;
    }

    async decryptFile(encryptedContent, vaultDEK, context) {
        // Before anything else: is this a format from a newer build? Saying "damaged" about an
        // intact file is the failure this check exists to prevent.
        const contentV2 = this._inspectV2Header(encryptedContent);
        if (contentV2) {
            const b = encryptedContent instanceof Uint8Array
                ? encryptedContent : new Uint8Array(encryptedContent || []);
            // The one recognised shape this build can now read. Everything else keeps the
            // answer it had: a recognised header we cannot handle is 'saved by a newer
            // version', which is true and actionable, and a malformed one is still damage.
            //
            // The purpose byte selects a reader here, and ONLY here. Inside that reader the
            // transcript is built from what the caller expects, never from what the wire
            // says -- a reader that picked its own transcript off the wire would satisfy
            // every other rule in this family and lose the property it exists for.
            if (contentV2 === 'UNSUPPORTED'
                    && b[4] === this.V2_VERSION && b[5] === this.V2_PURPOSE_CONTENT) {
                return this.decryptFileV2(b, vaultDEK, context);
            }
            this._fail(contentV2 === 'UNSUPPORTED'
                ? CRYPTO_ERROR_CODES.CONTENT_UNSUPPORTED
                : CRYPTO_ERROR_CODES.CONTENT_INVALID, 'decryptFile.v2');
        }
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
    wrapVaultDEKV2: CRYPTO_ERROR_CODES.WRAP_FAILED,
    wrapTeamDEKV2: CRYPTO_ERROR_CODES.WRAP_FAILED,
    wrapTeamPrivateKeyV2: CRYPTO_ERROR_CODES.WRAP_FAILED,
    wrapPrivateKeyToPublic: CRYPTO_ERROR_CODES.WRAP_FAILED,
    unwrapPrivateKeyFromWrapped: CRYPTO_ERROR_CODES.WRAP_FAILED,

    // Vault-key-encrypted content. The user supplied no secret to reach here, so a failure is
    // never a passphrase problem and must never be reported as one.
    decryptFile: CRYPTO_ERROR_CODES.CONTENT_AUTH_FAILED,
    decryptFileV2: CRYPTO_ERROR_CODES.CONTENT_AUTH_FAILED,
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
