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

        // Verbose per-operation logging — off in production (flip to debug).
        this.DEBUG = false;
        if (this.DEBUG) console.log('🔐 ECC Crypto Library initialized (P-384)');
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
            const keypair = await window.crypto.subtle.generateKey(
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                true, // extractable
                this.KEY_USAGES_PRIVATE
            );
            
            console.log('✅ Generated ECC P-384 keypair');
            return keypair;
        } catch (error) {
            console.error('❌ Keypair generation failed:', error);
            throw new Error(`Failed to generate keypair: ${error.message}`);
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
            const exported = await window.crypto.subtle.exportKey('spki', publicKey);
            const base64 = this._arrayBufferToBase64(exported);
            const pem = this._formatPEM(base64, 'PUBLIC KEY');
            
            console.log('✅ Exported public key to PEM');
            return pem;
        } catch (error) {
            console.error('❌ Public key export failed:', error);
            throw new Error(`Failed to export public key: ${error.message}`);
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
            const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);
            const base64 = this._arrayBufferToBase64(exported);
            const pem = this._formatPEM(base64, 'PRIVATE KEY');
            
            console.log('⚠️  Exported UNENCRYPTED private key to PEM');
            return pem;
        } catch (error) {
            console.error('❌ Private key export failed:', error);
            throw new Error(`Failed to export private key: ${error.message}`);
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
            
            const publicKey = await window.crypto.subtle.importKey(
                'spki',
                der,
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                true,
                []
            );
            
            console.log('✅ Imported public key from PEM');
            return publicKey;
        } catch (error) {
            console.error('❌ Public key import failed:', error);
            throw new Error(`Failed to import public key: ${error.message}`);
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
            const privateKey = await window.crypto.subtle.importKey(
                'pkcs8',
                der,
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                extractable,
                this.KEY_USAGES_PRIVATE
            );

            if (this.DEBUG) console.log('✅ Imported private key from PEM');
            return privateKey;
        } catch (error) {
            console.error('❌ Private key import failed:', error);
            throw new Error(`Failed to import private key: ${error.message}`);
        }
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
            const salt = window.crypto.getRandomValues(new Uint8Array(this.PBKDF2_SALT_LENGTH));
            
            // Derive AES key from password
            const passwordKey = await this._deriveKeyFromPassword(password, salt);
            
            // Generate IV
            const iv = window.crypto.getRandomValues(new Uint8Array(this.AES_IV_LENGTH));
            
            // Encrypt private key PEM
            const privateKeyBytes = new TextEncoder().encode(privateKeyPEM);
            const encrypted = await window.crypto.subtle.encrypt(
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
            
            console.log('✅ Encrypted private key with password');
            
            return {
                encrypted: this._arrayBufferToBase64(combined),
                salt: this._arrayBufferToBase64(salt),
                iterations: this.PBKDF2_ITERATIONS
            };
        } catch (error) {
            console.error('❌ Private key encryption failed:', error);
            throw new Error(`Failed to encrypt private key: ${error.message}`);
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
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: this.AES_ALGORITHM,
                    iv: iv,
                    tagLength: this.AES_TAG_LENGTH
                },
                passwordKey,
                ciphertext
            );
            
            const privateKeyPEM = new TextDecoder().decode(decrypted);
            
            console.log('✅ Decrypted private key with password');
            return privateKeyPEM;
        } catch (error) {
            console.error('❌ Private key decryption failed:', error);
            throw new Error(`Failed to decrypt private key: ${error.message}`);
        }
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
            const sharedSecret = await window.crypto.subtle.deriveBits(
                { name: 'ECDH', public: ephemeralPublicKey },
                userPrivateKey,
                384 // P-384 produces a 384-bit shared secret
            );
            const wrappingKey = await this._deriveWrappingKey(sharedSecret);
            const wrappedDEKBytes = this._base64ToArrayBuffer(wrappedDEKBase64);
            const vaultDEK = await this._unwrapKeyWithAESKW(wrappedDEKBytes, wrappingKey);

            if (this.DEBUG) console.log('✅ Unwrapped vault DEK successfully');
            return vaultDEK;
        } catch (error) {
            console.error('❌ Vault DEK unwrapping failed:', error);
            throw new Error(`Failed to unwrap vault DEK: ${error.message}`);
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
        const ephemeral = await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            true,                 // extractable: we export the ephemeral PUBLIC key
            ['deriveBits']
        );
        const sharedSecret = await window.crypto.subtle.deriveBits(
            { name: 'ECDH', public: recipientPublicKey },
            ephemeral.privateKey,
            384
        );
        const wrappingKey = await this._deriveWrappingKey(sharedSecret);
        const wrapped = await window.crypto.subtle.wrapKey('raw', vaultDEK, wrappingKey, { name: 'AES-KW' });
        const ephRaw = await window.crypto.subtle.exportKey('raw', ephemeral.publicKey); // uncompressed
        return {
            wrappedDEK: this._arrayBufferToBase64(wrapped),
            ephemeralPublicKey: this._arrayBufferToBase64(ephRaw),
        };
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
        const sharedSecretKey = await window.crypto.subtle.importKey(
            'raw', sharedSecretBits, 'HKDF', false, ['deriveKey']
        );
        return await window.crypto.subtle.deriveKey(
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
        const ephemeral = await window.crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE }, true, ['deriveBits']
        );
        const sharedSecret = await window.crypto.subtle.deriveBits(
            { name: 'ECDH', public: recipientPublicKey }, ephemeral.privateKey, 384
        );
        const wrappingKey = await this._deriveTeamPrivWrappingKey(sharedSecret);
        const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', teamPrivateKey);
        const iv = window.crypto.getRandomValues(new Uint8Array(this.AES_IV_LENGTH));
        const ct = await window.crypto.subtle.encrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH }, wrappingKey, pkcs8
        );
        const combined = new Uint8Array(iv.length + ct.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ct), iv.length);
        const ephRaw = await window.crypto.subtle.exportKey('raw', ephemeral.publicKey); // uncompressed
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
        const sharedSecret = await window.crypto.subtle.deriveBits(
            { name: 'ECDH', public: ephemeralPublicKey }, memberPrivateKey, 384
        );
        const wrappingKey = await this._deriveTeamPrivWrappingKey(sharedSecret);
        const raw = new Uint8Array(this._base64ToArrayBuffer(wrappedKeyBase64));
        const iv = raw.slice(0, this.AES_IV_LENGTH);
        const ct = raw.slice(this.AES_IV_LENGTH);
        const pkcs8 = await window.crypto.subtle.decrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH }, wrappingKey, ct
        );
        // Least privilege: the team private key is only ever used to ECDH-unwrap the vault DEK
        // (deriveBits), never deriveKey — so import it with deriveBits only, not the identity
        // keypair's broader KEY_USAGES_PRIVATE.
        return await window.crypto.subtle.importKey(
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
            const iv = window.crypto.getRandomValues(new Uint8Array(this.AES_IV_LENGTH));
            
            const encrypted = await window.crypto.subtle.encrypt(
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
            
            console.log('✅ Encrypted file successfully');
            return combined.buffer;
        } catch (error) {
            console.error('❌ File encryption failed:', error);
            throw new Error(`Failed to encrypt file: ${error.message}`);
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
            
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: this.AES_ALGORITHM,
                    iv: iv,
                    tagLength: this.AES_TAG_LENGTH
                },
                vaultDEK,
                ciphertext
            );
            
            console.log('✅ Decrypted file successfully');
            return decrypted;
        } catch (error) {
            console.error('❌ File decryption failed:', error);
            throw new Error(`Failed to decrypt file: ${error.message}`);
        }
    }
    
    // =========================================================================
    // ZERO-KNOWLEDGE NAME / MIME ENCRYPTION + BLIND INDEX
    // =========================================================================
    // File and folder names (and a file's MIME type) are metadata that must NOT leak to
    // the server in a zero-knowledge vault. They are encrypted here IN THE BROWSER under
    // the same per-vault DEK as the content, and the server stores only the opaque blob
    // plus a blind index it cannot reverse. The server keeps these verbatim and decrypts
    // nothing. Format/AAD/HKDF here MUST match security.py (ZK_NAME_PREFIX) and the test
    // helpers — changing any of them silently breaks decryption of existing names.

    // Marker prefix on every ZK-sealed name blob so the SERVER can tell a browser-encrypted
    // name from a Standard (server-key) one and never try to decrypt it. Must equal
    // security.ZK_NAME_PREFIX.
    get ZK_NAME_PREFIX() { return 'zk1:'; }

    // AAD binds a name blob to its vault, field ('name'|'mime') and DEK epoch, so enc_name
    // and enc_mime are not interchangeable and a blob can't be reused under another epoch.
    // (The object id is NOT bound — the client doesn't know it before the row is created;
    // this matches ZK content, which the server also can't bind to a file id.)
    _zkNameAad(vaultId, field, epoch) {
        return new TextEncoder().encode(`dv-zk-name-v1|${vaultId}|${field}|${epoch}`);
    }

    /**
     * Encrypt a file/folder name or MIME string for a zero-knowledge vault.
     * @param {string} plaintext  the name (or MIME) to seal
     * @param {CryptoKey} vaultDEK the vault DEK (AES-GCM) at `epoch`
     * @param {string} vaultId
     * @param {string} field 'name' | 'mime'
     * @param {number} epoch the DEK epoch the name is sealed under
     * @returns {Promise<string>} ZK_NAME_PREFIX + base64(iv || ciphertext+tag)
     */
    async encryptName(plaintext, vaultDEK, vaultId, field, epoch) {
        const iv = window.crypto.getRandomValues(new Uint8Array(this.AES_IV_LENGTH));
        const ct = await window.crypto.subtle.encrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH,
              additionalData: this._zkNameAad(vaultId, field, epoch) },
            vaultDEK,
            new TextEncoder().encode(String(plaintext)),
        );
        const combined = new Uint8Array(iv.length + ct.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ct), iv.length);
        return this.ZK_NAME_PREFIX + this._arrayBufferToBase64(combined.buffer);
    }

    /**
     * Inverse of encryptName. Throws on a wrong DEK/epoch/field (GCM auth failure).
     */
    async decryptName(token, vaultDEK, vaultId, field, epoch) {
        let b64 = String(token);
        if (b64.startsWith(this.ZK_NAME_PREFIX)) b64 = b64.slice(this.ZK_NAME_PREFIX.length);
        const data = new Uint8Array(this._base64ToArrayBuffer(b64));
        const iv = data.slice(0, this.AES_IV_LENGTH);
        const ct = data.slice(this.AES_IV_LENGTH);
        const pt = await window.crypto.subtle.decrypt(
            { name: this.AES_ALGORITHM, iv, tagLength: this.AES_TAG_LENGTH,
              additionalData: this._zkNameAad(vaultId, field, epoch) },
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
        const raw = await window.crypto.subtle.exportKey('raw', vaultDEK);
        const hkdf = await window.crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
        const biKeyBits = await window.crypto.subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256',
              salt: new TextEncoder().encode('dv-zk-name-bi-v1'),
              info: new TextEncoder().encode(`${vaultId}|${epoch}`) },
            hkdf, 256,
        );
        const hmacKey = await window.crypto.subtle.importKey(
            'raw', biKeyBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = await window.crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(String(name)));
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
            const exported = await window.crypto.subtle.exportKey('raw', publicKey);
            const hash = await window.crypto.subtle.digest('SHA-256', exported);
            const hex = Array.from(new Uint8Array(hash))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            return hex.substring(0, 16);
        } catch (error) {
            console.error('❌ Fingerprint calculation failed:', error);
            throw new Error(`Failed to calculate fingerprint: ${error.message}`);
        }
    }
    
    /**
     * Generate random vault DEK (for vault creation).
     * 
     * @returns {Promise<CryptoKey>} Generated AES-256-GCM key
     */
    async generateVaultDEK() {
        try {
            const dek = await window.crypto.subtle.generateKey(
                {
                    name: this.AES_ALGORITHM,
                    length: this.AES_KEY_LENGTH
                },
                true,
                ['encrypt', 'decrypt']
            );
            
            console.log('✅ Generated vault DEK');
            return dek;
        } catch (error) {
            console.error('❌ DEK generation failed:', error);
            throw new Error(`Failed to generate vault DEK: ${error.message}`);
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
        
        const passwordKey = await window.crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );
        
        return await window.crypto.subtle.deriveKey(
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
        const sharedSecretKey = await window.crypto.subtle.importKey(
            'raw',
            sharedSecretBits,
            'HKDF',
            false,
            ['deriveKey']
        );
        // Derive an AES-KW wrapping key (RFC 3394) so it matches server aes_key_wrap
        return await window.crypto.subtle.deriveKey(
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
            console.log('  - attempting AES-KW unwrap; wrappedKeyBytes length:', (wrappedKeyBytes && wrappedKeyBytes.byteLength) || (wrappedKeyBytes && wrappedKeyBytes.length));

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
            const unwrappedKey = await window.crypto.subtle.unwrapKey(
                'raw', // format of the unwrapped key material
                wrappedBuf, // wrapped key bytes (RFC3394)
                wrappingKey, // the AES-KW CryptoKey derived via HKDF
                { name: 'AES-KW' }, // wrapping algorithm
                { name: this.AES_ALGORITHM, length: this.AES_KEY_LENGTH }, // result key algorithm (AES-GCM DEK)
                true, // extractable
                ['encrypt', 'decrypt'] // usages
            );

            console.log('  - AES-KW unwrap succeeded; obtained DEK CryptoKey');
            return unwrappedKey;
        } catch (err) {
            console.error('❌ AES-KW unwrap failed:', err);
            throw err;
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
            console.log('🔄 Converting compressed point to uncompressed...');
            // For P-384, we need to decompress the point
            // This is complex, so we'll import as SPKI (PEM) instead
            // Create a minimal SPKI structure for the compressed point
            const uncompressedBytes = await this._decompressP384Point(bytes);
            rawKeyBytes = uncompressedBytes;
        }
        
        return await window.crypto.subtle.importKey(
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
        
        console.log('🔧 Requesting server to decompress point...');
        
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
                throw new Error(`Server decompression failed: ${response.statusText}`);
            }
            
            const result = await response.json();
            const uncompressed = this._base64ToArrayBuffer(result.uncompressed_point);
            
            console.log('✅ Server decompressed point:', uncompressed.byteLength, 'bytes');
            return uncompressed;
        } catch (error) {
            console.error('❌ Point decompression failed:', error);
            throw new Error(`Failed to decompress P-384 point: ${error.message}`);
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

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ECCCryptoLibrary;
}
