/**
 * ECC Zero-Trust Crypto Library - TypeScript Edition
 * 
 * Strongly-typed client-side cryptographic operations for Zero-Trust vault encryption.
 * Uses Web Crypto API for ECC P-384 (SECP384R1) operations.
 * 
 * @author DockVault Team
 * @version 1.0.0
 * @date October 13, 2025
 */

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

/**
 * ECC Keypair containing private and public keys
 */
interface ECCKeypair {
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

/**
 * Password-protected private key data
 */
interface ProtectedPrivateKey {
    /** Base64-encoded encrypted private key (IV + ciphertext + tag) */
    encrypted: string;
    /** Base64-encoded PBKDF2 salt */
    salt: string;
    /** PBKDF2 iteration count */
    iterations: number;
}

/**
 * Vault access credentials from server
 */
interface VaultCredentials {
    /** Base64-encoded wrapped DEK */
    wrapped_dek: string;
    /** Base64-encoded ephemeral public key (X.962 format) */
    ephemeral_public_key: string;
}

/**
 * Library configuration options
 */
interface CryptoLibraryConfig {
    /** ECC curve name (default: P-384) */
    curve?: 'P-256' | 'P-384' | 'P-521';
    /** PBKDF2 iterations (default: 600000) */
    pbkdf2Iterations?: number;
    /** AES key length in bits (default: 256) */
    aesKeyLength?: 128 | 192 | 256;
}

// ============================================================================
// MAIN CLASS
// ============================================================================

export class ECCCryptoLibrary {
    // ECC curve parameters
    private readonly CURVE: string;
    private readonly KEY_USAGES_PRIVATE: KeyUsage[] = ['deriveKey', 'deriveBits'];
    private readonly KEY_USAGES_PUBLIC: KeyUsage[] = [];
    
    // AES-GCM parameters
    private readonly AES_ALGORITHM = 'AES-GCM';
    private readonly AES_KEY_LENGTH: 128 | 192 | 256;
    private readonly AES_IV_LENGTH = 12; // bytes
    private readonly AES_TAG_LENGTH = 128; // bits
    
    // PBKDF2 parameters
    private readonly PBKDF2_ITERATIONS: number;
    private readonly PBKDF2_HASH = 'SHA-256';
    private readonly PBKDF2_SALT_LENGTH = 32; // bytes
    
    // Key wrapping
    private readonly HKDF_INFO: Uint8Array;
    
    constructor(config: CryptoLibraryConfig = {}) {
        this.CURVE = config.curve || 'P-384';
        this.PBKDF2_ITERATIONS = config.pbkdf2Iterations || 600000;
        this.AES_KEY_LENGTH = config.aesKeyLength || 256;
        this.HKDF_INFO = new TextEncoder().encode('vault-key-wrapping');
        
        console.log(`🔐 ECC Crypto Library initialized (${this.CURVE})`);
    }
    
    // ========================================================================
    // ECC KEYPAIR GENERATION
    // ========================================================================
    
    /**
     * Generate ECC keypair for Zero-Trust encryption.
     * 
     * @returns Promise resolving to keypair
     * @throws Error if keypair generation fails
     */
    async generateKeypair(): Promise<ECCKeypair> {
        try {
            const keypair = await window.crypto.subtle.generateKey(
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                true, // extractable
                this.KEY_USAGES_PRIVATE
            ) as CryptoKeyPair;
            
            console.log(`✅ Generated ECC ${this.CURVE} keypair`);
            return {
                privateKey: keypair.privateKey,
                publicKey: keypair.publicKey
            };
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Keypair generation failed:', error);
            throw new Error(`Failed to generate keypair: ${message}`);
        }
    }
    
    /**
     * Export public key to PEM format for server registration.
     * 
     * @param publicKey - Public key to export
     * @returns Promise resolving to PEM-encoded public key
     * @throws Error if export fails
     */
    async exportPublicKeyPEM(publicKey: CryptoKey): Promise<string> {
        try {
            const exported = await window.crypto.subtle.exportKey('spki', publicKey);
            const base64 = this.arrayBufferToBase64(exported);
            const pem = this.formatPEM(base64, 'PUBLIC KEY');
            
            console.log('✅ Exported public key to PEM');
            return pem;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Public key export failed:', error);
            throw new Error(`Failed to export public key: ${message}`);
        }
    }
    
    /**
     * Export private key to PEM format (UNENCRYPTED - use with caution!).
     * 
     * @param privateKey - Private key to export
     * @returns Promise resolving to PEM-encoded private key
     * @throws Error if export fails
     */
    async exportPrivateKeyPEM(privateKey: CryptoKey): Promise<string> {
        try {
            const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);
            const base64 = this.arrayBufferToBase64(exported);
            const pem = this.formatPEM(base64, 'PRIVATE KEY');
            
            console.log('⚠️  Exported UNENCRYPTED private key to PEM');
            return pem;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Private key export failed:', error);
            throw new Error(`Failed to export private key: ${message}`);
        }
    }
    
    /**
     * Import public key from PEM format.
     * 
     * @param pem - PEM-encoded public key
     * @returns Promise resolving to imported public key
     * @throws Error if import fails
     */
    async importPublicKeyPEM(pem: string): Promise<CryptoKey> {
        try {
            const base64 = this.extractPEMContent(pem);
            const der = this.base64ToArrayBuffer(base64);
            
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
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Public key import failed:', error);
            throw new Error(`Failed to import public key: ${message}`);
        }
    }
    
    /**
     * Import private key from PEM format.
     * 
     * @param pem - PEM-encoded private key
     * @returns Promise resolving to imported private key
     * @throws Error if import fails
     */
    async importPrivateKeyPEM(pem: string): Promise<CryptoKey> {
        try {
            const base64 = this.extractPEMContent(pem);
            const der = this.base64ToArrayBuffer(base64);
            
            const privateKey = await window.crypto.subtle.importKey(
                'pkcs8',
                der,
                {
                    name: 'ECDH',
                    namedCurve: this.CURVE
                },
                true,
                this.KEY_USAGES_PRIVATE
            );
            
            console.log('✅ Imported private key from PEM');
            return privateKey;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Private key import failed:', error);
            throw new Error(`Failed to import private key: ${message}`);
        }
    }
    
    // ========================================================================
    // PASSWORD-BASED PRIVATE KEY ENCRYPTION
    // ========================================================================
    
    /**
     * Encrypt private key with password for secure storage/recovery.
     * Uses PBKDF2 (configurable iterations) + AES-256-GCM.
     * 
     * @param privateKeyPEM - PEM-encoded private key
     * @param password - User's password
     * @returns Promise resolving to encrypted key data
     * @throws Error if encryption fails
     */
    async encryptPrivateKey(privateKeyPEM: string, password: string): Promise<ProtectedPrivateKey> {
        try {
            // Generate random salt
            const salt = window.crypto.getRandomValues(new Uint8Array(this.PBKDF2_SALT_LENGTH));
            
            // Derive AES key from password
            const passwordKey = await this.deriveKeyFromPassword(password, salt);
            
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
                encrypted: this.arrayBufferToBase64(combined),
                salt: this.arrayBufferToBase64(salt),
                iterations: this.PBKDF2_ITERATIONS
            };
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Private key encryption failed:', error);
            throw new Error(`Failed to encrypt private key: ${message}`);
        }
    }
    
    /**
     * Decrypt password-protected private key.
     * 
     * @param encryptedBase64 - Base64-encoded encrypted private key (IV + ciphertext)
     * @param password - User's password
     * @param saltBase64 - Base64-encoded salt
     * @param iterations - PBKDF2 iterations (default: config value)
     * @returns Promise resolving to decrypted PEM-encoded private key
     * @throws Error if decryption fails (wrong password or corrupted data)
     */
    async decryptPrivateKey(
        encryptedBase64: string,
        password: string,
        saltBase64: string,
        iterations?: number
    ): Promise<string> {
        try {
            const combined = this.base64ToArrayBuffer(encryptedBase64);
            const salt = this.base64ToArrayBuffer(saltBase64);
            const iters = iterations || this.PBKDF2_ITERATIONS;
            
            // Derive AES key from password
            const passwordKey = await this.deriveKeyFromPassword(password, salt, iters);
            
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
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Private key decryption failed:', error);
            throw new Error(`Failed to decrypt private key: ${message}`);
        }
    }
    
    // ========================================================================
    // VAULT DEK WRAPPING/UNWRAPPING
    // ========================================================================
    
    /**
     * Unwrap vault DEK using user's private key.
     * Uses ECDH to derive shared secret, then decrypts the wrapped DEK.
     * 
     * @param wrappedDEKBase64 - Base64-encoded wrapped DEK
     * @param ephemeralPublicKeyBase64 - Base64-encoded ephemeral public key
     * @param userPrivateKey - User's private key
     * @returns Promise resolving to unwrapped vault DEK as AES-GCM key
     * @throws Error if unwrapping fails
     */
    async unwrapVaultDEK(
        wrappedDEKBase64: string,
        ephemeralPublicKeyBase64: string,
        userPrivateKey: CryptoKey
    ): Promise<CryptoKey> {
        try {
            // Import ephemeral public key (X.962 compressed point format)
            const ephemeralPublicKeyBytes = this.base64ToArrayBuffer(ephemeralPublicKeyBase64);
            const ephemeralPublicKey = await this.importRawPublicKey(ephemeralPublicKeyBytes);
            
            // Perform ECDH to derive shared secret
            const curveSize = this.CURVE === 'P-256' ? 256 : this.CURVE === 'P-384' ? 384 : 521;
            const sharedSecret = await window.crypto.subtle.deriveBits(
                {
                    name: 'ECDH',
                    public: ephemeralPublicKey
                },
                userPrivateKey,
                curveSize
            );
            
            // Derive AES wrapping key using HKDF
            const wrappingKey = await this.deriveWrappingKey(sharedSecret);
            
            // Unwrap the DEK
            const wrappedDEKBytes = this.base64ToArrayBuffer(wrappedDEKBase64);
            const vaultDEK = await this.unwrapKeyWithAESKW(wrappedDEKBytes, wrappingKey);
            
            console.log('✅ Unwrapped vault DEK successfully');
            return vaultDEK;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Vault DEK unwrapping failed:', error);
            throw new Error(`Failed to unwrap vault DEK: ${message}`);
        }
    }
    
    // ========================================================================
    // FILE ENCRYPTION/DECRYPTION
    // ========================================================================
    
    /**
     * Encrypt file content with vault DEK.
     * 
     * @param fileContent - File content to encrypt
     * @param vaultDEK - Vault Data Encryption Key
     * @returns Promise resolving to encrypted file content (IV + ciphertext)
     * @throws Error if encryption fails
     */
    async encryptFile(fileContent: ArrayBuffer | Uint8Array, vaultDEK: CryptoKey): Promise<ArrayBuffer> {
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
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ File encryption failed:', error);
            throw new Error(`Failed to encrypt file: ${message}`);
        }
    }
    
    /**
     * Decrypt file content with vault DEK.
     * 
     * @param encryptedContent - Encrypted file content (IV + ciphertext)
     * @param vaultDEK - Vault Data Encryption Key
     * @returns Promise resolving to decrypted file content
     * @throws Error if decryption fails
     */
    async decryptFile(encryptedContent: ArrayBuffer | Uint8Array, vaultDEK: CryptoKey): Promise<ArrayBuffer> {
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
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ File decryption failed:', error);
            throw new Error(`Failed to decrypt file: ${message}`);
        }
    }
    
    // ========================================================================
    // UTILITY FUNCTIONS
    // ========================================================================
    
    /**
     * Calculate SHA-256 fingerprint of public key (for verification).
     * 
     * @param publicKey - Public key
     * @returns Promise resolving to hex-encoded fingerprint (first 16 chars)
     * @throws Error if fingerprint calculation fails
     */
    async calculateFingerprint(publicKey: CryptoKey): Promise<string> {
        try {
            const exported = await window.crypto.subtle.exportKey('raw', publicKey);
            const hash = await window.crypto.subtle.digest('SHA-256', exported);
            const hex = Array.from(new Uint8Array(hash))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
            return hex.substring(0, 16);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ Fingerprint calculation failed:', error);
            throw new Error(`Failed to calculate fingerprint: ${message}`);
        }
    }
    
    /**
     * Generate random vault DEK (for vault creation).
     * 
     * @returns Promise resolving to generated AES-GCM key
     * @throws Error if generation fails
     */
    async generateVaultDEK(): Promise<CryptoKey> {
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
            const message = error instanceof Error ? error.message : String(error);
            console.error('❌ DEK generation failed:', error);
            throw new Error(`Failed to generate vault DEK: ${message}`);
        }
    }
    
    // ========================================================================
    // PRIVATE HELPER FUNCTIONS
    // ========================================================================
    
    /**
     * Derive AES key from password using PBKDF2.
     */
    private async deriveKeyFromPassword(
        password: string,
        salt: ArrayBuffer | Uint8Array,
        iterations?: number
    ): Promise<CryptoKey> {
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
     */
    private async deriveWrappingKey(sharedSecretBits: ArrayBuffer): Promise<CryptoKey> {
        const sharedSecretKey = await window.crypto.subtle.importKey(
            'raw',
            sharedSecretBits,
            'HKDF',
            false,
            ['deriveKey']
        );
        
        return await window.crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(),
                info: this.HKDF_INFO
            },
            sharedSecretKey,
            {
                name: this.AES_ALGORITHM,
                length: this.AES_KEY_LENGTH
            },
            false,
            ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
        );
    }
    
    /**
     * Unwrap key using AES-KW simulation (AES-GCM).
     */
    private async unwrapKeyWithAESKW(wrappedKeyBytes: ArrayBuffer, wrappingKey: CryptoKey): Promise<CryptoKey> {
        // Extract IV (first 12 bytes for AES-GCM)
        const data = new Uint8Array(wrappedKeyBytes);
        const iv = data.slice(0, 12);
        const ciphertext = data.slice(12);
        
        // Decrypt to get raw key material
        const dekBytes = await window.crypto.subtle.decrypt(
            {
                name: this.AES_ALGORITHM,
                iv: iv,
                tagLength: this.AES_TAG_LENGTH
            },
            wrappingKey,
            ciphertext
        );
        
        // Import as AES-GCM key
        return await window.crypto.subtle.importKey(
            'raw',
            dekBytes,
            {
                name: this.AES_ALGORITHM,
                length: this.AES_KEY_LENGTH
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
    
    /**
     * Import raw public key (X.962 compressed point format).
     */
    private async importRawPublicKey(rawKeyBytes: ArrayBuffer): Promise<CryptoKey> {
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
     * Convert ArrayBuffer to Base64.
     */
    private arrayBufferToBase64(buffer: ArrayBuffer): string {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
    
    /**
     * Convert Base64 to ArrayBuffer.
     */
    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    /**
     * Format binary data as PEM.
     */
    private formatPEM(base64: string, label: string): string {
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
     */
    private extractPEMContent(pem: string): string {
        return pem
            .replace(/-----BEGIN [A-Z ]+-----/, '')
            .replace(/-----END [A-Z ]+-----/, '')
            .replace(/\s/g, '');
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

export type {
    ECCKeypair,
    ProtectedPrivateKey,
    VaultCredentials,
    CryptoLibraryConfig
};
