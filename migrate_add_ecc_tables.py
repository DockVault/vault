"""
Database migration script to add ECC Zero-Trust encryption tables.
Adds: user_keypairs, vault_member_keys, chunked_upload_sessions
"""
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from config import settings

def run_migration():
    """Add ECC tables to the database."""
    try:
        # Connect to database using settings
        db_url = settings.database_url
        conn = psycopg2.connect(db_url)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        print("Connected to database successfully")
        
        # 1. Create user_keypairs table
        print("\n1. Creating user_keypairs table...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_keypairs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                encrypted_private_key TEXT,
                curve VARCHAR(50) DEFAULT 'SECP384R1',
                fingerprint VARCHAR(64) NOT NULL,
                version INTEGER DEFAULT 1,
                previous_public_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            );
            
            COMMENT ON TABLE user_keypairs IS 'ECC public keys for Zero-Trust encryption';
            COMMENT ON COLUMN user_keypairs.public_key IS 'PEM-encoded SECP384R1 public key';
            COMMENT ON COLUMN user_keypairs.encrypted_private_key IS 'Password-encrypted private key for recovery';
            COMMENT ON COLUMN user_keypairs.fingerprint IS 'SHA256 hash of public key';
        """)
        print("   ✅ user_keypairs table created")
        
        # Create indexes for user_keypairs
        print("   Creating indexes for user_keypairs...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_user_keypair_user ON user_keypairs(user_id);
            CREATE INDEX IF NOT EXISTS idx_user_keypair_fingerprint ON user_keypairs(fingerprint);
        """)
        print("   ✅ Indexes created")
        
        # 2. Create vault_member_keys table
        print("\n2. Creating vault_member_keys table...")
        
        # Drop and recreate to ensure proper schema
        cursor.execute("DROP TABLE IF EXISTS vault_member_keys CASCADE;")
        
        cursor.execute("""
            CREATE TABLE vault_member_keys (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                encrypted_dek TEXT NOT NULL,
                ephemeral_public_key TEXT NOT NULL,
                wrapping_algorithm VARCHAR(50) DEFAULT 'ECDH-AES-256-GCM',
                key_version INTEGER DEFAULT 1,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
                revoked_at TIMESTAMP,
                revoked_by UUID REFERENCES users(id) ON DELETE SET NULL,
                is_active BOOLEAN DEFAULT TRUE,
                CONSTRAINT uq_vault_member_key UNIQUE (vault_id, user_id)
            );
            
            COMMENT ON TABLE vault_member_keys IS 'Per-member wrapped vault DEKs using ECDH';
            COMMENT ON COLUMN vault_member_keys.encrypted_dek IS 'Vault DEK wrapped with ECDH-derived key';
            COMMENT ON COLUMN vault_member_keys.ephemeral_public_key IS 'Ephemeral public key for ECDH';
        """)
        print("   ✅ vault_member_keys table created")
        
        # Create indexes for vault_member_keys
        print("   Creating indexes for vault_member_keys...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vault_member_key_vault ON vault_member_keys(vault_id);
            CREATE INDEX IF NOT EXISTS idx_vault_member_key_user ON vault_member_keys(user_id);
            CREATE INDEX IF NOT EXISTS idx_vault_member_key_active ON vault_member_keys(vault_id, user_id, is_active);
        """)
        print("   ✅ Indexes created")
        
        # 3. Create chunked_upload_sessions table
        print("\n3. Creating chunked_upload_sessions table...")
        
        # Drop and recreate to ensure proper schema
        cursor.execute("DROP TABLE IF EXISTS chunked_upload_sessions CASCADE;")
        
        cursor.execute("""
            CREATE TABLE chunked_upload_sessions (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                filename VARCHAR(255) NOT NULL,
                total_size BIGINT NOT NULL,
                mime_type VARCHAR(255),
                chunks_received INTEGER DEFAULT 0,
                total_chunks INTEGER NOT NULL,
                bytes_received BIGINT DEFAULT 0,
                temp_file_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_chunk_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                completed_at TIMESTAMP,
                status VARCHAR(20) DEFAULT 'active',
                error_message TEXT,
                file_id UUID REFERENCES files(id) ON DELETE SET NULL
            );
            
            COMMENT ON TABLE chunked_upload_sessions IS 'Manages chunked file uploads with resumption support';
            COMMENT ON COLUMN chunked_upload_sessions.status IS 'active, completed, failed, or expired';
        """)
        print("   ✅ chunked_upload_sessions table created")
        
        # Create indexes for chunked_upload_sessions
        print("   Creating indexes for chunked_upload_sessions...")
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_chunked_upload_vault ON chunked_upload_sessions(vault_id);
            CREATE INDEX IF NOT EXISTS idx_chunked_upload_user ON chunked_upload_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_chunked_upload_status ON chunked_upload_sessions(status, expires_at);
        """)
        print("   ✅ Indexes created")
        
        # 4. Verify tables were created
        print("\n4. Verifying tables...")
        cursor.execute("""
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('user_keypairs', 'vault_member_keys', 'chunked_upload_sessions')
            ORDER BY table_name;
        """)
        tables = cursor.fetchall()
        print(f"   ✅ Found {len(tables)} ECC tables:")
        for table in tables:
            print(f"      - {table[0]}")
        
        cursor.close()
        conn.close()
        
        print("\n✅ Migration completed successfully!")
        print("   All ECC tables and indexes have been created.")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        raise

if __name__ == "__main__":
    print("=" * 60)
    print("  ECC Zero-Trust Tables Migration")
    print("=" * 60)
    run_migration()
