#!/usr/bin/env python3
"""
Add ECC team key management columns to vaults table.
"""
import psycopg2
from config import settings

def run_migration():
    """Add missing columns to vaults table."""
    
    # Parse database URL from settings
    import re
    db_url = settings.database_url
    # Format: postgresql://user:pass@host:port/dbname
    match = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    
    if not match:
        print(f"❌ Could not parse database URL: {db_url}")
        return
    
    user, password, host, port, dbname = match.groups()
    
    print(f"🔌 Connecting to {host}:{port}/{dbname} as {user}...")
    
    conn = psycopg2.connect(
        host=host,
        port=int(port),
        database=dbname,
        user=user,
        password=password
    )
    
    try:
        cursor = conn.cursor()
        
        print("🔧 Adding ECC columns to vaults table...")
        
        # Add key_wrapping_mode column
        cursor.execute("""
            ALTER TABLE vaults 
            ADD COLUMN IF NOT EXISTS key_wrapping_mode VARCHAR(20) DEFAULT 'direct';
        """)
        print("✅ Added key_wrapping_mode column")
        
        # Add member_keys column
        cursor.execute("""
            ALTER TABLE vaults 
            ADD COLUMN IF NOT EXISTS member_keys JSON;
        """)
        print("✅ Added member_keys column")
        
        # Add team_key column
        cursor.execute("""
            ALTER TABLE vaults 
            ADD COLUMN IF NOT EXISTS team_key TEXT;
        """)
        print("✅ Added team_key column")
        
        # Add comments
        cursor.execute("""
            COMMENT ON COLUMN vaults.key_wrapping_mode IS 'Key wrapping mode: direct or hierarchical';
        """)
        cursor.execute("""
            COMMENT ON COLUMN vaults.member_keys IS 'Per-member encrypted vault keys (ECC)';
        """)
        cursor.execute("""
            COMMENT ON COLUMN vaults.team_key IS 'Encrypted team key (hierarchical mode)';
        """)
        print("✅ Added column comments")
        
        conn.commit()
        print("\n🎉 Migration completed successfully!")
        
    except Exception as e:
        conn.rollback()
        print(f"\n❌ Migration failed: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    run_migration()
