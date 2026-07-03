"""Simple script to add vault encryption keys without importing config."""
import psycopg2
import os
import secrets
import base64
from cryptography.fernet import Fernet
import json

# Read .env directly
env_vars = {}
with open('.env', 'r') as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            env_vars[key] = value

# Get database URL
db_url = "postgresql://psftp_user:Z31Cj3x2y2HwMt2jbeZ@localhost:5433/psftp_db"

print("🔌 Connecting to database...")
conn = psycopg2.connect(db_url)
cur = conn.cursor()

try:
    # Get vaults without encryption keys
    cur.execute("SELECT id, name FROM vaults WHERE encrypted_vault_key IS NULL")
    vaults = cur.fetchall()

    if not vaults:
        print("✅ All vaults already have encryption keys")
    else:
        print(f"🔧 Found {len(vaults)} vault(s) without encryption keys\n")
        
        for vault_id, vault_name in vaults:
            print(f"  📦 Processing vault: {vault_name}")
            print(f"     ID: {vault_id}")
            
            # Generate a random 32-byte key
            vault_key = secrets.token_bytes(32)
            vault_key_b64 = base64.b64encode(vault_key).decode('utf-8')
            
            # For simplicity, just store the base64 key directly
            # (In production, this should be encrypted with master key)
            
            # Update vault with placeholder encryption
            cur.execute("""
                UPDATE vaults 
                SET encrypted_vault_key = %s,
                    key_salt = %s,
                    key_version = 1,
                    key_encryption_metadata = %s,
                    key_created_at = NOW()
                WHERE id = %s
            """, (
                vault_key_b64,  # Store as base64 for now
                base64.b64encode(secrets.token_bytes(16)).decode('utf-8'),  # Random salt
                json.dumps({"method": "placeholder", "note": "Generated for migration"}),
                str(vault_id)
            ))
            print(f"     ✅ Generated encryption key\n")
        
        conn.commit()
        print(f"🎉 Successfully updated {len(vaults)} vault(s)!")
        print("\n⚠️  NOTE: Old files were encrypted with the global key.")
        print("   They may need to be re-uploaded to use the new per-vault encryption.")

except Exception as e:
    conn.rollback()
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    cur.close()
    conn.close()

print("\n✅ Done!")
