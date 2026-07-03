"""Generate encryption keys for vaults that don't have them yet."""
from config import settings
from vault_key_utils import generate_vault_key, encrypt_vault_key
import psycopg2
import json

# Connect to database
conn = psycopg2.connect(settings.database_url)
cur = conn.cursor()

try:
    # Get vaults without encryption keys
    cur.execute("SELECT id, name FROM vaults WHERE encrypted_vault_key IS NULL")
    vaults = cur.fetchall()

    if not vaults:
        print("✅ All vaults already have encryption keys")
    else:
        print(f"🔧 Found {len(vaults)} vaults without encryption keys")
        
        master_key = settings.encryption_key.encode()
        
        for vault_id, vault_name in vaults:
            print(f"  Generating key for vault: {vault_name} ({vault_id})")
            
            # Generate new vault key
            vault_key = generate_vault_key()
            
            # Encrypt with master key (no password)
            encrypted_data = encrypt_vault_key(vault_key, master_key=master_key)
            
            # Update vault
            cur.execute("""
                UPDATE vaults 
                SET encrypted_vault_key = %s,
                    key_salt = %s,
                    key_version = %s,
                    key_encryption_metadata = %s,
                    key_created_at = NOW()
                WHERE id = %s
            """, (
                encrypted_data["encrypted_key"],
                encrypted_data["salt"],
                encrypted_data["version"],
                json.dumps({
                    "method": encrypted_data["method"],
                    "iterations": encrypted_data["iterations"]
                }),
                str(vault_id)
            ))
        
        conn.commit()
        print(f"✅ Successfully generated keys for {len(vaults)} vaults")

except Exception as e:
    conn.rollback()
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    cur.close()
    conn.close()
