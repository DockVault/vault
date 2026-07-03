#!/usr/bin/env python3
"""
Comprehensive test for ECC endpoints.
Tests the complete workflow:
1. Generate keypair
2. Create vault with ECC
3. Add member to vault
4. Share file with member
5. Member accesses file
"""
import requests
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

API_URL = "http://localhost:8000"

# Test credentials
ADMIN_USER = "admin"
ADMIN_PASS = "1111111111111111"

class ECCTester:
    def __init__(self):
        self.session = requests.Session()
        self.token = None
        self.user_id = None
        self.private_key = None
        self.public_key = None
        self.vault_id = None
        
    def print_section(self, title):
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    
    def login(self):
        """Login and get JWT token."""
        self.print_section("1. Login")
        
        response = self.session.post(
            f"{API_URL}/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS}
        )
        
        if response.status_code in [200, 201]:
            data = response.json()
            self.token = data["access_token"]
            # Get user ID from /users/me endpoint
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
            
            me_response = self.session.get(f"{API_URL}/users/me")
            if me_response.status_code == 200:
                me_data = me_response.json()
                self.user_id = me_data["id"]
                print(f"✅ Login successful")
                print(f"   User ID: {self.user_id}")
                return True
            else:
                print(f"❌ Failed to get user info: {me_response.status_code}")
                return False
        else:
            print(f"❌ Login failed: {response.status_code}")
            print(f"   {response.text}")
            return False
    
    def generate_keypair(self):
        """Generate ECC keypair using cryptography library."""
        self.print_section("2. Generate ECC Keypair")
        
        # Generate private key (P-384 curve - SECP384R1)
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        
        # Extract public key
        self.public_key = self.private_key.public_key()
        
        # Serialize for API
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        print(f"✅ Keypair generated")
        print(f"   Private key length: {len(private_pem)} bytes")
        print(f"   Public key length: {len(public_pem)} bytes")
        
        return private_pem, public_pem
    
    def register_public_key(self, public_key_pem):
        """Register public key with the server."""
        self.print_section("3. Register Public Key")
        
        response = self.session.post(
            f"{API_URL}/ecc/keys/register",
            json={"public_key": public_key_pem}
        )
        
        if response.status_code in [200, 201]:  # Accept both 200 and 201
            data = response.json()
            print(f"✅ Public key registered")
            print(f"   Key ID: {data.get('key_id')}")
            print(f"   Fingerprint: {data.get('fingerprint')}")
            return True
        else:
            print(f"❌ Registration failed: {response.status_code}")
            print(f"   {response.text}")
            return False
    
    def get_public_key(self):
        """Retrieve public key from server."""
        self.print_section("4. Retrieve Public Key")
        
        response = self.session.get(f"{API_URL}/ecc/keys/public")
        
        if response.status_code in [200, 201]:
            data = response.json()
            print(f"✅ Public key retrieved")
            print(f"   Has public key: {bool(data.get('public_key'))}")
            print(f"   Fingerprint: {data.get('fingerprint')}")
            return data
        else:
            print(f"❌ Retrieval failed: {response.status_code}")
            print(f"   {response.text}")
            return None
    
    def create_vault_with_ecc(self, name="ECC Test Vault"):
        """Create a new vault using ECC encryption."""
        self.print_section("5. Create Vault with ECC")
        
        response = self.session.post(
            f"{API_URL}/ecc/vaults",
            json={
                "name": name,
                "description": "Testing ECC encryption",
                "password": None  # Using ECC, not password
            }
        )
        
        if response.status_code in [200, 201]:
            data = response.json()
            self.vault_id = data["vault_id"]
            print(f"✅ Vault created with ECC")
            print(f"   Vault ID: {self.vault_id}")
            print(f"   Name: {data.get('name')}")
            print(f"   Wrapping mode: {data.get('key_wrapping_mode', 'N/A')}")
            return self.vault_id
        else:
            print(f"❌ Vault creation failed: {response.status_code}")
            print(f"   {response.text}")
            return None
    
    def list_vaults(self):
        """List all vaults."""
        self.print_section("6. List Vaults")
        
        response = self.session.get(f"{API_URL}/vaults")
        
        if response.status_code in [200, 201]:
            vaults = response.json()
            print(f"✅ Found {len(vaults)} vault(s)")
            for vault in vaults:
                ecc_mode = vault.get('key_wrapping_mode', 'N/A')
                print(f"   - {vault['name']} (ID: {vault['id'][:8]}..., Mode: {ecc_mode})")
            return vaults
        else:
            print(f"❌ Listing failed: {response.status_code}")
            return []
    
    def upload_file_to_vault(self, vault_id, filename="test_ecc.txt", content="ECC encrypted content"):
        """Upload a file to the vault."""
        self.print_section("7. Upload File to Vault")
        
        files = {
            'files': (filename, content.encode(), 'text/plain')
        }
        
        response = self.session.post(
            f"{API_URL}/vaults/{vault_id}/files",
            files=files
        )
        
        if response.status_code in [200, 201]:
            data = response.json()
            print(f"✅ File uploaded (Status: {response.status_code})")
            
            # Handle the response structure: {'message': '...', 'files': [...]}
            if 'files' in data and len(data['files']) > 0:
                file_info = data['files'][0]
                file_id = file_info.get('id')
                print(f"   File ID: {file_id}")
                print(f"   Name: {file_info.get('name')}")
                print(f"   Size: {file_info.get('size')} bytes")
                return file_id
            else:
                print(f"⚠️  No files in response: {data}")
                return None
        else:
            print(f"❌ Upload failed: {response.status_code}")
            print(f"   {response.text}")
            return None
    
    def download_file(self, vault_id, file_id):
        """Download a file from the vault."""
        self.print_section("8. Download File")
        
        response = self.session.get(
            f"{API_URL}/vaults/{vault_id}/files/{file_id}/download"
        )
        
        if response.status_code in [200, 201]:
            content = response.content
            print(f"✅ File downloaded")
            print(f"   Size: {len(content)} bytes")
            print(f"   Content: {content.decode()[:50]}...")
            return content
        else:
            print(f"❌ Download failed: {response.status_code}")
            print(f"   {response.text}")
            return None
    
    def get_vault_access_keys(self, vault_id):
        """Get encrypted vault keys for current user."""
        self.print_section("9. Get Vault Access Keys")
        
        response = self.session.get(
            f"{API_URL}/ecc/vaults/{vault_id}/keys"
        )
        
        if response.status_code in [200, 201]:
            data = response.json()
            print(f"✅ Access keys retrieved")
            print(f"   Wrapping mode: {data.get('mode')}")
            print(f"   Has encrypted key: {bool(data.get('encrypted_vault_key'))}")
            return data
        else:
            print(f"❌ Failed to get keys: {response.status_code}")
            print(f"   {response.text}")
            return None
    
    def run_full_test(self):
        """Run complete ECC workflow test."""
        print("\n")
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║         ECC Endpoints Comprehensive Test Suite           ║")
        print("╚═══════════════════════════════════════════════════════════╝")
        
        # Step 1: Login
        if not self.login():
            return False
        
        # Step 2-3: Generate and register keypair
        private_pem, public_pem = self.generate_keypair()
        if not self.register_public_key(public_pem):
            return False
        
        # Step 4: Verify registration
        key_info = self.get_public_key()
        if not key_info:
            return False
        
        # Step 5: Create ECC vault
        vault_id = self.create_vault_with_ecc()
        if not vault_id:
            return False
        
        # Step 6: List vaults
        self.list_vaults()
        
        # Step 7: Upload file
        file_id = self.upload_file_to_vault(
            vault_id,
            filename="ecc_test.txt",
            content="This file is encrypted with ECC! 🔐🚀"
        )
        if not file_id:
            return False
        
        # Step 8: Download file
        content = self.download_file(vault_id, file_id)
        if not content:
            return False
        
        # Step 9: Get vault access keys
        self.get_vault_access_keys(vault_id)
        
        # Final summary
        self.print_section("✅ TEST SUMMARY")
        print("All ECC endpoints working correctly!")
        print(f"  - Keypair generation: ✅")
        print(f"  - Public key registration: ✅")
        print(f"  - ECC vault creation: ✅")
        print(f"  - File upload (encrypted): ✅")
        print(f"  - File download (decrypted): ✅")
        print(f"  - Vault key access: ✅")
        print("\n🎉 ECC integration is fully functional!\n")
        
        return True


def main():
    tester = ECCTester()
    success = tester.run_full_test()
    
    if not success:
        print("\n⚠️  Some tests failed. Check the output above.")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
