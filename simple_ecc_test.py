"""
Simple ECC endpoint test - just test if routes are available
"""
import requests

API_URL = "http://localhost:8000"

# Login first
print("🔐 Logging in...")
response = requests.post(
    f"{API_URL}/auth/login",
    json={"username": "admin", "password": "1111111111111111"}
)

if response.status_code == 200:
    token = response.json()["access_token"]
    print(f"✅ Login successful! Token: {token[:20]}...")
    
    # Test ECC endpoint
    print("\n📡 Testing ECC endpoint: POST /ecc/keys/register")
    headers = {"Authorization": f"Bearer {token}"}
    
    test_public_key = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETest1234567890
-----END PUBLIC KEY-----"""
    
    response = requests.post(
        f"{API_URL}/ecc/keys/register",
        json={"public_key": test_public_key},
        headers=headers
    )
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code in [200, 201]:
        print("\n🎉 ECC endpoint is working!")
    else:
        print("\n❌ ECC endpoint returned an error")
else:
    print(f"❌ Login failed: {response.status_code}")
    print(f"   {response.text}")
