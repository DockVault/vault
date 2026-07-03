#!/usr/bin/env python3
"""
Quick test - just upload and download immediately.
"""

import requests

API_BASE_URL = "http://localhost:8000"

# Login
response = requests.post(f"{API_BASE_URL}/auth/login", json={"username": "admin", "password": "1111111111111111"})
token = response.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

vault_id = "d74c1fce-6c25-4a4a-8c5d-d17cccc1ddd6"

# Upload
test_content = b"Test file content\n" * 10
files = [("files", ("quick_test.txt", test_content, "text/plain"))]
response = requests.post(f"{API_BASE_URL}/vaults/{vault_id}/files", headers=headers, files=files)
file_id = response.json()["files"][0]["id"]
print(f"✅ Uploaded file: {file_id}")

# Download
print(f"📥 Attempting download...")
response = requests.get(f"{API_BASE_URL}/vaults/{vault_id}/files/{file_id}/download", headers=headers)
print(f"Status: {response.status_code}")

if response.status_code == 200:
    print(f"✅ SUCCESS! Downloaded {len(response.content)} bytes")
    print(f"Content matches: {response.content == test_content}")
else:
    print(f"❌ FAILED: {response.text}")
    print(f"\n⚠️  CHECK SERVER TERMINAL - should show full traceback now!")
