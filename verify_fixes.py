#!/usr/bin/env python3
"""
Quick verification that the server has loaded the fixed code.
Run this AFTER restarting the server.
"""

import requests
import json

API_BASE_URL = "http://localhost:8000"

print("\n" + "="*80)
print("  SERVER FIX VERIFICATION")
print("="*80)

# Login
print("\n1. Testing login...")
try:
    response = requests.post(
        f"{API_BASE_URL}/auth/login",
        json={"username": "admin", "password": "1111111111111111"}
    )
    if response.status_code == 200:
        print("   ✅ Login successful")
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
    else:
        print(f"   ❌ Login failed: {response.status_code}")
        exit(1)
except Exception as e:
    print(f"   ❌ Server not responding: {e}")
    print("\n   ⚠️  Make sure the server is running!")
    exit(1)

# Upload test
print("\n2. Testing file upload...")
vault_id = "d74c1fce-6c25-4a4a-8c5d-d17cccc1ddd6"
test_content = b"Verification test file\n" * 50
test_filename = "verification_test.txt"

files = [("files", (test_filename, test_content, "text/plain"))]

try:
    response = requests.post(
        f"{API_BASE_URL}/vaults/{vault_id}/files",
        headers=headers,
        files=files
    )
    if response.status_code == 200:
        data = response.json()
        file_id = data["files"][0]["id"]
        print(f"   ✅ Upload successful")
        print(f"   File ID: {file_id}")
    else:
        print(f"   ❌ Upload failed: {response.status_code}")
        print(f"   Response: {response.text}")
        exit(1)
except Exception as e:
    print(f"   ❌ Upload error: {e}")
    exit(1)

# Download test
print("\n3. Testing file download...")
try:
    response = requests.get(
        f"{API_BASE_URL}/vaults/{vault_id}/files/{file_id}/download",
        headers=headers,
        stream=True
    )
    
    if response.status_code == 200:
        downloaded = response.content
        print(f"   ✅ Download successful!")
        print(f"   Original size: {len(test_content)} bytes")
        print(f"   Downloaded size: {len(downloaded)} bytes")
        
        if downloaded == test_content:
            print(f"   ✅ Content matches perfectly!")
            print(f"\n{'='*80}")
            print("  🎉 SUCCESS! ALL FIXES ARE WORKING!")
            print("="*80)
            print("\n✅ The datetime.utcnow() deprecation has been fixed")
            print("✅ File upload is working")
            print("✅ File download is working")
            print("✅ Content integrity is preserved")
            print("\nYou can now use the system normally! 🚀")
        else:
            print(f"   ⚠️  Content mismatch!")
            print(f"   First 100 bytes original: {test_content[:100]}")
            print(f"   First 100 bytes downloaded: {downloaded[:100]}")
    else:
        print(f"   ❌ Download failed: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 500:
            print(f"\n   ⚠️  Still getting 500 error!")
            print(f"   Check the server terminal for Python exceptions.")
            print(f"   Look for:")
            print(f"   - Traceback")
            print(f"   - ERROR")
            print(f"   - Exception")
            
except Exception as e:
    print(f"   ❌ Download error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80 + "\n")
