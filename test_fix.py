import requests

BASE_URL = "http://localhost:5001"

def verify_fix():
    print("--- Verifying False Positive Fix ---")
    
    # 1. Test normal 'id' query (Should NOT redirect)
    print("Testing ?id=123 (Normal)...", end=" ")
    resp = requests.get(f"{BASE_URL}/products?id=123", allow_redirects=False)
    if resp.status_code == 200:
        print("OK (Pass)")
    else:
        print(f"FAILED (Status: {resp.status_code}, Location: {resp.headers.get('Location')})")

    # 2. Test actual attack pattern (Should STILL redirect)
    print("Testing SQLi pattern (Attack)...", end=" ")
    resp = requests.get(f"{BASE_URL}/products?q=union select 1", allow_redirects=False)
    if resp.status_code == 302:
        print(f"OK (Redirected to: {resp.headers.get('Location')})")
    else:
        print(f"FAILED (Status: {resp.status_code})")

    # 3. Test brute force redirection (Should be endpoint specific)
    print("\n--- Testing Brute Force Isolation ---")
    print("Triggering 5 failed logins...")
    for i in range(5):
        requests.post(f"{BASE_URL}/login", data={"username": "admin", "password": "pw"})
    
    print("Checking if /login is now redirected...", end=" ")
    resp = requests.get(f"{BASE_URL}/login", allow_redirects=False)
    if resp.status_code == 302:
        print("OK (Redirected)")
    else:
        print(f"FAILED (Status: {resp.status_code})")

    print("Checking if /about is STILL ACCESSIBLE...", end=" ")
    resp = requests.get(f"{BASE_URL}/about", allow_redirects=False)
    if resp.status_code == 200:
        print("OK (Pass)")
    else:
        print(f"FAILED (Blocked from legitimate page! Status: {resp.status_code})")

if __name__ == "__main__":
    verify_fix()
