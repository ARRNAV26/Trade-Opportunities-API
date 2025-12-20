"""
Comprehensive Security Test Suite
Tests all security features implemented in the application.
"""

import asyncio
import requests
import time
import json
from concurrent.futures import ThreadPoolExecutor
import os

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_USERNAME = "testuser123"
TEST_PASSWORD = "StrongPass123!"

def test_cors_headers():
    """Test CORS headers are properly set"""
    print("Testing CORS headers...")
    try:
        response = requests.options(f"{BASE_URL}/health",
                                  headers={"Origin": "http://localhost:3000"})
        cors_headers = [
            'access-control-allow-origin',
            'access-control-allow-methods',
            'access-control-allow-headers'
        ]
        present_headers = [h for h in cors_headers if h in response.headers]
        print(f"   ✅ CORS headers present: {len(present_headers)}/{len(cors_headers)}")
        return len(present_headers) > 0
    except Exception as e:
        print(f"   ❌ CORS test failed: {e}")
        return False

def test_security_headers():
    """Test security headers are properly set"""
    print("Testing security headers...")
    try:
        response = requests.get(f"{BASE_URL}/health")
        security_headers = [
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'content-security-policy'
        ]
        present_headers = [h for h in security_headers if h in response.headers]
        print(f"   ✅ Security headers present: {len(present_headers)}/{len(security_headers)}")
        return len(present_headers) >= 2  # At least some security headers
    except Exception as e:
        print(f"   ❌ Security headers test failed: {e}")
        return False

def test_rate_limiting():
    """Test rate limiting functionality"""
    print("Testing rate limiting...")
    try:
        # Test health endpoint (should not be rate limited)
        responses = []
        for i in range(10):
            response = requests.get(f"{BASE_URL}/health")
            responses.append(response.status_code)

        success_count = sum(1 for r in responses if r == 200)
        print(f"   ✅ Health endpoint responses: {success_count}/10 successful")

        # Test registration endpoint (should be rate limited)
        reg_responses = []
        for i in range(5):  # Should hit rate limit
            response = requests.post(f"{BASE_URL}/register",
                                   data={"username": f"test{i}", "password": "password123"})
            reg_responses.append(response.status_code)

        rate_limited = any(r == 429 for r in reg_responses)
        print(f"   ✅ Rate limiting working: {rate_limited}")
        return success_count >= 8 and rate_limited

    except Exception as e:
        print(f"   ❌ Rate limiting test failed: {e}")
        return False

def test_input_validation():
    """Test input validation"""
    print("Testing input validation...")
    try:
        # Test invalid sector name
        # First register and login to get token
        reg_response = requests.post(f"{BASE_URL}/register",
                                   data={"username": TEST_USERNAME, "password": TEST_PASSWORD})
        if reg_response.status_code not in [200, 400]:  # 400 is ok if user exists
            print("   ⚠️ Registration response unexpected, but continuing...")

        login_response = requests.post(f"{BASE_URL}/token",
                                     data={"username": TEST_USERNAME, "password": TEST_PASSWORD})

        if login_response.status_code == 200:
            token_data = login_response.json()
            token = token_data.get("access_token")

            headers = {"Authorization": f"Bearer {token}"}

            # Test invalid sector
            invalid_response = requests.get(f"{BASE_URL}/analyze/<script>alert('xss')</script>",
                                          headers=headers)
            xss_blocked = invalid_response.status_code in [400, 422]

            # Test empty sector
            empty_response = requests.get(f"{BASE_URL}/analyze/",
                                        headers=headers)
            empty_blocked = empty_response.status_code == 404  # Route not found

            print(f"   ✅ XSS protection: {xss_blocked}")
            print(f"   ✅ Invalid input handling: {empty_blocked}")
            return xss_blocked and empty_blocked
        else:
            print("   ❌ Could not get authentication token")
            return False

    except Exception as e:
        print(f"   ❌ Input validation test failed: {e}")
        return False

def test_authentication_flow():
    """Test complete authentication flow"""
    print("Testing authentication flow...")
    try:
        # Test registration
        reg_response = requests.post(f"{BASE_URL}/register",
                                   data={"username": "authtest", "password": "AuthTest123!"})
        reg_success = reg_response.status_code in [200, 400]  # 400 if already exists

        # Test login
        login_response = requests.post(f"{BASE_URL}/token",
                                     data={"username": "authtest", "password": "AuthTest123!"})
        login_success = login_response.status_code == 200

        if login_success:
            token_data = login_response.json()
            token = token_data.get("access_token")

            # Test protected endpoint
            headers = {"Authorization": f"Bearer {token}"}
            analysis_response = requests.get(f"{BASE_URL}/analyze/technology", headers=headers)
            protected_success = analysis_response.status_code in [200, 429]  # 429 is rate limit

            # Test logout
            logout_response = requests.post(f"{BASE_URL}/logout", headers=headers)
            logout_success = logout_response.status_code == 200

            print(f"   ✅ Registration: {reg_success}")
            print(f"   ✅ Login: {login_success}")
            print(f"   ✅ Protected access: {protected_success}")
            print(f"   ✅ Logout: {logout_success}")

            return reg_success and login_success and protected_success and logout_success
        else:
            print("   ❌ Login failed")
            return False

    except Exception as e:
        print(f"   ❌ Authentication flow test failed: {e}")
        return False

def test_error_handling():
    """Test error handling and information leakage prevention"""
    print("Testing error handling...")
    try:
        # Test invalid endpoint
        invalid_response = requests.get(f"{BASE_URL}/nonexistent")
        not_found = invalid_response.status_code == 404

        # Test invalid method
        method_response = requests.post(f"{BASE_URL}/health")
        method_not_allowed = method_response.status_code == 405

        # Test malformed request
        malformed_response = requests.get(f"{BASE_URL}/analyze/technology",
                                        headers={"Authorization": "InvalidToken"})
        unauthorized = malformed_response.status_code == 401

        print(f"   ✅ 404 handling: {not_found}")
        print(f"   ✅ Method validation: {method_not_allowed}")
        print(f"   ✅ Unauthorized access: {unauthorized}")

        return not_found and method_not_allowed and unauthorized

    except Exception as e:
        print(f"   ❌ Error handling test failed: {e}")
        return False

def run_comprehensive_test():
    """Run all security tests"""
    print("🔒 COMPREHENSIVE SECURITY TEST SUITE")
    print("=" * 50)

    # Check if server is running
    try:
        health_response = requests.get(f"{BASE_URL}/health", timeout=5)
        if health_response.status_code != 200:
            print("❌ Server not responding properly")
            return False
        print("✅ Server is running and healthy")
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("Please start the server with: python main.py")
        return False

    tests = [
        ("CORS Headers", test_cors_headers),
        ("Security Headers", test_security_headers),
        ("Rate Limiting", test_rate_limiting),
        ("Input Validation", test_input_validation),
        ("Authentication Flow", test_authentication_flow),
        ("Error Handling", test_error_handling),
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n🧪 Running {test_name}...")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ Test crashed: {e}")
            results.append((test_name, False))

    # Summary
    print("\n" + "=" * 50)
    print("SECURITY TEST RESULTS")
    print("=" * 50)

    passed = 0
    total = len(results)

    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_name}: {status}")
        if success:
            passed += 1

    print(f"\nOVERALL SECURITY SCORE: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 ALL SECURITY TESTS PASSED! 🎉")
        print("Your application has robust security measures in place.")
        return True
    else:
        print(f"\n⚠️ {total - passed} security test(s) failed")
        print("Please review and fix the failing security measures.")
        return False

if __name__ == "__main__":
    success = run_comprehensive_test()
    exit(0 if success else 1)
