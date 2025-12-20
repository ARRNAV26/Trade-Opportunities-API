"""
Trade Opportunities API - Curl Test Suite
Tests all API endpoints to verify functionality
"""

import subprocess
import json
import sys

def run_curl(command):
    """Run curl command and return response data"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return -1, "", str(e)

def test_health():
    """Test health check endpoint"""
    print("🔍 Testing Health Check...")
    curl_cmd = 'curl -s "http://localhost:8000/health"'
    returncode, stdout, stderr = run_curl(curl_cmd)

    if returncode == 0 and stdout:
        try:
            response = json.loads(stdout)
            print(f"✅ Health check PASSED: {response}")
            return True
        except json.JSONDecodeError:
            print(f"❌ Invalid JSON response: {stdout}")
            return False
    else:
        print(f"❌ Health check FAILED: {stderr}")
        return False

def test_register():
    """Test user registration"""
    print("\n🔍 Testing User Registration...")
    curl_cmd = 'curl -s -X POST "http://localhost:8000/register" -d "username=testuser&password=TestPass123!"'
    returncode, stdout, stderr = run_curl(curl_cmd)

    if returncode == 0 and stdout:
        try:
            response = json.loads(stdout)
            if response.get("message") == "User registered successfully":
                print("✅ Registration PASSED: User created successfully")
                return True
            else:
                print(f"❌ Unexpected response: {response}")
                return False
        except json.JSONDecodeError:
            print(f"❌ Invalid JSON response: {stdout}")
            return False
    else:
        print(f"❌ Registration FAILED: {stderr}")
        return False

def test_login():
    """Test user login and token generation"""
    print("\n🔍 Testing User Login...")
    curl_cmd = 'curl -s -X POST "http://localhost:8000/token" -d "username=testuser&password=testpass"'
    returncode, stdout, stderr = run_curl(curl_cmd)

    if returncode == 0 and stdout:
        try:
            response = json.loads(stdout)
            token = response.get("access_token")
            token_type = response.get("token_type")
            if token and token_type == "bearer":
                print(f"✅ Login PASSED: JWT token generated (length: {len(token)})")
                return token
            else:
                print(f"❌ Invalid token response: {response}")
                return None
        except json.JSONDecodeError:
            print(f"❌ Invalid JSON response: {stdout}")
            return None
    else:
        print(f"❌ Login FAILED: {stderr}")
        return None

def test_analyze(token):
    """Test sector analysis endpoint"""
    print("\n🔍 Testing Sector Analysis...")
    if not token:
        print("❌ No token available for analysis")
        return False

    curl_cmd = f'curl -s -X GET "http://localhost:8000/analyze/pharmaceuticals" -H "Authorization: Bearer {token}"'
    returncode, stdout, stderr = run_curl(curl_cmd)

    if returncode == 0 and stdout:
        try:
            response = json.loads(stdout)
            report = response.get("report", "")
            generated_at = response.get("generated_at", "")

            if report and generated_at:
                report_length = len(report)
                print(f"✅ Analysis PASSED: Generated {report_length} character report")
                print(f"📅 Generated at: {generated_at}")

                # Show a preview of the report
                report_preview = report[:200] + "..." if len(report) > 200 else report
                print(f"📄 Report Preview: {report_preview[:100]}...")

                return True
            else:
                print(f"❌ Invalid analysis response: {response}")
                return False
        except json.JSONDecodeError:
            print(f"❌ Invalid JSON response: {stdout}")
            return False
    else:
        print(f"❌ Analysis FAILED: {stderr}")
        return False

def main():
    """Run complete API test suite"""
    print("🚀 Trade Opportunities API - Curl Test Suite")
    print("=" * 50)

    # Check if curl is available
    print("🔧 Checking curl availability...")
    returncode, stdout, stderr = run_curl("curl --version")
    if returncode != 0:
        print("❌ curl is not available. Please install curl to run these tests.")
        sys.exit(1)
    print("✅ curl is available")

    # Run all tests
    results = []

    # Test 1: Health check
    results.append(test_health())

    # Test 2: Registration
    results.append(test_register())

    # Test 3: Login
    token = test_login()
    results.append(token is not None)

    # Test 4: Analysis
    results.append(test_analyze(token))

    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)

    tests = ["Health Check", "Registration", "Login", "Sector Analysis"]
    for i, (test_name, passed) in enumerate(zip(tests, results)):
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{i+1}. {test_name}: {status}")

    passed_count = sum(results)
    total_count = len(results)

    if passed_count == total_count:
        print(f"\n🎉 ALL TESTS PASSED! ({passed_count}/{total_count})")
        print("🟢 Trade Opportunities API is fully operational!")
        return 0
    else:
        print(f"\n⚠️  SOME TESTS FAILED ({passed_count}/{total_count})")
        print("Please check your API setup and try again.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
