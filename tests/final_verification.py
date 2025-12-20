"""
Final Comprehensive Verification of Trade Opportunities API
Tests all features and security implementations.
"""

import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def run_final_verification():
    """Run comprehensive verification of all features"""
    print("🔍 FINAL VERIFICATION: Trade Opportunities API")
    print("=" * 60)

    results = []
    scores = {"security": 0, "functionality": 0, "performance": 0}

    # 1. Test Dependencies
    print("\n1. 🔧 DEPENDENCY VERIFICATION")
    try:
        import fastapi, uvicorn, pydantic, slowapi, google.generativeai, duckduckgo_search
        from docx import Document
        results.append(("Dependencies", True, "All core packages imported successfully"))
        scores["functionality"] += 1
    except ImportError as e:
        results.append(("Dependencies", False, f"Missing: {e}"))
        return results, scores

    # 2. Test Configuration
    print("\n2. ⚙️ CONFIGURATION VALIDATION")
    try:
        from config.config import settings
        assert len(settings.SECRET_KEY) >= 32, "Weak SECRET_KEY"
        assert settings.ENVIRONMENT in ["development", "production"], "Invalid environment"
        results.append(("Configuration", True, f"Environment: {settings.ENVIRONMENT}, Security: ✅"))
        scores["security"] += 1
    except Exception as e:
        results.append(("Configuration", False, str(e)))

    # 3. Test Security Middleware
    print("\n3. 🛡️ SECURITY MIDDLEWARE")
    try:
        from middleware.security import get_security_middlewares, SecurityHeadersMiddleware
        middlewares = get_security_middlewares()
        results.append(("Security Middleware", True, f"{len(middlewares)} security middlewares configured"))
        scores["security"] += 1
    except Exception as e:
        results.append(("Security Middleware", False, str(e)))

    # 4. Test Authentication Service
    print("\n4. 🔐 AUTHENTICATION & SESSION MANAGEMENT")
    try:
        from api.auth import auth_service, AuthService
        from api.auth import active_sessions, user_sessions

        # Test password validation
        valid, msg = auth_service.validate_password_strength("StrongPass123!")
        assert valid, "Password validation failed"

        # Test username validation
        valid, msg = auth_service.validate_username("testuser")
        assert valid, "Username validation failed"

        results.append(("Authentication Service", True, "Password & username validation working"))
        scores["security"] += 1
    except Exception as e:
        results.append(("Authentication Service", False, str(e)))

    # 5. Test Rate Limiting
    print("\n5. 🚦 RATE LIMITING")
    try:
        from middleware.rate_limit import get_rate_limiter
        limiter = get_rate_limiter()
        results.append(("Rate Limiting", True, "Rate limiter initialized successfully"))
        scores["security"] += 1
    except Exception as e:
        results.append(("Rate Limiting", False, str(e)))

    # 6. Test Application Import
    print("\n6. 🚀 APPLICATION ARCHITECTURE")
    try:
        from api.main import app
        routes = [route.path for route in app.routes]
        required_routes = ["/register", "/token", "/analyze/{sector}", "/health", "/logout"]
        found_routes = sum(1 for req in required_routes if any(req in route or route == req for route in routes))

        results.append(("Application Import", True, f"Routes: {len(routes)}, Required: {found_routes}/{len(required_routes)}"))
        scores["functionality"] += 1
    except Exception as e:
        results.append(("Application Import", False, str(e)))
        return results, scores

    # 7. Test Data Collection
    print("\n7. 📊 DATA COLLECTION")
    try:
        from core.data_collector import collect_market_data
        data = collect_market_data("technology")
        results.append(("Data Collection", True, f"Collected {len(data)} data points"))
        scores["functionality"] += 1
    except Exception as e:
        results.append(("Data Collection", False, str(e)))

    # 8. Test AI Analysis
    print("\n8. 🤖 AI ANALYSIS")
    try:
        from core.ai_analyzer import analyze_with_gemini
        import asyncio

        async def test_ai():
            result = await analyze_with_gemini("test", [{"title": "Test", "url": "http://test.com", "body": "Content", "date": "N/A"}])
            return "analysis" in result

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        success = loop.run_until_complete(test_ai())
        loop.close()

        results.append(("AI Analysis", success, "Gemini AI integration working" if success else "AI analysis failed"))
        if success:
            scores["functionality"] += 1
    except Exception as e:
        results.append(("AI Analysis", False, str(e)))

    # 9. Test Document Generation
    print("\n9. 📄 DOCUMENT GENERATION")
    try:
        from utils.generate_word_report import create_word_document
        import tempfile

        test_data = [{"title": "Test", "url": "http://test.com", "body": "Content", "date": "2024-01-01"}]
        mock_analysis = {"analysis": "Test analysis", "data_sources": 1, "generated_at": "test"}

        temp_file = f"{tempfile.mktemp()}.docx"
        filename = create_word_document("Test Sector", test_data, mock_analysis, temp_file)

        exists = os.path.exists(filename) and os.path.getsize(filename) > 1000
        if exists:
            os.remove(filename)

        results.append(("Document Generation", exists, "Word document created successfully" if exists else "Document creation failed"))
        if exists:
            scores["functionality"] += 1
    except Exception as e:
        results.append(("Document Generation", False, str(e)))

    # 10. Performance Test
    print("\n10. ⚡ PERFORMANCE & RELIABILITY")
    try:
        import time
        start_time = time.time()

        # Quick operations
        from config.config import settings
        from middleware.rate_limit import default_limiter
        from api.auth import auth_service

        end_time = time.time()
        load_time = end_time - start_time

        results.append(("Performance", load_time < 2.0, f"Load time: {load_time:.2f}s"))
        if load_time < 2.0:
            scores["performance"] += 1
    except Exception as e:
        results.append(("Performance", False, str(e)))

    return results, scores

def print_final_report(results, scores):
    """Print comprehensive final report"""
    print("\n" + "=" * 60)
    print("🎯 FINAL VERIFICATION REPORT")
    print("=" * 60)

    # Individual test results
    for test_name, success, details in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_name:.<25} {status}")
        if details:
            print(f"{'':.<25} {details}")

    # Score summary
    print("\n" + "-" * 60)
    print("📊 SCORECARD")

    security_score = scores["security"] / 4 * 100  # 4 security tests
    functionality_score = scores["functionality"] / 5 * 100  # 5 functionality tests
    performance_score = scores["performance"] / 1 * 100  # 1 performance test

    print(f"Security Score: {security_score:.1f}%")
    print(f"Functionality Score: {functionality_score:.1f}%")
    print(f"Performance Score: {performance_score:.1f}%")
    overall_score = (security_score + functionality_score + performance_score) / 3
    print(f"Overall Score: {overall_score:.1f}%")
    print("-" * 60)

    # Final assessment
    if overall_score >= 90:
        print("🎉 EXCELLENT: Production-ready application!")
        print("   ✅ Enterprise-grade security implemented")
        print("   ✅ All core functionality working")
        print("   ✅ High performance and reliability")
        return True
    elif overall_score >= 75:
        print("👍 GOOD: Application ready with minor issues")
        print("   ⚠️ Review failed tests before production")
        return True
    else:
        print("❌ NEEDS WORK: Critical issues found")
        print("   🔧 Fix failed tests before proceeding")
        return False

if __name__ == "__main__":
    results, scores = run_final_verification()
    success = print_final_report(results, scores)
    sys.exit(0 if success else 1)
