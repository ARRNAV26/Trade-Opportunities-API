"""
Security Middleware - Implements comprehensive security best practices
Handles security headers, HTTPS enforcement, and security validations.
Optimized for performance while maintaining security.
"""

import re
import logging
from typing import List, Set
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from config import settings

logger = logging.getLogger(__name__)

# Pre-compile regex patterns for better performance
SQL_INJECTION_PATTERNS = [
    re.compile(r';\s*--', re.IGNORECASE),  # SQL comment
    re.compile(r';\s*/\*', re.IGNORECASE),  # SQL block comment start
    re.compile(r'union\s+select', re.IGNORECASE),  # UNION SELECT
    re.compile(r'drop\s+table', re.IGNORECASE),  # DROP TABLE
    re.compile(r'alter\s+table', re.IGNORECASE),  # ALTER TABLE
]

XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE),  # Script tags
    re.compile(r'javascript:', re.IGNORECASE),  # JavaScript protocol
    re.compile(r'on\w+\s*=', re.IGNORECASE),  # Event handlers
]

# Define sensitive endpoints that need full validation
SENSITIVE_ENDPOINTS: Set[str] = {
    "/register", "/token", "/analyze/", "/refresh-token"
}

# Simple validation cache to avoid repeated checks
VALIDATION_CACHE_SIZE = 1000
validation_cache: dict = {}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware for adding comprehensive security headers"""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.security_headers = {
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            # XSS protection
            "X-XSS-Protection": "1; mode=block",
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            # Content Security Policy
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            # HSTS (HTTP Strict Transport Security) - only if HTTPS is enabled
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains" if settings.ENABLE_HTTPS_REDIRECT else None,
            # Permissions policy
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        }

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if settings.ENABLE_SECURITY_HEADERS:
            for header, value in self.security_headers.items():
                if value is not None:
                    response.headers[header] = value

        return response


class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce HTTPS redirects"""

    async def dispatch(self, request: Request, call_next):
        if settings.ENABLE_HTTPS_REDIRECT and request.url.scheme == "http":
            # Redirect to HTTPS
            url = request.url.replace(scheme="https")
            return RedirectResponse(url=str(url), status_code=301)

        response = await call_next(request)
        return response


class HostValidationMiddleware(BaseHTTPMiddleware):
    """Middleware to validate trusted hosts"""

    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.trusted_hosts = set(settings.TRUSTED_HOSTS)

    async def dispatch(self, request: Request, call_next):
        host = request.headers.get("host", "").split(":")[0]

        # In production, validate host
        if settings.ENVIRONMENT == "production" and host not in self.trusted_hosts:
            logger.warning(f"Untrusted host access attempt: {host}")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Host not allowed"}
            )

        response = await call_next(request)
        return response


class OptimizedInputValidationMiddleware(BaseHTTPMiddleware):
    """Optimized middleware for input validation and sanitization"""

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint needs full validation"""
        return any(path.startswith(endpoint) for endpoint in SENSITIVE_ENDPOINTS)

    def _validate_with_cache(self, value: str, patterns: list, cache_key: str) -> bool:
        """Validate with caching to improve performance"""
        if not isinstance(value, str) or len(value) > 2000:  # Skip very long values
            return True

        # Check cache first
        cache_key_full = f"{cache_key}:{hash(value)}"
        if cache_key_full in validation_cache:
            return validation_cache[cache_key_full]

        # Perform validation
        for pattern in patterns:
            if pattern.search(value):
                logger.warning(f"Security threat detected: {cache_key} in {value[:50]}...")
                validation_cache[cache_key_full] = False
                return False

        # Cache positive result
        if len(validation_cache) < VALIDATION_CACHE_SIZE:
            validation_cache[cache_key_full] = True

        return True

    def _quick_validate(self, value: str, max_length: int = 1000) -> bool:
        """Fast validation for common cases"""
        if not isinstance(value, str):
            return True

        if len(value) > max_length:
            return False

        # Quick checks for obvious malicious content
        if '\x00' in value:  # Null bytes
            return False

        if '<script' in value.lower() or 'javascript:' in value.lower():
            return False

        return True

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip full validation for non-sensitive endpoints (like health check)
        is_sensitive = self._is_sensitive_endpoint(path)

        # Always do basic validation for query parameters
        for key, value in request.query_params.items():
            if not self._quick_validate(key, 100) or not self._quick_validate(value, 500):
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid query parameters"}
                )

        # Full validation only for sensitive endpoints
        if is_sensitive:
            # Validate form data with optimized patterns
            if hasattr(request, '_form') and request._form:
                for key, value in request._form.items():
                    if isinstance(value, str):
                        if not self._quick_validate(key, 100):
                            return JSONResponse(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                content={"detail": "Invalid form data"}
                            )

                        # Only do expensive validation for potentially dangerous content
                        if len(value) < 1000:  # Skip very long values for performance
                            if not self._validate_with_cache(value, SQL_INJECTION_PATTERNS, "sql") or \
                               not self._validate_with_cache(value, XSS_PATTERNS, "xss"):
                                return JSONResponse(
                                    status_code=status.HTTP_400_BAD_REQUEST,
                                    content={"detail": "Invalid form data"}
                                )

        response = await call_next(request)
        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for secure error handling without information leakage"""

    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            # Log the actual error for debugging
            logger.error(f"Unhandled error in {request.method} {request.url.path}: {str(e)}", exc_info=True)

            # Return generic error message to prevent information leakage
            if settings.ENVIRONMENT == "production":
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"detail": "Internal server error"}
                )
            else:
                # In development, show actual error for debugging
                return JSONResponse(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    content={"detail": f"Internal server error: {str(e)}"}
                )


def get_security_middlewares():
    """Get list of security middlewares to apply"""
    middlewares = []

    if settings.ENABLE_HTTPS_REDIRECT:
        middlewares.append(HTTPSRedirectMiddleware)

    middlewares.extend([
        HostValidationMiddleware,
        SecurityHeadersMiddleware,
        OptimizedInputValidationMiddleware,  # Use optimized version
        ErrorHandlingMiddleware,
    ])

    return middlewares
