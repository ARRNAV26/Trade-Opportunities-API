"""
Rate Limiting Middleware - Following Single Responsibility Principle
Handles rate limiting configuration and setup.
"""

import logging
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from config import settings

logger = logging.getLogger(__name__)


def get_rate_limiter() -> Limiter:
    """
    Factory function for creating rate limiter instance with configured limits.
    Follows Open/Closed Principle - easy to extend or replace.
    """
    # Configure limiter with remote address as key and configured limits
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[f"{settings.RATE_LIMIT_REQUESTS} per {settings.RATE_LIMIT_WINDOW_MINUTES} minutes"]
    )

    logger.info(f"Rate limiter initialized with limits: {settings.RATE_LIMIT_REQUESTS} requests per {settings.RATE_LIMIT_WINDOW_MINUTES} minutes")
    return limiter


def get_slowapi_middleware():
    """
    Get the SlowAPI middleware class for FastAPI.
    Note: This is just a reference, FastAPI will handle instantiation.
    """
    return SlowAPIMiddleware


# Default limiter instance for application-wide use
default_limiter = get_rate_limiter()
