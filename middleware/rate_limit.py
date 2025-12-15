"""
Rate Limiting Middleware - Following Single Responsibility Principle
Handles rate limiting configuration and setup.
"""

import logging
from slowapi import Limiter
from slowapi.util import get_remote_address
from config import settings

logger = logging.getLogger(__name__)


def get_rate_limiter() -> Limiter:
    """
    Factory function for creating rate limiter instance.
    Follows Open/Closed Principle - easy to extend or replace.
    """
    # Configure limiter with remote address as key
    limiter = Limiter(key_func=get_remote_address)

    logger.info("Rate limiter initialized with remote address key function")
    return limiter


# Default limiter instance for application-wide use
default_limiter = get_rate_limiter()
