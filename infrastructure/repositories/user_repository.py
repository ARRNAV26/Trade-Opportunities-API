"""
User Repository - Data access layer for user management.
Implements Repository pattern for data persistence abstraction.
"""

from typing import Dict, Optional, Protocol
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class User:
    """Domain model for User - immutable"""
    username: str
    hashed_password: str


class UserRepositoryInterface(Protocol):
    """Repository interface for user data operations"""

    def find_by_username(self, username: str) -> Optional[User]:
        """Find user by username"""
        pass

    def save(self, user: User) -> bool:
        """Save user to storage"""
        pass

    def exists(self, username: str) -> bool:
        """Check if user exists"""
        pass


class InMemoryUserRepository(UserRepositoryInterface):
    """
    In-memory implementation of UserRepository.
    Easy to replace with database implementation (following Open/Closed Principle).
    """

    def __init__(self):
        # In production, this would be your database connection
        self._storage: Dict[str, Dict] = {}

    def find_by_username(self, username: str) -> Optional[User]:
        """Find user by username"""
        user_data = self._storage.get(username)
        if user_data:
            return User(
                username=user_data["username"],
                hashed_password=user_data["hashed_password"]
            )
        return None

    def save(self, user: User) -> bool:
        """Save user to storage"""
        try:
            self._storage[user.username] = {
                "username": user.username,
                "hashed_password": user.hashed_password
            }
            logger.info(f"User {user.username} saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save user {user.username}: {e}")
            return False

    def exists(self, username: str) -> bool:
        """Check if user exists"""
        return username in self._storage
