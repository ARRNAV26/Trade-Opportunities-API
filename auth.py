"""
Authentication Service - Implements authentication business logic.
Follows SOLID principles with dependency injection and proper separation of concerns.
"""

from datetime import datetime, timedelta
from typing import Optional, Callable
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
import jwt
from passlib.context import CryptContext
import logging

from dependencies import get_user_repository
from config import settings

logger = logging.getLogger(__name__)

# Security components
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """
    Authentication service implementing Single Responsibility Principle.
    Handles user authentication, password management, and JWT token operations.
    """

    def __init__(self, user_repository_getter: Callable = get_user_repository):
        self.user_repository_getter = user_repository_getter
        self.pwd_context = pwd_context

    def hash_password(self, password: str) -> str:
        """Hash a plain text password"""
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.warning(f"Password verification error: {e}")
            return False

    def authenticate_user(self, username: str, password: str):
        """
        Authenticate a user by username and password.
        Returns user if authentication succeeds, None otherwise.
        """
        try:
            user_repo = self.user_repository_getter()

            # Find user
            user = user_repo.find_by_username(username)
            if not user:
                logger.info(f"User {username} not found")
                return None

            # Verify password
            if not self.verify_password(password, user.hashed_password):
                logger.info(f"Invalid password for user {username}")
                return None

            logger.info(f"User {username} authenticated successfully")
            return user

        except Exception as e:
            logger.error(f"Authentication error for {username}: {e}")
            return None

    def register_user(self, username: str, password: str) -> bool:
        """
        Register a new user.
        Returns True if successful, False otherwise.
        """
        try:
            user_repo = self.user_repository_getter()

            # Check if user already exists
            if user_repo.exists(username):
                logger.info(f"Registration failed: user {username} already exists")
                return False

            # Hash password and save user
            hashed_password = self.hash_password(password)

            from infrastructure.repositories.user_repository import User
            user = User(username=username, hashed_password=hashed_password)

            success = user_repo.save(user)

            if success:
                logger.info(f"User {username} registered successfully")
            else:
                logger.error(f"Failed to save user {username}")

            return success

        except Exception as e:
            logger.error(f"Registration error for {username}: {e}")
            return False

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()

        # Set expiration time
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)

        to_encode.update({"exp": expire})

        try:
            # Create and return JWT token
            encoded_jwt = jwt.encode(
                to_encode,
                settings.SECRET_KEY,
                algorithm=settings.ALGORITHM
            )
            return encoded_jwt

        except Exception as e:
            logger.error(f"Error creating access token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error creating access token"
            )

    def verify_token(self, credentials: HTTPAuthorizationCredentials):
        """
        Verify JWT token and return username.
        Raises HTTPException if token is invalid.
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            # Decode JWT token
            payload = jwt.decode(
                credentials.credentials,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )

            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception

            return username

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.JWTError:
            raise credentials_exception
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            raise credentials_exception

    def get_current_user(self, credentials: HTTPAuthorizationCredentials):
        """
        Get current authenticated user from JWT token.
        Returns user object if valid, raises HTTPException otherwise.
        """
        try:
            username = self.verify_token(credentials)

            user_repo = self.user_repository_getter()
            user = user_repo.find_by_username(username)

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            logger.info(f"Current user validated: {username}")
            return user

        except HTTPException:
            raise  # Re-raise HTTP exceptions
        except Exception as e:
            logger.error(f"Error getting current user: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )


# Global auth service instance for FastAPI dependency injection
auth_service = AuthService()


# FastAPI dependency functions
def get_auth_service() -> AuthService:
    """Dependency injection for auth service"""
    return auth_service


# FastAPI-compatible dependency functions
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = Depends(get_auth_service)
):
    """FastAPI dependency for getting current authenticated user"""
    return auth_service.get_current_user(credentials)
