"""
Authentication Service - Implements authentication business logic.
Follows SOLID principles with dependency injection and proper separation of concerns.
Enhanced with session management, password validation, and security best practices.
"""

import re
import secrets
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, List
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security import HTTPBearer
import jwt
from passlib.context import CryptContext
import logging

from scripts.dependencies import get_user_repository
from config.config import settings

logger = logging.getLogger(__name__)

# Security components
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Session storage (in production, use Redis or database)
active_sessions: Dict[str, Dict] = {}  # token -> session_info
user_sessions: Dict[str, List[str]] = {}  # username -> list of tokens


class AuthService:
    """
    Authentication service implementing Single Responsibility Principle.
    Handles user authentication, password management, JWT token operations,
    session management, and security validation.
    """

    def __init__(self, user_repository_getter: Callable = get_user_repository):
        self.user_repository_getter = user_repository_getter
        self.pwd_context = pwd_context

    def validate_password_strength(self, password: str) -> tuple[bool, str]:
        """
        Validate password strength based on configuration requirements.
        Optimized with pre-compiled patterns and early returns.
        """
        # Quick length check first
        if len(password) < settings.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long"

        # Convert to set for O(1) lookups instead of regex
        chars = set(password)

        # Check character requirements with set operations (much faster)
        if settings.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if settings.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if settings.PASSWORD_REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        if settings.PASSWORD_REQUIRE_SPECIAL_CHARS:
            # Use set intersection for fast special character check
            special_chars = set('!@#$%^&*(),.?":{}|<>')
            if not chars & special_chars:
                return False, "Password must contain at least one special character"

        return True, ""

    def validate_username(self, username: str) -> tuple[bool, str]:
        """
        Validate username format and constraints.
        Returns (is_valid, error_message)
        """
        if not username or len(username.strip()) == 0:
            return False, "Username cannot be empty"

        username = username.strip()

        if len(username) > settings.MAX_USERNAME_LENGTH:
            return False, f"Username cannot exceed {settings.MAX_USERNAME_LENGTH} characters"

        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"

        # Check for reserved usernames
        reserved = ['admin', 'root', 'system', 'api', 'user', 'guest']
        if username.lower() in reserved:
            return False, "This username is reserved"

        return True, ""

    def create_session(self, username: str, user_agent: str = "", ip_address: str = "") -> tuple[str, str]:
        """
        Create a new session for the user.
        Returns (access_token, refresh_token)
        """
        # Check concurrent session limit
        user_tokens = user_sessions.get(username, [])
        if len(user_tokens) >= settings.SESSION_MAX_CONCURRENT:
            # Remove oldest session if limit exceeded
            oldest_token = user_tokens[0]
            if oldest_token in active_sessions:
                del active_sessions[oldest_token]
            user_tokens = user_tokens[1:]

        # Create access token
        access_token_data = {"sub": username, "type": "access"}
        access_token = self.create_access_token(access_token_data)

        # Create refresh token
        refresh_token = secrets.token_urlsafe(32)
        refresh_expires = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        # Store session info
        session_info = {
            "username": username,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "created_at": datetime.utcnow(),
            "expires_at": refresh_expires,
            "user_agent": user_agent,
            "ip_address": ip_address,
            "active": True
        }

        active_sessions[access_token] = session_info

        # Track user sessions
        if username not in user_sessions:
            user_sessions[username] = []
        user_sessions[username].append(access_token)

        logger.info(f"Session created for user {username}")
        return access_token, refresh_token

    def validate_session(self, token: str) -> bool:
        """
        Validate if a session is active and not expired.
        """
        if token not in active_sessions:
            return False

        session = active_sessions[token]
        if not session["active"]:
            return False

        # Check if session has timed out
        if datetime.utcnow() - session["created_at"] > timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES):
            self.revoke_session(token)
            return False

        return True

    def revoke_session(self, token: str):
        """
        Revoke a specific session.
        """
        if token in active_sessions:
            session = active_sessions[token]
            username = session["username"]

            # Remove from active sessions
            session["active"] = False
            del active_sessions[token]

            # Remove from user sessions
            if username in user_sessions and token in user_sessions[username]:
                user_sessions[username].remove(token)

            logger.info(f"Session revoked for user {username}")

    def revoke_user_sessions(self, username: str):
        """
        Revoke all sessions for a user.
        """
        if username in user_sessions:
            tokens_to_revoke = user_sessions[username].copy()
            for token in tokens_to_revoke:
                self.revoke_session(token)
            logger.info(f"All sessions revoked for user {username}")

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """
        Create a new access token using refresh token.
        Returns new access token or None if invalid.
        """
        # Find session with matching refresh token
        for token, session in active_sessions.items():
            if session["refresh_token"] == refresh_token and session["active"]:
                # Check if refresh token is expired
                if datetime.utcnow() > session["expires_at"]:
                    self.revoke_session(token)
                    return None

                # Create new access token
                username = session["username"]
                new_access_token_data = {"sub": username, "type": "access"}
                new_access_token = self.create_access_token(new_access_token_data)

                # Update session with new access token
                session["access_token"] = new_access_token
                active_sessions[new_access_token] = session
                del active_sessions[token]

                # Update user sessions list
                user_sessions[username].remove(token)
                user_sessions[username].append(new_access_token)

                logger.info(f"Access token refreshed for user {username}")
                return new_access_token

        return None

    def cleanup_expired_sessions(self):
        """
        Clean up expired sessions (should be called periodically).
        """
        current_time = datetime.utcnow()
        expired_tokens = []

        for token, session in active_sessions.items():
            if not session["active"] or current_time > session["expires_at"]:
                expired_tokens.append(token)

        for token in expired_tokens:
            session = active_sessions[token]
            username = session["username"]
            self.revoke_session(token)
            logger.info(f"Cleaned up expired session for user {username}")

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
