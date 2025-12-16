"""
Main Application Entry Point - Refactored with SOLID Principles
Separates application setup from business logic using dependency injection.
"""

import uvicorn
import logging
import re
from fastapi import FastAPI, Depends, Request, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from pydantic import BaseModel, Field, validator
from datetime import datetime

from config import settings
from dependencies import get_market_analysis_service
from auth import get_auth_service, get_current_user, AuthService
from middleware.rate_limit import default_limiter
from middleware.security import get_security_middlewares

# Load environment and configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create FastAPI application instance
app = FastAPI(
    title="Trade Opportunities API",
    description="FastAPI service for market data analysis and trade opportunity insights with SOLID architecture",
    version="2.0.0"  # Updated version reflecting SOLID refactoring
)

# Configure security middlewares first (order matters)
security_middlewares = get_security_middlewares()
for middleware_class in security_middlewares:
    app.add_middleware(middleware_class)

# Configure CORS middleware with security settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=settings.ALLOW_CREDENTIALS,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
)

# Configure rate limiting middleware
app.state.limiter = default_limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Pydantic request/response models with validation
class UserRegistrationRequest(BaseModel):
    """Request model for user registration"""
    username: str
    password: str

    @validator('username')
    def validate_username(cls, v):
        from auth import auth_service
        is_valid, error_msg = auth_service.validate_username(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v

    @validator('password')
    def validate_password(cls, v):
        from auth import auth_service
        is_valid, error_msg = auth_service.validate_password_strength(v)
        if not is_valid:
            raise ValueError(error_msg)
        return v

class UserLoginRequest(BaseModel):
    """Request model for user login"""
    username: str
    password: str

class TokenResponse(BaseModel):
    """Response model for authentication tokens"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(default_factory=lambda: settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)

class AnalysisResponse(BaseModel):
    """Response model for sector analysis"""
    report: str
    generated_at: str
    sector: str
    data_sources: int

class SectorAnalysisRequest(BaseModel):
    """Request model for sector analysis"""
    sector: str

    @validator('sector')
    def validate_sector(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Sector name cannot be empty")

        sector = v.lower().strip()

        if len(sector) < 2:
            raise ValueError("Sector name must be at least 2 characters long")

        if len(sector) > settings.MAX_SECTOR_NAME_LENGTH:
            raise ValueError(f"Sector name cannot exceed {settings.MAX_SECTOR_NAME_LENGTH} characters")

        if not re.match(f'^[{settings.ALLOWED_SECTOR_CHARS}]+$', sector):
            raise ValueError("Sector name contains invalid characters")

        return sector


# Route handlers - separated by concern
@app.post("/register", tags=["Authentication"], response_model=dict)
@default_limiter.limit("3 per hour")  # Limit registration attempts
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user with comprehensive validation.
    Includes password strength validation and username sanitization.
    """
    try:
        logger.info(f"Registration attempt for user: {username}")

        # Validate username
        is_valid_username, username_error = auth_service.validate_username(username)
        if not is_valid_username:
            raise HTTPException(status_code=400, detail=username_error)

        # Validate password strength
        is_valid_password, password_error = auth_service.validate_password_strength(password)
        if not is_valid_password:
            raise HTTPException(status_code=400, detail=password_error)

        # Additional server-side validation
        if len(username) > settings.MAX_USERNAME_LENGTH:
            raise HTTPException(status_code=400, detail=f"Username too long (max {settings.MAX_USERNAME_LENGTH} characters)")

        if len(password) > settings.MAX_PASSWORD_LENGTH:
            raise HTTPException(status_code=400, detail=f"Password too long (max {settings.MAX_PASSWORD_LENGTH} characters)")

        success = auth_service.register_user(username.strip(), password)

        if not success:
            raise HTTPException(status_code=400, detail="Username already registered")

        logger.info(f"User {username} registered successfully")
        return {"message": "User registered successfully", "username": username}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Registration error: {e}")
        raise HTTPException(status_code=500, detail="Registration failed due to server error")


@app.post("/token", tags=["Authentication"], response_model=TokenResponse)
@default_limiter.limit("5 per hour")  # Limit login attempts
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user and create session with JWT tokens.
    Includes session management and security tracking.
    """
    try:
        logger.info(f"Login attempt for user: {username}")

        # Authenticate user
        user = auth_service.authenticate_user(username.strip(), password)

        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        # Create session with tokens
        user_agent = request.headers.get("user-agent", "")
        ip_address = request.client.host if request.client else ""

        access_token, refresh_token = auth_service.create_session(
            username=user.username,
            user_agent=user_agent,
            ip_address=ip_address
        )

        logger.info(f"User {username} logged in successfully from {ip_address}")

        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for {username}: {e}")
        raise HTTPException(status_code=500, detail="Login failed due to server error")


@app.post("/logout", tags=["Authentication"])
async def logout(
    req: Request,
    current_user: dict = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Logout user and revoke current session.
    """
    try:
        # Extract token from request
        auth_header = req.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            auth_service.revoke_session(token)

        logger.info(f"User {current_user.username} logged out")
        return {"message": "Logged out successfully"}

    except Exception as e:
        logger.error(f"Logout error: {e}")
        raise HTTPException(status_code=500, detail="Logout failed")


@app.post("/refresh-token", tags=["Authentication"], response_model=TokenResponse)
async def refresh_access_token(
    refresh_token: str = Form(...),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Refresh access token using refresh token.
    """
    try:
        new_access_token = auth_service.refresh_access_token(refresh_token)

        if not new_access_token:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

        return TokenResponse(
            access_token=new_access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(status_code=500, detail="Token refresh failed")


@app.get("/analyze/{sector}", response_model=AnalysisResponse, tags=["Analysis"])
@default_limiter.limit("2 per minute")  # Stricter limit for analysis endpoint (uses AI)
async def analyze_sector(
    sector: str,
    request: Request,
    current_user: dict = Depends(get_current_user),
    analysis_service = Depends(get_market_analysis_service)
):
    """
    Analyze market sector and return comprehensive report.
    Following Dependency Inversion Principle - depends on abstractions, not concretions.
    """
    try:
        logger.info(f"Sector analysis request: {sector} by user: {current_user.username}")

        # Validate input
        sector = sector.lower().strip()
        if not sector or len(sector) < 2 or len(sector) > 50:
            raise HTTPException(status_code=400, detail="Invalid sector name")

        # Use dependency-injected service (all business logic abstracted)
        report = await analysis_service.analyze_sector(sector)

        logger.info(f"Successfully analyzed sector: {sector}")

        return AnalysisResponse(
            report=report,
            generated_at=datetime.utcnow().isoformat(),
            sector=sector,
            data_sources=1  # This would be obtained from the analysis service
        )

    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(f"Unexpected error analyzing sector {sector}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error during analysis"
        )


@app.get("/health", tags=["Health"])
async def health_check():
    """
    Health check endpoint for monitoring.
    Simple and independent - no dependencies needed.
    """
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0"
    }


# Application entry point
if __name__ == "__main__":
    logger.info("Starting Trade Opportunities API with SOLID architecture...")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
