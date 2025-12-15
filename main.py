"""
Main Application Entry Point - Refactored with SOLID Principles
Separates application setup from business logic using dependency injection.
"""

import uvicorn
import logging
from fastapi import FastAPI, Depends, Request, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from pydantic import BaseModel, Field
from datetime import datetime

from config import settings
from dependencies import get_market_analysis_service
from auth import get_auth_service, get_current_user, AuthService

# Load environment and configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create FastAPI application instance
app = FastAPI(
    title="Trade Opportunities API",
    description="FastAPI service for market data analysis and trade opportunity insights with SOLID architecture",
    version="2.0.0"  # Updated version reflecting SOLID refactoring
)

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure rate limiting middleware
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Pydantic response models
class AnalysisResponse(BaseModel):
    """Response model for sector analysis"""
    report: str
    generated_at: str


# Route handlers - separated by concern
@app.post("/register", tags=["Authentication"])
async def register(
    username: str = Form(...),
    password: str = Form(...),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user with dependency injection.
    Following Single Responsibility Principle - only handles registration.
    """
    logger.info(f"Registration attempt for user: {username}")

    success = auth_service.register_user(username, password)

    if not success:
        raise HTTPException(status_code=400, detail="Username already registered")

    return {"message": "User registered successfully"}


@app.post("/token", tags=["Authentication"])
async def login(
    username: str = Form(...),
    password: str = Form(...),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user and return JWT token.
    Following Single Responsibility Principle - only handles authentication.
    """
    logger.info(f"Login attempt for user: {username}")

    user = auth_service.authenticate_user(username, password)

    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # Create access token with proper expiration
    access_token_expires_minutes = getattr(settings, 'ACCESS_TOKEN_EXPIRE_MINUTES', 30)
    access_token = auth_service.create_access_token(
        data={"sub": user.username},
        expires_delta=None  # Uses default expiration
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/analyze/{sector}", response_model=AnalysisResponse, tags=["Analysis"])
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
            generated_at=datetime.utcnow().isoformat()
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
