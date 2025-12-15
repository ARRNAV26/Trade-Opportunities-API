"""
Dependency Injection Container - Implements DIP (Dependency Inversion Principle).
Provides centralized dependency management for easy testing and maintainability.
"""

from functools import lru_cache
from typing import Callable, Any
from services.market_analysis_service import (
    MarketAnalysisService,
    DataCollectorInterface,
    AIAnalyzerInterface,
    ReportGeneratorInterface
)
from infrastructure.repositories.user_repository import (
    UserRepositoryInterface,
    InMemoryUserRepository
)
from infrastructure.services import (
    DataCollectorAdapter,
    AIAnalyzerAdapter,
    ReportGeneratorAdapter
)


# Dependency Injection Container
class DependencyContainer:
    """Centralized dependency management following Dependency Inversion Principle"""

    def __init__(self):
        self._dependencies: dict[str, Any] = {}

    def register(self, interface: type, implementation_factory: Callable[[], Any]):
        """Register a factory function for an interface"""
        self._dependencies[interface.__name__] = implementation_factory

    def resolve(self, interface: type) -> Any:
        """Resolve (get) an instance of the registered interface"""
        if interface.__name__ not in self._dependencies:
            raise ValueError(f"No registration found for {interface.__name__}")
        return self._dependencies[interface.__name__]()


# Global container instance - in production, this would be managed by a DI framework
_container = DependencyContainer()


# Registration of dependencies
def setup_dependencies():
    """Initialize all dependency registrations"""

    # Repository dependencies
    _container.register(UserRepositoryInterface, InMemoryUserRepository)

    # Service adapters
    _container.register(DataCollectorInterface, DataCollectorAdapter)
    _container.register(AIAnalyzerInterface, AIAnalyzerAdapter)
    _container.register(ReportGeneratorInterface, ReportGeneratorAdapter)


# Dependency getter functions (used by FastAPI dependency injection)
@lru_cache()
def get_user_repository() -> UserRepositoryInterface:
    """Get user repository instance"""
    return _container.resolve(UserRepositoryInterface)


@lru_cache()
def get_market_analysis_service() -> MarketAnalysisService:
    """Get market analysis service instance with all dependencies injected"""
    data_collector = _container.resolve(DataCollectorInterface)
    ai_analyzer = _container.resolve(AIAnalyzerInterface)
    report_generator = _container.resolve(ReportGeneratorInterface)

    return MarketAnalysisService(
        data_collector=data_collector,
        ai_analyzer=ai_analyzer,
        report_generator=report_generator
    )


# Initialize dependencies on module import
setup_dependencies()
