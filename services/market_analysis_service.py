"""
Market Analysis Service - Implements business logic for market data analysis.
Follows SOLID principles with dependency injection.
"""

from typing import List, Dict, Protocol, Any
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


# Data models (would typically be in a separate models module)
class MarketData:
    """Represents market data from web search"""
    def __init__(self, title: str, url: str, body: str, date: str = ""):
        self.title = title
        self.url = url
        self.body = body
        self.date = date


class AnalysisResult:
    """Represents AI analysis result"""
    def __init__(
        self,
        sector: str,
        analysis: str,
        data_sources: int,
        generated_at: str,
        error: str = None
    ):
        self.sector = sector
        self.analysis = analysis
        self.data_sources = data_sources
        self.generated_at = generated_at
        self.error = error


# Interfaces (contracts) - Interface Segregation Principle
class DataCollectorInterface(Protocol):
    """Interface for data collection services"""

    async def collect_market_data(self, sector: str) -> List[MarketData]:
        """Collect market data for a specific sector"""
        pass


class AIAnalyzerInterface(Protocol):
    """Interface for AI analysis services"""

    async def analyze_data(self, sector: str, data: List[MarketData]) -> AnalysisResult:
        """Analyze market data using AI"""
        pass


class ReportGeneratorInterface(Protocol):
    """Interface for report generation services"""

    def generate_report(self, sector: str, analysis: AnalysisResult) -> str:
        """Generate formatted report from analysis"""
        pass


# Service implementation - Single Responsibility Principle
class MarketAnalysisService:
    """
    High-level service that orchestrates market analysis.
    Follows Dependency Inversion Principle by depending on abstractions.
    """

    def __init__(
        self,
        data_collector: DataCollectorInterface,
        ai_analyzer: AIAnalyzerInterface,
        report_generator: ReportGeneratorInterface
    ):
        self.data_collector = data_collector
        self.ai_analyzer = ai_analyzer
        self.report_generator = report_generator

    async def analyze_sector(self, sector: str) -> str:
        """
        Analyze a market sector using the configured services.
        This is the main business logic orchestration.
        """
        try:
            logger.info(f"Starting market analysis for sector: {sector}")

            # Collect market data
            market_data = await self.data_collector.collect_market_data(sector)
            logger.info(f"Collected {len(market_data)} data points for {sector}")

            # Analyze with AI
            analysis_result = await self.ai_analyzer.analyze_data(sector, market_data)
            logger.info(f"Completed AI analysis for {sector}")

            # Generate report
            report = self.report_generator.generate_report(sector, analysis_result)
            logger.info(f"Generated report for {sector} ({len(report)} characters)")

            return report

        except Exception as e:
            logger.error(f"Error analyzing sector {sector}: {str(e)}")
            raise  # Re-raise to let the API layer handle it
