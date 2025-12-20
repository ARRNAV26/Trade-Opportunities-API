"""
Infrastructure Service Adapters - Implement interfaces with external dependencies.
These classes adapt the existing functions to the new interface contracts.
"""

from typing import List
import logging
import sys
import os

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.market_analysis_service import (
    DataCollectorInterface,
    AIAnalyzerInterface,
    ReportGeneratorInterface,
    MarketData,
    AnalysisResult
)

logger = logging.getLogger(__name__)


class DataCollectorAdapter(DataCollectorInterface):
    """Adapter for existing data collection functionality"""

    async def collect_market_data(self, sector: str) -> List[MarketData]:
        """Collect market data using existing data_collector module"""
        try:
            from core.data_collector import collect_market_data

            # Call the existing synchronous function
            raw_data = collect_market_data(sector)

            # Adapt to our MarketData model
            market_data = []
            for item in raw_data:
                market_data.append(MarketData(
                    title=item.get("title", ""),
                    url=item.get("url", ""),
                    body=item.get("body", ""),
                    date=item.get("date", "N/A")
                ))

            return market_data

        except Exception as e:
            logger.error(f"Data collection failed for sector {sector}: {e}")
            return []  # Return empty list on error


class AIAnalyzerAdapter(AIAnalyzerInterface):
    """Adapter for existing AI analysis functionality"""

    async def analyze_data(self, sector: str, data: List[MarketData]) -> AnalysisResult:
        """Analyze data using existing ai_analyzer module"""
        try:
            from core.ai_analyzer import analyze_with_gemini

            # Convert MarketData objects to dict format expected by existing function
            market_data_dicts = [
                {
                    "title": item.title,
                    "url": item.url,
                    "body": item.body,
                    "date": item.date
                }
                for item in data
            ]

            # Call existing async function
            analysis_result = await analyze_with_gemini(sector, market_data_dicts)

            # Adapt to our AnalysisResult model
            return AnalysisResult(
                sector=analysis_result.get("sector", sector),
                analysis=analysis_result.get("analysis", "Analysis unavailable"),
                data_sources=analysis_result.get("data_sources", len(data)),
                generated_at=analysis_result.get("generated_at", "current_timestamp")
            )

        except Exception as e:
            logger.error(f"AI analysis failed for sector {sector}: {e}")

            # Return fallback analysis
            fallback_analysis = f"""
            # Market Analysis - {sector.title()} Sector (Error Fallback)

            **Error:** Unable to perform AI analysis. Technical issues encountered.

            ## Basic Analysis Summary
            - Sector: {sector}
            - Data points collected: {len(data)}
            - Analysis status: Fallback mode
            """
            return AnalysisResult(
                sector=sector,
                analysis=fallback_analysis,
                data_sources=len(data),
                generated_at="error_fallback",
                error=str(e)
            )


class ReportGeneratorAdapter(ReportGeneratorInterface):
    """Adapter for existing report generation functionality"""

    def generate_report(self, sector: str, analysis: AnalysisResult) -> str:
        """Generate report using existing report_generator module"""
        try:
            from utils.report_generator import generate_markdown_report

            # Convert AnalysisResult to dict format expected by existing function
            analysis_dict = {
                "sector": analysis.sector,
                "analysis": analysis.analysis,
                "data_sources": analysis.data_sources,
                "generated_at": analysis.generated_at
            }

            # Call existing function
            return generate_markdown_report(sector, analysis_dict)

        except Exception as e:
            logger.error(f"Report generation failed for sector {sector}: {e}")

            # Fallback report
            return f"""
# Market Analysis - {sector.title()} Sector

**Status:** Error generating analysis report

## Error Details
Unable to generate the analysis report due to technical issues.

Please try again later or contact support.
"""
