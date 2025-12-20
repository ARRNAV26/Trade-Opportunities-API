"""
DuckDuckGo Search Data Collector
Uses DuckDuckGo search API for market data collection.
Provides privacy-focused search results with decent quality.
"""

import logging
from typing import List, Dict
from duckduckgo_search import DDGS
from config.config import settings

logger = logging.getLogger(__name__)


def collect_market_data(sector: str) -> List[Dict]:
    """
    Collect market data and news for a specific sector using DuckDuckGo search.
    Returns list of search results with titles, URLs, and snippets.

    Args:
        sector: Market sector name (e.g., "pharmaceuticals")

    Returns:
        List of dictionaries containing title, url, body (snippet), and date
    """
    try:
        # Construct search query for financial/market analysis
        query = f"India {sector} market news stock analysis trade opportunities"
        logger.info(f"Searching for market data: {query}")

        # Perform search using DuckDuckGo
        ddgs = DDGS()
        results = ddgs.text(
            query,
            max_results=settings.SEARCH_MAX_RESULTS,
            safesearch='moderate'
        )

        # Process search results into standardized format
        market_data = []
        for result in results:
            market_data.append({
                "title": result.get("title", ""),
                "url": result.get("url", ""),
                "body": result.get("body", ""),
                "date": result.get("date", "N/A")
            })

        logger.info(f"Collected {len(market_data)} market data items for sector: {sector}")
        return market_data

    except Exception as e:
        logger.error(f"Error collecting market data for sector {sector}: {str(e)}")
        # Return empty list instead of raising exception to handle gracefully
        return []
