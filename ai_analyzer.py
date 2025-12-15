import google.generativeai as genai
import logging
from typing import List, Dict, Any
from config import settings

logger = logging.getLogger(__name__)

genai.configure(api_key=settings.GEMINI_API_KEY)

async def analyze_with_gemini(sector: str, market_data: List[Dict]) -> Dict[str, Any]:
    """
    Analyze market data using Google Gemini AI to provide trade opportunity insights.

    Args:
        sector: The market sector being analyzed
        market_data: List of market news and data from web search

    Returns:
        Dictionary containing AI analysis with trade opportunities
    """
    try:
        if not settings.GEMINI_API_KEY:
            raise ValueError("Gemini API key not configured")

        # Prepare market data for analysis
        data_text = "\n\n".join([
            f"Title: {item['title']}\nURL: {item['url']}\nContent: {item['body']}\nDate: {item.get('date', 'N/A')}"
            for item in market_data
        ])

        # Create prompt for Gemini analysis
        prompt = f"""
        You are a financial analyst specializing in Indian markets. Analyze the following market data for the {sector} sector in India and provide trade opportunity insights.

        MARKET DATA:
        {data_text}

        Please provide a comprehensive analysis in the following structure:
        1. SECTOR OVERVIEW: Current market conditions and key trends
        2. KEY PLAYERS: Major companies and their performance
        3. MARKET DRIVERS: Factors influencing the sector
        4. TRADE OPPORTUNITIES: Specific bullish/bearish signals and potential trades
        5. RISKS: Potential risks and challenges
        6. RECOMMENDATIONS: Investment strategies and time horizons

        Focus on actionable insights for traders and investors. Use bullet points and clear sections. Be specific with stock symbols, price levels, and timeframes where applicable.
        """

        # Initialize Gemini model (try available models)
        available_models = ["gemini-pro", "gemini-1.5-flash", "gemini-1.0-pro"]
        model = None
        for model_name in available_models:
            try:
                model = genai.GenerativeModel(model_name)
                logger.info(f"Successfully loaded Gemini model: {model_name}")
                break
            except Exception as e:
                logger.warning(f"Model {model_name} not available: {str(e)}")
                continue

        if model is None:
            # List available models
            try:
                available = genai.list_models()
                available_names = [m.name for m in available]
                logger.info(f"Available Gemini models: {available_names}")
                raise ValueError(f"No working models found. Available: {available_names}")
            except Exception as list_e:
                logger.error(f"Could not list available models: {list_e}")
                raise ValueError("No available Gemini models found and could not list available models")

        # Generate response
        response = model.generate_content(prompt)

        analysis_text = response.text if response.text else "Analysis unavailable"

        logger.info(f"Successfully analyzed market data for sector: {sector}")

        return {
            "sector": sector,
            "analysis": analysis_text,
            "data_sources": len(market_data),
            "generated_at": "current_timestamp"  # Will be set by caller
        }

    except Exception as e:
        logger.error(f"Error analyzing sector {sector} with Gemini: {str(e)}")
        # Return fallback analysis
        fallback_analysis = f"""
        # Market Analysis - {sector.title()} Sector (Fallback)

        **Note:** AI analysis unavailable due to error. Basic recommendation based on available data.

        ## Sector Overview
        - Current market conditions indicate {sector} sector activity in India
        - Data collection successful: {len(market_data)} sources found

        ## Trade Opportunities
        - Monitor major stocks in this sector
        - Consider technical analysis for entry/exit points

        ## Risks
        - Market volatility
        - External economic factors

        ## Recommendations
        - Consult financial advisors before making trades
        - Diversify investments
        """
        return {
            "sector": sector,
            "analysis": fallback_analysis,
            "data_sources": len(market_data),
            "generated_at": "current_timestamp",
            "error": str(e)
        }
