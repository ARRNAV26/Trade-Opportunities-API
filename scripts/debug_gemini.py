import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
print(f"Gemini API Key loaded: {bool(GEMINI_API_KEY)}")

if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)

        # Try different models to see what's available
        available_models = ["models/gemini-1.5-flash", "models/gemini-1.5-pro", "models/gemini-pro"]

        for model_name in available_models:
            try:
                model = genai.GenerativeModel(model_name)
                response = model.generate_content("Hello, give me a one-sentence response about the stock market.")
                print(f"✅ Model {model_name} works: {response.text[:100]}...")
                break
            except Exception as e:
                print(f"❌ Model {model_name}: {str(e)}")

    except Exception as e:
        print(f"❌ Gemini configuration error: {e}")
else:
    print("❌ No Gemini API key found in environment variables")
