import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
print(f"Gemini API Key found: {bool(GEMINI_API_KEY)}")
print(f"Key starts with: {GEMINI_API_KEY[:20] if GEMINI_API_KEY else 'None'}...")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

    print("\n--- Checking Available Models ---")
    try:
        models = genai.list_models()
        model_list = list(models)  # Convert generator to list
        print(f"Total available models: {len(model_list)}")

        text_generation_models = []
        for model in model_list:
            if 'generateContent' in str(model.supported_generation_methods):
                text_generation_models.append(model.name)
            print(f"Model: {model.name} - Methods: {model.supported_generation_methods}")

        print(f"\n--- Text Generation Models: ---")
        for model_name in text_generation_models:
            print(f"- {model_name}")

        print(f"\n--- Testing Models ---")
        for model_name in ["models/gemini-pro", "models/gemini-1.5-flash", "models/gemini-1.0-pro"]:
            try:
                print(f"Testing {model_name}...")
                model = genai.GenerativeModel(model_name)
                response = model.generate_content("Say hello in one word")
                print(f"✅ {model_name} works: {response.text}")
            except Exception as e:
                print(f"❌ {model_name} failed: {str(e)[:100]}...")

    except Exception as e:
        print(f"❌ Could not list models: {e}")
else:
    print("No Gemini API key configured")
