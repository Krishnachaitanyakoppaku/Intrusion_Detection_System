#!/usr/bin/env python3
"""Test Gemini API connection and functionality"""

import sys
import os

# Add the project directory to path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Import Gemini
try:
    import google.generativeai as genai
    print("[OK] google-generativeai package is installed")
except ImportError as e:
    print(f"[ERROR] google-generativeai package is NOT installed: {e}")
    print("  Run: pip install google-generativeai")
    sys.exit(1)

# Test API key from web_ids.py
GEMINI_API_KEY = "AIzaSyCK3N6q-3kxwLX0p-kqiEJmxPdxlxN-nZg"

if not GEMINI_API_KEY or GEMINI_API_KEY.strip() == '':
    print("[ERROR] Gemini API key is not configured")
    sys.exit(1)

print(f"[OK] API key found: {GEMINI_API_KEY[:20]}...")

# Test initialization
try:
    genai.configure(api_key=GEMINI_API_KEY)
    print("[OK] Gemini API configured successfully")
except Exception as e:
    print(f"[ERROR] Failed to configure Gemini API: {e}")
    sys.exit(1)

# Test model initialization - try different model names
print("\nListing available models...")
try:
    models = genai.list_models()
    print("Available models:")
    for m in models:
        if 'generateContent' in m.supported_generation_methods:
            print(f"  - {m.name} (supports generateContent)")
except Exception as e:
    print(f"[INFO] Could not list models: {e}")

model = None
model_names = ['models/gemini-pro-latest', 'models/gemini-flash-latest', 'models/gemini-2.0-flash', 'models/gemini-pro']
print("\nTrying to initialize models...")
for model_name in model_names:
    try:
        model = genai.GenerativeModel(model_name)
        print(f"[OK] Gemini model '{model_name}' initialized successfully")
        break
    except Exception as e:
        print(f"[INFO] Model '{model_name}' failed: {str(e)[:100]}")
        continue

if model is None:
    print("[ERROR] Failed to initialize any Gemini model")
    sys.exit(1)

# Test a simple API call
print("\nTesting API call with a simple prompt...")
test_prompt = "Convert this to IDS rule: Detect incoming ICMP ping"
try:
    resp = model.generate_content(test_prompt, request_options={'timeout': 30})
    result = (resp.text or '').strip()
    if result:
        print(f"[OK] API call successful!")
        print(f"  Response (first 200 chars): {result[:200]}...")
    else:
        print("[ERROR] API returned empty response")
        sys.exit(1)
except Exception as e:
    error_msg = str(e)
    print(f"[ERROR] API call failed: {error_msg}")
    
    # Provide specific error messages
    if '429' in error_msg or 'quota' in error_msg.lower():
        print("  -> API quota exceeded. Please try again later.")
    elif '401' in error_msg or '403' in error_msg or 'api key' in error_msg.lower():
        print("  -> Invalid API key. Please check your API key configuration.")
    elif 'timeout' in error_msg.lower():
        print("  -> Request timed out. Check your internet connection.")
    elif 'connection' in error_msg.lower() or 'network' in error_msg.lower():
        print("  -> Connection error. Check your internet connection.")
    elif '503' in error_msg or 'service unavailable' in error_msg.lower():
        print("  -> Service temporarily unavailable. Please try again later.")
    
    sys.exit(1)

print("\n[SUCCESS] All Gemini API tests passed!")
print("   The Gemini API integration is working correctly.")

