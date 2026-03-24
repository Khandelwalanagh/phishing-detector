import os
from google import genai
from pydantic import BaseModel
from typing import List, Dict, Optional
from dotenv import load_dotenv

try:
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    load_dotenv(env_path)
    api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key and os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                if line.startswith("GEMINI_API_KEY="):
                    api_key = line.split('=', 1)[1].strip()
                    break

    if api_key:
        client = genai.Client(api_key=api_key)
    else:
        raise ValueError("GEMINI_API_KEY not found in environment or .env file")
except Exception as e:
    print(f"Warning: Could not initialize Gemini client: {e}")
    client = None

# Custom system prompt to guide the AI's behavior
SYSTEM_PROMPT = """
You are PhishGuard AI, a helpful, expert cybersecurity assistant integrated directly into the user's Gmail.
Your goal is to help the user identify phishing emails, scams, and malicious links.
You will be provided with the content of the email the user is currently reading.

Please follow these guidelines:
1. Be concise, friendly, and direct.
2. If the user asks if an email is a scam, analyze the provided context for common phishing indicators (urgency, weird sender domains, unexpected requests for credentials, suspicious links).
3. Explain *why* something looks suspicious in plain English, avoiding overly dense jargon.
4. If the email looks safe, reassure the user but remind them to always be cautious.
5. NEVER recommend that the user click a link or download an attachment if you are unsure.
6. If the user asks a general question unrelated to the email, you can answer it, but prioritize cybersecurity context.
"""

def chat_with_gemini(user_message: str, email_context: str, history: List[Dict[str, str]] = None) -> str:
    """
    Sends a message to the Gemini API, including the email context and chat history.
    """
    if not client:
        return "I'm sorry, my AI backend is not properly configured. Please check the API key."

    if history is None:
        history = []

    # Format history for the new Gemini SDK
    formatted_history = []
    for msg in history:
        role = "user" if msg["role"] == "user" else "model"
        formatted_history.append({"role": role, "parts": [{"text": msg["content"]}]})

    # Prepare the context message
    context_prefix = f"Context: The user is currently reading the following email:\n\n---\n{email_context}\n---\n\nUser Question:\n"
    
    # If this is the start of a conversation, prepend the email context to their first message.
    # Otherwise, just send their message (the model has the context in history).
    if len(history) == 0 and email_context.strip():
        full_message = context_prefix + user_message
    else:
        full_message = user_message

    try:
        response = client.models.generate_content(
            model='gemini-3-flash-preview',
            contents=formatted_history + [{"role": "user", "parts": [{"text": full_message}]}],
            config=genai.types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.3, # Keep it focused and analytical
            )
        )
        return response.text
    except Exception as e:
        print(f"Gemini API Error: {e}")
        return "I encountered an error while trying to analyze that. Please try again or check the server logs."

