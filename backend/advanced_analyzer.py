import requests
import whois
import datetime
from urllib.parse import urlparse
import io

# ─────────────────────────────────────────────────────────────────────────────
# AI / Context Setup
# ─────────────────────────────────────────────────────────────────────────────
from google import genai
import os
from dotenv import load_dotenv

try:
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    load_dotenv(env_path)
    api_key = os.getenv("GEMINI_API_KEY")
    
    # Fallback to manual parsing if python-dotenv fails (common Windows issue)
    if not api_key and os.path.exists('.env'):
        with open('.env', 'r', encoding='utf-8-sig') as f:
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

def trace_url(url: str):
    """
    Follows redirects for a given URL and returns the final destination
    and the chain of URLs it bounced through.
    """
    try:
        if not url.startswith('http'):
            url = 'http://' + url
            
        session = requests.Session()
        # Set a realistic user agent
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        
        response = session.get(url, allow_redirects=True, timeout=10)
        
        chain = []
        for resp in response.history:
            chain.append({
                "url": resp.url,
                "status": resp.status_code
            })
        
        # Add the final destination
        chain.append({
            "url": response.url,
            "status": response.status_code
        })
        
        return {
            "success": True,
            "initial_url": url,
            "final_url": response.url,
            "redirect_chain": chain,
            "redirect_count": len(response.history)
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "initial_url": url
        }

def get_whois(domain_or_url: str):
    """
    Performs a WHOIS lookup and calculates domain age.
    """
    try:
        # Extract domain if URL is passed
        parsed = urlparse(domain_or_url)
        domain = parsed.netloc if parsed.netloc else parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        w = whois.whois(domain)
        
        if not w.domain_name:
            return {"success": False, "error": "Domain not found or WHOIS blocked"}
            
        creation_date = w.creation_date
        if type(creation_date) == list:
            creation_date = creation_date[0]
            
        age_days = None
        if creation_date:
            # Make both naive to calculate delta
            naive_creation = creation_date.replace(tzinfo=None)
            delta = datetime.datetime.now() - naive_creation
            age_days = delta.days
            
        return {
            "success": True,
            "domain": domain,
            "registrar": w.registrar,
            "creation_date": creation_date.isoformat() if creation_date else None,
            "age_days": age_days,
            "is_new": age_days is not None and age_days < 30 # Flag if < 30 days old
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def analyze_vision(image_bytes: bytes, mime_type: str = "image/jpeg"):
    """
    Sends an image to Gemini Vision to detect phishing indicators (e.g. fake login screens or QR code links).
    """
    if not client:
        return {"success": False, "error": "Gemini client not configured. Check API key."}
        
    prompt = (
        "You are an expert cybersecurity analyst. "
        "Analyze this image. If it is a screenshot of a login page, invoice, or email, check for signs of phishing or scams. "
        "If it contains a QR code, simulate what it might lead to. "
        "Extract any suspicious text, URLs, or urgent demands. "
        "Respond concisely with a threat assessment (Safe, Suspicious, or Phishing) and the reasons why."
    )
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=[
                {"role": "user", "parts": [
                    {"text": prompt},
                    {"inline_data": {"mime_type": mime_type, "data": image_bytes}}
                ]}
            ]
        )
        return {"success": True, "analysis": response.text}
    except Exception as e:
        return {"success": False, "error": str(e)}

def analyze_document(pdf_bytes: bytes):
    """
    Extracts text from a PDF and sends it to Gemini for threat analysis.
    Uses PyMuPDF to extract text accurately.
    """
    try:
        import fitz # PyMuPDF
        
        # Load PDF from memory
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        text_content = ""
        
        # Extract text from up to 5 pages
        for page_num in range(min(5, len(doc))):
            page = doc.load_page(page_num)
            text_content += page.get_text()
            
        if not text_content.strip():
             return {"success": False, "error": "Could not extract any readable text from this PDF. It may be image-only or password protected."}
             
        if not client:
             return {"success": False, "error": "Gemini AI client is not configured. Check that GEMINI_API_KEY is set in backend/.env and restart the server.", "extracted_text": text_content[:500]}
             
        prompt = (
            "You are a cybersecurity expert. Analyze the following text extracted from a document attachment (like a PDF). "
            "Look for invoice fraud, fake receipts, urgency hooks, impersonation, or malicious URLs. "
            "Respond concisely with a structured threat assessment: first state the overall verdict (Safe / Suspicious / Malicious), "
            "then list specific signals found, then give a brief recommendation."
        )
        
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=[prompt, f"Document Text:\n{text_content[:8000]}"]
        )
        
        return {"success": True, "analysis": response.text, "extracted_text_preview": text_content[:300]}
        
    except Exception as e:
        err = str(e)
        # Make quota/rate-limit errors more user-friendly
        if '429' in err or 'RESOURCE_EXHAUSTED' in err or 'quota' in err.lower():
            friendly = "Gemini API rate limit reached. Please wait 1-2 minutes and try again."
        elif 'API_KEY_INVALID' in err or '403' in err:
            friendly = "Gemini API key is invalid or expired. Please update GEMINI_API_KEY in backend/.env."
        elif 'NOT_FOUND' in err or '404' in err:
            friendly = "Gemini model not found. Please update the backend."
        else:
            friendly = f"Gemini API error: {err}"
        return {"success": False, "error": friendly}
