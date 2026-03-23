"""
FastAPI application — Phishing Detection System API
Serves the REST API and static frontend files.
"""
import os
from dotenv import load_dotenv

# Load .env from the backend directory explicitly (dotenv may fail on some Windows setups)
_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(_env_path)
if not os.getenv('GEMINI_API_KEY') and os.path.exists(_env_path):
    with open(_env_path, 'r', encoding='utf-8-sig') as _f:
        for _line in _f:
            if _line.startswith('GEMINI_API_KEY='):
                os.environ['GEMINI_API_KEY'] = _line.split('=', 1)[1].strip()
                break
import sys
import time
from contextlib import asynccontextmanager
from typing import Optional, List, Dict

from fastapi import FastAPI, HTTPException, File, UploadFile, Response, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, field_validator

import auth as _auth

# Ensure backend dir is on path
sys.path.insert(0, os.path.dirname(__file__))

from url_analyzer   import analyze_url
from email_analyzer import analyze_email
import model as ml_model
import train_model as trainer
import llm_agent as llm_agent
import advanced_analyzer as adv_analyzer

# ─────────────────────────────────────────────────────────────────────────────
# Config from environment
# ─────────────────────────────────────────────────────────────────────────────

PORT: int = int(os.environ.get("PORT", 8000))
SESSION_SECRET: str = os.environ.get("SESSION_SECRET", "change-me-please-use-a-real-secret")

# ALLOWED_ORIGINS: comma-separated list, or "*" for all (default for dev)
_origins_env: str = os.environ.get("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS: List[str] = (
    ["*"] if _origins_env.strip() == "*"
    else [o.strip() for o in _origins_env.split(",") if o.strip()]
)

# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────

stats = {
    "total_url_checks":    0,
    "total_email_checks":  0,
    "phishing_url_caught": 0,
    "phishing_email_caught": 0,
    "started_at":          time.time(),
}

FRONTEND_DIR = os.path.join(
    os.path.dirname(__file__), "..", "frontend"
)


# ─────────────────────────────────────────────────────────────────────────────
# Lifespan — auto-train model if missing
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.path.exists(ml_model.MODEL_PATH):
        print("[startup] No model found — training now …")
        try:
            trainer.train()
            print("[startup] Model trained and saved.")
        except Exception as e:
            print(f"[startup] WARNING: model training failed: {e}")
    else:
        print(f"[startup] Model loaded from {ml_model.MODEL_PATH}")
    print(f"[startup] Server ready on port {PORT}. CORS origins: {ALLOWED_ORIGINS}")
    yield


# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard API",
    description="Advanced AI + ML phishing detection for URLs, emails, images and documents.",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="phishguard_session",
    max_age=60 * 60 * 24 * 30,   # 30 days
    https_only=False,             # set True in production (HTTPS)
    same_site="lax",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Request / Response schemas
# ─────────────────────────────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty")
        return v


class EmailRequest(BaseModel):
    content: str

    @field_validator("content")
    @classmethod
    def validate_content(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 10:
            raise ValueError("Email content is too short")
        return v
        
class ChatRequest(BaseModel):
    message: str
    email_context: str
    history: List[Dict[str, str]] = []

class ExplainRequest(BaseModel):
    content_type: str          # "url" or "email"
    content: str               # the URL or email text
    risk_score: float
    label: str
    reasons: List[str] = []


# ─────────────────────────────────────────────────────────────────────────────
# API Key Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/keys/generate")
def generate_key(request: Request, response: Response):
    """
    Generate a new signed API key and set the phishguard_session cookie.
    The key is also returned in the JSON body so the client can store it.
    """
    key = _auth.generate_api_key()
    # Store the key hash in the server-side session cookie
    request.session["api_key_issued"] = True
    request.session["client"] = "phishguard-web"
    return {"api_key": key, "message": "Store this key securely. Pass it as X-API-Key header."}


@app.get("/api/keys/validate")
def validate_key(key: str):
    """Check whether the provided API key is valid without consuming it."""
    valid = _auth.validate_api_key(key)
    return {"valid": valid}


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/explain", dependencies=[Depends(_auth.require_api_key)])
async def explain_endpoint(req: ExplainRequest):
    """Uses Gemini AI to provide a human-readable explanation of a risk analysis result."""
    client = adv_analyzer.client
    if not client:
        raise HTTPException(status_code=503, detail="Gemini AI is not configured. Check GEMINI_API_KEY.")

    verdict = "⚠️ PHISHING / SUSPICIOUS" if req.label == "phishing" else "✅ LEGITIMATE"
    reasons_text = "\n".join(f"- {r}" for r in req.reasons) if req.reasons else "No specific reasons provided."

    if req.content_type == "url":
        subject = f"URL: {req.content}"
    else:
        subject = f"Email/Content (first 500 chars): {req.content[:500]}"

    prompt = f"""You are PhishGuard AI, a cybersecurity expert assistant.

A phishing detection system analysed the following {req.content_type} and produced this result:

{subject}

Risk Score: {round(req.risk_score, 1)} / 100
Verdict: {verdict}
ML/Heuristic signals detected:
{reasons_text}

Please provide a clear, concise explanation (3-5 bullet points) in plain English explaining:
1. Why this {req.content_type} was flagged with this score
2. What the specific red flags are
3. What the user should do

Format your response as clean bullet points starting with an emoji. Be direct and helpful. Do NOT use markdown headers."""

    try:
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=[prompt]
        )
        return {"success": True, "explanation": response.text}
    except Exception as e:
        err = str(e)
        if '429' in err or 'RESOURCE_EXHAUSTED' in err:
            raise HTTPException(status_code=429, detail="Gemini rate limit reached. Please wait a moment.")
        raise HTTPException(status_code=500, detail=f"Gemini error: {err}")

@app.get("/api/trace")
def trace_url_endpoint(url: str):
    if not url:
        raise HTTPException(status_code=400, detail="Missing url parameter")
    return adv_analyzer.trace_url(url)

@app.get("/api/whois")
def whois_endpoint(domain: str):
    if not domain:
        raise HTTPException(status_code=400, detail="Missing domain parameter")
    return adv_analyzer.get_whois(domain)

@app.post("/api/analyze-vision", dependencies=[Depends(_auth.require_api_key)])
async def analyze_vision_endpoint(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Invalid file type. Must be an image.")
    
    contents = await file.read()
    result = adv_analyzer.analyze_vision(contents, mime_type=file.content_type)
    return result

@app.post("/api/analyze-document", dependencies=[Depends(_auth.require_api_key)])
async def analyze_document_endpoint(file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Invalid file type. Must be PDF.")
        
    contents = await file.read()
    result = adv_analyzer.analyze_document(contents)
    return result

@app.get("/api/health")
def health():
    return {
        "status":   "ok",
        "version":  "2.0.0",
        "model":    "loaded" if os.path.exists(ml_model.MODEL_PATH) else "not_found",
        "uptime_s": round(time.time() - stats["started_at"]),
    }

@app.get("/api/version")
def version():
    return {
        "name":    "PhishGuard API",
        "version": "2.0.0",
        "features": ["url-analysis", "email-analysis", "whois-lookup", "url-tracing", "vision-analysis", "document-analysis", "ai-chat"]
    }


@app.get("/api/stats")
def get_stats():
    return {
        **stats,
        "uptime_s": round(time.time() - stats["started_at"]),
    }


@app.post("/api/check-url", dependencies=[Depends(_auth.require_api_key)])
def check_url(req: URLRequest):
    try:
        analysis        = analyze_url(req.url)
        h_score         = analysis["heuristic_score"]
        prediction      = ml_model.predict(analysis["features"], h_score)

        # Blend heuristic + ML score for final risk score
        if prediction["ml_score"] is not None:
            final_score = round(0.4 * h_score + 0.6 * prediction["ml_score"], 2)
        else:
            final_score = h_score

        # Derive label from blended score (more robust than ML alone at boundary)
        label = "phishing" if final_score >= 35 else "legitimate"
        confidence = round(min((final_score - 35) / 65, 1.0), 3) if label == "phishing" else round(min((35 - final_score) / 35, 1.0), 3)

        # Update stats
        stats["total_url_checks"] += 1
        if label == "phishing":
            stats["phishing_url_caught"] += 1

        return {
            "url":             req.url,
            "risk_score":      final_score,
            "heuristic_score": h_score,
            "ml_score":        prediction["ml_score"],
            "label":           label,
            "confidence":      confidence,
            "model_source":    prediction["source"],
            "reasons":         analysis["reasons"],
            "features":        analysis["features"],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))



@app.post("/api/check-email", dependencies=[Depends(_auth.require_api_key)])
def check_email(req: EmailRequest):
    try:
        result = analyze_email(req.content)
        score  = result["risk_score"]
        label  = "phishing" if score >= 35 else "legitimate"

        stats["total_email_checks"] += 1
        if label == "phishing":
            stats["phishing_email_caught"] += 1

        return {
            "risk_score":  score,
            "label":       label,
            "reasons":     result["reasons"],
            "features":    result["features"],
            "links_found": result["links_found"],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
        
@app.post("/api/chat", dependencies=[Depends(_auth.require_api_key)])
def chat_with_assistant(req: ChatRequest):
    try:
        response = llm_agent.chat_with_gemini(
            user_message=req.message,
            email_context=req.email_context,
            history=req.history
        )
        return {"response": response}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Serve frontend (last, so API routes take priority)
# ─────────────────────────────────────────────────────────────────────────────

if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
