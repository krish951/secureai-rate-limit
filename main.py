from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
import logging
from typing import Dict
from collections import defaultdict

app = FastAPI()

# ✅ Enable CORS (important for exam portal)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)

MAX_REQUESTS_PER_MINUTE = 22
BURST_LIMIT = 7
WINDOW_SIZE = 60  # seconds

# Store request timestamps per user/IP
request_log = defaultdict(list)

class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str

@app.get("/")
def home():
    return {"message": "SecureAI Rate Limiting API is running"}

def get_client_key(request: Request, user_id: str):
    return request.client.host

def check_rate_limit(key: str):
    now = time.time()
    window_start = now - WINDOW_SIZE

    # Remove requests outside 60-second window
    request_log[key] = [
        timestamp for timestamp in request_log[key]
        if timestamp > window_start
    ]

    current_count = len(request_log[key])

    # Burst protection
    if current_count >= BURST_LIMIT:
        retry_after = WINDOW_SIZE
        return False, retry_after

    # Overall per-minute protection
    if current_count >= MAX_REQUESTS_PER_MINUTE:
        retry_after = WINDOW_SIZE
        return False, retry_after

    request_log[key].append(now)
    return True, None

@app.post("/api/security/validate")
async def validate(request: Request, body: SecurityRequest):
    try:
        if body.category != "Rate Limiting":
            return JSONResponse(
                status_code=400,
                content={
                    "blocked": True,
                    "reason": "Invalid security category",
                    "sanitizedOutput": None,
                    "confidence": 0.80
                }
            )

        key = get_client_key(request, body.userId)
        allowed, retry_after = check_rate_limit(key)

        if not allowed:
            logging.warning(f"Rate limit exceeded for {key}")
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "blocked": True,
                    "reason": "Rate limit exceeded",
                    "sanitizedOutput": None,
                    "confidence": 0.99
                }
            )

        return JSONResponse(
            status_code=200,
            content={
                "blocked": False,
                "reason": "Input passed all security checks",
                "sanitizedOutput": body.input.strip(),
                "confidence": 0.95
            }
        )

    except Exception:
        logging.error("Validation error occurred")
        return JSONResponse(
            status_code=400,
            content={
                "blocked": True,
                "reason": "Request validation failed",
                "sanitizedOutput": None,
                "confidence": 0.75
            }
        )