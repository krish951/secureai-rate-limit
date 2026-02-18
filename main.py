from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import time
import logging
from typing import Dict

app = FastAPI()

logging.basicConfig(level=logging.INFO)

MAX_REQUESTS_PER_MINUTE = 22
BURST_CAPACITY = 7
REFILL_RATE = MAX_REQUESTS_PER_MINUTE / 60

rate_limit_store: Dict[str, dict] = {}

class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str

def get_client_key(request: Request, user_id: str):
    client_ip = request.client.host
    return f"{user_id}:{client_ip}"

def check_rate_limit(key: str):
    now = time.time()
    bucket = rate_limit_store.get(key)

    if not bucket:
        rate_limit_store[key] = {
            "tokens": BURST_CAPACITY,
            "last_refill": now
        }
        bucket = rate_limit_store[key]

    elapsed = now - bucket["last_refill"]
    refill_tokens = elapsed * REFILL_RATE
    bucket["tokens"] = min(BURST_CAPACITY, bucket["tokens"] + refill_tokens)
    bucket["last_refill"] = now

    if bucket["tokens"] < 1:
        retry_after = max(1, int((1 - bucket["tokens"]) / REFILL_RATE))
        return False, retry_after

    bucket["tokens"] -= 1
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
        return JSONResponse(
            status_code=400,
            content={
                "blocked": True,
                "reason": "Request validation failed",
                "sanitizedOutput": None,
                "confidence": 0.75
            }
        )