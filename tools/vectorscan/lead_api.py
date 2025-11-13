#!/usr/bin/env python3
"""
Minimal lead-capture API for VectorScan.

- POST /lead with JSON payload: {"email": "...", "result": {...}}
- Stores submissions to tools/vectorscan/captures_api/*.json
- Basic validation with Pydantic

Quick start:
  uvicorn tools.vectorscan.lead_api:app --host 0.0.0.0 --port 8080

Environment:
  LEAD_API_OUTPUT_DIR (optional): override storage directory
"""
from __future__ import annotations
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from typing import Any, Optional
from pathlib import Path
import time, json, hashlib, os

app = FastAPI(title="VectorScan Lead API", version="0.1.0")


class ViolationModel(BaseModel):
    policy_id: str
    message: str
    resource: str | None = None


class ResultModel(BaseModel):
    status: str
    file: Optional[str] = None
    # Original CLI output (list of strings)
    violations: list[str] = Field(default_factory=list)
    # Optional structured violations
    violations_struct: list[ViolationModel] | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    checks: list[str] = Field(default_factory=list)
    vectorscan_version: Optional[str] = None


class LeadModel(BaseModel):
    email: EmailStr
    result: ResultModel
    timestamp: Optional[int] = None
    source: Optional[str] = None


def save_payload(payload: dict) -> Path:
    out_root = Path(os.getenv("LEAD_API_OUTPUT_DIR", Path(__file__).parent / "captures_api"))
    out_root.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:10]
    out = out_root / f"lead_{stamp}_{h}.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


@app.post("/lead")
async def post_lead(lead: LeadModel):
    payload = lead.dict()
    try:
        out = save_payload(payload)
        return {"ok": True, "stored": str(out)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- Basic in-memory rate limiting (per-IP in a sliding window) ---
_HITS: dict[str, list[int]] = {}
_WINDOW_SECONDS = 60
_MAX_PER_WINDOW = 10


def _allow_request(ip: str) -> bool:
    now = int(time.time())
    lst = _HITS.get(ip, [])
    # drop stale
    lst = [t for t in lst if now - t < _WINDOW_SECONDS]
    if len(lst) >= _MAX_PER_WINDOW:
        _HITS[ip] = lst
        return False
    lst.append(now)
    _HITS[ip] = lst
    return True


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if not _allow_request(client_ip):
        raise HTTPException(status_code=429, detail="Too Many Requests")
    return await call_next(request)

# --- Optional API token auth (via env LEAD_API_TOKEN). If not set, auth is disabled. ---
@app.middleware("http")
async def token_auth_middleware(request: Request, call_next):
    token_required = os.getenv("LEAD_API_TOKEN")
    if token_required:
        provided = request.headers.get("x-api-key") or request.headers.get("authorization", "").removeprefix("Bearer ")
        if provided != token_required:
            raise HTTPException(status_code=401, detail="Unauthorized")
    return await call_next(request)

# --- Optional CORS (enable with LEAD_API_ENABLE_CORS=true; set origins via LEAD_API_CORS_ORIGINS=comma,separated) ---
if os.getenv("LEAD_API_ENABLE_CORS", "").lower() in {"1", "true", "yes"}:
    origins = [o.strip() for o in os.getenv("LEAD_API_CORS_ORIGINS", "*").split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"]
    )
