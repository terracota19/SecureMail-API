"""JWT and API-key authentication for SecureMail API."""

import logging
import os
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY or len(JWT_SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET_KEY must exist and be at least 32 characters long.")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))

AUTHORIZED_CLIENTS: dict[str, str] = {
    client_id.strip(): client_hash.strip()
    for entry in os.getenv("AUTHORIZED_CLIENTS", "").split(";")
    if ":" in entry
    for client_id, client_hash in [entry.split(":", 1)]
    if client_id.strip() and client_hash.strip()
}
if not AUTHORIZED_CLIENTS:
    raise RuntimeError("AUTHORIZED_CLIENTS must contain at least one client.")

RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW_S = int(os.getenv("RATE_LIMIT_WINDOW_S", "60"))
_rate_store: dict[str, list[float]] = defaultdict(list)
_last_cleanup = time.monotonic()


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    client_id: str
    scopes: list[str] = Field(default_factory=list)


def _check_rate_limit(ip: str) -> None:
    global _last_cleanup
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW_S
    if now - _last_cleanup > 300:
        dead_ips = [key for key, calls in _rate_store.items() if not calls or max(calls) < window_start]
        for key in dead_ips:
            del _rate_store[key]
        _last_cleanup = now

    calls = [stamp for stamp in _rate_store[ip] if stamp > window_start]
    if len(calls) >= RATE_LIMIT_REQUESTS:
        retry_after = max(1, int(calls[0] - window_start) + 1)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
    calls.append(now)
    _rate_store[ip] = calls


def _create_jwt(client_id: str, scopes: list[str]) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": client_id, "scopes": scopes, "exp": expire, "iat": now, "jti": secrets.token_hex(16)},
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def _decode_jwt(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        client_id = payload.get("sub")
        scopes = payload.get("scopes", [])
        if not client_id or not isinstance(scopes, list):
            raise HTTPException(status_code=401, detail="Invalid token.")
        return TokenData(client_id=client_id, scopes=scopes)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expired or invalid token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def require_auth(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
    bearer_token: Optional[str] = Depends(_oauth2_scheme),
) -> TokenData:
    ip = _get_ip(request)
    _check_rate_limit(ip)
    if bearer_token:
        token_data = _decode_jwt(bearer_token)
        logger.info("Auth OK | client=%s ip=%s", token_data.client_id, ip)
        return token_data
    if api_key:
        for client_id, hashed in AUTHORIZED_CLIENTS.items():
            try:
                if bcrypt.checkpw(api_key.encode(), hashed.encode()):
                    logger.info("API key OK | client=%s ip=%s", client_id, ip)
                    return TokenData(client_id=client_id, scopes=["predict"])
            except (ValueError, TypeError):
                logger.warning("Invalid bcrypt hash for client=%s", client_id)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Use X-API-Key or Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_scope(scope: str):
    async def _check(token_data: TokenData = Depends(require_auth)) -> TokenData:
        if scope not in token_data.scopes and "admin" not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permission. Required scope: '{scope}'.",
            )
        return token_data
    return _check


auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/token", response_model=TokenResponse, summary="Get an access JWT")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    ip = _get_ip(request)
    _check_rate_limit(ip)
    client_id = form_data.username
    client_secret = form_data.password
    hashed = AUTHORIZED_CLIENTS.get(client_id)
    valid = False
    if hashed:
        try:
            valid = bcrypt.checkpw(client_secret.encode(), hashed.encode())
        except (ValueError, TypeError):
            valid = False
    if not valid:
        logger.warning("Authentication failed | client=%s ip=%s", client_id, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenResponse(
        access_token=_create_jwt(client_id, scopes=["predict"]),
        expires_in=JWT_EXPIRE_MINUTES * 60,
    )
