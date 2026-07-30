"""
auth.py — Autenticación robusta y optimizada en memoria para SecureMail API
"""

import os
import time
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from collections import defaultdict

import bcrypt
import jwt  # Usando PyJWT en lugar de python-jose
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "fallback_secret_change_me")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))

AUTHORIZED_CLIENTS: dict[str, str] = {
    client_id: client_hash
    for entry in os.getenv("AUTHORIZED_CLIENTS", "").split(";")
    if ":" in entry
    for client_id, client_hash in [entry.split(":", 1)]
}

RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW_S: int = int(os.getenv("RATE_LIMIT_WINDOW_S", "60"))

# =============================================================================
# SCHEMAS
# =============================================================================

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    client_id: str
    scopes: list[str] = []

# =============================================================================
# RATE LIMITER OPTIMIZADO (Sin Fugas de Memoria)
# =============================================================================

_rate_store: dict[str, list[float]] = defaultdict(list)
_last_cleanup: float = time.monotonic()

def _check_rate_limit(ip: str) -> None:
    global _last_cleanup
    now = time.monotonic()
    
    # Mantenimiento de memoria: limpiar IPs inactivas cada 5 minutos
    if now - _last_cleanup > 300:
        window_start = now - RATE_LIMIT_WINDOW_S
        dead_ips = [k for k, v in _rate_store.items() if not v or max(v) < window_start]
        for k in dead_ips:
            del _rate_store[k]
        _last_cleanup = now

    window_start = now - RATE_LIMIT_WINDOW_S
    calls = [t for t in _rate_store[ip] if t > window_start]
    
    if len(calls) >= RATE_LIMIT_REQUESTS:
        retry_after = int(calls[0] - window_start) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiadas peticiones. Inténtalo más tarde.",
            headers={"Retry-After": str(retry_after)},
        )
    
    calls.append(now)
    _rate_store[ip] = calls

# =============================================================================
# JWT (PyJWT)
# =============================================================================

def _create_jwt(client_id: str, scopes: list[str]) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": client_id,
        "scopes": scopes,
        "exp": expire,
        "iat": now,
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def _decode_jwt(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        client_id: str = payload.get("sub")
        scopes: list[str] = payload.get("scopes", [])
        if not client_id:
            raise HTTPException(status_code=401, detail="Token inválido.")
        return TokenData(client_id=client_id, scopes=scopes)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado o inválido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

# =============================================================================
# SEGURIDAD HTTP Y DEPENDENCIAS
# =============================================================================

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host


async def require_auth(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
    bearer_token: Optional[str] = Depends(_oauth2_scheme),
) -> TokenData:
    ip = _get_ip(request)
    _check_rate_limit(ip)

    if bearer_token:
        token_data = _decode_jwt(bearer_token)
        logger.info("Auth OK (JWT) | client=%s ip=%s", token_data.client_id, ip)
        return token_data

    if api_key:
        matched_id: Optional[str] = None
        for cid, hashed in AUTHORIZED_CLIENTS.items():
            try:
                if bcrypt.checkpw(api_key.encode(), hashed.encode()):
                    matched_id = cid
                    break
            except Exception:
                continue

        if matched_id:
            logger.info("Auth OK (API Key) | client=%s ip=%s", matched_id, ip)
            return TokenData(client_id=matched_id, scopes=["predict"])

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Autenticación requerida. Usa X-API-Key o Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_scope(scope: str):
    async def _check(token_data: TokenData = Depends(require_auth)) -> TokenData:
        if scope not in token_data.scopes and "admin" not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permiso insuficiente. Se requiere scope: '{scope}'.",
            )
        return token_data
    return _check

# =============================================================================
# ROUTER DE AUTENTICACIÓN
# =============================================================================

from fastapi import APIRouter

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/token", response_model=TokenResponse, summary="Obtener JWT de acceso")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    ip = _get_ip(request)
    _check_rate_limit(ip)

    client_id = form_data.username
    client_secret = form_data.password

    hashed = AUTHORIZED_CLIENTS.get(client_id)
    valid = False
    if hashed:
        try:
            valid = bcrypt.checkpw(client_secret.encode(), hashed.encode())
        except Exception:
            valid = False

    if not valid:
        logger.warning("Auth fallida | client=%s ip=%s", client_id, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = _create_jwt(client_id, scopes=["predict"])
    logger.info("Token emitido | client=%s ip=%s", client_id, ip)
    return TokenResponse(
        access_token=token,
        expires_in=JWT_EXPIRE_MINUTES * 60,
    )
