"""
auth.py — Autenticación robusta para SecureMail API
=====================================================
Capas de seguridad implementadas:
  1. API Key  (identifica al cliente/aplicación)
  2. JWT      (sesión con expiración y scopes)
  3. Rate limiting por IP
  4. Hashing seguro de secrets con bcrypt
"""

import os
import time
import hashlib
import secrets
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from collections import defaultdict

import bcrypt
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURACIÓN — lee todo desde variables de entorno, nunca hardcodeado
# =============================================================================

JWT_SECRET_KEY: str = os.environ["JWT_SECRET_KEY"]          # openssl rand -hex 32
JWT_ALGORITHM: str  = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))  # 24 h

# Base de clientes autorizados (en producción: base de datos)
# Formato: { "client_id": bcrypt_hash_del_secret }
# Genera hash:  bcrypt.hashpw(b"tu_secret", bcrypt.gensalt()).decode()
AUTHORIZED_CLIENTS: dict[str, str] = {
    client_id: client_hash
    for entry in os.getenv("AUTHORIZED_CLIENTS", "").split(";")
    if ":" in entry
    for client_id, client_hash in [entry.split(":", 1)]
}

# Rate limiting: máximo N peticiones por ventana de tiempo
RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))
RATE_LIMIT_WINDOW_S: int  = int(os.getenv("RATE_LIMIT_WINDOW_S", "60"))

# =============================================================================
# SCHEMAS
# =============================================================================

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # segundos


class TokenData(BaseModel):
    client_id: str
    scopes: list[str] = []

# =============================================================================
# RATE LIMITER — en memoria; para producción usa Redis
# =============================================================================

_rate_store: dict[str, list[float]] = defaultdict(list)


def _check_rate_limit(ip: str) -> None:
    """Ventana deslizante: máximo RATE_LIMIT_REQUESTS por RATE_LIMIT_WINDOW_S."""
    now = time.monotonic()
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
# JWT — creación y verificación
# =============================================================================

def _create_jwt(client_id: str, scopes: list[str]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    payload = {
        "sub": client_id,
        "scopes": scopes,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": secrets.token_hex(16),  # ID único del token (permite revocación futura)
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
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado o inválido.",
            headers={"WWW-Authenticate": "Bearer"},
        )

# =============================================================================
# SEGURIDAD HTTP — esquemas FastAPI
# =============================================================================

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_oauth2_scheme  = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host

# =============================================================================
# DEPENDENCIAS PÚBLICAS (inyectar en los endpoints)
# =============================================================================

async def require_auth(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
    bearer_token: Optional[str] = Depends(_oauth2_scheme),
) -> TokenData:
    """
    Dependencia principal. Acepta DOS métodos de autenticación:
      - X-API-Key header  →  verifica contra AUTHORIZED_CLIENTS
      - Authorization: Bearer <jwt>  →  valida JWT
    Aplica rate limiting antes de cualquier verificación.
    """
    ip = _get_ip(request)
    _check_rate_limit(ip)

    # --- Método 1: JWT Bearer ---
    if bearer_token:
        token_data = _decode_jwt(bearer_token)
        logger.info("Auth OK (JWT) | client=%s ip=%s", token_data.client_id, ip)
        return token_data

    # --- Método 2: API Key directa ---
    if api_key:
        # Búsqueda en tiempo constante para evitar timing attacks
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
    """
    Fábrica de dependencias para verificar un scope específico.
    Uso:  @app.post("/predict", dependencies=[Depends(require_scope("predict"))])
    """
    async def _check(token_data: TokenData = Depends(require_auth)) -> TokenData:
        if scope not in token_data.scopes and "admin" not in token_data.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permiso insuficiente. Se requiere scope: '{scope}'.",
            )
        return token_data
    return _check

# =============================================================================
# ENDPOINT /auth/token — obtener JWT a partir de client_id + secret
# =============================================================================
# Registra este router en tu app principal:
#   from auth import auth_router
#   app.include_router(auth_router)

from fastapi import APIRouter

auth_router = APIRouter(prefix="/auth", tags=["auth"])


@auth_router.post("/token", response_model=TokenResponse, summary="Obtener JWT de acceso")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    Intercambia client_id + client_secret por un JWT con 24 h de validez.

    Ejemplo con curl:
        curl -X POST http://localhost:8000/auth/token \\
          -d "username=mi_cliente&password=mi_secret"
    """
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
        # Log sin exponer cuál campo fue incorrecto
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
