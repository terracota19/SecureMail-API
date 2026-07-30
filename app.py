import os
import re
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from contextlib import asynccontextmanager
from typing import List, Optional

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Cargar módulos de autenticación locales
from auth import auth_router, require_scope, TokenData

# ============================================================
# VARIABLES GLOBALES Y CARGA DE MODELOS
# ============================================================
model = None
feature_scaler = None
decision_threshold = 0.5

MODELS_DIR = os.getenv("MODELS_DIR", "/secure.mail/models")
OBJECTS_DIR = os.getenv("OBJECTS_DIR", "/secure.mail/objects")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, feature_scaler, decision_threshold
    print("Iniciando SecureMail API...")
    
    # 1. Cargar Modelo Principal
    model_path = os.path.join(MODELS_DIR, "best_phishing_model.joblib")
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        print(f"Modelo principal cargado desde: {model_path}")
    else:
        print(f"⚠️ ALERTA: No se encontró el modelo en {model_path}")

    # 2. Cargar Scaler / Feature Pipeline
    scaler_path = os.path.join(OBJECTS_DIR, "feature_scaler.joblib")
    if os.path.exists(scaler_path):
        feature_scaler = joblib.load(scaler_path)
        print(f"Pipeline de características cargado desde: {scaler_path}")
    else:
        print(f"⚠️ ALERTA: No se encontró el escalador en {scaler_path}")

    # 3. Cargar Umbral de Decisión (si existe)
    threshold_path = os.path.join(OBJECTS_DIR, "decision_threshold.joblib")
    if os.path.exists(threshold_path):
        decision_threshold = float(joblib.load(threshold_path))
        print(f"Umbral de decisión cargado: {decision_threshold}")

    yield
    print("API detenida y recursos liberados.")

# ============================================================
# CONFIGURACIÓN FASTAPI
# ============================================================
app = FastAPI(
    title="SecureMail Phishing Detection API",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rutas de autenticación JWT (/auth/token)
app.include_router(auth_router)

# ============================================================
# ESQUEMAS DE ENTRADA / SALIDA (PYDANTIC)
# ============================================================
class EmailInput(BaseModel):
    From: str = Field(default="No Data")
    To: str = Field(default="No Data")
    Subject: str = Field(default="No Data")
    Body: str = Field(default="No Data")
    Date: str = Field(default="No Data")
    Concatenated_URLs: str = Field(default="No Data")
    MessageId: str = Field(default="No Data")

# ============================================================
# FUNCIÓN DE EXTRACCIÓN DE CARACTERÍSTICAS
# ============================================================
def extract_features_from_email(email: EmailInput) -> pd.DataFrame:
    """
    Extrae las características del correo y garantiza que el DataFrame devuelto
    tenga las columnas exactas que espera el scaler / modelo.
    """
    urls = email.Concatenated_URLs.split(",") if email.Concatenated_URLs != "No Data" else []
    urls = [u.strip() for u in urls if u.strip() and u.strip() != "No Data"]

    # Diccionario base con características habituales
    features = {
        "url_count": len(urls),
        "body_length": len(email.Body) if email.Body != "No Data" else 0,
        "subject_length": len(email.Subject) if email.Subject != "No Data" else 0,
        "has_urls": 1 if len(urls) > 0 else 0,
        "num_dots_urls": sum(u.count('.') for u in urls),
        "num_hyphens_urls": sum(u.count('-') for u in urls),
        "has_suspicious_words": 1 if re.search(r'verify|account|bank|login|update|password|urgent|security', email.Body, re.IGNORECASE) else 0
    }

    df = pd.DataFrame([features])

    # Si el scaler fue entrenado con nombres de columna específicos (scikit-learn >= 1.0)
    if feature_scaler is not None and hasattr(feature_scaler, "feature_names_in_"):
        expected_columns = list(feature_scaler.feature_names_in_)
        # Reordenar y rellenar con 0 cualquier columna que falte
        df = df.reindex(columns=expected_columns, fill_value=0)

    return df

# ============================================================
# ENDPOINTS DE LA API
# ============================================================
@app.get("/")
async def root():
    return {"message": "SecureMail API active and operational."}

@app.post("/predict")
async def predict(
    email_data: EmailInput,
    token_data: TokenData = Depends(require_scope("predict"))
):
    if model is None or feature_scaler is None:
        raise HTTPException(
            status_code=503, 
            detail="Servidor no listo: los modelos de ML no se cargaron correctamente."
        )

    try:
        # 1. Extraer DataFrame de características
        features_df = extract_features_from_email(email_data)

        # Validación estricta para evitar array con 0 características (shape=(1,0))
        if features_df.empty or features_df.shape[1] == 0:
            raise ValueError("No se pudieron extraer características válidas del correo.")

        # 2. Escalar características
        X_scaled = feature_scaler.transform(features_df)

        # 3. Predecir probabilidades
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_scaled)[0]
            phishing_prob = float(probabilities[1])
        else:
            # Fallback en caso de modelos que no implementan predict_proba
            pred = model.predict(X_scaled)[0]
            phishing_prob = 1.0 if pred == 1 else 0.0

        label = "Phishing" if phishing_prob >= decision_threshold else "Legitimate"

        return {
            "status": "OK",
            "predictions": [{
                "message_id": email_data.MessageId,
                "model_prediction": {
                    "label": label,
                    "probability": round(phishing_prob, 4)
                }
            }]
        }

    except Exception as e:
        print(f"ERROR en /predict | MessageId={email_data.MessageId} | {type(e).__name__}: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=f"Error al procesar las características del correo: {str(e)}"
        )
