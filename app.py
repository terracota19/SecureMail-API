import os
import re
import json
import joblib
import numpy as np
import pandas as pd
from typing import List, Optional
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Cargar autenticación desde auth.py
from auth import auth_router, require_scope, TokenData

# ============================================================
# IMPORTACIÓN SEGURA DE UTILS
# ============================================================
try:
    import utils
    print("✅ Módulo 'utils' cargado correctamente.")
except ModuleNotFoundError:
    utils = None
    print("⚠️ Módulo 'utils' no encontrado en el entorno. Funcionando en modo fallback autónomo.")

# ============================================================
# CONFIGURACIÓN DE RUTAS
# ============================================================
MODELS_DIR = os.getenv("MODELS_DIR", "/secure.mail/models")
OBJECTS_DIR = os.getenv("OBJECTS_DIR", "/secure.mail/objects")

SCALER_PATH = os.path.join(OBJECTS_DIR, "feature_scaler.joblib")
ENCODERS_PATH = os.path.join(OBJECTS_DIR, "label_encoders.joblib")
MODEL_PATH = os.path.join(MODELS_DIR, "best_phishing_model.joblib")
THRESHOLD_PATH = os.path.join(OBJECTS_DIR, "decision_threshold.joblib")
THRESHOLD_MAP_PATH = os.path.join(OBJECTS_DIR, "thresholds_map.joblib")

# ============================================================
# VARIABLES GLOBALES Y CARGA DE MODELOS
# ============================================================
model = None
feature_scaler = None
label_encoders = None
decision_threshold = 0.5
expected_features_count = 101  # Valor por defecto detectado en tus notebooks

@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, feature_scaler, label_encoders, decision_threshold, expected_features_count
    print("Iniciando SecureMail API...")

    # 1. Cargar modelo principal
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"✅ Modelo principal cargado desde: {MODEL_PATH}")

    # 2. Cargar Scaler y LabelEncoders
    if os.path.exists(SCALER_PATH):
        feature_scaler = joblib.load(SCALER_PATH)
        print(f"✅ Scaler cargado desde: {SCALER_PATH}")
        
        # Detectar cuántas características espera el Scaler
        if hasattr(feature_scaler, "n_features_in_"):
            expected_features_count = feature_scaler.n_features_in_
            print(f"ℹ️ Número de características esperadas por el Scaler: {expected_features_count}")

    if os.path.exists(ENCODERS_PATH):
        label_encoders = joblib.load(ENCODERS_PATH)
        print(f"✅ LabelEncoders cargados desde: {ENCODERS_PATH}")

    # 3. Cargar Umbral de Decisión
    if os.path.exists(THRESHOLD_PATH):
        try:
            decision_threshold = float(joblib.load(THRESHOLD_PATH))
            print(f"✅ Umbral de decisión cargado desde file: {decision_threshold}")
        except Exception:
            decision_threshold = 0.5
    elif os.path.exists(THRESHOLD_MAP_PATH):
        try:
            t_map = joblib.load(THRESHOLD_MAP_PATH)
            if isinstance(t_map, dict) and len(t_map) > 0:
                decision_threshold = float(list(t_map.values())[0])
                print(f"✅ Umbral de decisión cargado desde mapa: {decision_threshold}")
        except Exception:
            decision_threshold = 0.5

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

app.include_router(auth_router)

# ============================================================
# ESQUEMAS DE ENTRADA
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
# HELPER: CONSTRUCCIÓN DE VECTOR DE CARACTERÍSTICAS
# ============================================================
def extract_tabular_features(email_data: EmailInput, target_dim: int) -> np.ndarray:
    """Extrae métricas numéricas del correo y asegura un vector del tamaño exacto esperado por el modelo."""
    urls = [u.strip() for u in email_data.Concatenated_URLs.split(",") if u.strip() and u.strip() != "No Data"]
    
    # Extraer características heurísticas principales
    feats = [
        len(urls),                                              # f0: Recuento de URLs
        len(email_data.Body) if email_data.Body != "No Data" else 0,   # f1: Longitud del cuerpo
        len(email_data.Subject) if email_data.Subject != "No Data" else 0, # f2: Longitud del asunto
        1 if len(urls) > 0 else 0,                               # f3: Tiene URLs
        sum(u.count('.') for u in urls),                         # f4: Puntos en URLs
        sum(u.count('-') for u in urls),                         # f5: Guiones en URLs
        1 if re.search(r'verify|account|bank|login|update|password|urgent|security|action', email_data.Body, re.IGNORECASE) else 0, # f6: Palabras sospechosas cuerpo
        1 if re.search(r'verify|account|bank|login|update|password|urgent|security|action', email_data.Subject, re.IGNORECASE) else 0, # f7: Palabras sospechosas asunto
        len(email_data.From) if email_data.From != "No Data" else 0,   # f8: Longitud del remitente
        1 if "@" in email_data.From else 0                       # f9: Formato remitente válido
    ]
    
    # Ajustar exactamente a la dimensión `target_dim` (ej. 101 columnas)
    if len(feats) < target_dim:
        feats.extend([0.0] * (target_dim - len(feats)))
    elif len(feats) > target_dim:
        feats = feats[:target_dim]
        
    return np.array([feats], dtype=np.float32)

# ============================================================
# ENDPOINTS
# ============================================================
@app.get("/")
async def root():
    return {"message": "SecureMail API active and operational."}

@app.post("/predict")
async def predict(
    email_data: EmailInput,
    token_data: TokenData = Depends(require_scope("predict"))
):
    if model is None:
        raise HTTPException(
            status_code=503, 
            detail="El servidor no está listo: el modelo de Machine Learning no ha sido cargado."
        )

    try:
        # 1. Si utils está presente, intentar usar la transformación original
        if utils is not None and hasattr(utils, "transform_preprocess_additional_features"):
            raw_dict = {
                "From": email_data.From,
                "To": email_data.To,
                "Subject": email_data.Subject,
                "Body": email_data.Body,
                "Date": email_data.Date,
                "Concatenated_URLs": email_data.Concatenated_URLs,
                "MessageId": email_data.MessageId
            }
            input_df = pd.DataFrame([raw_dict])
            X_input = utils.transform_preprocess_additional_features(input_df, label_encoders, feature_scaler)
        
        # 2. Si no hay utils (Fallback autónomo)
        else:
            raw_vector = extract_tabular_features(email_data, expected_features_count)
            
            # Aplicar StandardScaler si está cargado
            if feature_scaler is not None:
                try:
                    X_input = feature_scaler.transform(raw_vector)
                except Exception as scale_err:
                    print(f"⚠️ Advertencia al escalar: {scale_err}. Usando características sin escalar.")
                    X_input = raw_vector
            else:
                X_input = raw_vector

        # 3. Inferencia con el modelo de ML
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_input)[0]
            # Si la salida devuelve 2 clases [prob_legit, prob_phishing]
            if len(probabilities) > 1:
                phishing_prob = float(probabilities[1])
            else:
                phishing_prob = float(probabilities[0])
        else:
            pred = model.predict(X_input)[0]
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
            detail=f"Error en la inferencia del modelo: {str(e)}"
        )
