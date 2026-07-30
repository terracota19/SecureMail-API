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
expected_features_count = 27

@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, feature_scaler, label_encoders, decision_threshold, expected_features_count
    print("Iniciando SecureMail API...")

    # 1. Cargar modelo principal
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"✅ Modelo principal cargado desde: {MODEL_PATH}")

    # 2. Cargar Scaler
    if os.path.exists(SCALER_PATH):
        feature_scaler = joblib.load(SCALER_PATH)
        print(f"✅ Scaler cargado desde: {SCALER_PATH}")
        if hasattr(feature_scaler, "n_features_in_"):
            expected_features_count = feature_scaler.n_features_in_
            print(f"ℹ️ Número de características esperadas por el Scaler: {expected_features_count}")

    # 3. Cargar Encoders
    if os.path.exists(ENCODERS_PATH):
        label_encoders = joblib.load(ENCODERS_PATH)
        print(f"✅ LabelEncoders cargados desde: {ENCODERS_PATH}")

    # 4. Cargar Umbral
    if os.path.exists(THRESHOLD_PATH):
        try:
            decision_threshold = float(joblib.load(THRESHOLD_PATH))
            print(f"✅ Umbral de decisión cargado: {decision_threshold}")
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
# FASTAPI CONFIG
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
# RECONSTRUCTOR AUTÓNOMO EN DATAFRAME (EVITA SHAPE=(1,0))
# ============================================================
def build_fallback_dataframe(email_data: EmailInput, scaler_obj) -> pd.DataFrame:
    body = email_data.Body if email_data.Body != "No Data" else ""
    subject = email_data.Subject if email_data.Subject != "No Data" else ""
    sender = email_data.From if email_data.From != "No Data" else ""
    raw_urls = email_data.Concatenated_URLs if email_data.Concatenated_URLs != "No Data" else ""
    
    urls = [u.strip() for u in raw_urls.split(",") if u.strip()]
    
    # 1. Extraer características base
    feats = [
        float(len(urls)),
        float(len(body)),
        float(len(subject)),
        1.0 if len(urls) > 0 else 0.0,
        float(sum(u.count('.') for u in urls)),
        float(sum(u.count('-') for u in urls)),
        1.0 if re.search(r'verify|account|bank|login|update|password|urgent|security|action|confirm|click', body, re.IGNORECASE) else 0.0,
        1.0 if re.search(r'verify|account|bank|login|update|password|urgent|security|action|confirm|click', subject, re.IGNORECASE) else 0.0,
        float(len(sender)),
        1.0 if "@" in sender else 0.0,
        float(sum(u.count('/') for u in urls)),
        float(len(re.findall(r'\d', body))),
        float(len(re.findall(r'\d', subject))),
        1.0 if any(re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', u) for u in urls) else 0.0
    ]

    target_dim = 27
    if scaler_obj is not None and hasattr(scaler_obj, "n_features_in_"):
        target_dim = scaler_obj.n_features_in_

    # Rellenar con ceros hasta target_dim
    if len(feats) < target_dim:
        feats.extend([0.0] * (target_dim - len(feats)))
    else:
        feats = feats[:target_dim]

    # 2. Si el scaler requiere nombres de columna específicos, los aplicamos
    if scaler_obj is not None and hasattr(scaler_obj, "feature_names_in_"):
        col_names = list(scaler_obj.feature_names_in_)
        # Si el número coincide creamos el DataFrame exacto
        if len(col_names) == len(feats):
            return pd.DataFrame([feats], columns=col_names)

    # Nombres por defecto si no están en el scaler
    cols = [f"feature_{i}" for i in range(len(feats))]
    return pd.DataFrame([feats], columns=cols)

# ============================================================
# ENDPOINTS
# ============================================================
@app.api_route("/", methods=["GET", "HEAD"])
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
        # 1. Transformación si utils.py existe
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
        
        # 2. Transformación Fallback usando DataFrame compatible
        else:
            df_input = build_fallback_dataframe(email_data, feature_scaler)
            
            # Escalar si existe el Scaler
            if feature_scaler is not None:
                try:
                    # Si el scaler requiere numpy array sin nombres:
                    if hasattr(feature_scaler, "feature_names_in_"):
                        X_input = feature_scaler.transform(df_input)
                    else:
                        X_input = feature_scaler.transform(df_input.values)
                except Exception as scale_err:
                    print(f"⚠️ Aviso al escalar ({scale_err}). Pasando valores directos.")
                    X_input = df_input.values
            else:
                X_input = df_input.values

        # 3. Predicción
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_input)[0]
            phishing_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
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
