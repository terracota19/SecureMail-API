import os
import re
import json
import joblib
import torch
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
    print("⚠️ Módulo 'utils' no encontrado en el entorno. Funcionando en modo fallback.")

# ============================================================
# CONFIGURACIÓN INTERNA
# ============================================================
DEVICE = torch.device("cpu")
TEXT_COLUMNS_FOR_BERT = ["Subject", "Body", "Concatenated_URLs"]
BERT_SEP_TOKEN = "[SEP]"

MODELS_DIR = os.getenv("MODELS_DIR", "/secure.mail/models")
OBJECTS_DIR = os.getenv("OBJECTS_DIR", "/secure.mail/objects")

SCALER_PATH = os.path.join(OBJECTS_DIR, "feature_scaler.joblib")
ENCODERS_PATH = os.path.join(OBJECTS_DIR, "label_encoders.joblib")
MODEL_PATH = os.path.join(MODELS_DIR, "best_phishing_model.joblib")
THRESHOLD_PATH = os.path.join(OBJECTS_DIR, "decision_threshold.joblib")

# ============================================================
# VARIABLES GLOBALES Y CARGA DE MODELOS
# ============================================================
model = None
tokenizer = None
bert_model = None
feature_scaler = None
label_encoders = None
decision_threshold = 0.5

@asynccontextmanager
async def lifespan(app: FastAPI):
    global model, tokenizer, bert_model, feature_scaler, label_encoders, decision_threshold
    print("Iniciando SecureMail API...")

    # 1. Cargar modelo principal
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"✅ Modelo principal cargado desde: {MODEL_PATH}")

    # 2. Cargar Scaler y LabelEncoders
    if os.path.exists(SCALER_PATH):
        feature_scaler = joblib.load(SCALER_PATH)
        print(f"✅ Scaler cargado desde: {SCALER_PATH}")

    if os.path.exists(ENCODERS_PATH):
        label_encoders = joblib.load(ENCODERS_PATH)
        print(f"✅ LabelEncoders cargados desde: {ENCODERS_PATH}")

    # 3. Cargar Modelo BERT y Tokenizer solo si utils está presente
    if utils is not None and hasattr(utils, "get_bert_model_and_tokenizer"):
        print("Cargando modelo BERT y Tokenizer desde utils...")
        tokenizer, bert_model = utils.get_bert_model_and_tokenizer()
        print(f"✅ BERT cargado correctamente.")

    # 4. Umbral de Decisión
    if os.path.exists(THRESHOLD_PATH):
        decision_threshold = float(joblib.load(THRESHOLD_PATH))
        print(f"✅ Umbral de decisión cargado: {decision_threshold}")

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
    if model is None or feature_scaler is None:
        raise HTTPException(
            status_code=503, 
            detail="El servidor no está listo: los modelos de ML no han sido cargados."
        )

    try:
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

        # Opcion A: Si tenemos utils cargado y BERT funcionando
        if utils is not None and bert_model is not None and tokenizer is not None:
            text_list = []
            for col in TEXT_COLUMNS_FOR_BERT:
                val = input_df[col].fillna("").astype(str) if col in input_df.columns else pd.Series([""])
                text_list.append(val)
            
            combined_text = pd.concat(text_list, axis=1).apply(lambda x: f" {BERT_SEP_TOKEN} ".join(x), axis=1).tolist()
            bert_embeddings = utils.generate_bert_embeddings(combined_text, tokenizer, bert_model)

            additional_scaled = utils.transform_preprocess_additional_features(
                input_df, label_encoders, feature_scaler
            )
            X_input = np.hstack([bert_embeddings, additional_scaled])

        # Opción B: Fallback sin utils (extracción manual de features tabulares)
        else:
            urls = email_data.Concatenated_URLs.split(",") if email_data.Concatenated_URLs != "No Data" else []
            urls = [u.strip() for u in urls if u.strip() and u.strip() != "No Data"]

            features_dict = {
                "url_count": len(urls),
                "body_length": len(email_data.Body) if email_data.Body != "No Data" else 0,
                "subject_length": len(email_data.Subject) if email_data.Subject != "No Data" else 0,
                "has_urls": 1 if len(urls) > 0 else 0,
                "num_dots_urls": sum(u.count('.') for u in urls),
                "num_hyphens_urls": sum(u.count('-') for u in urls),
                "has_suspicious_words": 1 if re.search(r'verify|account|bank|login|update|password|urgent|security', email_data.Body, re.IGNORECASE) else 0
            }
            
            numeric_df = pd.DataFrame([features_dict])

            # Si el Scaler requiere columnas específicas por nombre
            if hasattr(feature_scaler, "feature_names_in_"):
                expected_cols = list(feature_scaler.feature_names_in_)
                numeric_df = numeric_df.reindex(columns=expected_cols, fill_value=0)

            X_input = feature_scaler.transform(numeric_df)

        # Realizar predicción
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_input)[0]
            phishing_prob = float(probabilities[1])
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
