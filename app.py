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

# Cargar autenticación
from auth import auth_router, require_scope, TokenData

# Importar tus propios módulos de entrenamiento
import config
import utils

# ============================================================
# VARIABLES GLOBALES Y CARGA DE MODELOS Y BERT
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

    # 1. Cargar modelo principal de clasificación
    model_path = os.path.join(config.MODELS_DIR if hasattr(config, 'MODELS_DIR') else "/secure.mail/models", "best_phishing_model.joblib")
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        print(f"✅ Modelo principal cargado desde: {model_path}")

    # 2. Cargar Scaler y LabelEncoders desde tus artefactos
    scaler_path = getattr(config, 'SCALER_PATH', "/secure.mail/objects/feature_scaler.joblib")
    if os.path.exists(scaler_path):
        feature_scaler = joblib.load(scaler_path)
        print(f"✅ Scaler cargado desde: {scaler_path}")

    encoders_path = getattr(config, 'ENCODERS_PATH', "/secure.mail/objects/label_encoders.joblib")
    if os.path.exists(encoders_path):
        label_encoders = joblib.load(encoders_path)
        print(f"✅ LabelEncoders cargados desde: {encoders_path}")

    # 3. Cargar Modelo BERT y Tokenizer usando tu utils
    print("Cargando modelo BERT y Tokenizer...")
    tokenizer, bert_model = utils.get_bert_model_and_tokenizer()
    print(f"✅ BERT cargado correctamente en dispositivo: {config.DEVICE}")

    # 4. Umbral de Decisión
    threshold_path = "/secure.mail/objects/decision_threshold.joblib"
    if os.path.exists(threshold_path):
        decision_threshold = float(joblib.load(threshold_path))
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
    if model is None or feature_scaler is None or bert_model is None:
        raise HTTPException(
            status_code=503, 
            detail="El servidor no está listo: los modelos de ML/BERT no han sido cargados."
        )

    try:
        # 1. Crear DataFrame con 1 fila representando el correo
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

        # 2. Generar Texto Concatenado para BERT (Subject + Body + URLs)
        text_cols = getattr(config, 'TEXT_COLUMNS_FOR_BERT', ['Subject', 'Body', 'Concatenated_URLs'])
        sep_token = getattr(config, 'BERT_SEP_TOKEN', '[SEP]')
        
        text_list = []
        for col in text_cols:
            val = input_df[col].fillna("").astype(str) if col in input_df.columns else pd.Series([""])
            text_list.append(val)
        
        combined_text = pd.concat(text_list, axis=1).apply(lambda x: f" {sep_token} ".join(x), axis=1).tolist()

        # 3. Generar Embeddings de BERT
        bert_embeddings = utils.generate_bert_embeddings(combined_text, tokenizer, bert_model)

        # 4. Transformar y escalar las características adicionales (Tabulares)
        additional_scaled = utils.transform_preprocess_additional_features(
            input_df, label_encoders, feature_scaler
        )

        # 5. Combinar Embeddings + Características Adicionales Escaladas (np.hstack)
        X_input = np.hstack([bert_embeddings, additional_scaled])

        # 6. Realizar Predicción final con el Modelo de ML
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
