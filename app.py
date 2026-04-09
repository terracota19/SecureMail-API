import re
import joblib
import numpy as np
import torch
import pandas as pd
import json
import os
from dotenv import load_dotenv
load_dotenv()

from urllib.parse import urlparse
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from transformers import XLMRobertaTokenizer, XLMRobertaModel
from auth import auth_router, require_scope, TokenData

# =============================================================================
# CONFIGURACION GLOBAL
# =============================================================================

BERT_MODEL_NAME = 'xlm-roberta-base'
MAX_LENGTH = 128
EMBEDDING_DIM = 768
DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'models/best_phishing_model.joblib')
PIPELINE_PATH = os.path.join(BASE_DIR, 'objects/feature_scaler.joblib')
METRICS_PATH = os.path.join(BASE_DIR, 'Metrics/validation_metrics.json')

MISSING_VALUE_STR = 'No Data'
BERT_SEP_TOKEN = '[SEP]'

ML_ARTIFACTS = {}

def engineer_detailed_features(df_input):
    df_eng = df_input.copy()

    for col in ['Subject', 'Body', 'From', 'Concatenated_URLs', 'Date']:
        df_eng[col] = df_eng.get(col, MISSING_VALUE_STR).astype(str).fillna(MISSING_VALUE_STR)

    df_eng['subject_perc_caps'] = df_eng['Subject'].apply(lambda x: sum(1 for c in str(x) if c.isupper()) / (len(str(x)) + 1e-6))
    df_eng['subject_kw_urgent'] = df_eng['Subject'].str.contains(r'urgent|URGENT|Important|IMPORTANTE', case=False).astype(int)

    df_eng['body_num_words'] = df_eng['Body'].apply(lambda x: len(str(x).split()))
    df_eng['body_num_unique_words'] = df_eng['Body'].apply(lambda x: len(set(str(x).split())))
    df_eng['body_perc_caps'] = df_eng['Body'].apply(lambda x: sum(1 for c in str(x) if c.isupper()) / (len(str(x)) + 1e-6))
    df_eng['body_kw_sensitive'] = df_eng['Body'].str.contains(r'password|account|verify|bank|ssn|confidential', case=False).astype(int)
    df_eng['Saludo_Generico'] = df_eng['Body'].str.contains(r'Dear user|Dear customer|Dear account holder', case=False).astype(int)

    richness = df_eng['body_num_unique_words'] / (df_eng['body_num_words'] + 1e-6)
    df_eng['body_richness_category'] = pd.cut(richness, bins=[-1, 0.3, 0.7, 999], labels=['Low', 'Medium', 'High'], right=False).astype(str).fillna('Low')

    def get_domain(sender):
        if not isinstance(sender, str) or '@' not in sender:
            return MISSING_VALUE_STR
        match = re.search(r'@([\w.-]+)', sender)
        return match.group(1) if match else MISSING_VALUE_STR

    df_eng['from_domain'] = df_eng['From'].apply(get_domain)
    df_eng['from_num_subdomains'] = df_eng['from_domain'].apply(lambda x: x.count('.') - 1 if x != MISSING_VALUE_STR else 0)
    common_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com']
    df_eng['from_is_common_domain'] = df_eng['from_domain'].isin(common_domains).astype(int)

    def get_urls_list(text):
        if not isinstance(text, str) or text == MISSING_VALUE_STR or not text.strip():
            return []
        return re.split(r'[,\s]+', text.strip())

    df_eng['url_list'] = df_eng['Concatenated_URLs'].apply(get_urls_list)
    df_eng['url_count'] = df_eng['url_list'].apply(lambda x: len([u for u in x if len(u) > 1]))
    df_eng['url_has_ip'] = df_eng['Concatenated_URLs'].str.contains(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}').astype(int)
    df_eng['url_has_at'] = df_eng['Concatenated_URLs'].str.contains(r'@').astype(int)
    df_eng['url_has_exe'] = df_eng['Concatenated_URLs'].str.contains(r'\.exe', case=False).astype(int)

    def avg_subdomains(urls):
        if not urls:
            return 0
        count = 0
        valid_urls = 0
        for url_str in urls:
            if len(url_str) < 5:
                continue
            try:
                hostname = urlparse(url_str).hostname
                if hostname:
                    count += hostname.count('.') - 1
                    valid_urls += 1
            except:
                pass
        return count / valid_urls if valid_urls > 0 else 0

    def avg_path_len(urls):
        if not urls:
            return 0
        length = 0
        valid_urls = 0
        for url_str in urls:
            if len(url_str) < 5:
                continue
            try:
                path = urlparse(url_str).path
                if path:
                    length += len(path)
                    valid_urls += 1
            except:
                pass
        return length / valid_urls if valid_urls > 0 else 0

    df_eng['url_avg_subdomains'] = df_eng['url_list'].apply(avg_subdomains)
    df_eng['url_avg_path_len'] = df_eng['url_list'].apply(avg_path_len)
    df_eng['Date_dt'] = pd.to_datetime(df_eng['Date'], errors='coerce', utc=True)
    df_eng['Hour'] = df_eng['Date_dt'].dt.hour.fillna(0).astype(float)

    df_eng.replace([np.inf, -np.inf], 0, inplace=True)
    df_eng.fillna(0, inplace=True)

    return df_eng

# =============================================================================
# CICLO DE VIDA
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Iniciando SecureMail API...")
    try:
        ML_ARTIFACTS['model'] = joblib.load(MODEL_PATH)
        print("Modelo cargado desde " + MODEL_PATH)

        ML_ARTIFACTS['pipeline'] = joblib.load(PIPELINE_PATH)
        print("Pipeline cargado desde " + PIPELINE_PATH)

        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH, 'r') as f:
                metrics = json.load(f)
            ML_ARTIFACTS['threshold'] = metrics.get('final_threshold', 0.5)
            print("Umbral de decision cargado: " + str(ML_ARTIFACTS['threshold']))
        else:
            print("Archivo de metricas no encontrado. Usando umbral 0.5.")
            ML_ARTIFACTS['threshold'] = 0.5

        print("Cargando BERT...")
        ML_ARTIFACTS['tokenizer'] = XLMRobertaTokenizer.from_pretrained(BERT_MODEL_NAME)
        ML_ARTIFACTS['bert'] = XLMRobertaModel.from_pretrained(BERT_MODEL_NAME).to(DEVICE).eval()
        print("BERT cargado en " + str(DEVICE))

    except Exception as e:
        print("ERROR CRITICO EN STARTUP: " + str(e))
        raise RuntimeError("Fallo al inicializar los modelos de ML.") from e

    yield

    ML_ARTIFACTS.clear()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    print("API detenida y recursos liberados.")

# =============================================================================
# APP
# =============================================================================

app = FastAPI(title="SecureMail Phishing Detection API", version="2.0", lifespan=lifespan)

app.include_router(auth_router)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

# =============================================================================
# MODELOS DE DATOS
# =============================================================================

class EmailInput(BaseModel):
    From: str = Field(..., description="Remitente del correo")
    To: str = Field(..., description="Destinatario del correo")
    Subject: str = Field(..., description="Asunto del correo")
    Body: str = Field(..., max_length=100000, description="Cuerpo del correo en texto plano")
    Date: str = Field(..., description="Fecha de recepcion")
    Concatenated_URLs: str = Field("", max_length=10000, description="URLs extraidas del cuerpo")
    MessageId: str = Field(..., description="ID unico del mensaje")

# =============================================================================
# ENDPOINTS
# =============================================================================

@app.get("/health")
def health_check():
    return {
        "status": "online",
        "models_loaded": bool(ML_ARTIFACTS),
    }

@app.post("/predict")
async def predict(
    email_data: EmailInput,
    token_data: TokenData = Depends(require_scope("predict"))
):
    if not ML_ARTIFACTS:
        raise HTTPException(status_code=503, detail="Servicio no inicializado correctamente.")

    try:
        df_raw = pd.DataFrame([email_data.model_dump()])
        df_engineered = engineer_detailed_features(df_raw)

        try:
            X_structured = ML_ARTIFACTS['pipeline'].transform(df_engineered)
            X_structured = X_structured.astype(np.float32)
        except Exception as e:
            raise HTTPException(status_code=400, detail="Error al procesar las caracteristicas del correo.")

        text_parts = [
            str(df_engineered.iloc[0].get('From', MISSING_VALUE_STR)),
            str(df_engineered.iloc[0].get('To', MISSING_VALUE_STR)),
            str(df_engineered.iloc[0].get('Date', MISSING_VALUE_STR)),
            str(df_engineered.iloc[0].get('Subject', MISSING_VALUE_STR)),
            str(df_engineered.iloc[0].get('Body', MISSING_VALUE_STR)),
            str(df_engineered.iloc[0].get('Concatenated_URLs', MISSING_VALUE_STR))
        ]
        full_text = (" " + BERT_SEP_TOKEN + " ").join(text_parts)

        bert_inputs = ML_ARTIFACTS['tokenizer'](
            full_text,
            return_tensors="pt",
            max_length=MAX_LENGTH,
            truncation=True,
            padding='max_length'
        ).to(DEVICE)

        with torch.no_grad():
            bert_outputs = ML_ARTIFACTS['bert'](**bert_inputs)

        X_bert = bert_outputs.last_hidden_state[:, 0, :].cpu().numpy()
        X_final = np.hstack([X_bert, X_structured])

        phishing_prob = float(ML_ARTIFACTS['model'].predict_proba(X_final)[0][1])
        threshold = ML_ARTIFACTS['threshold']
        label = "Phishing" if phishing_prob >= threshold else "Safe"

        return {
            "status": "OK",
            "predictions": [{
                "model_prediction": {
                    "label": label,
                    "probability": phishing_prob,
                    "malicious_file": None,
                    "file_analysis": "not_supported"
                }
            }],
            "metadata": {
                "message_id": email_data.MessageId,
                "threshold_used": threshold,
                "timestamp": pd.Timestamp.now().isoformat(),
                "analyzed_by": token_data.client_id
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        print("ERROR en /predict | MessageId=" + email_data.MessageId + " | " + type(e).__name__)
        raise HTTPException(status_code=500, detail="Error interno del servidor.")