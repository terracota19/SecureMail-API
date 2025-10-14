import os
import re
import base64
import joblib
import numpy as np
import torch
import pandas as pd
import json
from dotenv import load_dotenv
from urllib.parse import urlparse
from transformers import BertTokenizer, BertModel
from typing import Optional, List
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
# import binascii # YA NO ES NECESARIO
# import filetype # YA NO ES NECESARIO

# =============================================================================
# 0. CONFIGURACIÓN Y ARTEFACTOS
# =============================================================================

BERT_MODEL_NAME = 'bert-base-uncased'
MAX_LENGTH = 128
METRICS_PATH = './Metrics/validation_metrics.json'

UMBRAL_OPTIMO = None
MODEL = None
SCALER = None
TOKENIZER = None
MODEL_BERT = None

load_dotenv()
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://terracota19.github.io",
        "https://outlook.office.com",
        "https://outlook.live.com",
        "https://outlook.office365.com",
        "https://outlook.office.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def load_ml_artifacts():
    global MODEL, SCALER, TOKENIZER, MODEL_BERT, UMBRAL_OPTIMO
    
    try:
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH, 'r') as f:
                metrics = json.load(f)
            UMBRAL_OPTIMO = metrics.get("final_threshold")
            if UMBRAL_OPTIMO is None:
                UMBRAL_OPTIMO = 0.5
        else:
            UMBRAL_OPTIMO = 0.5

        MODEL = joblib.load("./models/best_phishing_model.joblib")
        SCALER = joblib.load("./objects/feature_scaler.joblib")
        TOKENIZER = BertTokenizer.from_pretrained(BERT_MODEL_NAME)
        MODEL_BERT = BertModel.from_pretrained(BERT_MODEL_NAME).to(device)
        MODEL_BERT.eval()
        
    except Exception as e:
        print(f"ERROR CRÍTICO al cargar artefactos de ML: {e}")

load_ml_artifacts()


# =============================================================================
# 1. MODELOS DE DATOS (FastAPI/Pydantic)
# =============================================================================

# ELIMINADO: class Attachment(BaseModel):
    
class EmailData(BaseModel):
    From: str
    To: str
    Subject: str
    Body: str
    MessageId: str
    Date: str
    Concatenated_URLs: str
    # ELIMINADO: Attachments: List[Attachment]


# =============================================================================
# 2. FUNCIONES DE PREPROCESAMIENTO (REPLICANDO JUPYTER)
# =============================================================================

def convert_to_float(value):
    return float(value)

def generate_bert_embeddings(text: str, tokenizer: BertTokenizer, model_bert: BertModel, max_length: int = MAX_LENGTH, device: torch.device = device) -> np.ndarray:
    if model_bert is None or tokenizer is None:
        raise RuntimeError("BERT Model/Tokenizer not loaded.")
        
    encoding = tokenizer.encode_plus(
        text,
        add_special_tokens=True,
        max_length=max_length,
        padding='max_length',
        truncation=True,
        return_tensors='pt'
    )
    
    input_ids = encoding['input_ids'].to(device)
    attention_mask = encoding['attention_mask'].to(device)
    
    with torch.no_grad():
        output = model_bert(input_ids=input_ids, attention_mask=attention_mask)
        
    cls_embedding = output.last_hidden_state[:, 0, :].cpu().numpy()
    
    return cls_embedding.flatten()

def extract_url_features(body_text: str) -> np.ndarray:
    
    url_pattern = r'\bhttps?://[\w.-]+(?:\/[\w./?%&=-]*)?\b'
    urls = re.findall(url_pattern, body_text)
    
    n_urls = len(urls)
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    has_ip_in_url = 1 if any(re.search(ip_pattern, urlparse(url).netloc) for url in urls) else 0

    features = np.array([
        n_urls, 
        has_ip_in_url,
    ])
    
    return features

def calculate_text_features(subject: str, body: str, n_attachments: int = 0) -> np.ndarray:
    
    full_text = f"{subject} {body}"
    
    len_subject = len(subject)
    len_body = len(body)
    len_full_text = len(full_text)
    
    n_at = full_text.count('@')
    n_html_tags = len(re.findall(r'<.*?>', body))

    n_attachments_feature = n_attachments # SE MANTIENE A CERO

    # Nota: si el feature de n_attachments ya no se usa en el entrenamiento, se debe eliminar de aquí y del SCALER
    features = np.array([
        len_subject,
        len_body,
        len_full_text,
        n_at,
        n_html_tags,
        n_attachments_feature, # MANTENER si está en el SCALER, sino, ELIMINAR
    ])
    
    return features


# =============================================================================
# 3. LÓGICA DE INFERENCIA DE ADJUNTOS (ELIMINADO)
# =============================================================================
# ELIMINADO: async def analyze_attachment(attachment: Attachment):


# =============================================================================
# 4. ENDPOINT PRINCIPAL
# =============================================================================

@app.post("/")
async def predict_phishing(email: EmailData, request: Request):
    if MODEL is None or SCALER is None or MODEL_BERT is None or UMBRAL_OPTIMO is None:
        raise HTTPException(status_code=503, detail="ML service is initializing or failed to load critical components.")
        
    try:
        # ASUMIENDO que n_attachments = 0 (ya no se reciben adjuntos)
        n_attachments = 0 
        
        X_text_features = calculate_text_features(email.Subject, email.Body, n_attachments)
        X_url_features = extract_url_features(email.Body)

        # 1. Combinar Features Adicionales (Numéricas)
        X_additional = np.hstack([X_text_features, X_url_features])
        
        # 2. Escalado de Features Adicionales
        X_additional_scaled = SCALER.transform(X_additional.reshape(1, -1))
        
        # 3. Generación de Embeddings BERT
        text_for_bert = " ".join([email.Subject, email.Body])
        X_bert_embeddings = generate_bert_embeddings(text_for_bert, TOKENIZER, MODEL_BERT)
        
        # 4. Combinación Final
        X_combined = np.hstack([X_bert_embeddings.reshape(1, -1), X_additional_scaled])
        
        # 5. Predicción del Modelo Final
        pred_prob = MODEL.predict_proba(X_combined)[0]
        prob_phishing = pred_prob[1]

        # 6. Aplicación de la Política de Umbral
        ml_verdict = (
            "Phishing" if prob_phishing >= UMBRAL_OPTIMO else
            "Safe"
        )
        
        # 7. Análisis de Adjuntos (Simplificado)
        # La bandera de 'malicious_file' debe ser False ya que no se analizan adjuntos.
        malicious_attachments = False 

        # 8. Retorno de la Respuesta (Formato Apps Script)
        prediction = [{
            "model_prediction": {
                "label": ml_verdict, 
                "malicious_file": malicious_attachments, 
                "probability": convert_to_float(prob_phishing)
            }
        }]

        return {"status": "OK", "predictions": prediction}

    except Exception as e:
        return JSONResponse(status_code=500, content={"status": "ERROR", "message": f"Error interno del servidor: {e}"})

@app.get("/health")
def read_root():
    if MODEL is None or SCALER is None or MODEL_BERT is None:
        raise HTTPException(status_code=503, detail="ML service failed to load.")
    return {"message": "SecureMail-API está operativa y saludable."}