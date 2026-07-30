import os
import sys
import re
import json
import joblib
import numpy as np
import pandas as pd

from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Modos de PyTorch / Transformers
import torch
from transformers import XLMRobertaTokenizer, XLMRobertaModel

# ============================================================
# IMPORTACIÓN DEL MÓDULO UTIL / CONFIG
# ============================================================
try:
    import utils
    print("✅ Módulo 'utils' cargado correctamente.")
except ModuleNotFoundError:
    try:
        import util as utils
        print("✅ Módulo 'util' cargado como 'utils'.")
    except ModuleNotFoundError:
        utils = None
        print("⚠️ Advertencia: No se encontró 'utils.py'. Se usará procesamiento fallback local.")

try:
    import config
    print("✅ Módulo 'config' cargado correctamente.")
except ModuleNotFoundError:
    config = None
    print("⚠️ Advertencia: No se encontró 'config.py'.")

# Importar autenticación (auth.py)
from auth import auth_router, require_scope, TokenData

# ============================================================
# CONSTANTES Y CONFIGURACIÓN DE RUTAS
# ============================================================
MODELS_DIR = os.getenv("MODELS_DIR", "/secure.mail/models")
OBJECTS_DIR = os.getenv("OBJECTS_DIR", "/secure.mail/objects")

MODEL_PATH_SKLEARN = getattr(config, "BEST_MODEL_PATH", os.path.join(MODELS_DIR, "best_phishing_model.joblib"))
MODEL_PATH_HYBRID = getattr(config, "HYBRID_BEST_MODEL_PATH", os.path.join(MODELS_DIR, "hybrid_best_model.pth"))
SCALER_PATH = getattr(config, "SCALER_PATH", os.path.join(OBJECTS_DIR, "feature_scaler.joblib"))
ENCODERS_PATH = getattr(config, "ENCODERS_PATH", os.path.join(OBJECTS_DIR, "label_encoders.joblib"))
THRESHOLD_MAP_PATH = getattr(config, "THRESHOLD_MAP_PATH", os.path.join(OBJECTS_DIR, "thresholds_map.joblib"))
BERT_MODEL_NAME = getattr(config, "BERT_MODEL_NAME", "xlm-roberta-base")

# ============================================================
# ARQUITECTURA DEL MODELO HÍBRIDO (PYTORCH)
# ============================================================
class HybridPhishingModel(torch.nn.Module):
    def __init__(self, n_metadata_features: int, bert_model_name: str = BERT_MODEL_NAME):
        super(HybridPhishingModel, self).__init__()
        self.bert = XLMRobertaModel.from_pretrained(bert_model_name)
        bert_output_dim = self.bert.config.hidden_size
        total_input_dim = bert_output_dim + n_metadata_features
        
        self.classification_head = torch.nn.Sequential(
            torch.nn.Linear(total_input_dim, 256), torch.nn.ReLU(), torch.nn.Dropout(0.3),
            torch.nn.Linear(256, 64), torch.nn.ReLU(), torch.nn.Dropout(0.2),
            torch.nn.Linear(64, 1)
        )
        
    def forward(self, input_ids, attention_mask, metadata):
        bert_outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
        bert_cls_embedding = bert_outputs.pooler_output
        fused_vector = torch.cat([bert_cls_embedding, metadata], dim=1)
        logits = self.classification_head(fused_vector)
        return logits

# ============================================================
# ESTADO GLOBAL DE LA APLICACIÓN
# ============================================================
state: Dict[str, Any] = {
    "model_type": None,          # 'sklearn' o 'hybrid'
    "model": None,
    "tokenizer": None,
    "bert_base_model": None,     # Para extracción de embeddings de Sklearn si aplica
    "feature_scaler": None,
    "label_encoders": None,
    "decision_threshold": 0.5,
    "device": torch.device("cuda" if torch.cuda.is_available() else "cpu")
}

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Iniciando SecureMail Inference API...")
    print(f"ℹ️ Dispositivo de procesamiento: {state['device']}")

    # 1. Cargar Scaler y Encoders
    if os.path.exists(SCALER_PATH):
        state["feature_scaler"] = joblib.load(SCALER_PATH)
        print(f"✅ Scaler cargado desde: {SCALER_PATH}")

    if os.path.exists(ENCODERS_PATH):
        state["label_encoders"] = joblib.load(ENCODERS_PATH)
        print(f"✅ Encoders cargados desde: {ENCODERS_PATH}")

    # 2. Cargar Umbral de Decisión
    if os.path.exists(THRESHOLD_MAP_PATH):
        try:
            t_map = joblib.load(THRESHOLD_MAP_PATH)
            if isinstance(t_map, dict) and len(t_map) > 0:
                state["decision_threshold"] = float(list(t_map.values())[0])
                print(f"✅ Umbral de decisión cargado: {state['decision_threshold']}")
        except Exception as e:
            print(f"⚠️ No se pudo cargar el umbral del mapa: {e}")

    # 3. Cargar Tokenizer
    try:
        state["tokenizer"] = XLMRobertaTokenizer.from_pretrained(BERT_MODEL_NAME)
        print(f"✅ Tokenizer ({BERT_MODEL_NAME}) cargado correctamente.")
    except Exception as e:
        print(f"⚠️ Error al cargar Tokenizer: {e}")

    # 4. Cargar Modelo (Prioridad al modelo Híbrido PyTorch, luego Sklearn)
    if os.path.exists(MODEL_PATH_HYBRID) and state["feature_scaler"] is not None:
        try:
            n_meta = len(state["feature_scaler"].feature_names_in_)
            hybrid_net = HybridPhishingModel(n_metadata_features=n_meta)
            hybrid_net.load_state_dict(torch.load(MODEL_PATH_HYBRID, map_location=state["device"]))
            hybrid_net.to(state["device"])
            hybrid_net.eval()
            
            state["model"] = hybrid_net
            state["model_type"] = "hybrid"
            print(f"✅ Modelo Híbrido PyTorch cargado con éxito desde: {MODEL_PATH_HYBRID}")
        except Exception as e:
            print(f"⚠️ Error cargando modelo híbrido PyTorch: {e}")

    if state["model"] is None and os.path.exists(MODEL_PATH_SKLEARN):
        try:
            state["model"] = joblib.load(MODEL_PATH_SKLEARN)
            state["model_type"] = "sklearn"
            print(f"✅ Modelo Sklearn / Calibrado cargado con éxito desde: {MODEL_PATH_SKLEARN}")

            # Cargar BERT base para embeddings si el modelo es de Sklearn
            if utils is not None and hasattr(utils, "get_bert_model_and_tokenizer"):
                _, state["bert_base_model"] = utils.get_bert_model_and_tokenizer()
            else:
                state["bert_base_model"] = XLMRobertaModel.from_pretrained(BERT_MODEL_NAME).to(state["device"])
                state["bert_base_model"].eval()
        except Exception as e:
            print(f"❌ Error cargando modelo Sklearn: {e}")

    yield
    print("🛑 Servidor detenido. Recursos liberados.")

# ============================================================
# CONFIGURACIÓN DE FASTAPI Y CORS
# ============================================================
app = FastAPI(
    title="SecureMail Phishing Detection API",
    version="2.0.0",
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

class EmailInput(BaseModel):
    From: str = Field(default="No Data")
    To: str = Field(default="No Data")
    Subject: str = Field(default="No Data")
    Body: str = Field(default="No Data")
    Date: str = Field(default="No Data")
    Concatenated_URLs: str = Field(default="No Data")
    MessageId: str = Field(default="No Data")

# ============================================================
# FUNCIONES AUXILIARES DE TRANSFORMACIÓN DE ENTRADA
# ============================================================
def extract_metadata_features(df_raw: pd.DataFrame) -> np.ndarray:
    """Preprocesa y escala metadatos igual que PhishingDataset o fit_preprocess_additional_features"""
    if utils is not None and hasattr(utils, "transform_preprocess_additional_features"):
        return utils.transform_preprocess_additional_features(
            df_raw, 
            state["label_encoders"], 
            state["feature_scaler"]
        )

    # Fallback local en caso de que utils falle o no exista
    df = df_raw.copy()
    scaler = state["feature_scaler"]
    encoders = state["label_encoders"]

    if "feature_hasher" in encoders:
        hasher = encoders["feature_hasher"]
        cat_cols = ["From", "To", "Subject", "Concatenated_URLs", "MessageId"]
        cols_to_hash = [c for c in cat_cols if c in df.columns]
        df_hashed = hasher.transform(df[cols_to_hash].astype(str).fillna("No Data"))
    else:
        df_hashed = pd.DataFrame(index=df.index)

    # Tiempo por defecto
    df["time_feature"] = 0.0

    features_to_scale = pd.concat([
        df_hashed.reset_index(drop=True),
        df[["time_feature"]].reset_index(drop=True)
    ], axis=1)

    if hasattr(scaler, "feature_names_in_"):
        features_to_scale = features_to_scale[list(scaler.feature_names_in_)]

    return scaler.transform(features_to_scale)

def prepare_concatenated_text(email_data: EmailInput) -> str:
    """Concatena los campos de texto usando el token separador de BERT"""
    sep = getattr(config, "BERT_SEP_TOKEN", "</s>")
    subj = str(email_data.Subject) if email_data.Subject != "No Data" else ""
    body = str(email_data.Body) if email_data.Body != "No Data" else ""
    urls = str(email_data.Concatenated_URLs) if email_data.Concatenated_URLs != "No Data" else ""
    return f"{subj} {sep} {body} {sep} {urls}"

def get_bert_embeddings(text: str) -> np.ndarray:
    """Genera embeddings del token [CLS] / </s> para modelos Sklearn"""
    tokenizer = state["tokenizer"]
    bert_model = state["bert_base_model"]
    device = state["device"]

    inputs = tokenizer(
        text,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=getattr(config, "MAX_LENGTH", 128)
    ).to(device)

    with torch.no_grad():
        outputs = bert_model(**inputs)
        # Extraer representación pooled o [CLS]
        if hasattr(outputs, "pooler_output") and outputs.pooler_output is not None:
            cls_embedding = outputs.pooler_output
        else:
            cls_embedding = outputs.last_hidden_state[:, 0, :]

    return cls_embedding.cpu().numpy()

# ============================================================
# ENDPOINTS
# ============================================================
@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    return {
        "status": "active",
        "model_type": state["model_type"],
        "threshold": state["decision_threshold"]
    }

@app.post("/predict")
async def predict(
    email_data: EmailInput,
    token_data: TokenData = Depends(require_scope("predict"))
):
    if state["model"] is None:
        raise HTTPException(
            status_code=503,
            detail="Servidor no listo: Ningún modelo de Machine Learning está cargado."
        )

    try:
        # Dataframe base para metadatos
        raw_dict = {
            "From": email_data.From,
            "To": email_data.To,
            "Subject": email_data.Subject,
            "Body": email_data.Body,
            "Date": email_data.Date,
            "Concatenated_URLs": email_data.Concatenated_URLs,
            "MessageId": email_data.MessageId
        }
        df_raw = pd.DataFrame([raw_dict])

        # 1. Obtención de Metadatos Procesados
        metadata_scaled = extract_metadata_features(df_raw)

        # 2. Inferencia según el tipo de modelo
        phishing_prob = 0.5

        if state["model_type"] == "hybrid":
            # Modelo PyTorch HybridPhishingModel
            text_str = prepare_concatenated_text(email_data)
            max_len = getattr(config, "MAX_LENGTH", 128)
            
            encoding = state["tokenizer"].encode_plus(
                text_str,
                max_length=max_len,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )

            input_ids = encoding['input_ids'].to(state["device"])
            attention_mask = encoding['attention_mask'].to(state["device"])
            meta_tensor = torch.tensor(metadata_scaled, dtype=torch.float).to(state["device"])

            with torch.no_grad():
                logits = state["model"](input_ids, attention_mask, meta_tensor)
                phishing_prob = float(torch.sigmoid(logits).cpu().numpy()[0][0])

        elif state["model_type"] == "sklearn":
            # Modelo de Sklearn (embeddings concantedos con metadatos)
            text_str = prepare_concatenated_text(email_data)
            text_embeddings = get_bert_embeddings(text_str)

            # Recreación de X_combined = [X_bert, X_metadata]
            X_combined = np.hstack([text_embeddings, metadata_scaled])

            if hasattr(state["model"], "predict_proba"):
                probs = state["model"].predict_proba(X_combined)[0]
                phishing_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            else:
                pred = state["model"].predict(X_combined)[0]
                phishing_prob = 1.0 if pred == 1 else 0.0

        # Evaluar resultado según umbral ajustado
        threshold = state["decision_threshold"]
        label = "Phishing" if phishing_prob >= threshold else "Legitimate"

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
        print(f"❌ ERROR en /predict: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail=f"Error al procesar la predicción: {str(e)}"
        )
