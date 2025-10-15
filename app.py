import joblib
import numpy as np
import torch
import pandas as pd
import json 
from dotenv import load_dotenv
from urllib.parse import urlparse 
from transformers import BertTokenizer, BertModel
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from torch.cuda.amp import autocast # Necesario para compatibilidad BERT
from datetime import datetime
from typing import Dict, Any, Union 

# =============================================================================
# 0. CONFIGURACIÓN Y ARTEFACTOS 
# =============================================================================

# Constantes de BERT
BERT_MODEL_NAME = 'bert-base-uncased' 
MAX_LENGTH = 128 
EMBEDDING_DIM = 768 # 768 features

# Rutas de Artefactos 
MODEL_PATH = './models/best_phishing_model.joblib'
SCALER_PATH = './objects/feature_scaler.joblib'
ENCODER_PATH = './objects/label_encoders.joblib' 
METRICS_PATH_VALIDATION = './Metrics/validation_metrics.json'

# Variables Globales (se inicializan en load_ml_artifacts)
UMBRAL_OPTIMO: Union[float, None] = None
MODEL: Any = None
SCALER: Any = None
LABEL_ENCODERS: Dict = {}
TOKENIZER: Any = None
MODEL_BERT: Any = None

# Carga de variables de entorno (si las hubiera)
load_dotenv()
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu') 

app = FastAPI(title="SecureMail Phishing Detection API", version="1.0.0")

# Configuración CORS para el Complemento de Gmail
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Permitir todos los orígenes para el desarrollo con ngrok
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# 1. MODELOS DE DATOS Y UTILIDADES
# =============================================================================

class EmailData(BaseModel):
    """Esquema de datos de entrada del correo desde el Complemento de Gmail."""
    From: str = Field(..., description="Dirección de correo del remitente.")
    To: str = Field(..., description="Dirección de correo del destinatario.")
    Subject: str = Field(..., description="Asunto del correo.")
    Body: str = Field(..., description="Cuerpo del correo (texto plano).")
    MessageId: str = Field(..., description="ID único del mensaje de Gmail.")
    Date: str = Field(..., description="Fecha y hora del correo en formato ISO 8601.")
    Concatenated_URLs: str = Field("No Data", description="URLs extraídas del cuerpo del mensaje, separadas por espacio.")


def convert_to_float(value: Any) -> float:
    """Convierte numpy.float32/64 a float de Python para JSON serializable."""
    if isinstance(value, np.float32) or isinstance(value, np.float64):
        return float(value)
    return value


# =============================================================================
# 2. FUNCIONES DE INGENIERÍA DE CARACTERÍSTICAS
# =============================================================================

def extract_time_feature(email_data: EmailData) -> float:
    """Extrae la hora (0-23) del campo 'Date'."""
    try:
        # Reemplazar 'Z' por '+00:00' para compatibilidad con datetime.fromisoformat
        date_obj = datetime.fromisoformat(email_data.Date.replace('Z', '+00:00'))
        hour_temp = float(date_obj.hour)
    except Exception:
        hour_temp = 0.0 # Valor seguro por defecto
    return hour_temp


def preprocess_additional_features(email_data: EmailData, label_encoders: Dict) -> np.ndarray:
    """
    Codifica From/To y la Hora. Retorna las 3 features ADICIONALES (NO ESCALADAS).
    
    NOTA IMPORTANTE: Se ha eliminado el escalado de aquí, ya que el SCALER fue
    entrenado para las 771 features combinadas.
    """
    
    categorical_cols = ['From', 'To'] 
    
    df_processed = pd.DataFrame([{
        'From': email_data.From,
        'To': email_data.To,
    }])

    # 1.1. Hora
    hour_temp = extract_time_feature(email_data)
    df_processed['Hour_temp'] = hour_temp
    
    # 1.2. Codificación Categórica (From, To)
    for col in categorical_cols:
        le = label_encoders.get(col)
        if le is None: continue

        input_value = df_processed[col].iloc[0]
        
        # Manejar categorías no vistas (OOD - Out of Distribution)
        if input_value in le.classes_:
            encoded_value = le.transform([input_value])[0]
        else:
            # Asignar un valor seguro (ej. el siguiente índice disponible)
            encoded_value = len(le.classes_) 
            
        df_processed[col] = encoded_value
            
    # Retornar el array de 3 features (1, 3) SIN ESCALAR
    features_to_return = df_processed[categorical_cols + ['Hour_temp']]
    features_array = features_to_return.values 
    
    return features_array


@torch.no_grad()
def generate_bert_embeddings(text: str, tokenizer: BertTokenizer, model: BertModel) -> np.ndarray:
    """
    Genera el embedding CLS usando BERT para un solo texto.
    """
    
    encoded_input = tokenizer(
        text, 
        padding='max_length', 
        truncation=True, 
        max_length=MAX_LENGTH, 
        return_tensors='pt'
    )

    input_ids = encoded_input['input_ids'].to(device)
    attention_mask = encoded_input['attention_mask'].to(device)

    # Uso de autocast para rendimiento (si CUDA está disponible)
    with autocast(enabled=device.type == 'cuda'): 
        outputs = model(input_ids=input_ids, attention_mask=attention_mask)
    
    # El embedding CLS (el primer token) es el resumen de la secuencia
    cls_embedding = outputs.last_hidden_state[:, 0, :].cpu().numpy()
    
    return cls_embedding # Retorna (1, 768)


# =============================================================================
# 3. CARGA DE ARTEFACTOS
# =============================================================================

def load_ml_artifacts():
    """Carga todos los artefactos de ML necesarios al inicio de la API."""
    global MODEL, SCALER, LABEL_ENCODERS, UMBRAL_OPTIMO, TOKENIZER, MODEL_BERT

    try:
        # 1. Cargar Modelo, Escalador y Encoders
        MODEL = joblib.load(MODEL_PATH)
        SCALER = joblib.load(SCALER_PATH)
        LABEL_ENCODERS = joblib.load(ENCODER_PATH)

        # 2. Cargar Umbral Óptimo de Validación
        with open(METRICS_PATH_VALIDATION, 'r') as f:
            metrics = json.load(f)
            # El umbral está anidado en el reporte
            UMBRAL_OPTIMO = metrics.get('final_threshold')
            
        # 3. Cargar BERT Tokenizer y Modelo
        TOKENIZER = BertTokenizer.from_pretrained(BERT_MODEL_NAME)
        MODEL_BERT = BertModel.from_pretrained(BERT_MODEL_NAME).to(device).eval()

        print(f"✅ Artefactos ML cargados. Modelo listo en {device}.")
        print(f"✅ Umbral Óptimo (Final Threshold): {UMBRAL_OPTIMO}")

    except Exception as e:
        print(f"❌ ERROR CRÍTICO al cargar artefactos de ML: {e}")
        # En un entorno de producción, esto debería salir o generar un log de alerta.
        raise RuntimeError("No se pudieron cargar los artefactos de ML. Verifique las rutas y archivos .joblib.")

# Hook de inicialización de FastAPI
@app.on_event("startup")
async def startup_event():
    load_ml_artifacts()


# =============================================================================
# 4. ENDPOINT DE PREDICCIÓN
# =============================================================================

@app.post("/predict")
async def predict_phishing(email_data: EmailData):
    
    # 1. Validación de Artefactos
    if MODEL is None or SCALER is None or UMBRAL_OPTIMO is None:
        raise HTTPException(status_code=503, detail={"status": "ERROR", "message": "Servicio de ML no inicializado. Inténtelo más tarde."})

    try:
        # 2. PREPARACIÓN DE FEATURES
        subject = email_data.Subject or ""
        body = email_data.Body or ""
        text_for_bert = " ".join([subject, body])

        # 2.1. Embeddings BERT (768 features)
        X_bert_embeddings = generate_bert_embeddings(text_for_bert, TOKENIZER, MODEL_BERT) 
        
        # 2.2. Features Adicionales (3 features SIN ESCALAR)
        X_additional_unscaled = preprocess_additional_features(email_data, LABEL_ENCODERS) 
        
        # 3. COMBINACIÓN Y ESCALADO (CORRECCIÓN CLAVE)
        # Combinación Final: BERT (768) + Adicionales (3) -> 771 features (NO ESCALADAS)
        X_combined_unscaled = np.hstack([
            X_bert_embeddings.reshape(1, -1), 
            X_additional_unscaled.reshape(1, -1)
        ]) 
        
        # Aplicación del StandardScaler sobre las 771 features combinadas
        X_final_scaled = SCALER.transform(X_combined_unscaled) 

        # 4. PREDICCIÓN
        pred_prob = MODEL.predict_proba(X_final_scaled)[0]
        prob_phishing = pred_prob[1] # Probabilidad de la clase 1 (Phishing)

        # Aplicación del Umbral Óptimo
        ml_verdict = (
            "Phishing" if prob_phishing >= UMBRAL_OPTIMO else
            "Safe"
        )
        
        malicious_attachments = False # Fijo a False ya que no se procesan adjuntos

        prediction = [{
            "model_prediction": {
                "label": ml_verdict, 
                "malicious_file": malicious_attachments, 
                "probability": convert_to_float(prob_phishing)
            }
        }]

        return {"status": "OK", "predictions": prediction}

    except Exception as e:
        # Log del error en el contenedor
        print(f"Error en la predicción: {e}")
        # Retornar una respuesta JSON con código 500
        raise HTTPException(status_code=500, detail={"status": "ERROR", "message": f"Error interno del servidor: {e}"})

# =============================================================================
# 5. ENDPOINT DE ESTADO
# =============================================================================

@app.get("/health")
def read_root():
    """Endpoint simple para verificar que la API está viva."""
    return {"status": "OK", "message": "Phishing Detection API running."}
