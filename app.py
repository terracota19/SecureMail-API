
import re

import joblib
import numpy as np
import torch
import pandas as pd
import json 
from dotenv import load_dotenv
from urllib.parse import urlparse 
from transformers import XLMRobertaTokenizer, XLMRobertaModel
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from torch.cuda.amp import autocast 
from datetime import datetime
from typing import Dict, Any, Union
from sklearn.preprocessing import StandardScaler
from category_encoders import HashingEncoder

# =============================================================================
# 0. CONFIGURACIÓN Y ARTEFACTOS 
# =============================================================================

# Constantes de BERT
BERT_MODEL_NAME = 'xlm-roberta-base'
MAX_LENGTH = 128 
EMBEDDING_DIM = 768 

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

MISSING_VALUE_STR = 'No Data'
CATEGORICAL_FEATURES = ['From', 'To']
TIME_FEATURE = 'Hour_temp'
BERT_SEP_TOKEN = '[SEP]'

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

def extract_time_feature(df):
    """Extrae la hora (0-23) del campo 'Date' y devuelve el DF."""
    df_copy = df.copy()
    if 'Date' in df_copy.columns:
        print("   ... (extract_time_feature) Parseando 'Date' con pd.to_datetime...")
        # Asegurar que el formato ISO 8601 de la API sea manejado correctamente
        df_copy['Date_dt'] = pd.to_datetime(df_copy['Date'], errors='coerce', utc=True)
        
        df_copy[TIME_FEATURE] = df_copy['Date_dt'].dt.hour.astype(float).fillna(0)
        df_copy.drop(columns=['Date_dt'], inplace=True, errors='ignore') 
        print(f"   ... (extract_time_feature) '{TIME_FEATURE}' creada.")
    else:
        print("⚠️ Columna 'Date' no encontrada. Creando feature de hora con ceros.")
        df_copy[TIME_FEATURE] = 0.0
    return df_copy

def transform_preprocess_additional_features(df, label_encoders, scaler):
    """
    Aplica preprocesadores (Hashing, Time, Scaling) ya ajustados a nuevos datos.
    """
    import numpy as np
    import pandas as pd
    
    print("--- (transform_preprocess) 1. Llamando a extract_time_feature ---")
    df_processed = extract_time_feature(df) 
    
    hasher = label_encoders['feature_hasher']
    
    cols_to_hash = [col for col in CATEGORICAL_FEATURES if col in df_processed.columns]
    
    num_hash_cols_expected = len([f for f in scaler.feature_names_in_ if f.startswith('col_')])
    
    if not cols_to_hash:
        print(f"   ... (transform_preprocess) ⚠️ No se encontraron columnas categóricas. Creando {num_hash_cols_expected} columnas de ceros.")
        transformed_data_hashed_values = np.zeros((len(df_processed), num_hash_cols_expected))
    else:
        print(f"   ... (transform_preprocess) 2. Aplicando HashingEncoder (transform) a {cols_to_hash} ---")
        df_processed_cat = df_processed[cols_to_hash].astype(str).fillna(MISSING_VALUE_STR)
        transformed_data_hashed = hasher.transform(df_processed_cat)
        transformed_data_hashed_values = transformed_data_hashed.values
        
        if transformed_data_hashed_values.shape[1] != num_hash_cols_expected:
            print(f"   ... (transform_preprocess) ❌ ERROR: Hasher generó {transformed_data_hashed_values.shape[1]} cols, Scaler espera {num_hash_cols_expected}.")
            if transformed_data_hashed_values.shape[1] < num_hash_cols_expected:
                 pad_width = num_hash_cols_expected - transformed_data_hashed_values.shape[1]
                 transformed_data_hashed_values = np.pad(transformed_data_hashed_values, ((0,0), (0, pad_width)), 'constant', constant_values=0)
                 print(f"   ... (transform_preprocess) ✅ Ajustado (padding) a {num_hash_cols_expected} cols.")
            else:
                 transformed_data_hashed_values = transformed_data_hashed_values[:, :num_hash_cols_expected]
                 print(f"   ... (transform_preprocess) ✅ Ajustado (truncado) a {num_hash_cols_expected} cols.")


    time_values = None
    if TIME_FEATURE in scaler.feature_names_in_:
        if TIME_FEATURE in df_processed.columns:
            print(f"   ... (transform_preprocess) 3. Obteniendo feature '{TIME_FEATURE}' ---")
            time_values = df_processed[[TIME_FEATURE]].fillna(0).values
        else:
            print(f"   ... (transform_preprocess) ⚠️ Columna '{TIME_FEATURE}' no encontrada. Usando ceros.")
            time_values = np.zeros((len(df_processed), 1))
    
    print("   ... (transform_preprocess) 4. Combinando (hstack) features para scaler ---")
    features_to_scale_list = []
    
    features_to_scale_list.append(transformed_data_hashed_values)
    
    if time_values is not None:
         features_to_scale_list.append(time_values)
    
    if not features_to_scale_list:
         print("   ... (transform_preprocess) ❌ No hay features para escalar.")
         return np.array([]).reshape(len(df_processed), 0)

    features_to_scale = np.hstack(features_to_scale_list).astype(float)
    
    print("   ... (transform_preprocess) 5. Aplicando StandardScaler (transform) ---")
    
    if features_to_scale.shape[1] != len(scaler.feature_names_in_):
         print(f"   ... (transform_preprocess) ❌ ERROR DE DIMENSIÓN FINAL: Datos tienen {features_to_scale.shape[1]} features, Scaler espera {len(scaler.feature_names_in_)}.")
         print(f"   ... Scaler espera: {scaler.feature_names_in_}")
         raise ValueError(f"Inconsistencia de features: se generaron {features_to_scale.shape[1]} features, pero el scaler fue ajustado con {len(scaler.feature_names_in_)}")

    scaled_data = scaler.transform(features_to_scale)
    print("   ... (transform_preprocess) 6. transform_preprocess completado ---")
    return scaled_data 


@torch.no_grad()
def generate_bert_embeddings(text: str) -> np.ndarray:
    """
    Genera el embedding CLS usando BERT (XLM-Roberta) para un solo texto.
    """
    
    encoded_input = TOKENIZER( # Usa el TOKENIZER global
        text, 
        padding='max_length', 
        truncation=True, 
        max_length=MAX_LENGTH, 
        return_tensors='pt',
        add_special_tokens=True
    )

    input_ids = encoded_input['input_ids'].to(device)
    attention_mask = encoded_input['attention_mask'].to(device)

    # Uso de autocast para rendimiento (si CUDA está disponible)
    with autocast(enabled=device.type == 'cuda'): 
        outputs = MODEL_BERT(input_ids=input_ids, attention_mask=attention_mask) # Usa el MODEL_BERT global
    
    # Usar last_hidden_state[:, 0, :] para el CLS token, igual que en el pre-cálculo
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
            # El umbral está en el nivel superior del JSON
            UMBRAL_OPTIMO = metrics.get('final_threshold')
            if UMBRAL_OPTIMO is None:
                print(f"⚠️ 'final_threshold' no encontrado, usando 0.5 por defecto.")
                UMBRAL_OPTIMO = 0.5
            
        # 3. Cargar BERT Tokenizer y Modelo (Corregido a XLM-Roberta)
        TOKENIZER = XLMRobertaTokenizer.from_pretrained(BERT_MODEL_NAME)
        MODEL_BERT = XLMRobertaModel.from_pretrained(BERT_MODEL_NAME).to(device).eval()

        print(f"✅ Artefactos ML cargados. Modelo listo en {device}.")
        print(f"✅ Umbral Óptimo (Final Threshold): {UMBRAL_OPTIMO}")

    except Exception as e:
        print(f"❌ ERROR CRÍTICO al cargar artefactos de ML: {e}")
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
    if MODEL is None or SCALER is None or UMBRAL_OPTIMO is None or LABEL_ENCODERS is None:
        raise HTTPException(status_code=503, detail={"status": "ERROR", "message": "Servicio de ML no inicializado. Inténtelo más tarde."})

    try:
        # 2. PREPARACIÓN DE FEATURES (LÓGICA CORRECTA)

        text_for_bert = (
            f"{email_data.Subject or MISSING_VALUE_STR} {BERT_SEP_TOKEN} "
            f"{email_data.Body or MISSING_VALUE_STR} {BERT_SEP_TOKEN} "
            f"{email_data.Concatenated_URLs or MISSING_VALUE_STR}"
        )
        
        X_bert_embeddings = generate_bert_embeddings(text_for_bert) # (1, 768)
        
        df_input = pd.DataFrame([email_data.dict()])
        
        X_additional_scaled = transform_preprocess_additional_features(
            df_input, LABEL_ENCODERS, SCALER
        ) # (1, 101)

        X_final_combined = np.hstack([
            X_bert_embeddings.reshape(1, -1), 
            X_additional_scaled.reshape(1, -1)
        ])

        pred_prob = MODEL.predict_proba(X_final_combined)[0]
        prob_phishing = pred_prob[1] # Probabilidad de la clase 1 (Phishing)

        ml_verdict = "Phishing" if prob_phishing >= UMBRAL_OPTIMO else "Safe"
        
        malicious_attachments = False # Fijo a False

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
        import traceback
        traceback.print_exc() # Imprime el stack trace completo para depuración
        # Retornar una respuesta JSON con código 500
        raise HTTPException(status_code=500, detail={"status": "ERROR", "message": f"Error interno del servidor: {e}"})
    
# =============================================================================
# 5. ENDPOINT DE ESTADO
# =============================================================================

@app.get("/health")
def read_root():
    """Endpoint simple para verificar que la API está viva."""
    return {"status": "OK", "message": "Phishing Detection API running."}