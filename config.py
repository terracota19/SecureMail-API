# config.py
import os
import torch

# Dispositivo de ejecución (CPU en Render)
DEVICE = torch.device("cpu")

# Columnas y separadores
TARGET_COLUMN = "label"
TEXT_COLUMNS_FOR_BERT = ["Subject", "Body", "Concatenated_URLs"]
BERT_SEP_TOKEN = "[SEP]"

# Rutas de artefactos dentro del contenedor Render
MODELS_DIR = os.getenv("MODELS_DIR", "/secure.mail/models")
OBJECTS_DIR = os.getenv("OBJECTS_DIR", "/secure.mail/objects")
SCALER_PATH = os.path.join(OBJECTS_DIR, "feature_scaler.joblib")
ENCODERS_PATH = os.path.join(OBJECTS_DIR, "label_encoders.joblib")
