import os
import torch

# 1. Dispositivo de ejecución (CPU en Render para controlar la RAM)
DEVICE = torch.device("cpu")

# 2. Verificación de Optuna
try:
    import optuna
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False

# 3. Configuración de Modelos y Textos
BERT_MODEL_NAME = "xlm-roberta-base"
BERT_SEP_TOKEN = "</s>"
MAX_LENGTH = 128
BATCH_SIZE = 16

# 4. Definición de Columnas y Metadatos
TARGET_COLUMN = "label"
MISSING_VALUE_STR = "No Data"
TIME_FEATURE = "time_feature"

TEXT_COLUMNS_FOR_BERT = ["Subject", "Body", "Concatenated_URLs"]
CATEGORICAL_FEATURES = ["From", "To", "Subject", "Concatenated_URLs", "MessageId"]

EXPECTED_CSV_COLS = ["From", "To", "Subject", "Body", "Date", "urls", TARGET_COLUMN]
EXPECTED_PARSED_COLS = ["From", "To", "Subject", "Body", "Date", "Concatenated_URLs", TARGET_COLUMN]

# 5. Rutas de Artefactos dentro del contenedor Docker (/secure.mail)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODELS_DIR = os.getenv("MODELS_DIR", os.path.join(BASE_DIR, "models"))
OBJECTS_DIR = os.getenv("OBJECTS_DIR", os.path.join(BASE_DIR, "objects"))

BEST_MODEL_PATH = os.path.join(MODELS_DIR, "best_phishing_model.joblib")
HYBRID_BEST_MODEL_PATH = os.path.join(MODELS_DIR, "hybrid_best_model.pth")

SCALER_PATH = os.path.join(OBJECTS_DIR, "feature_scaler.joblib")
ENCODERS_PATH = os.path.join(OBJECTS_DIR, "label_encoders.joblib")
THRESHOLD_MAP_PATH = os.path.join(OBJECTS_DIR, "thresholds_map.joblib")
