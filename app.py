import json
import os
from contextlib import asynccontextmanager

import joblib
import numpy as np
import torch
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from transformers import XLMRobertaModel, XLMRobertaTokenizerFast

load_dotenv()

from auth import TokenData, auth_router, require_scope
from training_compat import build_model_text, transform_additional_features

# =============================================================================
# CONFIGURATION
# =============================================================================

BERT_MODEL_NAME = os.getenv("BERT_MODEL_NAME", "xlm-roberta-base")
MAX_LENGTH = int(os.getenv("MAX_LENGTH", "128"))
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
TORCH_NUM_THREADS = max(1, int(os.getenv("TORCH_NUM_THREADS", "1")))
torch.set_num_threads(TORCH_NUM_THREADS)
if DEVICE.type == "cuda":
    torch.set_float32_matmul_precision("high")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models/best_phishing_model.joblib")
SCALER_PATH = os.path.join(BASE_DIR, "objects/feature_scaler.joblib")
LABEL_ENCODERS_PATH = os.path.join(BASE_DIR, "objects/label_encoders.joblib")
THRESHOLD_MAP_PATH = os.path.join(BASE_DIR, "objects/threshold_map.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "Metrics/validation_metrics.json")

MISSING_VALUE_STR = "No Data"
BERT_SEP_TOKEN = "[SEP]"
ML_ARTIFACTS: dict[str, object] = {}


# =============================================================================
# RESPONSE MODELS: stable contract consumed by the Gmail add-on
# =============================================================================

class EmailInput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    From: str = Field(..., min_length=3, max_length=320)
    To: str = Field(..., min_length=3, max_length=320)
    Subject: str = Field(..., max_length=1000)
    Body: str = Field(..., max_length=50000)
    Date: str = Field(..., max_length=100)
    Concatenated_URLs: str = Field("", max_length=10000)
    MessageId: str = Field(..., min_length=1, max_length=500)


class ModelPrediction(BaseModel):
    label: str
    probability: float = Field(..., ge=0, le=1)


class PredictionItem(BaseModel):
    model_prediction: ModelPrediction


class PredictionResponse(BaseModel):
    status: str
    predictions: list[PredictionItem]
    is_phishing: bool
    probability: float = Field(..., ge=0, le=1)
    threshold: float = Field(..., ge=0, le=1)


# =============================================================================
# LIFECYCLE
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"Starting SecureMail API on {DEVICE.type}...")
    try:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file not found: {MODEL_PATH}")
        for artifact_path in (SCALER_PATH, LABEL_ENCODERS_PATH, THRESHOLD_MAP_PATH):
            if not os.path.exists(artifact_path):
                raise FileNotFoundError(f"Artifact file not found: {artifact_path}")

        ML_ARTIFACTS["model"] = joblib.load(MODEL_PATH)
        ML_ARTIFACTS["scaler"] = joblib.load(SCALER_PATH)
        ML_ARTIFACTS["label_encoders"] = joblib.load(LABEL_ENCODERS_PATH)
        threshold_map = joblib.load(THRESHOLD_MAP_PATH)

        threshold = float(threshold_map.get("R_min_98_P_min_90", 0.85))
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH, encoding="utf-8") as metrics_file:
                threshold = float(json.load(metrics_file).get("final_threshold", threshold))
        ML_ARTIFACTS["threshold"] = max(0.0, min(1.0, threshold))

        ML_ARTIFACTS["tokenizer"] = XLMRobertaTokenizerFast.from_pretrained(BERT_MODEL_NAME)
        model_kwargs = {"low_cpu_mem_usage": True}
        if DEVICE.type == "cuda":
            model_kwargs["torch_dtype"] = torch.float16

        ML_ARTIFACTS["bert"] = (
            XLMRobertaModel.from_pretrained(BERT_MODEL_NAME, **model_kwargs)
            .to(DEVICE)
            .eval()
        )
        print("Models loaded successfully.")
    except Exception as exc:
        ML_ARTIFACTS.clear()
        print(f"CRITICAL STARTUP ERROR: {exc}")
        raise RuntimeError("Failed to initialize models.") from exc

    yield
    ML_ARTIFACTS.clear()


# =============================================================================
# APP AND ENDPOINTS
# =============================================================================

app = FastAPI(
    title="SecureMail Phishing Detection API",
    version="2.1.0",
    lifespan=lifespan,
)
app.include_router(auth_router)

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)


@app.get("/")
def read_root():
    return {"status": "online", "message": "API SecureMail", "version": "2.1.0"}


@app.get("/health/live")
def liveness():
    return {"status": "alive"}


@app.get("/health/ready")
def readiness():
    required = {"model", "scaler", "label_encoders", "threshold", "tokenizer", "bert"}
    if not required.issubset(ML_ARTIFACTS):
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")
    return {"status": "ready", "models_loaded": True}


@app.get("/health")
def health_check():
    ready = {"model", "scaler", "label_encoders", "threshold", "tokenizer", "bert"}.issubset(ML_ARTIFACTS)
    return {"status": "online", "models_loaded": ready}


@app.post("/predict", response_model=PredictionResponse)
async def predict(
    email_data: EmailInput,
    token_data: TokenData = Depends(require_scope("predict")),
):
    del token_data
    required = {"bert", "model", "scaler", "label_encoders", "tokenizer", "threshold"}
    if not required.issubset(ML_ARTIFACTS):
        raise HTTPException(status_code=503, detail="Models are not loaded correctly.")

    try:
        bert_model = ML_ARTIFACTS["bert"]
        tokenizer = ML_ARTIFACTS["tokenizer"]
        scaler = ML_ARTIFACTS["scaler"]
        label_encoders = ML_ARTIFACTS["label_encoders"]
        inputs = tokenizer(
            build_model_text(email_data, separator=BERT_SEP_TOKEN),
            return_tensors="pt",
            padding="max_length",
            truncation=True,
            max_length=MAX_LENGTH,
        ).to(DEVICE)

        with torch.inference_mode():
            outputs = bert_model(**inputs)
            embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()

        x_additional_scaled = transform_additional_features(
            email_data,
            label_encoders=label_encoders,
            scaler=scaler,
        )
        x_final = np.hstack((embeddings.astype(np.float32), x_additional_scaled))

        model = ML_ARTIFACTS["model"]
        expected_features = int(getattr(model, "n_features_in_", x_final.shape[1]))
        if x_final.shape[1] != expected_features:
            raise ValueError(
                f"The model expects {expected_features} features, but inference produced {x_final.shape[1]}."
            )

        if hasattr(model, "predict_proba"):
            probability = float(model.predict_proba(x_final)[0][1])
        else:
            decision = float(model.decision_function(x_final)[0])
            probability = float(1.0 / (1.0 + np.exp(-decision)))

        probability = max(0.0, min(1.0, probability))
        threshold = float(ML_ARTIFACTS["threshold"])
        is_phishing = probability >= threshold
        label = "Phishing" if is_phishing else "Safe"

        return PredictionResponse(
            status="OK",
            predictions=[
                PredictionItem(
                    model_prediction=ModelPrediction(
                        label=label,
                        probability=probability,
                    )
                )
            ],
            is_phishing=is_phishing,
            probability=probability,
            threshold=threshold,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Internal prediction error.") from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
