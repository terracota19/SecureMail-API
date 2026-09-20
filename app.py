import json
import os
import re
from contextlib import asynccontextmanager
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import torch
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from transformers import XLMRobertaModel, XLMRobertaTokenizer

from auth import TokenData, auth_router, require_scope

load_dotenv()

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
PIPELINE_PATH = os.path.join(BASE_DIR, "objects/feature_scaler.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "Metrics/validation_metrics.json")

MISSING_VALUE_STR = "No Data"
BERT_SEP_TOKEN = "[SEP]"
ML_ARTIFACTS: dict[str, object] = {}


def engineer_detailed_features(df_input: pd.DataFrame) -> pd.DataFrame:
    df_eng = df_input.copy()

    for col in ["Subject", "Body", "From", "Concatenated_URLs", "Date"]:
        if col not in df_eng:
            df_eng[col] = MISSING_VALUE_STR
        df_eng[col] = df_eng[col].fillna(MISSING_VALUE_STR).astype(str)

    df_eng["subject_perc_caps"] = df_eng["Subject"].apply(
        lambda x: sum(1 for c in x if c.isupper()) / (len(x) + 1e-6)
    )
    df_eng["subject_kw_urgent"] = df_eng["Subject"].str.contains(
        r"urgent|important|importante", case=False, regex=True
    ).astype(int)

    df_eng["body_num_words"] = df_eng["Body"].apply(lambda x: len(x.split()))
    df_eng["body_num_unique_words"] = df_eng["Body"].apply(
        lambda x: len(set(x.split()))
    )
    df_eng["body_perc_caps"] = df_eng["Body"].apply(
        lambda x: sum(1 for c in x if c.isupper()) / (len(x) + 1e-6)
    )
    df_eng["body_kw_sensitive"] = df_eng["Body"].str.contains(
        r"password|account|verify|bank|ssn|confidential", case=False, regex=True
    ).astype(int)
    df_eng["Saludo_Generico"] = df_eng["Body"].str.contains(
        r"Dear user|Dear customer|Dear account holder", case=False, regex=True
    ).astype(int)

    richness = df_eng["body_num_unique_words"] / (df_eng["body_num_words"] + 1e-6)
    df_eng["body_richness_category"] = pd.cut(
        richness,
        bins=[-1, 0.3, 0.7, 999],
        labels=["Low", "Medium", "High"],
        right=False,
    ).astype(str).fillna("Low")

    def get_domain(sender: str) -> str:
        if "@" not in sender:
            return MISSING_VALUE_STR
        match = re.search(r"@([\w.-]+)", sender)
        return match.group(1) if match else MISSING_VALUE_STR

    df_eng["from_domain"] = df_eng["From"].apply(get_domain)
    df_eng["from_num_subdomains"] = df_eng["from_domain"].apply(
        lambda x: max(0, x.count(".") - 1) if x != MISSING_VALUE_STR else 0
    )
    common_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
    df_eng["from_is_common_domain"] = df_eng["from_domain"].isin(common_domains).astype(int)

    def get_urls_list(text: str) -> list[str]:
        if text == MISSING_VALUE_STR or not text.strip():
            return []
        return re.split(r"[,\s]+", text.strip())

    df_eng["url_list"] = df_eng["Concatenated_URLs"].apply(get_urls_list)
    df_eng["url_count"] = df_eng["url_list"].apply(
        lambda urls: len([url for url in urls if len(url) > 1])
    )
    df_eng["url_has_ip"] = df_eng["Concatenated_URLs"].str.contains(
        r"https?://\d{1,3}(?:\.\d{1,3}){3}", regex=True
    ).astype(int)
    df_eng["url_has_at"] = df_eng["Concatenated_URLs"].str.contains(r"@", regex=True).astype(int)
    df_eng["url_has_exe"] = df_eng["Concatenated_URLs"].str.contains(
        r"\.exe", case=False, regex=True
    ).astype(int)

    def avg_subdomains(urls: list[str]) -> float:
        values = []
        for url_string in urls:
            if len(url_string) < 5:
                continue
            try:
                hostname = urlparse(url_string).hostname
                if hostname:
                    values.append(max(0, hostname.count(".") - 1))
            except ValueError:
                continue
        return float(np.mean(values)) if values else 0.0

    def avg_path_len(urls: list[str]) -> float:
        values = []
        for url_string in urls:
            if len(url_string) < 5:
                continue
            try:
                path = urlparse(url_string).path
                if path:
                    values.append(len(path))
            except ValueError:
                continue
        return float(np.mean(values)) if values else 0.0

    df_eng["url_avg_subdomains"] = df_eng["url_list"].apply(avg_subdomains)
    df_eng["url_avg_path_len"] = df_eng["url_list"].apply(avg_path_len)
    df_eng["Date_dt"] = pd.to_datetime(df_eng["Date"], errors="coerce", utc=True)
    df_eng["Hour"] = df_eng["Date_dt"].dt.hour.fillna(0).astype(float)

    df_eng.replace([np.inf, -np.inf], 0, inplace=True)
    df_eng.fillna(0, inplace=True)
    return df_eng


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
        if not os.path.exists(PIPELINE_PATH):
            raise FileNotFoundError(f"Pipeline file not found: {PIPELINE_PATH}")

        ML_ARTIFACTS["model"] = joblib.load(MODEL_PATH)
        ML_ARTIFACTS["pipeline"] = joblib.load(PIPELINE_PATH)

        threshold = 0.5
        if os.path.exists(METRICS_PATH):
            with open(METRICS_PATH, encoding="utf-8") as metrics_file:
                threshold = float(json.load(metrics_file).get("final_threshold", 0.5))
        ML_ARTIFACTS["threshold"] = max(0.0, min(1.0, threshold))

        ML_ARTIFACTS["tokenizer"] = XLMRobertaTokenizer.from_pretrained(BERT_MODEL_NAME)
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
    required = {"model", "pipeline", "threshold", "tokenizer", "bert"}
    if not required.issubset(ML_ARTIFACTS):
        raise HTTPException(status_code=503, detail="Models are not loaded yet.")
    return {"status": "ready", "models_loaded": True}


@app.get("/health")
def health_check():
    ready = {"model", "pipeline", "threshold", "tokenizer", "bert"}.issubset(ML_ARTIFACTS)
    return {"status": "online", "models_loaded": ready}


@app.post("/predict", response_model=PredictionResponse)
async def predict(
    email_data: EmailInput,
    token_data: TokenData = Depends(require_scope("predict")),
):
    del token_data
    required = {"bert", "model", "pipeline", "tokenizer", "threshold"}
    if not required.issubset(ML_ARTIFACTS):
        raise HTTPException(status_code=503, detail="Models are not loaded correctly.")

    try:
        bert_model = ML_ARTIFACTS["bert"]
        tokenizer = ML_ARTIFACTS["tokenizer"]
        inputs = tokenizer(
            f"{email_data.Subject} {BERT_SEP_TOKEN} {email_data.Body}",
            return_tensors="pt",
            truncation=True,
            max_length=MAX_LENGTH,
        ).to(DEVICE)

        with torch.inference_mode():
            outputs = bert_model(**inputs)
            embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()

        input_dict = {
            "From": [email_data.From],
            "To": [email_data.To],
            "Subject": [email_data.Subject],
            "Body": [email_data.Body],
            "Date": [email_data.Date],
            "Concatenated_URLs": [email_data.Concatenated_URLs],
            "MessageId": [email_data.MessageId],
        }
        df_features = engineer_detailed_features(pd.DataFrame(input_dict))
        pipeline = ML_ARTIFACTS["pipeline"]
        numeric_cols = list(pipeline.feature_names_in_)
        x_tabular_scaled = pipeline.transform(df_features[numeric_cols])
        x_final = np.hstack((embeddings, x_tabular_scaled))

        model = ML_ARTIFACTS["model"]
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
