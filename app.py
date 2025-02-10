import os
import base64
import aiohttp
import joblib
import numpy as np
import torch
import pandas as pd
from dotenv import load_dotenv
from urllib.parse import urlparse
from transformers import DistilBertTokenizer, DistilBertModel
from sklearn.preprocessing import StandardScaler
from typing import Optional, List
from pydantic import BaseModel, EmailStr
from fastapi import FastAPI, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

# Cargar variables de entorno y modelo
load_dotenv()
app = FastAPI()
 
# Configuración de `slowapi` para limitar solicitudes
limiter = Limiter(key_func = get_remote_address)
app.state.limiter = limiter

# Configuración de DistilBERT
tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
model_bert = DistilBertModel.from_pretrained('distilbert-base-uncased')
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model_bert.to(device)

# Variables de entorno
HYBRID_ANALYSIS_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY")
HYBRID_ANALYSIS_API_URL = os.getenv("HYBRID_ANALYSIS_API_URL")
ML_MODEL_NAME_URI = os.getenv("ML_MODEL_NAME_URI")

model = joblib.load(ML_MODEL_NAME_URI) 


#Validación de datos de entrada de usuario
class EmailData(BaseModel):
    From: EmailStr
    To: EmailStr
    Subject: str
    Body: str
    Date: str
    Concatenated_URLs: Optional[str] = "No Data"
    Attachments: Optional[List[dict]] 



def process_urls(urls):
    if urls == "No Data" or not isinstance(urls, str):
        return pd.Series({
            'domain_length_avg': 0,
            'url_length_avg': 0,
            'subdomains_avg': 0,
            'is_https_avg': 0,
            'total_urls': 0,
        })

    url_list = urls.split()
    domain_lengths, url_lengths, subdomains, https_indicators = [], [], [], []

    for single_url in url_list:
        try:
            parsed = urlparse(single_url)
            domain = parsed.netloc
            domain_lengths.append(len(domain))
            url_lengths.append(len(single_url))
            subdomains.append(domain.count('.'))
            https_indicators.append(1 if parsed.scheme == 'https' else 0)
        except Exception:
            continue

    return pd.Series({
        'domain_length_avg': np.mean(domain_lengths) if domain_lengths else 0,
        'url_length_avg': np.mean(url_lengths) if url_lengths else 0,
        'subdomains_avg': np.mean(subdomains) if subdomains else 0,
        'is_https_avg': np.mean(https_indicators) if https_indicators else 0,
        'total_urls': len(url_list),
    })

def encode_frequency(data, cols):
    for col in cols:
        freq = data[col].value_counts(normalize=True)
        data[col] = data[col].map(freq)
    return data

def extract_time_features(data):
    data['Date'] = pd.to_datetime(data['Date'], errors='coerce', utc=True)
    data['Month'] = data['Date'].dt.month
    data['Hour'] = data['Date'].dt.hour
    data['DayOfWeek'] = data['Date'].dt.dayofweek
    data = data.drop(columns=['Date'])
    return data

def preprocess_additional_features(data):
    data = encode_frequency(data, ['From', 'To'])
    data = extract_time_features(data)
    processed_data = data[['From', 'To', 'Month', 'Hour', 'DayOfWeek']]
    scaler = StandardScaler()
    processed_data = scaler.fit_transform(processed_data)
    return processed_data

def convert_to_float(obj):
    if isinstance(obj, np.generic):  
        return obj.item()  
    return obj

def generate_distilbert_embeddings(texts, tokenizer, model, max_length=512, batch_size=8):
    model.eval()
    embeddings = []
    with torch.no_grad():
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            encoded = tokenizer(batch, padding=True, truncation=True, max_length=max_length, return_tensors='pt')
            encoded = {k: v.to(device) for k, v in encoded.items()}
            outputs = model(**encoded)
            cls_embeddings = outputs.last_hidden_state[:, 0, :].cpu()
            embeddings.append(cls_embeddings.numpy())
            torch.cuda.empty_cache()
    return np.vstack(embeddings)

async def analyze_attachment(attachment: str):
    try:
        file_data = base64.b64decode(attachment)

        async with aiohttp.ClientSession() as session:
            form_data = aiohttp.FormData()
            form_data.add_field("file", file_data, filename="attachment", content_type="application/octet-stream")
            form_data.add_field("environment_id", "160")  

            async with session.post(
                f"{HYBRID_ANALYSIS_API_URL}/submit/file",
                headers={"accept": "application/json", "api-key": HYBRID_ANALYSIS_API_KEY},
                data=form_data
            ) as response:
                if response.status == 201:
                    response_json = await response.json()
                    sha256 = response_json.get("sha256")
                    if sha256:
                        
                        summary_url = f"{HYBRID_ANALYSIS_API_URL}/report/{sha256}:160/summary"
                        async with session.get(
                            summary_url,
                            headers={"accept": "application/json", "api-key": HYBRID_ANALYSIS_API_KEY}
                        ) as summary_response:
                            if summary_response.status == 200:
                                return await summary_response.json()
                            else:
                                return {
                                    "verdict": "unknown",
                                    "detail": f"Failed to retrieve summary: {summary_response.status}"
                                }
                    else:
                        return {"verdict": "unknown", "detail": "Failed to retrieve analysis ID"}
                else:
                    return {"verdict": "unknown", "detail": f"Failed to submit file: {response.status}"}

    except Exception as e:
        return {"verdict": "unknown", "detail": str(e)}


# Endpoint Principal -- Limitar a 5 por minuto para evitar ataques de denegación de servicio DDOS O DOS con slowapi.limiter.
@app.post("/")
@limiter.limit("5 per minute")
async def predict_emails(email: EmailData, request: Request):
    try:
        prediction = None
        
        additional_features = preprocess_additional_features(pd.DataFrame([email.dict()]))

        urls_features = process_urls(email.Concatenated_URLs)

        text_data = [" ".join([email.Subject, email.Body])]
        text_embeddings = generate_distilbert_embeddings(text_data, tokenizer, model_bert)

        X_combined = np.hstack([text_embeddings, additional_features, urls_features.values.reshape(1, -1)])

        pred_prob = model.predict_proba(X_combined)[0]
        pred_label = model.predict(X_combined)[0]

        attachment_results = []
        malicious_attachments = False  

        if email.Attachments != ["No Data"]:
            for attachment in email.Attachments:
                analysis = await analyze_attachment(attachment)
                attachment_results.append(analysis)

            malicious_attachments = any(
                result.get("verdict") == "malicious" for result in attachment_results if "verdict" in result
            )

        ml_verdict = (
            "Phishing" if pred_label == 1 else
            "Not Phishing"
        )

        prediction = [{
            "model_prediction": {"label": ml_verdict, "malicious_file" : malicious_attachments , "probability": convert_to_float(pred_prob[1])}
        }]

        return {"status": "OK", "predictions": prediction}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar los datos: {str(e)}")
