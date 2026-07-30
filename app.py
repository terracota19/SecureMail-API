import os
import gc
import re
import glob
import json
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from time import time

import numpy as np
import pandas as pd
from tqdm import tqdm

import torch
from torch.cuda.amp import autocast
from transformers import XLMRobertaTokenizer, XLMRobertaModel

from sklearn.preprocessing import StandardScaler, LabelEncoder
from category_encoders import HashingEncoder
from sklearn.model_selection import StratifiedKFold, GridSearchCV
from sklearn.metrics import precision_recall_curve, f1_score, classification_report
import joblib

from fastapi import FastAPI

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import config
except ImportError:
    class ConfigDummy:
        MISSING_VALUE_STR = "No Data"
        TARGET_COLUMN = "Phishing"
        TIME_FEATURE = "Hour"
        CATEGORICAL_FEATURES = ["From", "To", "Subject"]
        EXPECTED_PARSED_COLS = ["From", "To", "Subject", "Date", "Body", "Concatenated_URLs", "Phishing"]
        BERT_MODEL_NAME = "xlm-roberta-base"
        DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        BATCH_SIZE = 32
        MAX_LENGTH = 512
        OPTUNA_AVAILABLE = False
    config = ConfigDummy()

def create_concatenated_urls(url_value):
    missing_val_str = config.MISSING_VALUE_STR
    if pd.isna(url_value) or str(url_value).strip().lower() in ['0', '0.0', '', 'nan', 'none']:
        return missing_val_str

    url_str = str(url_value).strip()
    url_str = re.sub(r'\\n|\\r', ' ', url_str)
    url_str = re.sub(r'[\[\]\'"]', '', url_str)
    url_str = re.sub(r'\s+', ' ', url_str).strip()

    if url_str == '1':
        return missing_val_str

    url_str = re.sub(r'(https?://)', r' \1', url_str).strip()
    result = ' '.join(url_str.split())
    return result if result else missing_val_str

def load_and_combine_data(file_paths, expected_cols, target_col, missing_val_str=config.MISSING_VALUE_STR):
    all_data = []

    for file in tqdm(file_paths, desc="Cargando CSVs"):
        try:
            try:
                df = pd.read_csv(file)
            except UnicodeDecodeError:
                df = pd.read_csv(file, encoding='latin1')
            except pd.errors.ParserError:
                df = pd.read_csv(file, encoding='latin1', on_bad_lines='skip')
            all_data.append(df)
        except Exception as e:
            pass

    if not all_data:
        return pd.DataFrame()

    df_combined = pd.concat(all_data, ignore_index=True)
    del all_data
    gc.collect()

    df_combined.columns = df_combined.columns.str.lower().str.replace('sender', 'from').str.replace('receiver', 'to').str.replace('label', 'phish')
    column_mapping = {'subject': 'Subject', 'body': 'Body', 'date': 'Date', 'from': 'From', 'to': 'To', 'phish': target_col, 'urls': 'Original_URLs'}
    df_combined.rename(columns=lambda c: column_mapping.get(c, c), inplace=True)

    for col in expected_cols:
        if col not in df_combined.columns:
            if col == 'urls' and 'Original_URLs' in df_combined.columns:
                continue
            df_combined[col] = 0 if col == target_col else missing_val_str

        if df_combined[col].dtype == object or col != target_col:
            df_combined[col] = df_combined[col].fillna(missing_val_str).astype(str)
        elif col == target_col:
            df_combined[col] = pd.to_numeric(df_combined[col], errors='coerce').fillna(0).astype(np.int8)

    if 'Original_URLs' in df_combined.columns:
        df_combined['Concatenated_URLs'] = df_combined['Original_URLs'].apply(create_concatenated_urls)
        df_combined.drop(columns=['Original_URLs'], inplace=True, errors='ignore')
    elif 'Concatenated_URLs' not in df_combined.columns:
        df_combined['Concatenated_URLs'] = missing_val_str

    final_cols_order = [c for c in config.EXPECTED_PARSED_COLS if c in df_combined.columns]
    df_combined = df_combined[final_cols_order].dropna(subset=[target_col])
    
    return df_combined

def decode_payload(part):
    payload = part.get_payload(decode=True)
    if not payload:
        return ""

    charset = part.get_content_charset()
    fallback_encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252', 'ascii']

    if charset:
        try:
            return payload.decode(charset, errors='replace')
        except (LookupError, UnicodeDecodeError):
            pass

    for encoding in fallback_encodings:
        try:
            return payload.decode(encoding, errors='replace')
        except UnicodeDecodeError:
            continue

    return payload.decode('ascii', errors='replace')

def extract_body_from_eml(msg):
    body_plain, body_html = None, None

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))
            if 'attachment' in content_disposition or not content_type.startswith('text/'):
                continue
            if content_type == 'text/plain' and body_plain is None:
                body_plain = decode_payload(part)
            elif content_type == 'text/html' and body_html is None:
                body_html = decode_payload(part)
    else:
        content_type = msg.get_content_type()
        if content_type == 'text/plain':
            body_plain = decode_payload(msg)
        elif content_type == 'text/html':
            body_html = decode_payload(msg)

    if body_plain:
        return re.sub(r'\s+', ' ', body_plain).strip() or config.MISSING_VALUE_STR
    elif body_html:
        if BS4_AVAILABLE:
            try:
                soup = BeautifulSoup(body_html, 'html.parser')
                return re.sub(r'\s+', ' ', soup.get_text(separator=' ', strip=True)).strip() or config.MISSING_VALUE_STR
            except Exception:
                pass
        return re.sub(r'\s+', ' ', body_html).strip() or config.MISSING_VALUE_STR

    return config.MISSING_VALUE_STR

def parse_eml_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        return {
            'From': re.sub(r'\s+', ' ', str(msg.get('From', config.MISSING_VALUE_STR))).strip(),
            'To': re.sub(r'\s+', ' ', str(msg.get('To', config.MISSING_VALUE_STR))).strip(),
            'Subject': re.sub(r'\s+', ' ', str(msg.get('Subject', config.MISSING_VALUE_STR))).strip(),
            'Date': re.sub(r'\s+', ' ', str(msg.get('Date', config.MISSING_VALUE_STR))).strip(),
            'Body': extract_body_from_eml(msg)
        }
    except Exception as e:
        return None

def extract_urls_from_body_text(body_text):
    if not isinstance(body_text, str) or not body_text:
        return config.MISSING_VALUE_STR

    url_pattern = re.compile(
        r'(?:(?:https?|ftp):\/\/|www\.)'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?(?:[/?]\S*)?', re.IGNORECASE
    )

    urls = url_pattern.findall(body_text)
    valid_urls = []
    for url in urls:
        if url.lower().startswith('www.'):
            url = 'http://' + url
        try:
            parsed = urlparse(url)
            if parsed.scheme in ['http', 'https', 'ftp'] and ('.' in parsed.netloc or parsed.netloc == 'localhost'):
                valid_urls.append(re.sub(r'[.,)\]}>\'"?]+$', '', url.strip()))
        except ValueError:
            continue

    return ' '.join(valid_urls) if valid_urls else config.MISSING_VALUE_STR

def process_eml_directory(dir_path, target_value=1):
    eml_files = glob.glob(os.path.join(dir_path, '**', '*.eml'), recursive=True)
    if not eml_files:
        return pd.DataFrame(columns=config.EXPECTED_PARSED_COLS)

    all_email_data = []
    for file_path in tqdm(eml_files, desc="Parseando EMLs"):
        parsed_data = parse_eml_file(file_path)
        if parsed_data:
            parsed_data[config.TARGET_COLUMN] = target_value
            all_email_data.append(parsed_data)

    if not all_email_data:
        return pd.DataFrame(columns=config.EXPECTED_PARSED_COLS)

    df = pd.DataFrame(all_email_data)
    del all_email_data
    gc.collect()

    df['Concatenated_URLs'] = df['Body'].astype(str).apply(extract_urls_from_body_text)

    for col in config.EXPECTED_PARSED_COLS:
        if col not in df.columns:
            df[col] = 0 if col == config.TARGET_COLUMN else config.MISSING_VALUE_STR
        elif col == config.TARGET_COLUMN:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(np.int8)
        else:
            df[col] = df[col].fillna(config.MISSING_VALUE_STR).astype(str)

    return df[config.EXPECTED_PARSED_COLS]

def extract_time_feature(df):
    df_copy = df.copy()
    if 'Date' in df_copy.columns:
        date_dt = pd.to_datetime(df_copy['Date'], errors='coerce', utc=True)
        df_copy[config.TIME_FEATURE] = date_dt.dt.hour.astype(np.float32).fillna(0.0)
    else:
        df_copy[config.TIME_FEATURE] = 0.0
    return df_copy

def fit_preprocess_additional_features(df_train):
    df_processed = extract_time_feature(df_train)
    label_encoders = {}
    fitted_data_list = []
    feature_names_for_scaler = []

    N_HASH_COMPONENTS = 100
    cols_to_hash = [col for col in config.CATEGORICAL_FEATURES if col in df_processed.columns]

    hasher = HashingEncoder(cols=cols_to_hash, n_components=N_HASH_COMPONENTS, return_df=True)
    df_processed_cat = df_processed[cols_to_hash].astype(str).fillna(config.MISSING_VALUE_STR)
    
    fitted_data_hashed = hasher.fit_transform(df_processed_cat)
    del df_processed_cat
    gc.collect()

    label_encoders['feature_hasher'] = hasher

    if not fitted_data_hashed.empty:
        fitted_data_list.append(fitted_data_hashed.values.astype(np.float32))
        feature_names_for_scaler.extend(list(fitted_data_hashed.columns))
        del fitted_data_hashed

    if config.TIME_FEATURE in df_processed.columns:
        time_vals = df_processed[[config.TIME_FEATURE]].fillna(0).values.astype(np.float32)
        fitted_data_list.append(time_vals)
        feature_names_for_scaler.append(config.TIME_FEATURE)

    target_encoder = LabelEncoder()
    target_encoder.fit(df_train[config.TARGET_COLUMN].values)
    label_encoders['target_encoder'] = target_encoder

    features_to_scale = np.hstack(fitted_data_list)
    del fitted_data_list
    gc.collect()

    scaler = StandardScaler()
    scaled_data = scaler.fit_transform(features_to_scale).astype(np.float32)
    scaler.feature_names_in_ = np.array(feature_names_for_scaler, dtype=object)

    return scaled_data, label_encoders, scaler

def transform_preprocess_additional_features(df, label_encoders, scaler):
    df_processed = extract_time_feature(df)
    hasher = label_encoders['feature_hasher']
    cols_to_hash = [col for col in config.CATEGORICAL_FEATURES if col in df_processed.columns]
    num_hash_cols_expected = len([f for f in scaler.feature_names_in_ if str(f).startswith('col_')])

    if not cols_to_hash:
        transformed_data_hashed_values = np.zeros((len(df_processed), num_hash_cols_expected), dtype=np.float32)
    else:
        df_processed_cat = df_processed[cols_to_hash].astype(str).fillna(config.MISSING_VALUE_STR)
        transformed_data_hashed = hasher.transform(df_processed_cat)
        transformed_data_hashed_values = transformed_data_hashed.values.astype(np.float32)
        del df_processed_cat, transformed_data_hashed
        gc.collect()

        if transformed_data_hashed_values.shape[1] < num_hash_cols_expected:
            pad = num_hash_cols_expected - transformed_data_hashed_values.shape[1]
            transformed_data_hashed_values = np.pad(transformed_data_hashed_values, ((0, 0), (0, pad)))
        else:
            transformed_data_hashed_values = transformed_data_hashed_values[:, :num_hash_cols_expected]

    features_list = [transformed_data_hashed_values]

    if config.TIME_FEATURE in scaler.feature_names_in_:
        if config.TIME_FEATURE in df_processed.columns:
            time_vals = df_processed[[config.TIME_FEATURE]].fillna(0).values.astype(np.float32)
        else:
            time_vals = np.zeros((len(df_processed), 1), dtype=np.float32)
        features_list.append(time_vals)

    features_to_scale = np.hstack(features_list)
    return scaler.transform(features_to_scale).astype(np.float32)

def set_dynamic_model_weights(y_train, models_tune, models_no_tune):
    counts = np.bincount(y_train)
    xgb_scale_weight = float(counts[0] / counts[1]) if len(counts) > 1 and counts[1] > 0 else 1.0

    for model_dict in [models_tune, models_no_tune]:
        if 'XGBoost' in model_dict:
            try:
                model_dict['XGBoost'].set_params(scale_pos_weight=xgb_scale_weight)
            except Exception as e:
                pass

def get_bert_model_and_tokenizer():
    tokenizer = XLMRobertaTokenizer.from_pretrained(config.BERT_MODEL_NAME)
    model = XLMRobertaModel.from_pretrained(config.BERT_MODEL_NAME)
    model.to(config.DEVICE)
    model.eval()
    return tokenizer, model

def generate_bert_embeddings(texts, tokenizer, model):
    if not texts:
        return np.empty((0, 768), dtype=np.float32)

    embeddings = []
    use_cuda = config.DEVICE.type == 'cuda'
    dtype = torch.float16 if use_cuda else torch.float32

    with torch.no_grad():
        with autocast(enabled=use_cuda, dtype=dtype):
            for i in tqdm(range(0, len(texts), config.BATCH_SIZE), desc="Generando Embeddings"):
                batch_texts = [str(t) for t in texts[i:i + config.BATCH_SIZE]]
                
                encoded = tokenizer.batch_encode_plus(
                    batch_texts,
                    padding=True,
                    truncation=True,
                    max_length=config.MAX_LENGTH,
                    return_tensors='pt'
                ).to(config.DEVICE)

                outputs = model(**encoded)
                
                mask = encoded['attention_mask'].unsqueeze(-1).expand(outputs.last_hidden_state.size()).float()
                sum_emb = torch.sum(outputs.last_hidden_state * mask, 1)
                sum_mask = torch.clamp(mask.sum(1), min=1e-9)
                mean_pooled = (sum_emb / sum_mask).cpu().numpy().astype(np.float32)

                embeddings.append(mean_pooled)

                del encoded, outputs, mask, sum_emb, sum_mask
                if use_cuda:
                    torch.cuda.empty_cache()

    final_embeddings = np.vstack(embeddings)
    del embeddings
    gc.collect()
    
    return final_embeddings

app = FastAPI(title="SecureMail Phishing Detection API", version="1.0")

@app.get("/")
def read_root():
    return {"status": "online", "message": "API de detección de phishing activa"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
