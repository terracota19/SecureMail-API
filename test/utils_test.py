import pytest
import pandas as pd
import numpy as np
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import process_urls, preprocess_additional_features

def test_process_urls():
    urls = "https://example.com https://test.com"
    result = process_urls(urls)

    assert isinstance(result, pd.Series)
    assert result['total_urls'] == 2
    assert result['is_https_avg'] == 1.0

def test_process_urls_no_data():
    result = process_urls("No Data")

    assert isinstance(result, pd.Series)
    assert result['total_urls'] == 0
    assert result['is_https_avg'] == 0.0

def test_preprocess_additional_features():
    data = pd.DataFrame([{
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Date": "2024-01-01T12:00:00Z"
    }])

    processed_data = preprocess_additional_features(data)
    
    assert processed_data.shape[1] == 5  # Asegurar que hay 5 columnas después del preprocesamiento
    assert isinstance(processed_data, np.ndarray)  # Debe ser un array de NumPy
