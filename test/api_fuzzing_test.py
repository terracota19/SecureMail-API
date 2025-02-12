import pytest
from fastapi.testclient import TestClient
import sys
import os

# Ajustar la ruta para poder importar desde la carpeta 'app'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
from app import EmailData

client = TestClient(app)

def test_api_health():
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": "This is a test email, not necessarily a phishing attempt",
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 200
    json_data = response.json()
    assert "status" in json_data
    assert json_data["status"] == "OK"
    assert "predictions" in json_data

def test_fuzzing_from_empty():
    response = client.post("/", json={
        "From": "",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": "This is a test email",
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 422

def test_fuzzing_invalid_date():
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": "This is a test email",
        "Date": "invalid-date-format",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 422  

def test_fuzzing_long_url():
    long_url = "https://" + "a" * 5000 + ".com"
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": "This is a test email",
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": long_url,
        "Attachments": []
    })
    assert response.status_code == 200

def test_fuzzing_special_characters():
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": "This is a test email! @#$%^&*()_+",
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 200

def test_fuzzing_large_body():
    large_body = "A" * 10000
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": large_body,
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 200

def test_fuzzing_missing_field():
    response = client.post("/", json={
        "From": "user@example.com",
        "To": None,
        "Subject": "Hello!",
        "Body": "This is a test email",
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 422
