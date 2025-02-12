import pytest
from fastapi.testclient import TestClient
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import *

client = TestClient(app)

# Test básico de salud
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


# Fuzzing: Test con campo 'From' vacío
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
    assert response.status_code == 422  # Esperamos un error de validación

# Fuzzing: Test con 'Date' mal formateado
def test_fuzzing_invalid_date():
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": "This is a test email",
        "Date": "invalid-date-format",  # Fecha malformada
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 422  

# Fuzzing: Test con URL muy larga
def test_fuzzing_long_url():
    long_url = "https://" + "a" * 5000 + ".com"  # URL extremadamente larga
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": "This is a test email",
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": long_url,  # URL muy larga
        "Attachments": []
    })
    assert response.status_code == 200  # Verifica que no cause un error de servidor, la app debe manejar esta entrada

# Fuzzing: Test con caracteres especiales
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
    assert response.status_code == 200  # Verificar que caracteres especiales no rompen la API

# Fuzzing: Test con datos excesivamente grandes
def test_fuzzing_large_body():
    large_body = "A" * 10000  # Cuerpo de mensaje muy grande
    response = client.post("/", json={
        "From": "user@example.com",
        "To": "receiver@example.com",
        "Subject": "Hello!",
        "Body": large_body,  # Cuerpo muy grande
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 200  # Verificar que la API maneja entradas grandes sin colapsar

# Fuzzing: Test con campo faltante (None en vez de string)
def test_fuzzing_missing_field():
    response = client.post("/", json={
        "From": "user@example.com",
        "To": None,  # Campo "To" está vacío (None)
        "Subject": "Hello!",
        "Body": "This is a test email",
        "Date": "2024-01-01T12:00:00Z",
        "Concatenated_URLs": "https://example.com",
        "Attachments": []
    })
    assert response.status_code == 422  # Esperamos un error de validación

