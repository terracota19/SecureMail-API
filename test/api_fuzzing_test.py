import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-characters")
os.environ.setdefault("AUTHORIZED_CLIENTS", "gmail_addon:$2b$12$abcdefghijklmnopqrstuu")

from app import EmailInput, PredictionResponse


def test_email_input_accepts_gmail_payload():
    payload = EmailInput(
        From="sender@example.com",
        To="receiver@example.com",
        Subject="Test message",
        Body="This is a test email.",
        Date="2026-09-20T12:00:00Z",
        Concatenated_URLs="https://example.com",
        MessageId="message-1",
    )
    assert payload.MessageId == "message-1"


def test_gmail_response_contract():
    response = PredictionResponse.model_validate(
        {
            "status": "OK",
            "predictions": [
                {"model_prediction": {"label": "Phishing", "probability": 0.91}}
            ],
            "is_phishing": True,
            "probability": 0.91,
            "threshold": 0.5,
        }
    )
    assert response.status == "OK"
    assert response.predictions[0].model_prediction.label == "Phishing"
    assert 0 <= response.predictions[0].model_prediction.probability <= 1
