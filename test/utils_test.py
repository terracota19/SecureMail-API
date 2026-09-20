import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-with-at-least-32-characters")
os.environ.setdefault("AUTHORIZED_CLIENTS", "gmail_addon:$2b$12$abcdefghijklmnopqrstuu")

import pytest
from pydantic import ValidationError

from app import EmailInput


def test_email_input_rejects_oversized_body():
    with pytest.raises(ValidationError):
        EmailInput(
            From="sender@example.com",
            To="receiver@example.com",
            Subject="Test",
            Body="x" * 50001,
            Date="2026-09-20T12:00:00Z",
            MessageId="message-1",
        )


def test_email_input_ignores_unknown_fields():
    payload = EmailInput(
        From="sender@example.com",
        To="receiver@example.com",
        Subject="Test",
        Body="Body",
        Date="2026-09-20T12:00:00Z",
        MessageId="message-1",
        Attachments=[],
    )
    assert not hasattr(payload, "Attachments")
