FROM python:3.11-slim

RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /secure.mail

RUN python -m venv venv

COPY requirements.txt .
RUN . venv/bin/activate && pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY XGBoost.pkl .

RUN mkdir -p /secure.mail/cache && chown -R appuser:appgroup /secure.mail

ENV HF_HOME=/secure.mail/cache

USER appuser

EXPOSE 10000

CMD ["/secure.mail/venv/bin/uvicorn", "app:app", "--host", "0.0.0.0", "--port", "10000"]
