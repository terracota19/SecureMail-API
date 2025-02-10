FROM python:3.11-slim

RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py /app/
COPY XGBoost.pkl /app/

RUN mkdir -p /app/cache && chown -R appuser:appgroup /app
ENV HF_HOME=/app/cache
USER appuser

EXPOSE 10000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "10000"]