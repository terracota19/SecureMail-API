FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    VECLIB_MAXIMUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    TOKENIZERS_PARALLELISM=false \
    HF_HOME=/secure.mail/cache

RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /secure.mail

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Empaquetar el modelo en la imagen evita descargas durante el arranque.
RUN mkdir -p /secure.mail/cache
COPY download_model.py .
RUN python download_model.py

COPY app.py .
COPY auth.py .
COPY utils.py .
COPY models/ ./models/
COPY objects/ ./objects/
COPY Metrics/ ./Metrics/

RUN chown -R appuser:appgroup /secure.mail
USER appuser

EXPOSE 10000

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --limit-concurrency ${LIMIT_CONCURRENCY:-1}"]
