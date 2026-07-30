FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HF_HOME=/secure.mail/.cache/huggingface \
    TRANSFORMERS_CACHE=/secure.mail/.cache/huggingface \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    VECLIB_MAXIMUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1

RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /secure.mail

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . ./

RUN mkdir -p /secure.mail/.cache/huggingface && \
    chown -R appuser:appgroup /secure.mail

USER appuser

EXPOSE 10000

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --limit-concurrency 10"]
