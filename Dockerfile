FROM python:3.13.5-slim

# Variables de entorno para optimizar memoria y hilos de CPU en contenedores
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    VECLIB_MAXIMUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1

RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /secure.mail

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copiar requirements primero para aprovechar la caché de capas de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /secure.mail/cache && chown -R appuser:appgroup /secure.mail
ENV HF_HOME=/secure.mail/cache

USER appuser

# Hornear BERT en la imagen para que no descargue nada en caliente
RUN python -c "from transformers import XLMRobertaTokenizer, XLMRobertaModel; XLMRobertaTokenizer.from_pretrained('xlm-roberta-base'); XLMRobertaModel.from_pretrained('xlm-roberta-base')"

USER root

# Copiar código y artefactos necesarios de manera ordenada
COPY app.py .
COPY auth.py ./
COPY utils.py ./

COPY models/ ./models/
COPY objects/ ./objects/
COPY Metrics/ ./Metrics/



RUN chown -R appuser:appgroup /secure.mail
USER appuser

EXPOSE 10000

# Usar el puerto dinámico de Render y limitar la concurrencia para proteger la RAM de 512MB
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --limit-concurrency 10"]
