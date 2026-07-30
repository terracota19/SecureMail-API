FROM python:3.13.5-slim

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

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Directorio de caché local para Hugging Face dentro del contenedor
RUN mkdir -p /secure.mail/cache && chown -R appuser:appgroup /secure.mail
ENV HF_HOME=/secure.mail/cache

# Descargar el modelo durante el build de Docker para evitar descargas en tiempo de ejecución
COPY download_model.py .
RUN python download_model.py

USER root

# Copiar el resto del código y artefactos
COPY app.py .
COPY auth.py ./
COPY utils.py ./
COPY models/ ./models/
COPY objects/ ./objects/
COPY Metrics/ ./Metrics/

RUN chown -R appuser:appgroup /secure.mail
USER appuser

EXPOSE 10000

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --limit-concurrency 10"]
