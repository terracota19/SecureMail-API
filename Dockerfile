FROM python:3.13-slim

# 1. Crear usuario no-root y directorio de trabajo
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /secure.mail

# 2. Entorno virtual Python
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# 3. Directorio para el caché de HuggingFace
RUN mkdir -p /secure.mail/cache && chown -R appuser:appgroup /secure.mail
ENV HF_HOME=/secure.mail/cache

# 4. INSTALACIÓN DE DEPENDENCIAS OPTIMIZADA (Ahorro masivo de RAM y disco)
COPY requirements.txt .
# A) Instalamos la versión exclusiva para CPU de PyTorch (evita librerías GPU CUDA de ~2GB)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
# B) Instalamos el resto de librerías sin guardar el caché del instalador
RUN pip install --no-cache-dir -r requirements.txt

# 5. Descarga de pesos de XLM-RoBERTa en tiempo de Build
USER appuser
RUN python -c "from transformers import XLMRobertaTokenizer, XLMRobertaModel; XLMRobertaTokenizer.from_pretrained('xlm-roberta-base'); XLMRobertaModel.from_pretrained('xlm-roberta-base')"

# 6. Copia de código fuente y artefactos
USER root
COPY app.py auth.py ./
COPY models/ ./models/
COPY objects/ ./objects/
COPY Metrics/ ./Metrics/

# 7. Permisos finales y ejecución
RUN chown -R appuser:appgroup /secure.mail
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
