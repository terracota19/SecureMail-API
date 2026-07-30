# 1. Crear el usuario y directorio de trabajo
WORKDIR /secure.mail

# 2. Definir variables de entorno para la caché de Hugging Face
ENV HF_HOME=/secure.mail/.cache/huggingface
ENV TRANSFORMERS_CACHE=/secure.mail/.cache/huggingface

# 3. Copiar el código fuente (asegúrate de incluir config.py y utils.py)
COPY app.py ./
COPY auth.py ./
COPY utils.py ./
COPY config.py ./

# Copiar los directorios de artefactos
COPY models/ ./models/
COPY objects/ ./objects/
COPY Metrics/ ./Metrics/

# 4. Crear la carpeta de caché y dar permisos globales a appuser sobre TODO /secure.mail
RUN mkdir -p /secure.mail/.cache/huggingface && \
    chown -R appuser:appgroup /secure.mail

# 5. Cambiar al usuario sin privilegios después de asignar permisos
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
