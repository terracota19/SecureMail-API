#!/bin/bash

set -e

if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
else
    echo "❌ Error: Archivo .env no encontrado. Crea un archivo .env con las variables necesarias."
    exit 1
fi

echo "📦 Construyendo la imagen de la API..."
docker build -t securemail:v1.0.0 .

echo "🚀 Iniciando API en Docker..."
docker run -d --name securemail_container \
  -e HYBRID_ANALYSIS_API_KEY="$HYBRID_ANALYSIS_API_KEY" \
  -e HYBRID_ANALYSIS_API_URL="$HYBRID_ANALYSIS_API_URL" \
  -e ML_MODEL_NAME_URI="$ML_MODEL_NAME_URI" \
  -p 8080:8080 securemail:v1.0.0

echo "🕵️ Iniciando OWASP ZAP en modo headless..."
docker run -d --name zap -p 8090:8090 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8090

echo "⏳ Esperando 20 segundos para que ZAP se inicie correctamente..."
sleep 20

echo "🔍 Iniciando escaneo activo contra la API..."
curl "http://localhost:8090/JSON/ascan/action/scan/?url=http://host.docker.internal:8080&recurse=true"

echo "📊 Generando reporte de OWASP ZAP..."
curl "http://localhost:8090/OTHER/core/other/htmlreport/" -o zap-report.html

echo "✅ Escaneo completado. Revisa zap-report.html para ver los resultados."

if command -v xdg-open &> /dev/null; then
    xdg-open zap-report.html
elif command -v open &> /dev/null; then
    open zap-report.html
fi

echo "🛑 Limpiando contenedores..."
docker stop securemail_container zap
docker rm securemail_container zap

echo "🎉 Proceso completado."
