FROM python:3.11-slim

RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /secure.mail

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
COPY XGBoost.pkl .
RUN mkdir -p /secure.mail/cache && chown -R appuser:appgroup /secure.mail
ENV HF_HOME=/secure.mail/cache
USER appuser
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]


