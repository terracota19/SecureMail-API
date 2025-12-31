FROM python:3.13.4-slim

RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /secure.mail

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY requirements.txt .
RUN pip install -r requirements.txt

RUN mkdir -p /secure.mail/cache && chown -R appuser:appgroup /secure.mail
ENV HF_HOME=/secure.mail/cache

USER appuser

RUN python -c "from transformers import XLMRobertaTokenizer, XLMRobertaModel; XLMRobertaTokenizer.from_pretrained('xlm-roberta-base'); XLMRobertaModel.from_pretrained('xlm-roberta-base')"

USER root

COPY app.py .
COPY models/ ./models/
COPY objects/ ./objects/
COPY Metrics/ ./Metrics/

RUN chown -R appuser:appgroup /secure.mail
USER appuser
EXPOSE 10000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "10000"]
