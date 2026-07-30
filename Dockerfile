FROM python:3.13-slim

RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /secure.mail

ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN mkdir -p /secure.mail/cache && chown -R appuser:appgroup /secure.mail

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

USER root
COPY app.py auth.py ./
COPY models/ ./models/
COPY objects/ ./objects/
COPY Metrics/ ./Metrics/

RUN chown -R appuser:appgroup /secure.mail
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
