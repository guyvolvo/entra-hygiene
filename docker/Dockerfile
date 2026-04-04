FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY entra_hygiene/ ./entra_hygiene/

RUN pip install --no-cache-dir .

EXPOSE 5454

CMD ["entra-hygiene", "serve"]
