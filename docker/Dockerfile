FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md .
COPY entra_hygiene/ ./entra_hygiene/

RUN pip install --no-cache-dir . && \
    useradd -r -s /bin/false appuser

USER appuser

EXPOSE 5454

ENTRYPOINT ["entra-hygiene"]
CMD ["serve"]
