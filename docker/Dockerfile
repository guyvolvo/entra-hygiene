FROM python:3.11-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml .
RUN uv sync --no-dev

COPY entra_hygiene/ ./entra_hygiene/

EXPOSE 9090

CMD ["uv", "run", "entra-hygiene", "serve"]
