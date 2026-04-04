FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY arcanum/ arcanum/
COPY frontend/ frontend/

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["arcanum", "serve", "--port", "8000"]
