FROM python:3.12-slim

WORKDIR /app

# Install build essentials for wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libkrb5-dev libsasl2-dev libldap2-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY config ./config
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["adscan"]
CMD ["--help"]
