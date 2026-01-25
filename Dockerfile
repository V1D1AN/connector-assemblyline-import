FROM python:3.11-alpine

# Set work directory
WORKDIR /opt/opencti-connector-assemblyline-import

# Install system dependencies
RUN apk add --no-cache \
    git \
    build-base \
    libffi-dev \
    openssl-dev

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy connector code
COPY src/assemblyline_import.py .
COPY src/config.yml.example .

# Create non-root user
RUN addgroup -g 1000 connector && \
    adduser -u 1000 -G connector -s /bin/sh -D connector && \
    chown -R connector:connector /opt/opencti-connector-assemblyline-import

USER connector

# Run connector
ENTRYPOINT ["python", "assemblyline_import.py"]
