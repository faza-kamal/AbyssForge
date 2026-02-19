FROM python:3.11-slim

LABEL maintainer="faza-kamal"
LABEL description="AbyssForge - Web Vulnerability Scanner"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .

# Create output directory
RUN mkdir -p /app/output

# Create non-root user for security
RUN useradd -m -u 1000 abyssforge && chown -R abyssforge:abyssforge /app
USER abyssforge

ENTRYPOINT ["abyssforge"]
CMD ["--help"]
