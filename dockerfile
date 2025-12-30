FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Check health
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1