# CyberAgents Multi-Agent Cybersecurity System
# Dockerfile for containerized deployment

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs

# Create non-root user for security
RUN useradd -m -u 1000 cyberagent && \
    chown -R cyberagent:cyberagent /app

# Switch to non-root user
USER cyberagent

# Expose ports
# 8501 - Streamlit UI
# 8502 - WebHook Server
# 5000 - MCP Server (stdio/chat)
EXPOSE 8501 8502 5000

# Health check for Streamlit UI
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command runs Streamlit UI
# Can be overridden with docker run command
CMD ["streamlit", "run", "src/ui/streamlit_app.py", "--server.address", "0.0.0.0", "--server.port", "8501"]
