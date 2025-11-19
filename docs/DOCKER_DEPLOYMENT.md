# Docker Deployment Guide

Complete guide for deploying CyberAgents using Docker and Docker Compose.

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

- Docker 20.10+ installed
- Docker Compose 2.0+ installed
- At least 8GB RAM available
- 20GB disk space

### 1. Clone and Configure

```bash
# Clone repository
git clone https://github.com/yourusername/cyberAgents.git
cd cyberAgents

# Create environment file
cp .env.example .env

# Edit .env with your settings
nano .env
```

### 2. Build and Run

```bash
# Build the Docker image
docker-compose build

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f
```

### 3. Access Services

- **Streamlit UI**: http://localhost:8501
- **WebHook API**: http://localhost:8502
- **MCP Server**: http://localhost:5000
- **Ollama API**: http://localhost:11434

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Host                          │
│                                                          │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│  │ Streamlit  │  │  WebHook   │  │    MCP     │       │
│  │  :8501     │  │  :8502     │  │   :5000    │       │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘       │
│        │                │                │              │
│        └────────────────┼────────────────┘              │
│                         │                               │
│                  ┌──────▼──────┐                        │
│                  │   Ollama    │                        │
│                  │   :11434    │                        │
│                  └─────────────┘                        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# LLM Provider Configuration
LLM_PROVIDER=ollama  # Options: ollama, lmstudio, openai
OLLAMA_BASE_URL=http://ollama:11434
OPENAI_API_KEY=your_openai_api_key_here

# WebHook Configuration
WEBHOOK_API_KEY=change-me-in-production
WEBHOOK_PORT=8502

# Logging
LOG_LEVEL=INFO  # Options: DEBUG, INFO, WARNING, ERROR

# Production Settings
ENVIRONMENT=development  # Options: development, production
MAX_REQUESTS_PER_MINUTE=60
RATE_LIMIT_ENABLED=true
```

### Volume Mounts

The Docker setup includes several volume mounts:

```yaml
volumes:
  - ./config:/app/config:ro        # Configuration files (read-only)
  - ./logs:/app/logs                # Application logs
  - ./.env:/app/.env:ro             # Environment variables (read-only)
  - ollama-data:/root/.ollama       # Ollama models
```

## Deployment Options

### Option 1: All Services (Default)

Run all services including Ollama:

```bash
docker-compose up -d
```

### Option 2: Streamlit UI Only

Run only the Streamlit interface:

```bash
docker-compose up -d streamlit ollama
```

### Option 3: WebHook Server Only

Run only the webhook API:

```bash
docker-compose up -d webhook ollama
```

### Option 4: External Ollama

If you have Ollama running elsewhere:

```bash
# Edit docker-compose.yml to comment out the ollama service
# Update OLLAMA_BASE_URL in .env
OLLAMA_BASE_URL=http://your-ollama-host:11434

# Start without Ollama
docker-compose up -d streamlit webhook mcp
```

### Option 5: Using OpenAI

To use OpenAI instead of Ollama:

```bash
# Update .env
LLM_PROVIDER=openai
OPENAI_API_KEY=your_api_key_here

# Start without Ollama
docker-compose up -d streamlit webhook mcp
```

## Production Deployment

### 1. Production Configuration

Use the production docker-compose override:

```bash
# Build production image
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

# Start with production settings
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 2. SSL/TLS Configuration

Generate SSL certificates:

```bash
# Create SSL directory
mkdir -p ssl

# Generate self-signed certificate (for testing)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem -out ssl/cert.pem

# For production, use Let's Encrypt or your certificate provider
```

Update `nginx.conf` to enable HTTPS section.

### 3. Production Environment Variables

```bash
# .env.production
ENVIRONMENT=production
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://ollama:11434
LOG_LEVEL=WARNING
WEBHOOK_API_KEY=secure_random_key_here
MAX_REQUESTS_PER_MINUTE=30
RATE_LIMIT_ENABLED=true
```

### 4. Resource Limits

The production compose file includes resource limits:

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 4G
    reservations:
      cpus: '1.0'
      memory: 2G
```

Adjust based on your workload.

### 5. Security Hardening

#### a. Use Docker Secrets

```bash
# Create secrets
echo "your_webhook_key" | docker secret create webhook_api_key -
echo "your_openai_key" | docker secret create openai_api_key -
```

#### b. Network Isolation

```bash
# Only expose necessary ports
# Bind to localhost for internal-only services
ports:
  - "127.0.0.1:8502:8502"  # Only accessible from host
```

#### c. Read-Only Filesystems

```yaml
services:
  streamlit:
    read_only: true
    tmpfs:
      - /tmp
      - /app/logs
```

### 6. Monitoring and Logging

#### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f streamlit

# Last 100 lines
docker-compose logs --tail=100 webhook
```

#### Log Rotation

Production config includes log rotation:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

#### Health Checks

```bash
# Check service health
docker-compose ps

# Manual health check
curl http://localhost:8501/_stcore/health
curl http://localhost:8502/health
```

## Docker Commands Reference

### Building

```bash
# Build all services
docker-compose build

# Build specific service
docker-compose build streamlit

# Build without cache
docker-compose build --no-cache

# Build with specific tag
docker build -t cyberagents:v1.0 .
```

### Running

```bash
# Start all services
docker-compose up -d

# Start with logs
docker-compose up

# Start specific services
docker-compose up -d streamlit ollama

# Restart services
docker-compose restart

# Stop services
docker-compose stop

# Stop and remove containers
docker-compose down

# Stop and remove everything including volumes
docker-compose down -v
```

### Maintenance

```bash
# Pull latest images
docker-compose pull

# Remove unused images
docker image prune -a

# View resource usage
docker stats

# Execute command in container
docker-compose exec streamlit bash

# Copy files from container
docker cp cyberagents-streamlit:/app/logs ./local-logs
```

### Updating

```bash
# Pull latest code
git pull

# Rebuild and restart
docker-compose build
docker-compose up -d

# View updated logs
docker-compose logs -f
```

## Ollama Model Management

### Pull Models Inside Container

```bash
# Access Ollama container
docker-compose exec ollama bash

# Pull models
ollama pull phi4:latest
ollama pull llama3.2:latest

# List models
ollama list

# Remove model
ollama rm model_name
```

### Pre-load Models on Startup

Edit `docker-compose.yml`:

```yaml
ollama:
  image: ollama/ollama:latest
  entrypoint: ["/bin/sh", "-c"]
  command:
    - |
      ollama serve &
      sleep 10
      ollama pull phi4:latest
      ollama pull llama3.2:latest
      wait
```

## Troubleshooting

### Issue: Services won't start

```bash
# Check logs
docker-compose logs

# Check if ports are in use
netstat -tuln | grep 8501
netstat -tuln | grep 8502

# Stop conflicting services
docker-compose down
```

### Issue: Ollama not responding

```bash
# Check Ollama status
docker-compose exec ollama ollama list

# Restart Ollama
docker-compose restart ollama

# Check Ollama logs
docker-compose logs ollama
```

### Issue: Out of memory

```bash
# Check resource usage
docker stats

# Increase Docker memory limit
# Docker Desktop -> Settings -> Resources -> Memory

# Or reduce concurrent agents in config/app_config.yaml
agents:
  concurrent_execution: false
```

### Issue: Permission denied

```bash
# Fix ownership
sudo chown -R $USER:$USER logs/

# Or run as root (not recommended)
docker-compose run --user root streamlit bash
```

### Issue: Can't connect to services

```bash
# Check network
docker network ls
docker network inspect cyberagents_cyberagents-network

# Restart networking
docker-compose down
docker-compose up -d
```

### Issue: Models not loading

```bash
# Check Ollama volume
docker volume inspect cyberagents_ollama-data

# Re-pull models
docker-compose exec ollama ollama pull phi4:latest

# Check disk space
df -h
```

## Performance Optimization

### 1. Multi-stage Builds

For faster builds and smaller images:

```dockerfile
# Build stage
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Runtime stage
FROM python:3.11-slim
COPY --from=builder /root/.local /root/.local
COPY . /app
WORKDIR /app
```

### 2. Layer Caching

```bash
# Order Dockerfile commands by change frequency
# Most stable (base image) → Most volatile (app code)

# Use .dockerignore to exclude unnecessary files
```

### 3. Resource Allocation

```yaml
# Allocate more resources to Ollama
services:
  ollama:
    deploy:
      resources:
        limits:
          cpus: '8.0'
          memory: 16G
```

### 4. Use BuildKit

```bash
# Enable BuildKit for faster builds
export DOCKER_BUILDKIT=1
docker-compose build
```

## Backup and Restore

### Backup Volumes

```bash
# Backup Ollama models
docker run --rm \
  -v cyberagents_ollama-data:/data \
  -v $(pwd):/backup \
  busybox tar czf /backup/ollama-backup.tar.gz /data

# Backup logs
tar czf logs-backup.tar.gz logs/
```

### Restore Volumes

```bash
# Restore Ollama models
docker run --rm \
  -v cyberagents_ollama-data:/data \
  -v $(pwd):/backup \
  busybox tar xzf /backup/ollama-backup.tar.gz -C /
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build and Push Docker Image

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build image
        run: docker build -t cyberagents:${{ github.sha }} .

      - name: Run tests
        run: |
          docker-compose up -d
          # Add your tests here
          docker-compose down
```

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Ollama Docker Guide](https://github.com/ollama/ollama/blob/main/docs/docker.md)
- [Streamlit in Docker](https://docs.streamlit.io/knowledge-base/tutorials/deploy/docker)

## Support

For issues related to Docker deployment:
1. Check logs: `docker-compose logs -f`
2. Review this documentation
3. Open an issue on GitHub with logs and configuration
