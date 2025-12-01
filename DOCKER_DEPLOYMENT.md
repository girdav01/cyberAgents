# 🐳 Docker Deployment Guide for CyberAgents

This guide provides detailed instructions for deploying CyberAgents and its integrated security tools using Docker.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Deployment Options](#deployment-options)
- [Service Configuration](#service-configuration)
- [Security Hardening](#security-hardening)
- [Monitoring and Logs](#monitoring-and-logs)
- [Troubleshooting](#troubleshooting)
- [Production Deployment](#production-deployment)

## Prerequisites

### Required Software

- **Docker Engine**: 20.10+ ([Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose**: 2.0+ ([Install Compose](https://docs.docker.com/compose/install/))
- **System Resources**:
  - Minimum: 8GB RAM, 4 CPU cores, 50GB disk
  - Recommended: 16GB RAM, 8 CPU cores, 100GB disk (for full deployment)

### Checking Prerequisites

```bash
# Check Docker version
docker --version

# Check Docker Compose version
docker compose version

# Check available resources
docker system df
```

## Quick Start

### 1. Clone and Setup

```bash
# Clone repository
git clone https://github.com/yourusername/cyberAgents.git
cd cyberAgents

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Configure Environment Variables

Edit `.env` file with your settings:

```bash
# Required: LLM Provider (point to host Ollama)
OLLAMA_BASE_URL=http://host.docker.internal:11434

# Optional: API Keys for external services
OPENCTI_API_KEY=your_opencti_key
MISP_API_KEY=your_misp_key
TREND_VISION_ONE_API_KEY=your_trend_key
```

### 3. Launch Services

```bash
# Option 1: Use installation script (Recommended)
chmod +x scripts/install_tools.sh
./scripts/install_tools.sh

# Option 2: Manual deployment
docker compose up -d
```

### 4. Verify Deployment

```bash
# Check running containers
docker compose ps

# Check logs
docker compose logs -f cyberagents-ui

# Test web interface
curl http://localhost:8501/_stcore/health
```

## Deployment Options

### Option 1: Minimal Deployment (CyberAgents Only)

Fastest startup, minimal resources:

```bash
docker compose up -d cyberagents-ui cyberagents-webhook
```

**Services:**
- Streamlit UI: `http://localhost:8501`
- Webhook Server: `http://localhost:8502`

**Resources:** ~2GB RAM, 2 CPU cores

### Option 2: CyberAgents + OpenCTI

Includes threat intelligence platform:

```bash
docker compose up -d cyberagents-ui cyberagents-webhook \
  opencti redis elasticsearch minio rabbitmq
```

**Additional Services:**
- OpenCTI Platform: `http://localhost:8080`
- OpenCTI Connectors: Various threat feeds

**Resources:** ~8GB RAM, 4 CPU cores

### Option 3: CyberAgents + SpiderFoot

Includes OSINT reconnaissance:

```bash
docker compose up -d cyberagents-ui cyberagents-webhook spiderfoot
```

**Additional Services:**
- SpiderFoot UI: `http://localhost:5001`

**Resources:** ~4GB RAM, 2 CPU cores

### Option 4: CyberAgents + MISP

Includes threat sharing platform:

```bash
docker compose up -d cyberagents-ui cyberagents-webhook \
  misp misp-db misp-redis
```

**Additional Services:**
- MISP Platform: `https://localhost:8443`

**Resources:** ~6GB RAM, 4 CPU cores

### Option 5: Full Deployment (All Tools)

Complete security operations platform:

```bash
docker compose up -d
```

**All Services:**
- CyberAgents UI + Webhook
- OpenCTI + dependencies
- SpiderFoot
- MISP + database

**Resources:** ~16GB RAM, 8 CPU cores

## Service Configuration

### CyberAgents Configuration

Edit `config/app_config.yaml` before deployment:

```yaml
# LLM Provider
llm_provider:
  default: ollama
  ollama:
    base_url: http://host.docker.internal:11434

# Agent Settings
agents:
  config_file: config/adv_cybersec-system-prompts.json
  temperature: 0.3
  concurrent_execution: true
```

### OpenCTI Configuration

First-time setup:

```bash
# Wait for OpenCTI to start
docker compose logs -f opencti

# Access UI at http://localhost:8080
# Default credentials: admin@opencti.io / ChangeMeNow!

# Change default password immediately
```

Configure connectors in OpenCTI UI:
1. Navigate to Data → Connectors
2. Enable desired threat feeds (MITRE, AlienVault OTX, etc.)
3. Configure API keys for external sources

### SpiderFoot Configuration

```bash
# Access UI at http://localhost:5001
# No authentication required by default (configure in production)

# Configure API keys for enhanced modules:
# - VirusTotal
# - Shodan
# - Have I Been Pwned
```

### MISP Configuration

```bash
# Access UI at https://localhost:8443
# Default credentials: admin@misp.local / admin

# Initial setup:
1. Change admin password
2. Generate API key (Administration → Users → Auth Keys)
3. Configure feeds (Sync Actions → List Feeds)
4. Enable desired feeds
```

## Security Hardening

### Production Environment Variables

```bash
# Generate strong passwords
OPENCTI_ADMIN_PASSWORD=$(openssl rand -base64 32)
MISP_DB_PASSWORD=$(openssl rand -base64 32)
WEBHOOK_API_KEY=$(openssl rand -hex 32)

# Add to .env
echo "OPENCTI_ADMIN_PASSWORD=$OPENCTI_ADMIN_PASSWORD" >> .env
```

### Network Security

Create isolated network for security tools:

```yaml
# docker-compose.override.yml
networks:
  cyberagents-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

### SSL/TLS Configuration

#### Enable HTTPS for Streamlit

```yaml
# docker-compose.override.yml
services:
  cyberagents-ui:
    command: >
      streamlit run src/ui/streamlit_app.py
      --server.enableCORS=false
      --server.enableXsrfProtection=true
    volumes:
      - ./ssl/cert.pem:/app/ssl/cert.pem:ro
      - ./ssl/key.pem:/app/ssl/key.pem:ro
```

#### Reverse Proxy (Nginx)

```bash
# Example nginx.conf for production
upstream cyberagents {
    server localhost:8501;
}

server {
    listen 443 ssl;
    server_name cyberagents.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://cyberagents;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Access Control

```yaml
# Add authentication to services
services:
  cyberagents-webhook:
    environment:
      - WEBHOOK_API_KEY=${WEBHOOK_API_KEY}
      - ENABLE_AUTH=true
```

## Monitoring and Logs

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f cyberagents-ui

# Last 100 lines
docker compose logs --tail=100 opencti

# Follow with grep
docker compose logs -f | grep ERROR
```

### Resource Monitoring

```bash
# Container resource usage
docker stats

# Disk usage
docker system df

# Detailed inspection
docker inspect cyberagents-ui
```

### Health Checks

```bash
# Check container health
docker compose ps

# Test endpoints
curl http://localhost:8501/_stcore/health
curl http://localhost:8502/health
curl http://localhost:8080/health
```

### Log Aggregation

Use Docker logging driver:

```yaml
# docker-compose.override.yml
x-logging: &default-logging
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"

services:
  cyberagents-ui:
    logging: *default-logging
```

## Troubleshooting

### Common Issues

#### 1. Container Fails to Start

```bash
# Check logs
docker compose logs [service-name]

# Check for port conflicts
netstat -an | grep LISTEN | grep -E "8501|8502|8080"

# Restart service
docker compose restart [service-name]
```

#### 2. Ollama Connection Issues

```bash
# Test Ollama from host
curl http://localhost:11434/api/tags

# Test from container
docker exec cyberagents-ui curl http://host.docker.internal:11434/api/tags

# Check OLLAMA_BASE_URL in .env
# Should be: http://host.docker.internal:11434 (not localhost)
```

#### 3. OpenCTI Won't Start

```bash
# Check all dependencies are running
docker compose ps | grep -E "redis|elasticsearch|minio|rabbitmq"

# Wait for Elasticsearch to be ready (can take 2-3 minutes)
docker compose logs elasticsearch | grep "started"

# Restart OpenCTI after dependencies are ready
docker compose restart opencti
```

#### 4. Insufficient Resources

```bash
# Check resource usage
docker stats

# Increase Docker resource limits (Docker Desktop)
# Settings → Resources → Advanced
# - Memory: 16GB+
# - CPUs: 6-8 cores
```

#### 5. Permission Issues

```bash
# Fix volume permissions
sudo chown -R 1000:1000 logs/
docker compose restart
```

### Reset and Clean Up

```bash
# Stop all services
docker compose down

# Remove volumes (⚠️ deletes all data)
docker compose down -v

# Remove images
docker compose down --rmi all

# Clean up system
docker system prune -a --volumes
```

## Production Deployment

### Best Practices

1. **Use Docker Secrets for Sensitive Data**

```bash
# Create secrets
echo "your_api_key" | docker secret create opencti_api_key -

# Reference in compose
services:
  cyberagents-ui:
    secrets:
      - opencti_api_key
```

2. **Implement Backup Strategy**

```bash
# Backup volumes
docker run --rm -v cyberagents_elasticsearch-data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/elasticsearch-$(date +%Y%m%d).tar.gz /data

# Backup databases
docker exec misp-db mysqldump -u misp -p misp > misp-backup.sql
```

3. **Use Health Checks**

All services include health checks. Monitor with:

```bash
# Check health status
docker compose ps

# Set up monitoring alerts
# Use tools like Prometheus, Grafana, or Docker Health Check API
```

4. **Enable Auto-Restart**

```yaml
services:
  cyberagents-ui:
    restart: always  # Changed from unless-stopped
```

5. **Resource Limits**

```yaml
services:
  cyberagents-ui:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

### Scaling

For high-availability deployments:

```bash
# Scale webhook servers
docker compose up -d --scale cyberagents-webhook=3

# Add load balancer (nginx, traefik, etc.)
```

### Updates and Maintenance

```bash
# Pull latest images
docker compose pull

# Restart with new images
docker compose up -d

# Clean up old images
docker image prune -f
```

## Support

For issues and questions:
- GitHub Issues: [Repository Issues](https://github.com/yourusername/cyberAgents/issues)
- Documentation: Check README.md and inline comments
- Docker Compose Docs: [docs.docker.com/compose](https://docs.docker.com/compose/)

---

**Built with security in mind** 🔒
