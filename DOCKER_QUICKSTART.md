# 🐳 Docker Quick Start Guide

Get CyberAgents running in under 5 minutes with Docker!

## Prerequisites

- Docker 20.10+ installed ([Get Docker](https://docs.docker.com/get-docker/))
- Docker Compose 2.0+ installed
- 8GB+ RAM available
- 20GB disk space

## 1️⃣ Clone and Configure

```bash
# Clone the repository
git clone https://github.com/yourusername/cyberAgents.git
cd cyberAgents

# Create environment file
cp .env.example .env

# Optional: Edit .env if you want to customize
# nano .env
```

## 2️⃣ Start Everything

Choose your method:

### Method A: Using Makefile (Recommended)

```bash
# One command to rule them all!
make first-run
```

This will:
- Build all Docker images
- Start all services
- Pull Ollama models (phi4 and llama3.2)
- Show you the access URLs

### Method B: Using Docker Compose

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# Pull models
docker-compose exec ollama ollama pull phi4:latest
docker-compose exec ollama ollama pull llama3.2:latest
```

## 3️⃣ Access Services

Once started, access:

- **🎨 Streamlit UI**: http://localhost:8501
- **🔗 WebHook API**: http://localhost:8502
- **🤖 Ollama API**: http://localhost:11434

## 4️⃣ Test It Out

### Test Streamlit UI

1. Open http://localhost:8501 in your browser
2. Enter a cybersecurity question like:
   ```
   Analyze this suspicious PowerShell command:
   powershell -enc JABzAD0ATgBlAHcA...
   ```
3. Click "Analyze" and watch the multi-agent system work!

### Test WebHook API

```bash
curl -X POST http://localhost:8502/api/security-event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "malware_detection",
    "description": "Suspicious file detected on endpoint",
    "severity": "high"
  }'
```

## 🎮 Common Operations

### View Logs

```bash
# All services
make logs

# Or specific service
make logs-streamlit
make logs-webhook
make logs-ollama
```

### Check Status

```bash
# Service status
make status

# Resource usage
make stats
```

### Stop Services

```bash
# Stop everything
make down

# Or restart
make restart
```

### Update

```bash
# Pull latest code and restart
make update
```

## 🔧 Configuration

### Environment Variables

Edit `.env` to configure:

```bash
# LLM Provider (ollama, lmstudio, or openai)
LLM_PROVIDER=ollama

# Ollama URL (use service name in Docker)
OLLAMA_BASE_URL=http://ollama:11434

# OpenAI API Key (if using OpenAI)
OPENAI_API_KEY=your_key_here

# WebHook API Key
WEBHOOK_API_KEY=change-me-in-production

# Logging Level
LOG_LEVEL=INFO
```

### Using External Ollama

If you have Ollama running on your host machine:

```bash
# Edit .env
OLLAMA_BASE_URL=http://host.docker.internal:11434

# Or on Linux
OLLAMA_BASE_URL=http://172.17.0.1:11434

# Start without Ollama container
docker-compose up -d streamlit webhook mcp
```

### Using OpenAI Instead

```bash
# Edit .env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here

# Start without Ollama
docker-compose up -d streamlit webhook mcp
```

## 🏭 Production Deployment

For production with SSL, Nginx, and optimizations:

```bash
# Build production images
make prod-build

# Start with production config
make prod-up

# View production logs
make prod-logs
```

## 🐛 Troubleshooting

### Services Won't Start

```bash
# Check logs
docker-compose logs

# Check if ports are in use
netstat -tuln | grep 8501

# Clean start
docker-compose down -v
docker-compose up -d
```

### Ollama Models Not Loading

```bash
# Check Ollama status
docker-compose exec ollama ollama list

# Re-pull models
make pull-models

# Or manually
docker-compose exec ollama ollama pull phi4:latest
```

### Out of Memory

```bash
# Check resource usage
docker stats

# Increase Docker memory in Docker Desktop:
# Settings → Resources → Memory (set to 8GB+)

# Or disable concurrent execution
# Edit config/app_config.yaml:
agents:
  concurrent_execution: false
```

### Permission Errors

```bash
# Fix log directory permissions
sudo chown -R $USER:$USER logs/

# Or on Linux, run Docker commands with sudo
sudo docker-compose up -d
```

### Container Can't Connect to Ollama

```bash
# Check network
docker network inspect cyberagents_cyberagents-network

# Restart everything
docker-compose down
docker-compose up -d
```

## 📚 Advanced Usage

### Run Specific Services Only

```bash
# Only Streamlit + Ollama
docker-compose up -d streamlit ollama

# Only WebHook + Ollama
docker-compose up -d webhook ollama
```

### Execute Commands in Containers

```bash
# Open bash in Streamlit container
docker-compose exec streamlit bash

# Open bash in Ollama container
docker-compose exec ollama bash

# Run Python script
docker-compose exec streamlit python examples/agent_capabilities_example.py
```

### Backup and Restore

```bash
# Backup Ollama models
make backup-ollama

# Backup logs
make backup-logs

# Restore (replace timestamp with your backup)
docker run --rm \
  -v cyberagents_ollama-data:/data \
  -v $(pwd):/backup \
  busybox tar xzf /backup/ollama-backup-YYYYMMDD-HHMMSS.tar.gz -C /
```

## 🔍 Useful Commands

```bash
# See all available make commands
make help

# Monitor services in real-time
make monitor

# Clean up everything (DESTRUCTIVE!)
make clean-all

# Update to latest version
make update

# Check health
make test-health
```

## 📖 Next Steps

- **Full Docker Guide**: [docs/DOCKER_DEPLOYMENT.md](docs/DOCKER_DEPLOYMENT.md)
- **Agent Capabilities**: [docs/AGENT_CAPABILITIES.md](docs/AGENT_CAPABILITIES.md)
- **Main README**: [README.md](README.md)
- **Configuration**: [config/app_config.yaml](config/app_config.yaml)

## 💡 Tips

1. **First Run**: The first startup takes longer as Docker downloads images and Ollama pulls models
2. **Resources**: Ollama needs at least 8GB RAM for larger models like phi4
3. **Development**: Mount code as volume for live updates: `-v $(pwd)/src:/app/src`
4. **Logs**: Keep an eye on logs with `make logs` when troubleshooting
5. **Updates**: Regular `make update` keeps you on the latest version

## 🆘 Getting Help

- Check logs: `make logs`
- Review [Docker Deployment Guide](docs/DOCKER_DEPLOYMENT.md)
- Open an issue on [GitHub](https://github.com/yourusername/cyberAgents/issues)
- Check [Troubleshooting section](#-troubleshooting) above

---

**Happy Analyzing! 🛡️**
