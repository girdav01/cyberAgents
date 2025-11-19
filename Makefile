# CyberAgents Makefile
# Simplifies common Docker operations

.PHONY: help build up down logs restart clean pull-models test

# Default target
.DEFAULT_GOAL := help

# Variables
COMPOSE_FILE = docker-compose.yml
COMPOSE_PROD = docker-compose.prod.yml
PROJECT_NAME = cyberagents

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build all Docker images
	docker-compose build

build-no-cache: ## Build all Docker images without cache
	docker-compose build --no-cache

up: ## Start all services in detached mode
	docker-compose up -d

up-logs: ## Start all services with logs
	docker-compose up

down: ## Stop and remove all containers
	docker-compose down

down-volumes: ## Stop and remove all containers and volumes
	docker-compose down -v

restart: ## Restart all services
	docker-compose restart

logs: ## Show logs for all services
	docker-compose logs -f

logs-streamlit: ## Show logs for Streamlit service
	docker-compose logs -f streamlit

logs-webhook: ## Show logs for WebHook service
	docker-compose logs -f webhook

logs-ollama: ## Show logs for Ollama service
	docker-compose logs -f ollama

status: ## Show status of all services
	docker-compose ps

stats: ## Show resource usage statistics
	docker stats

# Development targets
dev-up: ## Start only Streamlit and Ollama for development
	docker-compose up -d streamlit ollama

dev-logs: ## Show Streamlit logs
	docker-compose logs -f streamlit

dev-shell: ## Open shell in Streamlit container
	docker-compose exec streamlit bash

# Production targets
prod-build: ## Build production images
	docker-compose -f $(COMPOSE_FILE) -f $(COMPOSE_PROD) build

prod-up: ## Start production services
	docker-compose -f $(COMPOSE_FILE) -f $(COMPOSE_PROD) up -d

prod-down: ## Stop production services
	docker-compose -f $(COMPOSE_FILE) -f $(COMPOSE_PROD) down

prod-logs: ## Show production logs
	docker-compose -f $(COMPOSE_FILE) -f $(COMPOSE_PROD) logs -f

# Ollama operations
ollama-shell: ## Open shell in Ollama container
	docker-compose exec ollama bash

pull-models: ## Pull required Ollama models
	docker-compose exec ollama ollama pull phi4:latest
	docker-compose exec ollama ollama pull llama3.2:latest

list-models: ## List installed Ollama models
	docker-compose exec ollama ollama list

# Maintenance
clean: ## Remove stopped containers and unused images
	docker-compose down
	docker system prune -f

clean-all: ## Remove all containers, images, and volumes (DESTRUCTIVE)
	docker-compose down -v
	docker system prune -af
	docker volume prune -f

backup-ollama: ## Backup Ollama models
	@echo "Backing up Ollama models..."
	docker run --rm \
		-v $(PROJECT_NAME)_ollama-data:/data \
		-v $(PWD):/backup \
		busybox tar czf /backup/ollama-backup-$$(date +%Y%m%d-%H%M%S).tar.gz /data
	@echo "Backup complete!"

backup-logs: ## Backup application logs
	@echo "Backing up logs..."
	tar czf logs-backup-$$(date +%Y%m%d-%H%M%S).tar.gz logs/
	@echo "Backup complete!"

# Testing
test: ## Run tests in Docker container
	docker-compose run --rm streamlit pytest tests/ -v

test-health: ## Test health endpoints
	@echo "Testing Streamlit health..."
	curl -f http://localhost:8501/_stcore/health || echo "Streamlit not healthy"
	@echo "\nTesting WebHook health..."
	curl -f http://localhost:8502/health || echo "WebHook not healthy"

# Installation and setup
install: ## Initial setup - build and start services
	@echo "Setting up CyberAgents..."
	cp -n .env.example .env || true
	@echo "Please edit .env file with your configuration"
	@echo "Then run: make build && make up"

first-run: build up pull-models ## Complete first-time setup
	@echo "CyberAgents is running!"
	@echo "Streamlit UI: http://localhost:8501"
	@echo "WebHook API: http://localhost:8502"
	@echo "Ollama API: http://localhost:11434"

# Update
update: ## Pull latest code and restart
	git pull
	docker-compose build
	docker-compose up -d
	@echo "Update complete!"

# Monitoring
monitor: ## Monitor all services
	watch -n 2 'docker-compose ps && echo "" && docker stats --no-stream'

# Network operations
network-inspect: ## Inspect Docker network
	docker network inspect $(PROJECT_NAME)_cyberagents-network

network-clean: ## Remove unused networks
	docker network prune -f

# Volume operations
volume-list: ## List all volumes
	docker volume ls | grep $(PROJECT_NAME)

volume-inspect: ## Inspect Ollama volume
	docker volume inspect $(PROJECT_NAME)_ollama-data
