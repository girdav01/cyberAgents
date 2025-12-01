#!/bin/bash
# CyberAgents Tool Installation Script
# This script helps install and configure security tools for CyberAgents

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_command() {
    if command -v "$1" &> /dev/null; then
        print_success "$1 is installed"
        return 0
    else
        print_error "$1 is not installed"
        return 1
    fi
}

# Main script
print_header "CyberAgents Tool Installation Script"

echo ""
print_info "This script will help you install security tools for CyberAgents"
echo ""

# Check prerequisites
print_header "Checking Prerequisites"
check_command "docker" || MISSING_DOCKER=1
check_command "docker-compose" || check_command "docker compose" || MISSING_DOCKER_COMPOSE=1
check_command "python3" || MISSING_PYTHON=1
check_command "pip3" || MISSING_PIP=1

if [ ! -z "$MISSING_DOCKER" ]; then
    print_error "Docker is required but not installed."
    print_info "Please install Docker from: https://docs.docker.com/get-docker/"
    exit 1
fi

if [ ! -z "$MISSING_PYTHON" ]; then
    print_error "Python 3 is required but not installed."
    print_info "Please install Python 3.9+ from: https://www.python.org/"
    exit 1
fi

echo ""
print_header "Installation Options"
echo "1. Full Docker deployment (CyberAgents + OpenCTI + SpiderFoot + MISP)"
echo "2. CyberAgents only (minimal)"
echo "3. CyberAgents + OpenCTI"
echo "4. CyberAgents + SpiderFoot"
echo "5. CyberAgents + MISP"
echo "6. Custom selection"
echo ""
read -p "Enter your choice (1-6): " choice

# Setup environment file
if [ ! -f ".env" ]; then
    print_info "Creating .env file from template..."
    cp .env.example .env
    print_success ".env file created"
    print_warning "Please edit .env file with your API keys and configuration"
else
    print_info ".env file already exists"
fi

# Install Python dependencies
print_header "Installing Python Dependencies"
pip3 install -r requirements.txt
print_success "Python dependencies installed"

# Docker deployment
case $choice in
    1)
        print_header "Starting Full Deployment"
        print_info "This will start CyberAgents, OpenCTI, SpiderFoot, and MISP"
        docker-compose up -d
        ;;
    2)
        print_header "Starting Minimal Deployment"
        docker-compose up -d cyberagents-ui cyberagents-webhook
        ;;
    3)
        print_header "Starting CyberAgents + OpenCTI"
        docker-compose up -d cyberagents-ui cyberagents-webhook opencti redis elasticsearch minio rabbitmq
        ;;
    4)
        print_header "Starting CyberAgents + SpiderFoot"
        docker-compose up -d cyberagents-ui cyberagents-webhook spiderfoot
        ;;
    5)
        print_header "Starting CyberAgents + MISP"
        docker-compose up -d cyberagents-ui cyberagents-webhook misp misp-db misp-redis
        ;;
    6)
        print_header "Custom Deployment"
        print_info "Edit docker-compose.yml to select specific services"
        print_info "Then run: docker-compose up -d <service_names>"
        exit 0
        ;;
    *)
        print_error "Invalid choice"
        exit 1
        ;;
esac

echo ""
print_header "Installation Complete!"
echo ""
print_success "CyberAgents is now running!"
echo ""
print_info "Access points:"
echo "  - Streamlit UI:     http://localhost:8501"
echo "  - Webhook Server:   http://localhost:8502"

if [ "$choice" = "1" ] || [ "$choice" = "3" ]; then
    echo "  - OpenCTI:          http://localhost:8080"
    echo "    Default login:    admin@opencti.io / ChangeMeNow!"
fi

if [ "$choice" = "1" ] || [ "$choice" = "4" ]; then
    echo "  - SpiderFoot:       http://localhost:5001"
fi

if [ "$choice" = "1" ] || [ "$choice" = "5" ]; then
    echo "  - MISP:             https://localhost:8443"
    echo "    Default login:    admin@misp.local / admin"
fi

echo ""
print_warning "Important: Change default passwords in production!"
print_info "Check logs with: docker-compose logs -f"
print_info "Stop services with: docker-compose down"
echo ""
