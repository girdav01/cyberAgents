@echo off
REM CyberAgents Tool Installation Script for Windows
REM This script helps install and configure security tools for CyberAgents

setlocal enabledelayedexpansion

echo ================================================
echo CyberAgents Tool Installation Script
echo ================================================
echo.

REM Check prerequisites
echo Checking Prerequisites...
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Docker is not installed
    echo Please install Docker Desktop from: https://www.docker.com/products/docker-desktop
    exit /b 1
)
echo [OK] Docker is installed

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not installed
    echo Please install Python 3.9+ from: https://www.python.org/
    exit /b 1
)
echo [OK] Python is installed

echo.
echo ================================================
echo Installation Options
echo ================================================
echo 1. Full Docker deployment (CyberAgents + OpenCTI + SpiderFoot + MISP)
echo 2. CyberAgents only (minimal)
echo 3. CyberAgents + OpenCTI
echo 4. CyberAgents + SpiderFoot
echo 5. CyberAgents + MISP
echo 6. Custom selection
echo.
set /p choice="Enter your choice (1-6): "

REM Setup environment file
if not exist ".env" (
    echo Creating .env file from template...
    copy .env.example .env
    echo [OK] .env file created
    echo [WARNING] Please edit .env file with your API keys and configuration
) else (
    echo [INFO] .env file already exists
)

REM Install Python dependencies
echo.
echo ================================================
echo Installing Python Dependencies
echo ================================================
pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install Python dependencies
    exit /b 1
)
echo [OK] Python dependencies installed

REM Docker deployment
echo.
echo ================================================
if "%choice%"=="1" (
    echo Starting Full Deployment
    echo This will start CyberAgents, OpenCTI, SpiderFoot, and MISP
    docker-compose up -d
) else if "%choice%"=="2" (
    echo Starting Minimal Deployment
    docker-compose up -d cyberagents-ui cyberagents-webhook
) else if "%choice%"=="3" (
    echo Starting CyberAgents + OpenCTI
    docker-compose up -d cyberagents-ui cyberagents-webhook opencti redis elasticsearch minio rabbitmq
) else if "%choice%"=="4" (
    echo Starting CyberAgents + SpiderFoot
    docker-compose up -d cyberagents-ui cyberagents-webhook spiderfoot
) else if "%choice%"=="5" (
    echo Starting CyberAgents + MISP
    docker-compose up -d cyberagents-ui cyberagents-webhook misp misp-db misp-redis
) else if "%choice%"=="6" (
    echo Custom Deployment
    echo Edit docker-compose.yml to select specific services
    echo Then run: docker-compose up -d [service_names]
    exit /b 0
) else (
    echo [ERROR] Invalid choice
    exit /b 1
)

echo.
echo ================================================
echo Installation Complete!
echo ================================================
echo.
echo [OK] CyberAgents is now running!
echo.
echo Access points:
echo   - Streamlit UI:     http://localhost:8501
echo   - Webhook Server:   http://localhost:8502

if "%choice%"=="1" (
    echo   - OpenCTI:          http://localhost:8080
    echo     Default login:    admin@opencti.io / ChangeMeNow!
    echo   - SpiderFoot:       http://localhost:5001
    echo   - MISP:             https://localhost:8443
    echo     Default login:    admin@misp.local / admin
) else if "%choice%"=="3" (
    echo   - OpenCTI:          http://localhost:8080
    echo     Default login:    admin@opencti.io / ChangeMeNow!
) else if "%choice%"=="4" (
    echo   - SpiderFoot:       http://localhost:5001
) else if "%choice%"=="5" (
    echo   - MISP:             https://localhost:8443
    echo     Default login:    admin@misp.local / admin
)

echo.
echo [WARNING] Important: Change default passwords in production!
echo [INFO] Check logs with: docker-compose logs -f
echo [INFO] Stop services with: docker-compose down
echo.

pause
