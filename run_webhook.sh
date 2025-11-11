#!/bin/bash
# Run CyberAgents WebHook Server

echo "🔗 Starting CyberAgents WebHook Server..."
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Check if dependencies are installed
if ! python -c "import flask" 2>/dev/null; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
fi

# Create logs directory if it doesn't exist
mkdir -p logs

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Run webhook server
python src/webhook/server.py
