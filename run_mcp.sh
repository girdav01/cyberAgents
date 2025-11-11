#!/bin/bash
# Run CyberAgents MCP Server

echo "💬 Starting CyberAgents MCP Server..."
echo ""

# Check if virtual environment exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Check if dependencies are installed
if ! python -c "import mcp" 2>/dev/null; then
    echo "MCP library not found. Installing..."
    pip install mcp
fi

# Create logs directory if it doesn't exist
mkdir -p logs

# Load environment variables
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Run MCP server
python src/mcp/server.py
