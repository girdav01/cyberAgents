# 🚀 CyberAgents Quick Start Guide

Get up and running with CyberAgents in 5 minutes!

## Step 1: Install Ollama (Recommended)

The easiest way to run CyberAgents locally is with Ollama.

### On macOS/Linux:
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

### On Windows:
Download from [ollama.ai](https://ollama.ai/download)

### Pull Required Models:
```bash
# Reasoning model for orchestrator (choose one):
ollama pull phi4              # Recommended - Microsoft PHI-4 (14B)
# OR
ollama pull llama3.2:latest   # Alternative - Meta Llama 3.2 (3B)

# Specialist model (faster, smaller):
ollama pull llama3.2:latest   # Meta Llama 3.2 (3B)
```

## Step 2: Install CyberAgents

```bash
# Clone repository
git clone https://github.com/yourusername/cyberAgents.git
cd cyberAgents

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Step 3: Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env if needed (defaults work with Ollama)
# LLM_PROVIDER=ollama  # already set
```

## Step 4: Start the Web UI

### On Linux/macOS:
```bash
chmod +x run_webui.sh
./run_webui.sh
```

### On Windows:
```bash
streamlit run src/ui/streamlit_app.py
```

### Or directly:
```bash
streamlit run src/ui/streamlit_app.py
```

🎉 **That's it!** Open your browser to `http://localhost:8501`

## Example Queries to Try

### 1. Malware Analysis
```
Analyze this suspicious PowerShell command:
powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0A

What does it do and how can I detect it?
```

### 2. Code Security Review
```
Review this login function for security issues:

def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)
```

### 3. Threat Intelligence
```
Analyze recent activity from IP 203.0.113.45:
- Port scans on ports 22, 3389, 445
- Failed authentication attempts
- Suspicious user agent strings

Should we block this IP?
```

### 4. Incident Investigation
```
We detected:
- Unusual outbound traffic to 45.33.32.156:443
- At 3 AM (outside business hours)
- From user account: admin_backup
- Large file transfer (2.5 GB)

Investigate this potential data exfiltration.
```

### 5. Red Team Planning
```
Plan a red team exercise to test our defenses against:
- Phishing with credential harvesting
- Lateral movement techniques
- Data exfiltration via DNS tunneling

What tools and techniques should we use?
```

## Verifying Everything Works

1. **Check Ollama is running**:
```bash
ollama list
```
You should see `phi4` and `llama3.2:latest` in the list.

2. **Test Ollama connectivity**:
```bash
curl http://localhost:11434/api/tags
```
You should get a JSON response with available models.

3. **Check CyberAgents UI**:
- Open `http://localhost:8501`
- Look for "✅ LLM Provider Online" in the sidebar
- You should see "Specialists: 9"

## Troubleshooting

### "Connection refused" error

**Problem**: Ollama not running
**Solution**:
```bash
# Start Ollama
ollama serve
```

### "Model not found" error

**Problem**: Models not pulled
**Solution**:
```bash
ollama pull phi4
ollama pull llama3.2:latest
```

### Slow responses

**Problem**: Large model or CPU inference
**Solution**:
- Use smaller models: `ollama pull llama3.2:latest`
- Configure in `config/app_config.yaml`:
```yaml
llm_provider:
  ollama:
    models:
      reasoning: llama3.2:latest  # Use faster 3B model
      specialist: llama3.2:latest
```

### Import errors

**Problem**: Dependencies not installed
**Solution**:
```bash
pip install -r requirements.txt
```

## Next Steps

- 📖 Read the full [README.md](README.md) for advanced configuration
- 🔗 Set up [WebHook Integration](README.md#webhook-integration) for SIEM/EDR integration
- 💬 Configure [MCP Server](README.md#mcp-integration) for programmatic access
- ⚙️ Customize agents in `config/cybersec-system-prompts.json`

## Performance Tips for Local Deployment

### For Fast Responses (Recommended for most users):
```yaml
# config/app_config.yaml
llm_provider:
  ollama:
    models:
      reasoning: llama3.2:latest  # 3B model - fast
      specialist: llama3.2:latest # 3B model - fast
```

### For Best Quality (Requires more resources):
```yaml
# config/app_config.yaml
llm_provider:
  ollama:
    models:
      reasoning: phi4:latest      # 14B model - better reasoning
      specialist: llama3.2:latest # 3B model - balanced
```

### For Maximum Performance (Requires GPU):
- Use quantized models: `ollama pull phi4:q4_K_M`
- Enable GPU acceleration (automatic with CUDA/Metal)

## Using Alternative Providers

### LM Studio

1. Download from [lmstudio.ai](https://lmstudio.ai)
2. Load PHI-4 or similar model
3. Start local server (port 1234)
4. Update `.env`:
```
LLM_PROVIDER=lmstudio
```

### OpenAI API

1. Get API key from [platform.openai.com](https://platform.openai.com)
2. Update `.env`:
```
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

## Support

Need help?
- 📝 Check [README.md](README.md) for detailed docs
- 🐛 Report issues on [GitHub](https://github.com/yourusername/cyberAgents/issues)
- 💡 Join discussions for tips and tricks

---

**Happy threat hunting! 🛡️**
