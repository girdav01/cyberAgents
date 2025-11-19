# 🛡️ CyberAgents - Multi-Agent Cybersecurity System

A powerful multi-agent cybersecurity analysis system that leverages specialized AI agents to provide comprehensive security insights. Built to run locally with Ollama, LM Studio, or OpenAI-compatible APIs.

## 🌟 Features

- **🤖 Multi-Agent Architecture**: 9 specialized cybersecurity experts working in coordination
- **🧠 Intelligent Orchestration**: Reasoning-based orchestrator using models like PHI-4 or GPT-4o
- **🏠 Local Model Support**: Run completely offline with Ollama or LM Studio
- **🎨 Streamlit Web UI**: Clean, intuitive interface for security analysis
- **🔗 WebHook Integration**: Receive and analyze security events from external systems
- **💬 MCP Protocol Support**: Programmatic access via Model Context Protocol
- **⚡ Concurrent Execution**: Parallel agent execution for faster analysis
- **🔧 Highly Configurable**: YAML-based configuration for easy customization

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Interfaces                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐      │
│  │ Streamlit│  │ WebHook  │  │  MCP Server      │      │
│  │   UI     │  │  Server  │  │  (stdio/chat)    │      │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘      │
└───────┼─────────────┼─────────────────┼─────────────────┘
        │             │                 │
        └─────────────┼─────────────────┘
                      │
        ┌─────────────▼──────────────┐
        │   Orchestrator Agent       │
        │   (Reasoning: PHI-4/GPT-4) │
        └─────────────┬──────────────┘
                      │
        ┌─────────────▼──────────────┐
        │    Task Analysis &         │
        │    Agent Selection         │
        └─────────────┬──────────────┘
                      │
        ┌─────────────▼──────────────┐
        │   Specialist Agents        │
        │  ┌──────────────────────┐  │
        │  │ Offensive Security   │  │
        │  │ • Red Teamer         │  │
        │  │ • Malware RE         │  │
        │  │ • Vuln Researcher    │  │
        │  └──────────────────────┘  │
        │  ┌──────────────────────┐  │
        │  │ Defensive Security   │  │
        │  │ • Blue Teamer        │  │
        │  │ • SOC Analyst        │  │
        │  │ • Code Security      │  │
        │  └──────────────────────┘  │
        │  ┌──────────────────────┐  │
        │  │ Investigation        │  │
        │  │ • Forensics Expert   │  │
        │  │ • Threat Intel       │  │
        │  │ • Threat Researcher  │  │
        │  └──────────────────────┘  │
        └─────────────┬──────────────┘
                      │
        ┌─────────────▼──────────────┐
        │   LLM Provider Layer       │
        │ ┌────────┐ ┌────────┐ ┌───┐│
        │ │ Ollama │ │LMStudio│ │API││
        │ └────────┘ └────────┘ └───┘│
        └────────────────────────────┘
```

## 🚀 Quick Start

Choose your deployment method:
- [🐳 Docker Deployment](#-docker-deployment-recommended) (Recommended - easiest)
- [💻 Local Installation](#-local-installation) (For development)

## 🐳 Docker Deployment (Recommended)

### Quick Start with Docker

```bash
# Clone repository
git clone https://github.com/yourusername/cyberAgents.git
cd cyberAgents

# Copy and configure environment
cp .env.example .env

# Start all services with one command
make first-run

# Or using docker-compose directly
docker-compose up -d
```

Access the services:
- **Streamlit UI**: http://localhost:8501
- **WebHook API**: http://localhost:8502
- **Ollama**: http://localhost:11434

### Common Docker Commands

```bash
# Start services
make up              # or: docker-compose up -d

# View logs
make logs            # or: docker-compose logs -f

# Stop services
make down            # or: docker-compose down

# Restart services
make restart         # or: docker-compose restart

# Pull Ollama models
make pull-models

# See all commands
make help
```

### Production Deployment

```bash
# Build and run with production settings
make prod-build
make prod-up

# Or using docker-compose
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

📚 **Full Docker Documentation**: See [docs/DOCKER_DEPLOYMENT.md](docs/DOCKER_DEPLOYMENT.md) for complete guide including:
- Production deployment with SSL/TLS
- Resource optimization
- Security hardening
- Backup and restore
- Troubleshooting

## 💻 Local Installation

### Prerequisites

1. **Python 3.9+** installed
2. **One of the following LLM providers**:
   - [Ollama](https://ollama.ai/) (recommended for local deployment)
   - [LM Studio](https://lmstudio.ai/)
   - OpenAI API access

### Installation

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/cyberAgents.git
cd cyberAgents
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your settings
```

4. **Set up LLM provider**:

**For Ollama** (recommended):
```bash
# Install Ollama from https://ollama.ai/

# Pull required models
ollama pull phi4           # Reasoning model
ollama pull llama3.2:latest # Specialist agents model
```

**For LM Studio**:
- Download and install LM Studio
- Load PHI-4 or similar reasoning model
- Start the local server on port 1234

**For OpenAI**:
- Set your API key in `.env`: `OPENAI_API_KEY=your_key_here`

### Running the Application

#### Option 1: Streamlit Web UI (Recommended for beginners)

```bash
streamlit run src/ui/streamlit_app.py
```

Then open your browser to `http://localhost:8501`

#### Option 2: WebHook Server (For integration with external systems)

```bash
python src/webhook/server.py
```

Server runs on `http://localhost:8502`

Test with:
```bash
curl -X POST http://localhost:8502/api/security-event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{
    "event_type": "malware_detection",
    "description": "Suspicious PowerShell execution detected",
    "severity": "high",
    "source": "EDR"
  }'
```

#### Option 3: MCP Server (For programmatic access)

```bash
python src/mcp/server.py
```

Use with MCP-compatible clients or integrate into your development environment.

## 📖 Usage Examples

### Example 1: Threat Analysis

**Request**:
```
Analyze this suspicious PowerShell command:
powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0A...
```

**Response**: The orchestrator will:
1. Route to **Malware Reverse Engineer** for script analysis
2. Route to **Cyber Threat Intelligence Expert** for threat correlation
3. Route to **Blue Teamer** for detection recommendations
4. Synthesize a comprehensive response with IOCs and remediation steps

### Example 2: Code Security Review

**Request**:
```python
# Review this authentication function
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    return result
```

**Response**: The **Code Security Expert** will identify:
- SQL injection vulnerabilities
- Plaintext password handling
- Missing input validation
- Provide secure code examples

### Example 3: Incident Investigation

**Request**:
```
Investigate potential data exfiltration:
- Large file transfer to unknown IP 203.0.113.45
- Outside business hours (3 AM)
- User account: admin_backup
```

**Response**: Coordination between:
- **Cyber Forensic Expert** - Timeline analysis
- **SOC Analyst** - Alert correlation
- **Cyber Threat Intelligence Expert** - IP reputation check
- Comprehensive incident report with remediation steps

## ⚙️ Configuration

### Main Configuration: `config/app_config.yaml`

```yaml
llm_provider:
  default: ollama  # ollama, lmstudio, or openai

  ollama:
    base_url: http://localhost:11434
    models:
      reasoning: phi4:latest
      specialist: llama3.2:latest

orchestrator:
  max_iterations: 10
  temperature: 0.7

agents:
  temperature: 0.3
  concurrent_execution: true

web_ui:
  port: 8501
  host: 0.0.0.0

webhook:
  enabled: true
  port: 8502
```

### Specialist Agents: `config/cybersec-system-prompts.json`

Contains detailed configurations for all 9 specialist agents with their:
- System prompts
- Tools and frameworks
- Output formats
- Expertise areas

## 🤖 Available Specialist Agents

### Offensive Security
1. **Red Teamer** - Adversary emulation and penetration testing
2. **Malware Reverse Engineer** - Binary analysis and malware dissection
3. **Vulnerability & Bug Bounty Researcher** - Zero-day discovery and responsible disclosure

### Defensive Security
4. **Blue Teamer** - Threat hunting and detection engineering
5. **SOC Analyst** - Real-time monitoring and incident response
6. **Code Security Expert** - Secure development and code review

### Investigation & Research
7. **Cyber Forensic Expert** - Digital evidence and incident reconstruction
8. **Cyber Threat Intelligence Expert** - Threat correlation and attribution
9. **Cyber Threat Researcher** - Emerging threats and AI-driven attacks

## 🎯 Enhanced Agent Capabilities

Each specialist agent now includes **detailed functions and workflows**:

### 📊 Capabilities Summary
- **81 Specialized Functions** across all 9 agent types
- **27 Predefined Workflows** for common cybersecurity operations
- **40+ Tool Integrations** with API configurations
- **8 Function Categories**: Analysis, Detection, Investigation, Remediation, Research, Exploitation, Defense, Reporting

### 🔧 Function Examples

**Malware Reverse Engineer** (9 functions):
- `static_binary_analysis` - Disassemble and analyze binaries
- `dynamic_malware_analysis` - Sandbox execution and behavior monitoring
- `yara_rule_creation` - Generate detection rules
- `ransomware_analysis` - Specialized ransomware analysis

**Cyber Threat Intelligence Expert** (8 functions):
- `threat_actor_profiling` - Build APT profiles
- `ioc_enrichment` - Enrich indicators with context
- `campaign_tracking` - Track threat campaigns
- `stix_bundle_creation` - Create STIX 2.1 bundles

**SOC Analyst** (8 functions):
- `alert_triage` - Prioritize security alerts
- `log_correlation` - Correlate events across sources
- `endpoint_investigation` - Investigate suspicious endpoints
- `phishing_analysis` - Analyze phishing emails

**Red Teamer** (10 functions):
- `reconnaissance` - OSINT and attack surface mapping
- `vulnerability_exploitation` - Exploit vulnerabilities
- `lateral_movement` - Move across compromised networks
- `credential_harvesting` - Extract credentials
- `data_exfiltration` - Simulate data theft

**Blue Teamer** (9 functions):
- `detection_rule_development` - Create Sigma/YARA rules
- `threat_hunting` - Proactive threat hunting
- `purple_team_exercise` - Coordinate purple team exercises
- `attack_simulation_testing` - Test defenses with Atomic Red Team

### 🔄 Workflow Examples

Each agent includes predefined workflows:

```python
# Execute a complete malware analysis workflow
agent = manager.get_agent_by_id("malware_reverse_engineer")
responses = agent.execute_workflow(
    "complete_malware_triage",
    {"sample_path": "/samples/malware.exe"}
)

# Execute SOC analyst alert-to-resolution workflow
soc_agent = manager.get_agent_by_id("soc_analyst")
responses = soc_agent.execute_workflow(
    "alert_to_resolution",
    {"alert_id": "ALERT-12345"}
)
```

### 📚 Documentation

For complete details on all agent capabilities:
- **Full Documentation**: [`docs/AGENT_CAPABILITIES.md`](docs/AGENT_CAPABILITIES.md)
- **Quick Summary**: [`docs/CAPABILITIES_SUMMARY.md`](docs/CAPABILITIES_SUMMARY.md)
- **Usage Examples**: [`examples/agent_capabilities_example.py`](examples/agent_capabilities_example.py)
- **Tool Integrations**: [`src/tools/tool_integrations.py`](src/tools/tool_integrations.py)

## 🔌 Integration Examples

### WebHook Integration

Integrate with your SIEM, EDR, or security tools:

```python
import requests

response = requests.post(
    'http://localhost:8502/api/security-event',
    headers={'X-API-Key': 'your_api_key'},
    json={
        'event_type': 'intrusion_attempt',
        'description': 'Multiple failed SSH login attempts',
        'severity': 'medium',
        'source': 'SIEM',
        'data': {
            'source_ip': '192.168.1.100',
            'attempts': 15,
            'timestamp': '2024-01-15T10:30:00Z'
        }
    }
)

print(response.json()['analysis'])
```

### MCP Integration

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "cyberagents": {
      "command": "python",
      "args": ["src/mcp/server.py"],
      "cwd": "/path/to/cyberAgents"
    }
  }
}
```

## 🧪 Development

### Project Structure

```
cyberAgents/
├── config/
│   ├── app_config.yaml              # Main configuration
│   └── cybersec-system-prompts.json # Agent definitions
├── src/
│   ├── core/
│   │   ├── llm_provider.py          # LLM abstraction layer
│   │   ├── agent.py                 # Base agent classes
│   │   ├── orchestrator.py          # Orchestrator logic
│   │   └── agent_manager.py         # Agent coordination
│   ├── ui/
│   │   └── streamlit_app.py         # Streamlit interface
│   ├── webhook/
│   │   └── server.py                # WebHook server
│   └── mcp/
│       └── server.py                # MCP server
├── logs/                             # Application logs
├── .env.example                      # Environment template
├── requirements.txt                  # Python dependencies
└── README.md                         # This file
```

### Adding a New Specialist Agent

1. Edit `config/cybersec-system-prompts.json`
2. Add your agent configuration:
```json
{
  "your_agent_id": {
    "role": "Your Agent Name",
    "category": "offensive_security|defensive_security|investigation_research",
    "description": "What this agent does",
    "prompt": "Detailed system prompt for the agent",
    "tools": ["tool1", "tool2"],
    "frameworks": ["framework1"],
    "output_format": "Expected output format"
  }
}
```
3. Restart the application

## 🛠️ Troubleshooting

### Issue: "LLM Provider Offline"

**Solution**:
- Verify Ollama is running: `ollama list`
- Check LM Studio server is started
- Test connection: `curl http://localhost:11434/api/tags` (Ollama)

### Issue: "Agent initialization failed"

**Solution**:
- Check `config/cybersec-system-prompts.json` is valid JSON
- Verify all required models are pulled: `ollama pull phi4`

### Issue: "WebHook authentication failed"

**Solution**:
- Set `WEBHOOK_API_KEY` in `.env`
- Include header: `X-API-Key: your_key` in requests

## 📊 Performance Tips

1. **Use Ollama for best local performance**
2. **Enable concurrent execution** in config (default: true)
3. **Use appropriate model sizes**:
   - Reasoning: phi4 (14B) or llama3.2 (3B)
   - Specialists: llama3.2 (3B) for faster responses
4. **Adjust temperature**:
   - Lower (0.1-0.3) for factual analysis
   - Higher (0.7-0.9) for creative threat scenarios

## 🔒 Security Considerations

- **API Keys**: Never commit `.env` to version control
- **Network**: Bind to `127.0.0.1` instead of `0.0.0.0` for local-only access
- **Rate Limiting**: Configure webhook rate limits for production
- **Input Validation**: Enabled by default, sanitizes all inputs
- **Logs**: Review `logs/cyberagents.log` for security events

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Powered by [Ollama](https://ollama.ai/) / [LM Studio](https://lmstudio.ai/)
- MCP integration via [Model Context Protocol](https://modelcontextprotocol.io/)
- Specialist agent definitions based on industry-standard frameworks (MITRE ATT&CK, OWASP, etc.)

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/cyberAgents/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/cyberAgents/discussions)

---

**Built with ❤️ for the cybersecurity community**
