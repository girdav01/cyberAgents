"""
Streamlit Web UI for CyberAgents Multi-Agent System
"""

import streamlit as st
import yaml
import json
import logging
import requests
from pathlib import Path
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.agent_manager import AgentManager

# Page configuration
st.set_page_config(
    page_title="CyberAgents - Multi-Agent Cybersecurity System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 1rem;
    }
    .agent-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .response-box {
        background-color: #e8f4f8;
        padding: 1.5rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
        margin: 1rem 0;
    }
    .specialist-response {
        background-color: #f9f9f9;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        border-left: 3px solid #ff7f0e;
    }
</style>
""", unsafe_allow_html=True)


def load_config():
    """Load application configuration"""
    config_path = Path("config/app_config.yaml")
    if not config_path.exists():
        st.error(f"Configuration file not found: {config_path}")
        return None

    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def save_config(config):
    """Save application configuration"""
    config_path = Path("config/app_config.yaml")
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        return True
    except Exception as e:
        st.error(f"Failed to save configuration: {e}")
        return False


def initialize_agent_manager(_config):
    """Initialize the agent manager"""
    try:
        return AgentManager(_config)
    except Exception as e:
        st.error(f"Failed to initialize agent manager: {e}")
        logging.error(f"Agent manager initialization error: {e}", exc_info=True)
        return None


def test_llm_connection(provider, base_url, api_key=None):
    """Test connection to LLM provider"""
    try:
        if provider == "ollama":
            response = requests.get(f"{base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return True, f"Connected! Found {len(models)} models"
            return False, f"Connection failed: {response.status_code}"

        elif provider == "lmstudio":
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            response = requests.get(f"{base_url}/models", headers=headers, timeout=5)
            if response.status_code == 200:
                return True, "Connected to LM Studio!"
            return False, f"Connection failed: {response.status_code}"

        elif provider == "openai":
            if not api_key or api_key == "your_openai_api_key_here":
                return False, "Please provide a valid OpenAI API key"
            headers = {"Authorization": f"Bearer {api_key}"}
            response = requests.get(f"{base_url}/models", headers=headers, timeout=5)
            if response.status_code == 200:
                return True, "Connected to OpenAI!"
            return False, f"Connection failed: {response.status_code}"

        return False, "Unknown provider"

    except requests.exceptions.Timeout:
        return False, "Connection timeout - is the service running?"
    except requests.exceptions.ConnectionError:
        return False, "Cannot connect - check URL and ensure service is running"
    except Exception as e:
        return False, f"Error: {str(e)}"


def render_llm_settings():
    """Render LLM configuration settings"""
    st.markdown("### ⚙️ LLM Provider Configuration")
    st.markdown("Configure your Large Language Model provider settings.")

    # Load current config
    config = load_config()
    if not config:
        st.error("Cannot load configuration")
        return

    llm_config = config.get('llm_provider', {})
    current_provider = llm_config.get('default', 'ollama')

    # Provider selection
    st.markdown("#### 1️⃣ Select LLM Provider")
    provider = st.radio(
        "Choose your LLM provider:",
        options=['ollama', 'lmstudio', 'openai'],
        index=['ollama', 'lmstudio', 'openai'].index(current_provider),
        horizontal=True
    )

    st.markdown("---")

    # Provider-specific configuration
    if provider == "ollama":
        st.markdown("#### 2️⃣ Ollama Configuration")
        st.info("💡 Ollama runs locally on your machine. [Download Ollama](https://ollama.ai/)")

        ollama_config = llm_config.get('ollama', {})

        base_url = st.text_input(
            "Base URL",
            value=ollama_config.get('base_url', 'http://localhost:11434'),
            help="URL where Ollama is running"
        )

        col1, col2 = st.columns(2)
        with col1:
            reasoning_model = st.text_input(
                "Reasoning Model",
                value=ollama_config.get('models', {}).get('reasoning', 'phi4:latest'),
                help="Model for orchestrator reasoning (e.g., phi4:latest)"
            )
        with col2:
            specialist_model = st.text_input(
                "Specialist Model",
                value=ollama_config.get('models', {}).get('specialist', 'llama3.2:latest'),
                help="Model for specialist agents (e.g., llama3.2:latest)"
            )

        timeout = st.number_input(
            "Timeout (seconds)",
            value=ollama_config.get('timeout', 300),
            min_value=30,
            max_value=600,
            step=30
        )

        # Test connection
        if st.button("🔌 Test Connection", key="test_ollama"):
            with st.spinner("Testing connection..."):
                success, message = test_llm_connection(provider, base_url)
                if success:
                    st.success(f"✅ {message}")
                else:
                    st.error(f"❌ {message}")

        # Save configuration
        if st.button("💾 Save Configuration", type="primary", key="save_ollama"):
            llm_config['default'] = provider
            llm_config['ollama'] = {
                'base_url': base_url,
                'models': {
                    'reasoning': reasoning_model,
                    'specialist': specialist_model,
                    'embedding': ollama_config.get('models', {}).get('embedding', 'nomic-embed-text:latest')
                },
                'timeout': timeout
            }
            config['llm_provider'] = llm_config

            if save_config(config):
                st.success("✅ Configuration saved! Please restart the app to apply changes.")
                # Clear cache
                if 'agent_manager' in st.session_state:
                    del st.session_state['agent_manager']

    elif provider == "lmstudio":
        st.markdown("#### 2️⃣ LM Studio Configuration")
        st.info("💡 LM Studio provides a local LLM server. [Download LM Studio](https://lmstudio.ai/)")

        lmstudio_config = llm_config.get('lmstudio', {})

        base_url = st.text_input(
            "Base URL",
            value=lmstudio_config.get('base_url', 'http://localhost:1234/v1'),
            help="URL where LM Studio server is running"
        )

        api_key = st.text_input(
            "API Key",
            value=lmstudio_config.get('api_key', 'lm-studio'),
            help="LM Studio doesn't require a real API key",
            type="password"
        )

        col1, col2 = st.columns(2)
        with col1:
            reasoning_model = st.text_input(
                "Reasoning Model",
                value=lmstudio_config.get('models', {}).get('reasoning', 'phi-4'),
                help="Model name in LM Studio"
            )
        with col2:
            specialist_model = st.text_input(
                "Specialist Model",
                value=lmstudio_config.get('models', {}).get('specialist', 'llama-3.2-3b'),
                help="Model name in LM Studio"
            )

        timeout = st.number_input(
            "Timeout (seconds)",
            value=lmstudio_config.get('timeout', 300),
            min_value=30,
            max_value=600,
            step=30
        )

        # Test connection
        if st.button("🔌 Test Connection", key="test_lmstudio"):
            with st.spinner("Testing connection..."):
                success, message = test_llm_connection(provider, base_url, api_key)
                if success:
                    st.success(f"✅ {message}")
                else:
                    st.error(f"❌ {message}")

        # Save configuration
        if st.button("💾 Save Configuration", type="primary", key="save_lmstudio"):
            llm_config['default'] = provider
            llm_config['lmstudio'] = {
                'base_url': base_url,
                'models': {
                    'reasoning': reasoning_model,
                    'specialist': specialist_model
                },
                'timeout': timeout,
                'api_key': api_key
            }
            config['llm_provider'] = llm_config

            if save_config(config):
                st.success("✅ Configuration saved! Please restart the app to apply changes.")
                if 'agent_manager' in st.session_state:
                    del st.session_state['agent_manager']

    elif provider == "openai":
        st.markdown("#### 2️⃣ OpenAI Configuration")
        st.info("💡 Requires an OpenAI API key. [Get API Key](https://platform.openai.com/api-keys)")

        openai_config = llm_config.get('openai', {})

        base_url = st.text_input(
            "Base URL",
            value=openai_config.get('base_url', 'https://api.openai.com/v1'),
            help="OpenAI API endpoint"
        )

        api_key = st.text_input(
            "API Key",
            value=os.getenv('OPENAI_API_KEY', openai_config.get('api_key', '')),
            help="Your OpenAI API key",
            type="password"
        )

        col1, col2 = st.columns(2)
        with col1:
            reasoning_model = st.text_input(
                "Reasoning Model",
                value=openai_config.get('models', {}).get('reasoning', 'gpt-4o'),
                help="Model for orchestrator (e.g., gpt-4o)"
            )
        with col2:
            specialist_model = st.text_input(
                "Specialist Model",
                value=openai_config.get('models', {}).get('specialist', 'gpt-4o-mini'),
                help="Model for specialists (e.g., gpt-4o-mini)"
            )

        timeout = st.number_input(
            "Timeout (seconds)",
            value=openai_config.get('timeout', 300),
            min_value=30,
            max_value=600,
            step=30
        )

        # Test connection
        if st.button("🔌 Test Connection", key="test_openai"):
            with st.spinner("Testing connection..."):
                success, message = test_llm_connection(provider, base_url, api_key)
                if success:
                    st.success(f"✅ {message}")
                else:
                    st.error(f"❌ {message}")

        # Save configuration
        if st.button("💾 Save Configuration", type="primary", key="save_openai"):
            llm_config['default'] = provider
            llm_config['openai'] = {
                'base_url': base_url,
                'models': {
                    'reasoning': reasoning_model,
                    'specialist': specialist_model
                },
                'timeout': timeout,
                'api_key': '${OPENAI_API_KEY}'  # Reference env var
            }
            config['llm_provider'] = llm_config

            if save_config(config):
                st.success("✅ Configuration saved!")
                st.info("💡 Make sure to set OPENAI_API_KEY environment variable")
                if 'agent_manager' in st.session_state:
                    del st.session_state['agent_manager']

    # Quick Setup Guide
    st.markdown("---")
    with st.expander("📖 Quick Setup Guide", expanded=False):
        st.markdown("""
        ### Ollama Setup

        1. Download and install Ollama from [ollama.ai](https://ollama.ai/)
        2. Pull required models:
           ```bash
           ollama pull phi4
           ollama pull llama3.2
           ```
        3. Verify Ollama is running: `ollama list`
        4. Use default settings above

        ### LM Studio Setup

        1. Download LM Studio from [lmstudio.ai](https://lmstudio.ai/)
        2. Download and load your preferred models
        3. Start the local server (default port: 1234)
        4. Use default settings above

        ### OpenAI Setup

        1. Sign up at [platform.openai.com](https://platform.openai.com/)
        2. Generate an API key
        3. Set environment variable: `export OPENAI_API_KEY=your_key`
        4. Enter the key above or use environment variable

        ### Troubleshooting

        - **Connection Failed**: Ensure the service is running
        - **Timeout**: Increase timeout value or check network
        - **Invalid Models**: Verify model names with your provider
        - **API Key Issues**: Check key validity and permissions
        """)

    # Model Management (for Ollama)
    if provider == "ollama":
        st.markdown("---")
        st.markdown("#### 📦 Manage Ollama Models")

        if st.button("🔄 Refresh Model List"):
            with st.spinner("Fetching models..."):
                success, message = test_llm_connection(provider, base_url)
                if success:
                    try:
                        response = requests.get(f"{base_url}/api/tags", timeout=5)
                        models = response.json().get('models', [])
                        st.success(f"Found {len(models)} models:")
                        for model in models:
                            st.text(f"  • {model['name']}")
                    except Exception as e:
                        st.error(f"Error fetching models: {e}")
                else:
                    st.error(message)


def display_agent_info(agents_info):
    """Display available agents in sidebar"""
    st.sidebar.markdown("### 🤖 Available Specialists")

    categories = {}
    for agent in agents_info:
        category = agent.get('category', 'general')
        if category not in categories:
            categories[category] = []
        categories[category].append(agent)

    for category, agents in categories.items():
        with st.sidebar.expander(f"📁 {category.replace('_', ' ').title()}", expanded=False):
            for agent in agents:
                st.markdown(f"""
                **{agent['name']}**
                {agent['description']}
                """)


def display_decision(decision):
    """Display orchestrator's decision"""
    with st.expander("🧠 Orchestrator Analysis", expanded=True):
        st.markdown("**Analysis:**")
        st.info(decision.get('analysis', 'N/A'))

        st.markdown("**Reasoning:**")
        st.write(decision.get('reasoning', 'N/A'))

        selected = decision.get('selected_agents', [])
        if selected:
            st.markdown("**Selected Specialists:**")
            for agent_id in selected:
                st.markdown(f"- `{agent_id}`")


def display_specialist_responses(responses):
    """Display individual specialist responses"""
    if not responses:
        return

    st.markdown("### 👥 Specialist Responses")

    for i, response in enumerate(responses, 1):
        with st.expander(f"{i}. {response['role']}", expanded=False):
            if response.get('error'):
                st.error(f"Error: {response['error']}")
            else:
                st.markdown(response['content'])


def main():
    """Main Streamlit application"""

    # Header
    st.markdown('<p class="main-header">🛡️ CyberAgents</p>', unsafe_allow_html=True)
    st.markdown("**Multi-Agent Cybersecurity Analysis System**")

    # Load configuration
    config = load_config()
    if not config:
        st.stop()

    # Initialize agent manager (with session state caching)
    if 'agent_manager' not in st.session_state:
        st.session_state.agent_manager = initialize_agent_manager(config)

    agent_manager = st.session_state.agent_manager
    if not agent_manager:
        st.stop()

    # Sidebar - Agent Information
    agents_info = agent_manager.get_available_agents()
    display_agent_info(agents_info)

    # Sidebar - System Status
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ⚙️ System Status")

    provider_config = config.get('llm_provider', {})
    default_provider = provider_config.get('default', 'unknown')
    st.sidebar.info(f"**Provider:** {default_provider.upper()}")

    if agent_manager.llm_provider.is_available():
        st.sidebar.success("✅ LLM Provider Online")
    else:
        st.sidebar.warning("⚠️ LLM Provider Offline")

    st.sidebar.info(f"**Specialists:** {len(agents_info)}")

    # Main interface
    st.markdown("---")

    # Tab interface
    tab1, tab2, tab3, tab4 = st.tabs(["💬 Analysis", "📊 History", "⚙️ Settings", "ℹ️ About"])

    with tab1:
        st.markdown("### Submit Security Analysis Request")

        # Request input
        request = st.text_area(
            "Enter your cybersecurity query or analysis request:",
            height=150,
            placeholder="Example: Analyze this suspicious PowerShell script...\nExample: How can I detect lateral movement in my network?\nExample: Review this code for SQL injection vulnerabilities..."
        )

        # Context input (optional)
        with st.expander("⚙️ Additional Context (Optional)", expanded=False):
            context_input = st.text_area(
                "Provide additional context (JSON format):",
                height=100,
                placeholder='{"environment": "production", "urgency": "high"}'
            )

        col1, col2 = st.columns([1, 5])
        with col1:
            analyze_button = st.button("🔍 Analyze", type="primary", use_container_width=True)
        with col2:
            clear_button = st.button("🗑️ Clear", use_container_width=True)

        if clear_button:
            st.rerun()

        if analyze_button:
            if not request.strip():
                st.warning("Please enter a request")
            else:
                # Parse context
                context = None
                if context_input.strip():
                    try:
                        context = json.loads(context_input)
                    except json.JSONDecodeError:
                        st.warning("Invalid JSON in context, proceeding without it")

                # Process request
                with st.spinner("🤔 Orchestrator is analyzing your request..."):
                    try:
                        result = agent_manager.process_request(request, context)

                        # Store in session state
                        if 'history' not in st.session_state:
                            st.session_state.history = []

                        st.session_state.history.append({
                            'timestamp': datetime.now(),
                            'request': request,
                            'result': result
                        })

                        # Display results
                        st.markdown("---")
                        st.markdown("## 📋 Analysis Results")

                        # Display orchestrator decision
                        if 'decision' in result:
                            display_decision(result['decision'])

                        # Display final synthesized response
                        st.markdown("### 🎯 Comprehensive Analysis")
                        st.markdown('<div class="response-box">', unsafe_allow_html=True)
                        st.markdown(result.get('response', 'No response generated'))
                        st.markdown('</div>', unsafe_allow_html=True)

                        # Display individual specialist responses
                        if result.get('agent_responses'):
                            display_specialist_responses(result['agent_responses'])

                        # Task ID
                        st.caption(f"Task ID: `{result.get('task_id', 'N/A')}`")

                    except Exception as e:
                        st.error(f"Error processing request: {e}")
                        logging.error(f"Request processing error: {e}", exc_info=True)

    with tab2:
        st.markdown("### 📊 Analysis History")

        if 'history' not in st.session_state or not st.session_state.history:
            st.info("No analysis history yet. Submit a request in the Analysis tab.")
        else:
            for i, item in enumerate(reversed(st.session_state.history), 1):
                with st.expander(
                    f"{item['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - {item['request'][:60]}...",
                    expanded=(i == 1)
                ):
                    st.markdown("**Request:**")
                    st.code(item['request'])

                    st.markdown("**Response:**")
                    st.markdown(item['result'].get('response', 'N/A'))

                    if item['result'].get('decision'):
                        st.markdown("**Agents Used:**")
                        st.write(item['result']['decision'].get('selected_agents', []))

            if st.button("🗑️ Clear History"):
                st.session_state.history = []
                st.rerun()

    with tab3:
        render_llm_settings()

    with tab4:
        st.markdown("### ℹ️ About CyberAgents")

        st.markdown("""
        **CyberAgents** is a multi-agent cybersecurity analysis system that leverages specialized AI agents to provide comprehensive security insights.

        #### 🏗️ Architecture

        - **Orchestrator Agent**: Uses reasoning models (PHI-4, GPT-4) to coordinate specialists
        - **Specialist Agents**: 9 domain-specific cybersecurity experts
        - **LLM Providers**: Supports Ollama, LM Studio, and OpenAI
        - **Concurrent Execution**: Parallel agent execution for faster analysis

        #### 🔧 Features

        - Multi-agent coordination and task routing
        - Reasoning-based orchestration
        - Local model support (Ollama, LM Studio)
        - WebHook integration for external events
        - MCP server for programmatic access
        - Comprehensive security analysis across multiple domains

        #### 🛠️ Technology Stack

        - **Framework**: Custom lightweight agent framework
        - **UI**: Streamlit
        - **LLM Providers**: Ollama / LM Studio / OpenAI
        - **Configuration**: YAML + JSON

        #### 📚 Specialist Categories

        1. **Offensive Security**: Red Teamer, Malware Reverse Engineer, Vulnerability Researcher
        2. **Defensive Security**: Blue Teamer, SOC Analyst, Code Security Expert
        3. **Investigation & Research**: Cyber Forensic Expert, Threat Intelligence Expert, Threat Researcher

        """)

        st.markdown("---")
        st.caption("Built with ❤️ for the cybersecurity community")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    main()
