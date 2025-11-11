"""
Streamlit Web UI for CyberAgents Multi-Agent System
"""

import streamlit as st
import yaml
import json
import logging
from pathlib import Path
from datetime import datetime
import sys

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


@st.cache_resource
def load_config():
    """Load application configuration"""
    config_path = Path("config/app_config.yaml")
    if not config_path.exists():
        st.error(f"Configuration file not found: {config_path}")
        return None

    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


@st.cache_resource
def initialize_agent_manager(_config):
    """Initialize the agent manager (cached)"""
    try:
        return AgentManager(_config)
    except Exception as e:
        st.error(f"Failed to initialize agent manager: {e}")
        logging.error(f"Agent manager initialization error: {e}", exc_info=True)
        return None


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

    # Initialize agent manager
    agent_manager = initialize_agent_manager(config)
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
    tab1, tab2, tab3 = st.tabs(["💬 Analysis", "📊 History", "ℹ️ About"])

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
