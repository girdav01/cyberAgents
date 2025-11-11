"""
MCP (Model Context Protocol) Server for CyberAgents
Provides programmatic access to the multi-agent system
"""

import asyncio
import json
import logging
import yaml
from pathlib import Path
from typing import Any, Dict, List
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.agent_manager import AgentManager

# MCP imports
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        Tool,
        TextContent,
        EmbeddedResource,
        ImageContent,
        INVALID_PARAMS,
        INTERNAL_ERROR
    )
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    logging.warning("MCP library not available. Install with: pip install mcp")

logger = logging.getLogger(__name__)


class CyberAgentsMCPServer:
    """MCP Server for CyberAgents"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.agent_manager = None
        self.server = None

        if MCP_AVAILABLE:
            mcp_config = config.get('mcp', {})
            server_name = mcp_config.get('server_name', 'cyberagents-mcp')
            self.server = Server(server_name)
            self._register_handlers()

    def _register_handlers(self):
        """Register MCP handlers"""
        if not self.server:
            return

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available tools"""
            return [
                Tool(
                    name="analyze_threat",
                    description="Analyze a cybersecurity threat using specialist agents. Provides comprehensive analysis including threat assessment, IOCs, and recommended actions.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "threat_description": {
                                "type": "string",
                                "description": "Description of the threat to analyze"
                            },
                            "threat_type": {
                                "type": "string",
                                "description": "Type of threat (malware, intrusion, vulnerability, etc.)",
                                "enum": ["malware", "intrusion", "vulnerability", "phishing", "other"]
                            },
                            "context": {
                                "type": "object",
                                "description": "Additional context as key-value pairs"
                            }
                        },
                        "required": ["threat_description"]
                    }
                ),
                Tool(
                    name="reverse_malware",
                    description="Reverse engineer a malware sample. Provides detailed analysis including behavior, IOCs, and MITRE ATT&CK mapping.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "sample_info": {
                                "type": "string",
                                "description": "Information about the malware sample (hash, behavior, artifacts)"
                            },
                            "analysis_type": {
                                "type": "string",
                                "description": "Type of analysis",
                                "enum": ["static", "dynamic", "behavioral", "comprehensive"]
                            }
                        },
                        "required": ["sample_info"]
                    }
                ),
                Tool(
                    name="investigate_incident",
                    description="Investigate a security incident. Provides forensic analysis, timeline reconstruction, and remediation recommendations.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "incident_description": {
                                "type": "string",
                                "description": "Description of the security incident"
                            },
                            "incident_type": {
                                "type": "string",
                                "description": "Type of incident",
                                "enum": ["data_breach", "ransomware", "apt", "insider_threat", "other"]
                            },
                            "evidence": {
                                "type": "object",
                                "description": "Available evidence and artifacts"
                            }
                        },
                        "required": ["incident_description"]
                    }
                ),
                Tool(
                    name="review_code_security",
                    description="Review code for security vulnerabilities. Identifies issues like injection flaws, authentication problems, and provides remediation guidance.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "code": {
                                "type": "string",
                                "description": "Code to review"
                            },
                            "language": {
                                "type": "string",
                                "description": "Programming language"
                            },
                            "context": {
                                "type": "string",
                                "description": "Context about the code's purpose"
                            }
                        },
                        "required": ["code"]
                    }
                ),
                Tool(
                    name="research_vulnerability",
                    description="Research and analyze a vulnerability. Provides exploitation analysis, impact assessment, and mitigation strategies.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "vulnerability_id": {
                                "type": "string",
                                "description": "CVE ID or vulnerability identifier"
                            },
                            "vulnerability_description": {
                                "type": "string",
                                "description": "Description of the vulnerability"
                            },
                            "affected_system": {
                                "type": "string",
                                "description": "Affected system or component"
                            }
                        },
                        "required": ["vulnerability_description"]
                    }
                ),
                Tool(
                    name="analyze_general",
                    description="General cybersecurity analysis using the multi-agent system. Routes to appropriate specialists automatically.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "request": {
                                "type": "string",
                                "description": "Analysis request"
                            },
                            "context": {
                                "type": "object",
                                "description": "Additional context"
                            }
                        },
                        "required": ["request"]
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> List[TextContent]:
            """Handle tool calls"""
            try:
                if not self.agent_manager:
                    return [TextContent(
                        type="text",
                        text="Error: Agent manager not initialized"
                    )]

                # Route to appropriate handler
                if name == "analyze_threat":
                    result = await self._handle_analyze_threat(arguments)
                elif name == "reverse_malware":
                    result = await self._handle_reverse_malware(arguments)
                elif name == "investigate_incident":
                    result = await self._handle_investigate_incident(arguments)
                elif name == "review_code_security":
                    result = await self._handle_review_code_security(arguments)
                elif name == "research_vulnerability":
                    result = await self._handle_research_vulnerability(arguments)
                elif name == "analyze_general":
                    result = await self._handle_analyze_general(arguments)
                else:
                    return [TextContent(
                        type="text",
                        text=f"Error: Unknown tool '{name}'"
                    )]

                return [TextContent(type="text", text=result)]

            except Exception as e:
                logger.error(f"Error in tool call {name}: {e}", exc_info=True)
                return [TextContent(
                    type="text",
                    text=f"Error processing request: {str(e)}"
                )]

    async def _handle_analyze_threat(self, arguments: Dict[str, Any]) -> str:
        """Handle threat analysis request"""
        threat_description = arguments.get('threat_description')
        threat_type = arguments.get('threat_type', 'unknown')
        context = arguments.get('context', {})

        request = f"""Threat Analysis Request:

Type: {threat_type}

Description:
{threat_description}

Please provide a comprehensive threat analysis including:
1. Threat assessment and severity
2. Indicators of Compromise (IOCs)
3. MITRE ATT&CK mapping
4. Recommended detection and mitigation strategies
"""

        context['threat_type'] = threat_type
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_reverse_malware(self, arguments: Dict[str, Any]) -> str:
        """Handle malware reverse engineering request"""
        sample_info = arguments.get('sample_info')
        analysis_type = arguments.get('analysis_type', 'comprehensive')

        request = f"""Malware Reverse Engineering Request:

Analysis Type: {analysis_type}

Sample Information:
{sample_info}

Please perform {analysis_type} analysis and provide:
1. Malware behavior and capabilities
2. IOCs (hashes, domains, IPs, file paths)
3. MITRE ATT&CK techniques used
4. Yara rules for detection
5. Remediation recommendations
"""

        context = {'analysis_type': analysis_type}
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_investigate_incident(self, arguments: Dict[str, Any]) -> str:
        """Handle incident investigation request"""
        incident_description = arguments.get('incident_description')
        incident_type = arguments.get('incident_type', 'unknown')
        evidence = arguments.get('evidence', {})

        request = f"""Security Incident Investigation:

Incident Type: {incident_type}

Description:
{incident_description}

Evidence:
{json.dumps(evidence, indent=2)}

Please provide:
1. Incident timeline reconstruction
2. Root cause analysis
3. Scope and impact assessment
4. Forensic findings
5. Containment and remediation steps
"""

        context = {'incident_type': incident_type}
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_review_code_security(self, arguments: Dict[str, Any]) -> str:
        """Handle code security review request"""
        code = arguments.get('code')
        language = arguments.get('language', 'unknown')
        context_desc = arguments.get('context', '')

        request = f"""Code Security Review:

Language: {language}
Context: {context_desc}

Code:
```
{code}
```

Please review this code for security vulnerabilities including:
1. Injection flaws (SQL, XSS, Command Injection)
2. Authentication and authorization issues
3. Data exposure risks
4. Cryptographic problems
5. Other OWASP Top 10 vulnerabilities

Provide specific remediation recommendations.
"""

        context = {'language': language}
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_research_vulnerability(self, arguments: Dict[str, Any]) -> str:
        """Handle vulnerability research request"""
        vuln_id = arguments.get('vulnerability_id', 'N/A')
        vuln_description = arguments.get('vulnerability_description')
        affected_system = arguments.get('affected_system', 'unknown')

        request = f"""Vulnerability Research:

Vulnerability ID: {vuln_id}
Affected System: {affected_system}

Description:
{vuln_description}

Please provide:
1. Vulnerability analysis and technical details
2. Exploitation likelihood and impact (CVSS scoring)
3. Proof of concept (if applicable)
4. Mitigation and remediation strategies
5. Compensating controls
"""

        context = {
            'vulnerability_id': vuln_id,
            'affected_system': affected_system
        }
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_analyze_general(self, arguments: Dict[str, Any]) -> str:
        """Handle general analysis request"""
        request = arguments.get('request')
        context = arguments.get('context', {})

        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    def _format_result(self, result: Dict[str, Any]) -> str:
        """Format the result for MCP response"""
        response = f"""# CyberAgents Analysis Result

**Task ID:** `{result.get('task_id', 'N/A')}`

"""

        if result.get('decision'):
            decision = result['decision']
            response += f"""## Orchestrator Decision

**Analysis:** {decision.get('analysis', 'N/A')}

**Reasoning:** {decision.get('reasoning', 'N/A')}

**Specialists Used:** {', '.join(decision.get('selected_agents', []))}

---

"""

        response += f"""## Analysis

{result.get('response', 'No response generated')}
"""

        if result.get('agent_responses'):
            response += "\n---\n\n## Specialist Responses\n\n"
            for i, agent_resp in enumerate(result['agent_responses'], 1):
                response += f"""### {i}. {agent_resp['role']}

{agent_resp['content']}

"""

        return response

    def initialize(self):
        """Initialize the MCP server"""
        logger.info("Initializing CyberAgents MCP Server")

        # Initialize agent manager
        self.agent_manager = AgentManager(self.config)
        logger.info("Agent manager initialized for MCP server")

    async def run(self):
        """Run the MCP server"""
        if not MCP_AVAILABLE:
            raise RuntimeError("MCP library not available. Install with: pip install mcp")

        self.initialize()

        async with stdio_server() as (read_stream, write_stream):
            logger.info("MCP server running on stdio")
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


def load_config():
    """Load application configuration"""
    config_path = Path("config/app_config.yaml")
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


async def main():
    """Main entry point for MCP server"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    config = load_config()

    server = CyberAgentsMCPServer(config)
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
