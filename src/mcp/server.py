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
                ),
                Tool(
                    name="enrich_ioc_opencti",
                    description="Enrich indicators of compromise using OpenCTI threat intelligence platform. Provides context, relationships, and threat actor attribution.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "indicator": {
                                "type": "string",
                                "description": "IOC to enrich (IP, domain, hash, etc.)"
                            },
                            "indicator_type": {
                                "type": "string",
                                "description": "Type of indicator",
                                "enum": ["ip", "domain", "hash", "email", "url", "file"]
                            }
                        },
                        "required": ["indicator", "indicator_type"]
                    }
                ),
                Tool(
                    name="osint_reconnaissance",
                    description="Perform OSINT reconnaissance using SpiderFoot. Gathers intelligence from multiple sources including DNS, WHOIS, social media, and breach databases.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target for reconnaissance (domain, IP, email, company name)"
                            },
                            "scan_type": {
                                "type": "string",
                                "description": "Type of scan",
                                "enum": ["passive", "active", "comprehensive"]
                            },
                            "modules": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific SpiderFoot modules to run (optional)"
                            }
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="query_misp_events",
                    description="Query MISP threat intelligence platform for events and indicators. Searches across threat events, attributes, and IOCs.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "search_query": {
                                "type": "string",
                                "description": "Search query (IOC, tag, event name, etc.)"
                            },
                            "search_type": {
                                "type": "string",
                                "description": "Type of search",
                                "enum": ["events", "attributes", "objects", "tags"]
                            },
                            "time_range": {
                                "type": "string",
                                "description": "Time range for search (e.g., '7d', '30d', '1y')"
                            }
                        },
                        "required": ["search_query"]
                    }
                ),
                Tool(
                    name="analyze_file_sandbox",
                    description="Submit a file for analysis in Trend Vision One Sandbox. Provides behavioral analysis, network activity, and MITRE ATT&CK mapping.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "file_info": {
                                "type": "string",
                                "description": "File information (hash, path, or description)"
                            },
                            "analysis_environment": {
                                "type": "string",
                                "description": "Analysis environment",
                                "enum": ["windows7", "windows10", "windows11", "linux", "android"]
                            },
                            "analysis_timeout": {
                                "type": "number",
                                "description": "Analysis timeout in seconds (default: 300)"
                            }
                        },
                        "required": ["file_info"]
                    }
                ),
                Tool(
                    name="create_threat_report",
                    description="Create a comprehensive threat intelligence report combining data from multiple sources (OpenCTI, MISP, SpiderFoot).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "threat_name": {
                                "type": "string",
                                "description": "Name or identifier of the threat"
                            },
                            "iocs": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of IOCs to include in report"
                            },
                            "include_osint": {
                                "type": "boolean",
                                "description": "Include OSINT data from SpiderFoot"
                            },
                            "export_format": {
                                "type": "string",
                                "description": "Report format",
                                "enum": ["markdown", "json", "pdf", "stix"]
                            }
                        },
                        "required": ["threat_name"]
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
                elif name == "enrich_ioc_opencti":
                    result = await self._handle_enrich_ioc_opencti(arguments)
                elif name == "osint_reconnaissance":
                    result = await self._handle_osint_reconnaissance(arguments)
                elif name == "query_misp_events":
                    result = await self._handle_query_misp_events(arguments)
                elif name == "analyze_file_sandbox":
                    result = await self._handle_analyze_file_sandbox(arguments)
                elif name == "create_threat_report":
                    result = await self._handle_create_threat_report(arguments)
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

    async def _handle_enrich_ioc_opencti(self, arguments: Dict[str, Any]) -> str:
        """Handle IOC enrichment using OpenCTI"""
        indicator = arguments.get('indicator')
        indicator_type = arguments.get('indicator_type')

        request = f"""IOC Enrichment Request (OpenCTI):

Indicator: {indicator}
Type: {indicator_type}

Please enrich this indicator using threat intelligence analysis:
1. Query OpenCTI knowledge base for related entities
2. Identify associated threat actors and campaigns
3. Find related IOCs and patterns
4. Provide STIX 2.1 relationships
5. Assess threat severity and confidence
6. Provide mitigation recommendations

Use the Cyber Threat Intelligence Expert to correlate this indicator with known threats.
"""

        context = {
            'indicator': indicator,
            'indicator_type': indicator_type,
            'tool': 'opencti'
        }
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_osint_reconnaissance(self, arguments: Dict[str, Any]) -> str:
        """Handle OSINT reconnaissance using SpiderFoot"""
        target = arguments.get('target')
        scan_type = arguments.get('scan_type', 'passive')
        modules = arguments.get('modules', [])

        modules_str = ", ".join(modules) if modules else "all relevant modules"

        request = f"""OSINT Reconnaissance Request (SpiderFoot):

Target: {target}
Scan Type: {scan_type}
Modules: {modules_str}

Please perform comprehensive OSINT reconnaissance:
1. DNS enumeration and subdomain discovery
2. WHOIS and domain registration information
3. Social media presence and leaked credentials
4. Dark web and breach database checks
5. Port scanning and service identification (if active scan)
6. Certificate transparency logs
7. Email addresses and personnel information
8. Related domains and infrastructure

Use the Cyber Threat Intelligence Expert and Cyber Threat Researcher to analyze findings.
"""

        context = {
            'target': target,
            'scan_type': scan_type,
            'tool': 'spiderfoot'
        }
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_query_misp_events(self, arguments: Dict[str, Any]) -> str:
        """Handle MISP event queries"""
        search_query = arguments.get('search_query')
        search_type = arguments.get('search_type', 'events')
        time_range = arguments.get('time_range', '30d')

        request = f"""MISP Query Request:

Search Query: {search_query}
Search Type: {search_type}
Time Range: {time_range}

Please query MISP threat intelligence platform:
1. Search for matching events and indicators
2. Retrieve event details and context
3. Extract related attributes and objects
4. Identify threat tags and classifications
5. Find correlated events and campaigns
6. Provide STIX 2.1 export if available
7. Assess threat relevance and severity

Use the Cyber Threat Intelligence Expert to analyze MISP data and correlate findings.
"""

        context = {
            'search_query': search_query,
            'search_type': search_type,
            'time_range': time_range,
            'tool': 'misp'
        }
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_analyze_file_sandbox(self, arguments: Dict[str, Any]) -> str:
        """Handle file analysis using Trend Vision One Sandbox"""
        file_info = arguments.get('file_info')
        analysis_environment = arguments.get('analysis_environment', 'windows10')
        analysis_timeout = arguments.get('analysis_timeout', 300)

        request = f"""Sandbox Analysis Request (Trend Vision One):

File Information: {file_info}
Analysis Environment: {analysis_environment}
Timeout: {analysis_timeout}s

Please perform comprehensive sandbox analysis:
1. Submit file to Trend Vision One Sandbox
2. Execute behavioral analysis in isolated environment
3. Capture network traffic and DNS queries
4. Monitor process creation and file modifications
5. Analyze memory artifacts and API calls
6. Map behaviors to MITRE ATT&CK techniques
7. Extract IOCs (domains, IPs, file hashes)
8. Correlate with threat intelligence
9. Assess malware family and capabilities
10. Provide detection and mitigation recommendations

Use the Malware Reverse Engineer to analyze sandbox results and the Cyber Threat Intelligence Expert for attribution.
"""

        context = {
            'file_info': file_info,
            'analysis_environment': analysis_environment,
            'analysis_timeout': analysis_timeout,
            'tool': 'trend_vision_one_sandbox'
        }
        result = self.agent_manager.process_request(request, context)

        return self._format_result(result)

    async def _handle_create_threat_report(self, arguments: Dict[str, Any]) -> str:
        """Handle comprehensive threat report creation"""
        threat_name = arguments.get('threat_name')
        iocs = arguments.get('iocs', [])
        include_osint = arguments.get('include_osint', True)
        export_format = arguments.get('export_format', 'markdown')

        iocs_str = "\n".join([f"  - {ioc}" for ioc in iocs]) if iocs else "  (To be gathered during analysis)"

        request = f"""Comprehensive Threat Intelligence Report:

Threat Name: {threat_name}
IOCs Provided:
{iocs_str}

Include OSINT: {include_osint}
Export Format: {export_format}

Please create a comprehensive threat intelligence report:

**Data Sources:**
1. OpenCTI - Structured threat intelligence and relationships
2. MISP - Community threat events and indicators
3. SpiderFoot - OSINT reconnaissance (if include_osint=True)
4. Internal agent analysis

**Report Sections:**
1. Executive Summary
   - Threat overview and severity
   - Key findings and impact assessment

2. Threat Analysis
   - Threat actor attribution and motivation
   - Campaign timeline and evolution
   - Tactics, Techniques, and Procedures (TTPs)

3. Technical Details
   - Malware analysis and capabilities
   - Infrastructure analysis (domains, IPs, hosting)
   - Attack chain and kill chain mapping

4. Indicators of Compromise
   - Complete IOC list with context
   - Detection rules (Sigma, YARA, Snort)
   - STIX 2.1 bundle

5. Impact Assessment
   - Affected sectors and geographies
   - Potential business impact
   - Risk scoring (CVSS/MITRE ATT&CK)

6. Recommendations
   - Detection strategies
   - Mitigation measures
   - Incident response playbook
   - Threat hunting queries

Use ALL relevant specialist agents to compile this comprehensive report.
"""

        context = {
            'threat_name': threat_name,
            'iocs': iocs,
            'include_osint': include_osint,
            'export_format': export_format,
            'comprehensive_analysis': True
        }
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
