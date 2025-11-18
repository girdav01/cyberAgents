"""
Tool Integration Framework for Cybersecurity Agents

This module provides integrations with various cybersecurity tools
that agents can use to perform their functions.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Categories of cybersecurity tools"""
    MALWARE_ANALYSIS = "malware_analysis"
    THREAT_INTELLIGENCE = "threat_intelligence"
    FORENSICS = "forensics"
    SIEM_EDR = "siem_edr"
    OFFENSIVE = "offensive"
    DEFENSIVE = "defensive"
    CODE_SECURITY = "code_security"
    NETWORK_ANALYSIS = "network_analysis"


@dataclass
class ToolIntegration:
    """Represents a tool integration"""
    name: str
    category: ToolCategory
    description: str
    configuration: Dict[str, Any]
    api_available: bool = False
    local_execution: bool = False
    cloud_service: bool = False


class MalwareAnalysisTools:
    """Integration for malware analysis tools"""

    TOOLS = {
        "virustotal": ToolIntegration(
            name="VirusTotal",
            category=ToolCategory.MALWARE_ANALYSIS,
            description="Multi-AV scanning and file reputation service",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "file_scan": "/file/scan",
                    "file_report": "/file/report",
                    "url_scan": "/url/scan",
                    "domain_report": "/domain/report",
                    "ip_report": "/ip-address/report"
                },
                "rate_limits": "4 requests/min (public API)"
            },
            api_available=True,
            cloud_service=True
        ),
        "cuckoo_sandbox": ToolIntegration(
            name="Cuckoo Sandbox",
            category=ToolCategory.MALWARE_ANALYSIS,
            description="Automated malware analysis sandbox",
            configuration={
                "api_key_required": False,
                "endpoints": {
                    "submit_file": "/tasks/create/file",
                    "submit_url": "/tasks/create/url",
                    "task_report": "/tasks/report/{task_id}",
                    "task_status": "/tasks/view/{task_id}"
                },
                "analysis_timeout": 300
            },
            api_available=True,
            local_execution=True
        ),
        "yara": ToolIntegration(
            name="YARA",
            category=ToolCategory.MALWARE_ANALYSIS,
            description="Pattern matching for malware identification",
            configuration={
                "rule_paths": ["/opt/yara/rules", "./rules"],
                "supported_formats": ["yara", "yar"],
                "scan_options": ["fast", "recursive", "timeout"]
            },
            local_execution=True
        ),
        "ida_pro": ToolIntegration(
            name="IDA Pro",
            category=ToolCategory.MALWARE_ANALYSIS,
            description="Interactive disassembler for reverse engineering",
            configuration={
                "script_api": "IDAPython",
                "supported_architectures": ["x86", "x64", "ARM", "MIPS", "PPC"],
                "analysis_modes": ["auto", "manual", "scripted"]
            },
            local_execution=True
        ),
        "ghidra": ToolIntegration(
            name="Ghidra",
            category=ToolCategory.MALWARE_ANALYSIS,
            description="Open-source reverse engineering framework",
            configuration={
                "script_api": "Python/Java",
                "headless_mode": True,
                "supported_formats": ["PE", "ELF", "Mach-O", "raw"],
                "decompiler_available": True
            },
            local_execution=True
        )
    }


class ThreatIntelligenceTools:
    """Integration for threat intelligence tools"""

    TOOLS = {
        "shodan": ToolIntegration(
            name="Shodan",
            category=ToolCategory.THREAT_INTELLIGENCE,
            description="Search engine for Internet-connected devices",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "host_info": "/shodan/host/{ip}",
                    "search": "/shodan/host/search",
                    "dns_lookup": "/dns/resolve",
                    "exploit_search": "/exploit/search"
                },
                "rate_limits": "1 request/sec"
            },
            api_available=True,
            cloud_service=True
        ),
        "censys": ToolIntegration(
            name="Censys",
            category=ToolCategory.THREAT_INTELLIGENCE,
            description="Internet-wide scanning and certificate transparency",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "search_hosts": "/search/hosts",
                    "view_host": "/view/hosts/{ip}",
                    "search_certificates": "/search/certificates"
                },
                "rate_limits": "120 requests/5min"
            },
            api_available=True,
            cloud_service=True
        ),
        "misp": ToolIntegration(
            name="MISP",
            category=ToolCategory.THREAT_INTELLIGENCE,
            description="Threat intelligence platform for sharing IOCs",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "add_event": "/events/add",
                    "search_events": "/events/restSearch",
                    "add_attribute": "/attributes/add",
                    "export_stix": "/events/stix/download"
                },
                "supported_formats": ["STIX 1.x", "STIX 2.x", "MISP JSON"]
            },
            api_available=True,
            local_execution=True
        ),
        "alienvault_otx": ToolIntegration(
            name="AlienVault OTX",
            category=ToolCategory.THREAT_INTELLIGENCE,
            description="Open threat exchange platform",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "pulse_info": "/pulses/{pulse_id}",
                    "indicator_types": "/indicators/{indicator_type}/{indicator}",
                    "search": "/search/pulses"
                },
                "free_tier": True
            },
            api_available=True,
            cloud_service=True
        )
    }


class ForensicsTools:
    """Integration for digital forensics tools"""

    TOOLS = {
        "volatility": ToolIntegration(
            name="Volatility 3",
            category=ToolCategory.FORENSICS,
            description="Memory forensics framework",
            configuration={
                "supported_os": ["Windows", "Linux", "macOS"],
                "plugins": [
                    "pslist", "pstree", "netstat", "filescan",
                    "malfind", "cmdline", "hivelist", "hashdump"
                ],
                "output_formats": ["json", "csv", "text"]
            },
            local_execution=True
        ),
        "autopsy": ToolIntegration(
            name="Autopsy",
            category=ToolCategory.FORENSICS,
            description="Digital forensics platform",
            configuration={
                "supported_images": ["E01", "DD", "AFF"],
                "analysis_modules": [
                    "hash_lookup", "keyword_search", "web_artifacts",
                    "timeline", "registry", "email"
                ],
                "database": "PostgreSQL/SQLite"
            },
            local_execution=True
        ),
        "plaso": ToolIntegration(
            name="Plaso (log2timeline)",
            category=ToolCategory.FORENSICS,
            description="Timeline creation for digital forensics",
            configuration={
                "supported_sources": [
                    "Windows event logs", "browser history", "registry",
                    "filesystem", "logs", "memory"
                ],
                "output_format": "plaso/CSV",
                "parsers": "100+"
            },
            local_execution=True
        ),
        "wireshark": ToolIntegration(
            name="Wireshark/tshark",
            category=ToolCategory.FORENSICS,
            description="Network protocol analyzer",
            configuration={
                "supported_protocols": "2000+",
                "capture_filters": "BPF syntax",
                "display_filters": "Wireshark filter syntax",
                "export_formats": ["CSV", "JSON", "XML", "PDML"]
            },
            local_execution=True
        )
    }


class SIEMEDRTools:
    """Integration for SIEM and EDR tools"""

    TOOLS = {
        "splunk": ToolIntegration(
            name="Splunk",
            category=ToolCategory.SIEM_EDR,
            description="SIEM and log analysis platform",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "search": "/services/search/jobs",
                    "search_results": "/services/search/jobs/{sid}/results",
                    "saved_searches": "/services/saved/searches"
                },
                "query_language": "SPL"
            },
            api_available=True,
            local_execution=True
        ),
        "elastic_siem": ToolIntegration(
            name="Elastic SIEM",
            category=ToolCategory.SIEM_EDR,
            description="Security information and event management",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "search": "/_search",
                    "alerts": "/api/detection_engine/rules",
                    "cases": "/api/cases"
                },
                "query_language": "KQL/Lucene"
            },
            api_available=True,
            local_execution=True,
            cloud_service=True
        ),
        "crowdstrike_falcon": ToolIntegration(
            name="CrowdStrike Falcon",
            category=ToolCategory.SIEM_EDR,
            description="Endpoint detection and response platform",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "detections": "/detects/queries/detects/v1",
                    "devices": "/devices/queries/devices/v1",
                    "incidents": "/incidents/queries/incidents/v1",
                    "iocs": "/indicators/queries/iocs/v1"
                },
                "real_time_response": True
            },
            api_available=True,
            cloud_service=True
        ),
        "sentinelone": ToolIntegration(
            name="SentinelOne",
            category=ToolCategory.SIEM_EDR,
            description="Autonomous endpoint protection platform",
            configuration={
                "api_key_required": True,
                "endpoints": {
                    "threats": "/threats",
                    "agents": "/agents",
                    "activities": "/activities",
                    "exclusions": "/exclusions"
                },
                "automation_available": True
            },
            api_available=True,
            cloud_service=True
        )
    }


class OffensiveTools:
    """Integration for offensive security tools"""

    TOOLS = {
        "metasploit": ToolIntegration(
            name="Metasploit Framework",
            category=ToolCategory.OFFENSIVE,
            description="Penetration testing and exploitation framework",
            configuration={
                "api_available": True,
                "rpc_endpoint": "/api/1.0",
                "modules": {
                    "exploits": "2000+",
                    "payloads": "500+",
                    "auxiliary": "1000+",
                    "post": "300+"
                },
                "database": "PostgreSQL"
            },
            api_available=True,
            local_execution=True
        ),
        "cobalt_strike": ToolIntegration(
            name="Cobalt Strike",
            category=ToolCategory.OFFENSIVE,
            description="Adversary simulation and red team platform",
            configuration={
                "teamserver_required": True,
                "c2_protocols": ["HTTP", "HTTPS", "DNS", "SMB"],
                "malleable_c2": True,
                "beacon_types": ["HTTP", "DNS", "SMB", "TCP"]
            },
            local_execution=True
        ),
        "bloodhound": ToolIntegration(
            name="BloodHound",
            category=ToolCategory.OFFENSIVE,
            description="Active Directory attack path mapping",
            configuration={
                "database": "Neo4j",
                "collectors": ["SharpHound", "AzureHound"],
                "analysis_queries": [
                    "shortest_path_to_da", "kerberoastable_users",
                    "as_rep_roastable", "unconstrained_delegation"
                ]
            },
            local_execution=True
        ),
        "burp_suite": ToolIntegration(
            name="Burp Suite",
            category=ToolCategory.OFFENSIVE,
            description="Web application security testing platform",
            configuration={
                "api_available": True,
                "components": ["Proxy", "Scanner", "Intruder", "Repeater", "Sequencer"],
                "extensions_api": "Java/Python",
                "scanner_checks": "100+"
            },
            api_available=True,
            local_execution=True
        )
    }


class DefensiveTools:
    """Integration for defensive security tools"""

    TOOLS = {
        "sigma": ToolIntegration(
            name="Sigma",
            category=ToolCategory.DEFENSIVE,
            description="Generic signature format for SIEM systems",
            configuration={
                "rule_format": "YAML",
                "supported_backends": [
                    "Splunk", "Elastic", "QRadar", "ArcSight",
                    "LogPoint", "Sumo Logic"
                ],
                "rule_repository": "github.com/SigmaHQ/sigma"
            },
            local_execution=True
        ),
        "atomic_red_team": ToolIntegration(
            name="Atomic Red Team",
            category=ToolCategory.DEFENSIVE,
            description="Library of tests mapped to MITRE ATT&CK",
            configuration={
                "execution_frameworks": ["Invoke-AtomicRedTeam", "atomic-operator"],
                "test_count": "300+",
                "mitre_coverage": "70%+",
                "platforms": ["Windows", "Linux", "macOS"]
            },
            local_execution=True
        ),
        "caldera": ToolIntegration(
            name="CALDERA",
            category=ToolCategory.DEFENSIVE,
            description="Automated adversary emulation platform",
            configuration={
                "api_available": True,
                "agents": ["Sandcat", "Manx", "Ragdoll"],
                "abilities": "mitre_att&ck_mapped",
                "autonomous_mode": True
            },
            api_available=True,
            local_execution=True
        )
    }


class CodeSecurityTools:
    """Integration for code security tools"""

    TOOLS = {
        "sonarqube": ToolIntegration(
            name="SonarQube",
            category=ToolCategory.CODE_SECURITY,
            description="Continuous code quality and security inspection",
            configuration={
                "api_key_required": True,
                "supported_languages": [
                    "Java", "C#", "JavaScript", "Python", "Go",
                    "PHP", "C/C++", "TypeScript", "Kotlin"
                ],
                "security_rules": "OWASP Top 10, CWE",
                "ci_cd_integration": True
            },
            api_available=True,
            local_execution=True,
            cloud_service=True
        ),
        "semgrep": ToolIntegration(
            name="Semgrep",
            category=ToolCategory.CODE_SECURITY,
            description="Fast, customizable static analysis tool",
            configuration={
                "api_available": True,
                "supported_languages": [
                    "Python", "JavaScript", "Java", "Go", "Ruby",
                    "C", "PHP", "TypeScript", "Rust"
                ],
                "rule_sets": ["security", "owasp", "custom"],
                "ci_cd_integration": True
            },
            api_available=True,
            local_execution=True
        ),
        "snyk": ToolIntegration(
            name="Snyk",
            category=ToolCategory.CODE_SECURITY,
            description="Developer security platform",
            configuration={
                "api_key_required": True,
                "scan_types": [
                    "dependencies", "code", "containers",
                    "infrastructure_as_code"
                ],
                "supported_languages": "20+",
                "fix_suggestions": True
            },
            api_available=True,
            cloud_service=True
        ),
        "codeql": ToolIntegration(
            name="CodeQL",
            category=ToolCategory.CODE_SECURITY,
            description="Semantic code analysis engine",
            configuration={
                "supported_languages": [
                    "C/C++", "C#", "Java", "JavaScript", "Python",
                    "Go", "Ruby", "TypeScript"
                ],
                "query_language": "QL",
                "github_integration": True,
                "variant_analysis": True
            },
            local_execution=True
        )
    }


# Central registry of all tool integrations
TOOL_REGISTRY = {
    **MalwareAnalysisTools.TOOLS,
    **ThreatIntelligenceTools.TOOLS,
    **ForensicsTools.TOOLS,
    **SIEMEDRTools.TOOLS,
    **OffensiveTools.TOOLS,
    **DefensiveTools.TOOLS,
    **CodeSecurityTools.TOOLS
}


def get_tool(tool_name: str) -> Optional[ToolIntegration]:
    """Get a specific tool integration"""
    return TOOL_REGISTRY.get(tool_name.lower().replace(" ", "_"))


def get_tools_by_category(category: ToolCategory) -> List[ToolIntegration]:
    """Get all tools in a specific category"""
    return [tool for tool in TOOL_REGISTRY.values() if tool.category == category]


def get_api_tools() -> List[ToolIntegration]:
    """Get all tools with API available"""
    return [tool for tool in TOOL_REGISTRY.values() if tool.api_available]


def get_local_tools() -> List[ToolIntegration]:
    """Get all tools that support local execution"""
    return [tool for tool in TOOL_REGISTRY.values() if tool.local_execution]


def get_tools_for_agent(agent_tools: List[str]) -> List[ToolIntegration]:
    """Get tool integrations for a list of agent tools"""
    integrations = []
    for tool_name in agent_tools:
        tool = get_tool(tool_name)
        if tool:
            integrations.append(tool)
        else:
            logger.warning(f"No integration found for tool: {tool_name}")
    return integrations


class ToolExecutor:
    """Base class for executing tool operations"""

    def __init__(self, tool: ToolIntegration, config: Optional[Dict[str, Any]] = None):
        self.tool = tool
        self.config = config or {}
        self.api_key = self.config.get('api_key')

    def validate_configuration(self) -> bool:
        """Validate that the tool is properly configured"""
        if self.tool.api_available and self.tool.configuration.get('api_key_required', False):
            if not self.api_key:
                logger.error(f"API key required for {self.tool.name} but not provided")
                return False
        return True

    def execute(self, operation: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool operation (to be implemented by specific executors)"""
        raise NotImplementedError("Subclasses must implement execute method")


def get_tool_recommendations(function_name: str, agent_type: str) -> List[str]:
    """Get recommended tools for a specific function and agent type"""
    # This would be enhanced with more sophisticated logic
    recommendations = {
        "static_binary_analysis": ["ida_pro", "ghidra", "yara"],
        "dynamic_malware_analysis": ["cuckoo_sandbox", "virustotal"],
        "threat_hunting": ["splunk", "elastic_siem"],
        "ioc_enrichment": ["virustotal", "shodan", "censys"],
        "secure_code_review": ["sonarqube", "semgrep", "codeql"],
        "web_app_vulnerability_scan": ["burp_suite"],
        "detection_rule_development": ["sigma", "atomic_red_team"]
    }

    return recommendations.get(function_name, [])
