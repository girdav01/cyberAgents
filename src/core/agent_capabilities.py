"""
Agent Capabilities - Specific functions and workflows for each agent type
"""

import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class FunctionCategory(Enum):
    """Categories of agent functions"""
    ANALYSIS = "analysis"
    DETECTION = "detection"
    INVESTIGATION = "investigation"
    REMEDIATION = "remediation"
    RESEARCH = "research"
    EXPLOITATION = "exploitation"
    DEFENSE = "defense"
    REPORTING = "reporting"


@dataclass
class AgentFunction:
    """Represents a specific function an agent can perform"""
    name: str
    description: str
    category: FunctionCategory
    parameters: List[Dict[str, Any]]
    output_format: str
    required_tools: List[str] = None
    estimated_time: str = "varies"

    def __post_init__(self):
        if self.required_tools is None:
            self.required_tools = []


class MalwareReverseEngineerCapabilities:
    """Detailed capabilities for Malware Reverse Engineer agent"""

    FUNCTIONS = [
        AgentFunction(
            name="static_binary_analysis",
            description="Perform static analysis on a binary without execution",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "binary_path", "type": "str", "required": True},
                {"name": "analysis_depth", "type": "str", "options": ["basic", "intermediate", "deep"]},
                {"name": "target_architecture", "type": "str", "options": ["x86", "x64", "ARM", "MIPS"]}
            ],
            output_format="Disassembly listing, imported functions, strings, entry points, PE/ELF structure",
            required_tools=["IDA Pro", "Ghidra", "PE-bear", "readelf"],
            estimated_time="15-60 minutes"
        ),
        AgentFunction(
            name="dynamic_malware_analysis",
            description="Execute malware in controlled sandbox environment and monitor behavior",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "sample_hash", "type": "str", "required": True},
                {"name": "sandbox_type", "type": "str", "options": ["Cuckoo", "Any.Run", "Joe Sandbox"]},
                {"name": "network_simulation", "type": "bool", "default": True},
                {"name": "duration_seconds", "type": "int", "default": 300}
            ],
            output_format="Process tree, network traffic, file system changes, registry modifications, API calls",
            required_tools=["Cuckoo Sandbox", "Process Monitor", "Wireshark", "RegShot"],
            estimated_time="5-30 minutes"
        ),
        AgentFunction(
            name="deobfuscation_unpacking",
            description="Unpack and deobfuscate protected/packed malware samples",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "packed_sample", "type": "str", "required": True},
                {"name": "packer_type", "type": "str", "options": ["UPX", "Themida", "VMProtect", "custom", "unknown"]},
                {"name": "auto_detect", "type": "bool", "default": True}
            ],
            output_format="Unpacked binary, packer identification, anti-analysis techniques detected",
            required_tools=["x64dbg", "OllyDbg", "Detect It Easy", "UPX"],
            estimated_time="30-120 minutes"
        ),
        AgentFunction(
            name="ioc_extraction",
            description="Extract Indicators of Compromise from malware sample",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "sample_path", "type": "str", "required": True},
                {"name": "ioc_types", "type": "list", "options": ["IPs", "domains", "URLs", "file_hashes", "registry_keys", "mutexes"]},
                {"name": "include_behavioral", "type": "bool", "default": True}
            ],
            output_format="Structured IOC list in STIX/JSON format with confidence scores",
            required_tools=["strings", "YARA", "VirusTotal API", "PE-sieve"],
            estimated_time="10-30 minutes"
        ),
        AgentFunction(
            name="code_flow_analysis",
            description="Analyze control flow and identify critical code paths",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "function_address", "type": "str", "required": True},
                {"name": "analysis_type", "type": "str", "options": ["CFG", "DFG", "call_graph"]},
                {"name": "detect_obfuscation", "type": "bool", "default": True}
            ],
            output_format="Control flow graph, critical paths, suspicious patterns",
            required_tools=["IDA Pro", "Ghidra", "Binary Ninja"],
            estimated_time="20-90 minutes"
        ),
        AgentFunction(
            name="yara_rule_creation",
            description="Generate YARA rules for malware family detection",
            category=FunctionCategory.DETECTION,
            parameters=[
                {"name": "sample_set", "type": "list", "required": True},
                {"name": "rule_strictness", "type": "str", "options": ["loose", "moderate", "strict"]},
                {"name": "include_metadata", "type": "bool", "default": True}
            ],
            output_format="YARA rule with metadata, strings, and conditions",
            required_tools=["yarGen", "YARA", "PE-bear"],
            estimated_time="30-60 minutes"
        ),
        AgentFunction(
            name="anti_analysis_detection",
            description="Identify anti-debugging, anti-VM, and anti-sandbox techniques",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "sample_path", "type": "str", "required": True},
                {"name": "technique_categories", "type": "list", "options": ["debugger_detection", "vm_detection", "sandbox_evasion", "timing_checks"]}
            ],
            output_format="List of detected techniques with mitigation strategies",
            required_tools=["pafish", "al-khaser", "IDA Pro plugins"],
            estimated_time="15-45 minutes"
        ),
        AgentFunction(
            name="memory_dump_analysis",
            description="Analyze memory dumps for injected code and artifacts",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "dump_file", "type": "str", "required": True},
                {"name": "target_process", "type": "str", "optional": True},
                {"name": "scan_for", "type": "list", "options": ["injected_code", "hooks", "hidden_processes", "network_artifacts"]}
            ],
            output_format="Identified malicious artifacts, injection points, process anomalies",
            required_tools=["Volatility", "Rekall", "WinDbg"],
            estimated_time="20-60 minutes"
        ),
        AgentFunction(
            name="ransomware_analysis",
            description="Specialized analysis for ransomware samples",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "sample_hash", "type": "str", "required": True},
                {"name": "extract_crypto", "type": "bool", "default": True},
                {"name": "analyze_ransom_note", "type": "bool", "default": True}
            ],
            output_format="Encryption algorithm, key derivation, file targeting, ransom note analysis, decryption possibility",
            required_tools=["IDA Pro", "Ghidra", "crypto analysis tools"],
            estimated_time="60-180 minutes"
        )
    ]

    WORKFLOWS = {
        "complete_malware_triage": [
            "static_binary_analysis",
            "ioc_extraction",
            "dynamic_malware_analysis",
            "anti_analysis_detection"
        ],
        "deep_dive_analysis": [
            "static_binary_analysis",
            "deobfuscation_unpacking",
            "code_flow_analysis",
            "dynamic_malware_analysis",
            "memory_dump_analysis",
            "yara_rule_creation"
        ],
        "rapid_ioc_extraction": [
            "static_binary_analysis",
            "ioc_extraction"
        ]
    }


class ThreatIntelligenceCapabilities:
    """Detailed capabilities for Cyber Threat Intelligence Expert agent"""

    FUNCTIONS = [
        AgentFunction(
            name="threat_actor_profiling",
            description="Build comprehensive profile of threat actor or APT group",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "actor_name", "type": "str", "required": True},
                {"name": "include_ttps", "type": "bool", "default": True},
                {"name": "include_infrastructure", "type": "bool", "default": True},
                {"name": "include_victims", "type": "bool", "default": True}
            ],
            output_format="Structured threat actor profile with TTPs, tools, infrastructure, motivation, attribution confidence",
            required_tools=["MISP", "threat intelligence platforms", "OSINT tools"],
            estimated_time="60-240 minutes"
        ),
        AgentFunction(
            name="ioc_enrichment",
            description="Enrich IOCs with context from multiple intelligence sources",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "ioc_value", "type": "str", "required": True},
                {"name": "ioc_type", "type": "str", "options": ["ip", "domain", "hash", "url", "email"]},
                {"name": "sources", "type": "list", "options": ["VirusTotal", "Shodan", "Censys", "AlienVault", "ThreatConnect"]}
            ],
            output_format="Enriched IOC with threat scores, relationships, historical activity, attribution",
            required_tools=["VirusTotal API", "Shodan API", "Censys API", "TI platforms"],
            estimated_time="5-15 minutes"
        ),
        AgentFunction(
            name="campaign_tracking",
            description="Track and correlate threat campaign across multiple incidents",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "campaign_indicators", "type": "list", "required": True},
                {"name": "time_range", "type": "str", "required": True},
                {"name": "correlation_threshold", "type": "float", "default": 0.7}
            ],
            output_format="Campaign timeline, related incidents, common TTPs, infrastructure overlap",
            required_tools=["MISP", "threat intelligence platforms", "graph databases"],
            estimated_time="120-480 minutes"
        ),
        AgentFunction(
            name="infrastructure_analysis",
            description="Analyze adversary infrastructure and identify patterns",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "seed_indicators", "type": "list", "required": True},
                {"name": "pivot_depth", "type": "int", "default": 2},
                {"name": "include_passive_dns", "type": "bool", "default": True}
            ],
            output_format="Infrastructure map, related domains/IPs, hosting patterns, registration details",
            required_tools=["Shodan", "Censys", "PassiveTotal", "DomainTools"],
            estimated_time="30-90 minutes"
        ),
        AgentFunction(
            name="vulnerability_intelligence",
            description="Gather intelligence on exploited vulnerabilities and 0-days",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "cve_id", "type": "str", "optional": True},
                {"name": "threat_context", "type": "str", "required": True},
                {"name": "include_exploit_availability", "type": "bool", "default": True}
            ],
            output_format="Vulnerability details, exploitation in wild, affected systems, mitigation strategies",
            required_tools=["NVD", "exploit-db", "threat intel feeds"],
            estimated_time="20-60 minutes"
        ),
        AgentFunction(
            name="diamond_model_analysis",
            description="Apply Diamond Model to analyze intrusion event",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "incident_data", "type": "dict", "required": True},
                {"name": "focus_area", "type": "str", "options": ["adversary", "capability", "infrastructure", "victim"]}
            ],
            output_format="Diamond Model representation with all four vertices analyzed",
            required_tools=["analysis frameworks", "threat intel platforms"],
            estimated_time="45-120 minutes"
        ),
        AgentFunction(
            name="stix_bundle_creation",
            description="Create STIX 2.1 bundle for threat intelligence sharing",
            category=FunctionCategory.REPORTING,
            parameters=[
                {"name": "intelligence_data", "type": "dict", "required": True},
                {"name": "include_relationships", "type": "bool", "default": True},
                {"name": "tlp_marking", "type": "str", "options": ["WHITE", "GREEN", "AMBER", "RED"]}
            ],
            output_format="STIX 2.1 JSON bundle with objects and relationships",
            required_tools=["STIX libraries", "threat intel platforms"],
            estimated_time="30-90 minutes"
        ),
        AgentFunction(
            name="threat_landscape_report",
            description="Generate comprehensive threat landscape report for specific sector/region",
            category=FunctionCategory.REPORTING,
            parameters=[
                {"name": "sector", "type": "str", "required": True},
                {"name": "time_period", "type": "str", "required": True},
                {"name": "include_predictions", "type": "bool", "default": True}
            ],
            output_format="Executive summary, trending threats, sector-specific risks, recommendations",
            required_tools=["threat intel aggregators", "reporting tools"],
            estimated_time="180-600 minutes"
        )
    ]

    WORKFLOWS = {
        "incident_enrichment": [
            "ioc_enrichment",
            "infrastructure_analysis",
            "threat_actor_profiling"
        ],
        "strategic_intelligence": [
            "threat_landscape_report",
            "campaign_tracking",
            "vulnerability_intelligence"
        ],
        "tactical_sharing": [
            "ioc_enrichment",
            "stix_bundle_creation"
        ]
    }


class ForensicsCapabilities:
    """Detailed capabilities for Cyber Forensic Expert agent"""

    FUNCTIONS = [
        AgentFunction(
            name="disk_image_acquisition",
            description="Create forensically sound disk image with verification",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "source_device", "type": "str", "required": True},
                {"name": "image_format", "type": "str", "options": ["E01", "DD", "AFF4"]},
                {"name": "verify_hash", "type": "bool", "default": True},
                {"name": "write_blocker", "type": "bool", "default": True}
            ],
            output_format="Disk image file, hash values, acquisition log, chain of custody",
            required_tools=["FTK Imager", "dd", "write blocker"],
            estimated_time="varies by disk size"
        ),
        AgentFunction(
            name="memory_forensics",
            description="Analyze memory dump for volatile artifacts",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "memory_dump", "type": "str", "required": True},
                {"name": "os_profile", "type": "str", "options": ["Win7", "Win10", "Win11", "Linux", "macOS"]},
                {"name": "analysis_targets", "type": "list", "options": ["processes", "network", "registry", "malware"]}
            ],
            output_format="Process listing, network connections, injected code, registry hives, passwords",
            required_tools=["Volatility 3", "Rekall", "WinDbg"],
            estimated_time="30-120 minutes"
        ),
        AgentFunction(
            name="timeline_analysis",
            description="Create comprehensive timeline of system activity",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "evidence_sources", "type": "list", "required": True},
                {"name": "time_range", "type": "str", "required": True},
                {"name": "timezone", "type": "str", "required": True},
                {"name": "include_registry", "type": "bool", "default": True}
            ],
            output_format="Unified timeline in CSV/Plaso format with all artifacts",
            required_tools=["Plaso", "log2timeline", "Timeline Explorer"],
            estimated_time="60-240 minutes"
        ),
        AgentFunction(
            name="file_carving_recovery",
            description="Recover deleted or fragmented files from disk image",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "image_path", "type": "str", "required": True},
                {"name": "file_types", "type": "list", "options": ["documents", "images", "executables", "all"]},
                {"name": "deep_scan", "type": "bool", "default": False}
            ],
            output_format="Recovered files with metadata and recovery confidence",
            required_tools=["Autopsy", "PhotoRec", "Scalpel"],
            estimated_time="60-480 minutes"
        ),
        AgentFunction(
            name="registry_analysis",
            description="Analyze Windows registry for forensic artifacts",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "registry_hives", "type": "list", "required": True},
                {"name": "artifact_types", "type": "list", "options": ["persistence", "user_activity", "usb_devices", "network", "execution"]}
            ],
            output_format="Registry artifacts with timestamps and forensic interpretation",
            required_tools=["RegRipper", "Registry Explorer", "RECmd"],
            estimated_time="30-90 minutes"
        ),
        AgentFunction(
            name="email_forensics",
            description="Analyze email files and metadata for investigation",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "email_source", "type": "str", "required": True},
                {"name": "email_format", "type": "str", "options": ["PST", "OST", "MBOX", "EML"]},
                {"name": "extract_attachments", "type": "bool", "default": True}
            ],
            output_format="Email metadata, communication patterns, attachments, header analysis",
            required_tools=["MailXaminer", "PST Viewer", "email forensic tools"],
            estimated_time="30-180 minutes"
        ),
        AgentFunction(
            name="network_pcap_analysis",
            description="Analyze network packet captures for forensic evidence",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "pcap_file", "type": "str", "required": True},
                {"name": "analysis_focus", "type": "list", "options": ["malware_c2", "exfiltration", "lateral_movement", "protocols"]},
                {"name": "extract_files", "type": "bool", "default": True}
            ],
            output_format="Network timeline, extracted files, protocol analysis, IOCs",
            required_tools=["Wireshark", "NetworkMiner", "tshark"],
            estimated_time="45-180 minutes"
        ),
        AgentFunction(
            name="browser_forensics",
            description="Analyze browser history, cache, and artifacts",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "browser_profile", "type": "str", "required": True},
                {"name": "browser_type", "type": "str", "options": ["Chrome", "Firefox", "Edge", "Safari"]},
                {"name": "include_cache", "type": "bool", "default": True}
            ],
            output_format="Browsing history, downloads, cookies, cached files, stored credentials",
            required_tools=["Browser History Examiner", "Hindsight", "browser forensic tools"],
            estimated_time="20-60 minutes"
        ),
        AgentFunction(
            name="mobile_forensics",
            description="Extract and analyze data from mobile devices",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "device_type", "type": "str", "options": ["iOS", "Android"]},
                {"name": "extraction_method", "type": "str", "options": ["logical", "file_system", "physical"]},
                {"name": "data_types", "type": "list", "options": ["calls", "messages", "locations", "apps", "all"]}
            ],
            output_format="Extracted data with timeline, app artifacts, location history",
            required_tools=["Cellebrite", "Oxygen Forensics", "AXIOM"],
            estimated_time="60-360 minutes"
        )
    ]

    WORKFLOWS = {
        "standard_investigation": [
            "disk_image_acquisition",
            "timeline_analysis",
            "registry_analysis",
            "browser_forensics"
        ],
        "incident_response_forensics": [
            "memory_forensics",
            "timeline_analysis",
            "network_pcap_analysis",
            "file_carving_recovery"
        ],
        "data_breach_investigation": [
            "disk_image_acquisition",
            "email_forensics",
            "network_pcap_analysis",
            "timeline_analysis"
        ]
    }


class SOCAnalystCapabilities:
    """Detailed capabilities for SOC Analyst agent"""

    FUNCTIONS = [
        AgentFunction(
            name="alert_triage",
            description="Triage and prioritize security alerts from SIEM",
            category=FunctionCategory.DETECTION,
            parameters=[
                {"name": "alert_id", "type": "str", "required": True},
                {"name": "context_enrichment", "type": "bool", "default": True},
                {"name": "auto_classify", "type": "bool", "default": True}
            ],
            output_format="Alert classification, severity, recommended action, false positive assessment",
            required_tools=["SIEM", "SOAR", "threat intel feeds"],
            estimated_time="5-15 minutes"
        ),
        AgentFunction(
            name="log_correlation",
            description="Correlate logs across multiple sources to identify incidents",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "log_sources", "type": "list", "required": True},
                {"name": "time_window", "type": "str", "required": True},
                {"name": "correlation_rules", "type": "list", "optional": True}
            ],
            output_format="Correlated events, incident timeline, related entities",
            required_tools=["SIEM", "Splunk", "ELK"],
            estimated_time="15-45 minutes"
        ),
        AgentFunction(
            name="endpoint_investigation",
            description="Investigate suspicious activity on endpoint using EDR",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "hostname", "type": "str", "required": True},
                {"name": "investigation_scope", "type": "list", "options": ["processes", "network", "files", "registry", "all"]},
                {"name": "include_timeline", "type": "bool", "default": True}
            ],
            output_format="Endpoint activity summary, suspicious findings, IOCs, remediation steps",
            required_tools=["EDR", "CrowdStrike", "SentinelOne", "Defender"],
            estimated_time="20-60 minutes"
        ),
        AgentFunction(
            name="threat_hunting_query",
            description="Execute proactive threat hunting query across environment",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "hunt_hypothesis", "type": "str", "required": True},
                {"name": "data_sources", "type": "list", "required": True},
                {"name": "time_range", "type": "str", "required": True}
            ],
            output_format="Hunt results, identified threats, recommended follow-up actions",
            required_tools=["SIEM", "EDR", "threat hunting tools"],
            estimated_time="30-120 minutes"
        ),
        AgentFunction(
            name="phishing_analysis",
            description="Analyze suspected phishing email for threats",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "email_source", "type": "str", "required": True},
                {"name": "detonate_links", "type": "bool", "default": False},
                {"name": "analyze_attachments", "type": "bool", "default": True}
            ],
            output_format="Phishing verdict, IOCs, sender reputation, recommended actions",
            required_tools=["email security gateway", "sandbox", "URL analysis"],
            estimated_time="10-30 minutes"
        ),
        AgentFunction(
            name="incident_escalation",
            description="Escalate incident with complete documentation",
            category=FunctionCategory.REPORTING,
            parameters=[
                {"name": "incident_data", "type": "dict", "required": True},
                {"name": "escalation_level", "type": "str", "options": ["L2", "L3", "IR_team"]},
                {"name": "include_artifacts", "type": "bool", "default": True}
            ],
            output_format="Escalation ticket with summary, timeline, IOCs, recommended actions",
            required_tools=["ticketing system", "SOAR", "documentation tools"],
            estimated_time="15-30 minutes"
        ),
        AgentFunction(
            name="false_positive_tuning",
            description="Analyze and tune detection rules to reduce false positives",
            category=FunctionCategory.DETECTION,
            parameters=[
                {"name": "rule_id", "type": "str", "required": True},
                {"name": "false_positive_examples", "type": "list", "required": True},
                {"name": "suggest_improvements", "type": "bool", "default": True}
            ],
            output_format="Tuned detection rule, test results, expected reduction in FPs",
            required_tools=["SIEM", "detection engineering tools"],
            estimated_time="30-90 minutes"
        ),
        AgentFunction(
            name="user_behavior_analysis",
            description="Analyze user behavior for anomalies and insider threats",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "user_id", "type": "str", "required": True},
                {"name": "baseline_period", "type": "str", "required": True},
                {"name": "anomaly_types", "type": "list", "options": ["access", "data_transfer", "location", "time"]}
            ],
            output_format="Behavioral analysis, anomalies detected, risk score, investigation recommendations",
            required_tools=["UEBA", "SIEM", "DLP"],
            estimated_time="20-60 minutes"
        )
    ]

    WORKFLOWS = {
        "alert_to_resolution": [
            "alert_triage",
            "log_correlation",
            "endpoint_investigation",
            "incident_escalation"
        ],
        "proactive_hunting": [
            "threat_hunting_query",
            "log_correlation",
            "endpoint_investigation"
        ],
        "email_threat_response": [
            "phishing_analysis",
            "endpoint_investigation",
            "alert_triage"
        ]
    }


# Import extended capabilities
try:
    from .agent_capabilities_extended import EXTENDED_AGENT_CAPABILITIES
except ImportError:
    EXTENDED_AGENT_CAPABILITIES = {}


# Agent Capabilities Registry
AGENT_CAPABILITIES = {
    "malware_reverse_engineer": MalwareReverseEngineerCapabilities,
    "cyber_threat_intelligence_expert": ThreatIntelligenceCapabilities,
    "cyber_forensic_expert": ForensicsCapabilities,
    "soc_analyst": SOCAnalystCapabilities,
}

# Merge extended capabilities
AGENT_CAPABILITIES.update(EXTENDED_AGENT_CAPABILITIES)


def get_agent_functions(agent_id: str) -> List[AgentFunction]:
    """Get all functions for a specific agent type"""
    capability_class = AGENT_CAPABILITIES.get(agent_id)
    if capability_class and hasattr(capability_class, 'FUNCTIONS'):
        return capability_class.FUNCTIONS
    return []


def get_agent_workflows(agent_id: str) -> Dict[str, List[str]]:
    """Get predefined workflows for a specific agent type"""
    capability_class = AGENT_CAPABILITIES.get(agent_id)
    if capability_class and hasattr(capability_class, 'WORKFLOWS'):
        return capability_class.WORKFLOWS
    return {}


def get_function_by_name(agent_id: str, function_name: str) -> Optional[AgentFunction]:
    """Get a specific function for an agent"""
    functions = get_agent_functions(agent_id)
    for func in functions:
        if func.name == function_name:
            return func
    return None


def get_all_agent_capabilities() -> Dict[str, Dict[str, Any]]:
    """Get a summary of all agent capabilities"""
    summary = {}
    for agent_id, capability_class in AGENT_CAPABILITIES.items():
        functions = getattr(capability_class, 'FUNCTIONS', [])
        workflows = getattr(capability_class, 'WORKFLOWS', {})
        summary[agent_id] = {
            'function_count': len(functions),
            'workflow_count': len(workflows),
            'functions': [f.name for f in functions],
            'workflows': list(workflows.keys())
        }
    return summary
