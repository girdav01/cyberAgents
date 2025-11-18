"""
Extended Agent Capabilities - Additional agent types
"""

from typing import Dict, List
from .agent_capabilities import AgentFunction, FunctionCategory


class RedTeamerCapabilities:
    """Detailed capabilities for Red Teamer agent"""

    FUNCTIONS = [
        AgentFunction(
            name="reconnaissance",
            description="Perform comprehensive reconnaissance of target environment",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "target_scope", "type": "list", "required": True},
                {"name": "recon_type", "type": "str", "options": ["passive", "active", "hybrid"]},
                {"name": "osint_depth", "type": "str", "options": ["basic", "intermediate", "deep"]}
            ],
            output_format="Target profile, attack surface, potential entry points, employee data, technology stack",
            required_tools=["Shodan", "Censys", "theHarvester", "Maltego", "Recon-ng"],
            estimated_time="120-480 minutes"
        ),
        AgentFunction(
            name="vulnerability_exploitation",
            description="Exploit identified vulnerabilities to gain access",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "vulnerability_id", "type": "str", "required": True},
                {"name": "target_system", "type": "str", "required": True},
                {"name": "stealth_level", "type": "str", "options": ["aggressive", "moderate", "stealthy"]},
                {"name": "payload_type", "type": "str", "options": ["shell", "beacon", "custom"]}
            ],
            output_format="Exploitation status, access level gained, payload deployed, artifacts created",
            required_tools=["Metasploit", "Cobalt Strike", "custom exploits"],
            estimated_time="30-180 minutes"
        ),
        AgentFunction(
            name="lateral_movement",
            description="Move laterally across compromised network",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "source_host", "type": "str", "required": True},
                {"name": "movement_technique", "type": "str", "options": ["psexec", "wmi", "rdp", "ssh", "pass_the_hash"]},
                {"name": "target_hosts", "type": "list", "optional": True}
            ],
            output_format="Compromised hosts, credentials obtained, network map, persistence mechanisms",
            required_tools=["CrackMapExec", "Impacket", "BloodHound", "PowerShell Empire"],
            estimated_time="60-240 minutes"
        ),
        AgentFunction(
            name="privilege_escalation",
            description="Escalate privileges on compromised system",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "current_access", "type": "str", "required": True},
                {"name": "target_os", "type": "str", "options": ["Windows", "Linux", "macOS"]},
                {"name": "escalation_method", "type": "str", "options": ["kernel_exploit", "misconfiguration", "token_manipulation", "auto"]}
            ],
            output_format="Escalation method used, privileges obtained, persistence installed",
            required_tools=["PowerUp", "LinPEAS", "WinPEAS", "BeRoot"],
            estimated_time="30-120 minutes"
        ),
        AgentFunction(
            name="credential_harvesting",
            description="Extract and harvest credentials from compromised systems",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "target_system", "type": "str", "required": True},
                {"name": "harvest_methods", "type": "list", "options": ["lsass", "sam", "ntds", "browser", "memory"]},
                {"name": "crack_hashes", "type": "bool", "default": False}
            ],
            output_format="Extracted credentials, password hashes, kerberos tickets, browser passwords",
            required_tools=["Mimikatz", "LaZagne", "SecretsDump", "Hashcat"],
            estimated_time="15-90 minutes"
        ),
        AgentFunction(
            name="c2_establishment",
            description="Establish command and control infrastructure",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "c2_platform", "type": "str", "options": ["Cobalt Strike", "Mythic", "Empire", "Sliver"]},
                {"name": "communication_channel", "type": "str", "options": ["https", "dns", "smb", "tcp"]},
                {"name": "evasion_features", "type": "list", "options": ["domain_fronting", "malleable_c2", "encryption"]}
            ],
            output_format="C2 infrastructure details, beacon configuration, communication channels",
            required_tools=["Cobalt Strike", "Mythic", "Apache", "redirectors"],
            estimated_time="60-180 minutes"
        ),
        AgentFunction(
            name="data_exfiltration",
            description="Exfiltrate sensitive data from target environment",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "data_location", "type": "str", "required": True},
                {"name": "exfil_method", "type": "str", "options": ["https", "dns", "icmp", "cloud_sync", "email"]},
                {"name": "data_size_mb", "type": "int", "required": True},
                {"name": "stealth_mode", "type": "bool", "default": True}
            ],
            output_format="Exfiltration status, data transferred, method used, detection likelihood",
            required_tools=["custom scripts", "cloud services", "C2 channels"],
            estimated_time="30-240 minutes"
        ),
        AgentFunction(
            name="persistence_installation",
            description="Install persistence mechanisms for long-term access",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "target_system", "type": "str", "required": True},
                {"name": "persistence_type", "type": "str", "options": ["scheduled_task", "service", "registry", "wmi", "startup"]},
                {"name": "backup_persistence", "type": "bool", "default": True}
            ],
            output_format="Persistence mechanisms installed, trigger conditions, backup methods",
            required_tools=["PowerShell", "WMI", "Task Scheduler", "custom implants"],
            estimated_time="20-60 minutes"
        ),
        AgentFunction(
            name="defense_evasion",
            description="Implement techniques to evade detection and defenses",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "current_activity", "type": "str", "required": True},
                {"name": "evasion_techniques", "type": "list", "options": ["obfuscation", "process_injection", "unhooking", "amsi_bypass"]},
                {"name": "target_defenses", "type": "list", "options": ["edr", "av", "siem", "dlp"]}
            ],
            output_format="Evasion techniques applied, detection probability, recommendations",
            required_tools=["custom tools", "obfuscators", "packers"],
            estimated_time="45-120 minutes"
        ),
        AgentFunction(
            name="engagement_reporting",
            description="Generate comprehensive red team engagement report",
            category=FunctionCategory.REPORTING,
            parameters=[
                {"name": "engagement_data", "type": "dict", "required": True},
                {"name": "include_remediation", "type": "bool", "default": True},
                {"name": "map_to_mitre", "type": "bool", "default": True}
            ],
            output_format="Executive summary, technical findings, MITRE ATT&CK mapping, remediation recommendations",
            required_tools=["reporting tools", "MITRE ATT&CK Navigator"],
            estimated_time="180-480 minutes"
        )
    ]

    WORKFLOWS = {
        "full_engagement": [
            "reconnaissance",
            "vulnerability_exploitation",
            "privilege_escalation",
            "lateral_movement",
            "credential_harvesting",
            "data_exfiltration",
            "persistence_installation",
            "engagement_reporting"
        ],
        "assumed_breach": [
            "privilege_escalation",
            "lateral_movement",
            "credential_harvesting",
            "data_exfiltration",
            "engagement_reporting"
        ],
        "quick_strike": [
            "vulnerability_exploitation",
            "privilege_escalation",
            "credential_harvesting"
        ]
    }


class BlueTeamerCapabilities:
    """Detailed capabilities for Blue Teamer agent"""

    FUNCTIONS = [
        AgentFunction(
            name="detection_rule_development",
            description="Develop and test detection rules for specific threats",
            category=FunctionCategory.DETECTION,
            parameters=[
                {"name": "threat_scenario", "type": "str", "required": True},
                {"name": "rule_format", "type": "str", "options": ["Sigma", "YARA", "Snort", "Suricata", "KQL"]},
                {"name": "include_testing", "type": "bool", "default": True}
            ],
            output_format="Detection rule, test cases, false positive analysis, deployment instructions",
            required_tools=["Sigma", "YARA", "rule testing frameworks"],
            estimated_time="60-180 minutes"
        ),
        AgentFunction(
            name="threat_hunting",
            description="Proactively hunt for threats in environment",
            category=FunctionCategory.INVESTIGATION,
            parameters=[
                {"name": "hunt_hypothesis", "type": "str", "required": True},
                {"name": "data_sources", "type": "list", "required": True},
                {"name": "time_window", "type": "str", "required": True},
                {"name": "hunt_methodology", "type": "str", "options": ["hypothesis_driven", "baseline_deviation", "ioc_based"]}
            ],
            output_format="Hunt findings, new IOCs, detection gaps, recommended improvements",
            required_tools=["SIEM", "EDR", "hunting platforms"],
            estimated_time="120-480 minutes"
        ),
        AgentFunction(
            name="log_source_optimization",
            description="Optimize log collection and retention for security monitoring",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "current_sources", "type": "list", "required": True},
                {"name": "coverage_gaps", "type": "list", "optional": True},
                {"name": "budget_constraint", "type": "str", "optional": True}
            ],
            output_format="Recommended log sources, collection configurations, retention policies, cost analysis",
            required_tools=["SIEM", "log collectors", "analysis tools"],
            estimated_time="120-360 minutes"
        ),
        AgentFunction(
            name="baseline_establishment",
            description="Establish behavioral baselines for anomaly detection",
            category=FunctionCategory.DETECTION,
            parameters=[
                {"name": "baseline_scope", "type": "str", "options": ["network", "user", "application", "system"]},
                {"name": "baseline_period", "type": "str", "required": True},
                {"name": "statistical_method", "type": "str", "options": ["mean_std", "percentile", "ml_based"]}
            ],
            output_format="Baseline metrics, normal behavior patterns, anomaly thresholds",
            required_tools=["SIEM", "UEBA", "statistical tools"],
            estimated_time="60-240 minutes"
        ),
        AgentFunction(
            name="attack_simulation_testing",
            description="Test defenses against simulated attacks",
            category=FunctionCategory.DETECTION,
            parameters=[
                {"name": "attack_scenarios", "type": "list", "required": True},
                {"name": "test_framework", "type": "str", "options": ["Atomic Red Team", "Caldera", "AttackIQ", "custom"]},
                {"name": "validate_detections", "type": "bool", "default": True}
            ],
            output_format="Test results, detection coverage, blind spots, recommended improvements",
            required_tools=["Atomic Red Team", "Caldera", "detection platforms"],
            estimated_time="120-480 minutes"
        ),
        AgentFunction(
            name="incident_playbook_development",
            description="Create incident response playbooks for specific scenarios",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "incident_type", "type": "str", "required": True},
                {"name": "include_automation", "type": "bool", "default": True},
                {"name": "integrate_soar", "type": "bool", "default": False}
            ],
            output_format="Detailed playbook with steps, decision trees, automation scripts, metrics",
            required_tools=["documentation tools", "SOAR platforms"],
            estimated_time="180-480 minutes"
        ),
        AgentFunction(
            name="security_metrics_dashboard",
            description="Create security metrics and KPI dashboard",
            category=FunctionCategory.REPORTING,
            parameters=[
                {"name": "metric_categories", "type": "list", "required": True},
                {"name": "audience", "type": "str", "options": ["technical", "management", "executive"]},
                {"name": "update_frequency", "type": "str", "options": ["real-time", "daily", "weekly", "monthly"]}
            ],
            output_format="Dashboard configuration, KPI definitions, visualization recommendations",
            required_tools=["Grafana", "Kibana", "PowerBI", "SIEM dashboards"],
            estimated_time="120-360 minutes"
        ),
        AgentFunction(
            name="purple_team_exercise",
            description="Coordinate purple team exercise combining red and blue activities",
            category=FunctionCategory.DETECTION,
            parameters=[
                {"name": "exercise_scope", "type": "str", "required": True},
                {"name": "attack_scenarios", "type": "list", "required": True},
                {"name": "detection_focus", "type": "list", "required": True}
            ],
            output_format="Exercise plan, attack execution results, detection analysis, improvement recommendations",
            required_tools=["red team tools", "detection platforms", "collaboration tools"],
            estimated_time="480-1200 minutes"
        ),
        AgentFunction(
            name="threat_intelligence_integration",
            description="Integrate threat intelligence into defensive operations",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "intel_sources", "type": "list", "required": True},
                {"name": "integration_targets", "type": "list", "options": ["SIEM", "EDR", "firewall", "IDS/IPS"]},
                {"name": "automation_level", "type": "str", "options": ["manual", "semi-automated", "automated"]}
            ],
            output_format="Integration architecture, automated workflows, validation results",
            required_tools=["MISP", "TIP", "SOAR", "security platforms"],
            estimated_time="180-600 minutes"
        )
    ]

    WORKFLOWS = {
        "detection_engineering_cycle": [
            "threat_hunting",
            "detection_rule_development",
            "attack_simulation_testing",
            "log_source_optimization"
        ],
        "continuous_improvement": [
            "baseline_establishment",
            "threat_hunting",
            "security_metrics_dashboard",
            "attack_simulation_testing"
        ],
        "collaborative_defense": [
            "purple_team_exercise",
            "detection_rule_development",
            "incident_playbook_development"
        ]
    }


class VulnerabilityResearcherCapabilities:
    """Detailed capabilities for Vulnerability & Bug Bounty Researcher agent"""

    FUNCTIONS = [
        AgentFunction(
            name="web_app_vulnerability_scan",
            description="Perform comprehensive web application vulnerability assessment",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "target_url", "type": "str", "required": True},
                {"name": "scan_depth", "type": "str", "options": ["quick", "standard", "thorough"]},
                {"name": "vuln_categories", "type": "list", "options": ["injection", "xss", "auth", "crypto", "all"]},
                {"name": "authenticated_scan", "type": "bool", "default": False}
            ],
            output_format="Vulnerability findings with CVSS scores, PoC, remediation recommendations",
            required_tools=["Burp Suite Pro", "OWASP ZAP", "Nuclei", "custom scripts"],
            estimated_time="120-480 minutes"
        ),
        AgentFunction(
            name="api_security_testing",
            description="Test API endpoints for security vulnerabilities",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "api_specification", "type": "str", "required": True},
                {"name": "api_type", "type": "str", "options": ["REST", "GraphQL", "SOAP", "gRPC"]},
                {"name": "test_categories", "type": "list", "options": ["auth", "injection", "logic", "rate_limiting", "all"]}
            ],
            output_format="API vulnerabilities, authentication issues, business logic flaws, security recommendations",
            required_tools=["Postman", "Burp Suite", "API fuzzing tools"],
            estimated_time="90-360 minutes"
        ),
        AgentFunction(
            name="fuzzing_campaign",
            description="Execute fuzzing campaign to discover vulnerabilities",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "target_binary", "type": "str", "required": True},
                {"name": "fuzzer_type", "type": "str", "options": ["AFL++", "libFuzzer", "Honggfuzz", "custom"]},
                {"name": "duration_hours", "type": "int", "default": 24},
                {"name": "coverage_guided", "type": "bool", "default": True}
            ],
            output_format="Crashes found, unique bugs, coverage statistics, crash analysis",
            required_tools=["AFL++", "libFuzzer", "crash analysis tools"],
            estimated_time="varies (hours to days)"
        ),
        AgentFunction(
            name="source_code_audit",
            description="Perform security-focused source code review",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "repository_url", "type": "str", "required": True},
                {"name": "language", "type": "str", "required": True},
                {"name": "audit_focus", "type": "list", "options": ["injection", "crypto", "auth", "logic", "all"]},
                {"name": "use_sast", "type": "bool", "default": True}
            ],
            output_format="Security vulnerabilities, code quality issues, remediation recommendations",
            required_tools=["Semgrep", "CodeQL", "manual review"],
            estimated_time="480-2400 minutes"
        ),
        AgentFunction(
            name="mobile_app_pentest",
            description="Penetration test mobile application",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "app_package", "type": "str", "required": True},
                {"name": "platform", "type": "str", "options": ["Android", "iOS"]},
                {"name": "test_areas", "type": "list", "options": ["static", "dynamic", "network", "storage", "all"]}
            ],
            output_format="Mobile app vulnerabilities, insecure storage, hardcoded secrets, API issues",
            required_tools=["MobSF", "Frida", "objection", "Burp Suite"],
            estimated_time="240-960 minutes"
        ),
        AgentFunction(
            name="exploit_development",
            description="Develop proof-of-concept exploit for vulnerability",
            category=FunctionCategory.EXPLOITATION,
            parameters=[
                {"name": "vulnerability_details", "type": "dict", "required": True},
                {"name": "exploit_type", "type": "str", "options": ["remote", "local", "web", "privilege_escalation"]},
                {"name": "reliability_target", "type": "str", "options": ["poc", "reliable", "weaponized"]}
            ],
            output_format="Working exploit code, reliability assessment, mitigations, detection methods",
            required_tools=["debuggers", "exploit frameworks", "development tools"],
            estimated_time="120-960 minutes"
        ),
        AgentFunction(
            name="supply_chain_analysis",
            description="Analyze software supply chain for vulnerabilities",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "project_path", "type": "str", "required": True},
                {"name": "scan_dependencies", "type": "bool", "default": True},
                {"name": "check_typosquatting", "type": "bool", "default": True}
            ],
            output_format="Vulnerable dependencies, supply chain risks, update recommendations",
            required_tools=["Snyk", "OWASP Dependency-Check", "npm audit"],
            estimated_time="30-120 minutes"
        ),
        AgentFunction(
            name="cloud_security_assessment",
            description="Assess cloud infrastructure for misconfigurations and vulnerabilities",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "cloud_provider", "type": "str", "options": ["AWS", "Azure", "GCP", "multi-cloud"]},
                {"name": "assessment_scope", "type": "list", "options": ["iam", "storage", "network", "compute", "all"]},
                {"name": "compliance_framework", "type": "str", "optional": True}
            ],
            output_format="Misconfigurations, security gaps, compliance violations, remediation steps",
            required_tools=["ScoutSuite", "Prowler", "CloudSploit"],
            estimated_time="180-480 minutes"
        ),
        AgentFunction(
            name="responsible_disclosure",
            description="Prepare and submit responsible vulnerability disclosure",
            category=FunctionCategory.REPORTING,
            parameters=[
                {"name": "vulnerability_data", "type": "dict", "required": True},
                {"name": "vendor_contact", "type": "str", "required": True},
                {"name": "include_poc", "type": "bool", "default": True}
            ],
            output_format="Disclosure report with timeline, CVSS score, PoC, remediation guidance",
            required_tools=["documentation tools", "encryption tools"],
            estimated_time="60-240 minutes"
        )
    ]

    WORKFLOWS = {
        "web_app_assessment": [
            "web_app_vulnerability_scan",
            "api_security_testing",
            "source_code_audit",
            "responsible_disclosure"
        ],
        "zero_day_research": [
            "fuzzing_campaign",
            "source_code_audit",
            "exploit_development",
            "responsible_disclosure"
        ],
        "bug_bounty_workflow": [
            "web_app_vulnerability_scan",
            "api_security_testing",
            "mobile_app_pentest",
            "responsible_disclosure"
        ]
    }


class CodeSecurityExpertCapabilities:
    """Detailed capabilities for Code Security Expert agent"""

    FUNCTIONS = [
        AgentFunction(
            name="secure_code_review",
            description="Perform comprehensive secure code review",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "code_repository", "type": "str", "required": True},
                {"name": "programming_language", "type": "str", "required": True},
                {"name": "review_depth", "type": "str", "options": ["quick", "standard", "thorough"]},
                {"name": "focus_areas", "type": "list", "options": ["injection", "auth", "crypto", "logic", "all"]}
            ],
            output_format="Security findings, code quality issues, best practice violations, remediation code examples",
            required_tools=["SonarQube", "Checkmarx", "Semgrep", "manual review"],
            estimated_time="180-960 minutes"
        ),
        AgentFunction(
            name="threat_modeling",
            description="Create threat model for application or system",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "system_description", "type": "str", "required": True},
                {"name": "modeling_approach", "type": "str", "options": ["STRIDE", "PASTA", "Attack_Trees", "hybrid"]},
                {"name": "include_mitigations", "type": "bool", "default": True}
            ],
            output_format="Threat model diagram, identified threats, risk ratings, mitigation strategies",
            required_tools=["Microsoft Threat Modeling Tool", "draw.io", "documentation"],
            estimated_time="180-600 minutes"
        ),
        AgentFunction(
            name="sast_implementation",
            description="Implement and configure SAST tools in CI/CD pipeline",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "project_info", "type": "dict", "required": True},
                {"name": "sast_tool", "type": "str", "options": ["SonarQube", "Semgrep", "CodeQL", "Checkmarx"]},
                {"name": "quality_gate_rules", "type": "list", "required": True}
            ],
            output_format="SAST configuration, custom rules, CI/CD integration, quality gates",
            required_tools=["SAST tools", "CI/CD platforms"],
            estimated_time="240-720 minutes"
        ),
        AgentFunction(
            name="secure_architecture_design",
            description="Design secure software architecture",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "requirements", "type": "dict", "required": True},
                {"name": "architecture_type", "type": "str", "options": ["monolithic", "microservices", "serverless"]},
                {"name": "compliance_requirements", "type": "list", "optional": True}
            ],
            output_format="Architecture diagrams, security controls, data flow diagrams, security requirements",
            required_tools=["architecture tools", "security frameworks"],
            estimated_time="480-1440 minutes"
        ),
        AgentFunction(
            name="crypto_implementation_review",
            description="Review cryptographic implementations for security",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "code_path", "type": "str", "required": True},
                {"name": "crypto_operations", "type": "list", "options": ["encryption", "hashing", "signing", "key_management"]},
                {"name": "check_compliance", "type": "bool", "default": True}
            ],
            output_format="Cryptographic issues, weak implementations, compliance gaps, recommended fixes",
            required_tools=["manual review", "crypto analysis tools"],
            estimated_time="120-480 minutes"
        ),
        AgentFunction(
            name="auth_authorization_review",
            description="Review authentication and authorization implementations",
            category=FunctionCategory.ANALYSIS,
            parameters=[
                {"name": "auth_code", "type": "str", "required": True},
                {"name": "auth_mechanism", "type": "str", "options": ["OAuth", "SAML", "JWT", "session", "custom"]},
                {"name": "check_patterns", "type": "list", "options": ["privilege_escalation", "bypass", "injection", "all"]}
            ],
            output_format="Authentication flaws, authorization issues, session management problems, secure implementation examples",
            required_tools=["code analysis", "security testing tools"],
            estimated_time="180-480 minutes"
        ),
        AgentFunction(
            name="input_validation_framework",
            description="Design and implement input validation framework",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "application_type", "type": "str", "required": True},
                {"name": "input_types", "type": "list", "required": True},
                {"name": "validation_approach", "type": "str", "options": ["whitelist", "blacklist", "hybrid"]}
            ],
            output_format="Validation framework code, sanitization functions, test cases",
            required_tools=["development frameworks", "validation libraries"],
            estimated_time="240-720 minutes"
        ),
        AgentFunction(
            name="secure_sdlc_integration",
            description="Integrate security practices into SDLC",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "current_sdlc", "type": "str", "required": True},
                {"name": "team_size", "type": "int", "required": True},
                {"name": "security_maturity", "type": "str", "options": ["low", "medium", "high"]}
            ],
            output_format="Security integration plan, tooling recommendations, training requirements, metrics",
            required_tools=["SDLC frameworks", "security tools"],
            estimated_time="480-1440 minutes"
        ),
        AgentFunction(
            name="dependency_security_management",
            description="Manage and monitor third-party dependency security",
            category=FunctionCategory.DEFENSE,
            parameters=[
                {"name": "project_path", "type": "str", "required": True},
                {"name": "package_manager", "type": "str", "options": ["npm", "pip", "maven", "nuget"]},
                {"name": "auto_update_policy", "type": "str", "options": ["manual", "patch", "minor", "major"]}
            ],
            output_format="Vulnerability report, update recommendations, policy configuration, monitoring setup",
            required_tools=["Snyk", "Dependabot", "OWASP Dependency-Check"],
            estimated_time="60-240 minutes"
        )
    ]

    WORKFLOWS = {
        "secure_development": [
            "threat_modeling",
            "secure_architecture_design",
            "secure_code_review",
            "sast_implementation"
        ],
        "security_review_cycle": [
            "secure_code_review",
            "auth_authorization_review",
            "crypto_implementation_review",
            "dependency_security_management"
        ],
        "devsecops_implementation": [
            "secure_sdlc_integration",
            "sast_implementation",
            "dependency_security_management"
        ]
    }


class ThreatResearcherCapabilities:
    """Detailed capabilities for Cyber Threat Researcher agent"""

    FUNCTIONS = [
        AgentFunction(
            name="emerging_threat_analysis",
            description="Analyze and document emerging cybersecurity threats",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "threat_topic", "type": "str", "required": True},
                {"name": "research_depth", "type": "str", "options": ["overview", "detailed", "comprehensive"]},
                {"name": "include_predictions", "type": "bool", "default": True}
            ],
            output_format="Threat analysis report, technical details, impact assessment, defensive recommendations",
            required_tools=["research databases", "OSINT tools", "threat feeds"],
            estimated_time="240-960 minutes"
        ),
        AgentFunction(
            name="apt_campaign_research",
            description="Research and document APT campaign activities",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "apt_group", "type": "str", "required": True},
                {"name": "time_period", "type": "str", "required": True},
                {"name": "include_iocs", "type": "bool", "default": True}
            ],
            output_format="Campaign documentation, TTPs, IOCs, victim analysis, attribution assessment",
            required_tools=["threat intelligence platforms", "research databases"],
            estimated_time="360-1440 minutes"
        ),
        AgentFunction(
            name="darkweb_monitoring",
            description="Monitor darkweb and underground forums for threat intelligence",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "monitoring_targets", "type": "list", "required": True},
                {"name": "keywords", "type": "list", "required": True},
                {"name": "monitoring_duration", "type": "str", "required": True}
            ],
            output_format="Monitoring report, relevant findings, threat actor discussions, leaked data alerts",
            required_tools=["darkweb access tools", "monitoring platforms"],
            estimated_time="continuous"
        ),
        AgentFunction(
            name="malware_family_research",
            description="Research and document malware family evolution",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "malware_family", "type": "str", "required": True},
                {"name": "analysis_period", "type": "str", "required": True},
                {"name": "track_variants", "type": "bool", "default": True}
            ],
            output_format="Malware family report, evolution timeline, variant analysis, detection strategies",
            required_tools=["malware databases", "analysis tools", "YARA"],
            estimated_time="480-1440 minutes"
        ),
        AgentFunction(
            name="attack_technique_research",
            description="Research specific attack techniques and methodologies",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "technique_id", "type": "str", "required": True},
                {"name": "include_real_world", "type": "bool", "default": True},
                {"name": "defensive_focus", "type": "bool", "default": True}
            ],
            output_format="Technique documentation, real-world usage, detection methods, mitigation strategies",
            required_tools=["MITRE ATT&CK", "research databases"],
            estimated_time="180-600 minutes"
        ),
        AgentFunction(
            name="ai_ml_threat_research",
            description="Research AI/ML-based threats and adversarial techniques",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "ai_threat_type", "type": "str", "options": ["adversarial_ml", "deepfakes", "ai_malware", "automated_attacks"]},
                {"name": "include_defenses", "type": "bool", "default": True}
            ],
            output_format="AI threat analysis, attack methodologies, defense mechanisms, future predictions",
            required_tools=["ML frameworks", "research papers", "POC tools"],
            estimated_time="360-1440 minutes"
        ),
        AgentFunction(
            name="exploit_kit_analysis",
            description="Analyze exploit kit campaigns and infrastructure",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "exploit_kit_name", "type": "str", "required": True},
                {"name": "analysis_scope", "type": "list", "options": ["infrastructure", "exploits", "payloads", "distribution"]},
                {"name": "time_range", "type": "str", "required": True}
            ],
            output_format="Exploit kit report, infrastructure analysis, exploit chain, IOCs, mitigation",
            required_tools=["traffic analysis", "malware analysis", "threat intelligence"],
            estimated_time="240-960 minutes"
        ),
        AgentFunction(
            name="ransomware_ecosystem_research",
            description="Research ransomware-as-a-service and related ecosystems",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "ransomware_group", "type": "str", "required": True},
                {"name": "research_areas", "type": "list", "options": ["operations", "affiliates", "payments", "negotiations", "all"]},
                {"name": "include_victimology", "type": "bool", "default": True}
            ],
            output_format="Ecosystem analysis, operational model, affiliate structure, victim patterns, trends",
            required_tools=["threat intelligence", "darkweb monitoring", "cryptocurrency analysis"],
            estimated_time="480-1440 minutes"
        ),
        AgentFunction(
            name="vulnerability_trend_analysis",
            description="Analyze vulnerability trends and exploitation patterns",
            category=FunctionCategory.RESEARCH,
            parameters=[
                {"name": "time_period", "type": "str", "required": True},
                {"name": "vulnerability_types", "type": "list", "optional": True},
                {"name": "include_exploitation", "type": "bool", "default": True}
            ],
            output_format="Trend analysis report, exploitation statistics, predictions, defensive priorities",
            required_tools=["vulnerability databases", "exploit databases", "analytics tools"],
            estimated_time="360-960 minutes"
        ),
        AgentFunction(
            name="threat_research_publication",
            description="Prepare threat research for publication and sharing",
            category=FunctionCategory.REPORTING,
            parameters=[
                {"name": "research_data", "type": "dict", "required": True},
                {"name": "publication_type", "type": "str", "options": ["blog", "whitepaper", "conference", "advisory"]},
                {"name": "tlp_marking", "type": "str", "options": ["WHITE", "GREEN", "AMBER", "RED"]}
            ],
            output_format="Publication-ready document, IOCs, detection rules, presentation materials",
            required_tools=["documentation tools", "visualization tools"],
            estimated_time="480-1440 minutes"
        )
    ]

    WORKFLOWS = {
        "comprehensive_threat_research": [
            "emerging_threat_analysis",
            "apt_campaign_research",
            "malware_family_research",
            "threat_research_publication"
        ],
        "continuous_monitoring": [
            "darkweb_monitoring",
            "vulnerability_trend_analysis",
            "emerging_threat_analysis"
        ],
        "specialized_research": [
            "ai_ml_threat_research",
            "ransomware_ecosystem_research",
            "exploit_kit_analysis",
            "threat_research_publication"
        ]
    }


# Extended capabilities registry
EXTENDED_AGENT_CAPABILITIES = {
    "red_teamer": RedTeamerCapabilities,
    "blue_teamer": BlueTeamerCapabilities,
    "vulnerability_bug_bounty_researcher": VulnerabilityResearcherCapabilities,
    "code_security_expert": CodeSecurityExpertCapabilities,
    "cyber_threat_researcher": ThreatResearcherCapabilities,
}
