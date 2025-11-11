# 📚 CyberAgents Usage Examples

Comprehensive examples demonstrating CyberAgents capabilities across different security domains.

## Table of Contents

1. [Malware Analysis](#malware-analysis)
2. [Code Security Review](#code-security-review)
3. [Incident Investigation](#incident-investigation)
4. [Threat Intelligence](#threat-intelligence)
5. [Vulnerability Assessment](#vulnerability-assessment)
6. [Red Team Planning](#red-team-planning)
7. [Blue Team Detection](#blue-team-detection)
8. [WebHook Integration](#webhook-integration)

---

## Malware Analysis

### Example 1: PowerShell Obfuscation Analysis

**Input**:
```
Analyze this obfuscated PowerShell command found in our EDR logs:

powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACIASAA0AHMASQBBAEEAQQBBAEEAQQBBAEEAQQBLADEAVwBhADMALwBhAE4AZAA9ACIAKQApADsASQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBHAHoAaQBwAFMAdAByAGUAYQBtACgAJABzACwAWwBJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ATQBvAGQAZQBdADoAOgBEAGUAYwBvAG0AcAByAGUAcwBzACkAKQApAC4AUgBlAGEAZABUAG8ARQBuAGQAKAApAA==

What does this do and how should we respond?
```

**Expected Agents**: Malware Reverse Engineer, Blue Teamer

**Output Includes**:
- Decoded PowerShell command
- Behavior analysis (downloads and executes code)
- IOCs (command patterns, techniques)
- MITRE ATT&CK mapping (T1059.001 - PowerShell, T1140 - Deobfuscate/Decode Files)
- Detection rules (YARA, Sigma)
- Remediation steps

---

## Code Security Review

### Example 2: SQL Injection Vulnerability

**Input**:
```python
Review this user authentication code for security issues:

def authenticate_user(request):
    username = request.POST.get('username')
    password = request.POST.get('password')

    # Check credentials
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)

    if result:
        session['user_id'] = result[0]['id']
        return redirect('/dashboard')
    else:
        return "Invalid credentials"
```

**Expected Agents**: Code Security Expert

**Output Includes**:
- SQL injection vulnerability identification
- Plaintext password storage issue
- Missing input validation
- Session security concerns
- Secure code rewrite with:
  - Parameterized queries
  - Password hashing (bcrypt/argon2)
  - Input validation
  - Proper error handling
- OWASP Top 10 mapping (A03:2021 - Injection)

---

## Incident Investigation

### Example 3: Ransomware Incident

**Input**:
```
Security incident detected:

Timeline:
- 09:00 - User john.doe@company.com opened email "Invoice_Q4.pdf"
- 09:05 - Suspicious process 'invoice_Q4.exe' executed from Downloads folder
- 09:10 - Mass file modifications detected on file server
- 09:15 - Files encrypted with .locked extension
- 09:20 - Ransom note created: "YOUR_FILES_ARE_ENCRYPTED.txt"

Evidence:
- Email sender: accounting@supp1ier-inv0ice.com (note the l/1 substitution)
- Executable hash: d41d8cd98f00b204e9800998ecf8427e
- Encrypted files: 15,000+ files across network share
- Ransom demand: 5 BTC to address bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

Investigate and recommend response actions.
```

**Expected Agents**: Cyber Forensic Expert, Malware Reverse Engineer, SOC Analyst, Cyber Threat Intelligence Expert

**Output Includes**:
- Incident timeline reconstruction
- Attack vector analysis (phishing email)
- Malware behavior analysis
- Threat actor attribution (if possible)
- Containment steps (network isolation, disable user accounts)
- Recovery options (backups, decryption tools)
- Long-term remediation (email filtering, user training)

---

## Threat Intelligence

### Example 4: Suspicious IP Investigation

**Input**:
```
Analyze this IP address that triggered multiple alerts:

IP: 185.220.101.47
Activity:
- Port scanning on 22, 23, 3389, 445
- 50+ failed SSH authentication attempts
- User-Agent: Mozilla/5.0 (compatible; Nimbostratus-Bot/v1.3.2)
- Targeting our web application login endpoints
- Originating from: Russia (autonomous system AS48693)

Should we block this IP? What's the threat level?
```

**Expected Agents**: Cyber Threat Intelligence Expert, SOC Analyst

**Output Includes**:
- IP reputation analysis
- Threat actor identification (known botnet/scanner)
- Historical attack patterns
- Recommended actions (block, monitor, report)
- Firewall/IDS rules
- Threat level assessment

---

## Vulnerability Assessment

### Example 5: Critical CVE Analysis

**Input**:
```
Analyze the impact of CVE-2024-1234 on our infrastructure:

Vulnerability: Remote Code Execution in Apache Struts 2.x
CVSS Score: 9.8 (Critical)
Affected Versions: 2.0.0 - 2.5.32
Our Systems:
- Production web app: Apache Struts 2.5.30 (VULNERABLE)
- Staging environment: Apache Struts 2.5.33 (PATCHED)
- Dev servers: Mixed versions

Public exploit available: Yes
Active exploitation in the wild: Yes (since 2024-01-15)

Provide risk assessment and remediation plan.
```

**Expected Agents**: Vulnerability & Bug Bounty Researcher, Code Security Expert, SOC Analyst

**Output Includes**:
- Vulnerability technical analysis
- Exploitation likelihood (HIGH - public exploit available)
- Business impact assessment
- Prioritized remediation plan
- Temporary mitigations (WAF rules, network segmentation)
- Long-term fixes (patching schedule)

---

## Red Team Planning

### Example 6: Adversary Emulation Exercise

**Input**:
```
Plan a red team exercise simulating APT29 (Cozy Bear) tactics:

Objectives:
1. Test phishing defenses
2. Evaluate lateral movement detection
3. Assess data exfiltration controls

Scope:
- Internal network: 10.0.0.0/8
- Target: Finance department data
- Timeframe: 2 weeks
- Constraints: No DoS, no data destruction

What attack chain should we use?
```

**Expected Agents**: Red Teamer, Cyber Threat Intelligence Expert

**Output Includes**:
- Attack scenario based on APT29 TTPs
- Phishing campaign design (credential harvesting)
- Initial access techniques
- Privilege escalation methods
- Lateral movement tactics (WMI, PowerShell remoting)
- Data exfiltration channels (DNS tunneling, HTTPS)
- MITRE ATT&CK technique mapping
- Expected detection points
- Success criteria

---

## Blue Team Detection

### Example 7: Lateral Movement Detection

**Input**:
```
Design detection rules for lateral movement in our Windows environment:

Environment:
- 500+ Windows workstations
- 50 Windows servers
- Active Directory domain
- EDR deployed: CrowdStrike Falcon
- SIEM: Splunk

Focus on detecting:
- Pass-the-Hash attacks
- Remote PowerShell usage
- SMB-based lateral movement
- RDP lateral movement
```

**Expected Agents**: Blue Teamer, SOC Analyst

**Output Includes**:
- Sigma rules for SIEM
- EDR detection policies
- Windows Event Log queries (4624, 4648, 4672)
- Network traffic patterns to monitor
- Baseline vs. anomaly detection strategies
- MITRE ATT&CK techniques covered (T1021, T1550)
- False positive mitigation

---

## WebHook Integration

### Example 8: SIEM Alert Processing

**WebHook Request**:
```bash
curl -X POST http://localhost:8502/api/security-event \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "event_type": "malware_detection",
    "severity": "critical",
    "source": "CrowdStrike EDR",
    "description": "Malicious executable detected on DESKTOP-ABC123",
    "data": {
      "hostname": "DESKTOP-ABC123",
      "user": "john.doe",
      "process": "invoice.exe",
      "hash": "44d88612fea8a8f36de82e1278abb02f",
      "detection": "Trojan.Generic.KD.12345",
      "timestamp": "2024-01-15T14:30:00Z"
    }
  }'
```

**Response**:
```json
{
  "status": "success",
  "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "analysis": "**Executive Summary**\n\nCritical malware detection...",
  "agents_used": ["malware_reverse_engineer", "soc_analyst", "cyber_forensic_expert"],
  "timestamp": "2024-01-15T14:30:05Z"
}
```

**Analysis Includes**:
- Malware family identification
- Behavior analysis
- IOC extraction
- Containment recommendations (isolate host, kill process)
- Forensic preservation steps

---

## Advanced Multi-Agent Scenarios

### Example 9: Complex Threat Investigation

**Input**:
```
We're investigating a potential APT campaign:

Initial Detection:
- Spear-phishing email to executives
- PDF with embedded macro
- C2 beacon to 45.33.32.156:443

Follow-up Activity:
- Lateral movement to domain controller
- Credential dumping (Mimikatz signatures)
- Data staging in C:\Windows\Temp\update.cab (15 GB)

Current Status:
- 3 confirmed infected hosts
- Possible data exfiltration (large DNS queries)
- Attacker still has access

Provide comprehensive incident response plan.
```

**Expected Agents**: Multiple (Orchestrator will coordinate):
1. **Cyber Threat Intelligence Expert** - Attribution and campaign tracking
2. **Malware Reverse Engineer** - C2 beacon analysis
3. **Cyber Forensic Expert** - Evidence collection and timeline
4. **SOC Analyst** - Immediate containment actions
5. **Blue Teamer** - Detection and prevention improvements

**Comprehensive Output**:
- Full incident timeline
- Threat actor profile
- Complete IOC list
- Eradication plan
- Recovery procedures
- Post-incident hardening recommendations

---

## Integration Patterns

### Example 10: Automated Vulnerability Triage

**Scenario**: Automatically analyze vulnerability scan results

**WebHook Integration**:
```python
import requests

# Vulnerability scanner webhook
vulnerability_results = {
    "target": "production_web_app",
    "vulnerabilities": [
        {
            "cve": "CVE-2024-1234",
            "severity": "critical",
            "description": "RCE in Apache Struts",
            "affected_component": "struts-core-2.5.30.jar"
        },
        {
            "cve": "CVE-2024-5678",
            "severity": "high",
            "description": "XSS in React component",
            "affected_component": "user-profile.jsx"
        }
    ]
}

response = requests.post(
    'http://localhost:8502/api/vulnerability-scan',
    json=vulnerability_results
)

# Get prioritized remediation plan
print(response.json()['analysis'])
```

**Output**: Risk-prioritized remediation roadmap with exploitation likelihood and business impact.

---

## Tips for Best Results

### 1. Provide Context
**Bad**: "Is this IP malicious? 192.168.1.1"
**Good**: "Analyze IP 192.168.1.1 - saw 100 failed logins from this source in the last hour"

### 2. Include Relevant Details
- Timestamps
- System information
- Error messages
- Sample data (hashes, URLs, IPs)

### 3. Specify Your Goal
- "Investigate and recommend response" → Full analysis
- "Quick triage" → Fast assessment
- "Detection rules" → Focus on detection engineering

### 4. Use Structured Input for Complex Scenarios
```
Incident: Data Exfiltration

Timeline:
- [timestamp] [event]
- [timestamp] [event]

Evidence:
- [artifact 1]
- [artifact 2]

Questions:
1. What happened?
2. How do we contain it?
3. How do we prevent recurrence?
```

---

## Next Steps

- Try these examples in the Web UI
- Modify them for your specific use cases
- Integrate with your security tools via WebHook
- Build custom workflows with MCP

**Have a unique use case?** Share it in [GitHub Discussions](https://github.com/yourusername/cyberAgents/discussions)!
