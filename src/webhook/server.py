"""
WebHook Server for External Event Integration
Receives security events from external systems
"""

import os
import yaml
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
from functools import wraps

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.agent_manager import AgentManager

logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Global agent manager
agent_manager: Optional[AgentManager] = None
webhook_config: Dict[str, Any] = {}


def load_configuration():
    """Load application configuration"""
    config_path = Path("config/app_config.yaml")
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not webhook_config.get('api_key'):
            # API key not configured, skip authentication
            return f(*args, **kwargs)

        provided_key = request.headers.get('X-API-Key')
        expected_key = webhook_config.get('api_key')

        if provided_key != expected_key:
            return jsonify({
                'error': 'Invalid or missing API key',
                'status': 'unauthorized'
            }), 401

        return f(*args, **kwargs)
    return decorated_function


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'CyberAgents WebHook Server',
        'agents_available': len(agent_manager.get_available_agents()) if agent_manager else 0
    })


@app.route('/api/security-event', methods=['POST'])
@require_api_key
def security_event():
    """
    Handle security event submissions

    Expected payload:
    {
        "event_type": "malware_detection|intrusion_attempt|vulnerability_scan|...",
        "description": "Event description",
        "severity": "low|medium|high|critical",
        "source": "SIEM|EDR|Firewall|...",
        "data": { ... additional data ... }
    }
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        payload = request.get_json()

        # Validate required fields
        required_fields = ['event_type', 'description']
        missing_fields = [f for f in required_fields if f not in payload]
        if missing_fields:
            return jsonify({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400

        # Build analysis request
        event_type = payload.get('event_type')
        description = payload.get('description')
        severity = payload.get('severity', 'unknown')
        source = payload.get('source', 'unknown')
        data = payload.get('data', {})

        analysis_request = f"""Security Event Analysis Request:

Event Type: {event_type}
Severity: {severity}
Source: {source}

Description:
{description}

Additional Data:
{json.dumps(data, indent=2)}

Please analyze this security event and provide:
1. Assessment of the threat
2. Recommended actions
3. Relevant IOCs or indicators
4. Mitigation strategies
"""

        context = {
            'event_type': event_type,
            'severity': severity,
            'source': source,
            'webhook_timestamp': datetime.now().isoformat()
        }

        # Process through agent system
        result = agent_manager.process_request(analysis_request, context)

        return jsonify({
            'status': 'success',
            'task_id': result.get('task_id'),
            'analysis': result.get('response'),
            'agents_used': result.get('decision', {}).get('selected_agents', []),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error processing security event: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@app.route('/api/ioc-report', methods=['POST'])
@require_api_key
def ioc_report():
    """
    Handle Indicator of Compromise (IOC) submissions

    Expected payload:
    {
        "ioc_type": "ip|domain|hash|url|email|...",
        "ioc_value": "192.168.1.1",
        "context": "Description or context",
        "source": "VirusTotal|AlienVault|..."
    }
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        payload = request.get_json()

        ioc_type = payload.get('ioc_type', 'unknown')
        ioc_value = payload.get('ioc_value')
        context_desc = payload.get('context', '')
        source = payload.get('source', 'unknown')

        if not ioc_value:
            return jsonify({'error': 'ioc_value is required'}), 400

        analysis_request = f"""IOC Analysis Request:

IOC Type: {ioc_type}
IOC Value: {ioc_value}
Source: {source}

Context:
{context_desc}

Please analyze this indicator of compromise and provide:
1. Threat assessment and attribution
2. Related campaigns or threat actors
3. Recommended detection rules
4. Containment and remediation steps
"""

        context = {
            'ioc_type': ioc_type,
            'ioc_value': ioc_value,
            'source': source
        }

        result = agent_manager.process_request(analysis_request, context)

        return jsonify({
            'status': 'success',
            'task_id': result.get('task_id'),
            'analysis': result.get('response'),
            'agents_used': result.get('decision', {}).get('selected_agents', []),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error processing IOC report: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@app.route('/api/vulnerability-scan', methods=['POST'])
def vulnerability_scan():
    """
    Handle vulnerability scan results (no auth required by default)

    Expected payload:
    {
        "target": "application|system|network",
        "vulnerabilities": [
            {
                "cve": "CVE-2024-1234",
                "severity": "high",
                "description": "...",
                "affected_component": "..."
            }
        ]
    }
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        payload = request.get_json()

        target = payload.get('target', 'unknown')
        vulnerabilities = payload.get('vulnerabilities', [])

        if not vulnerabilities:
            return jsonify({'error': 'No vulnerabilities provided'}), 400

        # Build vulnerability summary
        vuln_summary = "\n".join([
            f"- CVE: {v.get('cve', 'N/A')}, Severity: {v.get('severity', 'unknown')}, Component: {v.get('affected_component', 'N/A')}"
            for v in vulnerabilities
        ])

        analysis_request = f"""Vulnerability Scan Analysis:

Target: {target}
Vulnerabilities Found: {len(vulnerabilities)}

Vulnerability Summary:
{vuln_summary}

Detailed Vulnerabilities:
{json.dumps(vulnerabilities, indent=2)}

Please analyze these vulnerabilities and provide:
1. Risk assessment and prioritization
2. Exploitation likelihood
3. Recommended remediation steps
4. Compensating controls if patching is not immediate
"""

        context = {
            'target': target,
            'vulnerability_count': len(vulnerabilities)
        }

        result = agent_manager.process_request(analysis_request, context)

        return jsonify({
            'status': 'success',
            'task_id': result.get('task_id'),
            'analysis': result.get('response'),
            'agents_used': result.get('decision', {}).get('selected_agents', []),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error processing vulnerability scan: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@app.route('/api/analyze', methods=['POST'])
@require_api_key
def analyze():
    """
    Generic analysis endpoint

    Expected payload:
    {
        "request": "Analysis request text",
        "context": { ... optional context ... }
    }
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        payload = request.get_json()
        analysis_request = payload.get('request')
        context = payload.get('context')

        if not analysis_request:
            return jsonify({'error': 'request field is required'}), 400

        result = agent_manager.process_request(analysis_request, context)

        return jsonify({
            'status': 'success',
            'task_id': result.get('task_id'),
            'analysis': result.get('response'),
            'agents_used': result.get('decision', {}).get('selected_agents', []),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error processing analysis request: {e}", exc_info=True)
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


def initialize_webhook_server():
    """Initialize the webhook server"""
    global agent_manager, webhook_config

    # Load configuration
    config = load_configuration()

    # Initialize agent manager
    agent_manager = AgentManager(config)
    logger.info("Agent manager initialized for webhook server")

    # Get webhook configuration
    webhook_config = config.get('webhook', {})

    # Get API key from env or config
    api_key = os.getenv('WEBHOOK_API_KEY') or webhook_config.get('api_key', '')
    if api_key.startswith('${') and api_key.endswith('}'):
        # Environment variable reference
        env_var = api_key[2:-1]
        api_key = os.getenv(env_var, '')

    webhook_config['api_key'] = api_key

    if api_key:
        logger.info("API key authentication enabled")
    else:
        logger.warning("API key not configured - authentication disabled")


def run_webhook_server(host: str = None, port: int = None):
    """Run the webhook server"""
    initialize_webhook_server()

    host = host or webhook_config.get('host', '0.0.0.0')
    port = port or webhook_config.get('port', 8502)

    logger.info(f"Starting WebHook server on {host}:{port}")

    app.run(
        host=host,
        port=port,
        debug=False
    )


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    run_webhook_server()
