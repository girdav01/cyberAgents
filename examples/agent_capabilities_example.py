#!/usr/bin/env python3
"""
Example usage of agent capabilities and functions

This script demonstrates how to use the expanded agent capabilities,
execute individual functions, and run predefined workflows.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
from src.core.agent_manager import AgentManager
from src.core.agent_capabilities import get_all_agent_capabilities
from src.tools.tool_integrations import get_tools_for_agent, get_tool_recommendations


def load_config():
    """Load configuration from config.yaml"""
    import yaml
    with open('config/config.yaml', 'r') as f:
        return yaml.safe_load(f)


def example_1_list_all_capabilities():
    """Example 1: List all agent capabilities"""
    print("=" * 80)
    print("EXAMPLE 1: Listing All Agent Capabilities")
    print("=" * 80)

    capabilities = get_all_agent_capabilities()

    for agent_id, info in capabilities.items():
        print(f"\n{agent_id.upper()}")
        print(f"  Functions: {info['function_count']}")
        print(f"  Workflows: {info['workflow_count']}")
        print(f"  Available Functions: {', '.join(info['functions'][:3])}...")
        print(f"  Available Workflows: {', '.join(info['workflows'])}")


def example_2_get_agent_details():
    """Example 2: Get detailed information about a specific agent"""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Getting Agent Details")
    print("=" * 80)

    config = load_config()
    manager = AgentManager(config)

    # Get malware reverse engineer agent
    agent = manager.get_agent_by_id("malware_reverse_engineer")

    if agent:
        info = agent.get_info()
        print(f"\nAgent: {info['name']}")
        print(f"Role: {info['role']}")
        print(f"Category: {info['category']}")
        print(f"Description: {info['description']}")
        print(f"\nFunctions ({info['function_count']}):")
        for func_name in info['functions']:
            print(f"  - {func_name}")

        print(f"\nWorkflows ({info['workflow_count']}):")
        for workflow_name in info['workflows']:
            print(f"  - {workflow_name}")


def example_3_get_function_details():
    """Example 3: Get details about a specific function"""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Getting Function Details")
    print("=" * 80)

    config = load_config()
    manager = AgentManager(config)

    agent = manager.get_agent_by_id("malware_reverse_engineer")

    if agent:
        # Get details about static_binary_analysis function
        func_info = agent.get_function_info("static_binary_analysis")

        if func_info:
            print(f"\nFunction: {func_info['name']}")
            print(f"Description: {func_info['description']}")
            print(f"Category: {func_info['category']}")
            print(f"Estimated Time: {func_info['estimated_time']}")
            print(f"\nParameters:")
            for param in func_info['parameters']:
                print(f"  - {param['name']}: {param['type']}")
                if 'options' in param:
                    print(f"    Options: {param['options']}")
            print(f"\nRequired Tools:")
            for tool in func_info['required_tools']:
                print(f"  - {tool}")
            print(f"\nOutput Format: {func_info['output_format']}")


def example_4_execute_function():
    """Example 4: Execute a single function"""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Executing a Single Function")
    print("=" * 80)

    config = load_config()
    manager = AgentManager(config)

    agent = manager.get_agent_by_id("cyber_threat_intelligence_expert")

    if agent:
        print(f"\nExecuting 'ioc_enrichment' function...")

        response = agent.execute_function(
            "ioc_enrichment",
            {
                "ioc_value": "1.2.3.4",
                "ioc_type": "ip",
                "sources": ["VirusTotal", "Shodan"]
            }
        )

        print(f"\nAgent: {response.agent_name}")
        print(f"Status: {'Success' if not response.error else 'Error'}")
        if response.error:
            print(f"Error: {response.error}")
        else:
            print(f"Response Preview: {response.content[:500]}...")


def example_5_execute_workflow():
    """Example 5: Execute a complete workflow"""
    print("\n" + "=" * 80)
    print("EXAMPLE 5: Executing a Workflow")
    print("=" * 80)

    config = load_config()
    manager = AgentManager(config)

    agent = manager.get_agent_by_id("soc_analyst")

    if agent:
        # Get workflow details first
        workflow_info = agent.get_workflow_info("alert_to_resolution")

        if workflow_info:
            print(f"\nWorkflow: {workflow_info['name']}")
            print(f"Steps: {workflow_info['step_count']}")
            print(f"Estimated Time: {workflow_info['estimated_total_time']}")
            print(f"\nWorkflow Steps:")
            for i, step in enumerate(workflow_info['steps'], 1):
                print(f"  {i}. {step}")

            print(f"\nExecuting workflow...")

            responses = agent.execute_workflow(
                "alert_to_resolution",
                {
                    "alert_id": "ALERT-12345",
                    "hostname": "workstation-42"
                }
            )

            print(f"\nWorkflow completed with {len(responses)} steps")
            for i, response in enumerate(responses, 1):
                print(f"\nStep {i}: {response.agent_name}")
                print(f"  Status: {'Success' if not response.error else 'Error'}")
                if response.error:
                    print(f"  Error: {response.error}")


def example_6_list_functions_by_category():
    """Example 6: List functions by category"""
    print("\n" + "=" * 80)
    print("EXAMPLE 6: Listing Functions by Category")
    print("=" * 80)

    config = load_config()
    manager = AgentManager(config)

    agent = manager.get_agent_by_id("blue_teamer")

    if agent:
        categories = ["detection", "investigation", "defense"]

        for category in categories:
            functions = agent.list_functions_by_category(category)
            print(f"\n{category.upper()} Functions:")
            for func_name in functions:
                print(f"  - {func_name}")


def example_7_tool_integrations():
    """Example 7: Explore tool integrations"""
    print("\n" + "=" * 80)
    print("EXAMPLE 7: Tool Integrations")
    print("=" * 80)

    # Get tools for a specific agent
    agent_tools = ["IDA Pro", "Ghidra", "YARA", "VirusTotal"]
    integrations = get_tools_for_agent(agent_tools)

    print(f"\nTool Integrations for Malware Reverse Engineer:")
    for tool in integrations:
        print(f"\n{tool.name}")
        print(f"  Category: {tool.category.value}")
        print(f"  API Available: {tool.api_available}")
        print(f"  Local Execution: {tool.local_execution}")
        print(f"  Cloud Service: {tool.cloud_service}")

    # Get tool recommendations for a function
    print("\n" + "-" * 80)
    recommendations = get_tool_recommendations("static_binary_analysis", "malware_reverse_engineer")
    print(f"\nRecommended tools for static_binary_analysis:")
    for tool_name in recommendations:
        print(f"  - {tool_name}")


def example_8_orchestrator_with_capabilities():
    """Example 8: Using orchestrator with agent capabilities"""
    print("\n" + "=" * 80)
    print("EXAMPLE 8: Orchestrator with Agent Capabilities")
    print("=" * 80)

    config = load_config()
    manager = AgentManager(config)

    # Make a request that will be routed to appropriate agents
    request = """
    I need to analyze a suspicious binary file found on a compromised system.
    The file is located at /samples/suspicious.exe.
    Please perform a complete analysis including static analysis, dynamic analysis,
    IOC extraction, and create YARA rules for detection.
    """

    print(f"\nRequest: {request[:100]}...")
    print(f"\nProcessing request through orchestrator...")

    result = manager.process_request(request)

    print(f"\nTask ID: {result['task_id']}")
    print(f"\nOrchestrator Decision:")
    print(f"  Selected Agents: {result['decision']['selected_agents']}")
    print(f"  Reasoning: {result['decision']['reasoning'][:200]}...")

    if 'agent_responses' in result and result['agent_responses']:
        print(f"\nAgent Responses:")
        for agent_resp in result['agent_responses']:
            print(f"\n  {agent_resp['agent']}:")
            print(f"    Status: {'Success' if not agent_resp['error'] else 'Error'}")
            if agent_resp['error']:
                print(f"    Error: {agent_resp['error']}")


def main():
    """Run all examples"""
    try:
        print("\n" + "=" * 80)
        print("CYBERSECURITY AGENT CAPABILITIES - EXAMPLES")
        print("=" * 80)

        example_1_list_all_capabilities()
        example_2_get_agent_details()
        example_3_get_function_details()
        example_4_execute_function()
        example_5_execute_workflow()
        example_6_list_functions_by_category()
        example_7_tool_integrations()
        example_8_orchestrator_with_capabilities()

        print("\n" + "=" * 80)
        print("ALL EXAMPLES COMPLETED")
        print("=" * 80)

    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
