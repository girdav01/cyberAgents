"""
Tools Integration Module
"""

from .tool_integrations import (
    ToolIntegration,
    ToolCategory,
    ToolExecutor,
    TOOL_REGISTRY,
    get_tool,
    get_tools_by_category,
    get_api_tools,
    get_local_tools,
    get_tools_for_agent,
    get_tool_recommendations,
    MalwareAnalysisTools,
    ThreatIntelligenceTools,
    ForensicsTools,
    SIEMEDRTools,
    OffensiveTools,
    DefensiveTools,
    CodeSecurityTools
)

__all__ = [
    'ToolIntegration',
    'ToolCategory',
    'ToolExecutor',
    'TOOL_REGISTRY',
    'get_tool',
    'get_tools_by_category',
    'get_api_tools',
    'get_local_tools',
    'get_tools_for_agent',
    'get_tool_recommendations',
    'MalwareAnalysisTools',
    'ThreatIntelligenceTools',
    'ForensicsTools',
    'SIEMEDRTools',
    'OffensiveTools',
    'DefensiveTools',
    'CodeSecurityTools'
]
