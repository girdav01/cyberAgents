"""
Orchestrator Agent with Reasoning Capabilities
Routes tasks to specialist agents and synthesizes responses
"""

import logging
import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from .agent import BaseAgent, AgentTask, AgentResponse
from .llm_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorDecision:
    """Orchestrator's decision on how to handle a task"""
    analysis: str
    selected_agents: List[str]
    sub_tasks: List[Dict[str, Any]]
    reasoning: str


class OrchestratorAgent(BaseAgent):
    """
    Orchestrator agent with reasoning capabilities
    Uses reasoning models like PHI-4 or GPT-4o to coordinate specialists
    """

    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        specialist_registry: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None
    ):
        self.specialist_registry = specialist_registry
        self.max_iterations = config.get('max_iterations', 10) if config else 10

        # Build system prompt with specialist information
        system_prompt = self._build_orchestrator_prompt()

        super().__init__(
            name="CyberSecOrchestrator",
            role="Orchestrator",
            system_prompt=system_prompt,
            llm_provider=llm_provider,
            config=config
        )

    def _build_orchestrator_prompt(self) -> str:
        """Build the orchestrator system prompt with specialist info"""
        base_prompt = """You are the CyberSec Orchestrator, a reasoning agent responsible for coordinating multiple specialized cybersecurity agents.

Your capabilities:
- Analyze incoming security requests and break them into sub-tasks
- Route tasks to appropriate specialist agents
- Synthesize responses from multiple agents
- Provide comprehensive security analysis and recommendations

Available specialists:
"""

        for agent_id, info in self.specialist_registry.items():
            base_prompt += f"\n{agent_id}. {info['name']}"
            base_prompt += f"\n   Category: {info['category']}"
            base_prompt += f"\n   Description: {info['description']}"
            base_prompt += f"\n   Tools: {', '.join(info['tools'])}"
            base_prompt += "\n"

        base_prompt += """
When you receive a task:
1. Analyze the request and identify required specialists
2. Create specific sub-tasks for each specialist
3. Return your decision in JSON format:
{
  "analysis": "Your analysis of the request",
  "selected_agents": ["agent_id1", "agent_id2"],
  "sub_tasks": [
    {"agent_id": "agent_id1", "task": "Specific task description"},
    {"agent_id": "agent_id2", "task": "Specific task description"}
  ],
  "reasoning": "Why you selected these agents and tasks"
}

For simple queries or general guidance, you can respond directly without delegating.
Return JSON ONLY when you need to delegate to specialists.
"""

        return base_prompt

    def analyze_task(self, task: AgentTask) -> OrchestratorDecision:
        """Analyze task and decide which agents to use"""
        try:
            analysis_prompt = f"""Analyze this cybersecurity request and determine which specialist agents should handle it:

REQUEST: {task.content}

If this requires specialist expertise, respond with a JSON object containing your decision.
If this is a simple query you can answer directly, just provide the answer without JSON.

Remember to use the JSON format specified in your system prompt when delegating to specialists."""

            llm_response = self.llm_provider.generate(
                prompt=analysis_prompt,
                system_prompt=self.system_prompt,
                model=self.llm_provider.models.get('reasoning'),
                temperature=0.7,
                max_tokens=2048
            )

            if llm_response.error:
                logger.error(f"Error in orchestrator analysis: {llm_response.error}")
                # Fallback: use a general agent
                return OrchestratorDecision(
                    analysis="Error in analysis, using fallback",
                    selected_agents=["soc_analyst"],
                    sub_tasks=[{"agent_id": "soc_analyst", "task": task.content}],
                    reasoning="Fallback to SOC Analyst due to analysis error"
                )

            content = llm_response.content.strip()

            # Try to extract JSON from the response
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                try:
                    decision_data = json.loads(json_match.group())
                    return OrchestratorDecision(
                        analysis=decision_data.get('analysis', ''),
                        selected_agents=decision_data.get('selected_agents', []),
                        sub_tasks=decision_data.get('sub_tasks', []),
                        reasoning=decision_data.get('reasoning', '')
                    )
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON decision: {e}")

            # If no JSON found, treat as direct response (no delegation needed)
            logger.info("Orchestrator providing direct response without delegation")
            return OrchestratorDecision(
                analysis=content,
                selected_agents=[],
                sub_tasks=[],
                reasoning="Direct response without specialist delegation"
            )

        except Exception as e:
            logger.error(f"Error in task analysis: {e}", exc_info=True)
            # Fallback decision
            return OrchestratorDecision(
                analysis="Error occurred during analysis",
                selected_agents=["soc_analyst"],
                sub_tasks=[{"agent_id": "soc_analyst", "task": task.content}],
                reasoning="Fallback to SOC Analyst due to error"
            )

    def synthesize_responses(
        self,
        original_task: str,
        agent_responses: List[AgentResponse],
        decision: OrchestratorDecision
    ) -> str:
        """Synthesize responses from multiple agents"""
        try:
            synthesis_prompt = f"""You coordinated multiple cybersecurity specialists to analyze this request:

ORIGINAL REQUEST: {original_task}

YOUR ANALYSIS: {decision.analysis}

SPECIALIST RESPONSES:
"""

            for i, response in enumerate(agent_responses, 1):
                synthesis_prompt += f"\n{i}. {response.agent_role}:\n{response.content}\n"

            synthesis_prompt += """
Now synthesize these specialist responses into a comprehensive, actionable answer.
Structure your response with:
1. Executive Summary
2. Detailed Findings (from each specialist)
3. Recommended Actions
4. Conclusion

Be concise but thorough. Focus on actionable insights."""

            llm_response = self.llm_provider.generate(
                prompt=synthesis_prompt,
                system_prompt="You are a cybersecurity analyst synthesizing expert opinions into actionable recommendations.",
                model=self.llm_provider.models.get('reasoning'),
                temperature=0.5,
                max_tokens=4096
            )

            if llm_response.error:
                logger.error(f"Error in synthesis: {llm_response.error}")
                # Fallback: concatenate responses
                return self._simple_concatenate(agent_responses)

            return llm_response.content

        except Exception as e:
            logger.error(f"Error in synthesis: {e}", exc_info=True)
            return self._simple_concatenate(agent_responses)

    def _simple_concatenate(self, responses: List[AgentResponse]) -> str:
        """Simple concatenation fallback"""
        result = "**Analysis Results:**\n\n"
        for response in responses:
            result += f"**{response.agent_role}:**\n{response.content}\n\n"
        return result
