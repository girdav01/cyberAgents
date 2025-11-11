"""
Base Agent and Specialist Agent Implementation
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

from .llm_provider import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


@dataclass
class AgentTask:
    """Represents a task for an agent"""
    task_id: str
    content: str
    context: Optional[Dict[str, Any]] = None
    priority: int = 1
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()


@dataclass
class AgentResponse:
    """Represents an agent's response"""
    agent_name: str
    agent_role: str
    task_id: str
    content: str
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class BaseAgent:
    """Base class for all agents"""

    def __init__(
        self,
        name: str,
        role: str,
        system_prompt: str,
        llm_provider: BaseLLMProvider,
        config: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.llm_provider = llm_provider
        self.config = config or {}
        self.temperature = self.config.get('temperature', 0.3)
        self.max_tokens = self.config.get('max_tokens', 4096)

        logger.info(f"Initialized agent: {self.name} ({self.role})")

    def process_task(self, task: AgentTask) -> AgentResponse:
        """Process a task and return a response"""
        try:
            logger.info(f"Agent {self.name} processing task {task.task_id}")

            # Build the prompt with context
            prompt = self._build_prompt(task)

            # Generate response using LLM
            llm_response = self.llm_provider.generate(
                prompt=prompt,
                system_prompt=self.system_prompt,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )

            if llm_response.error:
                logger.error(f"LLM error for agent {self.name}: {llm_response.error}")
                return AgentResponse(
                    agent_name=self.name,
                    agent_role=self.role,
                    task_id=task.task_id,
                    content="",
                    error=llm_response.error
                )

            # Post-process the response
            processed_content = self._post_process(llm_response.content)

            return AgentResponse(
                agent_name=self.name,
                agent_role=self.role,
                task_id=task.task_id,
                content=processed_content,
                metadata={
                    'model': llm_response.model,
                    'provider': llm_response.provider,
                    'usage': llm_response.usage
                }
            )

        except Exception as e:
            logger.error(f"Error in agent {self.name}: {e}", exc_info=True)
            return AgentResponse(
                agent_name=self.name,
                agent_role=self.role,
                task_id=task.task_id,
                content="",
                error=str(e)
            )

    def _build_prompt(self, task: AgentTask) -> str:
        """Build the prompt for the LLM"""
        prompt_parts = [task.content]

        if task.context:
            context_str = "\n\n**Additional Context:**\n"
            for key, value in task.context.items():
                context_str += f"- {key}: {value}\n"
            prompt_parts.insert(0, context_str)

        return "\n".join(prompt_parts)

    def _post_process(self, content: str) -> str:
        """Post-process the LLM response"""
        # Basic sanitization
        content = content.strip()
        return content


class SpecialistAgent(BaseAgent):
    """Specialist cybersecurity agent"""

    def __init__(
        self,
        agent_id: str,
        agent_config: Dict[str, Any],
        llm_provider: BaseLLMProvider,
        config: Optional[Dict[str, Any]] = None
    ):
        self.agent_id = agent_id
        self.category = agent_config.get('category', 'general')
        self.description = agent_config.get('description', '')
        self.tools = agent_config.get('tools', [])
        self.frameworks = agent_config.get('frameworks', [])
        self.output_format = agent_config.get('output_format', '')

        super().__init__(
            name=agent_config['role'],
            role=agent_config['role'],
            system_prompt=agent_config['prompt'],
            llm_provider=llm_provider,
            config=config
        )

    def get_info(self) -> Dict[str, Any]:
        """Get agent information"""
        return {
            'id': self.agent_id,
            'name': self.name,
            'role': self.role,
            'category': self.category,
            'description': self.description,
            'tools': self.tools,
            'frameworks': self.frameworks,
            'output_format': self.output_format
        }
