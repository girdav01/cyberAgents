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
    """Specialist cybersecurity agent with advanced capabilities"""

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

        # Load agent-specific capabilities
        self.available_functions = []
        self.available_workflows = {}
        self._load_capabilities()

        super().__init__(
            name=agent_config['role'],
            role=agent_config['role'],
            system_prompt=agent_config['prompt'],
            llm_provider=llm_provider,
            config=config
        )

    def _load_capabilities(self):
        """Load agent-specific functions and workflows"""
        try:
            from .agent_capabilities import get_agent_functions, get_agent_workflows
            self.available_functions = get_agent_functions(self.agent_id)
            self.available_workflows = get_agent_workflows(self.agent_id)
            logger.info(f"Loaded {len(self.available_functions)} functions and {len(self.available_workflows)} workflows for {self.agent_id}")
        except Exception as e:
            logger.warning(f"Could not load capabilities for {self.agent_id}: {e}")

    def get_info(self) -> Dict[str, Any]:
        """Get agent information including capabilities"""
        return {
            'id': self.agent_id,
            'name': self.name,
            'role': self.role,
            'category': self.category,
            'description': self.description,
            'tools': self.tools,
            'frameworks': self.frameworks,
            'output_format': self.output_format,
            'function_count': len(self.available_functions),
            'workflow_count': len(self.available_workflows),
            'functions': [f.name for f in self.available_functions],
            'workflows': list(self.available_workflows.keys())
        }

    def get_function_info(self, function_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific function"""
        for func in self.available_functions:
            if func.name == function_name:
                return {
                    'name': func.name,
                    'description': func.description,
                    'category': func.category.value,
                    'parameters': func.parameters,
                    'output_format': func.output_format,
                    'required_tools': func.required_tools,
                    'estimated_time': func.estimated_time
                }
        return None

    def get_workflow_info(self, workflow_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific workflow"""
        if workflow_name in self.available_workflows:
            workflow_functions = self.available_workflows[workflow_name]
            return {
                'name': workflow_name,
                'steps': workflow_functions,
                'step_count': len(workflow_functions),
                'estimated_total_time': self._calculate_workflow_time(workflow_functions)
            }
        return None

    def _calculate_workflow_time(self, workflow_functions: List[str]) -> str:
        """Calculate estimated time for a workflow"""
        # Simple estimation - in practice this would be more sophisticated
        return f"{len(workflow_functions) * 60}-{len(workflow_functions) * 120} minutes"

    def list_functions_by_category(self, category: str) -> List[str]:
        """List all functions in a specific category"""
        from .agent_capabilities import FunctionCategory
        try:
            cat_enum = FunctionCategory(category)
            return [f.name for f in self.available_functions if f.category == cat_enum]
        except ValueError:
            return []

    def execute_function(self, function_name: str, parameters: Dict[str, Any]) -> AgentResponse:
        """Execute a specific function with given parameters"""
        func_info = self.get_function_info(function_name)

        if not func_info:
            return AgentResponse(
                agent_name=self.name,
                agent_role=self.role,
                task_id=f"func_{function_name}",
                content="",
                error=f"Function '{function_name}' not found for this agent"
            )

        # Build a specialized task for this function
        task_content = self._build_function_task(func_info, parameters)

        task = AgentTask(
            task_id=f"func_{function_name}_{datetime.now().timestamp()}",
            content=task_content,
            context={'function': function_name, 'parameters': parameters}
        )

        return self.process_task(task)

    def _build_function_task(self, func_info: Dict[str, Any], parameters: Dict[str, Any]) -> str:
        """Build a task description for function execution"""
        task_parts = [
            f"**Function**: {func_info['name']}",
            f"**Description**: {func_info['description']}",
            f"**Expected Output Format**: {func_info['output_format']}",
            "",
            "**Parameters**:"
        ]

        for key, value in parameters.items():
            task_parts.append(f"- {key}: {value}")

        task_parts.extend([
            "",
            "**Required Tools**: " + ", ".join(func_info['required_tools']),
            "",
            "Please execute this function with the provided parameters and return results in the specified output format."
        ])

        return "\n".join(task_parts)

    def execute_workflow(self, workflow_name: str, parameters: Dict[str, Any]) -> List[AgentResponse]:
        """Execute a complete workflow"""
        workflow_info = self.get_workflow_info(workflow_name)

        if not workflow_info:
            return [AgentResponse(
                agent_name=self.name,
                agent_role=self.role,
                task_id=f"workflow_{workflow_name}",
                content="",
                error=f"Workflow '{workflow_name}' not found for this agent"
            )]

        responses = []
        workflow_context = parameters.copy()

        for step_function in workflow_info['steps']:
            logger.info(f"Executing workflow step: {step_function}")
            response = self.execute_function(step_function, workflow_context)
            responses.append(response)

            # Update context with previous step's output for next step
            if not response.error:
                workflow_context[f"{step_function}_output"] = response.content

        return responses
