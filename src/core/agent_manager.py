"""
Agent Manager - Loads and manages all agents
"""

import json
import logging
import uuid
from typing import Dict, List, Optional, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from .agent import SpecialistAgent, AgentTask, AgentResponse
from .orchestrator import OrchestratorAgent, OrchestratorDecision
from .llm_provider import BaseLLMProvider, LLMProviderFactory

logger = logging.getLogger(__name__)


class AgentManager:
    """Manages all agents in the system"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.specialist_agents: Dict[str, SpecialistAgent] = {}
        self.orchestrator: Optional[OrchestratorAgent] = None
        self.llm_provider: Optional[BaseLLMProvider] = None

        self._initialize()

    def _initialize(self):
        """Initialize the agent system"""
        # Initialize LLM provider
        provider_config = self.config.get('llm_provider', {})
        default_provider = provider_config.get('default', 'ollama')

        provider_settings = provider_config.get(default_provider, {})
        self.llm_provider = LLMProviderFactory.create_provider(
            default_provider,
            provider_settings
        )

        logger.info(f"Initialized LLM provider: {default_provider}")

        # Check provider availability
        if not self.llm_provider.is_available():
            logger.warning(f"LLM provider {default_provider} may not be available")

        # Load specialist agents
        self._load_specialist_agents()

        # Initialize orchestrator
        self._initialize_orchestrator()

        logger.info(f"Agent Manager initialized with {len(self.specialist_agents)} specialists")

    def _load_specialist_agents(self):
        """Load specialist agents from configuration"""
        agents_config = self.config.get('agents', {})
        config_file = agents_config.get('config_file', 'config/cybersec-system-prompts.json')

        config_path = Path(config_file)
        if not config_path.exists():
            logger.error(f"Agent config file not found: {config_file}")
            return

        with open(config_path, 'r') as f:
            prompts_config = json.load(f)

        system_prompts = prompts_config.get('system_prompts', {})

        for agent_id, agent_config in system_prompts.items():
            try:
                specialist = SpecialistAgent(
                    agent_id=agent_id,
                    agent_config=agent_config,
                    llm_provider=self.llm_provider,
                    config=agents_config
                )
                self.specialist_agents[agent_id] = specialist
                logger.info(f"Loaded specialist: {agent_id} - {specialist.name}")
            except Exception as e:
                logger.error(f"Failed to load specialist {agent_id}: {e}")

    def _initialize_orchestrator(self):
        """Initialize the orchestrator agent"""
        # Build specialist registry
        specialist_registry = {
            agent_id: agent.get_info()
            for agent_id, agent in self.specialist_agents.items()
        }

        orchestrator_config = self.config.get('orchestrator', {})

        self.orchestrator = OrchestratorAgent(
            llm_provider=self.llm_provider,
            specialist_registry=specialist_registry,
            config=orchestrator_config
        )

        logger.info("Orchestrator initialized")

    def process_request(self, request: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process a cybersecurity request through the multi-agent system
        """
        task_id = str(uuid.uuid4())
        logger.info(f"Processing request {task_id}: {request[:100]}...")

        try:
            # Create task
            task = AgentTask(
                task_id=task_id,
                content=request,
                context=context
            )

            # Orchestrator analyzes the task
            decision = self.orchestrator.analyze_task(task)

            # If no agents selected, orchestrator handled it directly
            if not decision.selected_agents:
                return {
                    'task_id': task_id,
                    'request': request,
                    'decision': {
                        'analysis': decision.analysis,
                        'selected_agents': [],
                        'reasoning': decision.reasoning
                    },
                    'response': decision.analysis,
                    'agent_responses': []
                }

            # Execute sub-tasks with specialist agents
            agent_responses = self._execute_subtasks(decision, task_id)

            # Synthesize responses
            final_response = self.orchestrator.synthesize_responses(
                original_task=request,
                agent_responses=agent_responses,
                decision=decision
            )

            return {
                'task_id': task_id,
                'request': request,
                'decision': {
                    'analysis': decision.analysis,
                    'selected_agents': decision.selected_agents,
                    'reasoning': decision.reasoning
                },
                'response': final_response,
                'agent_responses': [
                    {
                        'agent': r.agent_name,
                        'role': r.agent_role,
                        'content': r.content,
                        'error': r.error
                    }
                    for r in agent_responses
                ]
            }

        except Exception as e:
            logger.error(f"Error processing request {task_id}: {e}", exc_info=True)
            return {
                'task_id': task_id,
                'request': request,
                'error': str(e),
                'response': f"An error occurred while processing your request: {str(e)}"
            }

    def _execute_subtasks(
        self,
        decision: OrchestratorDecision,
        parent_task_id: str
    ) -> List[AgentResponse]:
        """Execute sub-tasks with specialist agents"""
        responses = []

        concurrent = self.config.get('agents', {}).get('concurrent_execution', True)

        if concurrent and len(decision.sub_tasks) > 1:
            # Execute in parallel
            with ThreadPoolExecutor(max_workers=min(len(decision.sub_tasks), 5)) as executor:
                future_to_task = {}

                for subtask in decision.sub_tasks:
                    agent_id = subtask.get('agent_id')
                    task_content = subtask.get('task')

                    if agent_id not in self.specialist_agents:
                        logger.warning(f"Unknown agent: {agent_id}")
                        continue

                    agent = self.specialist_agents[agent_id]
                    task = AgentTask(
                        task_id=f"{parent_task_id}_{agent_id}",
                        content=task_content
                    )

                    future = executor.submit(agent.process_task, task)
                    future_to_task[future] = agent_id

                for future in as_completed(future_to_task):
                    try:
                        response = future.result()
                        responses.append(response)
                    except Exception as e:
                        agent_id = future_to_task[future]
                        logger.error(f"Error executing task for {agent_id}: {e}")
        else:
            # Execute sequentially
            for subtask in decision.sub_tasks:
                agent_id = subtask.get('agent_id')
                task_content = subtask.get('task')

                if agent_id not in self.specialist_agents:
                    logger.warning(f"Unknown agent: {agent_id}")
                    continue

                agent = self.specialist_agents[agent_id]
                task = AgentTask(
                    task_id=f"{parent_task_id}_{agent_id}",
                    content=task_content
                )

                response = agent.process_task(task)
                responses.append(response)

        return responses

    def get_available_agents(self) -> List[Dict[str, Any]]:
        """Get list of available specialist agents"""
        return [agent.get_info() for agent in self.specialist_agents.values()]

    def get_agent_by_id(self, agent_id: str) -> Optional[SpecialistAgent]:
        """Get a specialist agent by ID"""
        return self.specialist_agents.get(agent_id)
