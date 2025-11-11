"""
LLM Provider Abstraction Layer
Supports Ollama, LM Studio, and OpenAI-compatible APIs
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import requests
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized LLM response"""
    content: str
    model: str
    provider: str
    usage: Optional[Dict[str, int]] = None
    error: Optional[str] = None


class BaseLLMProvider(ABC):
    """Base class for LLM providers"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get('base_url')
        self.timeout = config.get('timeout', 300)
        self.models = config.get('models', {})

    @abstractmethod
    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> LLMResponse:
        """Generate completion from the LLM"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is available"""
        pass


class OllamaProvider(BaseLLMProvider):
    """Ollama LLM Provider"""

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> LLMResponse:
        """Generate completion using Ollama"""
        try:
            model = model or self.models.get('specialist', 'llama3.2:latest')

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                }
            }

            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            content = data.get('message', {}).get('content', '')

            return LLMResponse(
                content=content,
                model=model,
                provider='ollama',
                usage={
                    'prompt_tokens': data.get('prompt_eval_count', 0),
                    'completion_tokens': data.get('eval_count', 0)
                }
            )

        except Exception as e:
            logger.error(f"Ollama generation error: {e}")
            return LLMResponse(
                content="",
                model=model or "unknown",
                provider='ollama',
                error=str(e)
            )

    def is_available(self) -> bool:
        """Check if Ollama is available"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"Ollama not available: {e}")
            return False


class LMStudioProvider(BaseLLMProvider):
    """LM Studio LLM Provider (OpenAI-compatible)"""

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> LLMResponse:
        """Generate completion using LM Studio"""
        try:
            model = model or self.models.get('specialist', 'local-model')

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            headers = {
                "Content-Type": "application/json"
            }

            api_key = self.config.get('api_key')
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "stream": False
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            content = data['choices'][0]['message']['content']
            usage = data.get('usage', {})

            return LLMResponse(
                content=content,
                model=model,
                provider='lmstudio',
                usage=usage
            )

        except Exception as e:
            logger.error(f"LM Studio generation error: {e}")
            return LLMResponse(
                content="",
                model=model or "unknown",
                provider='lmstudio',
                error=str(e)
            )

    def is_available(self) -> bool:
        """Check if LM Studio is available"""
        try:
            response = requests.get(f"{self.base_url}/models", timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"LM Studio not available: {e}")
            return False


class OpenAIProvider(BaseLLMProvider):
    """OpenAI-compatible LLM Provider"""

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> LLMResponse:
        """Generate completion using OpenAI API"""
        try:
            model = model or self.models.get('specialist', 'gpt-4o-mini')

            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            api_key = self.config.get('api_key') or os.getenv('OPENAI_API_KEY')
            if not api_key:
                raise ValueError("OpenAI API key not configured")

            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }

            payload = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }

            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            content = data['choices'][0]['message']['content']
            usage = data.get('usage', {})

            return LLMResponse(
                content=content,
                model=model,
                provider='openai',
                usage=usage
            )

        except Exception as e:
            logger.error(f"OpenAI generation error: {e}")
            return LLMResponse(
                content="",
                model=model or "unknown",
                provider='openai',
                error=str(e)
            )

    def is_available(self) -> bool:
        """Check if OpenAI API is available"""
        try:
            api_key = self.config.get('api_key') or os.getenv('OPENAI_API_KEY')
            if not api_key:
                return False

            headers = {"Authorization": f"Bearer {api_key}"}
            response = requests.get(
                f"{self.base_url}/models",
                headers=headers,
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.debug(f"OpenAI not available: {e}")
            return False


class LLMProviderFactory:
    """Factory for creating LLM providers"""

    @staticmethod
    def create_provider(provider_type: str, config: Dict[str, Any]) -> BaseLLMProvider:
        """Create an LLM provider instance"""
        providers = {
            'ollama': OllamaProvider,
            'lmstudio': LMStudioProvider,
            'openai': OpenAIProvider
        }

        provider_class = providers.get(provider_type.lower())
        if not provider_class:
            raise ValueError(f"Unknown provider type: {provider_type}")

        return provider_class(config)
