"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Unified LLM service supporting OpenAI GPT-4o and Azure OpenAI for cybersecurity rule conversion.
"""

import asyncio
from typing import List, Dict, Any, Optional, Union
import json
from openai import AsyncOpenAI, AsyncAzureOpenAI
from loguru import logger
import backoff

from ..core.config import settings
from ..core.models import TargetFormat


class UnifiedLLMService:
    """Unified LLM service supporting OpenAI GPT-4o and Azure OpenAI."""
    
    def __init__(self):
        """Initialize the unified LLM service."""
        self.provider = settings.llm_provider.lower()
        self.model = settings.llm_model
        self.max_tokens = settings.llm_max_tokens
        self.temperature = settings.llm_temperature
        
        # Initialize the appropriate client
        if self.provider == "openai":
            self.client = AsyncOpenAI(
                api_key=settings.openai_api_key,
                base_url=settings.openai_base_url
            )
        elif self.provider == "azure":
            self.client = AsyncAzureOpenAI(
                api_key=settings.azure_openai_key,
                azure_endpoint=settings.azure_openai_endpoint,
                api_version=settings.azure_openai_version
            )
            # Use deployment name for Azure
            self.model = settings.azure_openai_deployment
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider}")
        
        logger.info(f"Initialized {self.provider.upper()} LLM service with model: {self.model}")

    @backoff.on_exception(
        backoff.expo,
        Exception,
        max_tries=3,
        factor=2,
        max_value=60
    )
    async def generate_completion(
        self, 
        messages: List[Dict[str, str]], 
        **kwargs
    ) -> str:
        """Generate completion using the configured LLM provider.
        
        Args:
            messages: List of messages in OpenAI format
            **kwargs: Additional parameters
            
        Returns:
            Generated completion text
        """
        try:
            # Merge default settings with provided kwargs
            params = {
                "model": self.model,
                "messages": messages,
                "max_tokens": kwargs.get("max_tokens", self.max_tokens),
                "temperature": kwargs.get("temperature", self.temperature),
                **{k: v for k, v in kwargs.items() if k not in ["max_tokens", "temperature"]}
            }
            
            logger.debug(f"Generating completion with {self.provider} model {self.model}")
            
            response = await self.client.chat.completions.create(**params)
            
            if not response.choices:
                raise ValueError("No choices returned from LLM")
                
            content = response.choices[0].message.content
            if not content:
                raise ValueError("Empty content returned from LLM")
                
            logger.debug(f"Generated completion: {len(content)} characters")
            return content.strip()
            
        except Exception as e:
            logger.error(f"Error generating completion: {str(e)}")
            raise

    async def generate_response(
        self, 
        prompt: str, 
        **kwargs
    ) -> str:
        """Generate response from a text prompt (compatibility method).
        
        Args:
            prompt: Text prompt
            **kwargs: Additional parameters
            
        Returns:
            Generated response text
        """
        messages = [{"role": "user", "content": prompt}]
        return await self.generate_completion(messages, **kwargs)

    async def generate_structured_completion(
        self, 
        messages: List[Dict[str, str]], 
        schema: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """Generate structured completion with JSON schema validation.
        
        Args:
            messages: List of messages in OpenAI format
            schema: JSON schema for response format
            **kwargs: Additional parameters
            
        Returns:
            Parsed JSON response
        """
        try:
            # Add response format for structured outputs
            params = {
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "rule_conversion",
                        "schema": schema,
                        "strict": True
                    }
                }
            }
            
            content = await self.generate_completion(messages, **params, **kwargs)
            
            # Parse and validate JSON
            try:
                result = json.loads(content)
                logger.debug("Successfully parsed structured response")
                return result
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON response: {e}")
                logger.error(f"Raw content: {content}")
                raise ValueError(f"Invalid JSON response: {e}")
                
        except Exception as e:
            logger.error(f"Error generating structured completion: {str(e)}")
            raise

    async def convert_rule(
        self,
        source_rule: str,
        source_format: str,
        target_format: TargetFormat,
        context: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """Convert a rule from source format to target format.
        
        Args:
            source_rule: Source rule content
            source_format: Source format (sigma, qradar, kibanaql)
            target_format: Target format enum
            context: Additional context for conversion
            **kwargs: Additional parameters
            
        Returns:
            Conversion result with target rule and metadata
        """
        try:
            # Build the system prompt
            system_prompt = self._build_system_prompt(source_format, target_format.value)
            
            # Build the user prompt
            user_prompt = self._build_conversion_prompt(
                source_rule, source_format, target_format.value, context
            )
            
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
            
            # Define response schema
            schema = self._get_conversion_schema(target_format.value)
            
            # Generate structured response
            result = await self.generate_structured_completion(messages, schema, **kwargs)
            
            logger.info(f"Successfully converted {source_format} rule to {target_format.value}")
            return result
            
        except Exception as e:
            logger.error(f"Error converting rule: {str(e)}")
            raise

    def _build_system_prompt(self, source_format: str, target_format: str) -> str:
        """Build system prompt for rule conversion."""
        return f"""You are DIER Rule-Converter, a cybersecurity expert specializing in SIEM rule conversion.

CRITICAL INSTRUCTIONS:
1. ONLY use information provided in the <CONTEXT> section
2. If context is insufficient, respond with confidence score < 0.5 and explanation
3. Output MUST be valid JSON following the exact schema provided
4. Focus on accurate field mappings and logical equivalence

EXPERTISE:
- Deep knowledge of {source_format.upper()} and {target_format.upper()} formats
- MITRE ATT&CK framework integration
- Security detection logic patterns
- Field mapping and data source optimization

CONVERSION PRINCIPLES:
- Preserve detection logic and intent
- Map fields accurately between data sources
- Maintain time windows and thresholds
- Include relevant MITRE techniques
- Provide confidence assessment

You excel at converting between SIEM rule formats while maintaining security effectiveness."""

    def _build_conversion_prompt(
        self, 
        source_rule: str, 
        source_format: str, 
        target_format: str, 
        context: str
    ) -> str:
        """Build conversion prompt with source rule and context."""
        return f"""Convert this {source_format.upper()} rule to {target_format.upper()}:

<SOURCE_RULE>
{source_rule}
</SOURCE_RULE>

<CONTEXT>
{context}
</CONTEXT>

CONVERSION STEPS:
1. Analyze the source rule structure and detection logic
2. Identify key fields, operators, and conditions
3. Map fields to target format data sources
4. Construct equivalent query in target format
5. Validate syntax and logical correctness
6. Assess conversion confidence and completeness

Provide the conversion following the required JSON schema exactly."""

    def _get_conversion_schema(self, target_format: str) -> Dict[str, Any]:
        """Get JSON schema for conversion response."""
        base_schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "rule_name": {
                    "type": "string",
                    "description": "Name of the converted rule"
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                    "description": "Conversion confidence score"
                },
                "mitre_techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Related MITRE ATT&CK technique IDs"
                },
                "explanation": {
                    "type": "string",
                    "description": "Explanation of the conversion approach"
                }
            },
            "required": ["rule_name", "confidence", "mitre_techniques", "explanation"]
        }
        
        # Add format-specific fields
        if target_format.lower() == "kustoql":
            base_schema["properties"]["kusto_query"] = {
                "type": "string",
                "description": "KustoQL query for Azure Sentinel"
            }
            base_schema["properties"]["required_tables"] = {
                "type": "array",
                "items": {"type": "string"},
                "description": "Required data tables"
            }
            base_schema["required"].extend(["kusto_query", "required_tables"])
            
        elif target_format.lower() == "sigma":
            base_schema["properties"]["sigma_rule"] = {
                "type": "object",
                "description": "Sigma rule in YAML structure"
            }
            base_schema["required"].append("sigma_rule")
            
        elif target_format.lower() in ["spl", "splunk"]:
            base_schema["properties"]["splunk_query"] = {
                "type": "string",
                "description": "Splunk SPL query"
            }
            base_schema["required"].append("splunk_query")
            
        elif target_format.lower() == "eql":
            base_schema["properties"]["eql_query"] = {
                "type": "string",
                "description": "Event Query Language query"
            }
            base_schema["required"].append("eql_query")
            
        elif target_format.lower() in ["qradar", "aql"]:
            base_schema["properties"]["aql_query"] = {
                "type": "string",
                "description": "QRadar AQL query"
            }
            base_schema["required"].append("aql_query")
            
        elif target_format.lower() in ["kibanaql", "kibana"]:
            base_schema["properties"]["kibana_query"] = {
                "type": "string",
                "description": "Kibana Query Language query"
            }
            base_schema["required"].append("kibana_query")
            
        return base_schema

    async def validate_syntax(self, query: str, format_type: str) -> Dict[str, Any]:
        """Validate syntax of a query in specific format.
        
        Args:
            query: Query to validate
            format_type: Format type (kustoql, splunk, etc.)
            
        Returns:
            Validation result with status and suggestions
        """
        try:
            messages = [
                {
                    "role": "system",
                    "content": f"""You are a {format_type.upper()} syntax validator. 
                    Analyze the query for syntax errors, logical issues, and optimization opportunities."""
                },
                {
                    "role": "user",
                    "content": f"""Validate this {format_type.upper()} query:

{query}

Provide detailed validation results including:
1. Syntax correctness
2. Logical validation  
3. Performance considerations
4. Suggested improvements"""
                }
            ]
            
            schema = {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "is_valid": {"type": "boolean"},
                    "syntax_errors": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "warnings": {
                        "type": "array", 
                        "items": {"type": "string"}
                    },
                    "suggestions": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1}
                },
                "required": ["is_valid", "syntax_errors", "warnings", "suggestions", "confidence"]
            }
            
            result = await self.generate_structured_completion(messages, schema)
            logger.debug(f"Validated {format_type} query: {result['is_valid']}")
            return result
            
        except Exception as e:
            logger.error(f"Error validating {format_type} syntax: {str(e)}")
            return {
                "is_valid": False,
                "syntax_errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "suggestions": [],
                "confidence": 0.0
            }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the LLM service."""
        try:
            test_messages = [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Reply with exactly: 'Service is healthy'"}
            ]
            
            response = await self.generate_completion(test_messages, max_tokens=10)
            
            is_healthy = "healthy" in response.lower()
            
            return {
                "status": "healthy" if is_healthy else "degraded",
                "provider": self.provider,
                "model": self.model,
                "response": response
            }
            
        except Exception as e:
            logger.error(f"LLM health check failed: {str(e)}")
            return {
                "status": "unhealthy",
                "provider": self.provider,
                "model": self.model,
                "error": str(e)
            }


# Global service instance - lazy initialization
llm_service = None

def get_llm_service():
    """Get the LLM service instance, initializing if needed."""
    global llm_service
    if llm_service is None:
        llm_service = UnifiedLLMService()
    return llm_service 