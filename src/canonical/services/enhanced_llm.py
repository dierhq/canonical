"""
Enhanced LLM service that wraps the unified LLM service with additional functionality.
"""

import asyncio
from typing import Dict, Any, Optional
from loguru import logger

from .llm import get_llm_service
from ..core.models import SourceFormat, TargetFormat


class EnhancedLLMService:
    """Enhanced LLM service with retry logic and validation."""
    
    def __init__(self):
        self.llm_service = get_llm_service()
    
    async def convert_with_retry(
        self,
        source_rule: str,
        source_format: str,
        target_format: str,
        context: str = "",
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """Convert a rule with retry logic and enhanced context."""
        for attempt in range(max_retries + 1):
            try:
                # Convert target format string to enum
                target_fmt = TargetFormat(target_format)
                
                # Use the unified conversion method
                result = await self.llm_service.convert_rule(
                    source_rule=source_rule,
                    source_format=source_format,
                    target_format=target_fmt,
                    context=context
                )
                
                # Standardize response format
                return {
                    "success": True,
                    "target_rule": self._extract_target_rule(result, target_format),
                    "confidence_score": result.get("confidence", 0.0),
                    "metadata": {
                        "rule_name": result.get("rule_name", ""),
                        "mitre_techniques": result.get("mitre_techniques", []),
                        "explanation": result.get("explanation", ""),
                        "required_tables": result.get("required_tables", [])
                    }
                }
                
            except Exception as e:
                logger.warning(f"Conversion attempt {attempt + 1} failed: {e}")
                if attempt == max_retries:
                    return {
                        "success": False,
                        "error": str(e),
                        "target_rule": "",
                        "confidence_score": 0.0
                    }
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        return {
            "success": False,
            "error": "Max retries exceeded",
            "target_rule": "",
            "confidence_score": 0.0
        }
    
    def _extract_target_rule(self, result: Dict[str, Any], target_format: str) -> str:
        """Extract the target rule from the conversion result."""
        format_key_map = {
            "kustoql": "kusto_query",
            "sigma": "sigma_rule", 
            "spl": "splunk_query",
            "splunk": "splunk_query",
            "eql": "eql_query",
            "qradar": "aql_query",
            "aql": "aql_query",
            "kibanaql": "kibana_query",
            "kibana": "kibana_query"
        }
        
        key = format_key_map.get(target_format.lower())
        if key and key in result:
            rule = result[key]
            # Convert dict to YAML string if needed (for sigma)
            if isinstance(rule, dict):
                import yaml
                return yaml.dump(rule, default_flow_style=False)
            return str(rule)
        
        # Fallback: look for any query-like field
        for field in result.values():
            if isinstance(field, str) and len(field) > 10:
                return field
                
        return ""
    
    async def validate_kusto_query(self, query: str) -> Dict[str, Any]:
        """Validate a KustoQL query using the LLM service."""
        try:
            result = await self.llm_service.validate_syntax(query, "kustoql")
            
            return {
                "is_valid": result.get("is_valid", False),
                "errors": result.get("syntax_errors", []),
                "warnings": result.get("warnings", []),
                "suggestions": result.get("suggestions", []),
                "confidence": result.get("confidence", 0.0)
            }
                
        except Exception as e:
            logger.error(f"Error validating KustoQL query: {e}")
            return {
                "is_valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "suggestions": [],
                "confidence": 0.0
            }

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the enhanced LLM service."""
        try:
            # Check the underlying LLM service
            base_health = await self.llm_service.health_check()
            
            return {
                "status": base_health.get("status", "unknown"),
                "enhanced_service": "operational",
                "provider": base_health.get("provider", "unknown"),
                "model": base_health.get("model", "unknown")
            }
            
        except Exception as e:
            logger.error(f"Enhanced LLM health check failed: {e}")
            return {
                "status": "unhealthy",
                "enhanced_service": "error",
                "error": str(e)
            }


# Create singleton instance
enhanced_llm_service = EnhancedLLMService() 