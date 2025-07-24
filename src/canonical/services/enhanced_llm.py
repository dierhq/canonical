"""
Enhanced LLM service that wraps the basic LLM service with additional functionality.
"""

import asyncio
from typing import Dict, Any, Optional
from loguru import logger

from .llm import llm_service
from ..core.models import SourceFormat, TargetFormat


class EnhancedLLMService:
    """Enhanced LLM service with retry logic and validation."""
    
    def __init__(self):
        self.llm_service = llm_service
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the enhanced LLM service."""
        if not self._initialized:
            await self.llm_service.initialize()
            self._initialized = True
    
    async def convert_with_retry(
        self,
        source_rule: str,
        source_format: str,
        target_format: str,
        context: Optional[Dict[str, Any]] = None,
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """Convert a rule with retry logic and enhanced context."""
        await self.initialize()
        
        for attempt in range(max_retries + 1):
            try:
                # Convert source format string to enum
                source_fmt = SourceFormat(source_format) if source_format != "sigma" else SourceFormat.SIGMA
                target_fmt = TargetFormat(target_format)
                
                # Use unified conversion methods with context support
                if source_fmt == SourceFormat.SIGMA:
                    result = await self.llm_service.convert_sigma_rule(
                        sigma_rule=source_rule,
                        target_format=target_fmt,
                        context=context
                    )
                elif source_fmt == SourceFormat.QRADAR:
                    result = await self.llm_service.convert_qradar_rule(
                        qradar_rule=source_rule,
                        target_format=target_fmt,
                        context=context
                    )
                else:
                    # For other formats, use sigma conversion as fallback
                    result = await self.llm_service.convert_sigma_rule(
                        sigma_rule=source_rule,
                        target_format=target_fmt,
                        context=context
                    )
                
                return {
                    "success": True,
                    "target_rule": result.get("target_rule", ""),
                    "confidence_score": result.get("confidence_score", 0.0),  # Use consistent field name
                    "metadata": result.get("metadata", {})
                }
                
            except Exception as e:
                logger.warning(f"Conversion attempt {attempt + 1} failed: {e}")
                if attempt == max_retries:
                    return {
                        "success": False,
                        "error": str(e),
                        "target_rule": "",
                        "confidence_score": 0.0  # Use consistent field name
                    }
                await asyncio.sleep(1)  # Brief delay before retry
        
        return {
            "success": False,
            "error": "Max retries exceeded",
            "target_rule": "",
            "confidence_score": 0.0  # Use consistent field name
        }
    
    async def validate_kusto_query(self, query: str) -> Dict[str, Any]:
        """Validate a KustoQL query."""
        await self.initialize()
        
        try:
            # Basic validation - check for common KustoQL patterns
            if not query.strip():
                return {
                    "is_valid": False,
                    "errors": ["Empty query"]
                }
            
            # Check for basic KustoQL structure
            has_table = any(keyword in query.lower() for keyword in [
                "securityevent", "syslog", "commonSecurityLog", "windowsevent",
                "signinevent", "auditlogs", "event", "log"
            ])
            
            has_operators = any(op in query for op in ["|", "where", "project", "extend", "summarize"])
            
            if has_table or has_operators:
                return {
                    "is_valid": True,
                    "errors": []
                }
            else:
                return {
                    "is_valid": False,
                    "errors": ["Query does not appear to be valid KustoQL"]
                }
                
        except Exception as e:
            logger.error(f"Error validating KustoQL query: {e}")
            return {
                "is_valid": False,
                "errors": [f"Validation error: {str(e)}"]
            }


# Create singleton instance
enhanced_llm_service = EnhancedLLMService() 