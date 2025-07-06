"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Main rule converter class for the Canonical SIEM rule converter.
"""

import asyncio
from typing import Dict, List, Any, Optional
from loguru import logger

from .models import ConversionRequest, ConversionResponse, SourceFormat, TargetFormat
from ..workflows.conversion import conversion_workflow


class RuleConverter:
    """Main rule converter class."""
    
    def __init__(self):
        """Initialize the rule converter."""
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the converter and all its dependencies."""
        if self._initialized:
            return
        
        try:
            logger.info("Initializing Canonical Rule Converter")
            
            # Initialize the conversion workflow (which will initialize all services)
            await conversion_workflow._initialize_services()
            
            self._initialized = True
            logger.info("Canonical Rule Converter initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize converter: {e}")
            raise
    
    async def convert_rule(
        self,
        source_rule: str,
        source_format: SourceFormat,
        target_format: TargetFormat,
        context: Optional[Dict[str, Any]] = None
    ) -> ConversionResponse:
        """Convert a rule from source format to target format.
        
        Args:
            source_rule: Source rule content
            source_format: Source rule format
            target_format: Target rule format
            context: Additional context for conversion
            
        Returns:
            Conversion response
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            logger.info(f"Converting rule from {source_format} to {target_format}")
            
            # Create conversion request
            request = ConversionRequest(
                source_rule=source_rule,
                source_format=source_format,
                target_format=target_format,
                context=context
            )
            
            # Execute conversion workflow
            response = await conversion_workflow.convert_rule(request)
            
            logger.info(f"Conversion completed with success: {response.success}")
            return response
            
        except Exception as e:
            logger.error(f"Conversion failed: {e}")
            return ConversionResponse(
                success=False,
                target_rule=None,
                confidence_score=0.0,
                explanation="Conversion failed due to unexpected error",
                error_message=str(e)
            )
    
    async def convert_sigma_to_kustoql(self, sigma_rule: str) -> ConversionResponse:
        """Convert Sigma rule to KustoQL.
        
        Args:
            sigma_rule: Sigma rule content
            
        Returns:
            Conversion response
        """
        return await self.convert_rule(
            source_rule=sigma_rule,
            source_format=SourceFormat.SIGMA,
            target_format=TargetFormat.KUSTOQL
        )
    
    async def convert_sigma_to_kibanaql(self, sigma_rule: str) -> ConversionResponse:
        """Convert Sigma rule to Kibana Query Language.
        
        Args:
            sigma_rule: Sigma rule content
            
        Returns:
            Conversion response
        """
        return await self.convert_rule(
            source_rule=sigma_rule,
            source_format=SourceFormat.SIGMA,
            target_format=TargetFormat.KIBANAQL
        )
    
    async def convert_sigma_to_eql(self, sigma_rule: str) -> ConversionResponse:
        """Convert Sigma rule to Event Query Language.
        
        Args:
            sigma_rule: Sigma rule content
            
        Returns:
            Conversion response
        """
        return await self.convert_rule(
            source_rule=sigma_rule,
            source_format=SourceFormat.SIGMA,
            target_format=TargetFormat.EQL
        )
    
    async def convert_sigma_to_qradar(self, sigma_rule: str) -> ConversionResponse:
        """Convert Sigma rule to QRadar AQL.
        
        Args:
            sigma_rule: Sigma rule content
            
        Returns:
            Conversion response
        """
        return await self.convert_rule(
            source_rule=sigma_rule,
            source_format=SourceFormat.SIGMA,
            target_format=TargetFormat.QRADAR
        )
    
    async def convert_sigma_to_spl(self, sigma_rule: str) -> ConversionResponse:
        """Convert Sigma rule to Splunk Processing Language.
        
        Args:
            sigma_rule: Sigma rule content
            
        Returns:
            Conversion response
        """
        return await self.convert_rule(
            source_rule=sigma_rule,
            source_format=SourceFormat.SIGMA,
            target_format=TargetFormat.SPL
        )
    
    async def batch_convert(
        self,
        rules: List[Dict[str, Any]],
        target_format: TargetFormat,
        max_concurrent: int = 5
    ) -> List[ConversionResponse]:
        """Convert multiple rules concurrently.
        
        Args:
            rules: List of rule dictionaries with 'content' and 'source_format' keys
            target_format: Target format for all conversions
            max_concurrent: Maximum number of concurrent conversions
            
        Returns:
            List of conversion responses
        """
        if not self._initialized:
            await self.initialize()
        
        logger.info(f"Starting batch conversion of {len(rules)} rules to {target_format}")
        
        # Create semaphore to limit concurrent conversions
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def convert_single_rule(rule_data: Dict[str, Any]) -> ConversionResponse:
            async with semaphore:
                return await self.convert_rule(
                    source_rule=rule_data["content"],
                    source_format=rule_data["source_format"],
                    target_format=target_format,
                    context=rule_data.get("context")
                )
        
        # Execute all conversions concurrently
        tasks = [convert_single_rule(rule) for rule in rules]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        final_responses = []
        for i, response in enumerate(responses):
            if isinstance(response, Exception):
                logger.error(f"Rule {i} conversion failed: {response}")
                final_responses.append(ConversionResponse(
                    success=False,
                    target_rule=None,
                    confidence_score=0.0,
                    explanation="Batch conversion failed",
                    error_message=str(response)
                ))
            else:
                final_responses.append(response)
        
        # Log batch results
        successful = sum(1 for r in final_responses if r.success)
        logger.info(f"Batch conversion completed: {successful}/{len(rules)} successful")
        
        return final_responses
    
    async def get_supported_formats(self) -> Dict[str, List[str]]:
        """Get supported source and target formats.
        
        Returns:
            Dictionary with supported formats
        """
        return {
            "source_formats": [format.value for format in SourceFormat],
            "target_formats": [format.value for format in TargetFormat]
        }
    
    async def validate_rule(self, rule_content: str, source_format: SourceFormat) -> Dict[str, Any]:
        """Validate a rule without converting it.
        
        Args:
            rule_content: Rule content to validate
            source_format: Source format of the rule
            
        Returns:
            Validation result
        """
        try:
            if source_format == SourceFormat.SIGMA:
                from ..parsers.sigma import sigma_parser
                
                # Parse and validate the rule
                parsed_rule = sigma_parser.parse_rule(rule_content)
                is_valid, errors = sigma_parser.validate_rule(parsed_rule)
                
                # Get rule analysis
                complexity = sigma_parser.analyze_rule_complexity(parsed_rule)
                mitre_techniques = sigma_parser.extract_mitre_tags(parsed_rule)
                
                return {
                    "valid": is_valid,
                    "errors": errors,
                    "complexity": complexity,
                    "mitre_techniques": mitre_techniques,
                    "title": parsed_rule.title,
                    "description": parsed_rule.description
                }
            else:
                return {
                    "valid": False,
                    "errors": [f"Validation not supported for format: {source_format}"],
                    "complexity": None,
                    "mitre_techniques": [],
                    "title": None,
                    "description": None
                }
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Validation failed: {str(e)}"],
                "complexity": None,
                "mitre_techniques": [],
                "title": None,
                "description": None
            }
    
    async def get_conversion_stats(self) -> Dict[str, Any]:
        """Get conversion statistics and system status.
        
        Returns:
            System statistics
        """
        try:
            from ..services.chromadb import chromadb_service
            
            # Get collection statistics
            collections_stats = {}
            for collection_name in ["sigma_rules", "mitre_attack", "mitre_car", "atomic_red_team"]:
                try:
                    stats = await chromadb_service.get_collection_stats(collection_name)
                    collections_stats[collection_name] = stats
                except Exception as e:
                    collections_stats[collection_name] = {"error": str(e)}
            
            return {
                "initialized": self._initialized,
                "collections": collections_stats,
                "supported_formats": await self.get_supported_formats()
            }
        except Exception as e:
            return {
                "initialized": self._initialized,
                "error": str(e),
                "supported_formats": await self.get_supported_formats()
            }


# Global converter instance
rule_converter = RuleConverter() 