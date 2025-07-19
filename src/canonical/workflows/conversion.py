"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
LangGraph workflow for intelligent rule conversion pipeline.
"""

import asyncio
from typing import Dict, List, Any, Optional, TypedDict
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from loguru import logger

from ..core.models import ConversionRequest, ConversionResponse, TargetFormat
from ..parsers.sigma import sigma_parser
from ..services.embedding import embedding_service
from ..services.chromadb import chromadb_service
from ..services.llm import llm_service
from ..services.enhanced_llm import enhanced_llm_service
from ..services.hybrid_retrieval import hybrid_retrieval_service
# TODO: Re-implement schema and validation services
# from ..services.schema_service import schema_service
# from ..services.validation_service import validation_service


class ConversionState(TypedDict):
    """State for the conversion workflow."""
    request: ConversionRequest
    parsed_rule: Optional[Dict[str, Any]]
    mitre_techniques: List[str]
    similar_rules: List[Dict[str, Any]]
    context_data: Dict[str, Any]
    conversion_result: Optional[Dict[str, Any]]
    response: Optional[ConversionResponse]
    error: Optional[str]


class ConversionWorkflow:
    """LangGraph workflow for rule conversion."""
    
    def __init__(self):
        """Initialize the conversion workflow."""
        self.workflow = None
        self.memory = MemorySaver()
        self._setup_workflow()
    
    def _setup_workflow(self) -> None:
        """Setup the LangGraph workflow."""
        # Create the workflow graph
        workflow = StateGraph(ConversionState)
        
        # Add nodes
        workflow.add_node("parse_rule", self._parse_rule_node)
        workflow.add_node("extract_mitre", self._extract_mitre_node)
        workflow.add_node("find_similar", self._find_similar_node)
        workflow.add_node("gather_context", self._gather_context_node)
        workflow.add_node("convert_rule", self._convert_rule_node)
        workflow.add_node("validate_result", self._validate_result_node)
        workflow.add_node("create_response", self._create_response_node)
        
        # Define the flow
        workflow.set_entry_point("parse_rule")
        workflow.add_edge("parse_rule", "extract_mitre")
        workflow.add_edge("extract_mitre", "find_similar")
        workflow.add_edge("find_similar", "gather_context")
        workflow.add_edge("gather_context", "convert_rule")
        workflow.add_edge("convert_rule", "validate_result")
        workflow.add_edge("validate_result", "create_response")
        workflow.add_edge("create_response", END)
        
        # Compile the workflow
        self.workflow = workflow.compile(checkpointer=self.memory)
    
    async def _parse_rule_node(self, state: ConversionState) -> ConversionState:
        """Parse the source rule."""
        try:
            logger.info("Parsing source rule")
            request = state["request"]
            
            if request.source_format.value == "sigma":
                # Parse Sigma rule
                parsed_rule = sigma_parser.parse_rule(request.source_rule)
                state["parsed_rule"] = sigma_parser.convert_to_dict(parsed_rule)
                logger.info(f"Successfully parsed Sigma rule: {parsed_rule.title}")
            elif request.source_format.value == "qradar":
                # Parse QRadar rule
                from ..parsers.qradar import qradar_parser
                parsed_rule = qradar_parser.parse_rule(request.source_rule)
                state["parsed_rule"] = qradar_parser.convert_to_dict(parsed_rule)
                logger.info(f"Successfully parsed QRadar rule: {parsed_rule.name}")
            elif request.source_format.value == "kibanaql":
                # Parse KibanaQL rule
                from ..parsers.kibanaql import KibanaQLParser
                kibanaql_parser = KibanaQLParser()
                parsed_rule = kibanaql_parser.parse_rule(request.source_rule)
                state["parsed_rule"] = kibanaql_parser.convert_to_dict(parsed_rule)
                logger.info(f"Successfully parsed KibanaQL rule: {parsed_rule.name}")
            else:
                raise ValueError(f"Unsupported source format: {request.source_format}")
            
        except Exception as e:
            logger.error(f"Failed to parse rule: {e}")
            state["error"] = f"Rule parsing failed: {str(e)}"
        
        return state
    
    async def _extract_mitre_node(self, state: ConversionState) -> ConversionState:
        """Extract MITRE ATT&CK techniques from the rule."""
        try:
            logger.info("Extracting MITRE techniques")
            
            if state.get("error"):
                return state
            
            parsed_rule = state["parsed_rule"]
            if not parsed_rule:
                return state
            
            request = state["request"]
            mitre_techniques = []
            
            if request.source_format.value == "sigma":
                # Create SigmaRule object for extraction
                rule_obj = sigma_parser.parse_rule(request.source_rule)
                mitre_techniques = sigma_parser.extract_mitre_tags(rule_obj)
            elif request.source_format.value == "qradar":
                # Extract from parsed QRadar rule
                mitre_techniques = parsed_rule.get("mitre_techniques", [])
            elif request.source_format.value == "kibanaql":
                # Extract from parsed KibanaQL rule
                from ..parsers.kibanaql import KibanaQLParser
                kibanaql_parser = KibanaQLParser()
                rule_obj = kibanaql_parser.parse_rule(request.source_rule)
                mitre_techniques = kibanaql_parser.extract_mitre_techniques(rule_obj)
            
            state["mitre_techniques"] = mitre_techniques
            logger.info(f"Extracted {len(mitre_techniques)} MITRE techniques")
            
        except Exception as e:
            logger.error(f"Failed to extract MITRE techniques: {e}")
            state["error"] = f"MITRE extraction failed: {str(e)}"
        
        return state
    
    async def _find_similar_node(self, state: ConversionState) -> ConversionState:
        """Find similar rules in the knowledge base."""
        try:
            logger.info("Finding similar rules")
            
            if state.get("error"):
                return state
            
            parsed_rule = state["parsed_rule"]
            if not parsed_rule:
                return state
            
            request = state["request"]
            rule_summary = ""
            similar_rules = []
            
            if request.source_format.value == "sigma":
                # Create rule summary for similarity search
                rule_obj = sigma_parser.parse_rule(request.source_rule)
                rule_summary = sigma_parser.extract_rule_summary(rule_obj)
                
                # Search for similar Sigma rules
                similar_rules = await chromadb_service.find_similar_sigma_rules(
                    query=rule_summary,
                    n_results=5
                )
            elif request.source_format.value == "qradar":
                # Create rule summary for QRadar rule
                from ..parsers.qradar import qradar_parser
                rule_obj = qradar_parser.parse_rule(request.source_rule)
                rule_summary = qradar_parser.extract_rule_summary(rule_obj)
                
                # Search for similar QRadar rules
                similar_rules = await chromadb_service.find_qradar_rules(
                    query=rule_summary,
                    n_results=5
                )
            
            state["similar_rules"] = similar_rules
            logger.info(f"Found {len(similar_rules)} similar rules")
            
        except Exception as e:
            logger.error(f"Failed to find similar rules: {e}")
            # Don't set error here as this is not critical
            state["similar_rules"] = []
        
        return state
    
    async def _gather_context_node(self, state: ConversionState) -> ConversionState:
        """Gather additional context from knowledge base using enhanced retrieval."""
        try:
            logger.info("Gathering enhanced context data")
            
            if state.get("error"):
                return state
            
            request = state["request"]
            
            # Use enhanced hybrid retrieval for comprehensive context
            enhanced_context = await hybrid_retrieval_service.retrieve_context_for_conversion(
                rule_content=request.source_rule,
                source_format=request.source_format.value,
                target_format=request.target_format.value
            )
            
            # Add schema-aware field mappings if available
            try:
                
                # Get schema name from request context if provided
                schema_name = None
                if request.context and "schema_name" in request.context:
                    schema_name = request.context["schema_name"]
                
                # Extract field references from the parsed rule
                field_references = self._extract_field_references(state.get("parsed_rule", {}))
                
                if field_references:
                    logger.info(f"Found {len(field_references)} field references for schema mapping")
                    
                    # Get field mappings from schema service
                    # TODO: Re-implement schema service integration
                    field_mappings = {}
                    for field_ref in field_references:
                        try:
                            # mappings = schema_service.find_field_mappings(
                            #     field_name=field_ref,
                            # )
                            mappings = {}  # Placeholder until schema service is implemented
                            if mappings:
                                field_mappings[field_ref] = mappings
                                logger.info(f"Found {len(mappings)} mappings for field '{field_ref}'")
                        except Exception as e:
                            logger.debug(f"No mappings found for field '{field_ref}': {e}")
                    
                    # Add field mappings to context
                    enhanced_context["schema_field_mappings"] = field_mappings
                    enhanced_context["schema_name"] = schema_name
                    
                    logger.info(f"Added schema-aware field mappings for {len(field_mappings)} fields")
                
            except ImportError:
                logger.debug("Schema service not available, skipping schema-aware enhancements")
            except Exception as e:
                logger.warning(f"Failed to add schema-aware context: {e}")
            
            # Store enhanced context
            state["context_data"] = enhanced_context
            logger.info(f"Enhanced context gathered with {len(enhanced_context.get('field_names', []))} field names")
            
        except Exception as e:
            logger.error(f"Failed to gather enhanced context: {e}")
            # Fallback to original context gathering
            state["context_data"] = {}
        
        return state
    
    async def _convert_rule_node(self, state: ConversionState) -> ConversionState:
        """Convert the rule using the enhanced LLM."""
        try:
            logger.info("Converting rule with enhanced LLM")
            
            if state.get("error"):
                return state
            
            request = state["request"]
            
            # Use enhanced LLM service with retry logic
            # Use enhanced LLM service with retry logic and context
            context = {
                "mitre_techniques": state.get("mitre_techniques", []),
                "similar_rules": state.get("similar_rules", []),
                "context_data": state.get("context_data", {}),
                "schema_field_mappings": state.get("context_data", {}).get("schema_field_mappings", {}),
                "schema_name": state.get("context_data", {}).get("schema_name")
            }
            
            conversion_result = await enhanced_llm_service.convert_with_retry(
                source_rule=request.source_rule,
                source_format=request.source_format.value,
                target_format=request.target_format.value,
                context=context,
                max_retries=2
            )
            
            state["conversion_result"] = conversion_result
            logger.info("Enhanced rule conversion completed")
            
        except Exception as e:
            logger.error(f"Failed to convert rule with enhanced LLM: {e}")
            # Fallback to original LLM service
            try:
                logger.info("Falling back to original LLM service")
                request = state["request"]
                
                # Prepare context for original LLM
                context = {
                    "mitre_techniques": state.get("mitre_techniques", []),
                    "similar_rules": state.get("similar_rules", []),
                    "context_data": state.get("context_data", {})
                }
                
                # Use original LLM service
                if (request.source_format.value == "qradar" and 
                    request.target_format.value == "kustoql"):
                    conversion_result = await llm_service.convert_qradar_to_kustoql(
                        qradar_rule=request.source_rule,
                        context=context
                    )
                else:
                    conversion_result = await llm_service.convert_sigma_rule(
                        sigma_rule=request.source_rule,
                        target_format=request.target_format,
                        context=context
                    )
                
                state["conversion_result"] = conversion_result
                logger.info("Fallback conversion completed")
                
            except Exception as fallback_error:
                logger.error(f"Fallback conversion also failed: {fallback_error}")
                state["error"] = f"Rule conversion failed: {str(e)}, Fallback also failed: {str(fallback_error)}"
        
        return state
    
    async def _validate_result_node(self, state: ConversionState) -> ConversionState:
        """Validate the conversion result with enhanced guardrails and schema validation."""
        try:
            logger.info("Validating conversion result with guardrails and schema validation")
            
            if state.get("error"):
                return state
            
            conversion_result = state.get("conversion_result")
            if not conversion_result:
                state["error"] = "No conversion result available"
                return state
            
            request = state["request"]
            
            # Enhanced validation with guardrails
            validation_results = []
            
            # Add schema-based validation if available
            try:
                
                target_rule = conversion_result.get("target_rule")
                if target_rule:
                    # Get schema name from context
                    schema_name = None
                    if request.context and "schema_name" in request.context:
                        schema_name = request.context["schema_name"]
                    
                    # Get original field mappings from context
                    original_field_mappings = None
                    context_data = state.get("context_data", {})
                    if "schema_field_mappings" in context_data:
                        original_field_mappings = context_data["schema_field_mappings"]
                    
                    # Validate the converted rule against the schema
                    # TODO: Re-implement validation service integration
                    # schema_validation = await validation_service.validate_converted_rule(
                    #     converted_rule=target_rule,
                    #     target_format=request.target_format.value,
                    #     original_field_mappings=original_field_mappings
                    # )
                    schema_validation = {"valid": True, "errors": []}  # Placeholder until validation service is implemented
                    
                    # Add schema validation results to conversion result
                    conversion_result["schema_validation"] = {
                        "is_valid": schema_validation.is_valid,
                        "field_coverage": getattr(schema_validation, 'field_coverage', 0.0),
                        "issues": getattr(schema_validation, 'issues', []),
                        "suggestions": getattr(schema_validation, 'suggestions', []),
                        "validated_fields": getattr(schema_validation, 'validated_fields', []),
                        "missing_fields": getattr(schema_validation, 'missing_fields', []),
                        "confidence_score": schema_validation.confidence_score
                    }
                    
                    logger.info(f"Schema validation completed: {schema_validation.field_coverage:.2%} field coverage")
                    
                    # Adjust overall confidence based on schema validation
                    if "confidence" in conversion_result:
                        original_confidence = conversion_result["confidence"]
                        schema_confidence = schema_validation.confidence_score
                        # Weighted average: 70% original, 30% schema validation
                        adjusted_confidence = (original_confidence * 0.7) + (schema_confidence * 0.3)
                        conversion_result["confidence"] = adjusted_confidence
                        conversion_result["confidence_score"] = adjusted_confidence  # Also update confidence_score
                        logger.info(f"Adjusted confidence from {original_confidence:.2f} to {adjusted_confidence:.2f}")
                
            except ImportError:
                logger.debug("Validation service not available, skipping schema validation")
            except Exception as e:
                logger.warning(f"Schema validation failed: {e}")
                # Continue with basic validation
            
            # 1. Basic validation
            if not conversion_result.get("success"):
                validation_results.append("Conversion marked as unsuccessful")
            
            if not conversion_result.get("target_rule"):
                validation_results.append("No target rule generated")
                conversion_result["success"] = False
                conversion_result["error_message"] = "No target rule generated"
            
            # 2. Confidence score validation
            confidence = conversion_result.get("confidence_score", 0.0)
            if confidence < 0.3:
                validation_results.append(f"Low confidence score: {confidence}")
            
            # 3. KustoQL-specific validation
            if (request.target_format.value == "kustoql" and 
                conversion_result.get("success") and 
                conversion_result.get("target_rule")):
                
                # Use enhanced LLM validation
                kusto_validation = await enhanced_llm_service.validate_kusto_query(
                    conversion_result["target_rule"]
                )
                
                if not kusto_validation.get("is_valid", True):
                    validation_results.extend(kusto_validation.get("errors", []))
                    conversion_result["validation_errors"] = kusto_validation.get("errors", [])
                    conversion_result["suggestions"] = kusto_validation.get("suggestions", [])
                    
                    # If critical errors, mark as failed
                    critical_errors = ["Query is empty", "No query lines found"]
                    if any(error in kusto_validation.get("errors", []) for error in critical_errors):
                        conversion_result["success"] = False
                        conversion_result["error_message"] = "Critical KustoQL validation errors"
            
            # 4. Field mapping validation
            field_names = state.get("context_data", {}).get("field_names", [])
            if field_names and conversion_result.get("target_rule"):
                # Check if at least some fields were mapped
                target_rule = conversion_result["target_rule"].lower()
                mapped_fields = 0
                for field in field_names:
                    if field.lower() in target_rule:
                        mapped_fields += 1
                
                if mapped_fields == 0:
                    validation_results.append("No field mappings found in target rule")
                    conversion_result["confidence_score"] = max(0.0, confidence - 0.2)
                elif mapped_fields < len(field_names) * 0.5:
                    validation_results.append(f"Only {mapped_fields}/{len(field_names)} fields mapped")
                    conversion_result["confidence_score"] = max(0.0, confidence - 0.1)
            
            # 5. Table validation for KustoQL
            if (request.target_format.value == "kustoql" and 
                conversion_result.get("target_rule")):
                
                recommended_table = state.get("context_data", {}).get("recommended_table")
                if recommended_table:
                    if recommended_table not in conversion_result["target_rule"]:
                        validation_results.append(f"Recommended table '{recommended_table}' not used in query")
                        conversion_result["confidence_score"] = max(0.0, confidence - 0.1)
            
            # 6. NO MAPPING validation
            if "NO MAPPING" in str(conversion_result):
                validation_results.append("Model indicated insufficient context for mapping")
                conversion_result["success"] = False
                conversion_result["error_message"] = "Insufficient context for reliable mapping"
            
            # Store validation results
            if validation_results:
                conversion_result["validation_warnings"] = validation_results
                logger.warning(f"Validation warnings: {validation_results}")
            
            state["conversion_result"] = conversion_result
            logger.info(f"Enhanced validation completed with {len(validation_results)} warnings")
            
        except Exception as e:
            logger.error(f"Failed to validate result: {e}")
            state["error"] = f"Result validation failed: {str(e)}"
        
        return state
    
    async def _create_response_node(self, state: ConversionState) -> ConversionState:
        """Create the final response."""
        try:
            logger.info("Creating response")
            
            if state.get("error"):
                # Create error response
                response = ConversionResponse(
                    success=False,
                    target_rule=None,
                    confidence_score=0.0,
                    explanation="Conversion failed",
                    error_message=state["error"]
                )
            else:
                conversion_result = state.get("conversion_result", {})
                
                # Create successful response
                response = ConversionResponse(
                    success=conversion_result.get("success", False),
                    target_rule=conversion_result.get("target_rule"),
                    confidence_score=conversion_result.get("confidence_score", 0.0),
                    explanation=conversion_result.get("explanation", ""),
                    mitre_techniques=state.get("mitre_techniques", []),
                    error_message=conversion_result.get("error_message"),
                    metadata={
                        "similar_rules_found": len(state.get("similar_rules", [])),
                        "context_data_available": bool(state.get("context_data")),
                        "field_mappings": conversion_result.get("field_mappings", {}),
                        "notes": conversion_result.get("notes", "")
                    }
                )
            
            state["response"] = response
            logger.info("Response created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create response: {e}")
            # Create fallback error response
            response = ConversionResponse(
                success=False,
                target_rule=None,
                confidence_score=0.0,
                explanation="Failed to create response",
                error_message=f"Response creation failed: {str(e)}"
            )
            state["response"] = response
        
        return state
    
    def _extract_field_references(self, parsed_rule: Dict[str, Any]) -> List[str]:
        """Extract field references from parsed rule for schema mapping.
        
        Args:
            parsed_rule: Parsed rule dictionary
            
        Returns:
            List of field references found in the rule
        """
        field_references = []
        
        if not parsed_rule:
            return field_references
        
        try:
            # For Sigma rules
            if "detection" in parsed_rule:
                detection = parsed_rule["detection"]
                if isinstance(detection, dict):
                    for key, value in detection.items():
                        if key == "condition":
                            continue
                        if isinstance(value, dict):
                            for field_name in value.keys():
                                # Handle field modifiers (e.g., "Image|endswith")
                                base_field = field_name.split("|")[0]
                                if base_field not in field_references:
                                    field_references.append(base_field)
            
            # For QRadar rules
            elif "conditions" in parsed_rule:
                conditions = parsed_rule["conditions"]
                if isinstance(conditions, list):
                    for condition in conditions:
                        if isinstance(condition, dict) and "field" in condition:
                            field_name = condition["field"]
                            if field_name not in field_references:
                                field_references.append(field_name)
            
            # For KibanaQL rules
            elif "query" in parsed_rule:
                query = parsed_rule["query"]
                if isinstance(query, str):
                    # Extract field names from query string (basic extraction)
                    import re
                    # Look for field patterns like "field_name:" or "field_name ="
                    field_matches = re.findall(r'(\w+)(?:\s*[:=]|\s+(?:exists|not\s+exists))', query)
                    for field_match in field_matches:
                        if field_match not in field_references:
                            field_references.append(field_match)
            
            # Generic field extraction from any rule structure
            self._extract_fields_recursive(parsed_rule, field_references)
            
        except Exception as e:
            logger.debug(f"Error extracting field references: {e}")
        
        return field_references
    
    def _extract_fields_recursive(self, obj: Any, field_references: List[str]) -> None:
        """Recursively extract field references from nested structures."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                # Common field indicators
                if key in ["field", "field_name", "fieldname", "column", "attribute"]:
                    if isinstance(value, str) and value not in field_references:
                        field_references.append(value)
                else:
                    self._extract_fields_recursive(value, field_references)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_fields_recursive(item, field_references)
    
    async def convert_rule(self, request: ConversionRequest) -> ConversionResponse:
        """Convert a rule using the workflow.
        
        Args:
            request: Conversion request
            
        Returns:
            Conversion response
        """
        try:
            logger.info(f"Starting rule conversion workflow for {request.target_format}")
            
            # Initialize services
            await self._initialize_services()
            
            # Create initial state
            initial_state = ConversionState(
                request=request,
                parsed_rule=None,
                mitre_techniques=[],
                similar_rules=[],
                context_data={},
                conversion_result=None,
                response=None,
                error=None
            )
            
            # Run the workflow
            config = {"configurable": {"thread_id": "conversion"}}
            final_state = await self.workflow.ainvoke(initial_state, config)
            
            # Return the response
            response = final_state.get("response")
            if not response:
                response = ConversionResponse(
                    success=False,
                    target_rule=None,
                    confidence_score=0.0,
                    explanation="Workflow failed to produce response",
                    error_message="Unknown workflow error"
                )
            
            logger.info(f"Conversion workflow completed with success: {response.success}")
            return response
            
        except Exception as e:
            logger.error(f"Conversion workflow failed: {e}")
            return ConversionResponse(
                success=False,
                target_rule=None,
                confidence_score=0.0,
                explanation="Workflow execution failed",
                error_message=str(e)
            )
    
    async def _initialize_services(self) -> None:
        """Initialize all required services."""
        try:
            logger.info("Initializing conversion services")
            
            # Initialize services
            await embedding_service.initialize()
            await chromadb_service.initialize()
            await llm_service.initialize()
            await enhanced_llm_service.initialize()
            await hybrid_retrieval_service.initialize()
            
            logger.info("All conversion services initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize services: {e}")
            raise


# Global workflow instance
conversion_workflow = ConversionWorkflow() 