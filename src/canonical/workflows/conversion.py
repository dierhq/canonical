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
from ..core.rule_enhancer import universal_enhancer
from ..parsers.sigma import sigma_parser
from ..services.embedding import embedding_service
from ..services.chromadb import chromadb_service
from ..services.llm import llm_service
from ..services.enhanced_llm import enhanced_llm_service
from ..services.hybrid_retrieval import hybrid_retrieval_service


class ConversionState(TypedDict):
    """State for the conversion workflow."""
    request: ConversionRequest
    enhanced_rule: Optional[str]  # NEW: Enhanced rule after preprocessing
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
        
        # Add nodes - NEW: preprocessing node added first
        workflow.add_node("preprocess_rule", self._preprocess_rule_node)  # NEW
        workflow.add_node("parse_rule", self._parse_rule_node)
        workflow.add_node("extract_mitre", self._extract_mitre_node)
        workflow.add_node("find_similar", self._find_similar_node)
        workflow.add_node("gather_context", self._gather_context_node)
        workflow.add_node("convert_rule", self._convert_rule_node)
        workflow.add_node("validate_result", self._validate_result_node)
        workflow.add_node("create_response", self._create_response_node)
        
        # Define the flow - NEW: preprocess first
        workflow.set_entry_point("preprocess_rule")  # NEW
        workflow.add_edge("preprocess_rule", "parse_rule")  # NEW
        workflow.add_edge("parse_rule", "extract_mitre")
        workflow.add_edge("extract_mitre", "find_similar")
        workflow.add_edge("find_similar", "gather_context")
        workflow.add_edge("gather_context", "convert_rule")
        workflow.add_edge("convert_rule", "validate_result")
        workflow.add_edge("validate_result", "create_response")
        workflow.add_edge("create_response", END)
        
        # Compile the workflow
        self.workflow = workflow.compile(checkpointer=self.memory)
    
    async def _preprocess_rule_node(self, state: ConversionState) -> ConversionState:
        """NEW: Preprocess and enhance the source rule."""
        try:
            request = state["request"]
            logger.info(f"Preprocessing {request.source_format.value} rule")
            
            # Import settings here to avoid circular imports
            from ..core.config import settings
            
            # Check if enhancement is enabled
            if not settings.ENABLE_RULE_ENHANCEMENT:
                logger.info("Rule enhancement disabled, using original rule")
                state["enhanced_rule"] = request.source_rule
                return state
            
            # Check if enhancement is needed
            needs_enhancement = universal_enhancer.is_enhancement_needed(request.source_rule, request.source_format)
            
            if needs_enhancement or not settings.ENHANCEMENT_SKIP_STRUCTURED:
                logger.info("Applying universal rule enhancer")
                enhanced_rule = universal_enhancer.enhance_rule(request.source_rule, request.source_format)
                state["enhanced_rule"] = enhanced_rule
                logger.info("Rule successfully enhanced with structured metadata")
            else:
                logger.info("Rule already well-structured, skipping enhancement")
                state["enhanced_rule"] = request.source_rule
            
            return state
            
        except Exception as e:
            logger.error(f"Failed to preprocess rule: {e}")
            
            # Import settings for fallback behavior
            from ..core.config import settings
            
            if settings.ENHANCEMENT_FALLBACK_ON_ERROR:
                logger.info("Falling back to original rule")
                state["enhanced_rule"] = state["request"].source_rule
            else:
                # Propagate the error
                state["error"] = f"Rule preprocessing failed: {str(e)}"
            
            return state
    
    async def _parse_rule_node(self, state: ConversionState) -> ConversionState:
        """Parse the source rule (now using enhanced version)."""
        try:
            logger.info("Parsing enhanced rule")
            request = state["request"]
            enhanced_rule = state["enhanced_rule"]  # Use enhanced version
            
            if request.source_format.value == "sigma":
                # Parse Sigma rule
                parsed_rule = sigma_parser.parse_rule(enhanced_rule)  # Use enhanced
                state["parsed_rule"] = sigma_parser.convert_to_dict(parsed_rule)
                logger.info(f"Successfully parsed Sigma rule: {parsed_rule.title}")
            elif request.source_format.value == "qradar":
                # Parse QRadar rule
                from ..parsers.qradar_parser import qradar_parser
                parsed_rule = qradar_parser.parse_rule(enhanced_rule)  # Use enhanced
                state["parsed_rule"] = parsed_rule
                logger.info(f"Successfully parsed QRadar rule: {parsed_rule.get('rule_name', 'Unknown')}")
            elif request.source_format.value == "kibanaql":
                # Parse KibanaQL rule
                from ..parsers.kibanaql import KibanaQLParser
                kibanaql_parser = KibanaQLParser()
                parsed_rule = kibanaql_parser.parse_rule(enhanced_rule)  # Use enhanced
                state["parsed_rule"] = kibanaql_parser.convert_to_dict(parsed_rule)
                logger.info(f"Successfully parsed KibanaQL rule: {parsed_rule.name}")
            else:
                raise ValueError(f"Unsupported source format: {request.source_format}")
            
            return state
            
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
        """Find similar rules in the knowledge base with intelligent fallback."""
        try:
            logger.info("Finding similar rules with intelligent search")
            
            if state.get("error"):
                return state
            
            parsed_rule = state["parsed_rule"]
            if not parsed_rule:
                return state
            
            request = state["request"]
            rule_summary = ""
            similar_rules = []
            
            # Create intelligent rule summary
            if request.source_format.value == "sigma":
                rule_obj = sigma_parser.parse_rule(request.source_rule)
                rule_summary = sigma_parser.extract_rule_summary(rule_obj)
                primary_collection = "sigma_rules"
                fallback_collections = ["azure_sentinel_detections"]
            elif request.source_format.value == "qradar":
                from ..parsers.qradar_parser import qradar_parser
                rule_obj = qradar_parser.parse_rule(request.source_rule)
                # Create rule summary from parsed rule components
                rule_summary = f"QRadar rule {rule_obj.get('rule_name', 'unknown')} {rule_obj.get('description', '')}"
                # QRadar collection is empty, so use collections with similar content
                primary_collection = "azure_sentinel_detections"  # Has KustoQL examples
                fallback_collections = ["sigma_rules"]  # Has detection rules
            else:
                # Default for other formats
                rule_summary = f"security detection rule {request.source_format.value}"
                primary_collection = "sigma_rules"
                fallback_collections = ["azure_sentinel_detections"]
            
            # Intelligent search parameters based on rule complexity
            search_params = await self._determine_search_parameters(state, rule_summary)
            
            # Enhanced search strategy: try multiple collections
            try:
                # Try primary collection first
                similar_rules = await chromadb_service.search_similar(
                    collection_name=primary_collection,
                    query=rule_summary,
                    n_results=search_params["initial_search_count"]
                )
                
                # If primary collection has insufficient results, try fallback collections
                if len(similar_rules) < search_params["minimum_results_threshold"]:
                    for fallback_collection in fallback_collections:
                        try:
                            fallback_rules = await chromadb_service.search_similar(
                                collection_name=fallback_collection,
                                query=rule_summary,
                                n_results=search_params["fallback_search_count"]
                            )
                            similar_rules.extend(fallback_rules)
                        except Exception as e:
                            logger.warning(f"Fallback collection {fallback_collection} failed: {e}")
                
                # Remove duplicates and keep top results
                seen_docs = set()
                unique_rules = []
                for rule in similar_rules:
                    doc_id = rule.get('document', '')[:search_params["doc_id_length"]]  # Dynamic doc ID length
                    if doc_id not in seen_docs:
                        seen_docs.add(doc_id)
                        unique_rules.append(rule)
                        if len(unique_rules) >= search_params["max_context_items"]:  # Dynamic limit
                            break
                
                similar_rules = unique_rules
                logger.info(f"Found {len(similar_rules)} similar rules from ChromaDB")
                
            except Exception as e:
                logger.warning(f"ChromaDB search failed: {e}")
                similar_rules = []
            
            # INTELLIGENT FALLBACK: Use Foundation-Sec-8B's knowledge when ChromaDB is insufficient
            if len(similar_rules) < search_params["minimum_results_threshold"]:
                logger.info("ChromaDB returned insufficient results, using Foundation-Sec-8B knowledge")
                try:
                    sec8b_context = await self._get_foundation_sec8b_context(state, rule_summary)
                    if sec8b_context:
                        # Add Foundation-Sec-8B knowledge as synthetic "similar rules"
                        similar_rules.extend(sec8b_context)
                        logger.info(f"Added {len(sec8b_context)} items from Foundation-Sec-8B knowledge")
                except Exception as e:
                    logger.warning(f"Foundation-Sec-8B fallback failed: {e}")
            
            state["similar_rules"] = similar_rules
            logger.info(f"Total context items: {len(similar_rules)}")
            
        except Exception as e:
            logger.error(f"Failed to find similar rules: {e}")
            # Don't set error here as this is not critical
            state["similar_rules"] = []
        
        return state
    
    async def _determine_search_parameters(self, state: ConversionState, rule_summary: str) -> Dict[str, int]:
        """Dynamically determine search parameters using Foundation-Sec-8B's intelligence."""
        try:
            request = state["request"]
            
            # Ask Foundation-Sec-8B to determine optimal search parameters
            params_prompt = f"""As a cybersecurity expert, determine optimal search parameters for finding similar rules and context:

RULE TYPE: {request.source_format.value} to {request.target_format.value}
RULE SUMMARY: {rule_summary}

Based on your expertise, determine:
1. How many similar rules to search for initially (3-15 range)
2. Minimum results threshold before fallback (1-5 range)  
3. How many additional rules to search in fallback collections (2-10 range)
4. Maximum context items to keep (5-20 range)
5. Document ID comparison length for deduplication (50-200 range)

Consider:
- Rule complexity (simple rules need fewer examples)
- Conversion difficulty (complex conversions need more context)
- Target format requirements (some formats need more examples)

Respond with only numbers separated by commas:
initial_search,min_threshold,fallback_search,max_context,doc_id_length"""

            response = await llm_service.generate_response(params_prompt, max_tokens=100, use_cybersec_optimization=True)
            
            # Parse the response
            try:
                numbers = [int(x.strip()) for x in response.strip().split(',')]
                if len(numbers) >= 5:
                    return {
                        "initial_search_count": max(3, min(15, numbers[0])),
                        "minimum_results_threshold": max(1, min(5, numbers[1])),
                        "fallback_search_count": max(2, min(10, numbers[2])),
                        "max_context_items": max(5, min(20, numbers[3])),
                        "doc_id_length": max(50, min(200, numbers[4]))
                    }
            except (ValueError, IndexError):
                logger.warning("Failed to parse search parameters from Foundation-Sec-8B, using intelligent defaults")
            
            # Intelligent fallback based on complexity analysis
            complexity_keywords = ["complex", "advanced", "correlation", "behavioral", "anomaly"]
            is_complex = any(keyword in rule_summary.lower() for keyword in complexity_keywords)
            
            if is_complex:
                return {
                    "initial_search_count": 10,
                    "minimum_results_threshold": 4, 
                    "fallback_search_count": 8,
                    "max_context_items": 15,
                    "doc_id_length": 150
                }
            else:
                return {
                    "initial_search_count": 6,
                    "minimum_results_threshold": 2,
                    "fallback_search_count": 5,
                    "max_context_items": 10,
                    "doc_id_length": 100
                }
                
        except Exception as e:
            logger.warning(f"Failed to determine search parameters: {e}")
            # Safe defaults
            return {
                "initial_search_count": 7,
                "minimum_results_threshold": 3,
                "fallback_search_count": 6,
                "max_context_items": 12,
                "doc_id_length": 120
            }
    
    async def _get_foundation_sec8b_context(self, state: ConversionState, rule_summary: str) -> List[Dict[str, Any]]:
        """Get context from Foundation-Sec-8B's cybersecurity knowledge when ChromaDB is insufficient."""
        try:
            request = state["request"]
            
            # Create a prompt to get Foundation-Sec-8B's knowledge about similar rules and patterns
            knowledge_prompt = f"""As a cybersecurity expert with deep knowledge of SIEM rules and threat detection, provide context for converting this security rule:

SOURCE FORMAT: {request.source_format.value}
TARGET FORMAT: {request.target_format.value}
RULE SUMMARY: {rule_summary}

Based on your cybersecurity expertise, provide similar detection patterns, field mappings, and conversion guidance.

Focus on:
1. Similar detection rules and their patterns
2. Field mappings between {request.source_format.value} and {request.target_format.value}
3. Common tables and fields for this type of detection
4. MITRE ATT&CK techniques related to this detection
5. Best practices for this conversion

Provide relevant examples with explanations:"""

            # Get dynamic parameters for knowledge generation
            search_params = await self._determine_search_parameters(state, rule_summary)
            max_knowledge_items = min(search_params["max_context_items"], 8)  # Cap knowledge items
            
            # Get Foundation-Sec-8B's knowledge
            response = await llm_service.generate_response(knowledge_prompt, max_tokens=1500, use_cybersec_optimization=True)
            
            # Parse response into structured context items
            context_items = []
            
            # Split response into sections and create context items
            sections = response.split('\n\n')
            for i, section in enumerate(sections[:max_knowledge_items]):  # Dynamic max sections
                min_section_length = max(30, search_params["doc_id_length"] // 4)  # Dynamic minimum length
                if len(section.strip()) > min_section_length:  # Only meaningful sections
                    # Dynamic similarity scoring
                    base_similarity = 0.95 - (0.05 * (max_knowledge_items - 1))  # Adaptive base
                    similarity_decrement = 0.05 if max_knowledge_items > 4 else 0.03
                    
                    context_items.append({
                        'document': section.strip(),
                        'metadata': {
                            'source': 'foundation_sec8b_knowledge',
                            'type': 'cybersecurity_expertise',
                            'rule_type': request.source_format.value,
                            'target_format': request.target_format.value
                        },
                        'similarity': base_similarity - (i * similarity_decrement),  # Dynamic similarity scores
                        'distance': (1 - base_similarity) + (i * similarity_decrement)
                    })
            
            return context_items
            
        except Exception as e:
            logger.error(f"Failed to get Foundation-Sec-8B context: {e}")
            return []
    
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
            
            # Store enhanced context
            state["context_data"] = enhanced_context
            logger.info(f"Enhanced context gathered with {len(enhanced_context.get('field_names', []))} field names")
            
        except Exception as e:
            logger.error(f"Failed to gather enhanced context: {e}")
            # Fallback to original context gathering
            state["context_data"] = {}
        
        return state
    
    async def _convert_rule_node(self, state: ConversionState) -> ConversionState:
        """Convert the rule using specialized converters or enhanced LLM."""
        try:
            logger.info("Converting rule with specialized converter or enhanced LLM")
            
            if state.get("error"):
                return state
            
            request = state["request"]
            
            # Use enhanced LLM service for ALL conversions (ChromaDB + Foundation-Sec-8B)
            logger.info("Using enhanced LLM service with ChromaDB + Foundation-Sec-8B")
            # Use enhanced LLM service with retry logic and enhanced rule
            conversion_result = await enhanced_llm_service.convert_with_retry(
                source_rule=state["enhanced_rule"],  # Use enhanced rule
                source_format=request.source_format.value,
                target_format=request.target_format.value,
                context=state.get("context_data", {}),  # Pass enhanced context
                max_retries=2
            )
            
            state["conversion_result"] = conversion_result
            logger.info("Rule conversion completed")
            
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
                
                # Use Foundation-Sec-8B for ALL conversions - no specialized converters
                if request.source_format.value == "qradar":
                    # Use Foundation-Sec-8B for QRadar conversion with enhanced rule
                    enhanced_rule = state.get("enhanced_rule", request.source_rule)
                    conversion_result = await llm_service.convert_qradar_rule(
                        qradar_rule=enhanced_rule,
                        target_format=request.target_format,
                        context=context
                    )
                else:
                    # Use Foundation-Sec-8B for other formats
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
        """Validate the conversion result with enhanced guardrails."""
        try:
            logger.info("Validating conversion result with guardrails")
            
            if state.get("error"):
                return state
            
            conversion_result = state.get("conversion_result")
            if not conversion_result:
                state["error"] = "No conversion result available"
                return state
            
            request = state["request"]
            
            # Enhanced validation with guardrails
            validation_results = []
            
            # 1. Basic validation
            if not conversion_result.get("success"):
                validation_results.append("Conversion marked as unsuccessful")
            
            if not conversion_result.get("target_rule"):
                validation_results.append("No target rule generated")
                conversion_result["success"] = False
                conversion_result["error_message"] = "No target rule generated"
            
            # 2. Dynamic confidence score validation using Foundation-Sec-8B
            confidence = conversion_result.get("confidence_score", 0.0)
            dynamic_threshold = await self._determine_confidence_threshold(state, conversion_result)
            if confidence < dynamic_threshold:
                validation_results.append(f"Low confidence score: {confidence} (threshold: {dynamic_threshold})")
            
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
    
    async def _determine_confidence_threshold(self, state: ConversionState, conversion_result: Dict[str, Any]) -> float:
        """Dynamically determine confidence threshold based on conversion characteristics."""
        try:
            request = state["request"]
            
            # Dynamic threshold calculation based on objective factors
            base_threshold = 0.35
            
            # Adjust based on source format complexity
            source_adjustments = {
                "sigma": 0.0,      # Well-structured, easier to convert
                "qradar": 0.1,     # More complex, needs higher threshold
                "kibanaql": 0.05,  # Moderate complexity
            }
            
            # Adjust based on target format requirements
            target_adjustments = {
                "kustoql": 0.0,    # Good LLM support
                "spl": 0.05,       # Moderate LLM support
                "elastic": 0.1,    # More complex structure
            }
            
            # Apply adjustments
            threshold = base_threshold
            threshold += source_adjustments.get(request.source_format.value, 0.05)
            threshold += target_adjustments.get(request.target_format.value, 0.05)
            
            # Adjust based on context quality
            context_data = state.get("context_data", {})
            if context_data.get("field_names") and len(context_data["field_names"]) > 0:
                threshold -= 0.05  # Good context reduces required threshold
            
            if context_data.get("similar_rules_found", 0) >= 5:
                threshold -= 0.05  # Many similar rules available
            
            # Ensure reasonable bounds
            return max(0.2, min(0.7, threshold))
            
        except Exception as e:
            logger.warning(f"Failed to determine confidence threshold: {e}")
            # Safe fallback
            return 0.35
    
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
                # Merge existing metadata with workflow metadata
                base_metadata = {
                    "similar_rules_found": len(state.get("similar_rules", [])),
                    "context_data_available": bool(state.get("context_data")),
                    "field_mappings": conversion_result.get("field_mappings", {}),
                    "notes": conversion_result.get("notes", "")
                }
                # Preserve specialized converter metadata
                specialized_metadata = conversion_result.get("metadata", {})
                merged_metadata = {**base_metadata, **specialized_metadata}
                
                response = ConversionResponse(
                    success=conversion_result.get("success", False),
                    target_rule=conversion_result.get("target_rule"),
                    confidence_score=conversion_result.get("confidence_score", 0.0),
                    explanation=conversion_result.get("explanation", ""),
                    mitre_techniques=state.get("mitre_techniques", []),
                    field_mappings=conversion_result.get("field_mappings", {}),
                    conversion_notes=conversion_result.get("conversion_notes", []),
                    error_message=conversion_result.get("error_message"),
                    metadata=merged_metadata
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
                enhanced_rule=None, # NEW: Initialize enhanced_rule
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