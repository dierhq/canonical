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
from ..services.embedding import get_embedding_service
from ..services.chromadb import chromadb_service
from ..services.llm import get_llm_service
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
        self.chromadb_service = chromadb_service
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
            
            # INTELLIGENT FALLBACK: Use GPT-4o's knowledge when ChromaDB is insufficient
            if len(similar_rules) < search_params["minimum_results_threshold"]:
                logger.info("ChromaDB returned insufficient results, using GPT-4o knowledge")
                try:
                    gpt4o_context = await self._get_gpt4o_context(state, rule_summary)
                    if gpt4o_context:
                        # Add GPT-4o knowledge as synthetic "similar rules"
                        similar_rules.extend(gpt4o_context)
                        logger.info(f"Added {len(gpt4o_context)} items from GPT-4o knowledge")
                except Exception as e:
                    logger.warning(f"GPT-4o fallback failed: {e}")
            
            state["similar_rules"] = similar_rules
            logger.info(f"Total context items: {len(similar_rules)}")
            
        except Exception as e:
            logger.error(f"Failed to find similar rules: {e}")
            # Don't set error here as this is not critical
            state["similar_rules"] = []
        
        return state
    
    async def _determine_search_parameters(self, state: ConversionState, rule_summary: str) -> Dict[str, int]:
        """Dynamically determine search parameters using GPT-4o's intelligence."""
        try:
            request = state["request"]
            
            # Ask GPT-4o to determine optimal search parameters
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

            response = await get_llm_service().generate_response(params_prompt, max_tokens=100, use_cybersec_optimization=True)
            
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
                logger.warning("Failed to parse search parameters from GPT-4o, using intelligent defaults")
            
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
    
    async def _get_gpt4o_context(self, state: ConversionState, rule_summary: str) -> List[Dict[str, Any]]:
        """Get context from GPT-4o's cybersecurity knowledge when ChromaDB is insufficient."""
        try:
            request = state["request"]
            
            # Create a prompt to get GPT-4o's knowledge about similar rules and patterns
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
            
            # Get GPT-4o's knowledge
            response = await get_llm_service().generate_response(knowledge_prompt, max_tokens=1500, use_cybersec_optimization=True)
            
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
            logger.error(f"Failed to get GPT-4o context: {e}")
            return []
    
    async def _gather_context_node(self, state: ConversionState) -> ConversionState:
        """Gather additional context from knowledge base using enhanced retrieval."""
        try:
            logger.info("Gathering enhanced context data")
            
            if state.get("error"):
                return state

            request = state["request"]
            parsed_rule = state.get("parsed_rule", {})
            
            # Extract pattern analysis from parsed rule for enhanced context
            pattern_context = self._extract_pattern_context(parsed_rule, request.source_format)
            
            # Use enhanced hybrid retrieval with Azure Sentinel focus for KustoQL
            enhanced_context = await self._enhanced_hybrid_retrieval(
                request, state.get("similar_rules", []), pattern_context
            )
            
            # NEW: Add custom table context - auto-detect if not provided
            organization = None
            if hasattr(request, 'context') and request.context and request.context.get("organization"):
                organization = request.context["organization"]
            else:
                # Auto-detect organization from available custom tables
                from ..services.custom_tables import custom_table_service
                organization = await custom_table_service.auto_detect_organization(request.source_rule)
            
            if organization:
                logger.info(f"Using custom tables for organization: {organization}")
                
                try:
                    # Create rule summary for custom table search
                    rule_summary = ""
                    if hasattr(parsed_rule, 'get') and parsed_rule.get('title'):
                        rule_summary = f"{parsed_rule['title']} {parsed_rule.get('description', '')}"
                    elif hasattr(request, 'source_rule'):
                        # Extract key terms from source rule for search
                        rule_summary = request.source_rule[:200]  # First 200 chars as summary
                    
                    # Import and use custom table service
                    from ..services.custom_tables import custom_table_service
                    custom_tables = await custom_table_service.search_custom_tables(
                        query=rule_summary,
                        organization=organization,
                        n_results=3
                    )
                    
                    if custom_tables:
                        enhanced_context["custom_tables"] = custom_tables
                        logger.info(f"Added {len(custom_tables)} custom table schemas to context")
                        
                        # Extract table names for validation hints
                        table_names = []
                        for table in custom_tables:
                            table_name = table.get("metadata", {}).get("table_name")
                            if table_name:
                                table_names.append(table_name)
                        
                        if table_names:
                            enhanced_context["available_tables"] = table_names
                            logger.info(f"Available custom tables: {', '.join(table_names)}")
                    
                except Exception as e:
                    logger.warning(f"Failed to retrieve custom tables for {organization}: {e}")
            else:
                logger.debug("No custom tables available - using standard conversion")
            
            # Enhance context with pattern analysis
            if pattern_context:
                enhanced_context.update(pattern_context)
                logger.info(f"Enhanced context with {len(pattern_context.get('regex_patterns', []))} regex patterns")

            # Generate professional KustoQL template with Azure Sentinel examples
            if request.source_format.value == "qradar" and request.target_format.value == "kustoql":
                kusto_template = await self._generate_kusto_template_with_examples(parsed_rule, pattern_context)
                enhanced_context['kusto_template'] = kusto_template
                logger.info(f"Generated KustoQL template with {len(kusto_template.get('azure_examples', []))} Azure Sentinel examples")

            # Extract field names from context for validation
            field_names = set()
            for item in enhanced_context.get("context_items", []):
                if "metadata" in item and "field_names" in item["metadata"]:
                    field_names.update(item["metadata"]["field_names"])
                    
            enhanced_context["field_names"] = list(field_names)

            state["context_data"] = enhanced_context
            logger.info(f"Enhanced context gathered with {len(field_names)} field names")

            return state
            
        except Exception as e:
            logger.error(f"Error gathering context: {e}")
            state["error"] = f"Context gathering failed: {str(e)}"
            return state
    
    def _extract_pattern_context(self, parsed_rule: Dict[str, Any], source_format) -> Dict[str, Any]:
        """Extract pattern analysis context from parsed rule for better conversion."""
        pattern_context = {
            'regex_patterns': [],
            'field_mappings': {},
            'pattern_semantics': [],
            'conversion_hints': []
        }
        
        if source_format.value != "qradar":
            return pattern_context
        
        # Extract custom field patterns from QRadar conditions
        conditions = parsed_rule.get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'custom_field_match':
                field_name = condition.get('field', '')
                pattern = condition.get('pattern', '')
                pattern_analysis = condition.get('pattern_analysis', {})
                
                if pattern and pattern_analysis:
                    # Add regex pattern with analysis
                    pattern_context['regex_patterns'].append({
                        'pattern': pattern,
                        'field': field_name,
                        'analysis': pattern_analysis,
                        'raw_match': condition.get('raw_match', '')
                    })
                    
                    # Add field mapping hints
                    suggested_kusto_field = self._suggest_kusto_field_mapping(field_name, pattern_analysis)
                    if suggested_kusto_field:
                        pattern_context['field_mappings'][field_name] = suggested_kusto_field
                    
                    # Add semantic meaning for prompt context
                    if pattern_analysis.get('semantic_meaning'):
                        pattern_context['pattern_semantics'].append({
                            'field': field_name,
                            'meaning': pattern_analysis['semantic_meaning'],
                            'approach': pattern_analysis.get('suggested_kusto_approach', 'regex_match')
                        })
                    
                    # Add conversion hints based on pattern type
                    conversion_hint = self._generate_conversion_hint(field_name, pattern, pattern_analysis)
                    if conversion_hint:
                        pattern_context['conversion_hints'].append(conversion_hint)
        
        return pattern_context
    
    def _suggest_kusto_field_mapping(self, qradar_field: str, pattern_analysis: Dict[str, Any]) -> Optional[str]:
        """Suggest KustoQL field mapping based on QRadar field and pattern analysis."""
        field_lower = qradar_field.lower()
        
        # DNS-related field mappings
        if 'dns' in field_lower and 'query' in field_lower:
            return 'DnsEvents.QueryName'
        elif 'dns' in field_lower and 'response' in field_lower:
            return 'DnsEvents.ResponseName'
        elif 'dns' in field_lower:
            return 'DnsEvents.QueryName'
        
        # Network-related field mappings
        elif 'source' in field_lower and 'ip' in field_lower:
            return 'SourceIP'
        elif 'destination' in field_lower and 'ip' in field_lower:
            return 'DestinationIP'
        elif 'url' in field_lower or pattern_analysis.get('pattern_type') == 'domain_url':
            return 'Url'
        
        # Process-related field mappings
        elif 'process' in field_lower and 'name' in field_lower:
            return 'ProcessName'
        elif 'command' in field_lower:
            return 'CommandLine'
        
        # File-related field mappings
        elif 'file' in field_lower and 'name' in field_lower:
            return 'FileName'
        elif 'file' in field_lower and 'path' in field_lower:
            return 'FilePath'
        
        # Default based on pattern type
        elif pattern_analysis.get('pattern_type') == 'base64_encoding':
            # For Base64 patterns, suggest the most likely field based on context
            if 'dns' in field_lower:
                return 'DnsEvents.QueryName'
            else:
                return 'EventData'
        
        return None
    
    def _generate_conversion_hint(self, field_name: str, pattern: str, pattern_analysis: Dict[str, Any]) -> Optional[str]:
        """Generate conversion hints for GPT-4o based on pattern analysis."""
        pattern_type = pattern_analysis.get('pattern_type', 'unknown')
        suggested_approach = pattern_analysis.get('suggested_kusto_approach', 'regex_match')
        semantic_meaning = pattern_analysis.get('semantic_meaning', '')
        
        if pattern_type == 'base64_encoding':
            kusto_field = self._suggest_kusto_field_mapping(field_name, pattern_analysis)
            length_constraints = pattern_analysis.get('length_constraints', {})
            
            hint = f"Convert QRadar field '{field_name}' to KustoQL field '{kusto_field or 'QueryName'}' "
            hint += f"using regex pattern '{pattern}' for {semantic_meaning}. "
            
            if length_constraints:
                min_len = length_constraints.get('min', 0)
                hint += f"Pattern detects Base64 strings with minimum length {min_len}. "
            
            hint += f"Use KustoQL 'matches regex' operator for exact pattern matching."
            return hint
        
        elif pattern_type in ['hexadecimal', 'ip_address']:
            kusto_field = self._suggest_kusto_field_mapping(field_name, pattern_analysis)
            hint = f"Convert QRadar field '{field_name}' to KustoQL field '{kusto_field or 'EventData'}' "
            hint += f"using regex pattern '{pattern}' for {semantic_meaning}. "
            hint += f"Use KustoQL 'matches regex' operator."
            return hint
        
        elif pattern_type == 'domain_url':
            kusto_field = self._suggest_kusto_field_mapping(field_name, pattern_analysis)
            hint = f"Convert QRadar field '{field_name}' to KustoQL field '{kusto_field or 'Url'}' "
            hint += f"for {semantic_meaning}. Consider using 'contains' or 'matches regex' based on pattern complexity."
            return hint
        
        return None
    
    def _generate_kusto_template(self, parsed_rule: Dict[str, Any], pattern_context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate professional KustoQL template based on rule analysis."""
        template = {
            'pattern_variables': [],
            'table_selection': None,
            'filters': [],
            'field_mappings': {},
            'output_fields': [],
            'comments': []
        }
        
        # Extract rule metadata for template generation
        rule_name = parsed_rule.get('rule_name', 'Unknown Rule')
        category = parsed_rule.get('category', '')
        conditions = parsed_rule.get('conditions', [])
        
        # Generate pattern variables
        for pattern_info in pattern_context.get('regex_patterns', []):
            pattern = pattern_info.get('pattern', '')
            field = pattern_info.get('field', '')
            analysis = pattern_info.get('analysis', {})
            pattern_type = analysis.get('pattern_type', 'unknown')
            
            if pattern_type == 'base64_encoding':
                var_name = 'Base64Pattern'
                template['pattern_variables'].append({
                    'name': var_name,
                    'value': f'@"{pattern}$"',  # Add end anchor for proper matching
                    'comment': f'Base64 encoded data detection pattern'
                })
            elif pattern_type == 'hexadecimal':
                var_name = 'HexPattern'
                template['pattern_variables'].append({
                    'name': var_name,
                    'value': f'@"{pattern}"',
                    'comment': f'Hexadecimal data pattern'
                })
            elif pattern_type == 'ip_address':
                var_name = 'IpPattern'
                template['pattern_variables'].append({
                    'name': var_name,
                    'value': f'@"{pattern}"',
                    'comment': f'IP address pattern'
                })
        
        # Determine table based on rule category and conditions
        template['table_selection'] = self._select_kusto_table(category, conditions)
        
        # Generate filters based on conditions
        template['filters'] = self._generate_kusto_filters(conditions, pattern_context)
        
        # Generate field mappings
        template['field_mappings'] = self._generate_kusto_field_mappings(conditions, pattern_context)
        
        # Generate output fields
        template['output_fields'] = self._generate_kusto_output_fields(template['table_selection'], conditions)
        
        # Generate comments
        template['comments'] = [
            f'Converted from QRadar rule: {rule_name}',
            f'Original category: {category}' if category else None,
            'Generated by Canonical SIEM Rule Converter'
        ]
        template['comments'] = [c for c in template['comments'] if c]  # Remove None values
        
        return template
    
    def _select_kusto_table(self, category: str, conditions: List[Dict[str, Any]]) -> str:
        """Select appropriate KustoQL table based on rule category and conditions."""
        category_lower = category.lower() if category else ''
        
        # DNS-related rules
        if 'dns' in category_lower:
            return 'DnsEvents'
        
        # Process-related rules
        elif 'process' in category_lower or 'system.process' in category_lower:
            return 'DeviceProcessEvents'
        
        # Network-related rules
        elif 'network' in category_lower or 'connection' in category_lower:
            return 'DeviceNetworkEvents'
        
        # File-related rules
        elif 'file' in category_lower:
            return 'DeviceFileEvents'
        
        # Authentication-related rules
        elif 'logon' in category_lower or 'auth' in category_lower:
            return 'SigninLogs'
        
        # Check conditions for more specific table selection
        for condition in conditions:
            if condition.get('type') == 'event_category':
                categories = condition.get('values', [])
                for cat in categories:
                    cat_lower = cat.lower()
                    if 'dns' in cat_lower:
                        return 'DnsEvents'
                    elif 'process' in cat_lower:
                        return 'DeviceProcessEvents'
                    elif 'network' in cat_lower:
                        return 'DeviceNetworkEvents'
        
        # Default fallback
        return 'SecurityEvent'
    
    def _generate_kusto_filters(self, conditions: List[Dict[str, Any]], pattern_context: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate KustoQL filters based on QRadar conditions."""
        filters = []
        
        for condition in conditions:
            condition_type = condition.get('type')
            
            if condition_type == 'event_category':
                categories = condition.get('values', [])
                # Map QRadar categories to KustoQL EventSubType
                kusto_categories = self._map_qradar_categories_to_kusto(categories)
                if kusto_categories:
                    quoted_categories = [f'"{cat}"' for cat in kusto_categories]
                    filters.append({
                        'field': 'EventSubType',
                        'operator': 'in',
                        'value': f'({", ".join(quoted_categories)})',
                        'comment': 'QRadar category mapping'
                    })
            
            elif condition_type == 'custom_field_match':
                field = condition.get('field', '')
                pattern = condition.get('pattern', '')
                analysis = condition.get('pattern_analysis', {})
                
                kusto_field = self._suggest_kusto_field_mapping(field, analysis)
                if kusto_field:
                    # Use pattern variable if available
                    pattern_var = self._get_pattern_variable_name(analysis.get('pattern_type'))
                    if pattern_var:
                        filters.append({
                            'field': kusto_field,
                            'operator': 'matches regex',
                            'value': pattern_var,
                            'comment': f'Pattern matching for {field}'
                        })
        
        # Add default success filter for DNS queries
        if any('dns' in str(condition).lower() for condition in conditions):
            filters.append({
                'field': 'QueryStatus',
                'operator': '==',
                'value': '"Succeeded"',
                'comment': 'Only successful DNS queries'
            })
        
        return filters
    
    def _map_qradar_categories_to_kusto(self, qradar_categories: List[str]) -> List[str]:
        """Map QRadar event categories to KustoQL EventSubType values."""
        mapping = {
            'Application.DNS In Progress': 'DNS In Progress',
            'Application.DNS Opened': 'DNS Opened',
            'System.Process Created': 'Process Created',
            'Network.Connection Opened': 'Connection Opened',
            'Network.Connection Closed': 'Connection Closed',
            'File.Created': 'File Created',
            'File.Modified': 'File Modified',
            'Authentication.Login': 'Login',
            'Authentication.Logout': 'Logout'
        }
        
        kusto_categories = []
        for category in qradar_categories:
            mapped = mapping.get(category, category)  # Use original if no mapping
            kusto_categories.append(mapped)
        
        return kusto_categories
    
    def _get_pattern_variable_name(self, pattern_type: str) -> Optional[str]:
        """Get pattern variable name based on pattern type."""
        mapping = {
            'base64_encoding': 'Base64Pattern',
            'hexadecimal': 'HexPattern',
            'ip_address': 'IpPattern',
            'domain_url': 'DomainPattern'
        }
        return mapping.get(pattern_type)
    
    def _generate_kusto_field_mappings(self, conditions: List[Dict[str, Any]], pattern_context: Dict[str, Any]) -> Dict[str, str]:
        """Generate KustoQL field mappings with proper Azure Sentinel conventions."""
        mappings = {}
        
        # Standard Azure Sentinel field conventions
        standard_mappings = {
            'SourceIp': 'SrcIpAddr = tostring(SourceIp)',
            'DestinationIp': 'DstIpAddr = tostring(DestinationIp)',
            'SourceIP': 'SrcIpAddr = tostring(SourceIP)',
            'DestinationIP': 'DstIpAddr = tostring(DestinationIP)',
            'ProcessName': 'ProcessName',
            'CommandLine': 'CommandLine',
            'FileName': 'FileName',
            'QueryName': 'QueryName',
            'UserName': 'UserName'
        }
        
        # Apply standard mappings based on context
        for pattern_info in pattern_context.get('regex_patterns', []):
            field = pattern_info.get('field', '')
            analysis = pattern_info.get('analysis', {})
            kusto_field = self._suggest_kusto_field_mapping(field, analysis)
            
            if kusto_field and kusto_field in standard_mappings:
                mappings[kusto_field] = standard_mappings[kusto_field]
        
        return mappings
    
    def _generate_kusto_output_fields(self, table: str, conditions: List[Dict[str, Any]]) -> List[str]:
        """Generate appropriate output fields based on table and conditions."""
        base_fields = ['TimeGenerated']
        
        if table == 'DnsEvents':
            return base_fields + ['SrcIpAddr = tostring(SourceIp)', 'DstIpAddr = tostring(DestinationIp)', 
                                  'QueryName', 'DnsResponseCode']
        elif table == 'DeviceProcessEvents':
            return base_fields + ['DeviceName', 'ProcessName', 'CommandLine', 'AccountName']
        elif table == 'DeviceNetworkEvents':
            return base_fields + ['DeviceName', 'RemoteIP', 'RemotePort', 'LocalIP', 'LocalPort']
        elif table == 'SecurityEvent':
            return base_fields + ['Computer', 'Account', 'EventID', 'Activity']
        
        return base_fields + ['*']  # Fallback
    
    async def _convert_rule_node(self, state: ConversionState) -> ConversionState:
        """Convert the rule using specialized converters or enhanced LLM."""
        try:
            logger.info("Converting rule with specialized converter or enhanced LLM")
            
            if state.get("error"):
                return state
            
            request = state["request"]
            
            # Use enhanced LLM service for ALL conversions (ChromaDB + GPT-4o)
            logger.info("Using enhanced LLM service with ChromaDB + GPT-4o")
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
                
                # Use GPT-4o for ALL conversions - no specialized converters
                if request.source_format.value == "qradar":
                    # Use GPT-4o for QRadar conversion with enhanced rule
                    enhanced_rule = state.get("enhanced_rule", request.source_rule)
                    conversion_result = await get_llm_service().convert_qradar_rule(
                        qradar_rule=enhanced_rule,
                        target_format=request.target_format,
                        context=context
                    )
                else:
                    # Use GPT-4o for other formats
                    conversion_result = await get_llm_service().convert_sigma_rule(
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
            
            # 2. Dynamic confidence score validation using GPT-4o
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
            
            # 5. Enhanced pattern preservation validation for QRadar rules
            if (request.source_format.value == "qradar" and 
                conversion_result.get("target_rule")):
                
                pattern_validation = self._validate_pattern_preservation(state, conversion_result)
                validation_results.extend(pattern_validation["warnings"])
                if pattern_validation["confidence_adjustment"]:
                    current_confidence = conversion_result.get("confidence_score", confidence)
                    conversion_result["confidence_score"] = max(0.0, current_confidence + pattern_validation["confidence_adjustment"])
            
            # 6. Table validation for KustoQL
            if (request.target_format.value == "kustoql" and 
                conversion_result.get("target_rule")):
                
                table_validation = self._validate_kusto_table_usage(conversion_result["target_rule"])
                validation_results.extend(table_validation)
            
            # Store validation results
            if validation_results:
                logger.warning(f"Validation warnings: {validation_results}")
                conversion_result["validation_warnings"] = validation_results
            
            logger.info(f"Enhanced validation completed with {len(validation_results)} warnings")
            
        except Exception as e:
            logger.error(f"Failed to validate conversion result: {e}")
            state["error"] = f"Validation failed: {str(e)}"
        
        return state
    
    def _validate_pattern_preservation(self, state: ConversionState, conversion_result: Dict[str, Any]) -> Dict[str, Any]:
        """Validate that regex patterns from QRadar rule are preserved in the conversion."""
        validation_result = {
            "warnings": [],
            "confidence_adjustment": 0.0
        }
        
        context_data = state.get("context_data", {})
        regex_patterns = context_data.get("regex_patterns", [])
        target_rule = conversion_result.get("target_rule", "").lower()
        
        if not regex_patterns:
            return validation_result
        
        preserved_patterns = 0
        for pattern_info in regex_patterns:
            pattern = pattern_info.get("pattern", "")
            field = pattern_info.get("field", "")
            analysis = pattern_info.get("analysis", {})
            
            # Check if pattern is preserved (exact or adapted)
            pattern_preserved = False
            
            # Check for exact pattern preservation
            if pattern in conversion_result.get("target_rule", ""):
                pattern_preserved = True
                preserved_patterns += 1
            else:
                # Check for adapted pattern (common KustoQL adaptations)
                adapted_patterns = [
                    pattern.replace("\\", "\\\\"),  # Escaped backslashes
                    f"@\"{pattern}\"",  # KustoQL verbatim string
                    pattern.replace("+", "\\+").replace("*", "\\*")  # Escaped special chars
                ]
                
                for adapted in adapted_patterns:
                    if adapted in conversion_result.get("target_rule", ""):
                        pattern_preserved = True
                        preserved_patterns += 1
                        break
            
            if not pattern_preserved:
                pattern_type = analysis.get("pattern_type", "unknown")
                validation_result["warnings"].append(
                    f"Regex pattern '{pattern}' for field '{field}' ({pattern_type}) may not be preserved"
                )
        
        # Adjust confidence based on pattern preservation
        if regex_patterns:
            preservation_ratio = preserved_patterns / len(regex_patterns)
            if preservation_ratio >= 0.8:
                validation_result["confidence_adjustment"] = 0.1  # Boost confidence
            elif preservation_ratio >= 0.5:
                validation_result["confidence_adjustment"] = 0.0  # No change
            else:
                validation_result["confidence_adjustment"] = -0.15  # Reduce confidence
                validation_result["warnings"].append(
                    f"Only {preserved_patterns}/{len(regex_patterns)} regex patterns preserved"
                )
        
        return validation_result
    
    def _validate_kusto_table_usage(self, kusto_query: str) -> List[str]:
        """Validate KustoQL table usage and suggest improvements."""
        warnings = []
        query_lower = kusto_query.lower()
        
        # Check if a table is specified
        common_tables = [
            'dnsevents', 'securityevent', 'commonsecuritylog', 'syslog',
            'deviceprocessevents', 'devicenetworkevents', 'devicefileevents',
            'signinlogs', 'auditlogs', 'windowsevent'
        ]
        
        has_table = any(table in query_lower for table in common_tables)
        
        if not has_table:
            warnings.append("No specific table referenced - query may be too generic")
        
        # Check for proper KustoQL operators
        has_where = '| where' in kusto_query or 'where ' in query_lower
        has_project = '| project' in kusto_query
        
        if not has_where:
            warnings.append("No 'where' clause found - query may lack filtering")
        
        # Check for regex usage when patterns are expected
        has_regex = any(op in kusto_query for op in ['matches regex', 'matches', 'contains'])
        
        return warnings
    
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
            
            # Initialize services (only those that need async initialization)
            await get_embedding_service().initialize()
            await chromadb_service.initialize()
            # Other services initialize automatically in constructor
            
            logger.info("All conversion services initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize services: {e}")
            raise

    async def _enhanced_hybrid_retrieval(self, request, similar_rules, pattern_context):
        """Enhanced hybrid retrieval with Azure Sentinel focus for professional KustoQL examples."""
        context_items = []
        
        # Start with similar rules from initial search
        for rule in similar_rules[:3]:  # Top 3 similar rules
            context_items.append({
                "content": rule.get("content", ""),
                "metadata": rule.get("metadata", {}),
                "score": rule.get("score", 0.0),
                "source": "similar_rules"
            })
        
        # Query Azure Sentinel collections for professional examples
        if request.target_format.value == "kustoql":
            azure_examples = await self._query_azure_sentinel_examples(request, pattern_context)
            context_items.extend(azure_examples)
        
        return {
            "context_items": context_items,
            "total_items": len(context_items),
            "azure_sentinel_examples": len([item for item in context_items if item.get("source") == "azure_sentinel"])
        }
    
    async def _query_azure_sentinel_examples(self, request, pattern_context):
        """Query Azure Sentinel collections for professional KustoQL examples."""
        azure_examples = []
        
        try:
            # Build search queries based on pattern analysis
            search_queries = self._build_azure_sentinel_search_queries(request, pattern_context)
            
            for query_info in search_queries:
                # Query azure_sentinel_detections collection
                try:
                    detection_results = self.chromadb_service.query_collection(
                        collection_name="azure_sentinel_detections",
                        query_text=query_info["query"],
                        n_results=3,
                        metadata_filter=query_info.get("metadata_filter")
                    )
                    
                    for result in detection_results.get("documents", []):
                        azure_examples.append({
                            "content": result,
                            "metadata": {
                                "source_collection": "azure_sentinel_detections",
                                "query_type": query_info["type"],
                                "field_names": self._extract_kusto_field_names(result)
                            },
                            "score": 0.9,  # High relevance for Azure Sentinel examples
                            "source": "azure_sentinel"
                        })
                except Exception as e:
                    logger.warning(f"Failed to query azure_sentinel_detections: {e}")
                
                # Query azure_sentinel_hunting collection
                try:
                    hunting_results = self.chromadb_service.query_collection(
                        collection_name="azure_sentinel_hunting",
                        query_text=query_info["query"],
                        n_results=2,
                        metadata_filter=query_info.get("metadata_filter")
                    )
                    
                    for result in hunting_results.get("documents", []):
                        azure_examples.append({
                            "content": result,
                            "metadata": {
                                "source_collection": "azure_sentinel_hunting",
                                "query_type": query_info["type"],
                                "field_names": self._extract_kusto_field_names(result)
                            },
                            "score": 0.85,  # High relevance for hunting queries
                            "source": "azure_sentinel"
                        })
                except Exception as e:
                    logger.warning(f"Failed to query azure_sentinel_hunting: {e}")
                    
        except Exception as e:
            logger.warning(f"Failed to query Azure Sentinel examples: {e}")
        
        return azure_examples[:8]  # Limit to top 8 examples
    
    def _build_azure_sentinel_search_queries(self, request, pattern_context):
        """Build targeted search queries for Azure Sentinel collections."""
        queries = []
        
        # Base query from rule content
        base_query = f"DNS query detection Base64 encoding pattern matching"
        queries.append({
            "query": base_query,
            "type": "general",
            "metadata_filter": None
        })
        
        # Pattern-specific queries
        if pattern_context and pattern_context.get("regex_patterns"):
            for pattern_info in pattern_context["regex_patterns"]:
                pattern_type = pattern_info.get("pattern_analysis", {}).get("pattern_type", "")
                
                if pattern_type == "base64_encoding":
                    queries.append({
                        "query": "Base64 DNS query DnsEvents QueryName matches regex pattern variable",
                        "type": "base64_dns",
                        "metadata_filter": {"category": "DNS"}
                    })
                elif pattern_type == "hex_pattern":
                    queries.append({
                        "query": "hexadecimal pattern detection regex matches",
                        "type": "hex_pattern",
                        "metadata_filter": None
                    })
                elif pattern_type == "domain_pattern":
                    queries.append({
                        "query": "domain name pattern DNS resolution detection",
                        "type": "domain_pattern", 
                        "metadata_filter": {"category": "DNS"}
                    })
        
        # Field-specific queries
        field_queries = [
            "DnsEvents QueryName QueryStatus EventSubType project TimeGenerated",
            "let pattern variable regex matches where project tostring",
            "DNS query analysis pattern detection professional KustoQL"
        ]
        
        for field_query in field_queries:
            queries.append({
                "query": field_query,
                "type": "field_mapping",
                "metadata_filter": None
            })
        
        return queries[:6]  # Limit to 6 queries to avoid overload
    
    def _extract_kusto_field_names(self, kusto_content):
        """Extract field names from KustoQL content."""
        import re
        field_names = set()
        
        # Common KustoQL field patterns
        patterns = [
            r'\b(\w+)\s*==',  # field == value
            r'\b(\w+)\s*!=',  # field != value  
            r'\b(\w+)\s*contains',  # field contains
            r'\b(\w+)\s*matches',  # field matches
            r'project\s+([^|]+)',  # project fields
            r'extend\s+(\w+)\s*=',  # extend field =
            r'summarize.*by\s+([^|]+)',  # summarize by fields
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, kusto_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    field_names.update([f.strip() for f in match if f.strip()])
                else:
                    # Handle project clause with multiple fields
                    if 'project' in pattern:
                        fields = [f.strip() for f in match.split(',')]
                        field_names.update(fields)
                    else:
                        field_names.add(match.strip())
        
        # Filter out common KustoQL keywords
        kusto_keywords = {'where', 'project', 'extend', 'summarize', 'by', 'let', 'and', 'or', 'not', 'in', 'contains', 'matches', 'regex', 'tostring', 'ago', 'between'}
        return [f for f in field_names if f.lower() not in kusto_keywords and len(f) > 1] 

    async def _generate_kusto_template_with_examples(self, parsed_rule, pattern_context):
        """Generate professional KustoQL template using Azure Sentinel examples."""
        template = {
            "azure_examples": [],
            "pattern_variables": [],
            "field_mappings": [],
            "query_structure": [],
            "professional_patterns": []
        }
        
        try:
            # Extract Azure Sentinel examples for the specific pattern type
            if pattern_context and pattern_context.get("regex_patterns"):
                for pattern_info in pattern_context["regex_patterns"]:
                    pattern_analysis = pattern_info.get("pattern_analysis", {})
                    pattern_type = pattern_analysis.get("pattern_type", "")
                    
                    if pattern_type == "base64_encoding":
                        # Query for Base64 DNS examples
                        base64_examples = await self._get_base64_dns_examples()
                        template["azure_examples"].extend(base64_examples)
                        
                        # Create pattern variable template
                        template["pattern_variables"].append({
                            "name": "Base64Pattern",
                            "value": f'@"{pattern_info.get("raw_pattern", "")}"',
                            "description": "Base64 encoding detection pattern",
                            "usage": "QueryName matches regex Base64Pattern"
                        })
                        
                        # Professional structure template
                        template["query_structure"] = [
                            "// Professional KustoQL structure with pattern variables",
                            "let Base64Pattern = @\"^[A-Za-z0-9+/]{40,}={0,2}$\";",
                            "DnsEvents",
                            "| where QueryName matches regex Base64Pattern",
                            "| where QueryStatus == \"Succeeded\"",
                            "| where EventSubType in (\"DNS In Progress\", \"DNS Opened\")",
                            "| project TimeGenerated, SrcIpAddr = tostring(SourceIp), DstIpAddr = tostring(DestinationIp), QueryName, DnsResponseCode"
                        ]
            
            # Add field mapping templates from Azure Sentinel
            template["field_mappings"] = [
                {"qradar_field": "DNS Query (custom)", "kusto_field": "QueryName", "conversion": "direct"},
                {"qradar_field": "Source IP", "kusto_field": "tostring(SourceIp)", "conversion": "type_conversion"},
                {"qradar_field": "Destination IP", "kusto_field": "tostring(DestinationIp)", "conversion": "type_conversion"},
                {"qradar_field": "Event Category", "kusto_field": "EventSubType", "conversion": "category_mapping"}
            ]
            
            # Professional formatting patterns
            template["professional_patterns"] = [
                "Use 'let' statements for pattern variables",
                "Add descriptive comments explaining the detection logic",
                "Use proper field type conversions with tostring()",
                "Include query status filtering for DNS events",
                "Map QRadar categories to EventSubType appropriately",
                "Structure with clear project clause for output fields"
            ]
            
        except Exception as e:
            logger.warning(f"Failed to generate enhanced KustoQL template: {e}")
        
        return template
    
    async def _get_base64_dns_examples(self):
        """Get specific Base64 DNS examples from Azure Sentinel collections."""
        examples = []
        
        try:
            # Query for Base64 DNS detection examples
            try:
                detection_results = self.chromadb_service.query_collection(
                    collection_name="azure_sentinel_detections",
                    query_text="Base64 DNS query DnsEvents pattern variable regex matches",
                    n_results=3
                )
                
                for result in detection_results.get("documents", []):
                    examples.append({
                        "content": result,
                        "type": "detection_rule",
                        "collection": "azure_sentinel_detections",
                        "relevance": "base64_dns_pattern"
                    })
            except Exception as e:
                logger.warning(f"Failed to query azure_sentinel_detections for Base64 examples: {e}")
            
            # Query hunting queries for additional context
            try:
                hunting_results = self.chromadb_service.query_collection(
                    collection_name="azure_sentinel_hunting",
                    query_text="DNS Base64 encoding suspicious query pattern detection",
                    n_results=2
                )
                
                for result in hunting_results.get("documents", []):
                    examples.append({
                        "content": result,
                        "type": "hunting_query",
                        "collection": "azure_sentinel_hunting", 
                        "relevance": "base64_dns_hunting"
                    })
            except Exception as e:
                logger.warning(f"Failed to query azure_sentinel_hunting for Base64 examples: {e}")
                
        except Exception as e:
            logger.warning(f"Failed to get Base64 DNS examples: {e}")
        
        return examples[:5]  # Return top 5 examples


# Global workflow instance
conversion_workflow = ConversionWorkflow() 