"""
Hybrid retrieval service that combines semantic and keyword-based search.
"""

import re
from typing import Dict, Any, List, Optional
from loguru import logger

from .chromadb import chromadb_service
from .embedding import embedding_service
from .custom_tables import custom_table_service


class HybridRetrievalService:
    """Hybrid retrieval service combining semantic and keyword search."""
    
    def __init__(self):
        self.chromadb_service = chromadb_service
        self.embedding_service = embedding_service
        self.custom_table_service = custom_table_service
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the hybrid retrieval service."""
        if not self._initialized:
            await self.chromadb_service.initialize()
            await self.embedding_service.initialize()
            self._initialized = True
    
    async def retrieve_context_for_conversion(
        self,
        source_format: str,
        target_format: str,
        rule_summary: str,
        parsed_rule: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Retrieve context for rule conversion using hybrid approach.
        
        Args:
            source_format: Source rule format
            target_format: Target rule format
            rule_summary: Summary of the rule for context retrieval
            parsed_rule: Optional parsed rule data
            context: Optional context including organization info
            
        Returns:
            Dictionary containing retrieved context
        """
        if not self._initialized:
            await self.initialize()
        
        logger.info(f"Retrieving context for {source_format} -> {target_format} conversion")
        
        # Initialize context data
        context_data = {
            "similar_rules": [],
            "schema_info": [],
            "examples": [],
            "custom_tables": []
        }
        
        try:
            # 1. Get similar rules from standard collections
            similar_rules = await self._get_similar_rules(source_format, target_format, rule_summary)
            context_data["similar_rules"] = similar_rules
            
            # 2. Get schema information for target format
            schema_info = await self._get_schema_info(target_format)
            context_data["schema_info"] = schema_info
            
            # 3. Get conversion examples
            examples = await self._get_conversion_examples(source_format, target_format)
            context_data["examples"] = examples
            
            # 4. NEW: Get custom tables if organization is provided
            if context and context.get("organization"):
                organization = context["organization"]
                logger.info(f"Retrieving custom tables for organization: {organization}")
                
                try:
                    custom_tables = await self.custom_table_service.search_custom_tables(
                        query=rule_summary,
                        organization=organization,
                        n_results=3
                    )
                    context_data["custom_tables"] = custom_tables
                    logger.info(f"Found {len(custom_tables)} custom table schemas for {organization}")
                except Exception as e:
                    logger.warning(f"Failed to retrieve custom tables for {organization}: {e}")
            
            # Log context summary
            total_items = (
                len(context_data["similar_rules"]) + 
                len(context_data["schema_info"]) + 
                len(context_data["examples"]) +
                len(context_data["custom_tables"])
            )
            logger.info(f"Retrieved {total_items} total context items")
            
        except Exception as e:
            logger.error(f"Error retrieving conversion context: {e}")
        
        return context_data
    
    def _extract_structured_patterns(
        self, 
        results: List[Dict[str, Any]], 
        source_format: str, 
        target_format: str,
        organization: Optional[str] = None
    ) -> Dict[str, Any]:
        """Extract structured patterns from similar rules for better context."""
        
        # Detect rule category from content
        rule_category = self._detect_rule_category(results[0].get("content", "")) if results else "general"
        
        # Extract relevant patterns based on target format
        if target_format.lower() == "kustoql":
            return self._extract_kustoql_patterns(results, rule_category)
        elif target_format.lower() == "spl":
            return self._extract_spl_patterns(results, rule_category)
        else:
            return self._extract_general_patterns(results, rule_category)
    
    def _detect_rule_category(self, rule_content: str) -> str:
        """Detect the category of the rule based on content."""
        content_lower = rule_content.lower()
        
        if any(keyword in content_lower for keyword in ["dns", "query", "domain", "nslookup"]):
            return "dns"
        elif any(keyword in content_lower for keyword in ["process", "executable", "command", "powershell", "cmd"]):
            return "process"
        elif any(keyword in content_lower for keyword in ["network", "connection", "port", "ip", "traffic"]):
            return "network"
        elif any(keyword in content_lower for keyword in ["file", "write", "create", "delete", "modify"]):
            return "file"
        elif any(keyword in content_lower for keyword in ["login", "authentication", "logon", "signin"]):
            return "authentication"
        else:
            return "general"
    
    def _extract_kustoql_patterns(self, results: List[Dict[str, Any]], category: str) -> Dict[str, Any]:
        """Extract KustoQL-specific patterns and examples."""
        # Enhanced table mappings based on actual usage patterns
        table_mappings = {
            "dns": ["DnsEvents", "AzureDiagnostics", "CommonSecurityLog"],
            "process": ["DeviceProcessEvents", "ProcessCreation", "SecurityEvent"],
            "network": ["NetworkEvents", "CommonSecurityLog", "DeviceNetworkEvents"],
            "general": ["SecurityEvent", "DeviceEvents", "CommonSecurityLog"]
        }
        
        field_mappings = {
            "dns": [
                "QueryName (DNS query domain)",
                "QueryType (DNS record type)",
                "ResponseCode (DNS response status)",
                "SourceIp (requesting IP)",
                "DestinationIp (DNS server IP)"
            ],
            "process": [
                "ProcessCommandLine (full command)",
                "InitiatingProcessFileName (parent process)",
                "AccountName (user account)",
                "DeviceName (hostname)",
                "ProcessId (PID)"
            ],
            "network": [
                "RemoteIP (destination IP)",
                "RemotePort (destination port)",
                "LocalIP (source IP)",
                "LocalPort (source port)",
                "Protocol (TCP/UDP)"
            ]
        }
        
        # Enhanced pattern extraction - specifically look for regex patterns
        query_examples = []
        regex_patterns = []
        
        for result in results[:3]:  # Use top 3 results
            content = result.get("content", "")
            if content and "|" in content:  # Looks like KustoQL
                # Extract clean query patterns
                lines = content.split('\n')
                kusto_lines = [line.strip() for line in lines if '|' in line and line.strip()]
                if kusto_lines:
                    query_examples.append('\n'.join(kusto_lines[:3]))  # First 3 lines
                
                # Extract regex patterns specifically
                import re
                # Look for regex patterns in various KustoQL contexts
                regex_contexts = [
                    r'matches regex\s*@?"([^"]+)"',  # matches regex @"pattern"
                    r'matches regex\s*\'([^\']+)\'',  # matches regex 'pattern'
                    r'=~\s*@?"([^"]+)"',  # =~ @"pattern"
                    r'=~\s*\'([^\']+)\'',  # =~ 'pattern'
                    r'let\s+\w*[Rr]egex\w*\s*=\s*@?"([^"]+)"',  # let SomeRegex = @"pattern"
                    r'let\s+\w*[Pp]attern\w*\s*=\s*@?"([^"]+)"',  # let SomePattern = @"pattern"  
                    r'let\s+\w+\s*=\s*@?"([^"]*[.*+\[\]{}()|\\^$][^"]*)"',  # let var = @"regex-like"
                    r'contains regex\s*@?"([^"]+)"',  # contains regex @"pattern"
                    r'extract\s*\(\s*@?"([^"]+)"',  # extract(@"pattern", ...)
                    r'parse\s+.*with\s*@?"([^"]*[.*+\[\]{}()|\\^$][^"]*)"',  # parse ... with @"pattern"
                ]
                
                logger.debug(f"Extracting regex patterns from {len(results)} results")
                for pattern in regex_contexts:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    logger.debug(f"Pattern '{pattern[:30]}...' found {len(matches)} matches")
                    for match in matches:
                        if len(match) > 10:  # Filter out very short patterns
                            regex_patterns.append(match)
                            logger.debug(f"Added regex pattern: {match}")
                
                logger.debug(f"Total regex patterns extracted: {len(regex_patterns)}")
        
        # Build structured examples string
        similar_rules_formatted = self._format_similar_rules_context(results, category)
        
        return {
            "table_examples": table_mappings.get(category, table_mappings["general"]),
            "field_mappings": field_mappings.get(category, []),
            "query_patterns": query_examples,
            "regex_patterns": regex_patterns,  # Add extracted regex patterns
            "similar_rules_formatted": similar_rules_formatted
        }
    
    def _extract_spl_patterns(self, results: List[Dict[str, Any]], category: str) -> Dict[str, Any]:
        """Extract Splunk SPL-specific patterns."""
        # Similar structure for SPL
        table_mappings = {
            "dns": ["index=dns", "sourcetype=dns", "index=network sourcetype=dns"],
            "process": ["index=windows sourcetype=WinEventLog:Security", "index=endpoint"],
            "general": ["index=main", "index=security"]
        }
        
        # Extract regex patterns from SPL content
        regex_patterns = []
        for result in results[:3]:
            content = result.get("content", "")
            if content:
                import re
                # Look for SPL regex patterns
                spl_regex_contexts = [
                    r'rex\s+"([^"]+)"',  # rex "pattern"
                    r'regex\s+"([^"]+)"',  # regex "pattern"
                    r'match\s*\(\s*"([^"]+)"',  # match("pattern"
                    r'like\s*"([^"]+)"',  # like "pattern"
                ]
                
                for pattern in spl_regex_contexts:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if len(match) > 10:  # Filter out very short patterns
                            regex_patterns.append(match)
        
        return {
            "table_examples": table_mappings.get(category, table_mappings["general"]),
            "field_mappings": [],
            "query_patterns": [],
            "regex_patterns": regex_patterns,  # Add extracted regex patterns
            "similar_rules_formatted": ""
        }
    
    def _extract_general_patterns(self, results: List[Dict[str, Any]], category: str) -> Dict[str, Any]:
        """Extract general patterns for other formats."""
        return {
            "table_examples": [],
            "field_mappings": [],
            "query_patterns": [],
            "regex_patterns": [],  # Add empty regex patterns for consistency
            "similar_rules_formatted": ""
        }
    
    def _format_similar_rules_context(self, results: List[Dict[str, Any]], category: str) -> str:
        """Format similar rules into useful context for Foundation-Sec-8B."""
        if not results:
            return ""
        
        context_parts = [f"Examples for {category} detection:"]
        
        for i, result in enumerate(results[:2], 1):  # Use top 2 results
            content = result.get("content", "")
            title = result.get("title", f"Example {i}")
            
            if content:
                # Extract key parts of the rule
                if "|" in content:  # KustoQL-like
                    lines = content.split('\n')
                    key_lines = [line.strip() for line in lines if '|' in line and any(kw in line.lower() for kw in ['where', 'project', 'summarize'])]
                    if key_lines:
                        context_parts.append(f"\n{title}:")
                        context_parts.append('\n'.join(key_lines[:3]))
        
        return '\n'.join(context_parts)

    async def _semantic_search(self, query: str, max_results: int, collection_name: str = "sigma_rules") -> List[Dict[str, Any]]:
        """Perform semantic search using embeddings."""
        try:
            # Search in ChromaDB
            results = await self.chromadb_service.search_similar(
                collection_name=collection_name,
                query=query,
                n_results=max_results
            )
            
            return results
            
        except Exception as e:
            logger.error(f"Error in semantic search: {e}")
            return []
    
    async def _format_specific_search(
        self,
        source_format: str,
        target_format: str,
        max_results: int
    ) -> List[Dict[str, Any]]:
        """Search for format-specific examples."""
        try:
            # Search for examples of the target format
            format_query = f"{target_format} examples rules"
            format_results = await self._semantic_search(format_query, max_results, "azure_sentinel_detections")
            
            return format_results
            
        except Exception as e:
            logger.error(f"Error in format-specific search: {e}")
            return []
    
    async def _search_custom_tables(self, query: str, organization: str, max_results: int) -> List[Dict[str, Any]]:
        """Search custom tables for relevant examples."""
        try:
            results = await self.custom_table_service.search_custom_tables(
                query=query,
                organization=organization,
                n_results=max_results
            )
            return results
        except Exception as e:
            logger.error(f"Error searching custom tables: {e}")
            return []

    def _combine_results(
        self,
        semantic_results: List[Dict[str, Any]],
        format_results: List[Dict[str, Any]],
        custom_results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Combine and deduplicate search results."""
        combined = []
        seen_docs = set()
        
        # Add semantic results first (higher priority)
        for result in semantic_results:
            # Use document content hash for deduplication since results don't have 'id'
            doc_content = result.get("document", "")[:100]  # First 100 chars as unique identifier
            if doc_content and doc_content not in seen_docs:
                combined.append(result)
                seen_docs.add(doc_content)
        
        # Add format results that weren't already included
        for result in format_results:
            doc_content = result.get("document", "")[:100]  # First 100 chars as unique identifier
            if doc_content and doc_content not in seen_docs:
                combined.append(result)
                seen_docs.add(doc_content)
        
        # Add custom results that weren't already included
        for result in custom_results:
            doc_content = result.get("document", "")[:100]  # First 100 chars as unique identifier
            if doc_content and doc_content not in seen_docs:
                combined.append(result)
                seen_docs.add(doc_content)
        
        return combined


# Create singleton instance
hybrid_retrieval_service = HybridRetrievalService() 