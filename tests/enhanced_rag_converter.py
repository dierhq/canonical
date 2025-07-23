#!/usr/bin/env python3
"""
Enhanced QRadar to KustoQL converter that properly leverages RAG system
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "canonical" / "src"))

from canonical.core.rule_enhancer import universal_enhancer
from canonical.core.models import SourceFormat, ConversionRequest, TargetFormat
from canonical.parsers.qradar_parser import qradar_parser
from canonical.services.chromadb import chromadb_service

class EnhancedRAGConverter:
    """Enhanced converter that leverages ChromaDB knowledge for intelligent conversions."""
    
    def __init__(self):
        self.chromadb_service = chromadb_service
    
    async def convert_with_rag(self, qradar_rule: str) -> Dict[str, Any]:
        """Convert QRadar rule using RAG-enhanced intelligence."""
        
        # Step 1: Enhance and parse the rule
        enhanced_rule = universal_enhancer.enhance_rule(qradar_rule, SourceFormat.QRADAR)
        parsed_rule = qradar_parser.parse_rule(enhanced_rule)
        
        print(f"📋 Parsed Rule: {parsed_rule.get('rule_name')}")
        print(f"   Conditions: {len(parsed_rule.get('conditions', []))}")
        
        # Step 2: Use RAG to find similar Azure Sentinel rules
        similar_rules = await self._find_similar_azure_rules(parsed_rule)
        print(f"🔍 Found {len(similar_rules)} similar Azure Sentinel rules")
        
        # Step 3: Extract table recommendations from similar rules
        recommended_tables = self._extract_table_recommendations(similar_rules)
        print(f"📊 Recommended tables: {recommended_tables}")
        
        # Step 4: Extract query patterns from similar rules
        query_patterns = self._extract_query_patterns(similar_rules, parsed_rule)
        print(f"🎯 Query patterns identified: {len(query_patterns)} patterns")
        
        # Step 5: Generate intelligent KustoQL query
        kustoql_query = self._generate_intelligent_query(parsed_rule, recommended_tables, query_patterns)
        
        return {
            "success": True,
            "target_rule": kustoql_query,
            "confidence_score": self._calculate_rag_confidence(similar_rules, recommended_tables),
            "similar_rules_found": len(similar_rules),
            "recommended_tables": recommended_tables,
            "rag_enhanced": True
        }
    
    async def _find_similar_azure_rules(self, parsed_rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find similar Azure Sentinel rules using semantic search."""
        try:
            # Create search queries from rule components
            search_queries = []
            
            # Search by rule description/purpose
            if parsed_rule.get('description'):
                search_queries.append(parsed_rule['description'])
            
            # Search by conditions
            conditions = parsed_rule.get('conditions', [])
            for condition in conditions:
                if condition.get('type') == 'custom_field_match':
                    field = condition.get('field', '')
                    pattern = condition.get('pattern', '')
                    search_queries.append(f"{field} {pattern}")
                elif condition.get('type') == 'event_category':
                    categories = condition.get('values', [])
                    search_queries.append(' '.join(categories))
            
            # Search responses for additional context
            responses = parsed_rule.get('responses', [])
            for response in responses:
                if response.get('type') == 'dispatch_event':
                    desc = response.get('event_description', '')
                    if desc:
                        search_queries.append(desc)
            
            # Perform semantic searches
            all_results = []
            for query in search_queries[:3]:  # Limit to top 3 queries
                results = await self.chromadb_service.search_similar(
                    collection_name="azure_sentinel_detections",
                    query=query,
                    n_results=5
                )
                all_results.extend(results)
            
            # Deduplicate and return top results
            seen_ids = set()
            unique_results = []
            for result in all_results:
                result_id = result.get('id', '')
                if result_id not in seen_ids:
                    seen_ids.add(result_id)
                    unique_results.append(result)
                    if len(unique_results) >= 10:  # Limit total results
                        break
            
            return unique_results
            
        except Exception as e:
            print(f"❌ Error finding similar rules: {e}")
            return []
    
    def _extract_table_recommendations(self, similar_rules: List[Dict[str, Any]]) -> Dict[str, int]:
        """Extract table usage recommendations from similar Azure Sentinel rules."""
        table_counts = {}
        
        for rule in similar_rules:
            document = rule.get('document', '')
            if not document:
                continue
            
            # Extract table names from KustoQL queries
            tables = self._extract_tables_from_kustoql(document)
            for table in tables:
                table_counts[table] = table_counts.get(table, 0) + 1
        
        # Sort by frequency
        return dict(sorted(table_counts.items(), key=lambda x: x[1], reverse=True))
    
    def _extract_tables_from_kustoql(self, kustoql: str) -> List[str]:
        """Extract table names from KustoQL query."""
        # Common Azure Sentinel table patterns
        table_patterns = [
            r'\b(SecurityEvent)\b',
            r'\b(DnsEvents)\b', 
            r'\b(CommonSecurityLog)\b',
            r'\b(DeviceNetworkInfo)\b',
            r'\b(DeviceProcessEvents)\b',
            r'\b(DeviceFileEvents)\b',
            r'\b(DeviceLogonEvents)\b',
            r'\b(DeviceRegistryEvents)\b',
            r'\b(AzureDiagnostics)\b',
            r'\b(VMConnection)\b',
            r'\b(Heartbeat)\b',
            r'\b(Syslog)\b',
            r'\b(WindowsEvent)\b'
        ]
        
        tables = []
        for pattern in table_patterns:
            matches = re.findall(pattern, kustoql, re.IGNORECASE)
            tables.extend(matches)
        
        return list(set(tables))  # Remove duplicates
    
    def _extract_query_patterns(self, similar_rules: List[Dict[str, Any]], parsed_rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract query patterns from similar rules."""
        patterns = []
        
        for rule in similar_rules:
            document = rule.get('document', '')
            if not document:
                continue
            
            # Extract key patterns
            pattern = {
                'filters': self._extract_filters(document),
                'aggregations': self._extract_aggregations(document),
                'time_windows': self._extract_time_windows(document),
                'regex_patterns': self._extract_regex_patterns(document)
            }
            
            if any(pattern.values()):  # Only add if we found something
                patterns.append(pattern)
        
        return patterns
    
    def _extract_filters(self, kustoql: str) -> List[str]:
        """Extract filter patterns from KustoQL."""
        filters = []
        filter_lines = re.findall(r'\|\s*where\s+(.+)', kustoql, re.IGNORECASE)
        return filter_lines
    
    def _extract_aggregations(self, kustoql: str) -> List[str]:
        """Extract aggregation patterns from KustoQL."""
        agg_lines = re.findall(r'\|\s*summarize\s+(.+)', kustoql, re.IGNORECASE)
        return agg_lines
    
    def _extract_time_windows(self, kustoql: str) -> List[str]:
        """Extract time window patterns from KustoQL."""
        time_patterns = re.findall(r'ago\(([^)]+)\)', kustoql, re.IGNORECASE)
        return time_patterns
    
    def _extract_regex_patterns(self, kustoql: str) -> List[str]:
        """Extract regex patterns from KustoQL."""
        regex_patterns = re.findall(r'matches\s+regex\s+["\']([^"\']+)["\']', kustoql, re.IGNORECASE)
        return regex_patterns
    
    def _generate_intelligent_query(self, parsed_rule: Dict[str, Any], recommended_tables: Dict[str, int], query_patterns: List[Dict[str, Any]]) -> str:
        """Generate KustoQL query using RAG intelligence."""
        rule_name = parsed_rule.get('rule_name', 'Enhanced Rule')
        conditions = parsed_rule.get('conditions', [])
        responses = parsed_rule.get('responses', [])
        
        # Get the most recommended table
        primary_table = list(recommended_tables.keys())[0] if recommended_tables else "SecurityEvent"
        
        # Get event description
        event_description = "RAG-enhanced rule conversion"
        for response in responses:
            if response.get('type') == 'dispatch_event':
                desc = response.get('event_description', '')
                if desc:
                    event_description = desc
                    break
        
        query_lines = [
            f"// ===== {event_description} =========================================",
            f"// RAG-Enhanced Conversion: Based on analysis of {len(query_patterns)} similar Azure Sentinel rules",
            f"// Recommended table: {primary_table} (used in {recommended_tables.get(primary_table, 0)} similar rules)",
            f"// Alternative tables: {', '.join(list(recommended_tables.keys())[1:4])}",
            "let timeRange = 1h;",
            f"{primary_table}",
            "| where TimeGenerated >= ago(timeRange)"
        ]
        
        # Add intelligent filters based on conditions and patterns
        for condition in conditions:
            if condition.get('type') == 'custom_field_match':
                field = condition.get('field', '')
                pattern = condition.get('pattern', '')
                
                # Map field to appropriate column based on table
                kusto_field = self._map_field_to_kusto(field, primary_table)
                
                if pattern and kusto_field:
                    clean_pattern = pattern.replace('\\/', '/')
                    query_lines.append(f"| where {kusto_field} matches regex @\"{clean_pattern}\"")
            
            elif condition.get('type') == 'event_category':
                categories = condition.get('values', [])
                if categories and primary_table == "SecurityEvent":
                    # Map to EventID for SecurityEvent table
                    query_lines.append(f"| where EventID in (4624, 4625, 4688)  // Mapped from categories: {', '.join(categories)}")
            
            elif condition.get('type') == 'destination_port':
                port = condition.get('value')
                if port:
                    port_field = self._get_port_field(primary_table)
                    if port_field:
                        query_lines.append(f"| where {port_field} == {port}")
        
        # Add intelligent aggregation if patterns suggest it
        has_threshold = any(c.get('type') == 'threshold' for c in conditions)
        if has_threshold and query_patterns:
            # Learn from similar patterns
            agg_patterns = []
            for pattern in query_patterns:
                agg_patterns.extend(pattern.get('aggregations', []))
            
            if agg_patterns:
                # Use the most common aggregation pattern
                common_agg = max(set(agg_patterns), key=agg_patterns.count) if agg_patterns else None
                if common_agg:
                    query_lines.append(f"| summarize {common_agg}")
        
        # Add projection
        projection_fields = self._get_projection_fields(primary_table)
        query_lines.append(f"| project {', '.join(projection_fields)}")
        
        query_lines.append(f"// Generated using RAG analysis of {len(recommended_tables)} table recommendations")
        
        return '\n'.join(query_lines)
    
    def _map_field_to_kusto(self, qradar_field: str, table: str) -> Optional[str]:
        """Map QRadar field to appropriate KustoQL field based on table."""
        field_mappings = {
            "DnsEvents": {
                "DNS Query": "QueryName",
                "DNS Query (custom)": "QueryName"
            },
            "SecurityEvent": {
                "Process Name": "ProcessName",
                "Command Line": "CommandLine",
                "User Name": "Account"
            },
            "CommonSecurityLog": {
                "Source IP": "SourceIP",
                "Destination IP": "DestinationIP",
                "Application Protocol": "ApplicationProtocol"
            }
        }
        
        table_mapping = field_mappings.get(table, {})
        return table_mapping.get(qradar_field)
    
    def _get_port_field(self, table: str) -> Optional[str]:
        """Get the appropriate port field for the table."""
        port_fields = {
            "CommonSecurityLog": "DestinationPort",
            "DeviceNetworkInfo": "RemotePort",
            "SecurityEvent": "DestinationPort"
        }
        return port_fields.get(table)
    
    def _get_projection_fields(self, table: str) -> List[str]:
        """Get appropriate projection fields for the table."""
        projections = {
            "DnsEvents": ["TimeGenerated", "Computer", "QueryName", "QueryStatus", "SourceIP"],
            "SecurityEvent": ["TimeGenerated", "Computer", "EventID", "Account", "ProcessName"],
            "CommonSecurityLog": ["TimeGenerated", "Computer", "SourceIP", "DestinationIP", "DestinationPort"]
        }
        return projections.get(table, ["TimeGenerated", "Computer"])
    
    def _calculate_rag_confidence(self, similar_rules: List[Dict[str, Any]], recommended_tables: Dict[str, int]) -> float:
        """Calculate confidence based on RAG analysis."""
        base_confidence = 0.5
        
        # Boost confidence based on number of similar rules found
        if len(similar_rules) >= 5:
            base_confidence += 0.3
        elif len(similar_rules) >= 2:
            base_confidence += 0.2
        
        # Boost confidence based on table consensus
        if recommended_tables:
            max_count = max(recommended_tables.values())
            if max_count >= 3:
                base_confidence += 0.2
        
        return min(base_confidence, 1.0)

# Test the enhanced converter
async def test_enhanced_rag():
    """Test the enhanced RAG converter."""
    
    qradar_rule = """Rule Name: QRCE - 001 - Base64 DNS Query
Rule Description: Apply QRCE - 001 - Base64 DNS Query on events which are detected by the Local system
Rule Type: EVENT
Enabled: true
Severity: 5
Credibility: 10
Relevance: 10
Category: Application.DNS In Progress

when the event(s) are detected by the Local system
and when the event category for the event is one of the following "Application.DNS In Progress", "Application.DNS Opened"
and when any of DNS Query (custom) match "^[a-zA-Z0-9+\\/]{40,}={0,2}"

Rule Actions:
Force the detected Event to create a NEW offense, select the offense using Source IP
Annotate this offense with: QRCE - 001 - Base64 DNS Query

Rule Responses:
Dispatch New Event
Event Name: QRCE - 001 - Base64 DNS Query
Event Description: This rule is designed to detected Base64 encoded DNS queries. This could potentially indicate data exfiltration.
Severity: 5 Credibility: 10 Relevance: 10
High-Level Category: Application
Low-Level Category: DNS In Progress"""

    print("🚀 Testing Enhanced RAG Converter")
    print("=" * 60)
    
    converter = EnhancedRAGConverter()
    await converter.chromadb_service.initialize()
    
    result = await converter.convert_with_rag(qradar_rule)
    
    print(f"\n✅ Conversion completed!")
    print(f"Success: {result['success']}")
    print(f"Confidence: {result['confidence_score']}")
    print(f"RAG Enhanced: {result['rag_enhanced']}")
    print(f"Similar Rules Found: {result['similar_rules_found']}")
    print(f"Recommended Tables: {result['recommended_tables']}")
    
    print(f"\n📝 Generated Query:")
    print("-" * 50)
    print(result['target_rule'])

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_enhanced_rag()) 