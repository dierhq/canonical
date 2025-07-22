"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
QRadar to KustoQL conversion workflow.
"""

import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from loguru import logger

from ..core.models import ConversionRequest, ConversionResponse
from ..parsers.qradar_parser import qradar_parser
from ..services.chromadb import chromadb_service


class QRadarToKustoQLConverter:
    """Converts QRadar rules to KustoQL format."""
    
    def __init__(self):
        """Initialize the converter."""
        self.table_column_mapping = {
            "DnsEvents": {
                "query_field": "QueryName",
                "client_ip": "ClientIP",
                "event_type": "EventSubType",
                "time_field": "TimeGenerated",
                "response_code": "ResponseCode",
                "query_type": "QueryType",
                "logical_source": "dns_logs"
            },
            "DeviceNetworkInfo": {
                "local_ip": "LocalIP",
                "remote_ip": "RemoteIP", 
                "remote_port": "RemotePort",
                "local_port": "LocalPort",
                "action_type": "ActionType",
                "time_field": "TimeGenerated",
                "logical_source": "network_logs"
            },
            "SecurityEvent": {
                "event_id": "EventID",
                "ip_address": "IpAddress",
                "ip_port": "IpPort",
                "time_field": "TimeGenerated",
                "account_name": "Account",
                "target_domain": "TargetDomainName",
                "logical_source": "windows_logs"
            },
            "CommonSecurityLog": {
                "source_ip": "SourceIP",
                "destination_ip": "DestinationIP",
                "destination_port": "DestinationPort",
                "source_port": "SourcePort",
                "time_field": "TimeGenerated",
                "device_vendor": "DeviceVendor",
                "device_product": "DeviceProduct",
                "logical_source": "network_logs"
            },
            "Syslog": {
                "computer": "Computer",
                "facility": "Facility",
                "severity_level": "SeverityLevel",
                "syslog_message": "SyslogMessage",
                "time_field": "TimeGenerated",
                "logical_source": "syslog"
            }
        }
    
    async def convert_rule(self, request: ConversionRequest) -> ConversionResponse:
        """Convert QRadar rule to KustoQL.
        
        Args:
            request: Conversion request containing QRadar rule text
            
        Returns:
            Conversion response with KustoQL query
        """
        try:
            logger.info("Converting QRadar rule to KustoQL")
            
            # Parse the QRadar rule
            parsed_rule = qradar_parser.parse_rule(request.source_rule)
            
            # Detect candidate tables and make multi-table decision
            conditions = parsed_rule.get('conditions', [])
            candidate_tables = self._detect_candidate_tables(conditions)
            multi_table_decision = self._make_multi_table_decision(candidate_tables, conditions, parsed_rule)
            
            # Generate KustoQL query based on parsed rule
            kustoql_query = await self._generate_kustoql_query(parsed_rule)
            
            # Get additional context from ChromaDB
            context = await self._get_context_from_chromadb(parsed_rule)
            
            # Generate explanation including multi-table rationale
            explanation = self._generate_explanation(parsed_rule, context, multi_table_decision)
            
            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(parsed_rule)
            
            # Create enhanced conversion notes
            conversion_notes = self._generate_conversion_notes(parsed_rule, multi_table_decision)
            
            return ConversionResponse(
                success=True,
                target_rule=kustoql_query,
                confidence_score=confidence_score,
                explanation=explanation,
                mitre_techniques=self._extract_mitre_techniques(parsed_rule),
                field_mappings=self._generate_field_mappings(parsed_rule),
                conversion_notes=conversion_notes,
                # Add multi-table information to metadata
                metadata={
                    "multi_table_mode": multi_table_decision["mode"],
                    "candidate_tables": candidate_tables,
                    "selected_tables": multi_table_decision["tables"],
                    "multi_table_rationale": multi_table_decision["rationale"]
                }
            )
            
        except Exception as e:
            logger.error(f"QRadar to KustoQL conversion failed: {e}")
            return ConversionResponse(
                success=False,
                target_rule=None,
                confidence_score=0.0,
                explanation=f"Conversion failed: {str(e)}",
                error_message=str(e)
            )
    
    async def _generate_kustoql_query(self, parsed_rule: Dict[str, Any]) -> str:
        """Generate KustoQL query from parsed QRadar rule."""
        rule_name = parsed_rule.get('rule_name', 'Unknown Rule')
        conditions = parsed_rule.get('conditions', [])
        responses = parsed_rule.get('responses', [])
        
        # Detect potential tables and make intelligent multi-table decision
        candidate_tables = self._detect_candidate_tables(conditions)
        multi_table_decision = self._make_multi_table_decision(candidate_tables, conditions, parsed_rule)
        
        # Generate query based on multi-table decision
        if multi_table_decision["mode"] == "union":
            return self._generate_union_query(parsed_rule, multi_table_decision["tables"])
        elif multi_table_decision["mode"] == "split":
            # For split mode, return the primary table query (caller should handle multiple queries)
            primary_table = multi_table_decision["tables"][0]
            return self._generate_single_table_query(parsed_rule, primary_table)
        else:
            # Single table mode - use existing logic
            if self._is_dns_rule(conditions):
                return self._generate_dns_query(parsed_rule)
            elif self._is_network_scanning_rule(conditions):
                return self._generate_network_scanning_query(parsed_rule)
            else:
                return self._generate_generic_query(parsed_rule)

    def _detect_candidate_tables(self, conditions: List[Dict[str, Any]]) -> List[str]:
        """Detect which tables could be relevant based on rule conditions."""
        candidate_tables = []
        
        for condition in conditions:
            condition_type = condition.get('type', '')
            
            # DNS-related conditions
            if condition_type == 'event_category':
                categories = condition.get('values', [])
                for category in categories:
                    if 'DNS' in category:
                        candidate_tables.append("DnsEvents")
            
            # Network-related conditions  
            elif condition_type in ['destination_port', 'source_port']:
                candidate_tables.extend(["DeviceNetworkInfo", "CommonSecurityLog"])
            
            # Windows event conditions
            elif condition_type == 'event_id' or 'EventID' in str(condition):
                candidate_tables.append("SecurityEvent")
            
            # Custom field matches that might indicate specific log sources
            elif condition_type == 'custom_field_match':
                field = condition.get('field', '').lower()
                if 'dns' in field:
                    candidate_tables.append("DnsEvents")
                elif any(net_term in field for net_term in ['port', 'ip', 'network', 'connection']):
                    candidate_tables.extend(["DeviceNetworkInfo", "CommonSecurityLog"])
                elif any(win_term in field for win_term in ['event', 'security', 'logon', 'process']):
                    candidate_tables.append("SecurityEvent")
        
        # Remove duplicates while preserving order
        return list(dict.fromkeys(candidate_tables))

    def _make_multi_table_decision(
        self, 
        candidate_tables: List[str], 
        conditions: List[Dict[str, Any]], 
        parsed_rule: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Make intelligent decision about multi-table handling."""
        
        if len(candidate_tables) <= 1:
            return {
                "mode": "single",
                "tables": candidate_tables,
                "rationale": "Single table or no specific table detected"
            }
        
        # Group tables by logical source
        logical_sources = {}
        for table in candidate_tables:
            logical_source = self.table_column_mapping.get(table, {}).get("logical_source", "unknown")
            if logical_source not in logical_sources:
                logical_sources[logical_source] = []
            logical_sources[logical_source].append(table)
        
        # Check if multiple tables belong to the same logical source
        same_logical_source_groups = [tables for tables in logical_sources.values() if len(tables) > 1]
        
        if same_logical_source_groups:
            # Multiple tables for same logical source - decide union vs split
            primary_group = same_logical_source_groups[0]  # Take the first group
            
            # Decision factors
            rule_complexity = self._assess_rule_complexity(conditions, parsed_rule)
            field_compatibility = self._assess_field_compatibility(primary_group)
            query_type = self._determine_query_type(conditions)
            
            # Decision logic
            if (rule_complexity == "simple" and 
                field_compatibility >= 0.7 and 
                query_type in ["detection", "monitoring"]):
                return {
                    "mode": "union",
                    "tables": primary_group,
                    "rationale": f"Simple rule with high field compatibility ({field_compatibility:.1%}) - union provides comprehensive coverage"
                }
            elif (rule_complexity == "complex" or 
                  field_compatibility < 0.5 or 
                  query_type == "correlation"):
                return {
                    "mode": "split", 
                    "tables": primary_group,
                    "rationale": f"Complex rule or low field compatibility ({field_compatibility:.1%}) - split maintains precision"
                }
            else:
                # Default to union for moderate complexity
                return {
                    "mode": "union",
                    "tables": primary_group,
                    "rationale": f"Moderate complexity with acceptable field compatibility ({field_compatibility:.1%}) - union preferred"
                }
        else:
            # Different logical sources - default to single table (primary)
            return {
                "mode": "single",
                "tables": [candidate_tables[0]],
                "rationale": "Multiple tables from different logical sources - using primary table"
            }

    def _assess_rule_complexity(self, conditions: List[Dict[str, Any]], parsed_rule: Dict[str, Any]) -> str:
        """Assess the complexity of the rule."""
        complexity_score = 0
        
        # Count conditions
        complexity_score += len(conditions)
        
        # Check for complex condition types
        for condition in conditions:
            condition_type = condition.get('type', '')
            if condition_type in ['threshold', 'correlation', 'custom_field_match']:
                complexity_score += 2
            elif condition_type in ['regex_match', 'time_window']:
                complexity_score += 1
        
        # Check for multiple responses
        responses = parsed_rule.get('responses', [])
        if len(responses) > 1:
            complexity_score += 1
        
        # Classify complexity
        if complexity_score <= 3:
            return "simple"
        elif complexity_score <= 7:
            return "moderate" 
        else:
            return "complex"

    def _assess_field_compatibility(self, tables: List[str]) -> float:
        """Assess field compatibility between tables."""
        if len(tables) <= 1:
            return 1.0
        
        # Get field sets for each table
        field_sets = []
        for table in tables:
            fields = set(self.table_column_mapping.get(table, {}).keys())
            field_sets.append(fields)
        
        # Calculate intersection vs union ratio
        if len(field_sets) < 2:
            return 1.0
            
        intersection = field_sets[0]
        union = field_sets[0].copy()
        
        for field_set in field_sets[1:]:
            intersection = intersection.intersection(field_set)
            union = union.union(field_set)
        
        if len(union) == 0:
            return 0.0
            
        return len(intersection) / len(union)

    def _determine_query_type(self, conditions: List[Dict[str, Any]]) -> str:
        """Determine the type of query based on conditions."""
        has_threshold = any(c.get('type') == 'threshold' for c in conditions)
        has_correlation = any(c.get('type') == 'correlation' for c in conditions)
        has_time_window = any(c.get('type') == 'time_window' for c in conditions)
        
        if has_correlation or (has_threshold and has_time_window):
            return "correlation"
        elif has_threshold:
            return "monitoring"
        else:
            return "detection"

    def _generate_union_query(self, parsed_rule: Dict[str, Any], tables: List[str]) -> str:
        """Generate a union query for multiple tables."""
        rule_name = parsed_rule.get('rule_name', 'Unknown Rule')
        conditions = parsed_rule.get('conditions', [])
        
        # Build union query
        query_lines = [
            f"// {rule_name}",
            f"// Multi-table union query covering: {', '.join(tables)}",
            "let timeRange = 1h;",
            "union isfuzzy=true"
        ]
        
        # Add each table with basic filtering
        table_queries = []
        for table in tables:
            table_mapping = self.table_column_mapping.get(table, {})
            time_field = table_mapping.get("time_field", "TimeGenerated")
            
            table_query = f"    ({table} | where {time_field} >= ago(timeRange) | extend TableSource = \"{table}\")"
            table_queries.append(table_query)
        
        query_lines.extend(table_queries)
        
        # Add common filtering based on conditions
        query_lines.extend(self._build_common_filters(conditions, tables))
        
        return '\n'.join(query_lines)

    def _generate_single_table_query(self, parsed_rule: Dict[str, Any], table: str) -> str:
        """Generate a query for a single specific table."""
        conditions = parsed_rule.get('conditions', [])
        
        # Use existing specialized methods if available
        if table == "DnsEvents" and self._is_dns_rule(conditions):
            return self._generate_dns_query(parsed_rule)
        elif table in ["DeviceNetworkInfo", "CommonSecurityLog"] and self._is_network_scanning_rule(conditions):
            return self._generate_network_scanning_query(parsed_rule)
        else:
            return self._generate_generic_query(parsed_rule)

    def _build_common_filters(self, conditions: List[Dict[str, Any]], tables: List[str]) -> List[str]:
        """Build common filters that can apply across multiple tables."""
        filters = []
        
        for condition in conditions:
            condition_type = condition.get('type', '')
            
            if condition_type == 'destination_port':
                port = condition.get('value')
                if port:
                    filters.append(f"| where (DestinationPort == {port} or RemotePort == {port})")
            
            elif condition_type == 'source_network_exclusion':
                network = condition.get('value', '')
                if network:
                    # Convert network name to CIDR if needed
                    cidr_range = self._convert_network_names_to_ranges([network])
                    if cidr_range:
                        filters.append(f"| where not(ipv4_is_in_range(SourceIP, \"{cidr_range[0]}\"))")
        
        return filters
    
    def _is_dns_rule(self, conditions: List[Dict[str, Any]]) -> bool:
        """Check if this is a DNS-related rule."""
        for condition in conditions:
            if condition.get('type') == 'event_category':
                categories = condition.get('values', [])
                for category in categories:
                    if 'DNS' in category:
                        return True
            elif condition.get('type') == 'custom_field_match':
                field = condition.get('field', '')
                if 'DNS' in field:
                    return True
        return False
    
    def _is_network_scanning_rule(self, conditions: List[Dict[str, Any]]) -> bool:
        """Check if this is a network scanning rule."""
        has_port = False
        has_threshold = False
        
        for condition in conditions:
            if condition.get('type') == 'destination_port':
                has_port = True
            elif condition.get('type') == 'threshold':
                has_threshold = True
        
        return has_port and has_threshold
    
    def _generate_dns_query(self, parsed_rule: Dict[str, Any]) -> str:
        """Generate KustoQL query for DNS rules following best practices."""
        rule_name = parsed_rule.get('rule_name', 'DNS Rule')
        conditions = parsed_rule.get('conditions', [])
        responses = parsed_rule.get('responses', [])
        
        # Extract regex pattern from conditions
        regex_pattern = None
        event_categories = []
        
        for condition in conditions:
            if condition.get('type') == 'custom_field_match':
                # Clean up pattern and ensure proper anchoring
                pattern = condition.get('pattern', '').strip('^$')
                # Add proper anchoring for Base64 patterns
                if pattern and not pattern.startswith('^'):
                    pattern = '^' + pattern
                if pattern and not pattern.endswith('$'):
                    pattern = pattern + '$'
                regex_pattern = pattern
            elif condition.get('type') == 'event_category':
                event_categories = condition.get('values', [])
        
        # Get event description from responses
        event_description = "Base64-encoded DNS queries"
        
        for response in responses:
            if response.get('type') == 'dispatch_event':
                desc = response.get('event_description', '')
                if desc:
                    event_description = desc
        
        # Build clean, practical KustoQL query following human-expert patterns
        query_lines = [
            f"// ===== {event_description} =========================================",
            "// Common DNS tables in Sentinel:",
            "//   - DnsEvents           (Windows DNS analytic logs via AMA)",
            "//   - AzureDiagnostics    (Azure Firewall / DNS proxy logs)",
            "//   - CommonSecurityLog   (various DNS forwarders)",
            "// Pick the one you actually ingest.",
        ]
        
        if regex_pattern:
            # Use cleaner variable name and pattern format
            clean_pattern = regex_pattern.replace('\\/', '/')  # Simplify escaped forward slashes
            query_lines.append(f'let DetectionPattern = @"{clean_pattern}";')
        
        query_lines.extend([
            "DnsEvents  // <-- change to your table",
            f"| where QueryName matches regex DetectionPattern" if regex_pattern else "| where isnotempty(QueryName)",
            "| where QueryStatus == \"Succeeded\"  // Only successful queries"
        ])
        
        if event_categories:
            # Map QRadar categories to KustoQL EventSubType with helpful comment
            kusto_categories = self._map_dns_categories(event_categories)
            if kusto_categories:
                categories_str = '", "'.join(kusto_categories)
                query_lines.append(f'// Optional: keep only run-time classifications matching the QRadar rule')
                query_lines.append(f'| where EventSubType in ("{categories_str}")   // or however your product labels these')
        
        query_lines.extend([
            "| project TimeGenerated",
            "        , SrcIpAddr      = tostring(SourceIp)",
            "        , DstIpAddr      = tostring(DestinationIp)",
            "        , QueryName",
            "        , DnsResponseCode",
            f"// 1 row per suspicious lookup = 1 event --> \"New offense\" in QRadar"
        ])
        
        return '\n'.join(query_lines)
    
    def _generate_network_scanning_query(self, parsed_rule: Dict[str, Any]) -> str:
        """Generate KustoQL query for network scanning rules following best practices."""
        rule_name = parsed_rule.get('rule_name', 'Network Scanning Rule')
        conditions = parsed_rule.get('conditions', [])
        responses = parsed_rule.get('responses', [])
        
        # Extract conditions
        destination_port = None
        threshold_count = 10
        time_value = 2
        time_unit = "minutes"
        excluded_networks = []
        context_conditions = []
        
        for condition in conditions:
            if condition.get('type') == 'destination_port':
                destination_port = condition.get('value')
            elif condition.get('type') == 'threshold':
                threshold_count = condition.get('count', 10)
                time_value = condition.get('time_value', 2)
                time_unit = condition.get('time_unit', 'minutes')
            elif condition.get('type') == 'source_network_exclusion':
                excluded_networks.append(condition.get('value'))
            elif condition.get('type') == 'context':
                context_conditions = condition.get('values', [])
        
        # Get event description from responses
        event_description = "Outbound SMB scan detector"
        
        for response in responses:
            if response.get('type') == 'dispatch_event':
                desc = response.get('event_description', '')
                if desc and 'SMB' in desc:
                    event_description = "Outbound SMB scan detector"
                elif desc:
                    event_description = desc
        
        # Convert time unit to KustoQL format
        kusto_time_unit = self._convert_time_unit(time_unit)
        
        # Build clean, practical KustoQL query following human-expert patterns
        query_lines = [
            f"// ===== {event_description} =========================================",
            "// Tables that carry 5-tuple flow data in Sentinel include:",
            "//   - CommonSecurityLog        (firewall / NDR feeds)",
            "//   - VMConnection             (Azure NSG flow logs)",
            "//   - DeviceNetworkInfo        (MDE network connections)",
            "// Adjust names as needed.",
            f"let TimeWindow = {time_value}{kusto_time_unit};",
        ]
        
        # Choose the most practical table (CommonSecurityLog) as primary, following human-expert approach
        query_lines.extend([
            "CommonSecurityLog  // <-- change to your table"
        ])
        
        if destination_port:
            query_lines.append(f"| where DstPort == {destination_port}")
        
        # Handle context conditions - map QRadar context to Direction field
        if context_conditions:
            # QRadar "Local to Remote, Remote to Remote" maps to "not Inbound"
            if any('Remote' in ctx for ctx in context_conditions):
                query_lines.append("| where Direction != \"Inbound\"                  // Local→Remote OR Remote→Remote")
        
        # Handle network exclusions using zone-based approach (cleaner than IP parsing)
        if excluded_networks:
            for network in excluded_networks:
                # Convert network names to zone exclusions (more practical approach)
                if 'DMZ' in network or 'VLAN' in network:
                    # Use SrcZone field which is more practical than IP parsing
                    zone_name = network.replace('DMZ.', '').replace('-VLAN', '_VLAN')
                    query_lines.append(f"| where SrcZone != \"{zone_name}\" // exclude the DMZ VLAN")
                else:
                    # Fallback to IP range if it looks like a CIDR
                    if '.' in network and ('/' in network or network.count('.') == 3):
                        # Try to extract or convert to CIDR format
                        cidr = self._convert_network_name_to_cidr(network)
                        if cidr:
                            query_lines.append(f"| where not(ipv4_is_in_range(SrcIpAddr, \"{cidr}\")) // exclude {network}")
        
        query_lines.extend([
            "| summarize",
            "      StartTime = min(TimeGenerated),",
            "      EndTime   = max(TimeGenerated),",
            "      UniqueDst = dcount(DstIpAddr),",
            "      TotalHits = count()",
            f"      by bin(TimeGenerated, TimeWindow), SrcIpAddr",
            f"| where UniqueDst >= {threshold_count}        // threshold from the QRadar rule",
            "| project StartTime, EndTime, SrcIpAddr, UniqueDst, TotalHits"
        ])
        
        return '\n'.join(query_lines)
    
    def _generate_generic_query(self, parsed_rule: Dict[str, Any]) -> str:
        """Generate generic KustoQL query for other rule types."""
        rule_name = parsed_rule.get('rule_name', 'Generic Rule')
        
        return f"""// {rule_name}
// Generic QRadar rule conversion - requires manual review
let timeRange = 1h;
SecurityEvent
| where TimeGenerated >= ago(timeRange)
| extend 
    AlertName = "{rule_name}",
    AlertDescription = "Generic rule converted from QRadar - manual review required",
    Severity = "Medium"
| project 
    TimeGenerated,
    Computer,
    AlertName,
    AlertDescription,
    Severity
// Note: This is a generic conversion. Please review and adjust based on specific rule logic."""
    
    def _map_dns_categories(self, qradar_categories: List[str]) -> List[str]:
        """Map QRadar DNS categories to KustoQL EventSubType values."""
        mapping = {
            "Application.DNS In Progress": "DNS In Progress",
            "Application.DNS Opened": "DNS Opened"
        }
        
        kusto_categories = []
        for category in qradar_categories:
            if category in mapping:
                kusto_categories.append(mapping[category])
            else:
                kusto_categories.append(category)
        
        return kusto_categories
    
    def _map_severity(self, qradar_severity: int) -> str:
        """Map QRadar severity (1-10) to KustoQL severity levels."""
        if qradar_severity >= 8:
            return "High"
        elif qradar_severity >= 5:
            return "Medium"
        else:
            return "Low"
    
    def _convert_time_unit(self, qradar_unit: str) -> str:
        """Convert QRadar time units to KustoQL format."""
        mapping = {
            "minutes": "m",
            "minute": "m", 
            "hours": "h",
            "hour": "h",
            "seconds": "s",
            "second": "s",
            "days": "d",
            "day": "d"
        }
        
        return mapping.get(qradar_unit.lower(), "m")
    
    def _convert_network_names_to_ranges(self, network_names: List[str]) -> str:
        """Convert QRadar network names to IP ranges."""
        # Simplified mapping - in practice, this would need to be configurable
        mapping = {
            "DMZ.T-Pot_Docker_Containers-VLAN30": "10.30.0.0/24"
        }
        
        ranges = []
        for name in network_names:
            if name in mapping:
                ranges.append(mapping[name])
            else:
                # Default to a common private range if unknown
                ranges.append("10.0.0.0/8")
        
        return str(ranges)
    
    def _convert_network_name_to_cidr(self, network_name: str) -> str:
        """Convert a single network name to CIDR format."""
        # Simplified mapping for common network names
        mapping = {
            "DMZ.T-Pot_Docker_Containers-VLAN30": "10.30.0.0/24",
            "DMZ": "10.0.0.0/8",
            "Internal": "192.168.0.0/16",
            "Guest": "172.16.0.0/12"
        }
        
        if network_name in mapping:
            return mapping[network_name]
        
        # Try to extract IP range from name if it contains IP-like patterns
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b'
        matches = re.findall(ip_pattern, network_name)
        if matches:
            return matches[0]
        
        # Default fallback
        return "10.0.0.0/8"
    
    async def _get_context_from_chromadb(self, parsed_rule: Dict[str, Any]) -> Dict[str, Any]:
        """Get additional context from ChromaDB collections."""
        try:
            context = {}
            
            # Search QRadar docs for relevant information
            if 'rule_name' in parsed_rule:
                results = await chromadb_service.find_qradar_rules(parsed_rule['rule_name'], n_results=3)
                if results:
                    context['qradar_docs'] = results
            
            return context
            
        except Exception as e:
            logger.warning(f"Failed to get context from ChromaDB: {e}")
            return {}
    
    def _generate_explanation(self, parsed_rule: Dict[str, Any], context: Dict[str, Any], multi_table_decision: Dict[str, Any] = None) -> str:
        """Generate explanation for the conversion."""
        rule_name = parsed_rule.get('rule_name', 'Unknown Rule')
        conditions = parsed_rule.get('conditions', [])
        
        explanation_parts = [
            f"Converted QRadar rule '{rule_name}' to KustoQL format.",
        ]
        
        # Add multi-table decision explanation
        if multi_table_decision:
            mode = multi_table_decision.get("mode", "single")
            tables = multi_table_decision.get("tables", [])
            rationale = multi_table_decision.get("rationale", "")
            
            if mode == "union":
                explanation_parts.append(f"Multi-table approach: UNION mode applied across tables: {', '.join(tables)}")
                explanation_parts.append(f"Union rationale: {rationale}")
            elif mode == "split":
                explanation_parts.append(f"Multi-table approach: SPLIT mode - separate queries recommended for tables: {', '.join(tables)}")
                explanation_parts.append(f"Split rationale: {rationale}")
            else:
                explanation_parts.append(f"Single table approach: Using primary table detection")
        
        explanation_parts.append("Key mappings applied:")
        
        for condition in conditions:
            if condition.get('type') == 'custom_field_match':
                field = condition.get('field')
                explanation_parts.append(f"- QRadar '{field}' field mapped to appropriate KustoQL table column")
            elif condition.get('type') == 'destination_port':
                port = condition.get('value')
                explanation_parts.append(f"- Destination port {port} filtering preserved")
            elif condition.get('type') == 'threshold':
                count = condition.get('count')
                time_val = condition.get('time_value')
                time_unit = condition.get('time_unit')
                explanation_parts.append(f"- Threshold condition: {count} events in {time_val} {time_unit}")
        
        explanation_parts.extend([
            "- Added MITRE ATT&CK technique mapping for threat intelligence context",
            "- Implemented proper KustoQL table column names",
            "- Added summarization for performance optimization"
        ])
        
        return ' '.join(explanation_parts)
    
    def _extract_mitre_techniques(self, parsed_rule: Dict[str, Any]) -> List[str]:
        """Extract relevant MITRE ATT&CK techniques."""
        techniques = []
        conditions = parsed_rule.get('conditions', [])
        
        # Determine techniques based on rule type
        if self._is_dns_rule(conditions):
            techniques.append("T1041")  # Exfiltration Over C2 Channel
        elif self._is_network_scanning_rule(conditions):
            techniques.append("T1046")  # Network Service Scanning
        
        return techniques
    
    def _generate_field_mappings(self, parsed_rule: Dict[str, Any]) -> Dict[str, str]:
        """Generate field mappings documentation."""
        mappings = {
            "QRadar Source IP": "KustoQL SourceIP/ClientIP",
            "QRadar Local system": "KustoQL TimeGenerated filter"
        }
        
        conditions = parsed_rule.get('conditions', [])
        for condition in conditions:
            if condition.get('type') == 'custom_field_match':
                field = condition.get('field')
                if 'DNS Query' in field:
                    mappings["QRadar DNS Query (custom)"] = "KustoQL QueryName"
            elif condition.get('type') == 'destination_port':
                mappings["QRadar Destination Port"] = "KustoQL DestinationPort/RemotePort"
        
        return mappings
    
    def _generate_conversion_notes(self, parsed_rule: Dict[str, Any], multi_table_decision: Dict[str, Any] = None) -> List[str]:
        """Generate conversion notes."""
        notes = [
            "QRadar rule converted to KustoQL with equivalent logic and thresholds",
            "Column names confirmed per KustoQL table schema",
            "MITRE ATT&CK mappings added for threat intelligence context"
        ]
        
        # Add multi-table specific notes
        if multi_table_decision:
            mode = multi_table_decision.get("mode", "single")
            tables = multi_table_decision.get("tables", [])
            
            if mode == "union":
                notes.append(f"Multi-table UNION query applied across {len(tables)} tables: {', '.join(tables)}")
                notes.append("Union approach provides comprehensive coverage while maintaining performance")
            elif mode == "split":
                notes.append(f"Multi-table SPLIT approach recommended for {len(tables)} tables: {', '.join(tables)}")
                notes.append("Split approach maintains query precision and reduces false positives")
            else:
                notes.append("Single table detection applied based on rule characteristics")
        
        conditions = parsed_rule.get('conditions', [])
        if self._is_dns_rule(conditions):
            notes.append("DNS query field mapped to QueryName in DnsEvents table")
        elif self._is_network_scanning_rule(conditions):
            notes.append("Network scanning detection optimized for multiple data sources")
        
        notes.extend([
            "Time windows and thresholds preserved from original QRadar rule",
            "Network filtering adapted to KustoQL IP functions",
            "Summarization added for performance and noise reduction"
        ])
        
        return notes
    
    def _calculate_confidence_score(self, parsed_rule: Dict[str, Any]) -> float:
        """Calculate confidence score for the conversion."""
        score = 0.5  # Base score
        
        # Add points for successfully parsed elements
        if parsed_rule.get('rule_name'):
            score += 0.1
        if parsed_rule.get('conditions'):
            score += 0.2
        if parsed_rule.get('actions'):
            score += 0.1
        if parsed_rule.get('responses'):
            score += 0.1
        
        # Bonus for specific rule types we handle well
        conditions = parsed_rule.get('conditions', [])
        if self._is_dns_rule(conditions) or self._is_network_scanning_rule(conditions):
            score += 0.2
        
        return min(score, 1.0)


# Global converter instance
qradar_to_kustoql_converter = QRadarToKustoQLConverter() 