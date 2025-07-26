"""
Enhanced LLM service that wraps the unified LLM service with additional functionality.
"""

import asyncio
from typing import Dict, Any, Optional, Union
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
        context: Union[str, Dict[str, Any]] = "",
        max_retries: int = 2
    ) -> Dict[str, Any]:
        """Convert a rule with retry logic and enhanced context."""
        for attempt in range(max_retries + 1):
            try:
                # Convert target format string to enum
                target_fmt = TargetFormat(target_format)
                
                # Handle context format - convert dict to string if needed
                context_str = context
                if isinstance(context, dict):
                    # Convert dict context to string format
                    context_parts = []
                    for key, value in context.items():
                        if value:  # Only include non-empty values
                            context_parts.append(f"{key}: {value}")
                    context_str = "\n".join(context_parts)
                
                # Use the unified conversion method
                result = await self.llm_service.convert_rule(
                    source_rule=source_rule,
                    source_format=source_format,
                    target_format=target_fmt,
                    context=context_str
                )
                
                # Extract and validate target rule
                target_rule = self._extract_target_rule(result, target_format)
                
                # Apply post-processing corrections for KustoQL
                if target_format.lower() == "kustoql":
                    target_rule = self._fix_kustoql_rule(target_rule, source_rule)
                
                # Standardize response format
                return {
                    "success": True,
                    "target_rule": target_rule,
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
    
    def _fix_kustoql_rule(self, rule: str, source_rule: str) -> str:
        """Apply intelligent post-processing improvements to KustoQL rules."""
        if not rule:
            return rule
            
        logger.info(f"Post-processing KustoQL rule: {rule}")
        
        import re
        
        # 1. Fix string literal formatting (universal improvement)
        rule = self._fix_string_literals(rule)
        
        # 2. Add performance optimizations (universal improvement)
        rule = self._add_performance_optimizations(rule)
        
        # 3. Enhance case sensitivity handling (universal improvement)
        rule = self._improve_case_sensitivity(rule)
        
        # 4. Validate table names (universal improvement)
        rule = self._validate_table_names(rule)
        
        # 5. Fix field calculations (universal improvement)
        rule = self._fix_field_calculations(rule)
        
        # 6. Detect union patterns for complex queries (universal improvement)
        rule = self._optimize_union_patterns(rule, source_rule)
        
        # 7. Optimize field selections (universal improvement)
        rule = self._optimize_field_selection(rule)
        
        fixed_rule = rule.strip()
        logger.info(f"Post-processed result: {fixed_rule}")
        return fixed_rule
    
    def _fix_string_literals(self, rule: str) -> str:
        """Fix string literal formatting across all KustoQL queries."""
        import re
        # Replace single quotes with double quotes for string literals
        patterns = [
            (r"== '([^']*)'", r'== "\1"'),
            (r"!= '([^']*)'", r'!= "\1"'),
            (r"contains '([^']*)'", r'contains "\1"'),
            (r"startswith '([^']*)'", r'startswith "\1"'),
            (r"endswith '([^']*)'", r'endswith "\1"'),
            (r"in \('([^']*)'", r'in ("\1"'),
            (r"=~ '([^']*)'", r'=~ "\1"'),
        ]
        
        for pattern, replacement in patterns:
            rule = re.sub(pattern, replacement, rule)
        return rule
    
    def _add_performance_optimizations(self, rule: str) -> str:
        """Add time filtering and other performance optimizations."""
        import re
        
        # Check if time filtering already exists
        if "TimeGenerated" in rule and "ago(" in rule:
            return rule
            
        # Add time filtering for performance
        if re.match(r'^\s*\w+\s*\|', rule):  # Starts with table name
            # Insert time filter after first table reference
            rule = re.sub(
                r'^(\s*\w+)\s*\|',
                r'\1\n| where TimeGenerated >= ago(1h)\n|',
                rule
            )
        
        return rule
    
    def _improve_case_sensitivity(self, rule: str) -> str:
        """Improve case sensitivity handling for string comparisons."""
        import re
        
        # Common values that should use case-insensitive matching
        case_insensitive_values = ['tcp', 'udp', 'http', 'https', 'dns', 'icmp']
        
        for value in case_insensitive_values:
            # Replace == with =~ for these common protocol/service values
            rule = re.sub(
                rf'== "{value.upper()}"',
                f'=~ "{value.lower()}"',
                rule,
                flags=re.IGNORECASE
            )
            rule = re.sub(
                rf'== "{value.lower()}"',
                f'=~ "{value.lower()}"',
                rule
            )
        
        return rule
    
    def _validate_table_names(self, rule: str) -> str:
        """Validate and fix table names to use only standard Azure Sentinel tables."""
        import re
        
        # Define standard Azure Sentinel tables
        standard_tables = {
            'CommonSecurityLog', 'SecurityEvent', 'Syslog', 'DnsEvents', 
            'AzureDiagnostics', 'NetworkAccessTraffic', 'W3CIISLog', 
            'VMConnection', 'Heartbeat'
        }
        
        # Define invalid table mappings to valid ones
        invalid_table_mappings = {
            'NetworkConnections': 'VMConnection',  # Standard connection table
            'NetworkTraffic': 'CommonSecurityLog',  # Network logs go here
            'Network': 'CommonSecurityLog',  # Generic network to CSL
            'Events': 'SecurityEvent',  # Generic events
            'Logs': 'Syslog',  # Generic logs
        }
        
        # Replace invalid table names
        for invalid, valid in invalid_table_mappings.items():
            # Match table name at start of line or after whitespace, followed by pipe
            pattern = rf'\b{invalid}\b(?=\s*\|)'
            if re.search(pattern, rule):
                rule = re.sub(pattern, valid, rule)
                logger.info(f"Replaced invalid table '{invalid}' with '{valid}'")
        
        return rule
    
    def _fix_field_calculations(self, rule: str) -> str:
        """Fix field calculations for missing or non-standard fields."""
        import re
        
        # Define table-specific field calculation patterns
        table_field_calculations = {
            'CommonSecurityLog': {
                'TotalBytes': 'BytesReceived + BytesSent',
                'BytesTransferred': 'SentBytes + ReceivedBytes', 
                'TotalPackets': 'PacketsReceived + PacketsSent',
            },
            'DnsEvents': {
                'TotalBytes': 'tolong(0)',  # DNS events don't typically have byte counts
                'ResponseSize': 'ResultDataSize',
            },
            'SecurityEvent': {
                'Duration': 'TimeGenerated - TimeCreated',
                'FullUserName': 'strcat(Domain, "\\\\", Account)',
            }
        }
        
        # Detect which table is being used
        table_match = re.search(r'\b(CommonSecurityLog|SecurityEvent|DnsEvents|Syslog|VMConnection)\b', rule)
        if not table_match:
            return rule  # No recognized table found
            
        table_name = table_match.group(1)
        field_calculations = table_field_calculations.get(table_name, {})
        
        # Check if we need to add calculated fields
        for calc_field, calculation in field_calculations.items():
            # If the field is used in conditions but not available in the table
            if re.search(rf'\b{calc_field}\b', rule) and f'{calc_field}=' not in rule:
                logger.info(f"Adding field calculation: {calc_field} = {calculation}")
                
                # Check if we're in a union context that needs projection
                if 'union' in rule.lower() and 'project' in rule.lower():
                    # Add calculated field to existing project statements
                    rule = re.sub(
                        rf'(project\s+[^|]*)',
                        rf'\1, {calc_field}={calculation}',
                        rule
                    )
                else:
                    # Add extend statement for calculation before where clauses that use the field
                    if re.search(rf'\| where.*\b{calc_field}\b', rule):
                        # Insert extend before the where clause that uses this field
                        rule = re.sub(
                            rf'(\| where.*\b{calc_field}\b[^|]*)',
                            rf'| extend {calc_field} = {calculation}\n\1',
                            rule,
                            count=1
                        )
                    elif '| project' in rule:
                        # Insert extend before project
                        rule = re.sub(
                            r'(\| project)',
                            rf'| extend {calc_field} = {calculation}\n\1',
                            rule,
                            count=1
                        )
        
        return rule
    
    def _optimize_union_patterns(self, rule: str, source_rule: str) -> str:
        """Detect when union patterns would be better than joins or separate queries."""
        import re
        
        # Check if source rule has multiple event.dataset or event.category patterns (simplified detection)
        has_multiple_datasets = source_rule.lower().count('event.dataset:') > 1 or ('event.dataset:' in source_rule.lower() and ' or ' in source_rule.lower())
        has_multiple_categories = source_rule.lower().count('event.category:') > 1 or ('event.category:' in source_rule.lower() and ' or ' in source_rule.lower())
        has_network_bytes = 'network.bytes' in source_rule.lower()
        has_join = 'join' in rule.lower()
        
        logger.info(f"Union pattern analysis - datasets: {has_multiple_datasets}, categories: {has_multiple_categories}, network_bytes: {has_network_bytes}, has_join: {has_join}")
        logger.info(f"Source rule: {source_rule[:100]}...")
        logger.info(f"Current rule: {rule[:100]}...")
        
        # If current rule uses join but source suggests union pattern, fix it
        if ('join' in rule.lower() and (has_multiple_datasets or has_multiple_categories)):
            logger.info("Complex query detected - converting join to union pattern")
            rule = self._convert_join_to_union(rule, source_rule)
            
        # If rule has undefined field calculations, fix them
        if has_network_bytes and 'network.bytes' in rule:
            logger.info("Fixing network.bytes usage - converting to proper TotalBytes calculation")
            rule = self._fix_network_bytes_field(rule)
            
        return rule
    
    def _convert_join_to_union(self, rule: str, source_rule: str) -> str:
        """Convert join patterns to union patterns for better performance and accuracy."""
        import re
        
        # Detect any join pattern (more comprehensive)
        has_join = 'join' in rule.lower() and ('DnsEvents' in rule or 'CommonSecurityLog' in rule)
        
        if has_join:
            logger.info("Converting join pattern to optimized union pattern")
            
            # Create the standardized union pattern for network traffic queries
            union_replacement = """let network_traffic = 
    union isfuzzy=true
        (DnsEvents 
        | where TimeGenerated >= ago(1h)
        | project TimeGenerated, EventType="dns", EventCategory="network", 
                 DestinationPort=53, TotalBytes=tolong(0)),
        (CommonSecurityLog 
        | where TimeGenerated >= ago(1h)
        | project TimeGenerated, EventType=DeviceEventClassID, 
                 EventCategory=DeviceEventCategory, DestinationPort, 
                 TotalBytes=BytesReceived + BytesSent);
network_traffic
| where (EventType == "network_traffic.dns" or (EventCategory in ("network", "network_traffic") and DestinationPort == 53))
| where EventType in ("zeek.dns", "dns", "connection")
| where TotalBytes > 60000"""
            
            return union_replacement
        
        return rule
    
    def _fix_network_bytes_field(self, rule: str) -> str:
        """Fix usage of undefined network.bytes field."""
        import re
        
        # Replace network.bytes with proper calculation
        rule = re.sub(r'\bnetwork\.bytes\b', '(BytesReceived + BytesSent)', rule)
        return rule
    
    def _optimize_field_selection(self, rule: str) -> str:
        """Add intelligent field selection if missing."""
        import re
        
        # If no project statement exists, add one with relevant fields
        if "| project" not in rule.lower():
            # Detect what fields might be relevant based on conditions
            relevant_fields = ["TimeGenerated"]
            
            field_patterns = {
                r'\bSourceIP\b': "SourceIP",
                r'\bDestinationIP\b': "DestinationIP", 
                r'\bSourcePort\b': "SourcePort",
                r'\bDestinationPort\b': "DestinationPort",
                r'\bProtocol\b': "Protocol",
                r'\bProcess\b': "Process",
                r'\bAccount\b': "Account",
                r'\bComputer\b': "Computer",
                r'\bEventID\b': "EventID",
            }
            
            for pattern, field in field_patterns.items():
                if re.search(pattern, rule):
                    relevant_fields.append(field)
            
            # Add project statement if we found relevant fields
            if len(relevant_fields) > 1:
                project_clause = f"| project {', '.join(relevant_fields)}"
                rule = rule + "\n" + project_clause
                
        return rule
    
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