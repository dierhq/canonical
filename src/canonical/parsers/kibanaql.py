"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Kibana Query Language (KQL) rule parser for extracting and analyzing rule components.
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from loguru import logger

from ..core.models import KibanaQLRule


class KibanaQLParser:
    """Parser for Kibana Query Language (KQL) rules."""
    
    def __init__(self):
        """Initialize the KibanaQL parser."""
        self.field_patterns = {
            "rule_id": r"(?:rule_id|id|_id):\s*(.+)",
            "name": r"(?:name|title|rule_name):\s*(.+)",
            "description": r"(?:description|desc):\s*(.+)",
            "query": r"(?:query|kql|search):\s*(.+)",
            "index_patterns": r"(?:index_patterns|indices|index):\s*(.+)",
            "query_type": r"(?:query_type|type):\s*(.+)",
            "language": r"(?:language|lang):\s*(.+)",
            "enabled": r"(?:enabled|active):\s*(.+)",
            "severity": r"(?:severity|level):\s*(.+)",
            "risk_score": r"(?:risk_score|score):\s*(\d+)",
            "tags": r"(?:tags|labels):\s*(.+)",
            "interval": r"(?:interval|schedule):\s*(.+)",
            "from_time": r"(?:from|from_time):\s*(.+)",
            "to_time": r"(?:to|to_time):\s*(.+)",
            "threshold_field": r"(?:threshold_field|threshold_on):\s*(.+)",
            "threshold_value": r"(?:threshold_value|threshold):\s*(\d+)",
            "author": r"(?:author|created_by):\s*(.+)",
            "version": r"(?:version|ver):\s*(.+)",
            "license": r"(?:license|licence):\s*(.+)",
            "references": r"(?:references|refs):\s*(.+)",
            "false_positives": r"(?:false_positives|fp):\s*(.+)",
        }
        
        # Common KQL operators and patterns
        self.kql_operators = {
            "and", "or", "not", "exists", "match", "wildcard", "range", "term", "terms",
            "regexp", "fuzzy", "prefix", "match_phrase", "match_phrase_prefix", "bool",
            "must", "must_not", "should", "filter"
        }
        
        # Common field patterns in KQL
        self.field_patterns_kql = {
            "process": r"(?:process\.name|process\.executable|process\.command_line)",
            "file": r"(?:file\.name|file\.path|file\.extension)",
            "network": r"(?:network\.protocol|source\.ip|destination\.ip|source\.port|destination\.port)",
            "user": r"(?:user\.name|user\.domain|user\.id)",
            "host": r"(?:host\.name|host\.hostname|host\.ip)",
            "event": r"(?:event\.action|event\.category|event\.type|event\.code)",
            "winlog": r"(?:winlog\.event_id|winlog\.channel|winlog\.provider_name)",
        }
    
    def parse_rule(self, rule_content: str) -> KibanaQLRule:
        """Parse a KibanaQL rule from various formats.
        
        Args:
            rule_content: Content of the KibanaQL rule (JSON, YAML, or plain text)
            
        Returns:
            Parsed KibanaQLRule object
            
        Raises:
            ValueError: If the rule content is invalid
        """
        try:
            # Try to parse as JSON first (most common format for Kibana rules)
            if rule_content.strip().startswith('{'):
                return self._parse_json_rule(rule_content)
            
            # Try to parse as YAML
            elif any(line.strip().endswith(':') for line in rule_content.split('\n')[:5]):
                return self._parse_yaml_rule(rule_content)
            
            # Parse as plain text/configuration format
            else:
                return self._parse_text_rule(rule_content)
                
        except Exception as e:
            logger.error(f"Failed to parse KibanaQL rule: {e}")
            raise ValueError(f"Invalid KibanaQL rule format: {e}")
    
    def _parse_json_rule(self, rule_content: str) -> KibanaQLRule:
        """Parse a JSON-formatted KibanaQL rule."""
        try:
            rule_dict = json.loads(rule_content)
            
            # Extract required fields
            name = rule_dict.get("name") or rule_dict.get("title") or "Unnamed Rule"
            query = rule_dict.get("query") or rule_dict.get("kql") or rule_dict.get("search", "")
            
            if not query:
                raise ValueError("Rule must have a query field")
            
            # Create KibanaQLRule object
            kibana_rule = KibanaQLRule(
                rule_id=rule_dict.get("rule_id") or rule_dict.get("id"),
                name=name,
                description=rule_dict.get("description"),
                query=query,
                index_patterns=self._parse_list_field(rule_dict.get("index_patterns", [])),
                query_type=rule_dict.get("query_type", "query"),
                language=rule_dict.get("language", "kuery"),
                enabled=rule_dict.get("enabled", True),
                severity=rule_dict.get("severity", "medium"),
                risk_score=rule_dict.get("risk_score"),
                tags=self._parse_list_field(rule_dict.get("tags", [])),
                interval=rule_dict.get("interval"),
                from_time=rule_dict.get("from") or rule_dict.get("from_time"),
                to_time=rule_dict.get("to") or rule_dict.get("to_time"),
                threshold_field=rule_dict.get("threshold_field"),
                threshold_value=rule_dict.get("threshold_value"),
                threshold_cardinality=rule_dict.get("threshold_cardinality"),
                anomaly_threshold=rule_dict.get("anomaly_threshold"),
                machine_learning_job_id=rule_dict.get("machine_learning_job_id"),
                actions=rule_dict.get("actions", []),
                throttle=rule_dict.get("throttle"),
                author=rule_dict.get("author"),
                created_date=rule_dict.get("created_date") or rule_dict.get("created_at"),
                last_modified=rule_dict.get("last_modified") or rule_dict.get("updated_at"),
                version=rule_dict.get("version"),
                license=rule_dict.get("license"),
                references=self._parse_list_field(rule_dict.get("references", [])),
                false_positives=self._parse_list_field(rule_dict.get("false_positives", [])),
                threat=rule_dict.get("threat", [])
            )
            
            return kibana_rule
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")
    
    def _parse_yaml_rule(self, rule_content: str) -> KibanaQLRule:
        """Parse a YAML-formatted KibanaQL rule."""
        import yaml
        
        try:
            rule_dict = yaml.safe_load(rule_content)
            
            if not isinstance(rule_dict, dict):
                raise ValueError("Rule content must be a YAML dictionary")
            
            # Extract required fields
            name = rule_dict.get("name") or rule_dict.get("title") or "Unnamed Rule"
            query = rule_dict.get("query") or rule_dict.get("kql") or rule_dict.get("search", "")
            
            if not query:
                raise ValueError("Rule must have a query field")
            
            # Create KibanaQLRule object (similar to JSON parsing)
            kibana_rule = KibanaQLRule(
                rule_id=rule_dict.get("rule_id") or rule_dict.get("id"),
                name=name,
                description=rule_dict.get("description"),
                query=query,
                index_patterns=self._parse_list_field(rule_dict.get("index_patterns", [])),
                query_type=rule_dict.get("query_type", "query"),
                language=rule_dict.get("language", "kuery"),
                enabled=rule_dict.get("enabled", True),
                severity=rule_dict.get("severity", "medium"),
                risk_score=rule_dict.get("risk_score"),
                tags=self._parse_list_field(rule_dict.get("tags", [])),
                interval=rule_dict.get("interval"),
                from_time=rule_dict.get("from") or rule_dict.get("from_time"),
                to_time=rule_dict.get("to") or rule_dict.get("to_time"),
                threshold_field=rule_dict.get("threshold_field"),
                threshold_value=rule_dict.get("threshold_value"),
                threshold_cardinality=rule_dict.get("threshold_cardinality"),
                anomaly_threshold=rule_dict.get("anomaly_threshold"),
                machine_learning_job_id=rule_dict.get("machine_learning_job_id"),
                actions=rule_dict.get("actions", []),
                throttle=rule_dict.get("throttle"),
                author=rule_dict.get("author"),
                created_date=rule_dict.get("created_date") or rule_dict.get("created_at"),
                last_modified=rule_dict.get("last_modified") or rule_dict.get("updated_at"),
                version=rule_dict.get("version"),
                license=rule_dict.get("license"),
                references=self._parse_list_field(rule_dict.get("references", [])),
                false_positives=self._parse_list_field(rule_dict.get("false_positives", [])),
                threat=rule_dict.get("threat", [])
            )
            
            return kibana_rule
            
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {e}")
    
    def _parse_text_rule(self, rule_content: str) -> KibanaQLRule:
        """Parse a plain text KibanaQL rule."""
        metadata = self._extract_metadata(rule_content)
        
        # Extract the main query from the text
        query = self._extract_query(rule_content)
        
        if not query:
            raise ValueError("Could not extract query from rule content")
        
        # Create KibanaQLRule object
        kibana_rule = KibanaQLRule(
            rule_id=metadata.get("rule_id"),
            name=metadata.get("name", "Unnamed Rule"),
            description=metadata.get("description"),
            query=query,
            index_patterns=self._parse_list_field(metadata.get("index_patterns", [])),
            query_type=metadata.get("query_type", "query"),
            language=metadata.get("language", "kuery"),
            enabled=self._parse_bool(metadata.get("enabled", "true")),
            severity=metadata.get("severity", "medium"),
            risk_score=self._parse_int(metadata.get("risk_score")),
            tags=self._parse_list_field(metadata.get("tags", [])),
            interval=metadata.get("interval"),
            from_time=metadata.get("from_time"),
            to_time=metadata.get("to_time"),
            threshold_field=metadata.get("threshold_field"),
            threshold_value=self._parse_int(metadata.get("threshold_value")),
            author=metadata.get("author"),
            version=metadata.get("version"),
            license=metadata.get("license"),
            references=self._parse_list_field(metadata.get("references", [])),
            false_positives=self._parse_list_field(metadata.get("false_positives", []))
        )
        
        return kibana_rule
    
    def _extract_metadata(self, rule_content: str) -> Dict[str, Any]:
        """Extract metadata from rule content using regex patterns."""
        metadata = {}
        
        for field, pattern in self.field_patterns.items():
            match = re.search(pattern, rule_content, re.IGNORECASE | re.MULTILINE)
            if match:
                metadata[field] = match.group(1).strip()
        
        return metadata
    
    def _extract_query(self, rule_content: str) -> str:
        """Extract the main query from rule content."""
        # Look for common query patterns
        query_patterns = [
            r"(?:query|kql|search):\s*(.+?)(?:\n|$)",
            r"GET\s+[^/]+/[^/]+/_search\s*\{(.+?)\}",
            r"\{[^}]*\"query\"[^}]*:(.+?)\}",
            # If no explicit query marker, try to identify KQL-like content
            r"([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*.+)",
        ]
        
        for pattern in query_patterns:
            match = re.search(pattern, rule_content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if match:
                query = match.group(1).strip()
                # Clean up the query
                query = re.sub(r'^["\']|["\']$', '', query)  # Remove quotes
                query = re.sub(r'\\n', '\n', query)  # Unescape newlines
                return query
        
        # If no specific query found, return the entire content as query
        return rule_content.strip()
    
    def _parse_list_field(self, field_value: Any) -> List[str]:
        """Parse a field that should be a list."""
        if isinstance(field_value, list):
            return [str(item) for item in field_value]
        elif isinstance(field_value, str):
            # Try to parse as JSON array
            try:
                parsed = json.loads(field_value)
                if isinstance(parsed, list):
                    return [str(item) for item in parsed]
            except json.JSONDecodeError:
                pass
            # Split by comma if it looks like a comma-separated list
            if ',' in field_value:
                return [item.strip() for item in field_value.split(',')]
            else:
                return [field_value]
        elif field_value is None:
            return []
        else:
            return [str(field_value)]
    
    def _parse_bool(self, value: Any) -> bool:
        """Parse a boolean value."""
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            return value.lower() in ('true', '1', 'yes', 'on', 'enabled')
        else:
            return bool(value)
    
    def _parse_int(self, value: Any) -> Optional[int]:
        """Parse an integer value."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
    
    def extract_mitre_techniques(self, rule: KibanaQLRule) -> List[str]:
        """Extract MITRE ATT&CK techniques from the rule."""
        techniques = []
        
        # Extract from threat field
        for threat_item in rule.threat:
            if isinstance(threat_item, dict):
                technique = threat_item.get("technique", {})
                if isinstance(technique, dict):
                    technique_id = technique.get("id")
                    if technique_id:
                        techniques.append(technique_id)
                elif isinstance(technique, str):
                    techniques.append(technique)
        
        # Extract from tags
        for tag in rule.tags:
            if re.match(r'^T\d{4}(\.\d{3})?$', tag):
                techniques.append(tag)
        
        # Extract from query and description using regex
        content = f"{rule.query} {rule.description or ''}"
        technique_pattern = r'T\d{4}(?:\.\d{3})?'
        found_techniques = re.findall(technique_pattern, content, re.IGNORECASE)
        techniques.extend(found_techniques)
        
        return list(set(techniques))
    
    def analyze_rule_complexity(self, rule: KibanaQLRule) -> Dict[str, Any]:
        """Analyze the complexity of a KibanaQL rule."""
        complexity_score = 0
        factors = []
        
        # Query complexity
        query_length = len(rule.query)
        if query_length > 500:
            complexity_score += 3
            factors.append("Long query")
        elif query_length > 200:
            complexity_score += 2
            factors.append("Medium query length")
        elif query_length > 100:
            complexity_score += 1
            factors.append("Short query")
        
        # Operator complexity
        operators_used = [op for op in self.kql_operators if op in rule.query.lower()]
        if len(operators_used) > 5:
            complexity_score += 3
            factors.append("Many operators")
        elif len(operators_used) > 3:
            complexity_score += 2
            factors.append("Multiple operators")
        elif len(operators_used) > 1:
            complexity_score += 1
            factors.append("Few operators")
        
        # Field complexity
        field_count = len(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*', rule.query))
        if field_count > 10:
            complexity_score += 3
            factors.append("Many fields")
        elif field_count > 5:
            complexity_score += 2
            factors.append("Multiple fields")
        elif field_count > 2:
            complexity_score += 1
            factors.append("Few fields")
        
        # Threshold rules add complexity
        if rule.query_type == "threshold":
            complexity_score += 2
            factors.append("Threshold rule")
        
        # ML rules add complexity
        if rule.query_type == "machine_learning":
            complexity_score += 3
            factors.append("Machine learning rule")
        
        # EQL rules add complexity
        if rule.language == "eql":
            complexity_score += 2
            factors.append("EQL query")
        
        # Index patterns complexity
        if len(rule.index_patterns) > 5:
            complexity_score += 2
            factors.append("Many index patterns")
        elif len(rule.index_patterns) > 2:
            complexity_score += 1
            factors.append("Multiple index patterns")
        
        return {
            "score": complexity_score,
            "level": self._get_complexity_level(complexity_score),
            "factors": factors,
            "operators_used": operators_used,
            "field_count": field_count,
            "query_length": query_length
        }
    
    def _get_complexity_level(self, score: float) -> str:
        """Determine complexity level based on score."""
        if score >= 10:
            return "very_high"
        elif score >= 7:
            return "high"
        elif score >= 4:
            return "medium"
        elif score >= 2:
            return "low"
        else:
            return "very_low"
    
    def extract_rule_summary(self, rule: KibanaQLRule) -> str:
        """Extract a summary of the rule for context."""
        summary_parts = []
        
        # Basic info
        summary_parts.append(f"Rule: {rule.name}")
        if rule.description:
            summary_parts.append(f"Description: {rule.description}")
        
        # Query type and language
        summary_parts.append(f"Type: {rule.query_type} ({rule.language})")
        
        # Severity and risk
        summary_parts.append(f"Severity: {rule.severity}")
        if rule.risk_score:
            summary_parts.append(f"Risk Score: {rule.risk_score}")
        
        # Index patterns
        if rule.index_patterns:
            summary_parts.append(f"Indices: {', '.join(rule.index_patterns)}")
        
        # Tags
        if rule.tags:
            summary_parts.append(f"Tags: {', '.join(rule.tags)}")
        
        # MITRE techniques
        if rule.mitre_techniques:
            summary_parts.append(f"MITRE: {', '.join(rule.mitre_techniques)}")
        
        # Query preview (first 100 chars)
        query_preview = rule.query[:100] + "..." if len(rule.query) > 100 else rule.query
        summary_parts.append(f"Query: {query_preview}")
        
        return "\n".join(summary_parts)
    
    def validate_rule(self, rule: KibanaQLRule) -> Tuple[bool, List[str]]:
        """Validate a KibanaQL rule."""
        errors = []
        
        # Required fields
        if not rule.name:
            errors.append("Rule name is required")
        
        if not rule.query:
            errors.append("Query is required")
        
        # Validate query syntax (basic checks)
        if rule.language == "kuery":
            if not self._validate_kuery_syntax(rule.query):
                errors.append("Invalid KQL syntax")
        elif rule.language == "lucene":
            if not self._validate_lucene_syntax(rule.query):
                errors.append("Invalid Lucene syntax")
        elif rule.language == "eql":
            if not self._validate_eql_syntax(rule.query):
                errors.append("Invalid EQL syntax")
        
        # Validate severity
        valid_severities = ["low", "medium", "high", "critical"]
        if rule.severity not in valid_severities:
            errors.append(f"Invalid severity: {rule.severity}. Must be one of {valid_severities}")
        
        # Validate risk score
        if rule.risk_score is not None and (rule.risk_score < 0 or rule.risk_score > 100):
            errors.append("Risk score must be between 0 and 100")
        
        # Validate query type
        valid_query_types = ["query", "eql", "threshold", "machine_learning"]
        if rule.query_type not in valid_query_types:
            errors.append(f"Invalid query type: {rule.query_type}. Must be one of {valid_query_types}")
        
        # Validate threshold settings
        if rule.query_type == "threshold":
            if not rule.threshold_field:
                errors.append("Threshold rules require a threshold_field")
            if rule.threshold_value is None:
                errors.append("Threshold rules require a threshold_value")
        
        # Validate ML settings
        if rule.query_type == "machine_learning":
            if not rule.machine_learning_job_id:
                errors.append("Machine learning rules require a machine_learning_job_id")
        
        return len(errors) == 0, errors
    
    def _validate_kuery_syntax(self, query: str) -> bool:
        """Basic validation of KQL syntax."""
        try:
            # Check for balanced parentheses
            if query.count('(') != query.count(')'):
                return False
            
            # Check for balanced quotes
            if query.count('"') % 2 != 0:
                return False
            
            # Check for valid field patterns
            field_pattern = r'[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*'
            if not re.search(field_pattern, query):
                return False
            
            return True
        except Exception:
            return False
    
    def _validate_lucene_syntax(self, query: str) -> bool:
        """Basic validation of Lucene syntax."""
        try:
            # Check for balanced parentheses
            if query.count('(') != query.count(')'):
                return False
            
            # Check for balanced quotes
            if query.count('"') % 2 != 0:
                return False
            
            # Check for valid operators
            invalid_patterns = [
                r'AND\s+AND',
                r'OR\s+OR',
                r'NOT\s+NOT',
                r':\s*$',  # Field with no value
            ]
            
            for pattern in invalid_patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    return False
            
            return True
        except Exception:
            return False
    
    def _validate_eql_syntax(self, query: str) -> bool:
        """Basic validation of EQL syntax."""
        try:
            # Check for balanced parentheses
            if query.count('(') != query.count(')'):
                return False
            
            # Check for balanced brackets
            if query.count('[') != query.count(']'):
                return False
            
            # EQL should have event type
            if not re.search(r'\b(process|file|network|registry|dns|authentication)\b', query, re.IGNORECASE):
                return False
            
            return True
        except Exception:
            return False
    
    def convert_to_dict(self, rule: KibanaQLRule) -> Dict[str, Any]:
        """Convert a KibanaQLRule to a dictionary."""
        return {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "query": rule.query,
            "index_patterns": rule.index_patterns,
            "query_type": rule.query_type,
            "language": rule.language,
            "enabled": rule.enabled,
            "severity": rule.severity,
            "risk_score": rule.risk_score,
            "tags": rule.tags,
            "interval": rule.interval,
            "from_time": rule.from_time,
            "to_time": rule.to_time,
            "threshold_field": rule.threshold_field,
            "threshold_value": rule.threshold_value,
            "threshold_cardinality": rule.threshold_cardinality,
            "anomaly_threshold": rule.anomaly_threshold,
            "machine_learning_job_id": rule.machine_learning_job_id,
            "actions": rule.actions,
            "throttle": rule.throttle,
            "author": rule.author,
            "created_date": rule.created_date,
            "last_modified": rule.last_modified,
            "version": rule.version,
            "license": rule.license,
            "references": rule.references,
            "false_positives": rule.false_positives,
            "threat": rule.threat,
            "mitre_techniques": rule.mitre_techniques,
            "complexity": rule.complexity,
            "is_valid": rule.is_valid
        } 