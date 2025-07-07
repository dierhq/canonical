"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
QRadar rule parser for parsing QRadar correlation rules.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from loguru import logger

from ..core.models import QRadarRule


class QRadarParser:
    """Parser for QRadar correlation rules."""
    
    def __init__(self):
        """Initialize the QRadar parser."""
        self.rule_patterns = {
            "rule_name": r"(?:Rule Name|Name):\s*(.+)",
            "description": r"(?:Description|Desc):\s*(.+)",
            "rule_type": r"(?:Rule Type|Type):\s*(.+)",
            "enabled": r"(?:Enabled|Status):\s*(.+)",
            "severity": r"(?:Severity):\s*(\d+)",
            "credibility": r"(?:Credibility):\s*(\d+)",
            "relevance": r"(?:Relevance):\s*(\d+)",
            "category": r"(?:Category):\s*(.+)",
            "origin": r"(?:Origin):\s*(.+)",
            "username": r"(?:Username|User):\s*(.+)",
            "creation_date": r"(?:Creation Date|Created):\s*(.+)",
            "modification_date": r"(?:Modification Date|Modified):\s*(.+)",
        }
        
        # Common QRadar test patterns
        self.test_patterns = {
            "when_events": r"when\s+(.+?)\s+(?:and|or|$)",
            "and_condition": r"and\s+(.+?)(?:\s+and|\s+or|$)",
            "or_condition": r"or\s+(.+?)(?:\s+and|\s+or|$)",
            "group_by": r"group\s+by\s+(.+?)(?:\s+having|\s+last|$)",
            "having": r"having\s+(.+?)(?:\s+last|$)",
            "last_clause": r"last\s+(\d+)\s+(minutes?|hours?|days?|seconds?)",
            "username_test": r"username\s*(=|!=|ilike|not\s+ilike|in|not\s+in)\s*(.+)",
            "sourceip_test": r"sourceip\s*(=|!=|in|not\s+in)\s*(.+)",
            "destinationip_test": r"destinationip\s*(=|!=|in|not\s+in)\s*(.+)",
            "qid_test": r"qid\s*(=|!=|in|not\s+in)\s*(.+)",
            "category_test": r"category\s*(=|!=|in|not\s+in)\s*(.+)",
            "payload_test": r"payload\s*(ilike|not\s+ilike|matches)\s*(.+)",
            "custom_property": r"\"([^\"]+)\"\s*(=|!=|>|<|>=|<=|ilike|not\s+ilike)\s*(.+)",
        }
    
    def parse_rule(self, rule_content: str) -> QRadarRule:
        """Parse a QRadar rule from text content.
        
        Args:
            rule_content: Raw QRadar rule content
            
        Returns:
            Parsed QRadarRule object
        """
        try:
            logger.debug("Parsing QRadar rule")
            
            # Extract basic metadata
            metadata = self._extract_metadata(rule_content)
            
            # Extract rule tests/conditions
            tests = self._extract_tests(rule_content)
            
            # Extract actions and responses
            actions = self._extract_actions(rule_content)
            responses = self._extract_responses(rule_content)
            
            # Extract groups
            groups = self._extract_groups(rule_content)
            
            # Create QRadar rule object
            rule = QRadarRule(
                rule_id=metadata.get("rule_id"),
                name=metadata.get("name", "Unknown Rule"),
                description=metadata.get("description"),
                rule_type=metadata.get("rule_type", "EVENT"),
                enabled=metadata.get("enabled", True),
                tests=tests,
                actions=actions,
                responses=responses,
                groups=groups,
                severity=metadata.get("severity"),
                credibility=metadata.get("credibility"),
                relevance=metadata.get("relevance"),
                category=metadata.get("category"),
                origin=metadata.get("origin"),
                username=metadata.get("username"),
                creation_date=metadata.get("creation_date"),
                modification_date=metadata.get("modification_date")
            )
            
            # Extract MITRE techniques from description and tests
            rule.mitre_techniques = self._extract_mitre_techniques(rule_content)
            
            # Analyze complexity
            rule.complexity = self._analyze_complexity(tests)
            
            logger.debug(f"Successfully parsed QRadar rule: {rule.name}")
            return rule
            
        except Exception as e:
            logger.error(f"Failed to parse QRadar rule: {e}")
            # Return a minimal rule structure
            return QRadarRule(
                name="Parse Error",
                description=f"Failed to parse rule: {str(e)}",
                rule_type="EVENT",
                is_valid=False
            )
    
    def _extract_metadata(self, rule_content: str) -> Dict[str, Any]:
        """Extract metadata from rule content.
        
        Args:
            rule_content: Raw rule content
            
        Returns:
            Dictionary of extracted metadata
        """
        metadata = {}
        
        for field, pattern in self.rule_patterns.items():
            match = re.search(pattern, rule_content, re.IGNORECASE | re.MULTILINE)
            if match:
                value = match.group(1).strip()
                
                # Convert specific fields
                if field in ["enabled"]:
                    metadata[field] = value.lower() in ["true", "yes", "1", "enabled"]
                elif field in ["severity", "credibility", "relevance"]:
                    try:
                        metadata[field] = int(value)
                    except ValueError:
                        metadata[field] = None
                else:
                    metadata[field] = value
        
        return metadata
    
    def _extract_tests(self, rule_content: str) -> List[Dict[str, Any]]:
        """Extract test conditions from rule content.
        
        Args:
            rule_content: Raw rule content
            
        Returns:
            List of test dictionaries
        """
        tests = []
        
        # Look for common QRadar test patterns
        for test_type, pattern in self.test_patterns.items():
            matches = re.finditer(pattern, rule_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                test = {
                    "type": test_type,
                    "condition": match.group(1).strip() if match.groups() else match.group(0).strip(),
                    "raw": match.group(0).strip()
                }
                
                # Extract additional details for specific test types
                if test_type in ["username_test", "sourceip_test", "destinationip_test", "qid_test", "category_test"]:
                    if len(match.groups()) >= 2:
                        test["operator"] = match.group(1).strip()
                        test["value"] = match.group(2).strip()
                elif test_type == "custom_property":
                    if len(match.groups()) >= 3:
                        test["property"] = match.group(1).strip()
                        test["operator"] = match.group(2).strip()
                        test["value"] = match.group(3).strip()
                elif test_type == "last_clause":
                    if len(match.groups()) >= 2:
                        test["duration"] = match.group(1).strip()
                        test["unit"] = match.group(2).strip()
                
                tests.append(test)
        
        return tests
    
    def _extract_actions(self, rule_content: str) -> List[Dict[str, Any]]:
        """Extract actions from rule content.
        
        Args:
            rule_content: Raw rule content
            
        Returns:
            List of action dictionaries
        """
        actions = []
        
        # Look for common QRadar actions
        action_patterns = {
            "offense": r"(?:create|generate)\s+offense",
            "email": r"send\s+email\s+to\s+(.+)",
            "syslog": r"send\s+syslog\s+to\s+(.+)",
            "snmp": r"send\s+snmp\s+to\s+(.+)",
            "execute": r"execute\s+(.+)",
            "annotate": r"annotate\s+(.+)",
        }
        
        for action_type, pattern in action_patterns.items():
            matches = re.finditer(pattern, rule_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                action = {
                    "type": action_type,
                    "raw": match.group(0).strip()
                }
                
                if match.groups():
                    action["target"] = match.group(1).strip()
                
                actions.append(action)
        
        return actions
    
    def _extract_responses(self, rule_content: str) -> List[Dict[str, Any]]:
        """Extract responses from rule content.
        
        Args:
            rule_content: Raw rule content
            
        Returns:
            List of response dictionaries
        """
        responses = []
        
        # Look for response patterns
        response_patterns = {
            "block_ip": r"block\s+(?:source|destination)\s+ip",
            "quarantine": r"quarantine\s+(.+)",
            "isolate": r"isolate\s+(.+)",
            "notify": r"notify\s+(.+)",
        }
        
        for response_type, pattern in response_patterns.items():
            matches = re.finditer(pattern, rule_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                response = {
                    "type": response_type,
                    "raw": match.group(0).strip()
                }
                
                if match.groups():
                    response["target"] = match.group(1).strip()
                
                responses.append(response)
        
        return responses
    
    def _extract_groups(self, rule_content: str) -> List[str]:
        """Extract rule groups from content.
        
        Args:
            rule_content: Raw rule content
            
        Returns:
            List of group names
        """
        groups = []
        
        # Look for group patterns
        group_patterns = [
            r"(?:Group|Groups):\s*(.+)",
            r"(?:Assigned to|Member of):\s*(.+)",
        ]
        
        for pattern in group_patterns:
            matches = re.finditer(pattern, rule_content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                group_text = match.group(1).strip()
                # Split by common delimiters
                group_list = re.split(r'[,;|]', group_text)
                groups.extend([g.strip() for g in group_list if g.strip()])
        
        return list(set(groups))  # Remove duplicates
    
    def _extract_mitre_techniques(self, rule_content: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from rule content.
        
        Args:
            rule_content: Raw rule content
            
        Returns:
            List of MITRE technique IDs
        """
        techniques = []
        
        # Look for MITRE technique patterns
        mitre_patterns = [
            r"T\d{4}(?:\.\d{3})?",  # Standard MITRE technique format
            r"(?:MITRE|ATT&CK).*?(T\d{4}(?:\.\d{3})?)",  # MITRE context
            r"technique[:\s]+(T\d{4}(?:\.\d{3})?)",  # Technique field
        ]
        
        for pattern in mitre_patterns:
            matches = re.finditer(pattern, rule_content, re.IGNORECASE)
            for match in matches:
                if match.groups():
                    techniques.append(match.group(1))
                else:
                    techniques.append(match.group(0))
        
        return list(set(techniques))  # Remove duplicates
    
    def _analyze_complexity(self, tests: List[Dict[str, Any]]) -> str:
        """Analyze rule complexity based on tests.
        
        Args:
            tests: List of test dictionaries
            
        Returns:
            Complexity level string
        """
        if not tests:
            return "low"
        
        complexity_score = 0
        
        # Count different types of tests
        test_types = set(test.get("type", "") for test in tests)
        complexity_score += len(test_types)
        
        # Check for complex patterns
        for test in tests:
            condition = test.get("condition", "").lower()
            
            # Stateful tests increase complexity
            if any(keyword in condition for keyword in ["last", "minutes", "hours", "days", "count", "sum", "avg"]):
                complexity_score += 2
            
            # Payload and regex tests increase complexity
            if any(keyword in condition for keyword in ["payload", "matches", "regex", "ilike"]):
                complexity_score += 2
            
            # Custom properties increase complexity
            if test.get("type") == "custom_property":
                complexity_score += 1
        
        # Determine complexity level
        if complexity_score <= 2:
            return "low"
        elif complexity_score <= 6:
            return "medium"
        else:
            return "high"
    
    def validate_rule(self, rule: QRadarRule) -> Tuple[bool, List[str]]:
        """Validate a QRadar rule.
        
        Args:
            rule: QRadar rule to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required fields
        if not rule.name or rule.name.strip() == "":
            errors.append("Rule name is required")
        
        if not rule.rule_type or rule.rule_type not in ["EVENT", "FLOW", "OFFENSE", "COMMON"]:
            errors.append("Valid rule type is required (EVENT, FLOW, OFFENSE, COMMON)")
        
        if not rule.tests:
            errors.append("At least one test condition is required")
        
        # Check severity range
        if rule.severity is not None and (rule.severity < 1 or rule.severity > 10):
            errors.append("Severity must be between 1 and 10")
        
        # Check credibility range
        if rule.credibility is not None and (rule.credibility < 1 or rule.credibility > 10):
            errors.append("Credibility must be between 1 and 10")
        
        # Check relevance range
        if rule.relevance is not None and (rule.relevance < 1 or rule.relevance > 10):
            errors.append("Relevance must be between 1 and 10")
        
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def convert_to_dict(self, rule: QRadarRule) -> Dict[str, Any]:
        """Convert QRadar rule to dictionary format.
        
        Args:
            rule: QRadar rule object
            
        Returns:
            Dictionary representation of the rule
        """
        return {
            "rule_id": rule.rule_id,
            "name": rule.name,
            "description": rule.description,
            "rule_type": rule.rule_type,
            "enabled": rule.enabled,
            "tests": rule.tests,
            "actions": rule.actions,
            "responses": rule.responses,
            "groups": rule.groups,
            "severity": rule.severity,
            "credibility": rule.credibility,
            "relevance": rule.relevance,
            "category": rule.category,
            "origin": rule.origin,
            "username": rule.username,
            "creation_date": rule.creation_date,
            "modification_date": rule.modification_date,
            "mitre_techniques": rule.mitre_techniques,
            "complexity": rule.complexity,
            "is_valid": rule.is_valid
        }
    
    def extract_rule_summary(self, rule: QRadarRule) -> str:
        """Extract a summary of the rule for embedding.
        
        Args:
            rule: QRadar rule object
            
        Returns:
            Rule summary string
        """
        summary_parts = []
        
        # Add rule name and description
        summary_parts.append(f"Rule: {rule.name}")
        if rule.description:
            summary_parts.append(f"Description: {rule.description}")
        
        # Add rule type and category
        summary_parts.append(f"Type: {rule.rule_type}")
        if rule.category:
            summary_parts.append(f"Category: {rule.category}")
        
        # Add test conditions summary
        if rule.tests:
            test_summary = []
            for test in rule.tests:
                if test.get("type") == "custom_property":
                    test_summary.append(f"Custom property {test.get('property', 'unknown')}")
                elif test.get("type") in ["username_test", "sourceip_test", "destinationip_test", "qid_test"]:
                    test_summary.append(f"{test.get('type', 'unknown').replace('_test', '')} condition")
                else:
                    test_summary.append(test.get("type", "unknown"))
            
            if test_summary:
                summary_parts.append(f"Tests: {', '.join(set(test_summary))}")
        
        # Add MITRE techniques
        if rule.mitre_techniques:
            summary_parts.append(f"MITRE Techniques: {', '.join(rule.mitre_techniques)}")
        
        # Add complexity
        summary_parts.append(f"Complexity: {rule.complexity}")
        
        return " | ".join(summary_parts)


# Global QRadar parser instance
qradar_parser = QRadarParser() 