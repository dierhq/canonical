"""
Sigma rule parser for extracting and analyzing rule components.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
import yaml
from ruamel.yaml import YAML
from loguru import logger

from ..core.models import SigmaRule


class SigmaParser:
    """Parser for Sigma rules."""
    
    def __init__(self):
        """Initialize the Sigma parser."""
        self.yaml_parser = YAML()
        self.yaml_parser.preserve_quotes = True
        self.yaml_parser.width = 4096
    
    def parse_rule(self, rule_content: str) -> SigmaRule:
        """Parse a Sigma rule from YAML content.
        
        Args:
            rule_content: YAML content of the Sigma rule
            
        Returns:
            Parsed SigmaRule object
            
        Raises:
            ValueError: If the rule content is invalid
        """
        try:
            # Parse YAML content
            rule_dict = yaml.safe_load(rule_content)
            
            if not isinstance(rule_dict, dict):
                raise ValueError("Rule content must be a YAML dictionary")
            
            # Extract and validate required fields
            if "title" not in rule_dict:
                raise ValueError("Rule must have a 'title' field")
            
            if "detection" not in rule_dict:
                raise ValueError("Rule must have a 'detection' field")
            
            # Create SigmaRule object
            sigma_rule = SigmaRule(
                title=rule_dict["title"],
                id=rule_dict.get("id"),
                status=rule_dict.get("status"),
                description=rule_dict.get("description"),
                author=rule_dict.get("author"),
                date=rule_dict.get("date"),
                modified=rule_dict.get("modified"),
                tags=rule_dict.get("tags", []),
                logsource=rule_dict.get("logsource", {}),
                detection=rule_dict.get("detection", {}),
                fields=rule_dict.get("fields", []),
                falsepositives=rule_dict.get("falsepositives", []),
                level=rule_dict.get("level"),
                references=rule_dict.get("references", [])
            )
            
            return sigma_rule
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML format: {e}")
        except Exception as e:
            raise ValueError(f"Failed to parse Sigma rule: {e}")
    
    def extract_mitre_tags(self, rule: SigmaRule) -> List[str]:
        """Extract MITRE ATT&CK technique IDs from rule tags.
        
        Args:
            rule: Parsed Sigma rule
            
        Returns:
            List of MITRE technique IDs
        """
        mitre_tags = []
        mitre_pattern = re.compile(r'attack\.t\d{4}(?:\.\d{3})?', re.IGNORECASE)
        
        for tag in rule.tags:
            if mitre_pattern.match(tag):
                # Extract technique ID (e.g., "attack.t1059.001" -> "T1059.001")
                technique_id = tag.replace("attack.", "").upper()
                mitre_tags.append(technique_id)
        
        return mitre_tags
    
    def extract_detection_fields(self, rule: SigmaRule) -> Dict[str, List[str]]:
        """Extract field names and values from detection logic.
        
        Args:
            rule: Parsed Sigma rule
            
        Returns:
            Dictionary mapping field names to their possible values
        """
        fields = {}
        
        def extract_from_dict(obj: Dict[str, Any], prefix: str = "") -> None:
            """Recursively extract fields from detection dictionary."""
            for key, value in obj.items():
                if key in ["condition", "timeframe"]:
                    continue
                
                current_key = f"{prefix}.{key}" if prefix else key
                
                if isinstance(value, dict):
                    extract_from_dict(value, current_key)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            extract_from_dict(item, current_key)
                        else:
                            if current_key not in fields:
                                fields[current_key] = []
                            fields[current_key].append(str(item))
                else:
                    if current_key not in fields:
                        fields[current_key] = []
                    fields[current_key].append(str(value))
        
        extract_from_dict(rule.detection)
        return fields
    
    def extract_condition_logic(self, rule: SigmaRule) -> str:
        """Extract the condition logic from the detection section.
        
        Args:
            rule: Parsed Sigma rule
            
        Returns:
            Condition logic string
        """
        return rule.detection.get("condition", "")
    
    def get_log_source_info(self, rule: SigmaRule) -> Dict[str, str]:
        """Extract log source information.
        
        Args:
            rule: Parsed Sigma rule
            
        Returns:
            Dictionary with log source details
        """
        logsource = rule.logsource
        return {
            "category": logsource.get("category", ""),
            "product": logsource.get("product", ""),
            "service": logsource.get("service", ""),
            "definition": logsource.get("definition", "")
        }
    
    def analyze_rule_complexity(self, rule: SigmaRule) -> Dict[str, Any]:
        """Analyze the complexity of a Sigma rule.
        
        Args:
            rule: Parsed Sigma rule
            
        Returns:
            Dictionary with complexity metrics
        """
        detection = rule.detection
        condition = detection.get("condition", "")
        
        # Count detection items (excluding condition)
        detection_items = len([k for k in detection.keys() if k != "condition"])
        
        # Count logical operators in condition
        and_count = condition.lower().count(" and ")
        or_count = condition.lower().count(" or ")
        not_count = condition.lower().count(" not ")
        
        # Count field references
        field_refs = len(re.findall(r'\b\w+\b', condition))
        
        # Estimate complexity score
        complexity_score = (
            detection_items * 2 +
            and_count * 1 +
            or_count * 1.5 +
            not_count * 2 +
            field_refs * 0.5
        )
        
        return {
            "detection_items": detection_items,
            "logical_operators": {
                "and": and_count,
                "or": or_count,
                "not": not_count
            },
            "field_references": field_refs,
            "complexity_score": complexity_score,
            "complexity_level": self._get_complexity_level(complexity_score)
        }
    
    def _get_complexity_level(self, score: float) -> str:
        """Determine complexity level based on score.
        
        Args:
            score: Complexity score
            
        Returns:
            Complexity level string
        """
        if score <= 5:
            return "low"
        elif score <= 15:
            return "medium"
        elif score <= 30:
            return "high"
        else:
            return "very_high"
    
    def extract_rule_summary(self, rule: SigmaRule) -> str:
        """Create a summary of the rule for embedding.
        
        Args:
            rule: Parsed Sigma rule
            
        Returns:
            Rule summary text
        """
        summary_parts = []
        
        # Title and description
        summary_parts.append(f"Title: {rule.title}")
        if rule.description:
            summary_parts.append(f"Description: {rule.description}")
        
        # Log source
        logsource = self.get_log_source_info(rule)
        if logsource["category"]:
            summary_parts.append(f"Category: {logsource['category']}")
        if logsource["product"]:
            summary_parts.append(f"Product: {logsource['product']}")
        if logsource["service"]:
            summary_parts.append(f"Service: {logsource['service']}")
        
        # MITRE techniques
        mitre_tags = self.extract_mitre_tags(rule)
        if mitre_tags:
            summary_parts.append(f"MITRE Techniques: {', '.join(mitre_tags)}")
        
        # Detection fields
        fields = self.extract_detection_fields(rule)
        if fields:
            field_names = list(fields.keys())[:5]  # Limit to first 5 fields
            summary_parts.append(f"Detection Fields: {', '.join(field_names)}")
        
        # Condition
        condition = self.extract_condition_logic(rule)
        if condition:
            summary_parts.append(f"Condition: {condition}")
        
        return "\n".join(summary_parts)
    
    def validate_rule(self, rule: SigmaRule) -> Tuple[bool, List[str]]:
        """Validate a Sigma rule for completeness and correctness.
        
        Args:
            rule: Parsed Sigma rule
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required fields
        if not rule.title:
            errors.append("Missing required field: title")
        
        if not rule.detection:
            errors.append("Missing required field: detection")
        
        # Check detection structure
        if rule.detection and "condition" not in rule.detection:
            errors.append("Detection section missing condition")
        
        # Check log source
        if not rule.logsource:
            errors.append("Missing logsource information")
        else:
            if not any([rule.logsource.get("category"), 
                       rule.logsource.get("product"), 
                       rule.logsource.get("service")]):
                errors.append("Logsource must specify at least one of: category, product, service")
        
        # Check MITRE tags format
        mitre_pattern = re.compile(r'attack\.t\d{4}(?:\.\d{3})?$', re.IGNORECASE)
        for tag in rule.tags:
            if tag.startswith("attack.") and not mitre_pattern.match(tag):
                errors.append(f"Invalid MITRE tag format: {tag}")
        
        return len(errors) == 0, errors
    
    def convert_to_dict(self, rule: SigmaRule) -> Dict[str, Any]:
        """Convert a SigmaRule object back to dictionary format.
        
        Args:
            rule: Sigma rule object
            
        Returns:
            Dictionary representation
        """
        rule_dict = {
            "title": rule.title,
            "detection": rule.detection,
            "logsource": rule.logsource
        }
        
        # Add optional fields if they exist
        if rule.id:
            rule_dict["id"] = rule.id
        if rule.status:
            rule_dict["status"] = rule.status
        if rule.description:
            rule_dict["description"] = rule.description
        if rule.author:
            rule_dict["author"] = rule.author
        if rule.date:
            rule_dict["date"] = rule.date
        if rule.modified:
            rule_dict["modified"] = rule.modified
        if rule.tags:
            rule_dict["tags"] = rule.tags
        if rule.fields:
            rule_dict["fields"] = rule.fields
        if rule.falsepositives:
            rule_dict["falsepositives"] = rule.falsepositives
        if rule.level:
            rule_dict["level"] = rule.level
        if rule.references:
            rule_dict["references"] = rule.references
        
        return rule_dict


# Global parser instance
sigma_parser = SigmaParser() 