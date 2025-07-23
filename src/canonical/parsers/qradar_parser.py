"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
QRadar rule parser for extracting structured information from QRadar rule text.
"""

import re
from typing import Dict, List, Any, Optional
from loguru import logger


class QRadarRuleParser:
    """Parser for QRadar rule text format."""
    
    def __init__(self):
        """Initialize the QRadar parser."""
        self.rule_patterns = {
            'rule_name': r'Rule Name\s*:\s*(.+?)(?=\n|$)',
            'rule_description': r'Rule Description\s*:\s*(.+?)(?=\n\s*Rule Type|$)',
            'rule_type': r'Rule Type\s*:\s*(.+?)(?=\n|$)',
            'enabled': r'Enabled\s*:\s*(.+?)(?=\n|$)',
            'severity': r'Severity\s*:\s*(\d+)',
            'credibility': r'Credibility\s*:\s*(\d+)',
            'relevance': r'Relevance\s*:\s*(\d+)',
            'category': r'Category\s*:\s*(.+?)(?=\n|$)',
            'conditions': r'(?:Rule Type.*?\n.*?\n.*?\n.*?\n.*?\n.*?\n)(.*?)(?=\n\s*Rule Actions|$)',
            'rule_actions': r'Rule Actions\s*:\s*\n(.*?)(?=\n\s*Rule Responses|$)',
            'rule_responses': r'Rule Responses\s*:\s*\n(.*?)(?=\n\s*Note:|$)',
        }
        
        self.condition_patterns = {
            'apply_rule': r'Apply\s+(.+?)\s+on\s+(.+?)(?:\s+and|$)',
            'event_category': r'event category.*?is one of the following\s+(.+?)(?:\s+and|$)',
            'destination_port': r'destination port is one of the following\s+(\d+)',
            'source_network': r'NOT when the source network is\s+(.+?)(?:\s+and|$)',
            'threshold': r'at least\s+(\d+)\s+.+?\s+in\s+(\d+)\s+(\w+)',
            'context': r'context is\s+(.+?)(?:\s+and|$)',
            'regex_match': r'match\s+(.+?)(?:\s+and|$)',
            'custom_field': r'when any of\s+(.+?)\s+match\s+(.+?)(?:\s+and|$)',
        }
    
    def parse_rule(self, rule_text: str) -> Dict[str, Any]:
        """Parse QRadar rule text into structured format.
        
        Args:
            rule_text: Raw QRadar rule text
            
        Returns:
            Parsed rule structure
        """
        try:
            logger.debug("Parsing QRadar rule text")
            
            # Clean up the rule text
            cleaned_text = self._clean_rule_text(rule_text)
            
            # Extract main sections
            sections = self._extract_sections(cleaned_text)
            
            # Parse conditions from the conditions section (not description)
            conditions_text = sections.get('conditions', '')
            conditions = self._parse_conditions(conditions_text)
            
            # Parse actions and responses
            actions = self._parse_actions(sections.get('rule_actions', ''))
            responses = self._parse_responses(sections.get('rule_responses', ''))
            
            # Build structured rule
            parsed_rule = {
                'raw_text': rule_text,
                'rule_name': sections.get('rule_name', '').strip(),
                'description': sections.get('rule_description', '').strip(),
                'rule_type': sections.get('rule_type', '').strip(),
                'enabled': sections.get('enabled', '').strip(),
                'severity': int(sections.get('severity', '0')) if sections.get('severity') else None,
                'credibility': int(sections.get('credibility', '0')) if sections.get('credibility') else None,
                'relevance': int(sections.get('relevance', '0')) if sections.get('relevance') else None,
                'category': sections.get('category', '').strip(),
                'conditions': conditions,
                'actions': actions,
                'responses': responses,
                'metadata': self._extract_metadata_from_sections(sections, responses)
            }
            
            logger.debug(f"Successfully parsed QRadar rule: {parsed_rule['rule_name']}")
            return parsed_rule
            
        except Exception as e:
            logger.error(f"Failed to parse QRadar rule: {e}")
            raise
    
    def _clean_rule_text(self, text: str) -> str:
        """Clean and normalize rule text."""
        # Preserve line breaks but remove excessive whitespace within lines
        lines = text.strip().split('\n')
        cleaned_lines = []
        for line in lines:
            # Remove excessive whitespace within the line but preserve structure
            cleaned_line = re.sub(r'\s+', ' ', line.strip())
            if cleaned_line:  # Only add non-empty lines
                cleaned_lines.append(cleaned_line)
        
        return '\n'.join(cleaned_lines)
    
    def _extract_sections(self, text: str) -> Dict[str, str]:
        """Extract main sections from rule text."""
        sections = {}
        
        for section_name, pattern in self.rule_patterns.items():
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                sections[section_name] = match.group(1).strip()
        
        return sections
    
    def _extract_rule_name(self, description: str) -> str:
        """Extract rule name from description."""
        # Look for "Apply [RULE_NAME] on..."
        match = re.search(r'Apply\s+(.+?)\s+on', description)
        if match:
            rule_name = match.group(1).strip()
            # Clean up the rule name
            rule_name = re.sub(r'\s+', ' ', rule_name)
            return rule_name
        
        # Fallback: look for pattern like "QRCE - 001 - [NAME]"
        qrce_match = re.search(r'(QRCE\s*-\s*\d+\s*-\s*[^on]+)', description)
        if qrce_match:
            return qrce_match.group(1).strip()
        
        # Final fallback to first few words
        words = description.split()[:8]  # Increased from 5 to capture longer names
        return ' '.join(words)
    
    def _parse_conditions(self, description: str) -> List[Dict[str, Any]]:
        """Parse conditions from rule description."""
        conditions = []
        
        # Extract event categories
        category_match = re.search(self.condition_patterns['event_category'], description, re.IGNORECASE)
        if category_match:
            categories = [cat.strip() for cat in category_match.group(1).split(',')]
            conditions.append({
                'type': 'event_category',
                'values': categories
            })
        
        # Extract destination port
        port_match = re.search(self.condition_patterns['destination_port'], description)
        if port_match:
            conditions.append({
                'type': 'destination_port',
                'value': int(port_match.group(1))
            })
        
        # Extract source network exclusion
        network_match = re.search(self.condition_patterns['source_network'], description)
        if network_match:
            conditions.append({
                'type': 'source_network_exclusion',
                'value': network_match.group(1).strip()
            })
        
        # Extract threshold conditions
        threshold_match = re.search(self.condition_patterns['threshold'], description)
        if threshold_match:
            conditions.append({
                'type': 'threshold',
                'count': int(threshold_match.group(1)),
                'time_value': int(threshold_match.group(2)),
                'time_unit': threshold_match.group(3)
            })
        
        # Extract context conditions
        context_match = re.search(self.condition_patterns['context'], description)
        if context_match:
            contexts = [ctx.strip() for ctx in context_match.group(1).split(',')]
            conditions.append({
                'type': 'context',
                'values': contexts
            })
        
        # Extract custom field matches (like DNS Query)
        custom_match = re.search(self.condition_patterns['custom_field'], description)
        if custom_match:
            conditions.append({
                'type': 'custom_field_match',
                'field': custom_match.group(1).strip(),
                'pattern': custom_match.group(2).strip()
            })
        
        # Also look for the enhanced format: "when any of DNS Query (custom) match"
        enhanced_custom_match = re.search(r'when any of\s+(.+?)\s+match\s+(.+?)(?:\n|$)', description, re.IGNORECASE)
        if enhanced_custom_match:
            field_name = enhanced_custom_match.group(1).strip()
            pattern = enhanced_custom_match.group(2).strip()
            # Remove quotes if present
            pattern = pattern.strip('"\'')
            conditions.append({
                'type': 'custom_field_match',
                'field': field_name,
                'pattern': pattern
            })
        
        return conditions
    
    def _parse_actions(self, actions_text: str) -> List[Dict[str, Any]]:
        """Parse rule actions."""
        actions = []
        
        if not actions_text:
            return actions
        
        # Parse offense creation
        if 'create a NEW offense' in actions_text:
            # Extract offense grouping field
            group_match = re.search(r'select the offense using\s+(.+?)(?:\s|$)', actions_text)
            grouping_field = group_match.group(1) if group_match else 'Source IP'
            
            actions.append({
                'type': 'create_offense',
                'grouping_field': grouping_field
            })
        
        # Parse annotations
        annotation_match = re.search(r'Annotate.*?with:\s*(.+?)(?:\n|$)', actions_text)
        if annotation_match:
            actions.append({
                'type': 'annotate',
                'annotation': annotation_match.group(1).strip()
            })
        
        return actions
    
    def _parse_responses(self, responses_text: str) -> List[Dict[str, Any]]:
        """Parse rule responses."""
        responses = []
        
        if not responses_text:
            return responses
        
        # Parse dispatch new event
        if 'Dispatch New Event' in responses_text:
            event_response = {'type': 'dispatch_event'}
            
            # Extract event name
            name_match = re.search(r'Event Name:\s*(.+?)(?:\n|$)', responses_text)
            if name_match:
                event_response['event_name'] = name_match.group(1).strip()
            
            # Extract event description
            desc_match = re.search(r'Event Description:\s*(.+?)(?:\n\s*Severity|$)', responses_text, re.DOTALL)
            if desc_match:
                event_response['event_description'] = desc_match.group(1).strip()
            
            # Extract severity, credibility, relevance
            severity_match = re.search(r'Severity:\s*(\d+)', responses_text)
            if severity_match:
                event_response['severity'] = int(severity_match.group(1))
            
            credibility_match = re.search(r'Credibility:\s*(\d+)', responses_text)
            if credibility_match:
                event_response['credibility'] = int(credibility_match.group(1))
            
            relevance_match = re.search(r'Relevance:\s*(\d+)', responses_text)
            if relevance_match:
                event_response['relevance'] = int(relevance_match.group(1))
            
            # Extract categories
            high_cat_match = re.search(r'High-Level Category:\s*(.+?)(?:\n|$)', responses_text)
            if high_cat_match:
                event_response['high_level_category'] = high_cat_match.group(1).strip()
            
            low_cat_match = re.search(r'Low-Level Category:\s*(.+?)(?:\n|$)', responses_text)
            if low_cat_match:
                event_response['low_level_category'] = low_cat_match.group(1).strip()
            
            responses.append(event_response)
        
        return responses
    
    def _extract_metadata(self, responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract metadata from responses."""
        metadata = {}
        
        for response in responses:
            if response.get('type') == 'dispatch_event':
                if 'severity' in response:
                    metadata['severity'] = response['severity']
                if 'high_level_category' in response:
                    metadata['category'] = response['high_level_category']
        
        return metadata
    
    def _extract_metadata_from_sections(self, sections: Dict[str, str], responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract metadata from both sections and responses."""
        metadata = {}
        
        # Extract from sections (enhanced rule format)
        if sections.get('severity'):
            metadata['severity'] = int(sections['severity'])
        if sections.get('credibility'):
            metadata['credibility'] = int(sections['credibility'])
        if sections.get('relevance'):
            metadata['relevance'] = int(sections['relevance'])
        if sections.get('category'):
            metadata['category'] = sections['category']
        if sections.get('rule_type'):
            metadata['rule_type'] = sections['rule_type']
        if sections.get('enabled'):
            metadata['enabled'] = sections['enabled']
        
        # Also extract from responses (legacy)
        for response in responses:
            if response.get('type') == 'dispatch_event':
                if 'severity' in response and 'severity' not in metadata:
                    metadata['severity'] = response['severity']
                if 'high_level_category' in response and 'category' not in metadata:
                    metadata['category'] = response['high_level_category']
        
        return metadata


# Global parser instance
qradar_parser = QRadarRuleParser() 