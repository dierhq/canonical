"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
QRadar rule parser for extracting structured information from QRadar rule text.
Enhanced with Foundation-Sec-8B for intelligent correlation pattern detection.
"""

import re
import asyncio
from typing import Dict, List, Any, Optional
from loguru import logger


class QRadarRuleParser:
    """Parser for QRadar rule text format with AI-powered correlation detection."""
    
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
        
        # Legacy patterns kept for fallback only
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
        
        # AI-powered parsing flag
        self._llm_service = None
    
    def _get_llm_service(self):
        """Get LLM service instance for AI-powered parsing."""
        if self._llm_service is None:
            from ..services.llm import llm_service
            self._llm_service = llm_service
        return self._llm_service
    
    async def parse_rule_intelligent(self, rule_text: str) -> Dict[str, Any]:
        """Parse QRadar rule using Foundation-Sec-8B intelligence.
        
        Args:
            rule_text: Raw QRadar rule text
            
        Returns:
            Parsed rule structure with AI-detected correlation patterns
        """
        try:
            logger.info("Parsing QRadar rule with Foundation-Sec-8B intelligence")
            
            # First do basic parsing
            basic_parsed = self.parse_rule(rule_text)
            
            # Then enhance with AI-powered correlation detection
            correlation_patterns = await self._detect_correlation_patterns_ai(rule_text)
            
            # Merge AI insights with basic parsing
            basic_parsed['correlation_patterns'] = correlation_patterns
            basic_parsed['ai_enhanced'] = True
            
            logger.info(f"AI-enhanced parsing completed for: {basic_parsed['rule_name']}")
            return basic_parsed
            
        except Exception as e:
            logger.error(f"AI-enhanced parsing failed, falling back to basic parsing: {e}")
            return self.parse_rule(rule_text)
    
    async def _detect_correlation_patterns_ai(self, rule_text: str) -> Dict[str, Any]:
        """Use Foundation-Sec-8B to detect correlation patterns in QRadar rules.
        
        Args:
            rule_text: Raw QRadar rule text
            
        Returns:
            Detected correlation patterns and metadata
        """
        try:
            llm_service = self._get_llm_service()
            
            prompt = f"""You are a cybersecurity expert analyzing QRadar rules to extract correlation patterns for KustoQL conversion.

QRADAR RULE:
{rule_text}

Analyze this rule and extract correlation patterns. Look for:

1. AGGREGATION PATTERNS:
   - "at least X events" → threshold counting
   - "same [field]" → group by field
   - "different [field]" → distinct counting (dcount)
   - "unique [field]" → distinct counting (dcount)

2. TIME PATTERNS:
   - "in X minutes/hours/seconds" → time window
   - "within X time" → time window
   - "last X minutes" → time range

3. FIELD RELATIONSHIPS:
   - "same Source IP and different Destination IP" → group by SrcIP, count distinct DstIP
   - "same user, different systems" → group by user, count distinct systems
   - "multiple destinations" → dcount destinations

4. FILTERING PATTERNS:
   - "destination port X" → port filtering
   - "NOT when source network" → exclusion filters
   - "context is Local to Remote" → direction filters

Return ONLY a JSON object with this exact structure:
{{
    "has_correlation": true/false,
    "correlation_type": "threshold_based|time_based|multi_field|simple",
    "aggregation": {{
        "group_by_fields": ["field_name"],
        "count_distinct_fields": ["field_name"],
        "threshold_count": number,
        "threshold_operator": ">=|>|<=|<|=="
    }},
    "time_window": {{
        "value": number,
        "unit": "m|h|s|d",
        "kusto_format": "2m|1h|30s"
    }},
    "filters": [
        {{
            "field": "field_name",
            "operator": "==|!=|contains|startswith",
            "value": "filter_value",
            "type": "include|exclude"
        }}
    ],
    "table_hints": ["suggested_table_names"],
    "complexity_score": 1-10,
    "conversion_approach": "specialized_correlation|simple_filter|generic_template"
}}"""

            response = await llm_service.generate_response(prompt, max_tokens=800, use_cybersec_optimization=True)
            
            # Parse JSON response
            import json
            try:
                # Clean up response
                cleaned_response = response.strip()
                if cleaned_response.startswith('```json'):
                    cleaned_response = cleaned_response.split('```json')[1].split('```')[0]
                elif cleaned_response.startswith('```'):
                    cleaned_response = cleaned_response.split('```')[1].split('```')[0]
                
                correlation_data = json.loads(cleaned_response)
                logger.info(f"Detected correlation pattern: {correlation_data.get('correlation_type', 'unknown')}")
                return correlation_data
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse AI correlation response as JSON: {e}")
                # Return basic correlation detection
                return self._fallback_correlation_detection(rule_text)
                
        except Exception as e:
            logger.error(f"AI correlation detection failed: {e}")
            return self._fallback_correlation_detection(rule_text)
    
    def _fallback_correlation_detection(self, rule_text: str) -> Dict[str, Any]:
        """Fallback correlation detection using pattern matching."""
        correlation = {
            "has_correlation": False,
            "correlation_type": "simple",
            "aggregation": {},
            "time_window": {},
            "filters": [],
            "table_hints": [],
            "complexity_score": 1,
            "conversion_approach": "generic_template"
        }
        
        # Basic threshold detection
        threshold_match = re.search(r'at least\s+(\d+)\s+.+?\s+in\s+(\d+)\s+(\w+)', rule_text, re.IGNORECASE)
        if threshold_match:
            correlation["has_correlation"] = True
            correlation["correlation_type"] = "threshold_based"
            correlation["aggregation"]["threshold_count"] = int(threshold_match.group(1))
            correlation["aggregation"]["threshold_operator"] = ">="
            correlation["time_window"]["value"] = int(threshold_match.group(2))
            correlation["time_window"]["unit"] = threshold_match.group(3)[0].lower()  # m, h, s
            correlation["time_window"]["kusto_format"] = f"{threshold_match.group(2)}{threshold_match.group(3)[0].lower()}"
            correlation["complexity_score"] = 6
            correlation["conversion_approach"] = "specialized_correlation"
        
        return correlation

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
                'metadata': self._extract_metadata_from_sections(sections, responses),
                'ai_enhanced': False  # Mark as basic parsing
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