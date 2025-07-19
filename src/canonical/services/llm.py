"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Qwen LLM service for intelligent rule conversion.
"""

import asyncio
from typing import List, Dict, Any, Optional
import json
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch
from loguru import logger

from ..core.config import settings
from ..core.models import TargetFormat


class QwenLLMService:
    """Qwen language model service for rule conversion."""
    
    def __init__(self, model_name: Optional[str] = None, device: Optional[str] = None):
        """Initialize the LLM service.
        
        Args:
            model_name: Name of the Qwen model to use
            device: Device to run the model on ('cpu', 'cuda', 'mps')
        """
        self.model_name = model_name or settings.qwen_model
        self.device = device or settings.qwen_device
        self.tokenizer = None
        self.model = None
        self.pipeline = None
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the Qwen model."""
        if self._initialized:
            return
            
        try:
            logger.info(f"Loading Qwen 7B model: {self.model_name}")
            logger.info(f"Device: {self.device}, Max tokens: {settings.qwen_max_tokens}")
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )
            
            # Load model with optimized settings for 7B model
            torch_dtype = getattr(torch, settings.qwen_torch_dtype, torch.float16)
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=torch_dtype,
                device_map="auto" if self.device == "cuda" else None,
                trust_remote_code=True,
                low_cpu_mem_usage=True if self.device == "cuda" else False
            )
            
            logger.info(f"Model loaded with {self.model.num_parameters():,} parameters")
            if torch.cuda.is_available() and self.device == "cuda":
                memory_used = torch.cuda.memory_allocated() / (1024**3)
                logger.info(f"GPU memory usage: {memory_used:.2f} GB")
            
            # Create pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                
                torch_dtype=torch.float16 if self.device == "cuda" else torch.float32,
            )
            
            self._initialized = True
            logger.info(f"Qwen model loaded successfully on {self.device}")
        except Exception as e:
            logger.error(f"Failed to load Qwen model: {e}")
            raise
    
    async def generate_response(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Generate a response using the Qwen model.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum number of tokens to generate
            
        Returns:
            Generated response
        """
        if not self._initialized:
            await self.initialize()
            
        try:
            max_tokens = max_tokens or settings.qwen_max_tokens
            
            # Use direct model generation for better control
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._generate_direct, prompt, max_tokens)
            
            return result
        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            raise
    
    def _generate_direct(self, prompt: str, max_tokens: int) -> str:
        """Direct generation using model and tokenizer."""
        # Tokenize input
        inputs = self.tokenizer(prompt, return_tensors="pt")
        if self.device == "cuda":
            inputs = {k: v.to("cuda") for k, v in inputs.items()}
        
        # Generate with conservative parameters
        with torch.no_grad():
            outputs = self.model.generate(
                inputs["input_ids"],
                attention_mask=inputs.get("attention_mask"),
                max_new_tokens=max_tokens,
                do_sample=False,  # Use greedy decoding for stability
                pad_token_id=self.tokenizer.eos_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
            )
        
        # Decode response
        response = self.tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1]:], 
            skip_special_tokens=True
        )
        return response.strip()
    
    async def convert_sigma_rule(
        self, 
        sigma_rule: str, 
        target_format: TargetFormat,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert a Sigma rule to the target format.
        
        Args:
            sigma_rule: Sigma rule content
            target_format: Target format to convert to
            context: Additional context for conversion
            
        Returns:
            Conversion result with rule, confidence, and explanation
        """
        prompt = self._build_conversion_prompt(sigma_rule, target_format, context)
        
        try:
            response = await self.generate_response(prompt)
            logger.debug(f"LLM raw response: {response}")
            return self._parse_conversion_response(response, target_format)
        except Exception as e:
            logger.error(f"Failed to convert Sigma rule: {e}")
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": f"Conversion failed: {str(e)}",
                "error_message": str(e)
            }
    
    def _build_conversion_prompt(
        self, 
        sigma_rule: str, 
        target_format: TargetFormat,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the conversion prompt for the LLM.
        
        Args:
            sigma_rule: Sigma rule content
            target_format: Target format
            context: Additional context
            
        Returns:
            Formatted prompt
        """
        format_descriptions = {
            TargetFormat.KUSTOQL: "KustoQL (Azure Data Explorer/Sentinel)",
            TargetFormat.KIBANAQL: "Kibana Query Language (Elastic)",
            TargetFormat.EQL: "Event Query Language (Elastic)",
            TargetFormat.QRADAR: "QRadar AQL (IBM)",
            TargetFormat.SPL: "Splunk Processing Language"
        }
        
        format_examples = {
            TargetFormat.KUSTOQL: """
Example KustoQL:
SecurityEvent
| where EventID == 4688
| where Process contains "powershell.exe"
| where CommandLine contains "-EncodedCommand"
""",
            TargetFormat.KIBANAQL: """
Example Kibana Query:
event.code:4688 AND process.name:powershell.exe AND process.command_line:*EncodedCommand*
""",
            TargetFormat.EQL: """
Example EQL:
process where process.name == "powershell.exe" and process.command_line like "*EncodedCommand*"
""",
            TargetFormat.QRADAR: """
Example QRadar AQL:
SELECT * FROM events WHERE eventid=4688 AND processname LIKE '%powershell.exe%' AND commandline LIKE '%EncodedCommand%'
""",
            TargetFormat.SPL: """
Example SPL:
index=security EventCode=4688 Image="*powershell.exe" CommandLine="*EncodedCommand*"
"""
        }
        
        context_info = ""
        if context:
            if "mitre_techniques" in context:
                context_info += f"\nMITRE ATT&CK Techniques: {', '.join(context['mitre_techniques'])}"
            if "similar_rules" in context:
                context_info += f"\nSimilar rules found: {len(context['similar_rules'])}"
            if "schema_field_mappings" in context:
                schema_mappings = context["schema_field_mappings"]
                if schema_mappings:
                    context_info += f"\n\nSchema-Aware Field Mappings:"
                    if "schema_name" in context and context["schema_name"]:
                        context_info += f"\nTarget Environment: {context['schema_name']}"
                    for field_ref, mappings in schema_mappings.items():
                        context_info += f"\n  '{field_ref}' -> Suggested fields:"
                        for mapping in mappings[:3]:  # Show top 3 mappings
                            context_info += f"\n    - {mapping['field_name']} (confidence: {mapping['confidence']:.2f})"
                            if mapping.get('description'):
                                context_info += f" - {mapping['description']}"
        
        prompt = f"""You are an expert SIEM rule converter. Convert the following Sigma rule to {format_descriptions[target_format]}.

Sigma Rule:
```yaml
{sigma_rule}
```

Target Format: {target_format.value.upper()}
{format_examples[target_format]}

{context_info}

Instructions:
1. Analyze the Sigma rule structure and detection logic
2. Map Sigma fields to the target format's field names
3. **IMPORTANT**: If schema-aware field mappings are provided above, prioritize using those field names for better environment compatibility
4. Convert conditions and operators appropriately
5. Maintain the detection logic and intent
6. Provide a confidence score (0.0-1.0) - higher if schema mappings were used
7. Explain the conversion process and mention any schema-aware field mappings used

Respond in the following JSON format:
{{
    "success": true,
    "target_rule": "converted rule here",
    "confidence_score": 0.95,
    "explanation": "Detailed explanation of the conversion process",
    "field_mappings": {{"sigma_field": "target_field"}},
    "notes": "Any important notes or limitations"
}}

Response:"""
        
        return prompt
    
    def _parse_conversion_response(self, response: str, target_format: TargetFormat) -> Dict[str, Any]:
        """Parse the LLM response for conversion results.
        
        Args:
            response: LLM response
            target_format: Target format
            
        Returns:
            Parsed conversion result
        """
        try:
            # Clean up the response - remove markdown code blocks and handle multiple JSON blocks
            cleaned_response = response.strip()
            
            # Remove markdown code blocks
            import re
            # Remove ```json and ``` markers
            cleaned_response = re.sub(r'```json\s*', '', cleaned_response)
            cleaned_response = re.sub(r'```\s*', '', cleaned_response)
            
            # Find all JSON objects in the response
            json_objects = []
            brace_count = 0
            start_idx = -1
            
            for i, char in enumerate(cleaned_response):
                if char == '{':
                    if brace_count == 0:
                        start_idx = i
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_idx != -1:
                        json_objects.append(cleaned_response[start_idx:i+1])
                        start_idx = -1
            
            # Try to parse each JSON object and use the first valid one
            logger.debug(f"Found {len(json_objects)} JSON objects to parse")
            for json_str in json_objects:
                
                # Try to fix common JSON issues with multi-line strings
                try:
                    result = json.loads(json_str)
                    
                    # Validate and clean up required fields
                    if "target_rule" in result and result["target_rule"]:
                        # Unescape newlines in target_rule if needed
                        if isinstance(result["target_rule"], str):
                            result["target_rule"] = result["target_rule"].replace('\\n', '\n').replace('\\r', '\r')
                    else:
                        result["target_rule"] = None
                        
                    if "confidence_score" not in result:
                        result["confidence_score"] = 0.5
                    if "explanation" not in result:
                        result["explanation"] = "No explanation provided"
                    
                    result["success"] = bool(result.get("target_rule"))
                    return result
                    
                except json.JSONDecodeError:
                    # Try to fix malformed JSON by escaping newlines in target_rule
                    # Find target_rule value and escape newlines
                    pattern = r'"target_rule":\s*"([^"]*(?:\n[^"]*)*)"'
                    match = re.search(pattern, json_str, re.DOTALL)
                    if match:
                        original_rule = match.group(1)
                        escaped_rule = original_rule.replace('\n', '\\n').replace('\r', '\\r')
                        json_str = json_str.replace(match.group(0), f'"target_rule": "{escaped_rule}"')
                        
                        try:
                            result = json.loads(json_str)
                            # Unescape newlines in target_rule
                            if "target_rule" in result and result["target_rule"]:
                                result["target_rule"] = result["target_rule"].replace('\\n', '\n').replace('\\r', '\r')
                            else:
                                result["target_rule"] = None
                                
                            if "confidence_score" not in result:
                                result["confidence_score"] = 0.5
                            if "explanation" not in result:
                                result["explanation"] = "No explanation provided"
                            
                            result["success"] = bool(result.get("target_rule"))
                            return result
                        except json.JSONDecodeError:
                            continue  # Try next JSON object
                    else:
                        continue  # Try next JSON object
            
            # If no valid JSON objects found, fallback to extracting rule from response
            # Fallback: treat entire response as the converted rule
            return {
                "success": True,
                "target_rule": cleaned_response,
                "confidence_score": 0.3,
                "explanation": "Rule extracted from unstructured response",
                "field_mappings": {},
                "notes": "Response format was not structured"
            }
        except (json.JSONDecodeError, Exception) as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            # Try to extract just the rule part from the response
            lines = response.split('\n')
            rule_lines = []
            in_rule = False
            
            for line in lines:
                if 'SecurityEvent' in line or 'index=' in line or 'process where' in line or 'SELECT' in line:
                    in_rule = True
                if in_rule:
                    rule_lines.append(line.strip())
                    if line.strip().endswith('"') or line.strip().endswith(','):
                        break
            
            if rule_lines:
                extracted_rule = '\n'.join(rule_lines).strip(' ",')
                return {
                    "success": True,
                    "target_rule": extracted_rule,
                    "confidence_score": 0.4,
                    "explanation": "Rule extracted from malformed response",
                    "field_mappings": {},
                    "notes": "Response format was malformed but rule was extracted"
                }
            
            # Final fallback
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": "Failed to parse LLM response",
                "error_message": f"Invalid response format: {str(e)}"
            }
    
    async def convert_qradar_to_kustoql(
        self, 
        qradar_rule: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert a QRadar rule to KustoQL.
        
        Args:
            qradar_rule: QRadar rule content
            context: Additional context for conversion including Azure Sentinel examples
            
        Returns:
            Conversion result with KustoQL rule, confidence, and explanation
        """
        prompt = self._build_qradar_to_kustoql_prompt(qradar_rule, context)
        
        try:
            response = await self.generate_response(prompt)
            logger.debug(f"QRadar to KustoQL LLM response: {response}")
            return self._parse_conversion_response(response, TargetFormat.KUSTOQL)
        except Exception as e:
            logger.error(f"Failed to convert QRadar rule to KustoQL: {e}")
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": f"QRadar to KustoQL conversion failed: {str(e)}",
                "error_message": str(e)
            }
    
    def _build_qradar_to_kustoql_prompt(
        self, 
        qradar_rule: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the QRadar to KustoQL conversion prompt.
        
        Args:
            qradar_rule: QRadar rule content
            context: Additional context including Azure Sentinel examples
            
        Returns:
            Formatted prompt
        """
        context_info = ""
        azure_examples = ""
        
        if context:
            if "mitre_techniques" in context:
                context_info += f"\nMITRE ATT&CK Techniques: {', '.join(context['mitre_techniques'])}"
            
            if "similar_rules" in context:
                context_info += f"\nSimilar rules found: {len(context['similar_rules'])}"
            
            if "schema_field_mappings" in context:
                schema_mappings = context["schema_field_mappings"]
                if schema_mappings:
                    context_info += f"\n\nSchema-Aware Field Mappings:"
                    if "schema_name" in context and context["schema_name"]:
                        context_info += f"\nTarget Environment: {context['schema_name']}"
                    for field_ref, mappings in schema_mappings.items():
                        context_info += f"\n  '{field_ref}' -> Suggested fields:"
                        for mapping in mappings[:3]:  # Show top 3 mappings
                            context_info += f"\n    - {mapping['field_name']} (confidence: {mapping['confidence']:.2f})"
                            if mapping.get('description'):
                                context_info += f" - {mapping['description']}"
            
            if "azure_sentinel_examples" in context:
                azure_examples = "\n\nRelevant Azure Sentinel Examples:\n"
                for i, example in enumerate(context["azure_sentinel_examples"][:3]):  # Limit to 3 examples
                    azure_examples += f"\nExample {i+1}:\n{example.get('query', '')}\n"
        
        prompt = f"""You are an expert SIEM rule converter specializing in converting QRadar correlation rules to KustoQL (Azure Sentinel).

QRadar Rule to Convert:
```
{qradar_rule}
```

{context_info}
{azure_examples}

QRadar to KustoQL Field Mappings:
- sourceip → SourceIP, SrcIP, or ClientIP
- destinationip → DestinationIP, DstIP, or DestIP  
- username → AccountName, UserName, or Account
- qid → EventID (map to Windows Event IDs when possible)
- category → EventCategory or Category
- payload → EventData or CommandLine
- hostname → Computer or DeviceName
- processname → ProcessName or NewProcessName
- filename → FileName or TargetFilename
- url → Url or RequestURL
- domainname → Domain or TargetDomainName

QRadar Operators to KustoQL:
- = → ==
- != → !=
- ilike → contains (case-insensitive)
- not ilike → !contains
- in → in~
- not in → !in~
- matches → matches regex
- > → >
- < → <

QRadar Time Windows to KustoQL:
- "last X minutes" → "ago(Xm)"
- "last X hours" → "ago(Xh)"  
- "last X days" → "ago(Xd)"

KustoQL Table Selection Guidelines:
- Windows Events: SecurityEvent, Event, WindowsEvent
- Network Events: CommonSecurityLog, NetworkCommunicationEvents
- DNS Events: DnsEvents
- Process Events: SecurityEvent (EventID 4688), ProcessCreationEvents
- Logon Events: SecurityEvent (EventID 4624, 4625), SigninLogs
- File Events: DeviceFileEvents, SecurityEvent
- Web/Proxy: CommonSecurityLog, W3CIISLog

Instructions:
1. Analyze the QRadar rule structure and detection logic
2. Map QRadar fields to appropriate KustoQL table fields
3. **IMPORTANT**: If schema-aware field mappings are provided above, prioritize using those field names for better environment compatibility
4. Convert QRadar operators to KustoQL operators
5. Handle time windows and aggregations appropriately
6. Select the most appropriate KustoQL table(s)
7. Maintain the detection logic and intent
8. Use proper KustoQL syntax and functions
9. Provide a confidence score (0.0-1.0) - higher if schema mappings were used
10. Explain the conversion process, mention any schema-aware field mappings used, and any assumptions made

Respond in the following JSON format:
{{
    "success": true,
    "target_rule": "// Converted from QRadar rule\\n// Original rule logic: [brief description]\\n\\nTableName\\n| where TimeGenerated > ago(1h)\\n| where Field == \\"value\\"\\n| project TimeGenerated, Field1, Field2\\n| summarize count() by Field1",
    "confidence_score": 0.85,
    "explanation": "Detailed explanation of the conversion process, field mappings, and any assumptions made",
    "field_mappings": {{"qradar_field": "kustoql_field"}},
    "table_used": "SecurityEvent",
    "notes": "Any important notes, limitations, or manual adjustments needed"
}}

Response:"""
        
        return prompt
    
    async def explain_rule(self, rule: str, rule_format: str) -> str:
        """Explain what a rule does in natural language.
        
        Args:
            rule: Rule content
            rule_format: Format of the rule
            
        Returns:
            Natural language explanation
        """
        prompt = f"""Explain the following {rule_format} security rule in simple, clear language:

Rule:
```
{rule}
```

Provide a concise explanation covering:
1. What type of activity this rule detects
2. Key indicators or patterns it looks for
3. Potential threats or attack techniques it addresses
4. Any notable conditions or filters

Explanation:"""
        
        return await self.generate_response(prompt, max_tokens=512)


# Global LLM service instance
llm_service = QwenLLMService() 