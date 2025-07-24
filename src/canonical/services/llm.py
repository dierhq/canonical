"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Foundation-Sec-8B LLM service for cybersecurity-optimized rule conversion.
"""

import asyncio
from typing import List, Dict, Any, Optional
import json
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch
from loguru import logger

from ..core.config import settings
from ..core.models import TargetFormat


# Global shared model instances (singleton pattern)
_shared_tokenizer = None
_shared_model = None  
_shared_pipeline = None
_model_lock = asyncio.Lock()


class FoundationSecLLMService:
    """Foundation-Sec-8B language model service for cybersecurity tasks."""
    
    def __init__(self, model_name: Optional[str] = None, device: Optional[str] = None):
        """Initialize the Foundation-Sec-8B LLM service.
        
        Args:
            model_name: Model name (Foundation-Sec-8B by default)
            device: Device to run the model on ('auto', 'cpu', 'cuda', 'mps')
        """
        # Model configuration
        self.model_name = model_name or settings.llm_model
        self.device = device or settings.llm_device
        
        # Reference to shared instances
        self.tokenizer = None
        self.model = None
        self.pipeline = None
        
        # State tracking
        self.initialized = False
        self.model_capabilities = {
            "cybersecurity_specialized": True,
            "general_language": True,
            "rule_conversion_advanced": True,
            "mitre_attack_knowledge": True,
            "threat_intelligence": True
        }
        
    async def initialize(self) -> None:
        """Initialize the Foundation-Sec-8B model using shared instances."""
        global _shared_tokenizer, _shared_model, _shared_pipeline
        
        async with _model_lock:
            # If shared instances already exist, reuse them
            if _shared_tokenizer is not None and _shared_model is not None:
                logger.info("Reusing existing Foundation-Sec-8B model instance")
                self.tokenizer = _shared_tokenizer
                self.model = _shared_model  
                self.pipeline = _shared_pipeline
                self.initialized = True
                return
            
            # Load the model only once
            try:
                logger.info(f"Loading Foundation-Sec-8B model: {self.model_name}")
                
                # Determine device and dtype
                device_map = self._get_device_map(self.device)
                torch_dtype = self._get_torch_dtype(self.device)
                
                # Load tokenizer
                _shared_tokenizer = AutoTokenizer.from_pretrained(
                    self.model_name,
                    trust_remote_code=False  # Foundation-Sec-8B doesn't need custom code
                )
                
                # Set pad token if not present
                if _shared_tokenizer.pad_token is None:
                    _shared_tokenizer.pad_token = _shared_tokenizer.eos_token
                
                # Determine if quantization should be used
                use_quantization = self._should_use_quantization()
                
                # Load model with optimizations
                model_kwargs = {
                    "torch_dtype": torch_dtype,
                    "device_map": device_map,
                    "trust_remote_code": False
                }
                
                # Add quantization if needed
                if use_quantization:
                    try:
                        from transformers import BitsAndBytesConfig
                        quantization_config = BitsAndBytesConfig(
                            load_in_4bit=True,
                            bnb_4bit_compute_dtype=torch.float16,
                            bnb_4bit_use_double_quant=True,
                            bnb_4bit_quant_type="nf4"
                        )
                        model_kwargs["quantization_config"] = quantization_config
                        logger.info("Using 4-bit quantization for Foundation-Sec-8B")
                    except ImportError:
                        logger.warning("BitsAndBytesConfig not available, loading without quantization")
                
                # Add flash attention if available
                if self._supports_flash_attention():
                    model_kwargs["attn_implementation"] = "flash_attention_2"
                    logger.info("Using Flash Attention 2 for improved performance")
                
                _shared_model = AutoModelForCausalLM.from_pretrained(
                    self.model_name,
                    **model_kwargs
                )
                
                # Create pipeline
                _shared_pipeline = pipeline(
                    "text-generation",
                    model=_shared_model,
                    tokenizer=_shared_tokenizer,
                    torch_dtype=torch_dtype
                )
                
                # Set instance references
                self.tokenizer = _shared_tokenizer
                self.model = _shared_model
                self.pipeline = _shared_pipeline
                self.initialized = True
                
                logger.info(f"Foundation-Sec-8B loaded successfully on {self.device}")
                
            except Exception as e:
                logger.error(f"Failed to load Foundation-Sec-8B: {e}")
                raise RuntimeError(f"Foundation-Sec-8B initialization failed: {e}")
    
    def _get_device_map(self, device: str) -> str:
        """Get appropriate device mapping."""
        if device == "auto":
            return "auto"
        elif device == "cuda" and torch.cuda.is_available():
            return "auto"
        else:
            return None
    
    def _get_torch_dtype(self, device: str) -> torch.dtype:
        """Get appropriate torch dtype based on device."""
        if device in ["cuda", "auto"] and torch.cuda.is_available():
            return torch.float16
        else:
            return torch.float32
    
    def _supports_flash_attention(self) -> bool:
        """Check if flash attention is available."""
        try:
            import flash_attn
            return torch.cuda.is_available()
        except ImportError:
            return False
    
    def _should_use_quantization(self) -> bool:
        """Determine if quantization should be used based on available memory."""
        if not torch.cuda.is_available():
            return False
        
        try:
            available_memory = torch.cuda.mem_get_info()[0] / 1e9  # Available memory in GB
            threshold = 12.0  # Fixed threshold for Foundation-Sec-8B
            
            # Use quantization only if available memory is insufficient
            return available_memory < threshold
        except:
            return True  # Default to quantization for safety
    
    async def generate_response(self, prompt: str, max_tokens: Optional[int] = None, use_cybersec_optimization: bool = True) -> str:
        """Generate a response using Foundation-Sec-8B.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum number of tokens to generate
            use_cybersec_optimization: Whether to use cybersecurity-optimized settings
            
        Returns:
            Generated response
        """
        if not self.initialized:
            await self.initialize()
        
        try:
            max_tokens = max_tokens or settings.llm_max_tokens
            
            # Base generation parameters
            generation_params = {
                "max_new_tokens": min(max_tokens, settings.llm_max_tokens),
                "temperature": max(0.7, settings.llm_temperature),  # Ensure minimum creativity
                "top_p": 0.9,
                "do_sample": True,
                "pad_token_id": self.tokenizer.eos_token_id,
                "eos_token_id": self.tokenizer.eos_token_id,
                "return_full_text": False,  # Only return generated text, not prompt
            }
            
            # Apply cybersecurity optimization if enabled
            if use_cybersec_optimization:
                generation_params.update({
                    "top_k": 50,
                    "repetition_penalty": 1.15,  # Slightly higher to avoid repetition
                    "min_length": 20,  # Force some minimum generation
                    "temperature": 0.8,  # Override with higher creativity for cybersec
                })
            
            # Run generation in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.pipeline(prompt, **generation_params)
            )
            
            generated_text = result[0]["generated_text"].strip()
            
            # Post-process for cybersecurity tasks
            if use_cybersec_optimization:
                generated_text = self._post_process_cybersec_response(generated_text)
            
            return generated_text
            
        except Exception as e:
            logger.error(f"Failed to generate response with Foundation-Sec-8B: {e}")
            raise
    
    def _post_process_cybersec_response(self, response: str) -> str:
        """Post-process response for cybersecurity tasks."""
        # Remove common artifacts from Foundation-Sec-8B responses
        response = response.strip()
        
        # Remove duplicate content
        lines = response.split('\n')
        unique_lines = []
        seen = set()
        for line in lines:
            if line.strip() not in seen or line.strip().startswith('//'):
                unique_lines.append(line)
                seen.add(line.strip())
        
        return '\n'.join(unique_lines)
    
    async def convert_sigma_rule(
        self, 
        sigma_rule: str, 
        target_format: TargetFormat,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert a Sigma rule to the target format using Foundation-Sec-8B.
        
        Args:
            sigma_rule: Sigma rule content
            target_format: Target format to convert to
            context: Additional context for conversion
            
        Returns:
            Conversion result with rule, confidence, and explanation
        """
        prompt = self._build_conversion_prompt(sigma_rule, target_format, context)
        
        try:
            response = await self.generate_response(prompt, use_cybersec_optimization=True)
            logger.debug(f"Foundation-Sec-8B raw response: {response}")
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
    
    async def convert_qradar_rule(
        self, 
        qradar_rule: str, 
        target_format: TargetFormat,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert a QRadar rule to any target format using Foundation-Sec-8B.
        
        Args:
            qradar_rule: QRadar rule content
            target_format: Target format to convert to
            context: Additional context for conversion
            
        Returns:
            Conversion result with converted rule, confidence, and explanation
        """
        prompt = self._build_qradar_conversion_prompt(qradar_rule, target_format, context)
        
        try:
            response = await self.generate_response(prompt, use_cybersec_optimization=True)
            logger.debug(f"Foundation-Sec-8B QRadar conversion response: {response}")
            return self._parse_conversion_response(response, target_format)
        except Exception as e:
            logger.error(f"Failed to convert QRadar rule: {e}")
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": f"QRadar conversion failed: {str(e)}",
                "error_message": str(e)
            }

    async def convert_qradar_to_kustoql(
        self, 
        qradar_rule: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert a QRadar rule to KustoQL using Foundation-Sec-8B.
        
        Args:
            qradar_rule: QRadar rule content
            context: Additional context for conversion
            
        Returns:
            Conversion result with KustoQL rule, confidence, and explanation
        """
        return await self.convert_qradar_rule(qradar_rule, TargetFormat.KUSTOQL, context)
    
    def _build_conversion_prompt(self, sigma_rule: str, target_format: TargetFormat, context: Optional[Dict[str, Any]] = None) -> str:
        """Build a conversion prompt for Foundation-Sec-8B with enhanced context."""
        format_name = target_format.value.upper()
        
        # Build context from enhanced ChromaDB patterns
        context_str = self._build_enhanced_context_string(context, format_name)
        
        prompt = f"""Convert the following Sigma rule to {format_name}:

{sigma_rule}
{context_str}

{format_name} Query:
```{format_name.lower()}
"""

        return prompt
    
    def _build_qradar_conversion_prompt(self, qradar_rule: str, target_format: TargetFormat, context: Optional[Dict[str, Any]] = None) -> str:
        """Build a QRadar conversion prompt for Foundation-Sec-8B with enhanced context."""
        format_name = target_format.value.upper()
        
        # Build context from enhanced ChromaDB patterns  
        context_str = self._build_enhanced_context_string(context, format_name)
        
        prompt = f"""Convert the following QRadar rule to {format_name}:

{qradar_rule}
{context_str}

{format_name} Query:
```{format_name.lower()}
"""

        return prompt
    
    def _build_enhanced_context_string(self, context: Optional[Dict[str, Any]], format_name: str) -> str:
        """Build enhanced context string from ChromaDB patterns."""
        if not context:
            return ""
        
        context_parts = []
        
        # Add table usage guidance
        table_examples = context.get("table_examples", [])
        if table_examples:
            context_parts.append(f"\nCommon {format_name} tables: {', '.join(table_examples[:3])}")
        
        # Add field mapping guidance
        field_mappings = context.get("field_names", [])
        if field_mappings:
            context_parts.append(f"\nField mappings: {', '.join(field_mappings[:3])}")
        
        # Add regex pattern examples from similar rules
        regex_patterns = context.get("regex_patterns", [])
        logger.debug(f"Retrieved {len(regex_patterns)} regex patterns from context: {regex_patterns}")
        if regex_patterns:
            context_parts.append(f"\nRegex patterns from similar rules:")
            for pattern in regex_patterns[:3]:  # Use top 3 patterns
                if pattern.strip():
                    context_parts.append(f"  {pattern.strip()}")
        
        # Add query pattern examples
        query_patterns = context.get("query_patterns", [])
        if query_patterns:
            context_parts.append(f"\nExample query structures:")
            for i, pattern in enumerate(query_patterns[:2], 1):
                if pattern.strip():
                    context_parts.append(f"{pattern.strip()}")
        
        # Add similar rules context
        similar_rules = context.get("similar_rules", "")
        if similar_rules:
            context_parts.append(f"\n{similar_rules}")
        
        final_context = "\n".join(context_parts)
        logger.debug(f"Built context string length: {len(final_context)}")
        return final_context
    
    def _parse_conversion_response(self, response: str, target_format: TargetFormat) -> Dict[str, Any]:
        """Parse Foundation-Sec-8B conversion response."""
        try:
            logger.debug(f"Parsing response for target format: {target_format}")
            logger.debug(f"Raw response length: {len(response)}")
            
            # Extract the converted rule from the response
            converted_rule = self._extract_rule_from_response(response, target_format)
            logger.debug(f"Extracted rule: {repr(converted_rule)}")
            
            # Calculate confidence based on response quality
            confidence = self._calculate_confidence(response, converted_rule)
            logger.debug(f"Calculated confidence: {confidence}")
            
            # Generate explanation
            explanation = f"Successfully converted using Foundation-Sec-8B to {target_format.value.upper()} format with {confidence:.1%} confidence"
            
            return {
                "success": True,
                "target_rule": converted_rule,
                "confidence_score": confidence,
                "explanation": explanation,
                "model_used": "Foundation-Sec-8B"
            }
            
        except Exception as e:
            logger.error(f"Failed to parse conversion response: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": f"Failed to parse response: {str(e)}",
                "error_message": str(e)
            }
    
    def _parse_qradar_conversion_response(self, response: str, target_format: TargetFormat) -> Dict[str, Any]:
        """Parse QRadar conversion response for any target format."""
        try:
            # Use the same unified extraction logic we fixed for Sigma
            converted_rule = self._extract_rule_from_response(response, target_format)
            
            # Calculate confidence based on response quality
            confidence = self._calculate_confidence(response, converted_rule)
            
            # Generate explanation
            explanation = f"QRadar rule converted to {target_format.value.upper()} using Foundation-Sec-8B with {confidence:.1%} confidence"
            
            return {
                "success": True,
                "target_rule": converted_rule,
                "confidence_score": confidence,
                "explanation": explanation,
                "model_used": "Foundation-Sec-8B"
            }
            
        except Exception as e:
            logger.error(f"Failed to parse QRadar conversion response: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": f"Failed to parse QRadar response: {str(e)}",
                "error_message": str(e)
            }
    
    def _extract_rule_from_response(self, response: str, target_format: TargetFormat) -> str:
        """Extract the converted rule from Foundation-Sec-8B response."""
        if not response or not response.strip():
            return ""
        
        import re
        
        # Try different extraction strategies in order of preference
        
        # 1. Look for format-specific code blocks
        format_patterns = {
            TargetFormat.KUSTOQL: [r'```(?:kql|kusto|kustoql)\s*\n(.*?)\n```', r'```\s*\n(.*?)\n```'],
            TargetFormat.SPL: [r'```(?:spl|splunk)\s*\n(.*?)\n```', r'```\s*\n(.*?)\n```'],
            TargetFormat.EQL: [r'```(?:eql|elastic)\s*\n(.*?)\n```', r'```\s*\n(.*?)\n```'],
            TargetFormat.SIGMA: [r'```(?:sigma|yml|yaml)\s*\n(.*?)\n```', r'```\s*\n(.*?)\n```'],
        }
        
        if target_format in format_patterns:
            for pattern in format_patterns[target_format]:
                match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        
        # 2. Extract content based on target format keywords
        if target_format == TargetFormat.KUSTOQL:
            # Look for KustoQL patterns in the response
            kusto_keywords = ['| where', '| project', '| summarize', '| join', 'DeviceProcessEvents', 
                             'SecurityEvent', 'SigninLogs', 'let ', 'search ']
            lines = [line.strip() for line in response.split('\n') if line.strip()]
            
            # Find lines with KustoQL syntax
            relevant_lines = []
            for line in lines:
                if any(keyword in line for keyword in kusto_keywords):
                    relevant_lines.append(line)
            
            if relevant_lines:
                return '\n'.join(relevant_lines)
        
        elif target_format == TargetFormat.SPL:
            # Look for Splunk SPL patterns
            spl_keywords = ['index=', 'sourcetype=', '| eval', '| stats', '| search']
            lines = [line.strip() for line in response.split('\n') if line.strip()]
            
            relevant_lines = []
            for line in lines:
                if any(keyword in line for keyword in spl_keywords):
                    relevant_lines.append(line)
            
            if relevant_lines:
                return '\n'.join(relevant_lines)
            
        # 3. Fallback: return cleaned response if it looks like code
        cleaned = response.strip()
        if len(cleaned) > 10 and any(char in cleaned for char in ['|', '{', '(', 'where', 'select']):
            return cleaned
            
        return ""
    
    def _extract_kustoql_from_response(self, response: str) -> str:
        """Extract KustoQL query from response."""
        import re
        
        # Look for KustoQL code blocks
        kusto_match = re.search(r'```(?:kql|kusto)?\s*\n(.*?)\n```', response, re.DOTALL | re.IGNORECASE)
        if kusto_match:
            return kusto_match.group(1).strip()
        
        # Look for lines that look like KustoQL
        lines = response.split('\n')
        kustoql_lines = []
        in_query = False
        
        for line in lines:
            line = line.strip()
            if any(keyword in line.lower() for keyword in ['let ', '| where', '| summarize', '| project', 'commonsecuritylog', 'securityevent', 'dnsevents']):
                in_query = True
            
            if in_query:
                kustoql_lines.append(line)
                
        return '\n'.join(kustoql_lines) if kustoql_lines else response.strip()
    
    def _calculate_confidence(self, response: str, converted_rule: str) -> float:
        """Calculate confidence score for conversion based on rule quality indicators."""
        if not converted_rule or not converted_rule.strip():
            return 0.0
        
        confidence_factors = []
        
        # Content quality factors
        rule_length = len(converted_rule.strip())
        if rule_length > 20:  # Has meaningful content
            confidence_factors.append(0.3)
        
        # Syntax quality factors based on target format patterns
        response_lower = response.lower()
        rule_lower = converted_rule.lower()
        
        # Query language indicators
        query_indicators = ['where', 'select', 'from', '|', 'project', 'summarize', 'join']
        syntax_score = sum(1 for indicator in query_indicators if indicator in rule_lower)
        if syntax_score > 0:
            confidence_factors.append(min(syntax_score * 0.1, 0.4))  # Cap at 0.4
        
        # Structure quality
        if any(structure in rule_lower for structure in ['|', 'where', 'select']):
            confidence_factors.append(0.2)
        
        # No error indicators
        error_terms = ['error', 'failed', 'invalid', 'cannot', 'unable']
        if not any(term in response_lower for term in error_terms):
            confidence_factors.append(0.1)
        
        # Calculate final confidence
        total_confidence = sum(confidence_factors)
        return min(total_confidence, 1.0)
    
    def _calculate_kustoql_confidence(self, kustoql_query: str) -> float:
        """Calculate confidence score for KustoQL conversion."""
        confidence = 0.5  # Base confidence
        
        # Check for KustoQL-specific patterns
        if '| where' in kustoql_query:
            confidence += 0.2
        if '| summarize' in kustoql_query:
            confidence += 0.15
        if '| project' in kustoql_query:
            confidence += 0.1
        if any(table in kustoql_query for table in ['SecurityEvent', 'CommonSecurityLog', 'DnsEvents']):
            confidence += 0.15
        
        return min(confidence, 1.0)


# Global LLM service instance
llm_service = FoundationSecLLMService() 