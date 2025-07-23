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
        
        # Model instances
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
        """Initialize the Foundation-Sec-8B model."""
        try:
            logger.info(f"Loading Foundation-Sec-8B model: {self.model_name}")
            
            # Determine device and dtype
            device_map = self._get_device_map(self.device)
            torch_dtype = self._get_torch_dtype(self.device)
            
            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=False  # Foundation-Sec-8B doesn't need custom code
            )
            
            # Set pad token if not present
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
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
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                **model_kwargs
            )
            
            # Create pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                torch_dtype=torch_dtype
            )
            
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
            # Check available GPU memory
            gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1e9  # GB
            # Use quantization if GPU has less than 24GB memory
            return gpu_memory < 24
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
            
            # Use cybersecurity-optimized parameters
            generation_params = {
                "max_new_tokens": max_tokens,
                "temperature": settings.llm_temperature,
                "do_sample": True,
                "pad_token_id": self.tokenizer.eos_token_id,
                "return_full_text": False,
                "repetition_penalty": 1.1,
                "top_p": 0.9
            }
            
            if use_cybersec_optimization:
                # Adjust parameters for cybersecurity tasks
                generation_params["temperature"] = 0.1  # Lower temperature for more focused output
                generation_params["top_p"] = 0.8  # Slightly more focused sampling
                generation_params["repetition_penalty"] = 1.2  # Reduce repetition
            
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
        """Build a conversion prompt for Foundation-Sec-8B."""
        context_str = ""
        if context and context.get("similar_rules"):
            context_str = f"\nRelevant context from similar rules:\n{context['similar_rules'][:500]}..."
        
        format_name = target_format.value.upper()
        
        prompt = f"""You are a cybersecurity expert specializing in SIEM rule conversion. Convert this Sigma detection rule to {format_name} format.

Input Sigma Rule:
{sigma_rule}
{context_str}

Generate a high-quality {format_name} rule that:
1. Preserves the original detection logic
2. Uses appropriate {format_name} syntax and functions
3. Maintains the same security effectiveness
4. Includes proper field mappings

Output the converted {format_name} rule:"""

        return prompt
    
    def _build_qradar_conversion_prompt(self, qradar_rule: str, target_format: TargetFormat, context: Optional[Dict[str, Any]] = None) -> str:
        """Build a QRadar conversion prompt for Foundation-Sec-8B."""
        context_str = ""
        if context and context.get("similar_rules"):
            context_str = f"\nRelevant context from similar rules:\n{context['similar_rules'][:500]}..."
        
        format_name = target_format.value.upper()
        
        # Format-specific guidance
        format_guidance = {
            "KUSTOQL": "Uses Azure Sentinel tables (SecurityEvent, CommonSecurityLog, etc.) with KustoQL syntax",
            "SIGMA": "Uses Sigma detection rule format with proper field mappings",
            "SPL": "Uses Splunk Processing Language with appropriate data models",
            "EQL": "Uses Event Query Language with proper event correlation",
            "AQL": "Uses IBM QRadar AQL (optimization/validation)"
        }
        
        guidance = format_guidance.get(format_name, f"Uses {format_name} query language syntax")
        
        prompt = f"""You are a cybersecurity expert specializing in SIEM rule conversion. Convert this QRadar rule to {format_name} format.

Input QRadar Rule:
{qradar_rule}
{context_str}

Convert this QRadar rule to a production-ready {format_name} query that:
1. Preserves the original detection logic and thresholds
2. {guidance}
3. Implements proper syntax with correct operators
4. Maintains the same security effectiveness and alert conditions
5. Includes time windows, aggregations, and filtering as needed

Generate the complete {format_name} query:"""

        return prompt
    
    def _parse_conversion_response(self, response: str, target_format: TargetFormat) -> Dict[str, Any]:
        """Parse Foundation-Sec-8B conversion response."""
        try:
            # Extract the converted rule from the response
            converted_rule = self._extract_rule_from_response(response, target_format)
            
            # Calculate confidence based on response quality
            confidence = self._calculate_confidence(response, converted_rule)
            
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
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": f"Failed to parse response: {str(e)}",
                "error_message": str(e)
            }
    
    def _parse_qradar_conversion_response(self, response: str) -> Dict[str, Any]:
        """Parse QRadar to KustoQL conversion response."""
        try:
            # Extract KustoQL query from response
            kustoql_query = self._extract_kustoql_from_response(response)
            
            # Calculate confidence
            confidence = self._calculate_kustoql_confidence(kustoql_query)
            
            # Generate explanation
            explanation = f"QRadar rule converted to KustoQL using Foundation-Sec-8B with {confidence:.1%} confidence"
            
            return {
                "success": True,
                "target_rule": kustoql_query,
                "confidence_score": confidence,
                "explanation": explanation,
                "model_used": "Foundation-Sec-8B"
            }
            
        except Exception as e:
            logger.error(f"Failed to parse QRadar conversion response: {e}")
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": f"Failed to parse QRadar response: {str(e)}",
                "error_message": str(e)
            }
    
    def _extract_rule_from_response(self, response: str, target_format: TargetFormat) -> str:
        """Extract the converted rule from Foundation-Sec-8B response."""
        # Look for code blocks first
        import re
        
        # Format-specific patterns
        if target_format == TargetFormat.KUSTOQL:
            # Look for KustoQL patterns
            kusto_match = re.search(r'```(?:kql|kusto)?\s*\n(.*?)\n```', response, re.DOTALL | re.IGNORECASE)
            if kusto_match:
                return kusto_match.group(1).strip()
        
        # Generic code block extraction
        code_match = re.search(r'```\s*\n(.*?)\n```', response, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()
        
        # Fall back to the entire response if no code blocks found
        return response.strip()
    
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
        """Calculate confidence score for conversion."""
        confidence = 0.6  # Base confidence
        
        # Check for quality indicators
        if len(converted_rule) > 50:
            confidence += 0.1
        
        if any(keyword in response.lower() for keyword in ['where', 'select', 'from', '|']):
            confidence += 0.2
        
        if "error" not in response.lower() and "failed" not in response.lower():
            confidence += 0.1
        
        return min(confidence, 1.0)
    
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