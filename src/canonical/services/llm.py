"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Enhanced LLM service supporting Foundation-Sec-8B and Qwen with intelligent fallback.
"""

import asyncio
from typing import List, Dict, Any, Optional
import json
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
import torch
from loguru import logger

from ..core.config import settings
from ..core.models import TargetFormat


class EnhancedLLMService:
    """Enhanced language model service supporting Foundation-Sec-8B and Qwen fallback."""
    
    def __init__(self, primary_model: Optional[str] = None, fallback_model: Optional[str] = None, device: Optional[str] = None):
        """Initialize the enhanced LLM service.
        
        Args:
            primary_model: Primary model name (Foundation-Sec-8B by default)
            fallback_model: Fallback model name (Qwen by default)
            device: Device to run the model on ('auto', 'cpu', 'cuda', 'mps')
        """
        # Model configuration
        self.use_foundation_sec = settings.use_foundation_sec
        self.enable_fallback = settings.enable_model_fallback
        
        # Primary model (Foundation-Sec-8B)
        self.primary_model_name = primary_model or settings.llm_model
        self.primary_device = device or settings.llm_device
        
        # Fallback model (Qwen)
        self.fallback_model_name = fallback_model or settings.qwen_model
        self.fallback_device = settings.qwen_device
        
        # Model instances
        self.primary_tokenizer = None
        self.primary_model = None
        self.primary_pipeline = None
        
        self.fallback_tokenizer = None
        self.fallback_model = None
        self.fallback_pipeline = None
        
        # State tracking
        self.primary_initialized = False
        self.fallback_initialized = False
        self.current_model = None
        self.model_capabilities = {}
        
    async def initialize(self) -> None:
        """Initialize the LLM service with intelligent model selection."""
        try:
            if self.use_foundation_sec:
                await self._initialize_primary_model()
            
            # Always try to initialize fallback if enabled
            if self.enable_fallback:
                await self._initialize_fallback_model()
                
            # Set current model
            if self.primary_initialized:
                self.current_model = "foundation-sec-8b"
                logger.info("Using Foundation-Sec-8B as primary model")
            elif self.fallback_initialized:
                self.current_model = "qwen"
                logger.info("Using Qwen as fallback model")
            else:
                raise RuntimeError("No models successfully initialized")
                
        except Exception as e:
            logger.error(f"Failed to initialize LLM service: {e}")
            raise
    
    async def _initialize_primary_model(self) -> None:
        """Initialize Foundation-Sec-8B model."""
        try:
            logger.info(f"Loading Foundation-Sec-8B model: {self.primary_model_name}")
            
            # Determine device and dtype
            device_map = self._get_device_map(self.primary_device)
            torch_dtype = self._get_torch_dtype(self.primary_device)
            
            # Load tokenizer
            self.primary_tokenizer = AutoTokenizer.from_pretrained(
                self.primary_model_name,
                trust_remote_code=False  # Foundation-Sec-8B doesn't need custom code
            )
            
            # Set pad token if not exists
            if self.primary_tokenizer.pad_token is None:
                self.primary_tokenizer.pad_token = self.primary_tokenizer.eos_token
            
            # Load model with optimization
            model_kwargs = {
                "torch_dtype": torch_dtype,
                "device_map": device_map,
                "trust_remote_code": False,
                # "attn_implementation": "flash_attention_2" if self._supports_flash_attention() else "eager"  # Disabled for compatibility
            }
            
            # Add quantization if needed for memory efficiency
            if self._should_use_quantization():
                from transformers import BitsAndBytesConfig
                model_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_compute_dtype=torch_dtype,
                    bnb_4bit_use_double_quant=True
                )
                logger.info("Using 4-bit quantization for memory efficiency")
            
            self.primary_model = AutoModelForCausalLM.from_pretrained(
                self.primary_model_name,
                **model_kwargs
            )
            
            # Create pipeline
            self.primary_pipeline = pipeline(
                "text-generation",
                model=self.primary_model,
                tokenizer=self.primary_tokenizer,
                torch_dtype=torch_dtype,
                device_map=device_map
            )
            
            self.primary_initialized = True
            self.model_capabilities["foundation-sec-8b"] = {
                "cybersecurity_specialized": True,
                "mitre_attack_knowledge": True,
                "vulnerability_mapping": True,
                "threat_intelligence": True,
                "rule_conversion_optimized": True
            }
            
            logger.info(f"Foundation-Sec-8B loaded successfully on {self.primary_device}")
            
        except Exception as e:
            logger.error(f"Failed to load Foundation-Sec-8B: {e}")
            if not self.enable_fallback:
                raise
            logger.info("Will attempt fallback to Qwen model")
    
    async def _initialize_fallback_model(self) -> None:
        """Initialize Qwen fallback model."""
        try:
            logger.info(f"Loading Qwen fallback model: {self.fallback_model_name}")
            
            # Load tokenizer
            self.fallback_tokenizer = AutoTokenizer.from_pretrained(
                self.fallback_model_name,
                trust_remote_code=True
            )
            
            # Load model
            torch_dtype = torch.float16 if self.fallback_device == "cuda" else torch.float32
            self.fallback_model = AutoModelForCausalLM.from_pretrained(
                self.fallback_model_name,
                torch_dtype=torch_dtype,
                device_map="auto" if self.fallback_device == "cuda" else None,
                trust_remote_code=True
            )
            
            # Create pipeline
            self.fallback_pipeline = pipeline(
                "text-generation",
                model=self.fallback_model,
                tokenizer=self.fallback_tokenizer,
                torch_dtype=torch_dtype
            )
            
            self.fallback_initialized = True
            self.model_capabilities["qwen"] = {
                "cybersecurity_specialized": False,
                "general_language": True,
                "rule_conversion_basic": True
            }
            
            logger.info(f"Qwen fallback model loaded successfully on {self.fallback_device}")
            
        except Exception as e:
            logger.error(f"Failed to load Qwen fallback model: {e}")
            if not self.primary_initialized:
                raise
    
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
        """Generate a response using the best available model.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum number of tokens to generate
            use_cybersec_optimization: Whether to use cybersecurity-optimized settings
            
        Returns:
            Generated response
        """
        if not (self.primary_initialized or self.fallback_initialized):
            await self.initialize()
        
        # Choose model based on task and availability
        if self.primary_initialized and (use_cybersec_optimization or not self.fallback_initialized):
            return await self._generate_with_primary(prompt, max_tokens)
        elif self.fallback_initialized:
            return await self._generate_with_fallback(prompt, max_tokens)
        else:
            raise RuntimeError("No models available for generation")
    
    async def _generate_with_primary(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Generate response with Foundation-Sec-8B."""
        try:
            max_tokens = max_tokens or settings.llm_max_tokens
            
            # Run generation in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.primary_pipeline(
                    prompt,
                    max_new_tokens=max_tokens,
                    temperature=settings.llm_temperature,
                    do_sample=True,
                    pad_token_id=self.primary_tokenizer.eos_token_id,
                    return_full_text=False,
                    repetition_penalty=1.1,
                    top_p=0.9
                )
            )
            
            return result[0]["generated_text"].strip()
            
        except Exception as e:
            logger.error(f"Failed to generate with Foundation-Sec-8B: {e}")
            if self.fallback_initialized and self.enable_fallback:
                logger.info("Falling back to Qwen model")
                return await self._generate_with_fallback(prompt, max_tokens)
            raise
    
    async def _generate_with_fallback(self, prompt: str, max_tokens: Optional[int] = None) -> str:
        """Generate response with Qwen fallback."""
        try:
            max_tokens = max_tokens or settings.qwen_max_tokens
            
            # Run generation in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self.fallback_pipeline(
                    prompt,
                    max_new_tokens=max_tokens,
                    temperature=settings.qwen_temperature,
                    do_sample=True,
                    pad_token_id=self.fallback_tokenizer.eos_token_id,
                    return_full_text=False
                )
            )
            
            return result[0]["generated_text"].strip()
            
        except Exception as e:
            logger.error(f"Failed to generate with Qwen fallback: {e}")
            raise
    
    async def convert_sigma_rule(
        self, 
        sigma_rule: str, 
        target_format: TargetFormat,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert a Sigma rule to the target format using cybersecurity optimization.
        
        Args:
            sigma_rule: Sigma rule content
            target_format: Target format to convert to
            context: Additional context for conversion
            
        Returns:
            Conversion result with rule, confidence, and explanation
        """
        prompt = self._build_conversion_prompt(sigma_rule, target_format, context)
        
        try:
            # Use cybersecurity optimization for better results
            response = await self.generate_response(prompt, use_cybersec_optimization=True)
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
    
    async def convert_qradar_to_kustoql(
        self, 
        qradar_rule: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert a QRadar rule to KustoQL using cybersecurity optimization.
        
        Args:
            qradar_rule: QRadar rule content
            context: Additional context for conversion including Azure Sentinel examples
            
        Returns:
            Conversion result with KustoQL rule, confidence, and explanation
        """
        prompt = self._build_qradar_to_kustoql_prompt(qradar_rule, context)
        
        try:
            # Use cybersecurity optimization for better results
            response = await self.generate_response(prompt, use_cybersec_optimization=True)
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
    
    def _build_conversion_prompt(
        self, 
        sigma_rule: str, 
        target_format: TargetFormat,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the conversion prompt optimized for Foundation-Sec-8B.
        
        Args:
            sigma_rule: Sigma rule content
            target_format: Target format
            context: Additional context
            
        Returns:
            Formatted prompt optimized for cybersecurity models
        """
        # Enhanced prompts for Foundation-Sec-8B
        cybersec_context = ""
        if self.current_model == "foundation-sec-8b":
            cybersec_context = """
As a cybersecurity-specialized model, consider:
- MITRE ATT&CK technique mappings
- Common attack patterns and TTPs
- Field standardization across SIEM platforms
- Security context and threat intelligence

MULTI-TABLE POLICY:
• If context shows multiple tables for the SAME logical_source:
  – mode: "union"  → return ONE analytic rule whose KQL uses `union isfuzzy=true TableA, TableB`.
  – mode: "split"  → return SEPARATE YAML blocks, one per table, no `union`.
  – If only one table present → ignore mode, behave normally.
• Analyze metadata, schema relationships, and security context to intelligently decide between union/split.
• Base decisions on: logical relationships, query complexity, field overlap, security context, best practices.

STRICT GROUNDING:
Base every answer ONLY on retrieved context (<CTX>).
If information is missing, reply exactly "NO MAPPING".
"""
        
        format_descriptions = {
            TargetFormat.KUSTOQL: "KustoQL (Azure Data Explorer/Sentinel)",
            TargetFormat.KIBANAQL: "Kibana Query Language (Elastic)",
            TargetFormat.EQL: "Event Query Language (Elastic)",
            TargetFormat.QRADAR: "QRadar AQL (IBM)",
            TargetFormat.SPL: "Splunk Processing Language"
        }
        
        # Rest of the existing prompt building logic...
        context_info = ""
        if context:
            if "mitre_techniques" in context:
                context_info += f"\nMITRE ATT&CK Techniques: {', '.join(context['mitre_techniques'])}"
            if "similar_rules" in context:
                context_info += f"\nSimilar rules found: {len(context['similar_rules'])}"
            if "retrieved_context" in context:
                context_info += f"\n<CTX>\n{context['retrieved_context']}\n</CTX>"
        
        prompt = f"""You are an expert SIEM rule converter with deep cybersecurity knowledge. Convert the following Sigma rule to {format_descriptions[target_format]}.

{cybersec_context}

Sigma Rule:
```yaml
{sigma_rule}
```

Target Format: {target_format.value.upper()}
{context_info}

Instructions:
1. Analyze the Sigma rule structure and detection logic
2. Map Sigma fields to the target format's field names
3. Convert conditions and operators appropriately
4. Maintain the detection logic and intent
5. Apply cybersecurity best practices and Multi-Table Policy
6. Provide a confidence score (0.0-1.0)
7. Explain the conversion process and multi-table decisions

OUTPUT FORMAT:
Return valid YAML; each rule block must include:
rule_name, kusto_query, required_tables, tactics (ATT&CK), techniques, severity.

If multiple tables detected for same logical_source, decide intelligently:
- Union mode: Single rule with `union isfuzzy=true TableA, TableB`
- Split mode: Separate YAML blocks per table

Respond in JSON format:
{{
    "success": true,
    "target_rule": "converted rule here",
    "confidence_score": 0.95,
    "explanation": "Detailed explanation including multi-table decision rationale",
    "field_mappings": {{"sigma_field": "target_field"}},
    "required_tables": ["SecurityEvent"],
    "multi_table_mode": "union|split|single",
    "multi_table_rationale": "Explanation of union/split decision",
    "notes": "Important notes"
}}

Response:"""
        
        return prompt
    
    def _build_qradar_to_kustoql_prompt(
        self, 
        qradar_rule: str, 
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build the QRadar to KustoQL conversion prompt optimized for Foundation-Sec-8B."""
        
        cybersec_context = ""
        if self.current_model == "foundation-sec-8b":
            cybersec_context = """
As a cybersecurity-specialized model with deep knowledge of:
- QRadar rule patterns and correlation logic
- Azure Sentinel/KustoQL query structure
- SIEM field mapping and normalization
- Threat detection methodologies

MULTI-TABLE POLICY:
• If context shows multiple tables for the SAME logical_source:
  – mode: "union"  → return ONE analytic rule whose KQL uses `union isfuzzy=true TableA, TableB`.
  – mode: "split"  → return SEPARATE YAML blocks, one per table, no `union`.
  – If only one table present → ignore mode, behave normally.
• Analyze metadata, schema relationships, and security context to intelligently decide between union/split.
• Base decisions on: logical relationships, query complexity, field overlap, security context, best practices.

STRICT GROUNDING:
Base every answer ONLY on retrieved context (<CTX>).
If information is missing, reply exactly "NO MAPPING".
"""
        
        context_info = ""
        if context:
            if "mitre_techniques" in context:
                context_info += f"\nMITRE ATT&CK Techniques: {', '.join(context['mitre_techniques'])}"
            if "similar_rules" in context:
                context_info += f"\nSimilar rules found: {len(context['similar_rules'])}"
            if "retrieved_context" in context:
                context_info += f"\n<CTX>\n{context['retrieved_context']}\n</CTX>"
        
        prompt = f"""You are an expert SIEM rule converter specializing in QRadar to Azure Sentinel migrations.

{cybersec_context}

QRadar Rule to Convert:
```
{qradar_rule}
```
{context_info}

Convert this QRadar rule to KustoQL using cybersecurity best practices and proper field mappings.
Apply the Multi-Table Policy intelligently based on the context and metadata.

OUTPUT FORMAT:
Return valid YAML; each rule block must include:
rule_name, kusto_query, required_tables, tactics (ATT&CK), techniques, severity.

If multiple tables detected for same logical_source, decide intelligently:
- Union mode: Single rule with `union isfuzzy=true TableA, TableB`
- Split mode: Separate YAML blocks per table

Respond in JSON format:
{{
    "success": true,
    "target_rule": "// Converted KustoQL rule\\nSecurityEvent\\n| where ...",
    "confidence_score": 0.85,
    "explanation": "Detailed conversion explanation including multi-table decision rationale",
    "field_mappings": {{"qradar_field": "kustoql_field"}},
    "required_tables": ["SecurityEvent"],
    "multi_table_mode": "union|split|single",
    "multi_table_rationale": "Explanation of union/split decision",
    "notes": "Important notes"
}}

Response:"""
        
        return prompt
    
    def _parse_conversion_response(self, response: str, target_format: TargetFormat) -> Dict[str, Any]:
        """Parse the LLM response for conversion results."""
        try:
            # Clean up the response
            cleaned_response = response.strip()
            
            # Remove markdown code blocks
            import re
            cleaned_response = re.sub(r'```json\s*', '', cleaned_response)
            cleaned_response = re.sub(r'```\s*', '', cleaned_response)
            
            # Try to parse JSON
            try:
                result = json.loads(cleaned_response)
                
                # Validate and clean up fields
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
                # Fallback: extract rule from response
                return {
                    "success": True,
                    "target_rule": cleaned_response,
                    "confidence_score": 0.3,
                    "explanation": "Rule extracted from unstructured response",
                    "field_mappings": {},
                    "notes": "Response format was not structured"
                }
                
        except Exception as e:
            logger.warning(f"Failed to parse conversion response: {e}")
            return {
                "success": False,
                "target_rule": None,
                "confidence_score": 0.0,
                "explanation": "Failed to parse LLM response",
                "error_message": str(e)
            }
    
    async def explain_rule(self, rule: str, rule_format: str) -> str:
        """Explain what a rule does in natural language using cybersecurity expertise."""
        prompt = f"""Explain the following {rule_format} security rule using your cybersecurity expertise:

Rule:
```
{rule}
```

Provide a clear explanation covering:
1. What type of activity this rule detects
2. Key indicators or patterns it looks for
3. Potential threats or attack techniques (MITRE ATT&CK)
4. Security implications and context

Explanation:"""
        
        return await self.generate_response(prompt, max_tokens=512, use_cybersec_optimization=True)


# Global LLM service instance - now using Enhanced LLM Service
llm_service = EnhancedLLMService() 