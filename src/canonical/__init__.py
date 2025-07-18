"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Canonical - Intelligent SIEM Rule Converter

An intelligent system for converting security rules between different SIEM formats,
leveraging LangGraph, BGE embeddings, Qwen LLM, and ChromaDB for robust rule transformation.
"""

__version__ = "0.1.0"
__author__ = "Canonical Team"
__email__ = "team@canonical.dev"

from .core.converter import RuleConverter
from .core.models import ConversionRequest, ConversionResponse
from .api.main import app

__all__ = [
    "RuleConverter",
    "ConversionRequest", 
    "ConversionResponse",
    "app",
] 