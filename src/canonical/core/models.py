"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Core data models for the Canonical SIEM rule converter.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class SourceFormat(str, Enum):
    """Supported source rule formats."""
    SIGMA = "sigma"


class TargetFormat(str, Enum):
    """Supported target rule formats."""
    KUSTOQL = "kustoql"
    KIBANAQL = "kibanaql"
    EQL = "eql"
    QRADAR = "qradar"
    SPL = "spl"


class SigmaRule(BaseModel):
    """Sigma rule structure."""
    title: str
    id: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    modified: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    logsource: Dict[str, Any] = Field(default_factory=dict)
    detection: Dict[str, Any] = Field(default_factory=dict)
    fields: List[str] = Field(default_factory=list)
    falsepositives: List[str] = Field(default_factory=list)
    level: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    
    # Computed properties
    mitre_techniques: List[str] = Field(default_factory=list)
    complexity: str = "medium"
    is_valid: bool = True


class ConversionRequest(BaseModel):
    """Request model for rule conversion."""
    source_rule: str = Field(..., description="Source rule content")
    source_format: SourceFormat = Field(..., description="Source rule format")
    target_format: TargetFormat = Field(..., description="Target rule format")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Additional context for conversion")
    options: Optional[Dict[str, Any]] = Field(default=None, description="Conversion options")


class ConversionResponse(BaseModel):
    """Response model for rule conversion."""
    success: bool = Field(..., description="Whether conversion was successful")
    target_rule: Optional[str] = Field(None, description="Converted rule content")
    confidence_score: Optional[float] = Field(None, description="Confidence score of the conversion")
    explanation: Optional[str] = Field(None, description="Explanation of the conversion process")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK techniques")
    error_message: Optional[str] = Field(None, description="Error message if conversion failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique model."""
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    detection: Optional[str] = None
    mitigation: Optional[str] = None


class MitreSoftware(BaseModel):
    """MITRE ATT&CK software model."""
    software_id: str
    name: str
    description: str
    type: str  # malware, tool
    platforms: List[str]
    techniques: List[str]


class MitreGroup(BaseModel):
    """MITRE ATT&CK group model."""
    group_id: str
    name: str
    description: str
    aliases: List[str]
    techniques: List[str]
    software: List[str]


class AtomicTest(BaseModel):
    """Atomic Red Team test model."""
    technique: str
    test_number: int
    test_name: str
    description: str
    supported_platforms: List[str]
    executor: Dict[str, Any]
    input_arguments: Dict[str, Any] = Field(default_factory=dict)
    dependencies: List[Dict[str, Any]] = Field(default_factory=list)


class CARAnalytic(BaseModel):
    """MITRE CAR analytic model."""
    car_id: str
    title: str
    description: str
    mitre_techniques: List[str]
    data_model: List[str]
    implementations: List[Dict[str, Any]] = Field(default_factory=list)
    unit_tests: List[Dict[str, Any]] = Field(default_factory=list) 