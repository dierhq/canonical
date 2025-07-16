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
    QRADAR = "qradar"
    KIBANAQL = "kibanaql"


class TargetFormat(str, Enum):
    """Supported target rule formats."""
    KUSTOQL = "kustoql"
    KIBANAQL = "kibanaql"
    EQL = "eql"
    QRADAR = "qradar"
    SPL = "spl"
    SIGMA = "sigma"


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


class QRadarRule(BaseModel):
    """QRadar rule structure."""
    rule_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    rule_type: str  # "EVENT", "FLOW", "OFFENSE", "COMMON"
    enabled: bool = True
    tests: List[Dict[str, Any]] = Field(default_factory=list)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    responses: List[Dict[str, Any]] = Field(default_factory=list)
    groups: List[str] = Field(default_factory=list)
    severity: Optional[int] = None
    credibility: Optional[int] = None
    relevance: Optional[int] = None
    category: Optional[str] = None
    origin: Optional[str] = None
    username: Optional[str] = None
    creation_date: Optional[str] = None
    modification_date: Optional[str] = None
    
    # Extracted metadata
    mitre_techniques: List[str] = Field(default_factory=list)
    complexity: str = "medium"
    is_valid: bool = True


class AzureSentinelDetection(BaseModel):
    """Azure Sentinel detection rule structure."""
    rule_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    severity: str  # "Low", "Medium", "High", "Critical"
    query: Optional[str] = ""
    query_frequency: Optional[str] = None
    query_period: Optional[str] = None
    trigger_operator: Optional[str] = None
    trigger_threshold: Optional[int] = None
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    display_name: Optional[str] = None
    enabled: bool = True
    suppression_enabled: bool = False
    suppression_duration: Optional[str] = None
    event_grouping: Optional[Dict[str, Any]] = None
    alert_details_override: Optional[Dict[str, Any]] = None
    custom_details: Optional[Dict[str, Any]] = None
    entity_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metadata
    author: Optional[str] = None
    created_date: Optional[str] = None
    last_modified: Optional[str] = None
    version: Optional[str] = None
    source: str = "Azure Sentinel"
    
    # Extracted metadata
    mitre_techniques: List[str] = Field(default_factory=list)
    complexity: str = "medium"
    is_valid: bool = True


class AzureSentinelHuntingQuery(BaseModel):
    """Azure Sentinel hunting query structure."""
    query_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    query: Optional[str] = ""
    data_types: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    required_data_connectors: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Metadata
    author: Optional[str] = None
    created_date: Optional[str] = None
    last_modified: Optional[str] = None
    version: Optional[str] = None
    source: str = "Azure Sentinel"
    
    # Extracted metadata
    mitre_techniques: List[str] = Field(default_factory=list)
    complexity: str = "medium"
    is_valid: bool = True


class KibanaQLRule(BaseModel):
    """Kibana Query Language (KQL) rule structure."""
    rule_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    query: str
    index_patterns: List[str] = Field(default_factory=list)
    query_type: str = "query"  # "query", "eql", "threshold", "machine_learning"
    language: str = "kuery"  # "kuery", "lucene", "eql"
    
    # Rule configuration
    enabled: bool = True
    severity: str = "medium"  # "low", "medium", "high", "critical"
    risk_score: Optional[int] = None
    tags: List[str] = Field(default_factory=list)
    
    # Time-based settings
    interval: Optional[str] = None  # e.g., "5m", "1h"
    from_time: Optional[str] = None  # e.g., "now-6m"
    to_time: Optional[str] = None  # e.g., "now"
    
    # Threshold settings (for threshold rules)
    threshold_field: Optional[str] = None
    threshold_value: Optional[int] = None
    threshold_cardinality: Optional[List[Dict[str, Any]]] = None
    
    # ML settings (for machine learning rules)
    anomaly_threshold: Optional[int] = None
    machine_learning_job_id: Optional[str] = None
    
    # Actions and notifications
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    throttle: Optional[str] = None
    
    # Metadata
    author: Optional[str] = None
    created_date: Optional[str] = None
    last_modified: Optional[str] = None
    version: Optional[str] = None
    license: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    false_positives: List[str] = Field(default_factory=list)
    
    # MITRE ATT&CK mapping
    threat: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Extracted metadata
    mitre_techniques: List[str] = Field(default_factory=list)
    complexity: str = "medium"
    is_valid: bool = True 


class EnvironmentColumn(BaseModel):
    """Environment table column definition."""
    name: str = Field(..., description="Column name")
    type: str = Field(..., description="Column data type (string, int, datetime, dynamic, etc.)")
    description: Optional[str] = Field(None, description="Column description")
    is_nullable: bool = Field(True, description="Whether column can be null")
    max_length: Optional[int] = Field(None, description="Maximum length for string columns")
    default_value: Optional[str] = Field(None, description="Default value")


class EnvironmentTable(BaseModel):
    """Environment table definition."""
    name: str = Field(..., description="Table name")
    columns: List[EnvironmentColumn] = Field(..., description="Table columns")
    description: Optional[str] = Field(None, description="Table description")
    retention_in_days: Optional[int] = Field(None, description="Data retention period in days")
    category: Optional[str] = Field(None, description="Table category (Security, Network, etc.)")
    data_source: Optional[str] = Field(None, description="Data source name")
    ingestion_frequency: Optional[str] = Field(None, description="How often data is ingested")
    
    def get_column_by_name(self, name: str) -> Optional[EnvironmentColumn]:
        """Get column by name (case-insensitive)."""
        for column in self.columns:
            if column.name.lower() == name.lower():
                return column
        return None
    
    def has_column(self, name: str) -> bool:
        """Check if table has a column (case-insensitive)."""
        return self.get_column_by_name(name) is not None
    
    def get_columns_by_type(self, column_type: str) -> List[EnvironmentColumn]:
        """Get all columns of a specific type."""
        return [col for col in self.columns if col.type.lower() == column_type.lower()]


class EnvironmentSchema(BaseModel):
    """Complete environment schema definition."""
    name: str = Field(..., description="Schema name")
    version: str = Field("1.0", description="Schema version")
    description: Optional[str] = Field(None, description="Schema description")
    platform: str = Field(..., description="Platform (Azure Sentinel, Splunk, QRadar, etc.)")
    tables: List[EnvironmentTable] = Field(..., description="Tables in the schema")
    created_date: Optional[str] = Field(None, description="Schema creation date")
    last_modified: Optional[str] = Field(None, description="Last modification date")
    author: Optional[str] = Field(None, description="Schema author")
    
    def get_table_by_name(self, name: str) -> Optional[EnvironmentTable]:
        """Get table by name (case-insensitive)."""
        for table in self.tables:
            if table.name.lower() == name.lower():
                return table
        return None
    
    def has_table(self, name: str) -> bool:
        """Check if schema has a table (case-insensitive)."""
        return self.get_table_by_name(name) is not None
    
    def find_tables_with_column(self, column_name: str) -> List[EnvironmentTable]:
        """Find all tables that have a specific column."""
        return [table for table in self.tables if table.has_column(column_name)]
    
    def get_table_names(self) -> List[str]:
        """Get all table names."""
        return [table.name for table in self.tables]
    
    def get_column_mapping(self) -> Dict[str, List[str]]:
        """Get mapping of column names to tables that contain them."""
        mapping = {}
        for table in self.tables:
            for column in table.columns:
                if column.name not in mapping:
                    mapping[column.name] = []
                mapping[column.name].append(table.name)
        return mapping


class SchemaIngestionRequest(BaseModel):
    """Request model for schema ingestion."""
    schema_path: str = Field(..., description="Path to schema JSON file")
    schema_name: Optional[str] = Field(None, description="Optional custom schema name")
    overwrite: bool = Field(False, description="Whether to overwrite existing schema")


class SchemaIngestionResponse(BaseModel):
    """Response model for schema ingestion."""
    success: bool = Field(..., description="Whether ingestion was successful")
    schema_name: str = Field(..., description="Name of the ingested schema")
    tables_count: int = Field(..., description="Number of tables ingested")
    columns_count: int = Field(..., description="Total number of columns ingested")
    message: str = Field(..., description="Success or error message")
    error_details: Optional[str] = Field(None, description="Detailed error information")


class FieldMappingResult(BaseModel):
    """Result of field mapping operation."""
    source_field: str = Field(..., description="Original field name")
    target_field: str = Field(..., description="Mapped field name")
    table_name: str = Field(..., description="Table containing the field")
    confidence_score: float = Field(..., description="Confidence score (0.0 to 1.0)")
    field_type: str = Field(..., description="Data type of the field")
    mapping_reason: str = Field(..., description="Reason for the mapping")


class SchemaValidationResult(BaseModel):
    """Result of schema validation against converted rule."""
    is_valid: bool = Field(..., description="Whether the rule is valid against schema")
    table_validations: List[Dict[str, Any]] = Field(default_factory=list, description="Table-level validations")
    field_validations: List[Dict[str, Any]] = Field(default_factory=list, description="Field-level validations")
    missing_tables: List[str] = Field(default_factory=list, description="Tables referenced but not found")
    missing_fields: List[str] = Field(default_factory=list, description="Fields referenced but not found")
    type_mismatches: List[Dict[str, Any]] = Field(default_factory=list, description="Data type mismatches")
    suggestions: List[str] = Field(default_factory=list, description="Suggestions for improvement")
    warnings: List[str] = Field(default_factory=list, description="Non-critical warnings") 