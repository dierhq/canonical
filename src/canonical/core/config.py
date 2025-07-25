"""
Copyright (c) 2025 DIER

This software is proprietary and confidential. Unauthorized copying, distribution, 
or use of this software is strictly prohibited. This software is provided for 
internal use only within organizations for cybersecurity purposes.

For licensing inquiries, contact: licensing@dier.org
"""

"""
Configuration management for the Canonical SIEM rule converter.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    # Application settings
    app_name: str = "Canonical SIEM Rule Converter"
    app_version: str = "0.1.0"
    debug: bool = Field(default=False, env="DEBUG")
    
    # API settings
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=1, env="API_WORKERS")
    
    # ChromaDB settings
    chromadb_host: str = Field(default="localhost", env="CHROMADB_HOST")
    chromadb_port: int = Field(default=8000, env="CHROMADB_PORT")
    chromadb_path: str = Field(default="./data/persistent/chromadb", env="CHROMADB_PATH")
    
    # Collection names
    sigma_collection: str = Field(default="sigma_rules", env="SIGMA_COLLECTION")
    mitre_collection: str = Field(default="mitre_attack", env="MITRE_COLLECTION")
    car_collection: str = Field(default="mitre_car", env="CAR_COLLECTION")
    atomic_collection: str = Field(default="atomic_red_team", env="ATOMIC_COLLECTION")
    azure_sentinel_detections_collection: str = Field(default="azure_sentinel_detections", env="AZURE_SENTINEL_DETECTIONS_COLLECTION")
    azure_sentinel_hunting_collection: str = Field(default="azure_sentinel_hunting", env="AZURE_SENTINEL_HUNTING_COLLECTION")
    qradar_collection: str = Field(default="qradar_rules", env="QRADAR_COLLECTION")
    qradar_docs_collection: str = Field(default="qradar_docs", env="QRADAR_DOCS_COLLECTION")
    
    # Embedding model settings
    embedding_model: str = Field(default="text-embedding-3-large", env="EMBEDDING_MODEL")
    
    # LLM Provider settings (replaces Foundation-Sec-8B)
    llm_provider: str = Field(default="openai", env="LLM_PROVIDER")  # openai, azure, local
    llm_model: str = Field(default="gpt-4o", env="LLM_MODEL")
    llm_max_tokens: int = Field(default=4096, env="LLM_MAX_TOKENS")
    llm_temperature: float = Field(default=0.1, env="LLM_TEMPERATURE")
    
    # OpenAI settings
    openai_api_key: str = Field(default="", env="OPENAI_API_KEY")
    openai_base_url: str = Field(default="https://api.openai.com/v1", env="OPENAI_BASE_URL")
    
    # Azure OpenAI settings
    azure_openai_endpoint: str = Field(default="", env="AZURE_OPENAI_ENDPOINT")
    azure_openai_key: str = Field(default="", env="AZURE_OPENAI_KEY")
    azure_openai_version: str = Field(default="2024-10-21", env="AZURE_OPENAI_VERSION")
    azure_openai_deployment: str = Field(default="gpt-4o", env="AZURE_OPENAI_DEPLOYMENT")
    
    # Data sources
    sigma_repo_url: str = Field(
        default="https://github.com/SigmaHQ/sigma.git",
        env="SIGMA_REPO_URL"
    )
    mitre_attack_url: str = Field(
        default="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        env="MITRE_ATTACK_URL"
    )
    car_repo_url: str = Field(
        default="https://github.com/mitre-attack/car.git",
        env="CAR_REPO_URL"
    )
    atomic_repo_url: str = Field(
        default="https://github.com/redcanaryco/atomic-red-team.git",
        env="ATOMIC_REPO_URL"
    )
    azure_sentinel_repo_url: str = Field(
        default="https://github.com/Azure/Azure-Sentinel.git",
        env="AZURE_SENTINEL_REPO_URL"
    )
    
    # Data directories
    data_dir: Path = Field(default=Path("./data"), env="DATA_DIR")
    repos_dir: Path = Field(default=Path("./data/repos"), env="REPOS_DIR")
    cache_dir: Path = Field(default=Path("./data/persistent/cache"), env="CACHE_DIR")
    
    # Logging settings
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    # Performance settings
    max_concurrent_requests: int = Field(default=10, env="MAX_CONCURRENT_REQUESTS")
    request_timeout: int = Field(default=300, env="REQUEST_TIMEOUT")
    
    # Rule Enhancement Settings
    ENABLE_RULE_ENHANCEMENT: bool = Field(
        default=True, 
        description="Enable universal rule enhancement preprocessing"
    )
    ENHANCEMENT_SKIP_STRUCTURED: bool = Field(
        default=True,
        description="Skip enhancement for rules that are already well-structured"
    )
    ENHANCEMENT_FALLBACK_ON_ERROR: bool = Field(
        default=True,
        description="Fallback to original rule if enhancement fails"
    )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "allow"  # Allow extra fields from .env
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Create necessary directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        Path(self.chromadb_path).mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings() 