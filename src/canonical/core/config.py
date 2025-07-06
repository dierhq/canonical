"""
Configuration management for the Canonical SIEM rule converter.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseSettings, Field


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
    chromadb_path: str = Field(default="./data/chromadb", env="CHROMADB_PATH")
    
    # Collection names
    sigma_collection: str = Field(default="sigma_rules", env="SIGMA_COLLECTION")
    mitre_collection: str = Field(default="mitre_attack", env="MITRE_COLLECTION")
    car_collection: str = Field(default="mitre_car", env="CAR_COLLECTION")
    atomic_collection: str = Field(default="atomic_red_team", env="ATOMIC_COLLECTION")
    
    # Embedding model settings
    embedding_model: str = Field(default="BAAI/bge-large-en-v1.5", env="EMBEDDING_MODEL")
    embedding_device: str = Field(default="cpu", env="EMBEDDING_DEVICE")
    embedding_batch_size: int = Field(default=32, env="EMBEDDING_BATCH_SIZE")
    
    # Qwen LLM settings
    qwen_model: str = Field(default="Qwen/Qwen2.5-7B-Instruct", env="QWEN_MODEL")
    qwen_device: str = Field(default="cpu", env="QWEN_DEVICE")
    qwen_max_tokens: int = Field(default=4096, env="QWEN_MAX_TOKENS")
    qwen_temperature: float = Field(default=0.1, env="QWEN_TEMPERATURE")
    
    # Data sources
    sigma_repo_url: str = Field(
        default="https://github.com/SigmaHQ/sigma.git",
        env="SIGMA_REPO_URL"
    )
    mitre_attack_url: str = Field(
        default="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        env="MITRE_ATTACK_URL"
    )
    mitre_car_repo_url: str = Field(
        default="https://github.com/mitre-attack/car.git",
        env="MITRE_CAR_REPO_URL"
    )
    atomic_repo_url: str = Field(
        default="https://github.com/redcanaryco/atomic-red-team.git",
        env="ATOMIC_REPO_URL"
    )
    
    # Data directories
    data_dir: Path = Field(default=Path("./data"), env="DATA_DIR")
    repos_dir: Path = Field(default=Path("./data/repos"), env="REPOS_DIR")
    cache_dir: Path = Field(default=Path("./data/cache"), env="CACHE_DIR")
    
    # Logging settings
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    # Performance settings
    max_concurrent_requests: int = Field(default=10, env="MAX_CONCURRENT_REQUESTS")
    request_timeout: int = Field(default=300, env="REQUEST_TIMEOUT")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Create necessary directories
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        Path(self.chromadb_path).mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings() 