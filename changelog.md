# Changelog

All notable changes to the Canonical SIEM Rule Converter will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **KibanaQL Source Language Support** - **🆕 NEW**
  - KibanaQL rule parser with JSON, YAML, and text format support
  - KibanaQL → KustoQL (Azure Sentinel) conversion
  - KibanaQL → KibanaQL (validation/normalization) conversion
  - KibanaQL → EQL (Event Query Language) conversion
  - KibanaQL → QRadar AQL (IBM QRadar) conversion
  - KibanaQL → Splunk SPL (Splunk Enterprise Security) conversion
  - KibanaQL → Sigma (Universal Detection Format) conversion
  - CLI support for KibanaQL source format
  - API endpoints for all KibanaQL conversion paths
  - MITRE ATT&CK technique extraction from KibanaQL rules
  - Rule complexity analysis for KibanaQL rules
  - Comprehensive rule validation for KibanaQL syntax

- Initial public release preparation
- Custom license for internal SOC/MDR/corporate use
- Comprehensive documentation for open source release

## [0.1.0] - 2025-01-XX

### Added
- **Multi-Format Rule Conversion**
  - Sigma → KustoQL (Azure Sentinel)
  - Sigma → KibanaQL (Elastic SIEM)
  - Sigma → EQL (Event Query Language)
  - Sigma → Splunk SPL (Splunk Enterprise Security)
  - Sigma → QRadar AQL (IBM QRadar)

- **Foundation-Sec-8B Intelligence**
  - Context-aware conversions using BGE-large-en-v1.5 embeddings
  - Foundation-Sec-8B language model for cybersecurity-optimized rule generation
  - Confidence scoring for conversion quality assessment
  - Vector similarity search across knowledge base

- **Comprehensive Knowledge Base**
  - 3,015 Sigma rules from SigmaHQ repository
  - 2,044 MITRE ATT&CK techniques, tactics, groups, and mitigations
  - 102 MITRE CAR analytics for detection context
  - 1,730 Atomic Red Team tests for validation procedures

- **Data Ingestion System**
  - Automatic ingestion of Sigma rules from SigmaHQ
  - MITRE ATT&CK framework data integration
  - MITRE CAR analytics ingestion
  - Atomic Red Team test data processing
  - ChromaDB vector database for efficient storage and retrieval

- **API Interface**
  - RESTful API with FastAPI framework
  - OpenAPI/Swagger documentation
  - Health check and statistics endpoints
  - Batch conversion capabilities
  - Rule validation endpoints

- **Command Line Interface**
  - Single rule conversion commands
  - Batch processing for multiple rules
  - Data ingestion management
  - System statistics and health checks
  - Configurable output formats

- **Enterprise Features**
  - Scalable architecture design
  - Comprehensive logging and monitoring
  - Error handling and recovery
  - Performance optimization
  - Memory-efficient processing

### Technical Implementation
- **Vector Database**: ChromaDB for semantic search and storage
- **Embeddings**: BGE-large-en-v1.5 for text vectorization
- **Language Model**: Foundation-Sec-8B for cybersecurity-specialized rule generation
- **Web Framework**: FastAPI for API development
- **CLI Framework**: Click for command-line interface
- **Configuration**: Pydantic for settings management
- **Logging**: Loguru for structured logging

### Security
- Input validation for all rule formats
- Secure configuration management
- Error handling without information leakage
- Dependency vulnerability scanning
- Security policy documentation

### Documentation
- Comprehensive README with usage examples
- System requirements specification
- API documentation with OpenAPI
- Contributing guidelines
- Security policy and vulnerability reporting
- Installation and deployment guides

### Performance
- Optimized for CPU-based inference
- Batch processing capabilities
- Memory-efficient data handling
- Configurable model parameters
- Caching for improved performance

### Testing
- Unit tests for core functionality
- Integration tests for API endpoints
- End-to-end conversion testing
- Performance benchmarking
- Quality assurance workflows 