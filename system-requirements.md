# System Requirements - Canonical SIEM Rule Converter

## 🖥️ Hardware Requirements

### Minimum Requirements
- **CPU**: 4 cores (2.0+ GHz)
- **RAM**: 8 GB 
- **Storage**: 10 GB free space
- **OS**: Linux, macOS, or Windows with Python 3.9+

### Recommended Requirements
- **CPU**: 8+ cores (3.0+ GHz)
- **RAM**: 16 GB
- **Storage**: 20 GB free space (SSD preferred)
- **OS**: Linux (Ubuntu 20.04+) or macOS

### Enterprise/Production Requirements
- **CPU**: 16+ cores (3.5+ GHz)
- **RAM**: 32 GB
- **Storage**: 50 GB SSD
- **Network**: High-speed internet for initial data ingestion

## 💾 Storage Breakdown

| Component | Size | Description |
|-----------|------|-------------|
| **Source Repositories** | 885 MB | Sigma rules, MITRE CAR, Atomic Red Team repositories |
| **ChromaDB Vector Database** | 227 MB | Embeddings for 6,891 documents, metadata and indices |
| **Cache Files** | 34 MB | MITRE ATT&CK JSON data, temporary processing files |
| **Total Data** | **1.1 GB** | Complete dataset after ingestion |

### Data Collections
- **Sigma Rules**: 3,015 documents
- **MITRE ATT&CK**: 2,044 documents (823 techniques, 14 tactics, 181 groups, 758 software, 268 mitigations)
- **MITRE CAR**: 102 analytics documents
- **Atomic Red Team**: 1,730 test documents (325 techniques)

## 🧠 Memory Requirements by Component

### Embedding Model (BGE-large-en-v1.5)
- **Model Size**: ~1.3 GB
- **Runtime Memory**: ~2-3 GB
- **Batch Processing**: +1-2 GB during ingestion

### Language Model (Qwen2.5-3B-Instruct)
- **Model Size**: ~6 GB
- **Runtime Memory**: ~8-10 GB
- **Inference Memory**: +2-3 GB per request

### ChromaDB
- **Base Memory**: ~500 MB
- **Vector Index**: ~1 GB (for 6,891 documents)
- **Query Processing**: +500 MB during searches

## ⚡ Performance Considerations

### CPU vs GPU
- **CPU Only** (current): Works but slower inference (~3-5 seconds per conversion)
- **GPU Accelerated**: 5-10x faster inference (~0.5-1 second per conversion)
- **Recommended GPU**: 8+ GB VRAM (RTX 3070/4060 or better)

### Concurrent Users
- **Single User**: 8 GB RAM sufficient
- **5-10 Users**: 16 GB RAM recommended  
- **10+ Users**: 32 GB RAM + load balancing

## 🐳 Docker Requirements

```yaml
# Minimum container specs
resources:
  requests:
    memory: "8Gi"
    cpu: "2"
  limits:
    memory: "16Gi" 
    cpu: "4"

# Recommended container specs
resources:
  requests:
    memory: "16Gi"
    cpu: "4"
  limits:
    memory: "32Gi"
    cpu: "8"
```

## 🌐 Network Requirements

- **Initial Setup**: ~1 GB download for models and data repositories
- **Runtime**: Minimal network usage (local processing)
- **API Traffic**: Standard HTTP/REST traffic patterns
- **Bandwidth**: 10+ Mbps recommended for initial data ingestion

## 📋 Software Dependencies

### Core Dependencies
```txt
Python 3.9+
PyTorch (CPU: ~200MB, GPU: ~2GB)
Transformers (~500MB)
ChromaDB (~100MB)
FastAPI + dependencies (~50MB)
Git (for repository cloning)
```

### Python Packages
```txt
torch>=2.0.0
transformers>=4.30.0
sentence-transformers>=2.2.0
chromadb>=0.4.0
fastapi>=0.100.0
uvicorn>=0.20.0
pydantic>=2.0.0
loguru>=0.7.0
click>=8.0.0
pyyaml>=6.0
gitpython>=3.1.0
requests>=2.28.0
```

## 💰 Cost Estimation (Cloud Deployment)

### AWS/GCP/Azure Pricing
| Instance Type | Specs | Monthly Cost | Use Case |
|---------------|-------|--------------|----------|
| **Small** (t3.large) | 2 vCPU, 8 GB RAM | $60-80 | Development/Testing |
| **Medium** (t3.xlarge) | 4 vCPU, 16 GB RAM | $120-150 | Small Production |
| **Large** (t3.2xlarge) | 8 vCPU, 32 GB RAM | $240-300 | Production |
| **GPU** (g4dn.xlarge) | 4 vCPU, 16 GB RAM, T4 GPU | $300-400 | High Performance |

### Storage Costs
- **EBS GP3**: ~$10-15/month for 50 GB
- **EFS**: ~$15-20/month for shared storage

## 🚀 Scaling Architecture Options

### 1. Single Node Deployment
- **Capacity**: Up to 10 concurrent users
- **Requirements**: 16 GB RAM, 8 cores
- **Use Case**: Small teams, development

### 2. Horizontal Scaling
- **Architecture**: Multiple API instances + shared ChromaDB
- **Load Balancer**: nginx/HAProxy
- **Database**: Shared ChromaDB cluster
- **Use Case**: Medium to large deployments

### 3. Microservices Architecture
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   API       │    │  Embedding  │    │    LLM      │
│  Service    │◄──►│   Service   │◄──►│  Service    │
└─────────────┘    └─────────────┘    └─────────────┘
       │                    │                    │
       └────────────────────┼────────────────────┘
                            ▼
                   ┌─────────────┐
                   │  ChromaDB   │
                   │   Cluster   │
                   └─────────────┘
```

### 4. Edge Deployment
- **Lightweight Models**: Smaller language models
- **Reduced Memory**: 4-8 GB RAM configurations
- **Use Case**: Resource-constrained environments

## 📊 Performance Benchmarks

### Conversion Speed (CPU)
- **Simple Rules**: 2-3 seconds
- **Complex Rules**: 4-6 seconds
- **Batch Processing**: 50-100 rules/minute

### Conversion Speed (GPU)
- **Simple Rules**: 0.5-1 second
- **Complex Rules**: 1-2 seconds
- **Batch Processing**: 200-400 rules/minute

### Memory Usage
- **Idle**: 2-3 GB
- **Single Conversion**: 8-12 GB peak
- **Concurrent (5 users)**: 15-20 GB
- **Data Ingestion**: 20-25 GB peak

## 🔧 Optimization Tips

### Memory Optimization
1. **Model Quantization**: Reduce model size by 50-75%
2. **Batch Size Tuning**: Optimize for available RAM
3. **Garbage Collection**: Implement proper cleanup

### Storage Optimization
1. **SSD Storage**: 3-5x faster than HDD
2. **Data Compression**: Reduce ChromaDB size
3. **Cache Management**: Implement TTL policies

### CPU Optimization
1. **Multi-threading**: Parallel processing where possible
2. **Process Pools**: Isolate heavy computations
3. **Async Operations**: Non-blocking I/O

## 🛠️ Installation Requirements

### System Packages (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y python3.9 python3-pip git build-essential
```

### System Packages (CentOS/RHEL)
```bash
sudo yum install -y python39 python3-pip git gcc gcc-c++
```

### macOS
```bash
brew install python@3.9 git
```

## 🔒 Security Considerations

### Network Security
- **Firewall**: Restrict API port access
- **HTTPS**: SSL/TLS encryption required
- **Authentication**: API key or OAuth integration

### Data Security
- **Encryption at Rest**: Encrypt ChromaDB data
- **Encryption in Transit**: All API communications
- **Access Control**: Role-based permissions

## 📈 Monitoring Requirements

### System Metrics
- **CPU Usage**: Target <80% average
- **Memory Usage**: Monitor for leaks
- **Disk I/O**: SSD performance monitoring
- **Network**: API response times

### Application Metrics
- **Conversion Success Rate**: >95% target
- **Response Times**: <5 seconds target
- **Error Rates**: <1% target
- **Queue Depth**: For batch processing

## 🆘 Troubleshooting

### Common Issues
1. **Out of Memory**: Reduce batch size or upgrade RAM
2. **Slow Conversions**: Check CPU usage, consider GPU
3. **Model Loading Errors**: Verify disk space and permissions
4. **ChromaDB Issues**: Check storage and memory availability

### Performance Tuning
1. **Model Caching**: Keep models in memory
2. **Connection Pooling**: Optimize database connections
3. **Request Batching**: Group similar operations
4. **Resource Limits**: Set appropriate container limits

---

## Summary

**Minimum for Development**: 8 GB RAM, 4 cores, 10 GB storage
**Recommended for Production**: 16 GB RAM, 8 cores, 20 GB SSD
**Enterprise Scale**: 32+ GB RAM, 16+ cores, 50+ GB SSD

The system is designed to be scalable from single-user development environments to enterprise-scale deployments with thousands of concurrent users. 