# System Requirements - Canonical SIEM Rule Converter

## 🖥️ Hardware Requirements

### Minimum Requirements
- **CPU**: 4 cores (2.0+ GHz)
- **RAM**: 8 GB (for local processing)
- **Storage**: 15 GB free space
- **OS**: Linux, macOS, or Windows with Python 3.9+

### Recommended Requirements
- **CPU**: 8+ cores (3.0+ GHz)
- **RAM**: 32 GB
- **Storage**: 20 GB free space (SSD preferred)
- **OS**: Linux (Ubuntu 20.04+) or macOS

### Enterprise/Production Requirements
- **CPU**: 16+ cores (3.5+ GHz)
- **RAM**: 64 GB
- **Storage**: 50 GB SSD
- **Network**: High-speed internet for initial data ingestion

## 💾 Storage Breakdown

| Component | Size | Description |
|-----------|------|-------------|
| **Source Repositories** | 885 MB | Sigma rules, MITRE CAR, Atomic Red Team repositories |
| **ChromaDB Vector Database** | 227 MB | Embeddings for 6,891 documents, metadata and indices |
| **OpenAI API Access** | 0 GB | Cloud-based GPT-4o processing |
| **Cache Files** | 34 MB | MITRE ATT&CK JSON data, temporary processing files |
| **Total Data** | **~1 GB** | Complete dataset after ingestion |

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

### Language Model (GPT-4o via API)
- **Model Size**: 0 GB (cloud-based)
- **Runtime Memory**: ~100 MB (API client)
- **Request Processing**: Minimal local memory usage

### ChromaDB
- **Base Memory**: ~500 MB
- **Vector Index**: ~1 GB (for 6,891 documents)
- **Query Processing**: +500 MB during searches

## ⚡ Performance Considerations

### CPU vs GPU
- **CPU Only**: Works but slower inference (~5-10 seconds per conversion)
- **GPU Accelerated**: 5-10x faster inference (~1-2 seconds per conversion)
- **Recommended GPU**: 16+ GB VRAM (RTX A6000, V100, A100)

### Concurrent Users
- **Single User**: 32 GB RAM sufficient
- **5-10 Users**: 64 GB RAM recommended  
- **10+ Users**: 128 GB RAM + load balancing

## 🐳 Docker Requirements

```yaml
# Minimum container specs
resources:
  requests:
    memory: "24Gi"
    cpu: "4"
  limits:
    memory: "32Gi" 
    cpu: "8"

# Recommended container specs
resources:
  requests:
    memory: "32Gi"
    cpu: "8"
  limits:
    memory: "64Gi"
    cpu: "16"
```

## 🌐 Network Requirements

- **Initial Setup**: ~12 GB download for models and data repositories
- **Runtime**: Minimal network usage (local processing)
- **API Traffic**: Standard HTTP/REST traffic patterns
- **Bandwidth**: 50+ Mbps recommended for initial data ingestion

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
| **Medium** (m6i.2xlarge) | 8 vCPU, 32 GB RAM | $240-300 | Development/Testing |
| **Large** (m6i.4xlarge) | 16 vCPU, 64 GB RAM | $480-600 | Small Production |
| **X-Large** (m6i.8xlarge) | 32 vCPU, 128 GB RAM | $960-1200 | Production |
| **GPU** (p4d.xlarge) | 8 vCPU, 64 GB RAM, A100 GPU | $3000-4000 | High Performance |

### Storage Costs
- **EBS GP3**: ~$15-20/month for 100 GB
- **EFS**: ~$20-30/month for shared storage

## 🚀 Scaling Architecture Options

### 1. Single Node Deployment
- **Capacity**: Up to 5 concurrent users
- **Requirements**: 32 GB RAM, 8 cores
- **Use Case**: Small teams, development

### 2. Horizontal Scaling
- **Architecture**: Multiple API instances + shared ChromaDB
- **Load Balancer**: nginx/HAProxy
- **Database**: Shared ChromaDB cluster
- **Use Case**: Medium to large deployments

### 3. Microservices Architecture
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   API       │    │  Embedding  │    │Foundation   │
│  Service    │◄──►│   Service   │◄──►│  Sec-8B     │
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
- **Quantized Models**: 4-bit quantization for reduced memory
- **Reduced Memory**: 16-24 GB RAM configurations
- **Use Case**: Resource-constrained environments

## 📊 Performance Benchmarks

### Conversion Speed (CPU)
- **Simple Rules**: 5-8 seconds
- **Complex Rules**: 10-15 seconds
- **Batch Processing**: 20-40 rules/minute

### Conversion Speed (GPU)
- **Simple Rules**: 1-2 seconds
- **Complex Rules**: 2-4 seconds
- **Batch Processing**: 100-200 rules/minute

### Memory Usage
- **Idle**: 8-12 GB
- **Single Conversion**: 24-32 GB peak
- **Concurrent (5 users)**: 40-64 GB
- **Data Ingestion**: 48-64 GB peak

## 🔧 Optimization Tips

### Memory Optimization
1. **Model Quantization**: Reduce model size by 50-75%
2. **Batch Size Tuning**: Optimize for available RAM
3. **Garbage Collection**: Implement proper cleanup

### Storage Optimization
1. **SSD Storage**: Use NVMe SSDs for better I/O
2. **Data Compression**: Enable ChromaDB compression
3. **Cache Management**: Regular cache cleanup

### Performance Tuning
1. **GPU Utilization**: Use GPU when available
2. **CPU Cores**: Utilize all available cores
3. **Memory Management**: Monitor and optimize memory usage
4. **Network**: Optimize for low latency

## 🔍 Monitoring Requirements

### System Metrics
- **CPU Usage**: Monitor per-core utilization
- **Memory Usage**: Track RAM and GPU memory
- **Storage I/O**: Monitor disk read/write rates
- **Network**: Track bandwidth utilization

### Application Metrics
- **Conversion Speed**: Monitor processing times
- **Queue Length**: Track pending requests
- **Error Rates**: Monitor failure rates
- **Model Performance**: Track inference times

### Tools
- **System**: htop, iotop, nethogs
- **Application**: Built-in health endpoints
- **Monitoring**: Prometheus + Grafana recommended

## 🚨 Troubleshooting

### Memory Issues
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head

# Monitor GPU memory
nvidia-smi

# Adjust model settings
export LLM_DEVICE=cpu  # Force CPU if GPU memory insufficient
```

### Performance Issues
```bash
# Check CPU usage
htop

# Monitor disk I/O
iotop

# Check network
nethogs
```

### Model Loading Issues
```bash
# Check model cache
ls -la ~/.cache/huggingface/

# Clear cache if corrupted
rm -rf ~/.cache/huggingface/transformers/

# Verify model download
python -c "import openai; print('OpenAI library available')"
```

## 📞 Support

For performance and scaling questions:
- **Documentation**: [Performance Guide](docs/performance.md)
- **GitHub Issues**: [Report performance issues](https://github.com/dier/canonical/issues)
- **Enterprise Support**: licensing@dier.org

---

**Hardware recommendations based on GPT-4o API usage and production workloads.** 