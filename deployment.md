# Deployment Guide - Canonical SIEM Rule Converter

This guide provides detailed instructions for deploying Canonical in various environments, from development to enterprise production.

## 🆕 Foundation-Sec-8B Integration

**IMPORTANT**: Canonical now uses Foundation-Sec-8B by Cisco as the cybersecurity-specialized LLM for enhanced security performance. This model provides:

- **5-13% better performance** on cybersecurity benchmarks
- **Deep domain knowledge** of CVEs, CWEs, MITRE ATT&CK
- **Superior rule conversion accuracy** for SIEM platforms
- **Specialized cybersecurity training** on 5.1B tokens of security data

### System Requirements for Foundation-Sec-8B
- **Memory**: 32GB+ RAM recommended for optimal performance
- **GPU**: 16GB+ VRAM recommended (RTX A6000, V100, A100)
- **Storage**: Additional 10GB for model weights
- **Quantization**: Automatic 4-bit quantization on systems with <24GB VRAM

## 🚀 Quick Start Deployment

### Local Development
```bash
# Clone the repository
git clone https://github.com/dier/canonical.git
cd canonical

# Install dependencies
pip3 install -r requirements.txt

# Configure environment
cp env.example .env
# Edit .env with your settings

# Initialize data (one-time setup)
python3 -m src.canonical.cli data ingest-all --force-refresh

# Start API server
python3 -m src.canonical.cli serve --host 0.0.0.0 --port 8000
```

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# Initialize data (one-time setup)
docker-compose exec canonical python -m src.canonical.cli data ingest-all --force-refresh

# Check status
docker-compose ps
curl http://localhost:8000/health
```

## 🏗️ Production Deployment

### Prerequisites
- **OS**: Ubuntu 20.04+ / CentOS 8+ / RHEL 8+
- **Python**: 3.9+
- **Memory**: 32+ GB RAM (for Foundation-Sec-8B)
- **GPU Memory**: 16+ GB VRAM recommended (RTX A6000, V100, A100)
- **Storage**: 60+ GB SSD (additional space for Foundation-Sec-8B model)
- **Network**: Firewall configured for API access

### 1. System Preparation

#### Ubuntu/Debian
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv git curl nginx

# Create application user
sudo useradd -m -s /bin/bash canonical
sudo usermod -aG sudo canonical
```

#### CentOS/RHEL
```bash
# Update system
sudo yum update -y

# Install dependencies
sudo yum install -y python3 python3-pip git curl nginx

# Create application user
sudo useradd -m -s /bin/bash canonical
sudo usermod -aG wheel canonical
```

### 2. Application Setup

```bash
# Switch to application user
sudo su - canonical

# Clone repository
git clone https://github.com/dier/canonical.git
cd canonical

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install application
pip install -e .

# Create directories
mkdir -p data/persistent/{chromadb,converters,outputs,custom_tables,cache} data/{repos,temp} logs
```

### 3. Configuration

#### Environment Configuration
```bash
# Copy and edit configuration
cp env.example .env
nano .env
```

```env
# Production .env configuration
API_HOST=127.0.0.1
API_PORT=8000
DEBUG=false
LOG_LEVEL=INFO

# Model settings (Foundation-Sec-8B)
EMBEDDING_MODEL=BAAI/bge-large-en-v1.5
LLM_MODEL=fdtn-ai/Foundation-Sec-8B
EMBEDDING_DEVICE=cpu
LLM_DEVICE=auto

# Database settings
CHROMADB_PATH=/home/canonical/canonical/data/persistent/chromadb
CACHE_DIR=/home/canonical/canonical/data/persistent/cache
REPOS_DIR=/home/canonical/canonical/data/repos

# Logging
LOG_LEVEL=INFO
LOG_FILE=/home/canonical/canonical/logs/canonical.log
```

#### SystemD Service
```bash
# Create systemd service file
sudo nano /etc/systemd/system/canonical.service
```

```ini
[Unit]
Description=Canonical SIEM Rule Converter
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=canonical
WorkingDirectory=/home/canonical/canonical
Environment=PATH=/home/canonical/canonical/venv/bin
ExecStart=/home/canonical/canonical/venv/bin/python -m src.canonical.cli serve --host 127.0.0.1 --port 8000
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl enable canonical
sudo systemctl start canonical
sudo systemctl status canonical
```

### 4. Nginx Configuration

```bash
# Create nginx configuration
sudo nano /etc/nginx/sites-available/canonical
```

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts for LLM processing
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        proxy_send_timeout 300s;
    }
}
```

```bash
# Enable site and restart nginx
sudo ln -s /etc/nginx/sites-available/canonical /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 5. SSL/TLS Configuration (Recommended)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain SSL certificate
sudo certbot --nginx -d your-domain.com

# Verify auto-renewal
sudo certbot renew --dry-run
```

## 🐳 Docker Deployment

### Single Container

```bash
# Build image
docker build -t canonical .

# Run container
docker run -d \
  --name canonical \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  canonical
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  canonical:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    environment:
      - API_HOST=0.0.0.0
      - API_PORT=8000
      - DEBUG=false
      - LOG_LEVEL=INFO
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - canonical
    restart: unless-stopped
```

## ☸️ Kubernetes Deployment

### Namespace
```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: canonical
```

#### ConfigMap
```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: canonical-config
  namespace: canonical
data:
  API_HOST: "0.0.0.0"
  API_PORT: "8000"
  DEBUG: "false"
  LOG_LEVEL: "INFO"
```

#### Deployment
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: canonical
  namespace: canonical
spec:
  replicas: 2
  selector:
    matchLabels:
      app: canonical
  template:
    metadata:
      labels:
        app: canonical
    spec:
      containers:
      - name: canonical
        image: canonical:latest
        ports:
        - containerPort: 8000
        envFrom:
        - configMapRef:
            name: canonical-config
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "8Gi"
            cpu: "4"
        volumeMounts:
        - name: data
          mountPath: /app/data
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: canonical-data
```

## 🔧 Configuration Management

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `API_HOST` | API server host | `0.0.0.0` |
| `API_PORT` | API server port | `8000` |
| `DEBUG` | Debug mode | `false` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `EMBEDDING_MODEL` | Embedding model | `BAAI/bge-large-en-v1.5` |
| `LLM_MODEL` | Language model | `fdtn-ai/Foundation-Sec-8B` |
| `CHROMADB_PATH` | ChromaDB path | `./data/chromadb` |

### Security Configuration
```bash
# Firewall setup (Ubuntu/Debian)
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable

# SELinux configuration (CentOS/RHEL)
sudo setsebool -P httpd_can_network_connect 1
sudo semanage port -a -t http_port_t -p tcp 8000
```

## 📊 Monitoring and Maintenance

### Performance Monitoring
```bash
# System resource monitoring
htop
iotop
nethogs

# Application monitoring
curl http://localhost:8000/health
curl http://localhost:8000/stats
```

### Log Analysis
```bash
# View application logs
tail -f /home/canonical/canonical/logs/canonical.log

# View system logs
journalctl -u canonical -f

# Analyze access patterns
tail -f /var/log/nginx/access.log | grep canonical
```

### Backup Strategy
```bash
# Data backup script
#!/bin/bash
BACKUP_DIR="/backup/canonical"
DATA_DIR="/home/canonical/canonical/data"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/canonical_data_$DATE.tar.gz $DATA_DIR
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

## 🚨 Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
journalctl -u canonical -n 50
sudo systemctl status canonical

# Check configuration
python -m src.canonical.cli --help
```

#### High Memory Usage
```bash
# Monitor memory usage
free -h
ps aux | grep canonical

# Adjust model settings in .env
EMBEDDING_DEVICE=cpu
LLM_DEVICE=cpu
```

#### API Timeouts
```bash
# Check nginx configuration
sudo nginx -t
sudo systemctl reload nginx

# Increase timeouts in nginx config
proxy_read_timeout 300s;
```

### Performance Optimization
- **CPU**: Use multiple cores for model inference
- **Memory**: Increase available RAM for better performance
- **Storage**: Use SSD for better I/O performance
- **Network**: Optimize nginx buffer settings

## 📞 Support

For deployment issues or questions:
- **Documentation**: [README.md](README.md)
- **GitHub Issues**: [Report deployment issues](https://github.com/dier/canonical/issues)
- **Enterprise Support**: team@dierhq.com

---

**DIER Team** - Canonical SIEM Rule Converter 🛡️ 