# Deployment Guide - Canonical SIEM Rule Converter

This guide provides detailed instructions for deploying Canonical in various environments, from development to enterprise production.

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
- **Memory**: 16+ GB RAM
- **Storage**: 50+ GB SSD
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
mkdir -p data/cache data/chromadb data/repos logs
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

# Model settings
EMBEDDING_MODEL=BAAI/bge-large-en-v1.5
QWEN_MODEL=Qwen/Qwen2.5-3B-Instruct
EMBEDDING_DEVICE=cpu
QWEN_DEVICE=cpu

# Database settings
CHROMADB_PATH=/home/canonical/canonical/data/chromadb
CACHE_DIR=/home/canonical/canonical/data/cache
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

[Service]
Type=simple
User=canonical
Group=canonical
WorkingDirectory=/home/canonical/canonical
Environment=PATH=/home/canonical/canonical/venv/bin
ExecStart=/home/canonical/canonical/venv/bin/python -m src.canonical.cli serve --host 127.0.0.1 --port 8000
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/home/canonical/canonical/data /home/canonical/canonical/logs

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable canonical
sudo systemctl start canonical

# Check status
sudo systemctl status canonical
```

### 4. Reverse Proxy Setup

#### Nginx Configuration
```bash
# Create nginx configuration
sudo nano /etc/nginx/sites-available/canonical
```

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL configuration
    ssl_certificate /etc/ssl/certs/canonical.crt;
    ssl_certificate_key /etc/ssl/private/canonical.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # Proxy to application
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
    
    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8000/health;
        access_log off;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/canonical /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 5. Data Initialization

```bash
# Initialize data (this may take 10-15 minutes)
sudo su - canonical
cd canonical
source venv/bin/activate
python -m src.canonical.cli data ingest-all --force-refresh

# Verify data ingestion
python -m src.canonical.cli stats
```

### 6. Monitoring Setup

#### Log Rotation
```bash
# Create logrotate configuration
sudo nano /etc/logrotate.d/canonical
```

```
/home/canonical/canonical/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 canonical canonical
    postrotate
        systemctl reload canonical
    endscript
}
```

#### Health Monitoring
```bash
# Create health check script
nano /home/canonical/health_check.sh
```

```bash
#!/bin/bash
HEALTH_URL="http://localhost:8000/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -eq 200 ]; then
    echo "$(date): Canonical is healthy"
else
    echo "$(date): Canonical is unhealthy (HTTP $RESPONSE)"
    systemctl restart canonical
fi
```

```bash
# Make executable and add to cron
chmod +x /home/canonical/health_check.sh
crontab -e
# Add: */5 * * * * /home/canonical/health_check.sh >> /home/canonical/health_check.log 2>&1
```

## 🐳 Docker Production Deployment

### Docker Compose Production Setup
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  canonical:
    image: canonical:latest
    build: .
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - API_HOST=0.0.0.0
      - API_PORT=8000
      - DEBUG=false
      - LOG_LEVEL=INFO
    volumes:
      - canonical_data:/app/data
      - canonical_logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '4'
        reservations:
          memory: 4G
          cpus: '2'

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.prod.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - canonical
    restart: unless-stopped

volumes:
  canonical_data:
    driver: local
  canonical_logs:
    driver: local
```

### Kubernetes Deployment

#### Namespace
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
| `QWEN_MODEL` | Language model | `Qwen/Qwen2.5-3B-Instruct` |
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
QWEN_DEVICE=cpu
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