# DevOps Practical Exercises 🔧

## Exercise 1: CI/CD Pipeline Setup

**Objective**: Create a complete CI/CD pipeline for a web application

**Requirements**:
- Use GitHub Actions or Jenkins
- Include unit tests, linting, and security scanning
- Deploy to staging and production environments
- Implement blue-green deployment

**Deliverables**:
```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
    - name: Install dependencies
      run: npm ci
    - name: Run tests
      run: npm test
    - name: Run linting
      run: npm run lint
    - name: Security scan
      run: npm audit

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Build Docker image
      run: docker build -t myapp:${{ github.sha }} .
    - name: Push to registry
      run: docker push myapp:${{ github.sha }}

  deploy-staging:
    needs: build
    if: github.ref == 'refs/heads/develop'
    runs-on: ubuntu-latest
    steps:
    - name: Deploy to staging
      run: kubectl set image deployment/myapp myapp=myapp:${{ github.sha }}

  deploy-production:
    needs: build
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
    - name: Blue-Green Deployment
      run: |
        # Switch traffic to new version
        kubectl patch service myapp -p '{"spec":{"selector":{"version":"blue"}}}'
```

**Evaluation Criteria**:
- Pipeline triggers correctly on code changes
- All tests and quality gates pass
- Deployment strategy is properly implemented
- Rollback capability is available

---

## Exercise 2: Infrastructure as Code

**Objective**: Create reusable Terraform modules for common infrastructure patterns

**Requirements**:
- Create modules for VPC, compute, and database
- Implement proper variable validation
- Include comprehensive documentation
- Support multiple environments

**Solution Structure**:
```
terraform/
├── modules/
│   ├── vpc/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── compute/
│   └── database/
├── environments/
│   ├── dev/
│   ├── staging/
│   └── prod/
└── examples/
```

**VPC Module Example**:
```hcl
# modules/vpc/variables.tf
variable "environment" {
  description = "Environment name"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "cidr_block" {
  description = "CIDR block for VPC"
  type        = string
  validation {
    condition     = can(cidrhost(var.cidr_block, 0))
    error_message = "CIDR block must be a valid IPv4 CIDR."
  }
}

# modules/vpc/main.tf
resource "aws_vpc" "main" {
  cidr_block           = var.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.cidr_block, 4, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-public-${count.index + 1}"
    Environment = var.environment
    Type        = "public"
  }
}
```

**Evaluation Criteria**:
- Modules are reusable and well-documented
- Proper variable validation and typing
- State management is configured
- Multiple environments can be deployed

---

## Exercise 3: Container Orchestration

**Objective**: Deploy a microservices application on Kubernetes

**Requirements**:
- Multi-tier application (frontend, backend, database)
- Implement proper resource limits and requests
- Configure health checks and readiness probes
- Set up horizontal pod autoscaling
- Implement network policies for security

**Application Architecture**:
```yaml
# frontend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  labels:
    app: frontend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        image: nginx:1.21
        ports:
        - containerPort: 80
        resources:
          requests:
            memory: "64Mi"
            cpu: "250m"
          limits:
            memory: "128Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: frontend-service
spec:
  selector:
    app: frontend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: frontend-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: frontend
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

**Network Policy Example**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-network-policy
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: load-balancer
    ports:
    - protocol: TCP
      port: 80
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: backend
    ports:
    - protocol: TCP
      port: 8080
```

**Evaluation Criteria**:
- All components deploy successfully
- Health checks work properly
- Autoscaling responds to load
- Network policies enforce security

---

## Exercise 4: Monitoring and Alerting

**Objective**: Implement comprehensive monitoring for a web application

**Requirements**:
- Set up Prometheus for metrics collection
- Configure Grafana dashboards
- Implement alerting rules
- Set up log aggregation with ELK stack
- Create custom metrics for business logic

**Prometheus Configuration**:
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'application'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
    scrape_interval: 5s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

**Alert Rules**:
```yaml
# alert_rules.yml
groups:
- name: application_alerts
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }} errors per second"

  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High latency detected"
      description: "95th percentile latency is {{ $value }} seconds"

  - alert: ServiceDown
    expr: up == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Service is down"
      description: "{{ $labels.instance }} has been down for more than 1 minute"
```

**Custom Metrics Example**:
```python
# Python application with custom metrics
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
import random

# Define metrics
REQUEST_COUNT = Counter('app_requests_total', 'Total requests', ['method', 'endpoint'])
REQUEST_LATENCY = Histogram('app_request_duration_seconds', 'Request latency')
ACTIVE_USERS = Gauge('app_active_users', 'Number of active users')

@REQUEST_LATENCY.time()
def process_request(method, endpoint):
    # Simulate processing
    time.sleep(random.uniform(0.1, 0.5))
    REQUEST_COUNT.labels(method=method, endpoint=endpoint).inc()

# Start metrics server
start_http_server(8000)
```

**Evaluation Criteria**:
- Metrics are collected and stored properly
- Dashboards show relevant information
- Alerts fire at appropriate thresholds
- Logs are centralized and searchable

---

## Exercise 5: Backup and Disaster Recovery

**Objective**: Implement automated backup and disaster recovery procedures

**Requirements**:
- Automated database backups
- Cross-region replication
- Recovery time objective (RTO) < 4 hours
- Recovery point objective (RPO) < 1 hour
- Disaster recovery testing plan

**Backup Script Example**:
```bash
#!/bin/bash
# automated-backup.sh

set -e

# Configuration
DB_NAME="production_db"
BACKUP_BUCKET="company-backups"
RETENTION_DAYS=30
NOTIFICATION_EMAIL="ops@company.com"

# Generate backup filename with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${DB_NAME}_backup_${TIMESTAMP}.sql"

# Create database backup
echo "Starting backup of ${DB_NAME}..."
mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASSWORD $DB_NAME > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE
BACKUP_FILE="${BACKUP_FILE}.gz"

# Upload to cloud storage
aws s3 cp $BACKUP_FILE s3://$BACKUP_BUCKET/database/
if [ $? -eq 0 ]; then
    echo "Backup uploaded successfully"
    
    # Send success notification
    echo "Database backup completed successfully at $(date)" | \
    mail -s "DB Backup Success - $TIMESTAMP" $NOTIFICATION_EMAIL
else
    echo "Backup upload failed"
    
    # Send failure notification
    echo "Database backup failed at $(date)" | \
    mail -s "DB Backup FAILED - $TIMESTAMP" $NOTIFICATION_EMAIL
    exit 1
fi

# Clean up old backups
aws s3 ls s3://$BACKUP_BUCKET/database/ | \
while read -r line; do
    backup_date=$(echo $line | awk '{print $1}')
    backup_file=$(echo $line | awk '{print $4}')
    
    if [[ $(date -d "$backup_date" +%s) -lt $(date -d "$RETENTION_DAYS days ago" +%s) ]]; then
        aws s3 rm s3://$BACKUP_BUCKET/database/$backup_file
        echo "Deleted old backup: $backup_file"
    fi
done

# Clean up local files
rm -f $BACKUP_FILE

echo "Backup process completed"
```

**Disaster Recovery Plan**:
```yaml
# dr-plan.yml
disaster_recovery:
  rto: 4 hours
  rpo: 1 hour
  
  procedures:
    database_recovery:
      - step: "Identify latest valid backup"
        command: "aws s3 ls s3://company-backups/database/ --recursive"
        duration: "5 minutes"
      
      - step: "Provision new database instance"
        command: "terraform apply -var='environment=dr'"
        duration: "30 minutes"
      
      - step: "Restore from backup"
        command: "gunzip backup.sql.gz && mysql -h $DR_DB_HOST < backup.sql"
        duration: "2 hours"
      
      - step: "Update application configuration"
        command: "kubectl set env deployment/app DB_HOST=$DR_DB_HOST"
        duration: "10 minutes"
      
      - step: "Verify application functionality"
        command: "run-integration-tests.sh"
        duration: "30 minutes"

  testing_schedule:
    frequency: "quarterly"
    next_test: "2024-04-01"
    participants:
      - "SRE Team"
      - "Database Team"
      - "Application Team"
```

**Evaluation Criteria**:
- Backups run automatically and reliably
- Recovery procedures are documented and tested
- RTO and RPO targets are met
- Monitoring alerts on backup failures