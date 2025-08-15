# Troubleshooting Scenarios 🐛

Real-world troubleshooting scenarios that test your problem-solving skills and practical knowledge.

## 📋 Scenario Categories

- [🔧 DevOps Troubleshooting](#devops-troubleshooting) - CI/CD, automation, and infrastructure issues
- [☁️ Cloud Troubleshooting](#cloud-troubleshooting) - Cloud platform and service issues  
- [🛡️ Security Troubleshooting](#security-troubleshooting) - Security incidents and compliance issues
- [📊 Performance Troubleshooting](#performance-troubleshooting) - System performance and optimization
- [🐳 Container Troubleshooting](#container-troubleshooting) - Docker and Kubernetes issues

---

## DevOps Troubleshooting

### Scenario 1: CI/CD Pipeline Suddenly Failing

**Problem:**
Your Jenkins CI/CD pipeline that has been working fine for months suddenly starts failing. The error message shows:
```
ERROR: Could not connect to Docker daemon at unix:///var/run/docker.sock
```

**Information Given:**
- Pipeline was working yesterday
- No changes were made to the Jenkinsfile
- Jenkins is running on a Ubuntu server
- Pipeline builds Docker images as part of the process

**Question:** How would you troubleshoot and resolve this issue?

<details>
<summary>Click to see solution approach</summary>

**Troubleshooting Steps:**

1. **Check Docker Service Status:**
```bash
sudo systemctl status docker
sudo journalctl -u docker --since "1 hour ago"
```

2. **Verify Jenkins User Permissions:**
```bash
# Check if Jenkins user is in docker group
groups jenkins

# If not in docker group, add it
sudo usermod -aG docker jenkins
sudo systemctl restart jenkins
```

3. **Check Docker Socket Permissions:**
```bash
ls -la /var/run/docker.sock
# Should show: srw-rw---- 1 root docker /var/run/docker.sock
```

4. **Test Docker Access:**
```bash
# Test as Jenkins user
sudo -u jenkins docker ps
```

5. **Common Solutions:**
- Restart Docker service: `sudo systemctl restart docker`
- Restart Jenkins service: `sudo systemctl restart jenkins`
- Check disk space: `df -h` (Docker may fail if disk is full)
- Check for recent system updates that might have affected permissions

6. **Pipeline Fix:**
```groovy
// Add error handling to pipeline
pipeline {
    agent any
    stages {
        stage('Docker Build') {
            steps {
                script {
                    try {
                        sh 'docker --version'
                        sh 'docker build -t myapp .'
                    } catch (Exception e) {
                        echo "Docker error: ${e.getMessage()}"
                        sh 'sudo systemctl status docker'
                        error("Docker build failed")
                    }
                }
            }
        }
    }
}
```

</details>

---

### Scenario 2: Terraform Apply Failing with State Lock

**Problem:**
Your Terraform deployment is failing with the error:
```
Error: Error locking state: Error acquiring the state lock: ConditionalCheckFailedException
Lock Info:
  ID:        a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Path:      terraform-state-bucket/prod/terraform.tfstate
  Operation: OperationTypeApply
  Who:       user@company.com
  Version:   1.5.0
  Created:   2024-01-15 14:30:00 UTC
```

**Information Given:**
- Using S3 backend with DynamoDB for state locking
- Team member ran terraform apply earlier but it was interrupted
- Need to deploy urgent fix to production

**Question:** How would you safely resolve this state lock issue?

<details>
<summary>Click to see solution approach</summary>

**Troubleshooting Steps:**

1. **Investigate the Lock:**
```bash
# Check who has the lock and when it was created
aws dynamodb get-item \
    --table-name terraform-state-lock \
    --key '{"LockID":{"S":"terraform-state-bucket/prod/terraform.tfstate-md5"}}' \
    --region us-west-2
```

2. **Verify if Process is Still Running:**
```bash
# Check if terraform process is still running on the machine
ps aux | grep terraform
# Contact the team member to confirm their process status
```

3. **Safe Resolution Options:**

**Option A: Force Unlock (if process confirmed dead):**
```bash
terraform force-unlock a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Option B: Manual DynamoDB Cleanup:**
```bash
aws dynamodb delete-item \
    --table-name terraform-state-lock \
    --key '{"LockID":{"S":"terraform-state-bucket/prod/terraform.tfstate-md5"}}' \
    --region us-west-2
```

4. **Prevention Measures:**
```hcl
# Add backend configuration with shorter timeout
terraform {
  backend "s3" {
    bucket         = "terraform-state-bucket"
    key            = "prod/terraform.tfstate"
    region         = "us-west-2"
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
    
    # Add lock timeout
    lock_timeout = "5m"
  }
}
```

5. **Team Process Improvements:**
- Implement terraform wrapper script with timeout
- Use CI/CD pipeline instead of manual runs
- Set up monitoring for long-running terraform processes
- Create runbook for lock resolution

</details>

---

## Cloud Troubleshooting

### Scenario 3: AWS Application Load Balancer Health Check Failures

**Problem:**
Your web application deployed on AWS ECS is showing unhealthy targets in the Application Load Balancer. Users are experiencing intermittent 503 errors.

**Symptoms:**
- ALB target group shows targets cycling between healthy and unhealthy
- Application logs show health check requests returning 200 OK
- Users report occasional "Service Temporarily Unavailable" errors
- CloudWatch metrics show high response times during peak hours

**Question:** How would you diagnose and fix this issue?

<details>
<summary>Click to see solution approach</summary>

**Troubleshooting Steps:**

1. **Check Target Group Health Check Configuration:**
```bash
aws elbv2 describe-target-health \
    --target-group-arn arn:aws:elasticloadbalancing:region:account:targetgroup/my-targets/1234567890abcdef

aws elbv2 describe-target-groups \
    --target-group-arns arn:aws:elasticloadbalancing:region:account:targetgroup/my-targets/1234567890abcdef
```

2. **Analyze Health Check Settings:**
```yaml
# Current settings that might be problematic:
health_check_interval_seconds: 30
health_check_timeout_seconds: 5
healthy_threshold_count: 2
unhealthy_threshold_count: 2
health_check_grace_period: 60

# Recommended adjustments:
health_check_interval_seconds: 15
health_check_timeout_seconds: 10
healthy_threshold_count: 2
unhealthy_threshold_count: 5  # More tolerant
health_check_grace_period: 300  # Longer grace period
```

3. **Check Application Performance:**
```bash
# Monitor ECS task CPU/Memory usage
aws ecs describe-services --cluster my-cluster --services my-service

# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
    --namespace AWS/ApplicationELB \
    --metric-name TargetResponseTime \
    --dimensions Name=LoadBalancer,Value=app/my-alb/1234567890abcdef \
    --start-time 2024-01-15T12:00:00Z \
    --end-time 2024-01-15T13:00:00Z \
    --period 300 \
    --statistics Average,Maximum
```

4. **Application-Level Debugging:**
```python
# Improve health check endpoint
from flask import Flask, jsonify
import psutil
import time

app = Flask(__name__)

@app.route('/health')
def health_check():
    start_time = time.time()
    
    # Check application dependencies
    checks = {
        'database': check_database_connection(),
        'memory_usage': psutil.virtual_memory().percent < 85,
        'cpu_usage': psutil.cpu_percent(interval=1) < 80,
        'disk_space': psutil.disk_usage('/').percent < 90
    }
    
    all_healthy = all(checks.values())
    response_time = time.time() - start_time
    
    return jsonify({
        'status': 'healthy' if all_healthy else 'unhealthy',
        'checks': checks,
        'response_time': response_time,
        'timestamp': time.time()
    }), 200 if all_healthy else 503

def check_database_connection():
    try:
        # Test database connection with timeout
        with connection_pool.get_connection(timeout=3) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False
```

5. **ECS Service Optimization:**
```json
{
  "family": "my-app",
  "cpu": "512",
  "memory": "1024",
  "healthCheck": {
    "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
    "interval": 30,
    "timeout": 10,
    "retries": 3,
    "startPeriod": 60
  },
  "containerDefinitions": [
    {
      "name": "app",
      "image": "my-app:latest",
      "cpu": 0,
      "memoryReservation": 512,
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ]
    }
  ]
}
```

6. **Monitoring and Alerting:**
```yaml
# CloudWatch alarms
UnhealthyTargetAlarm:
  Type: AWS::CloudWatch::Alarm
  Properties:
    AlarmDescription: "ALB has unhealthy targets"
    MetricName: UnHealthyHostCount
    Namespace: AWS/ApplicationELB
    Statistic: Average
    Period: 300
    EvaluationPeriods: 2
    Threshold: 1
    ComparisonOperator: GreaterThanOrEqualToThreshold
```

</details>

---

## Security Troubleshooting

### Scenario 4: Suspicious Network Activity Alert

**Problem:**
Your security monitoring system has triggered an alert:
```
ALERT: Unusual outbound network traffic detected
Source: web-server-01 (10.0.1.15)
Destination: 185.234.72.89:443
Traffic Volume: 50MB over 5 minutes
Pattern: Regular intervals (every 30 seconds)
```

**Information Given:**
- Web server is part of production environment
- Server handles customer data
- No scheduled data transfers or backups
- Recent deployment was 3 days ago

**Question:** How would you investigate and respond to this potential security incident?

<details>
<summary>Click to see solution approach</summary>

**Incident Response Steps:**

1. **Immediate Containment Assessment:**
```bash
# Do NOT immediately disconnect - preserve evidence
# Document current time and take screenshots
# Check if this is isolated or widespread

# Quick check for obvious explanations
crontab -l  # Check for scheduled jobs
ps aux | grep -E "(curl|wget|rsync|scp)"  # Check for running transfers
netstat -tupln | grep :443  # Check current connections
```

2. **Evidence Collection:**
```bash
# Network analysis
sudo netstat -tupln > network_connections_$(date +%Y%m%d_%H%M%S).txt
sudo ss -tupln > socket_stats_$(date +%Y%m%d_%H%M%S).txt

# Process analysis
ps auxww > running_processes_$(date +%Y%m%d_%H%M%S).txt
top -b -n 1 > system_stats_$(date +%Y%m%d_%H%M%S).txt

# Check for recent file changes
find /var/www -type f -mtime -7 -ls > recent_file_changes.txt
find /etc -type f -mtime -7 -ls >> recent_file_changes.txt

# Memory dump (if suspected malware)
sudo dd if=/proc/kcore of=/tmp/memory_dump_$(date +%Y%m%d_%H%M%S).img bs=1M count=100
```

3. **Threat Intelligence:**
```bash
# Check destination IP reputation
# Use tools like VirusTotal, AbuseIPDB, etc.
dig -x 185.234.72.89  # Reverse DNS lookup
whois 185.234.72.89   # WHOIS information

# Check against threat intelligence feeds
curl -H "X-API-KEY: your-api-key" \
     "https://api.virustotal.com/api/v3/ip_addresses/185.234.72.89"
```

4. **Log Analysis:**
```bash
# Check system logs
sudo journalctl --since "2 hours ago" | grep -E "(185.234.72.89|unusual|error|failed)"

# Check web server logs
grep "185.234.72.89" /var/log/nginx/access.log
grep "185.234.72.89" /var/log/nginx/error.log

# Check authentication logs
grep -E "(ssh|sudo|su)" /var/log/auth.log | tail -50

# Application logs
grep -E "(error|exception|unusual)" /var/log/application/*.log
```

5. **Containment Decision Matrix:**
```yaml
high_confidence_malicious:
  actions:
    - "Immediately isolate server from network"
    - "Preserve memory dump"
    - "Contact incident response team"
    - "Begin forensic imaging"

medium_confidence:
  actions:
    - "Block outbound traffic to suspicious IP"
    - "Increase monitoring"
    - "Continue investigation"
    - "Prepare for isolation"

likely_benign:
  actions:
    - "Document findings"
    - "Continue monitoring"
    - "Update detection rules"
    - "Schedule security review"
```

6. **Network Isolation (if needed):**
```bash
# Block specific IP (temporary measure)
sudo iptables -A OUTPUT -d 185.234.72.89 -j DROP

# Or isolate entire server (preserve for forensics)
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
```

7. **Communication Protocol:**
```yaml
immediate_notifications:
  - security_team@company.com
  - incident_commander@company.com
  - legal@company.com  # if customer data involved

status_updates:
  frequency: "Every 30 minutes"
  stakeholders:
    - Management
    - IT Operations
    - Legal (if applicable)
    - Customers (if confirmed breach)

documentation:
  incident_timeline: "Detailed chronology of events"
  evidence_log: "Chain of custody for all evidence"
  action_log: "All investigative and containment actions"
```

</details>

---

## Performance Troubleshooting

### Scenario 5: Database Performance Degradation

**Problem:**
Your application's database performance has significantly degraded over the past week. Response times have increased from 50ms to 2000ms for typical queries.

**Symptoms:**
- Database CPU utilization consistently above 80%
- Increased query execution times
- Application timeouts and user complaints
- No recent application changes
- Database size has grown 30% in the past month

**Question:** How would you diagnose and resolve this performance issue?

<details>
<summary>Click to see solution approach</summary>

**Troubleshooting Methodology:**

1. **Initial Assessment:**
```sql
-- Check current database metrics (PostgreSQL example)
SELECT 
    datname,
    numbackends,
    xact_commit,
    xact_rollback,
    blks_read,
    blks_hit,
    temp_files,
    temp_bytes
FROM pg_stat_database 
WHERE datname = 'production_db';

-- Check for blocking queries
SELECT 
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS current_statement_in_blocking_process
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;
```

2. **Query Performance Analysis:**
```sql
-- Find slow queries (requires pg_stat_statements extension)
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows,
    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
FROM pg_stat_statements 
ORDER BY total_time DESC 
LIMIT 20;

-- Check table statistics
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation,
    most_common_vals
FROM pg_stats 
WHERE tablename IN ('users', 'orders', 'products')
ORDER BY tablename, attname;
```

3. **Index Analysis:**
```sql
-- Find missing indexes
SELECT 
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    seq_tup_read / seq_scan AS avg_seq_tup_read
FROM pg_stat_user_tables 
WHERE seq_scan > 0
ORDER BY seq_tup_read DESC;

-- Check index usage
SELECT 
    indexrelname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan,
    pg_size_pretty(pg_relation_size(indexrelid)) AS size
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- Unused indexes
SELECT 
    indexrelname,
    pg_size_pretty(pg_relation_size(indexrelid)) AS size
FROM pg_stat_user_indexes 
WHERE idx_scan = 0 
    AND idx_tup_read = 0 
    AND idx_tup_fetch = 0;
```

4. **System Resource Analysis:**
```bash
# I/O analysis
iostat -x 1 10

# Memory usage
free -h
cat /proc/meminfo | grep -E "(MemTotal|MemFree|Buffers|Cached)"

# Check for disk space issues
df -h
du -sh /var/lib/postgresql/

# Check database connections
netstat -an | grep :5432 | wc -l
```

5. **Database Configuration Review:**
```sql
-- Check important PostgreSQL settings
SELECT name, setting, unit, context 
FROM pg_settings 
WHERE name IN (
    'shared_buffers',
    'work_mem',
    'maintenance_work_mem',
    'effective_cache_size',
    'checkpoint_segments',
    'wal_buffers',
    'random_page_cost'
);

-- Check for auto-vacuum settings
SELECT 
    schemaname,
    tablename,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze,
    vacuum_count,
    autovacuum_count
FROM pg_stat_user_tables
ORDER BY last_autovacuum NULLS LAST;
```

6. **Optimization Solutions:**

**Immediate Actions:**
```sql
-- Update table statistics
ANALYZE;

-- Manual vacuum if auto-vacuum is behind
VACUUM VERBOSE users;
VACUUM VERBOSE orders;

-- Kill long-running queries if necessary
SELECT pg_terminate_backend(pid) 
FROM pg_stat_activity 
WHERE state = 'active' 
    AND query_start < now() - interval '1 hour'
    AND query NOT LIKE '%pg_stat_activity%';
```

**Index Optimization:**
```sql
-- Add missing indexes based on analysis
CREATE INDEX CONCURRENTLY idx_orders_user_id_created_at 
ON orders (user_id, created_at);

CREATE INDEX CONCURRENTLY idx_products_category_status 
ON products (category_id, status) 
WHERE status = 'active';

-- Drop unused indexes
DROP INDEX IF EXISTS old_unused_index;
```

**Configuration Tuning:**
```sql
-- Optimize PostgreSQL configuration
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET work_mem = '4MB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET checkpoint_completion_target = 0.7;

-- Apply changes
SELECT pg_reload_conf();
```

7. **Monitoring Setup:**
```python
# Application monitoring
import time
import logging
from contextlib import contextmanager

@contextmanager
def query_timer(query_name):
    start_time = time.time()
    try:
        yield
    finally:
        duration = time.time() - start_time
        if duration > 1.0:  # Log slow queries
            logging.warning(f"Slow query detected: {query_name} took {duration:.2f}s")

# Usage
with query_timer("user_orders_query"):
    results = db.execute("SELECT * FROM orders WHERE user_id = %s", [user_id])
```

8. **Prevention Measures:**
```yaml
monitoring_setup:
  database_metrics:
    - query_execution_time
    - connection_count
    - buffer_hit_ratio
    - index_usage_stats
    
  alerting_thresholds:
    slow_query_threshold: "1 second"
    connection_pool_usage: "80%"
    buffer_hit_ratio: "< 95%"
    
  regular_maintenance:
    - weekly_vacuum_analyze
    - monthly_index_review
    - quarterly_performance_review
```

</details>

---

## Container Troubleshooting

### Scenario 6: Kubernetes Pod Constantly Restarting

**Problem:**
A critical microservice pod in your Kubernetes cluster is stuck in a restart loop. The pod starts, runs for about 2 minutes, then crashes and restarts.

**Pod Status:**
```
NAME                           READY   STATUS             RESTARTS   AGE
payment-service-7d4b8c5f9-xyz   0/1     CrashLoopBackOff   15         30m
```

**Question:** How would you diagnose and fix this issue?

<details>
<summary>Click to see solution approach</summary>

**Troubleshooting Steps:**

1. **Gather Initial Information:**
```bash
# Get pod details
kubectl describe pod payment-service-7d4b8c5f9-xyz -n production

# Check pod logs (current and previous)
kubectl logs payment-service-7d4b8c5f9-xyz -n production
kubectl logs payment-service-7d4b8c5f9-xyz -n production --previous

# Check events
kubectl get events -n production --sort-by=.metadata.creationTimestamp
```

2. **Analyze Pod Configuration:**
```bash
# Get deployment configuration
kubectl get deployment payment-service -n production -o yaml

# Check resource limits and requests
kubectl top pod payment-service-7d4b8c5f9-xyz -n production

# Check node resources
kubectl describe node $(kubectl get pod payment-service-7d4b8c5f9-xyz -n production -o jsonpath='{.spec.nodeName}')
```

3. **Common Root Causes and Solutions:**

**Memory/CPU Limits Issue:**
```yaml
# Check if pod is being OOMKilled
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
spec:
  template:
    spec:
      containers:
      - name: payment-service
        image: payment-service:v1.2.0
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"  # Increase if OOMKilled
            cpu: "500m"
        # Add memory leak detection
        env:
        - name: JAVA_OPTS
          value: "-Xmx400m -XX:+HeapDumpOnOutOfMemoryError"
```

**Health Check Configuration:**
```yaml
# Fix aggressive health checks
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: payment-service
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 60  # Increased startup time
          periodSeconds: 30        # Less frequent checks
          timeoutSeconds: 10       # Longer timeout
          failureThreshold: 5      # More tolerant
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
```

4. **Application-Level Debugging:**
```bash
# Execute into running container (if possible)
kubectl exec -it payment-service-7d4b8c5f9-xyz -n production -- /bin/bash

# Check application configuration
kubectl exec payment-service-7d4b8c5f9-xyz -n production -- env | grep -E "(DB_|REDIS_|API_)"

# Check file system issues
kubectl exec payment-service-7d4b8c5f9-xyz -n production -- df -h
kubectl exec payment-service-7d4b8c5f9-xyz -n production -- ls -la /tmp
```

5. **Dependency Checks:**
```bash
# Check if dependent services are available
kubectl get svc -n production
kubectl get endpoints payment-db -n production

# Test network connectivity
kubectl run debug-pod --image=nicolaka/netshoot -it --rm -- /bin/bash
# From debug pod:
nslookup payment-db.production.svc.cluster.local
telnet payment-db.production.svc.cluster.local 5432
```

6. **Debug Container Method:**
```yaml
# Add debug container to existing pod (Kubernetes 1.23+)
apiVersion: v1
kind: Pod
metadata:
  name: payment-service-debug
spec:
  shareProcessNamespace: true
  containers:
  - name: payment-service
    image: payment-service:v1.2.0
  - name: debug
    image: nicolaka/netshoot
    command: ["/bin/bash"]
    stdin: true
    tty: true
    securityContext:
      capabilities:
        add: ["SYS_PTRACE"]
```

7. **Application Configuration Fix:**
```python
# Improve application startup and health checks
import logging
import signal
import sys
from flask import Flask, jsonify

app = Flask(__name__)

# Graceful shutdown handling
def signal_handler(sig, frame):
    logging.info('Graceful shutdown initiated')
    # Cleanup code here
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

@app.route('/health')
def health_check():
    try:
        # Check critical dependencies
        db_status = check_database()
        redis_status = check_redis()
        
        if db_status and redis_status:
            return jsonify({"status": "healthy"}), 200
        else:
            return jsonify({
                "status": "unhealthy",
                "database": db_status,
                "redis": redis_status
            }), 503
    except Exception as e:
        logging.error(f"Health check failed: {e}")
        return jsonify({"status": "error", "message": str(e)}), 503

@app.route('/ready')
def readiness_check():
    # Lighter check for readiness
    return jsonify({"status": "ready"}), 200

if __name__ == '__main__':
    # Allow time for dependencies to start
    import time
    time.sleep(10)
    
    app.run(host='0.0.0.0', port=8080)
```

8. **Monitoring and Prevention:**
```yaml
# Enhanced monitoring
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
data:
  prometheus.yml: |
    scrape_configs:
    - job_name: 'payment-service'
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: ['production']
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app]
        action: keep
        regex: payment-service
      - source_labels: [__meta_kubernetes_pod_container_port_name]
        action: keep
        regex: metrics

---
# Add alerting rules
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: payment-service-alerts
spec:
  groups:
  - name: payment-service
    rules:
    - alert: PaymentServiceHighRestarts
      expr: increase(kube_pod_container_status_restarts_total{pod=~"payment-service.*"}[15m]) > 3
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: "Payment service pod restarting frequently"
        description: "Pod {{ $labels.pod }} has restarted {{ $value }} times in the last 15 minutes"
```

</details>

---

These troubleshooting scenarios test your ability to:
- Think systematically under pressure
- Use appropriate tools and commands
- Understand system interactions
- Implement both immediate fixes and long-term solutions
- Document and communicate findings effectively

Practice these scenarios and develop your own troubleshooting methodology. Remember: **observe, hypothesize, test, and document** every step of your investigation.