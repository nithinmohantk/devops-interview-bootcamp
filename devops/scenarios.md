# DevOps Scenarios Interview Questions 🎯

## Real-world Problem-solving Scenarios

### 1. Production Outage: High Traffic E-commerce Site Down

**Scenario:**
It's Black Friday, 2 PM EST. Your e-commerce platform is experiencing a complete outage. Users can't access the website, and you're losing $50,000 per minute. You receive multiple alerts, and the CEO is asking for an ETA on resolution.

**Initial symptoms:**
- Website returns 503 Service Unavailable
- Load balancer health checks are failing
- Database connections are timing out
- Application servers showing high CPU (95%+)
- Memory usage is at 90%

**Investigation Process:**

```mermaid
graph TD
    A[Outage Detected] --> B[Assemble War Room]
    B --> C[Check Infrastructure Status]
    C --> D[Analyze Traffic Patterns]
    D --> E[Investigate Database Performance]
    E --> F[Check Application Logs]
    F --> G[Identify Root Cause]
    G --> H[Implement Fix]
    H --> I[Monitor Recovery]
    I --> J[Post-Mortem]
    
    style A fill:#f44336
    style G fill:#ff9800
    style H fill:#4caf50
```

**Step-by-step Resolution:**

**1. Immediate Response (0-5 minutes)**
```bash
# Check overall system health
kubectl get nodes
kubectl get pods --all-namespaces | grep -v Running

# Check load balancer status
aws elbv2 describe-target-health --target-group-arn $TARGET_GROUP_ARN

# Quick traffic analysis
aws cloudwatch get-metric-statistics \
  --namespace AWS/ApplicationELB \
  --metric-name RequestCount \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

**2. Traffic Analysis (5-10 minutes)**
```python
# Quick script to analyze traffic spike
import boto3
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

def analyze_traffic_spike():
    cloudwatch = boto3.client('cloudwatch')
    
    # Get metrics for the past 2 hours
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=2)
    
    response = cloudwatch.get_metric_statistics(
        Namespace='AWS/ApplicationELB',
        MetricName='RequestCount',
        Dimensions=[
            {'Name': 'LoadBalancer', 'Value': 'app/prod-lb/1234567890'}
        ],
        StartTime=start_time,
        EndTime=end_time,
        Period=300,
        Statistics=['Sum']
    )
    
    # Check if traffic is 10x normal
    current_rps = max([point['Sum'] for point in response['Datapoints']]) / 300
    normal_rps = 1000  # Normal traffic
    
    if current_rps > normal_rps * 10:
        print(f"TRAFFIC SPIKE DETECTED: {current_rps} RPS vs normal {normal_rps} RPS")
        return True
    
    return False

# Check for DDoS attack patterns
def check_ddos_patterns():
    # Analyze CloudFlare or WAF logs for suspicious patterns
    suspicious_patterns = [
        "Single IP making 1000+ requests/minute",
        "Requests to expensive endpoints (/search, /api/products)",
        "Bot-like user agents",
        "Geographic concentration"
    ]
    return suspicious_patterns
```

**3. Database Investigation (10-15 minutes)**
```sql
-- Check for long-running queries
SELECT 
    pid,
    now() - pg_stat_activity.query_start AS duration,
    query,
    state
FROM pg_stat_activity
WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes'
ORDER BY duration DESC;

-- Check for locks
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

-- Check connection count
SELECT count(*) as connection_count FROM pg_stat_activity;
```

**4. Application Logs Analysis**
```bash
# Check for memory leaks or OOM errors
kubectl logs -l app=web-app --tail=1000 | grep -i "out of memory\|oom"

# Look for database connection pool exhaustion
kubectl logs -l app=web-app --tail=1000 | grep -i "connection pool\|timeout"

# Check for cache issues
kubectl logs -l app=web-app --tail=1000 | grep -i "redis\|cache"
```

**Root Cause Discovery:**
- Traffic increased 20x due to viral social media post
- Database connection pool (default 10 connections) couldn't handle load
- Application servers ran out of memory due to connection queuing
- Cache layer (Redis) was overwhelmed and started rejecting connections

**Immediate Fix Implementation:**

```yaml
# 1. Emergency scaling
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 20  # Scale from 5 to 20 replicas
  template:
    spec:
      containers:
      - name: web-app
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        env:
        - name: DB_POOL_SIZE
          value: "25"  # Increase from 10 to 25
        - name: DB_POOL_TIMEOUT
          value: "30"  # Increase timeout
```

```bash
# 2. Database scaling
aws rds modify-db-instance \
  --db-instance-identifier prod-db \
  --db-instance-class db.r5.2xlarge \
  --apply-immediately

# 3. Cache scaling
aws elasticache modify-replication-group \
  --replication-group-id prod-redis \
  --node-type cache.r5.xlarge \
  --apply-immediately
```

**Long-term Prevention:**
- Implement auto-scaling based on CPU/memory
- Set up connection pool monitoring
- Implement circuit breakers
- Add rate limiting at API gateway level
- Set up traffic surge alerts

### 2. CI/CD Pipeline Failure: Critical Security Patch Needs Immediate Deployment

**Scenario:**
A critical security vulnerability (CVE-2024-XXXX) has been discovered in a library your application uses. You need to patch and deploy to production immediately, but your CI/CD pipeline is failing due to test failures in an unrelated component.

**Challenge:**
- Security patch must be deployed within 4 hours
- Current CI/CD pipeline has 15% test failure rate
- Failed tests are in a non-critical reporting module
- Normal deployment process takes 6 hours including approvals

**Resolution Strategy:**

```mermaid
graph LR
    A[Security Alert] --> B[Create Hotfix Branch]
    B --> C[Bypass Non-Critical Tests]
    C --> D[Emergency Approval Process]
    D --> E[Staged Deployment]
    E --> F[Monitor & Validate]
    F --> G[Full Pipeline Fix]
    
    style A fill:#f44336
    style D fill:#ff9800
    style E fill:#4caf50
```

**Emergency Deployment Process:**

```yaml
# .github/workflows/emergency-deploy.yml
name: Emergency Security Deployment

on:
  workflow_dispatch:
    inputs:
      security_patch:
        description: 'Security patch deployment'
        required: true
        default: 'false'
      bypass_tests:
        description: 'Bypass non-critical tests'
        required: true
        default: 'false'

jobs:
  emergency-validation:
    if: ${{ github.event.inputs.security_patch == 'true' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Only run critical security tests
      - name: Security Tests
        run: |
          pytest tests/security/ -v
          npm run test:security
      
      # Check for vulnerability scanning
      - name: Vulnerability Scan
        run: |
          npm audit --audit-level high
          bandit -r src/
      
      # Static analysis for security issues
      - name: SAST Scan
        run: |
          semgrep --config=security .
  
  emergency-deploy:
    needs: emergency-validation
    if: ${{ success() && github.event.inputs.bypass_tests == 'true' }}
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Security Patch
        run: |
          docker build -t app:security-patch-$(git rev-parse --short HEAD) .
      
      - name: Deploy to Canary
        run: |
          # Deploy to 5% of traffic first
          kubectl set image deployment/web-app web-app=app:security-patch-$(git rev-parse --short HEAD)
          kubectl patch deployment web-app -p '{"spec":{"replicas":1}}'
          
          # Wait for health checks
          kubectl rollout status deployment/web-app --timeout=300s
      
      - name: Validate Security Fix
        run: |
          # Test that vulnerability is patched
          ./scripts/test-security-vulnerability.sh
      
      - name: Full Production Rollout
        if: success()
        run: |
          # Scale to full capacity
          kubectl patch deployment web-app -p '{"spec":{"replicas":10}}'
          kubectl rollout status deployment/web-app --timeout=600s
```

**Security Patch Validation Script:**

```bash
#!/bin/bash
# scripts/test-security-vulnerability.sh

set -e

CANARY_URL="https://canary.app.com"
PROD_URL="https://app.com"

echo "Testing security vulnerability fix..."

# Test the specific vulnerability is patched
test_vulnerability_fix() {
    local url=$1
    
    # Example: Test for SQL injection vulnerability
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        -X POST "$url/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username": "admin'\'' OR 1=1--", "password": "anything"}')
    
    if [ "$response" -eq "400" ] || [ "$response" -eq "422" ]; then
        echo "✅ Vulnerability fix validated: Injection attempt properly rejected"
        return 0
    else
        echo "❌ Vulnerability fix failed: Injection attempt not properly handled"
        return 1
    fi
}

# Test canary deployment first
echo "Testing canary deployment..."
test_vulnerability_fix "$CANARY_URL"

# Test basic functionality still works
echo "Testing application functionality..."
health_response=$(curl -s -w "%{http_code}" -o /dev/null "$CANARY_URL/health")
if [ "$health_response" -eq "200" ]; then
    echo "✅ Application health check passed"
else
    echo "❌ Application health check failed"
    exit 1
fi

echo "Security patch validation completed successfully"
```

**Post-Deployment Monitoring:**

```python
# monitoring/security_patch_validation.py
import requests
import time
import logging
from prometheus_client import Gauge, Counter

# Metrics
security_patch_health = Gauge('security_patch_health_status', 
                             'Health status after security patch deployment')
vulnerability_test_results = Counter('vulnerability_tests_total', 
                                    'Results of vulnerability tests', 
                                    ['result'])

def monitor_security_patch():
    """Monitor application after security patch deployment"""
    
    endpoints_to_test = [
        '/api/health',
        '/api/users/me',
        '/api/products',
        '/admin/dashboard'
    ]
    
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(f"https://app.com{endpoint}", timeout=10)
            
            if response.status_code < 400:
                logging.info(f"✅ {endpoint} - Status: {response.status_code}")
                security_patch_health.set(1)
                vulnerability_test_results.labels(result='success').inc()
            else:
                logging.warning(f"⚠️ {endpoint} - Status: {response.status_code}")
                security_patch_health.set(0)
                vulnerability_test_results.labels(result='warning').inc()
                
        except Exception as e:
            logging.error(f"❌ {endpoint} - Error: {str(e)}")
            security_patch_health.set(0)
            vulnerability_test_results.labels(result='error').inc()
        
        time.sleep(5)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Monitor for 30 minutes after deployment
    for i in range(360):  # 30 minutes in 5-second intervals
        monitor_security_patch()
        time.sleep(5)
```

### 3. Database Performance Crisis: Slow Queries Affecting User Experience

**Scenario:**
Your e-commerce application is experiencing severe performance degradation. Page load times have increased from 200ms to 8+ seconds. Users are complaining, and conversion rates are dropping. Database monitoring shows high CPU usage and slow query warnings.

**Initial Investigation:**

```sql
-- Check current active queries
SELECT 
    pid,
    now() - pg_stat_activity.query_start AS duration,
    query,
    state,
    wait_event_type,
    wait_event
FROM pg_stat_activity
WHERE state = 'active' AND query != '<IDLE>'
ORDER BY duration DESC;

-- Check slow queries from pg_stat_statements
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows,
    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check table sizes and index usage
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch
FROM pg_stat_user_tables 
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

**Root Cause Analysis:**

```python
# database_analysis.py
import psycopg2
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta

def analyze_database_performance():
    conn = psycopg2.connect(
        host="prod-db.cluster-xxx.us-east-1.rds.amazonaws.com",
        database="ecommerce",
        user="readonly_user",
        password="secure_password"
    )
    
    # Analyze query patterns
    slow_queries = pd.read_sql("""
        SELECT 
            query,
            calls,
            total_time,
            mean_time,
            (total_time / sum(total_time) OVER()) * 100 as percent_time
        FROM pg_stat_statements 
        WHERE mean_time > 1000  -- Queries taking more than 1 second
        ORDER BY total_time DESC
        LIMIT 20
    """, conn)
    
    print("Top slow queries consuming database time:")
    print(slow_queries)
    
    # Check for missing indexes
    missing_indexes = pd.read_sql("""
        SELECT 
            schemaname,
            tablename,
            seq_scan,
            seq_tup_read,
            idx_scan,
            CASE 
                WHEN seq_scan > 0 THEN seq_tup_read / seq_scan 
                ELSE 0 
            END as avg_seq_read
        FROM pg_stat_user_tables
        WHERE seq_scan > 1000 AND idx_scan < seq_scan
        ORDER BY seq_tup_read DESC
    """, conn)
    
    print("\nTables with high sequential scans (potential missing indexes):")
    print(missing_indexes)
    
    # Check connection patterns
    connections = pd.read_sql("""
        SELECT 
            state,
            count(*) as connection_count,
            avg(EXTRACT(EPOCH FROM (now() - state_change))) as avg_duration_seconds
        FROM pg_stat_activity 
        WHERE pid != pg_backend_pid()
        GROUP BY state
    """, conn)
    
    print("\nConnection state analysis:")
    print(connections)
    
    conn.close()
    return slow_queries, missing_indexes, connections

# Run analysis
slow_queries, missing_indexes, connections = analyze_database_performance()
```

**Immediate Performance Fixes:**

```sql
-- 1. Add missing indexes identified from analysis
CREATE INDEX CONCURRENTLY idx_orders_user_id_created_at 
ON orders(user_id, created_at) 
WHERE status IN ('pending', 'processing');

CREATE INDEX CONCURRENTLY idx_products_category_price 
ON products(category_id, price) 
WHERE active = true;

CREATE INDEX CONCURRENTLY idx_order_items_order_id 
ON order_items(order_id) 
INCLUDE (product_id, quantity, price);

-- 2. Optimize the slowest query (product search)
-- Before: Full table scan on products
-- After: Use proper indexing and query optimization
EXPLAIN (ANALYZE, BUFFERS) 
SELECT p.*, c.name as category_name
FROM products p
JOIN categories c ON p.category_id = c.id
WHERE p.name ILIKE '%laptop%' 
  AND p.price BETWEEN 500 AND 2000
  AND p.active = true
ORDER BY p.created_at DESC
LIMIT 20;

-- 3. Add partial index for active products
CREATE INDEX CONCURRENTLY idx_products_search_active 
ON products USING gin(to_tsvector('english', name || ' ' || description))
WHERE active = true;
```

**Application-level Optimizations:**

```python
# application/database_optimizations.py
import redis
import json
from functools import wraps
from flask import current_app

# Redis connection for caching
redis_client = redis.Redis(host='prod-redis.amazonaws.com', port=6379, db=0)

def cache_result(expiration=300):
    """Decorator to cache function results in Redis"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key
            cache_key = f"{func.__name__}:{hash(str(args) + str(kwargs))}"
            
            # Check cache first
            cached_result = redis_client.get(cache_key)
            if cached_result:
                current_app.logger.info(f"Cache hit for {cache_key}")
                return json.loads(cached_result)
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            redis_client.setex(cache_key, expiration, json.dumps(result))
            current_app.logger.info(f"Cache miss for {cache_key}, result cached")
            
            return result
        return wrapper
    return decorator

@cache_result(expiration=600)  # Cache for 10 minutes
def get_product_search_results(query, category=None, min_price=None, max_price=None):
    """Optimized product search with caching"""
    
    # Use read replica for search queries
    read_db = get_read_replica_connection()
    
    sql = """
        SELECT p.id, p.name, p.price, p.image_url, c.name as category_name,
               ts_rank_cd(p.search_vector, plainto_tsquery(%s)) as rank
        FROM products p
        JOIN categories c ON p.category_id = c.id
        WHERE p.active = true
          AND p.search_vector @@ plainto_tsquery(%s)
    """
    
    params = [query, query]
    
    if category:
        sql += " AND c.slug = %s"
        params.append(category)
    
    if min_price:
        sql += " AND p.price >= %s"
        params.append(min_price)
    
    if max_price:
        sql += " AND p.price <= %s"
        params.append(max_price)
    
    sql += " ORDER BY rank DESC, p.created_at DESC LIMIT 50"
    
    cursor = read_db.cursor()
    cursor.execute(sql, params)
    results = cursor.fetchall()
    
    return [dict(zip([col[0] for col in cursor.description], row)) for row in results]

# Connection pooling optimization
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

# Optimized connection pool settings
engine = create_engine(
    'postgresql://user:pass@host:5432/db',
    poolclass=QueuePool,
    pool_size=20,          # Increased from 10
    max_overflow=30,       # Allow burst connections
    pool_pre_ping=True,    # Validate connections
    pool_recycle=3600,     # Recycle connections every hour
    echo=False
)
```

**Monitoring and Alerting Setup:**

```yaml
# prometheus-rules/database-performance.yml
groups:
  - name: database.performance
    rules:
      - alert: SlowQueryDetected
        expr: pg_stat_statements_mean_time_seconds > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Slow database query detected"
          description: "Query {{ $labels.query }} has mean execution time of {{ $value }}s"
      
      - alert: HighDatabaseConnections
        expr: pg_stat_activity_count > 80
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High database connection count"
          description: "Database has {{ $value }} active connections"
      
      - alert: LowDatabaseCacheHitRatio
        expr: pg_stat_database_blks_hit / (pg_stat_database_blks_hit + pg_stat_database_blks_read) < 0.95
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Low database cache hit ratio"
          description: "Database cache hit ratio is {{ $value }}, indicating potential memory issues"
```

**Performance Testing Script:**

```python
# performance_testing.py
import asyncio
import aiohttp
import time
import statistics
from concurrent.futures import ThreadPoolExecutor

async def load_test_endpoint(session, url, test_duration=60):
    """Load test a specific endpoint"""
    start_time = time.time()
    response_times = []
    error_count = 0
    success_count = 0
    
    while time.time() - start_time < test_duration:
        try:
            request_start = time.time()
            async with session.get(url) as response:
                await response.text()
                request_time = time.time() - request_start
                response_times.append(request_time)
                
                if response.status < 400:
                    success_count += 1
                else:
                    error_count += 1
                    
        except Exception as e:
            error_count += 1
            print(f"Request failed: {e}")
        
        await asyncio.sleep(0.1)  # 10 requests per second
    
    return {
        'url': url,
        'total_requests': len(response_times) + error_count,
        'successful_requests': success_count,
        'error_count': error_count,
        'mean_response_time': statistics.mean(response_times) if response_times else 0,
        'p95_response_time': statistics.quantiles(response_times, n=20)[18] if response_times else 0,
        'p99_response_time': statistics.quantiles(response_times, n=100)[98] if response_times else 0
    }

async def run_performance_test():
    """Run performance tests against key endpoints"""
    endpoints = [
        'https://app.com/api/products/search?q=laptop',
        'https://app.com/api/users/profile',
        'https://app.com/api/orders/recent',
        'https://app.com/api/cart/contents'
    ]
    
    async with aiohttp.ClientSession() as session:
        tasks = [load_test_endpoint(session, url) for url in endpoints]
        results = await asyncio.gather(*tasks)
    
    print("\nPerformance Test Results:")
    print("-" * 80)
    for result in results:
        print(f"Endpoint: {result['url']}")
        print(f"  Total Requests: {result['total_requests']}")
        print(f"  Success Rate: {result['successful_requests']}/{result['total_requests']} "
              f"({100 * result['successful_requests'] / result['total_requests']:.1f}%)")
        print(f"  Mean Response Time: {result['mean_response_time']:.3f}s")
        print(f"  P95 Response Time: {result['p95_response_time']:.3f}s")
        print(f"  P99 Response Time: {result['p99_response_time']:.3f}s")
        print()

if __name__ == "__main__":
    asyncio.run(run_performance_test())
```

This scenario demonstrates a systematic approach to diagnosing and resolving database performance issues, including immediate fixes, application optimizations, and long-term monitoring strategies.

### 4. Kubernetes Cluster Resource Exhaustion

**Scenario:**
Your production Kubernetes cluster is running out of resources. Pods are getting evicted, new deployments are failing with "Insufficient CPU/Memory" errors, and application performance is degrading. The cluster has 10 nodes, and you need to quickly identify resource hogs and optimize resource allocation.

**Investigation Commands:**

```bash
# Check overall cluster resource usage
kubectl top nodes
kubectl describe nodes | grep -A 5 "Allocated resources"

# Identify resource-hungry pods
kubectl top pods --all-namespaces --sort-by=cpu
kubectl top pods --all-namespaces --sort-by=memory

# Check pod resource requests vs limits
kubectl describe pods --all-namespaces | grep -A 3 "Requests:\|Limits:"

# Find evicted pods
kubectl get pods --all-namespaces --field-selector=status.phase=Failed

# Check events for resource-related issues
kubectl get events --sort-by=.metadata.creationTimestamp | tail -20
```

**Resource Analysis Script:**

```python
# cluster_resource_analysis.py
import subprocess
import json
import pandas as pd
from kubernetes import client, config

def analyze_cluster_resources():
    # Load kubeconfig
    config.load_kube_config()
    
    v1 = client.CoreV1Api()
    
    # Get all nodes
    nodes = v1.list_node()
    node_data = []
    
    for node in nodes.items:
        allocatable = node.status.allocatable
        capacity = node.status.capacity
        
        node_info = {
            'name': node.metadata.name,
            'cpu_capacity': capacity['cpu'],
            'memory_capacity': capacity['memory'],
            'cpu_allocatable': allocatable['cpu'],
            'memory_allocatable': allocatable['memory']
        }
        node_data.append(node_info)
    
    # Get all pods
    pods = v1.list_pod_for_all_namespaces()
    pod_data = []
    
    for pod in pods.items:
        if pod.status.phase == 'Running':
            total_cpu_request = 0
            total_memory_request = 0
            total_cpu_limit = 0
            total_memory_limit = 0
            
            for container in pod.spec.containers:
                if container.resources and container.resources.requests:
                    cpu_req = container.resources.requests.get('cpu', '0')
                    memory_req = container.resources.requests.get('memory', '0')
                    total_cpu_request += parse_cpu(cpu_req)
                    total_memory_request += parse_memory(memory_req)
                
                if container.resources and container.resources.limits:
                    cpu_limit = container.resources.limits.get('cpu', '0')
                    memory_limit = container.resources.limits.get('memory', '0')
                    total_cpu_limit += parse_cpu(cpu_limit)
                    total_memory_limit += parse_memory(memory_limit)
            
            pod_info = {
                'name': pod.metadata.name,
                'namespace': pod.metadata.namespace,
                'node': pod.spec.node_name,
                'cpu_request': total_cpu_request,
                'memory_request': total_memory_request,
                'cpu_limit': total_cpu_limit,
                'memory_limit': total_memory_limit
            }
            pod_data.append(pod_info)
    
    # Analysis
    df_pods = pd.DataFrame(pod_data)
    df_nodes = pd.DataFrame(node_data)
    
    # Resource utilization by namespace
    namespace_usage = df_pods.groupby('namespace').agg({
        'cpu_request': 'sum',
        'memory_request': 'sum',
        'cpu_limit': 'sum',
        'memory_limit': 'sum'
    }).reset_index()
    
    print("Resource Usage by Namespace:")
    print(namespace_usage.sort_values('memory_request', ascending=False))
    
    # Top resource consumers
    print("\nTop 10 Memory Consumers:")
    print(df_pods.nlargest(10, 'memory_request')[['name', 'namespace', 'memory_request']])
    
    print("\nTop 10 CPU Consumers:")
    print(df_pods.nlargest(10, 'cpu_request')[['name', 'namespace', 'cpu_request']])
    
    return df_pods, df_nodes

def parse_cpu(cpu_str):
    """Parse CPU value to cores"""
    if not cpu_str or cpu_str == '0':
        return 0
    if 'm' in cpu_str:
        return int(cpu_str.replace('m', '')) / 1000
    return float(cpu_str)

def parse_memory(memory_str):
    """Parse memory value to bytes"""
    if not memory_str or memory_str == '0':
        return 0
    
    units = {'Ki': 1024, 'Mi': 1024**2, 'Gi': 1024**3, 'Ti': 1024**4}
    
    for unit, multiplier in units.items():
        if unit in memory_str:
            return int(memory_str.replace(unit, '')) * multiplier
    
    return int(memory_str)

if __name__ == "__main__":
    analyze_cluster_resources()
```

**Immediate Resource Optimization:**

```yaml
# resource-optimization.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: resource-optimization-plan
data:
  plan.md: |
    # Immediate Actions:
    
    1. Scale down non-critical services
    2. Implement resource limits on unlimited pods
    3. Add node capacity
    4. Optimize resource requests
    
    # Critical Services to Maintain:
    - API Gateway
    - Payment Service
    - User Authentication
    - Database
    
    # Services to Scale Down:
    - Batch Jobs (scale to 0)
    - Development Environments (scale to 0)
    - Log Processing (reduce replicas)
    - Monitoring (reduce replicas)

---
# Scale down non-critical deployments
apiVersion: apps/v1
kind: Deployment
metadata:
  name: batch-job-processor
spec:
  replicas: 0  # Scale down from 5 to 0

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: log-aggregator
spec:
  replicas: 1  # Scale down from 3 to 1
  template:
    spec:
      containers:
      - name: log-aggregator
        resources:
          requests:
            memory: "256Mi"  # Reduce from 1Gi
            cpu: "100m"      # Reduce from 500m
          limits:
            memory: "512Mi"  # Reduce from 2Gi
            cpu: "200m"      # Reduce from 1000m

---
# Add resource limits to unlimited pods
apiVersion: apps/v1
kind: Deployment
metadata:
  name: data-processor
spec:
  template:
    spec:
      containers:
      - name: data-processor
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"     # Add missing limit
            cpu: "500m"       # Add missing limit
```

**Emergency Node Scaling:**

```bash
#!/bin/bash
# emergency-scale-nodes.sh

# Add emergency nodes to cluster
aws eks update-nodegroup \
  --cluster-name production-cluster \
  --nodegroup-name main-nodegroup \
  --scaling-config minSize=10,maxSize=20,desiredSize=15

# Or create new nodegroup for immediate capacity
aws eks create-nodegroup \
  --cluster-name production-cluster \
  --nodegroup-name emergency-nodes \
  --instance-types m5.2xlarge \
  --ami-type AL2_x86_64 \
  --capacity-type ON_DEMAND \
  --scaling-config minSize=3,maxSize=5,desiredSize=3 \
  --subnets subnet-12345678 subnet-87654321 \
  --node-role arn:aws:iam::123456789012:role/NodeInstanceRole

# Monitor scaling progress
kubectl get nodes -w
```

**Resource Quota Implementation:**

```yaml
# namespace-resource-quotas.yml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: development
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    persistentvolumeclaims: "4"
    pods: "10"

---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: staging
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    persistentvolumeclaims: "8"
    pods: "20"

---
# Limit ranges to prevent pods without resource specifications
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: production
spec:
  limits:
  - default:
      cpu: "500m"
      memory: "512Mi"
    defaultRequest:
      cpu: "100m"
      memory: "128Mi"
    type: Container
  - max:
      cpu: "2"
      memory: "4Gi"
    min:
      cpu: "10m"
      memory: "64Mi"
    type: Container
```

This comprehensive scenarios guide provides real-world problem-solving approaches for common DevOps challenges, complete with investigation procedures, resolution strategies, and prevention measures.