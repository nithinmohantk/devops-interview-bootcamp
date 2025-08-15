# SRE Exercises 📊

Practical hands-on exercises for Site Reliability Engineering, monitoring, reliability, and incident response.

## 📋 Exercise Categories

- [📊 Monitoring and Observability](#monitoring-and-observability) - Metrics, logs, traces, and dashboards
- [🎯 Service Level Objectives](#service-level-objectives) - SLIs, SLOs, and error budgets
- [🚨 Incident Response](#incident-response) - On-call, escalation, and post-mortems
- [🔄 Reliability Engineering](#reliability-engineering) - Chaos engineering and resilience testing
- [⚡ Performance Engineering](#performance-engineering) - Load testing and optimization
- [🤖 Automation and Toil Reduction](#automation-and-toil-reduction) - Runbook automation and self-healing

---

## Monitoring and Observability

### Exercise 1: Complete Observability Stack Implementation

**Objective**: Implement a comprehensive observability stack with the three pillars: metrics, logs, and traces

**Requirements**:
- Deploy Prometheus, Grafana, and AlertManager
- Set up centralized logging with ELK stack
- Implement distributed tracing with Jaeger
- Create custom metrics and dashboards
- Configure intelligent alerting

**Time Limit**: 6 hours

**Deliverables**:

```yaml
# prometheus-stack.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      containers:
      - name: prometheus
        image: prom/prometheus:v2.45.0
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: config
          mountPath: /etc/prometheus
        - name: storage
          mountPath: /prometheus
        command:
        - '/bin/prometheus'
        - '--config.file=/etc/prometheus/prometheus.yml'
        - '--storage.tsdb.path=/prometheus'
        - '--web.console.libraries=/etc/prometheus/console_libraries'
        - '--web.console.templates=/etc/prometheus/consoles'
        - '--storage.tsdb.retention.time=15d'
        - '--web.enable-lifecycle'
        - '--web.enable-admin-api'
      volumes:
      - name: config
        configMap:
          name: prometheus-config
      - name: storage
        persistentVolumeClaim:
          claimName: prometheus-storage
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s

    rule_files:
      - "/etc/prometheus/rules/*.yml"

    alerting:
      alertmanagers:
      - static_configs:
        - targets:
          - alertmanager:9093

    scrape_configs:
    - job_name: 'prometheus'
      static_configs:
      - targets: ['localhost:9090']

    - job_name: 'kubernetes-nodes'
      kubernetes_sd_configs:
      - role: node
      relabel_configs:
      - source_labels: [__address__]
        regex: '(.*):10250'
        target_label: __address__
        replacement: '${1}:9100'

    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)

    - job_name: 'application-metrics'
      static_configs:
      - targets: ['app-service:8080']
      metrics_path: '/metrics'
      scrape_interval: 10s

  alerting_rules.yml: |
    groups:
    - name: application.rules
      rules:
      - alert: HighCPUUsage
        expr: cpu_usage_percent > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage detected"
          description: "CPU usage is above 80% for more than 5 minutes"

      - alert: HighMemoryUsage
        expr: memory_usage_percent > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is above 85% for more than 5 minutes"

      - alert: ApplicationDown
        expr: up{job="application-metrics"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Application is down"
          description: "Application has been down for more than 1 minute"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.05
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is above 5% for more than 2 minutes"

      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"
          description: "95th percentile latency is above 500ms for more than 5 minutes"
```

```python
# custom-metrics-exporter.py
import time
import psutil
import redis
import mysql.connector
from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, start_http_server
from dataclasses import dataclass
from typing import Dict, Any
import logging
import threading

@dataclass
class MetricDefinition:
    name: str
    description: str
    metric_type: str
    labels: list = None

class CustomMetricsExporter:
    def __init__(self, port: int = 8080):
        self.port = port
        self.registry = CollectorRegistry()
        
        # Business metrics
        self.request_count = Counter(
            'http_requests_total',
            'Total HTTP requests',
            ['method', 'endpoint', 'status'],
            registry=self.registry
        )
        
        self.request_duration = Histogram(
            'http_request_duration_seconds',
            'HTTP request duration',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        self.active_users = Gauge(
            'active_users_total',
            'Number of active users',
            registry=self.registry
        )
        
        self.queue_size = Gauge(
            'queue_size_total',
            'Current queue size',
            ['queue_name'],
            registry=self.registry
        )
        
        # Infrastructure metrics
        self.cpu_usage = Gauge(
            'cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        self.memory_usage = Gauge(
            'memory_usage_percent',
            'Memory usage percentage',
            registry=self.registry
        )
        
        self.disk_usage = Gauge(
            'disk_usage_percent',
            'Disk usage percentage',
            ['mount_point'],
            registry=self.registry
        )
        
        # Database metrics
        self.db_connections = Gauge(
            'database_connections_active',
            'Active database connections',
            ['database'],
            registry=self.registry
        )
        
        self.db_query_duration = Histogram(
            'database_query_duration_seconds',
            'Database query duration',
            ['query_type'],
            registry=self.registry
        )
        
        # Cache metrics
        self.cache_hits = Counter(
            'cache_hits_total',
            'Cache hits',
            ['cache_type'],
            registry=self.registry
        )
        
        self.cache_misses = Counter(
            'cache_misses_total',
            'Cache misses',
            ['cache_type'],
            registry=self.registry
        )
        
        # Application-specific metrics
        self.orders_processed = Counter(
            'orders_processed_total',
            'Total orders processed',
            ['status'],
            registry=self.registry
        )
        
        self.revenue_total = Counter(
            'revenue_total_dollars',
            'Total revenue in dollars',
            registry=self.registry
        )
        
        # Redis client for cache metrics
        self.redis_client = redis.Redis(host='localhost', port=6379, db=0)
        
        # Database connection for DB metrics
        self.db_config = {
            'host': 'localhost',
            'database': 'app_db',
            'user': 'monitor_user',
            'password': 'monitor_password'
        }
    
    def collect_system_metrics(self):
        """Collect system-level metrics"""
        while True:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                self.cpu_usage.set(cpu_percent)
                
                # Memory usage
                memory = psutil.virtual_memory()
                self.memory_usage.set(memory.percent)
                
                # Disk usage
                for partition in psutil.disk_partitions():
                    try:
                        usage = psutil.disk_usage(partition.mountpoint)
                        self.disk_usage.labels(mount_point=partition.mountpoint).set(
                            (usage.used / usage.total) * 100
                        )
                    except PermissionError:
                        pass
                
                time.sleep(30)
                
            except Exception as e:
                logging.error(f"Error collecting system metrics: {e}")
                time.sleep(60)
    
    def collect_database_metrics(self):
        """Collect database metrics"""
        while True:
            try:
                conn = mysql.connector.connect(**self.db_config)
                cursor = conn.cursor()
                
                # Active connections
                cursor.execute("SHOW PROCESSLIST")
                connections = len(cursor.fetchall())
                self.db_connections.labels(database='app_db').set(connections)
                
                # Slow queries (example)
                cursor.execute("""
                    SELECT COUNT(*) FROM information_schema.processlist 
                    WHERE time > 10 AND command != 'Sleep'
                """)
                slow_queries = cursor.fetchone()[0]
                
                cursor.close()
                conn.close()
                
                time.sleep(60)
                
            except Exception as e:
                logging.error(f"Error collecting database metrics: {e}")
                time.sleep(60)
    
    def collect_cache_metrics(self):
        """Collect cache metrics"""
        while True:
            try:
                # Redis stats
                info = self.redis_client.info()
                
                # Hit rate calculation would be done in application code
                # This is just an example of collecting Redis info
                connected_clients = info.get('connected_clients', 0)
                used_memory = info.get('used_memory', 0)
                
                time.sleep(30)
                
            except Exception as e:
                logging.error(f"Error collecting cache metrics: {e}")
                time.sleep(60)
    
    def collect_business_metrics(self):
        """Collect business metrics from application"""
        while True:
            try:
                # Example: Get active users from database
                conn = mysql.connector.connect(**self.db_config)
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT COUNT(DISTINCT user_id) 
                    FROM user_sessions 
                    WHERE last_activity > NOW() - INTERVAL 15 MINUTE
                """)
                active_users = cursor.fetchone()[0]
                self.active_users.set(active_users)
                
                # Example: Get queue sizes (from Redis)
                for queue_name in ['email_queue', 'processing_queue', 'notification_queue']:
                    queue_size = self.redis_client.llen(queue_name)
                    self.queue_size.labels(queue_name=queue_name).set(queue_size)
                
                cursor.close()
                conn.close()
                
                time.sleep(30)
                
            except Exception as e:
                logging.error(f"Error collecting business metrics: {e}")
                time.sleep(60)
    
    def track_request(self, method: str, endpoint: str, status: int, duration: float):
        """Track HTTP request metrics (called from application)"""
        self.request_count.labels(method=method, endpoint=endpoint, status=status).inc()
        self.request_duration.labels(method=method, endpoint=endpoint).observe(duration)
    
    def track_order(self, status: str, revenue: float = 0):
        """Track order metrics (called from application)"""
        self.orders_processed.labels(status=status).inc()
        if status == 'completed' and revenue > 0:
            self.revenue_total.inc(revenue)
    
    def start_collector(self):
        """Start the metrics collection"""
        # Start HTTP server for Prometheus scraping
        start_http_server(self.port, registry=self.registry)
        
        # Start background metric collection threads
        threads = [
            threading.Thread(target=self.collect_system_metrics, daemon=True),
            threading.Thread(target=self.collect_database_metrics, daemon=True),
            threading.Thread(target=self.collect_cache_metrics, daemon=True),
            threading.Thread(target=self.collect_business_metrics, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
        
        logging.info(f"Metrics exporter started on port {self.port}")
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Metrics exporter stopped")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    exporter = CustomMetricsExporter(port=8080)
    exporter.start_collector()
```

```yaml
# grafana-dashboard.json (as YAML for readability)
dashboard:
  title: "SRE Operations Dashboard"
  tags: ["sre", "monitoring", "operations"]
  timezone: "UTC"
  refresh: "30s"
  
  panels:
  - title: "Service Health Overview"
    type: "stat"
    targets:
    - expr: "up{job='application-metrics'}"
      legendFormat: "{{instance}}"
    fieldConfig:
      defaults:
        color:
          mode: "thresholds"
        thresholds:
          steps:
          - color: "red"
            value: 0
          - color: "green"
            value: 1
        unit: "short"
  
  - title: "Request Rate"
    type: "graph"
    targets:
    - expr: "rate(http_requests_total[5m])"
      legendFormat: "{{method}} {{endpoint}}"
    yAxes:
    - label: "Requests/second"
      min: 0
  
  - title: "Error Rate"
    type: "graph"
    targets:
    - expr: "rate(http_requests_total{status=~'5..'}[5m]) / rate(http_requests_total[5m]) * 100"
      legendFormat: "Error Rate %"
    yAxes:
    - label: "Error Rate %"
      min: 0
      max: 100
    alert:
      name: "High Error Rate"
      conditions:
      - query: "A"
        reducer: "last"
        evaluator:
          params: [5]
          type: "gt"
  
  - title: "Response Time (95th percentile)"
    type: "graph"
    targets:
    - expr: "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
      legendFormat: "95th percentile"
    - expr: "histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))"
      legendFormat: "50th percentile"
    yAxes:
    - label: "Response Time (seconds)"
      min: 0
  
  - title: "System Resources"
    type: "graph"
    targets:
    - expr: "cpu_usage_percent"
      legendFormat: "CPU Usage %"
    - expr: "memory_usage_percent"
      legendFormat: "Memory Usage %"
    yAxes:
    - label: "Usage %"
      min: 0
      max: 100
  
  - title: "Database Performance"
    type: "graph"
    targets:
    - expr: "database_connections_active"
      legendFormat: "Active Connections"
    - expr: "rate(database_query_duration_seconds_count[5m])"
      legendFormat: "Queries/sec"
    yAxes:
    - label: "Count"
      min: 0
  
  - title: "Business Metrics"
    type: "graph"
    targets:
    - expr: "active_users_total"
      legendFormat: "Active Users"
    - expr: "rate(orders_processed_total{status='completed'}[5m]) * 60"
      legendFormat: "Orders/min"
    yAxes:
    - label: "Count"
      min: 0
```

```yaml
# elk-stack.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: logging
---
# Elasticsearch
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: elasticsearch
  namespace: logging
spec:
  serviceName: elasticsearch
  replicas: 3
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
      - name: elasticsearch
        image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
        env:
        - name: cluster.name
          value: "logging-cluster"
        - name: node.name
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: discovery.seed_hosts
          value: "elasticsearch-0.elasticsearch,elasticsearch-1.elasticsearch,elasticsearch-2.elasticsearch"
        - name: cluster.initial_master_nodes
          value: "elasticsearch-0,elasticsearch-1,elasticsearch-2"
        - name: ES_JAVA_OPTS
          value: "-Xms1g -Xmx1g"
        - name: xpack.security.enabled
          value: "false"
        ports:
        - containerPort: 9200
          name: http
        - containerPort: 9300
          name: transport
        volumeMounts:
        - name: data
          mountPath: /usr/share/elasticsearch/data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
# Logstash
apiVersion: apps/v1
kind: Deployment
metadata:
  name: logstash
  namespace: logging
spec:
  replicas: 2
  selector:
    matchLabels:
      app: logstash
  template:
    metadata:
      labels:
        app: logstash
    spec:
      containers:
      - name: logstash
        image: docker.elastic.co/logstash/logstash:8.8.0
        ports:
        - containerPort: 5044
        volumeMounts:
        - name: config
          mountPath: /usr/share/logstash/pipeline
        env:
        - name: LS_JAVA_OPTS
          value: "-Xmx1g -Xms1g"
      volumes:
      - name: config
        configMap:
          name: logstash-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: logstash-config
  namespace: logging
data:
  logstash.conf: |
    input {
      beats {
        port => 5044
      }
    }
    
    filter {
      if [fields][log_type] == "application" {
        grok {
          match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{DATA:logger} - %{GREEDYDATA:message}" }
        }
        
        date {
          match => [ "timestamp", "ISO8601" ]
        }
        
        if [level] == "ERROR" {
          mutate {
            add_tag => [ "error" ]
          }
        }
      }
      
      if [fields][log_type] == "access" {
        grok {
          match => { "message" => "%{COMBINEDAPACHELOG}" }
        }
        
        mutate {
          convert => { "response" => "integer" }
          convert => { "bytes" => "integer" }
        }
        
        if [response] >= 400 {
          mutate {
            add_tag => [ "error" ]
          }
        }
      }
    }
    
    output {
      elasticsearch {
        hosts => ["elasticsearch:9200"]
        index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
      }
    }
```

**Expected Outcomes**:
- Complete observability stack deployed
- Custom metrics being collected and visualized
- Intelligent alerting configured
- Log aggregation and analysis working
- Distributed tracing operational

**Evaluation Criteria**:
- Monitoring coverage and depth
- Alert quality and noise reduction
- Dashboard usability and insights
- Performance impact of monitoring
- Troubleshooting effectiveness

---

## Service Level Objectives

### Exercise 2: SLI/SLO Implementation and Error Budget Management

**Objective**: Define and implement comprehensive SLIs, SLOs, and error budget management

**Requirements**:
- Define appropriate SLIs for your service
- Set realistic SLOs with business alignment
- Implement error budget calculation and tracking
- Create error budget burn rate alerts
- Set up SLO reporting and governance

**Time Limit**: 4 hours

**Deliverables**:

```python
# slo-manager.py
import time
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Optional
import yaml
import logging
from prometheus_client.parser import text_string_to_metric_families
import requests

@dataclass
class SLI:
    name: str
    description: str
    query: str
    unit: str
    target_type: str  # 'availability', 'latency', 'throughput'

@dataclass
class SLO:
    name: str
    description: str
    sli: SLI
    target: float  # e.g., 99.9 for 99.9%
    window: str    # e.g., "30d", "7d"
    
@dataclass
class ErrorBudget:
    slo_name: str
    budget_remaining: float
    burn_rate: float
    time_to_exhaustion: Optional[timedelta]

class SLOManager:
    def __init__(self, config_file: str, prometheus_url: str):
        self.prometheus_url = prometheus_url
        self.slos = self._load_slos(config_file)
        
    def _load_slos(self, config_file: str) -> Dict[str, SLO]:
        """Load SLO definitions from YAML config"""
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        slos = {}
        for slo_config in config['slos']:
            sli = SLI(
                name=slo_config['sli']['name'],
                description=slo_config['sli']['description'],
                query=slo_config['sli']['query'],
                unit=slo_config['sli']['unit'],
                target_type=slo_config['sli']['target_type']
            )
            
            slo = SLO(
                name=slo_config['name'],
                description=slo_config['description'],
                sli=sli,
                target=slo_config['target'],
                window=slo_config['window']
            )
            
            slos[slo.name] = slo
        
        return slos
    
    def query_prometheus(self, query: str, time_range: str = '1h') -> float:
        """Query Prometheus and return single value"""
        try:
            response = requests.get(
                f"{self.prometheus_url}/api/v1/query",
                params={
                    'query': query,
                    'time': datetime.utcnow().isoformat()
                }
            )
            
            result = response.json()
            if result['status'] == 'success' and result['data']['result']:
                return float(result['data']['result'][0]['value'][1])
            
            return 0.0
            
        except Exception as e:
            logging.error(f"Error querying Prometheus: {e}")
            return 0.0
    
    def calculate_sli_value(self, slo: SLO) -> float:
        """Calculate current SLI value"""
        return self.query_prometheus(slo.sli.query)
    
    def calculate_error_budget(self, slo: SLO) -> ErrorBudget:
        """Calculate error budget for SLO"""
        # Get current SLI performance over the window
        window_hours = self._parse_window_to_hours(slo.window)
        
        # Query for the time window
        if slo.sli.target_type == 'availability':
            # For availability, calculate success rate
            success_query = f"sum(rate(http_requests_total{{status!~'5..'}}"[{window_hours}h]))"
            total_query = f"sum(rate(http_requests_total[{window_hours}h]))"
            
            success_rate = self.query_prometheus(success_query)
            total_rate = self.query_prometheus(total_query)
            
            if total_rate > 0:
                current_availability = (success_rate / total_rate) * 100
            else:
                current_availability = 100.0
            
            # Calculate error budget
            allowed_error_rate = 100.0 - slo.target
            actual_error_rate = 100.0 - current_availability
            
            if allowed_error_rate > 0:
                budget_consumed = actual_error_rate / allowed_error_rate
                budget_remaining = max(0, 1.0 - budget_consumed)
            else:
                budget_remaining = 1.0 if current_availability >= slo.target else 0.0
            
        elif slo.sli.target_type == 'latency':
            # For latency, calculate percentage of requests under target
            under_target_query = f"""
                sum(rate(http_request_duration_seconds_bucket{{le="{slo.target/1000}"}}[{window_hours}h])) /
                sum(rate(http_request_duration_seconds_count[{window_hours}h])) * 100
            """
            
            current_performance = self.query_prometheus(under_target_query)
            
            # Calculate error budget (simplified)
            allowed_error_rate = 100.0 - 95.0  # Assuming 95% should be under target
            actual_error_rate = 100.0 - current_performance
            
            budget_consumed = actual_error_rate / allowed_error_rate if allowed_error_rate > 0 else 0
            budget_remaining = max(0, 1.0 - budget_consumed)
        
        else:
            budget_remaining = 1.0
        
        # Calculate burn rate (simplified - rate of budget consumption)
        burn_rate = self._calculate_burn_rate(slo, budget_remaining)
        
        # Calculate time to exhaustion
        time_to_exhaustion = None
        if burn_rate > 0 and budget_remaining > 0:
            hours_remaining = budget_remaining / burn_rate
            time_to_exhaustion = timedelta(hours=hours_remaining)
        
        return ErrorBudget(
            slo_name=slo.name,
            budget_remaining=budget_remaining,
            burn_rate=burn_rate,
            time_to_exhaustion=time_to_exhaustion
        )
    
    def _parse_window_to_hours(self, window: str) -> int:
        """Parse window string to hours"""
        if window.endswith('d'):
            return int(window[:-1]) * 24
        elif window.endswith('h'):
            return int(window[:-1])
        elif window.endswith('w'):
            return int(window[:-1]) * 24 * 7
        else:
            return 24  # Default to 1 day
    
    def _calculate_burn_rate(self, slo: SLO, current_budget: float) -> float:
        """Calculate current burn rate of error budget"""
        # This is a simplified calculation
        # In practice, you'd look at the rate of change over time
        window_hours = self._parse_window_to_hours(slo.window)
        
        # Get error rate over last hour
        error_rate_query = f"""
            (1 - (
                sum(rate(http_requests_total{{status!~'5..'}}[1h])) /
                sum(rate(http_requests_total[1h]))
            )) * 100
        """
        
        current_error_rate = self.query_prometheus(error_rate_query)
        allowed_error_rate = 100.0 - slo.target
        
        if allowed_error_rate > 0:
            hourly_burn_rate = current_error_rate / allowed_error_rate
            return hourly_burn_rate
        
        return 0.0
    
    def generate_slo_report(self) -> Dict:
        """Generate comprehensive SLO report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'slos': {}
        }
        
        for name, slo in self.slos.items():
            sli_value = self.calculate_sli_value(slo)
            error_budget = self.calculate_error_budget(slo)
            
            # Determine SLO status
            if sli_value >= slo.target:
                status = 'healthy'
            elif error_budget.budget_remaining > 0.1:  # 10% buffer
                status = 'at_risk'
            else:
                status = 'violated'
            
            report['slos'][name] = {
                'sli_value': sli_value,
                'target': slo.target,
                'status': status,
                'error_budget': {
                    'remaining': error_budget.budget_remaining,
                    'burn_rate': error_budget.burn_rate,
                    'time_to_exhaustion': error_budget.time_to_exhaustion.total_seconds() if error_budget.time_to_exhaustion else None
                }
            }
        
        return report
    
    def check_burn_rate_alerts(self) -> List[Dict]:
        """Check for burn rate alerts"""
        alerts = []
        
        for name, slo in self.slos.items():
            error_budget = self.calculate_error_budget(slo)
            
            # Fast burn alert (consuming 5% of monthly budget in 1 hour)
            if error_budget.burn_rate > 0.05:  # 5% per hour
                alerts.append({
                    'type': 'fast_burn',
                    'slo': name,
                    'severity': 'critical',
                    'message': f'Fast burn rate detected for {name}: {error_budget.burn_rate:.2%}/hour'
                })
            
            # Slow burn alert (consuming 10% of monthly budget in 6 hours)
            elif error_budget.burn_rate > 0.017:  # ~10% in 6 hours
                alerts.append({
                    'type': 'slow_burn',
                    'slo': name,
                    'severity': 'warning',
                    'message': f'Elevated burn rate detected for {name}: {error_budget.burn_rate:.2%}/hour'
                })
            
            # Budget exhaustion warning
            if (error_budget.time_to_exhaustion and 
                error_budget.time_to_exhaustion < timedelta(hours=24)):
                alerts.append({
                    'type': 'budget_exhaustion',
                    'slo': name,
                    'severity': 'critical',
                    'message': f'Error budget for {name} will be exhausted in {error_budget.time_to_exhaustion}'
                })
        
        return alerts

# Usage example
if __name__ == "__main__":
    # Configuration would be loaded from YAML file
    slo_config = """
    slos:
    - name: "api_availability"
      description: "API availability should be 99.9%"
      target: 99.9
      window: "30d"
      sli:
        name: "http_success_rate"
        description: "Percentage of successful HTTP requests"
        query: "sum(rate(http_requests_total{status!~'5..'}[5m])) / sum(rate(http_requests_total[5m])) * 100"
        unit: "percent"
        target_type: "availability"
    
    - name: "api_latency"
      description: "95% of requests should complete within 500ms"
      target: 500
      window: "30d"
      sli:
        name: "http_request_latency_p95"
        description: "95th percentile of HTTP request latency"
        query: "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) * 1000"
        unit: "milliseconds"
        target_type: "latency"
    """
    
    # Save config and create manager
    with open('/tmp/slo_config.yaml', 'w') as f:
        f.write(slo_config)
    
    manager = SLOManager('/tmp/slo_config.yaml', 'http://prometheus:9090')
    
    # Generate report
    report = manager.generate_slo_report()
    print("SLO Report:", report)
    
    # Check alerts
    alerts = manager.check_burn_rate_alerts()
    print("Alerts:", alerts)
```

```yaml
# slo-alerting-rules.yaml
groups:
- name: slo.rules
  interval: 30s
  rules:
  
  # API Availability SLO
  - record: sli:http_success_rate:5m
    expr: sum(rate(http_requests_total{status!~"5.."}[5m])) / sum(rate(http_requests_total[5m]))
  
  - record: sli:http_success_rate:30m
    expr: sum(rate(http_requests_total{status!~"5.."}[30m])) / sum(rate(http_requests_total[30m]))
  
  - record: sli:http_success_rate:1h
    expr: sum(rate(http_requests_total{status!~"5.."}[1h])) / sum(rate(http_requests_total[1h]))
  
  - record: sli:http_success_rate:6h
    expr: sum(rate(http_requests_total{status!~"5.."}[6h])) / sum(rate(http_requests_total[6h]))
  
  # Error budget burn rate calculation
  - record: slo:error_budget_burn_rate:1h
    expr: |
      (1 - sli:http_success_rate:1h) / (1 - 0.999)
  
  - record: slo:error_budget_burn_rate:6h
    expr: |
      (1 - sli:http_success_rate:6h) / (1 - 0.999)

- name: slo.alerts
  rules:
  
  # Fast burn rate alert (burning 5% of monthly budget in 1 hour)
  - alert: SLOErrorBudgetFastBurn
    expr: slo:error_budget_burn_rate:1h > 0.05
    for: 2m
    labels:
      severity: critical
      slo: api_availability
    annotations:
      summary: "Fast error budget burn rate detected"
      description: "API availability SLO is burning error budget at {{ $value | humanizePercentage }} per hour"
      runbook_url: "https://runbooks.company.com/slo-fast-burn"
  
  # Slow burn rate alert (burning 10% of monthly budget in 6 hours)
  - alert: SLOErrorBudgetSlowBurn
    expr: slo:error_budget_burn_rate:6h > 0.017
    for: 15m
    labels:
      severity: warning
      slo: api_availability
    annotations:
      summary: "Elevated error budget burn rate detected"
      description: "API availability SLO is burning error budget at {{ $value | humanizePercentage }} per hour over 6 hours"
      runbook_url: "https://runbooks.company.com/slo-slow-burn"
  
  # SLO violation alert
  - alert: SLOViolation
    expr: sli:http_success_rate:5m < 0.999
    for: 1m
    labels:
      severity: critical
      slo: api_availability
    annotations:
      summary: "SLO violation detected"
      description: "API availability is {{ $value | humanizePercentage }}, below SLO target of 99.9%"
      runbook_url: "https://runbooks.company.com/slo-violation"
  
  # Latency SLO
  - alert: LatencySLOViolation
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 0.5
    for: 5m
    labels:
      severity: warning
      slo: api_latency
    annotations:
      summary: "Latency SLO violation detected"
      description: "95th percentile latency is {{ $value }}s, above SLO target of 500ms"
      runbook_url: "https://runbooks.company.com/latency-slo-violation"
```

---

## Incident Response

### Exercise 3: Automated Incident Response System

**Objective**: Build an automated incident response system with on-call management

**Requirements**:
- Implement incident detection and classification
- Set up automated escalation and notification
- Create incident response playbooks
- Build incident tracking and post-mortem automation
- Configure on-call scheduling

**Time Limit**: 6 hours

**Deliverables**:

```python
# incident-manager.py
import json
import time
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
import requests
import logging
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

class IncidentSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class IncidentStatus(Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    IDENTIFIED = "identified"
    MONITORING = "monitoring"
    RESOLVED = "resolved"

@dataclass
class Incident:
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None
    escalated_to: Optional[str] = None
    war_room_channel: Optional[str] = None
    timeline: List[Dict] = None
    affected_services: List[str] = None
    
    def __post_init__(self):
        if self.timeline is None:
            self.timeline = []
        if self.affected_services is None:
            self.affected_services = []

class IncidentManager:
    def __init__(self, config: Dict):
        self.config = config
        self.slack_client = WebClient(token=config['slack_token'])
        self.incidents: Dict[str, Incident] = {}
        self.escalation_policies = config['escalation_policies']
        self.on_call_schedule = config['on_call_schedule']
        
    def create_incident(self, title: str, description: str, 
                       severity: IncidentSeverity, 
                       affected_services: List[str] = None) -> Incident:
        """Create a new incident"""
        
        incident_id = f"INC-{int(time.time())}"
        now = datetime.utcnow()
        
        incident = Incident(
            id=incident_id,
            title=title,
            description=description,
            severity=severity,
            status=IncidentStatus.OPEN,
            created_at=now,
            updated_at=now,
            affected_services=affected_services or []
        )
        
        self.incidents[incident_id] = incident
        
        # Add creation event to timeline
        self._add_timeline_event(incident, "incident_created", {
            "message": "Incident created",
            "severity": severity.value
        })
        
        # Auto-assign based on severity and on-call schedule
        self._auto_assign_incident(incident)
        
        # Create Slack war room
        self._create_war_room(incident)
        
        # Send initial notifications
        self._send_notifications(incident, "incident_created")
        
        # Start automated response
        self._start_automated_response(incident)
        
        logging.info(f"Created incident {incident_id}: {title}")
        return incident
    
    def update_incident(self, incident_id: str, **updates) -> Optional[Incident]:
        """Update an existing incident"""
        
        if incident_id not in self.incidents:
            return None
        
        incident = self.incidents[incident_id]
        old_status = incident.status
        
        # Update fields
        for field, value in updates.items():
            if hasattr(incident, field):
                setattr(incident, field, value)
        
        incident.updated_at = datetime.utcnow()
        
        # Add timeline event
        self._add_timeline_event(incident, "incident_updated", updates)
        
        # Check for status changes
        if 'status' in updates and updates['status'] != old_status:
            self._handle_status_change(incident, old_status, updates['status'])
        
        # Update Slack channel
        self._update_war_room(incident)
        
        return incident
    
    def escalate_incident(self, incident_id: str, reason: str = "") -> bool:
        """Escalate an incident to the next level"""
        
        if incident_id not in self.incidents:
            return False
        
        incident = self.incidents[incident_id]
        
        # Find escalation policy for severity
        policy = self.escalation_policies.get(incident.severity.value)
        if not policy:
            return False
        
        # Get current escalation level
        current_level = 0
        if incident.escalated_to:
            for i, level in enumerate(policy['levels']):
                if incident.escalated_to in level['responders']:
                    current_level = i + 1
                    break
        
        # Check if we can escalate further
        if current_level >= len(policy['levels']):
            logging.warning(f"Cannot escalate incident {incident_id} further")
            return False
        
        # Escalate to next level
        next_level = policy['levels'][current_level]
        incident.escalated_to = next_level['responders'][0]  # Take first responder
        
        self._add_timeline_event(incident, "incident_escalated", {
            "escalated_to": incident.escalated_to,
            "level": current_level + 1,
            "reason": reason
        })
        
        # Send escalation notifications
        self._send_escalation_notification(incident, reason)
        
        return True
    
    def resolve_incident(self, incident_id: str, resolution: str) -> bool:
        """Resolve an incident"""
        
        incident = self.update_incident(
            incident_id,
            status=IncidentStatus.RESOLVED,
            resolution=resolution
        )
        
        if incident:
            # Archive war room
            self._archive_war_room(incident)
            
            # Trigger post-mortem process
            self._trigger_post_mortem(incident)
            
            return True
        
        return False
    
    def _auto_assign_incident(self, incident: Incident):
        """Auto-assign incident based on on-call schedule"""
        
        # Find current on-call person for the severity level
        on_call_person = self._get_current_on_call(incident.severity)
        
        if on_call_person:
            incident.assigned_to = on_call_person
            self._add_timeline_event(incident, "incident_assigned", {
                "assigned_to": on_call_person,
                "method": "auto_assignment"
            })
    
    def _get_current_on_call(self, severity: IncidentSeverity) -> Optional[str]:
        """Get current on-call person for severity level"""
        
        now = datetime.utcnow()
        schedule_key = f"{severity.value}_on_call"
        
        if schedule_key in self.on_call_schedule:
            schedule = self.on_call_schedule[schedule_key]
            
            # Simple rotation based on day of year
            day_of_year = now.timetuple().tm_yday
            index = day_of_year % len(schedule)
            return schedule[index]
        
        return None
    
    def _create_war_room(self, incident: Incident):
        """Create Slack war room for incident"""
        
        try:
            channel_name = f"incident-{incident.id.lower()}"
            
            response = self.slack_client.conversations_create(
                name=channel_name,
                is_private=False
            )
            
            incident.war_room_channel = response['channel']['id']
            
            # Set channel topic
            self.slack_client.conversations_setTopic(
                channel=incident.war_room_channel,
                topic=f"{incident.title} | Severity: {incident.severity.value} | Status: {incident.status.value}"
            )
            
            # Invite relevant people
            invitees = [incident.assigned_to]
            if incident.escalated_to:
                invitees.append(incident.escalated_to)
            
            for user in invitees:
                if user:
                    try:
                        self.slack_client.conversations_invite(
                            channel=incident.war_room_channel,
                            users=user
                        )
                    except SlackApiError:
                        pass  # User might already be in channel
            
            # Post initial incident summary
            self._post_incident_summary(incident)
            
        except SlackApiError as e:
            logging.error(f"Failed to create war room: {e}")
    
    def _post_incident_summary(self, incident: Incident):
        """Post incident summary to war room"""
        
        if not incident.war_room_channel:
            return
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {incident.title}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Incident ID:* {incident.id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:* {incident.severity.value.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:* {incident.status.value.title()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Assigned:* <@{incident.assigned_to}>" if incident.assigned_to else "*Assigned:* Unassigned"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{incident.description}"
                }
            }
        ]
        
        if incident.affected_services:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Affected Services:* {', '.join(incident.affected_services)}"
                }
            })
        
        try:
            self.slack_client.chat_postMessage(
                channel=incident.war_room_channel,
                blocks=blocks,
                text=f"Incident {incident.id}: {incident.title}"
            )
        except SlackApiError as e:
            logging.error(f"Failed to post incident summary: {e}")
    
    def _send_notifications(self, incident: Incident, event_type: str):
        """Send notifications for incident events"""
        
        # Send to assigned person
        if incident.assigned_to:
            self._send_slack_dm(
                incident.assigned_to,
                f"🚨 You've been assigned to incident {incident.id}: {incident.title}"
            )
        
        # Send to escalation person
        if incident.escalated_to:
            self._send_slack_dm(
                incident.escalated_to,
                f"🚨 Incident {incident.id} has been escalated to you: {incident.title}"
            )
        
        # Send to general alert channel for critical incidents
        if incident.severity == IncidentSeverity.CRITICAL:
            self._send_to_alert_channel(incident, event_type)
    
    def _send_slack_dm(self, user_id: str, message: str):
        """Send direct message to user"""
        try:
            self.slack_client.chat_postMessage(
                channel=user_id,
                text=message
            )
        except SlackApiError as e:
            logging.error(f"Failed to send DM to {user_id}: {e}")
    
    def _send_to_alert_channel(self, incident: Incident, event_type: str):
        """Send alert to general alerting channel"""
        alert_channel = self.config.get('alert_channel')
        if not alert_channel:
            return
        
        color = {
            IncidentSeverity.CRITICAL: "danger",
            IncidentSeverity.HIGH: "warning",
            IncidentSeverity.MEDIUM: "good",
            IncidentSeverity.LOW: "good"
        }.get(incident.severity, "good")
        
        attachment = {
            "color": color,
            "title": f"Incident {incident.id}: {incident.title}",
            "text": incident.description,
            "fields": [
                {
                    "title": "Severity",
                    "value": incident.severity.value.upper(),
                    "short": True
                },
                {
                    "title": "Status",
                    "value": incident.status.value.title(),
                    "short": True
                }
            ]
        }
        
        if incident.war_room_channel:
            attachment["actions"] = [
                {
                    "type": "button",
                    "text": "Join War Room",
                    "url": f"https://slack.com/app_redirect?channel={incident.war_room_channel}"
                }
            ]
        
        try:
            self.slack_client.chat_postMessage(
                channel=alert_channel,
                text=f"New incident: {incident.title}",
                attachments=[attachment]
            )
        except SlackApiError as e:
            logging.error(f"Failed to send to alert channel: {e}")
    
    def _add_timeline_event(self, incident: Incident, event_type: str, data: Dict):
        """Add event to incident timeline"""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "data": data
        }
        incident.timeline.append(event)
    
    def _start_automated_response(self, incident: Incident):
        """Start automated response procedures"""
        
        # Run automated diagnostics
        self._run_diagnostics(incident)
        
        # Start auto-escalation timer for critical incidents
        if incident.severity == IncidentSeverity.CRITICAL:
            self._schedule_auto_escalation(incident, minutes=15)
    
    def _run_diagnostics(self, incident: Incident):
        """Run automated diagnostics"""
        
        diagnostics = []
        
        # Check service health
        for service in incident.affected_services:
            health = self._check_service_health(service)
            diagnostics.append(f"Service {service}: {health}")
        
        # Check recent deployments
        recent_deployments = self._check_recent_deployments()
        if recent_deployments:
            diagnostics.append(f"Recent deployments: {recent_deployments}")
        
        # Post diagnostics to war room
        if diagnostics and incident.war_room_channel:
            diagnostic_text = "🤖 **Automated Diagnostics:**\n" + "\n".join(f"• {d}" for d in diagnostics)
            
            try:
                self.slack_client.chat_postMessage(
                    channel=incident.war_room_channel,
                    text=diagnostic_text
                )
            except SlackApiError:
                pass
    
    def _check_service_health(self, service: str) -> str:
        """Check health of a service"""
        # This would integrate with your monitoring system
        # For demo purposes, return a placeholder
        return "Checking..."
    
    def _check_recent_deployments(self) -> str:
        """Check for recent deployments"""
        # This would integrate with your deployment system
        # For demo purposes, return a placeholder
        return "No recent deployments found"

# Example usage
if __name__ == "__main__":
    config = {
        'slack_token': 'xoxb-your-slack-token',
        'alert_channel': '#alerts',
        'escalation_policies': {
            'critical': {
                'levels': [
                    {'responders': ['on_call_engineer'], 'timeout_minutes': 15},
                    {'responders': ['team_lead'], 'timeout_minutes': 30},
                    {'responders': ['engineering_manager'], 'timeout_minutes': 60}
                ]
            },
            'high': {
                'levels': [
                    {'responders': ['on_call_engineer'], 'timeout_minutes': 30},
                    {'responders': ['team_lead'], 'timeout_minutes': 60}
                ]
            }
        },
        'on_call_schedule': {
            'critical_on_call': ['engineer1', 'engineer2', 'engineer3'],
            'high_on_call': ['engineer1', 'engineer2', 'engineer3']
        }
    }
    
    manager = IncidentManager(config)
    
    # Create a test incident
    incident = manager.create_incident(
        title="API Response Time Degradation",
        description="95th percentile API response time has increased to 2 seconds",
        severity=IncidentSeverity.HIGH,
        affected_services=["api-service", "user-service"]
    )
    
    print(f"Created incident: {incident.id}")
```

---

## Reliability Engineering

### Exercise 4: Chaos Engineering Implementation

**Objective**: Implement chaos engineering practices to test system resilience

**Requirements**:
- Set up chaos experiments with Chaos Monkey
- Implement circuit breakers and bulkheads
- Create resilience testing scenarios
- Build automated resilience validation
- Document failure modes and mitigations

**Time Limit**: 6 hours

**Expected Outcomes**:
- Chaos engineering experiments running
- Circuit breakers implemented and tested
- Resilience test suite automated
- Failure mode documentation
- System improvements identified

---

## Performance Engineering

### Exercise 5: Comprehensive Load Testing

**Objective**: Implement comprehensive performance testing and optimization

**Requirements**:
- Create realistic load testing scenarios
- Implement performance regression testing
- Set up capacity planning automation
- Build performance monitoring
- Optimize based on test results

**Expected Outcomes**:
- Load testing framework deployed
- Performance baselines established
- Capacity planning models created
- Performance regression detection
- Optimization recommendations

---

## Automation and Toil Reduction

### Exercise 6: Runbook Automation

**Objective**: Automate common operational tasks and runbooks

**Requirements**:
- Identify repetitive operational tasks
- Create automated runbooks
- Implement self-healing systems
- Build approval workflows for automation
- Measure toil reduction

**Expected Outcomes**:
- Automated runbooks implemented
- Self-healing capabilities deployed
- Toil measurement and reduction
- Approval workflows configured
- Operational efficiency improved

---

## 🎯 Interview Tips

### SRE Questions You Should Be Able to Answer:

1. **How do you define and implement SLIs and SLOs for a service?**
2. **Explain error budgets and how they influence release decisions**
3. **How would you design an incident response process?**
4. **What is chaos engineering and how do you implement it safely?**
5. **How do you measure and reduce toil in operations?**

### Practical Demonstrations:

1. **Live Monitoring Setup**: Deploy monitoring stack and create dashboards
2. **Incident Response**: Walk through incident handling procedures
3. **Chaos Experiments**: Run controlled failure experiments
4. **Performance Analysis**: Analyze performance data and optimization

---

## 📚 Additional Resources

- [Google SRE Books](https://sre.google/books/)
- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Chaos Engineering Principles](https://principlesofchaos.org/)
- [DORA State of DevOps Reports](https://cloud.google.com/devops/state-of-devops/)