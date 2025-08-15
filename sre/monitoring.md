# Monitoring & Observability 📊

## Core Monitoring Concepts

### 1. What are the four golden signals of monitoring?

**Answer:**

The four golden signals, popularized by Google's SRE book, are the key metrics for monitoring any user-facing system:

**1. Latency:**
- **Definition**: Time to service a request
- **Types**: Request latency, processing latency, queue latency
- **Measurement**: 50th, 95th, 99th percentiles
- **Example**: API response time < 200ms for 95% of requests

**2. Traffic:**
- **Definition**: Demand on your system
- **Measurement**: Requests per second, transactions per second
- **Example**: HTTP requests/second, database queries/second

**3. Errors:**
- **Definition**: Rate of failed requests
- **Types**: Explicit failures (HTTP 5xx), implicit failures (wrong content)
- **Measurement**: Error rate percentage
- **Example**: Error rate < 0.1% of all requests

**4. Saturation:**
- **Definition**: How "full" your service is
- **Measurement**: Resource utilization (CPU, memory, I/O)
- **Example**: CPU utilization < 70%, memory usage < 80%

```yaml
# Golden signals monitoring config
monitoring:
  latency:
    p50: < 100ms
    p95: < 200ms
    p99: < 500ms
  
  traffic:
    target: 1000 rps
    peak_capacity: 5000 rps
  
  errors:
    error_rate: < 0.1%
    availability: > 99.9%
  
  saturation:
    cpu: < 70%
    memory: < 80%
    disk: < 85%
```

---

### 2. What is the difference between monitoring, observability, and telemetry?

**Answer:**

**Monitoring:**
- **Definition**: Collecting and alerting on known failure modes
- **Approach**: Predefined metrics and dashboards
- **Questions**: "Is the system working?"
- **Scope**: Known issues and expected behaviors

**Observability:**
- **Definition**: Understanding system state from external outputs
- **Approach**: Exploratory analysis capabilities
- **Questions**: "Why is the system behaving this way?"
- **Scope**: Unknown unknowns and complex system behaviors

**Telemetry:**
- **Definition**: Automated collection and transmission of data
- **Approach**: Data collection infrastructure
- **Questions**: "What data do we have?"
- **Scope**: Raw data streams from systems

**Relationship:**
```
Telemetry → Monitoring → Observability
(Data Collection) → (Analysis & Alerting) → (Understanding & Insights)
```

---

### 3. How do you implement effective alerting strategies?

**Answer:**

**Alerting Principles:**

**1. Alert on Symptoms, Not Causes:**
- ✅ "Users experiencing slow response times"
- ❌ "CPU utilization is high"

**2. Actionable Alerts:**
- Every alert should require immediate action
- If no action needed, it's not an alert

**3. Alert Fatigue Prevention:**
- Use appropriate thresholds
- Implement alert escalation
- Group related alerts

**Alert Severity Levels:**

```yaml
alert_levels:
  critical:
    description: "Service down or severely degraded"
    response_time: "< 5 minutes"
    escalation: "Immediate page"
    examples:
      - "Service availability < 99%"
      - "Error rate > 5%"
  
  warning:
    description: "Service degraded but functional"
    response_time: "< 30 minutes"
    escalation: "Email + Slack"
    examples:
      - "Latency p95 > 500ms"
      - "Error rate > 1%"
  
  info:
    description: "Potential issues to investigate"
    response_time: "< 24 hours"
    escalation: "Slack notification"
    examples:
      - "Unusual traffic patterns"
      - "Resource usage trending up"
```

**Alert Implementation:**

```python
# AlertManager configuration
class AlertRule:
    def __init__(self, name, condition, severity, runbook):
        self.name = name
        self.condition = condition
        self.severity = severity
        self.runbook = runbook
    
    def to_prometheus_rule(self):
        return f"""
        alert: {self.name}
        expr: {self.condition}
        for: 5m
        labels:
          severity: {self.severity}
        annotations:
          summary: "{{{{ $labels.instance }}}} - {self.name}"
          runbook: {self.runbook}
        """

# Example alert rules
HIGH_ERROR_RATE = AlertRule(
    name="HighErrorRate",
    condition="rate(http_requests_total{status=~'5..'}[5m]) > 0.01",
    severity="critical",
    runbook="https://runbooks.company.com/high-error-rate"
)
```

---

### 4. How do you implement distributed tracing?

**Answer:**

**Distributed Tracing Concepts:**

**Trace:** Complete journey of a request through the system
**Span:** Individual operation within a trace
**Context Propagation:** Passing trace context between services

**OpenTelemetry Implementation:**

```python
# Python distributed tracing with OpenTelemetry
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor

# Configure tracer
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

# Configure Jaeger exporter
jaeger_exporter = JaegerExporter(
    agent_host_name="jaeger",
    agent_port=6831,
)

# Add span processor
span_processor = BatchSpanProcessor(jaeger_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# Auto-instrument Flask and requests
FlaskInstrumentor().instrument()
RequestsInstrumentor().instrument()

@app.route('/api/user/<user_id>')
def get_user(user_id):
    with tracer.start_as_current_span("get_user") as span:
        span.set_attribute("user.id", user_id)
        
        # Database call
        with tracer.start_as_current_span("database_query") as db_span:
            db_span.set_attribute("db.statement", f"SELECT * FROM users WHERE id = {user_id}")
            user_data = database.get_user(user_id)
        
        # External API call
        with tracer.start_as_current_span("external_api_call") as api_span:
            api_span.set_attribute("http.url", "https://api.external.com/profile")
            profile_data = requests.get(f"https://api.external.com/profile/{user_id}")
        
        return jsonify({"user": user_data, "profile": profile_data})
```

**Tracing Architecture:**

```yaml
# docker-compose.yml for tracing stack
version: '3.8'
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true

  app:
    build: .
    environment:
      - JAEGER_AGENT_HOST=jaeger
      - OTEL_EXPORTER_JAEGER_ENDPOINT=http://jaeger:14268/api/traces
    depends_on:
      - jaeger
```

---

### 5. How do you implement structured logging and log aggregation?

**Answer:**

**Structured Logging Best Practices:**

```python
# Structured logging with Python
import json
import logging
import time
from datetime import datetime

class StructuredLogger:
    def __init__(self, service_name, version):
        self.service_name = service_name
        self.version = version
        self.logger = logging.getLogger(service_name)
        
    def _log(self, level, message, **kwargs):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "service": self.service_name,
            "version": self.version,
            "message": message,
            **kwargs
        }
        
        if level == "ERROR":
            self.logger.error(json.dumps(log_entry))
        elif level == "WARN":
            self.logger.warning(json.dumps(log_entry))
        else:
            self.logger.info(json.dumps(log_entry))
    
    def info(self, message, **kwargs):
        self._log("INFO", message, **kwargs)
    
    def error(self, message, error=None, **kwargs):
        log_data = kwargs
        if error:
            log_data["error"] = str(error)
            log_data["error_type"] = type(error).__name__
        self._log("ERROR", message, **log_data)

# Usage example
logger = StructuredLogger("user-service", "1.2.3")

@app.route('/api/user/<user_id>')
def get_user(user_id):
    start_time = time.time()
    
    logger.info("Processing user request", 
                user_id=user_id, 
                request_id=request.headers.get('X-Request-ID'))
    
    try:
        user = database.get_user(user_id)
        
        logger.info("User request completed",
                   user_id=user_id,
                   response_time=time.time() - start_time,
                   status="success")
        
        return jsonify(user)
        
    except Exception as e:
        logger.error("User request failed",
                    user_id=user_id,
                    response_time=time.time() - start_time,
                    error=e)
        raise
```

**ELK Stack Configuration:**

```yaml
# Logstash configuration for structured logs
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][service] {
    # Parse JSON logs
    json {
      source => "message"
    }
    
    # Add service metadata
    mutate {
      add_field => { "service_name" => "%{[fields][service]}" }
    }
    
    # Parse error logs differently
    if [level] == "ERROR" {
      mutate {
        add_tag => ["error"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "logs-%{service_name}-%{+YYYY.MM.dd}"
  }
}
```

---

### 6. What are Service Level Indicators (SLIs) and how do you choose them?

**Answer:**

**SLI Selection Framework:**

**1. User-Centric SLIs:**
Focus on what users experience, not internal metrics.

**2. Request/Response SLIs:**
```yaml
web_service_slis:
  availability:
    definition: "Percentage of successful requests"
    measurement: "2xx responses / total responses"
    target: "> 99.9%"
  
  latency:
    definition: "Request response time"
    measurement: "95th percentile of response time"
    target: "< 200ms"
  
  quality:
    definition: "Correctness of responses"
    measurement: "Valid responses / total responses"
    target: "> 99.5%"
```

**3. Data Processing SLIs:**
```yaml
pipeline_slis:
  freshness:
    definition: "Age of the last processed record"
    measurement: "Time since last successful processing"
    target: "< 5 minutes"
  
  coverage:
    definition: "Percentage of data processed"
    measurement: "Records processed / records received"
    target: "> 99.9%"
  
  correctness:
    definition: "Accuracy of processed data"
    measurement: "Valid outputs / total outputs"
    target: "> 99.5%"
```

**4. Storage SLIs:**
```yaml
storage_slis:
  durability:
    definition: "Data loss rate"
    measurement: "Lost objects / total objects"
    target: "< 0.001%"
  
  availability:
    definition: "Successful read/write operations"
    measurement: "Successful operations / total operations"
    target: "> 99.99%"
```

**SLI Implementation:**

```python
# SLI measurement framework
class SLIMeasurement:
    def __init__(self, name, query, target, window="30d"):
        self.name = name
        self.query = query
        self.target = target
        self.window = window
    
    def measure(self, prometheus_client):
        """Measure current SLI value"""
        result = prometheus_client.query(self.query)
        current_value = float(result[0]['value'][1])
        
        return {
            'sli': self.name,
            'current_value': current_value,
            'target': self.target,
            'compliant': current_value >= self.target,
            'window': self.window
        }

# Example SLI definitions
availability_sli = SLIMeasurement(
    name="availability",
    query="""
    sum(rate(http_requests_total{status!~'5..'}[30d])) /
    sum(rate(http_requests_total[30d])) * 100
    """,
    target=99.9
)

latency_sli = SLIMeasurement(
    name="latency_p95",
    query="histogram_quantile(0.95, http_request_duration_seconds)",
    target=0.2  # 200ms
)
```

---

### 7. How do you implement effective synthetic monitoring?

**Answer:**

**Synthetic Monitoring Types:**

**1. Health Check Monitoring:**
```python
# Simple health check synthetic
import requests
import time
import json
from datetime import datetime

class HealthCheckMonitor:
    def __init__(self, config):
        self.endpoints = config['endpoints']
        self.interval = config.get('interval', 60)
        
    def check_endpoint(self, endpoint):
        start_time = time.time()
        
        try:
            response = requests.get(
                endpoint['url'],
                timeout=endpoint.get('timeout', 10),
                headers=endpoint.get('headers', {})
            )
            
            duration = time.time() - start_time
            
            return {
                'endpoint': endpoint['name'],
                'url': endpoint['url'],
                'status_code': response.status_code,
                'response_time': duration,
                'success': response.status_code == endpoint.get('expected_status', 200),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                'endpoint': endpoint['name'],
                'url': endpoint['url'],
                'error': str(e),
                'success': False,
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def run_checks(self):
        results = []
        for endpoint in self.endpoints:
            result = self.check_endpoint(endpoint)
            results.append(result)
            
            # Send metrics to monitoring system
            self.send_metrics(result)
        
        return results
    
    def send_metrics(self, result):
        # Send to Prometheus pushgateway
        metric_data = f"""
        synthetic_check_success{{endpoint="{result['endpoint']}"}} {1 if result['success'] else 0}
        synthetic_check_response_time{{endpoint="{result['endpoint']}"}} {result.get('response_time', 0)}
        """
        
        requests.post(
            'http://pushgateway:9091/metrics/job/synthetic_monitoring',
            data=metric_data
        )
```

**2. User Journey Monitoring:**
```python
# Selenium-based user journey synthetic
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

class UserJourneyMonitor:
    def __init__(self, config):
        self.config = config
        self.driver = None
    
    def setup_driver(self):
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        self.driver = webdriver.Chrome(options=options)
    
    def test_login_flow(self):
        """Test complete login user journey"""
        start_time = time.time()
        
        try:
            # Navigate to login page
            self.driver.get(f"{self.config['base_url']}/login")
            
            # Fill login form
            username_field = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "username"))
            )
            password_field = self.driver.find_element(By.ID, "password")
            
            username_field.send_keys(self.config['test_user'])
            password_field.send_keys(self.config['test_password'])
            
            # Submit form
            login_button = self.driver.find_element(By.ID, "login-button")
            login_button.click()
            
            # Wait for successful login
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "dashboard"))
            )
            
            duration = time.time() - start_time
            
            return {
                'journey': 'login_flow',
                'success': True,
                'duration': duration,
                'timestamp': time.time()
            }
            
        except Exception as e:
            return {
                'journey': 'login_flow',
                'success': False,
                'error': str(e),
                'duration': time.time() - start_time,
                'timestamp': time.time()
            }
        
        finally:
            if self.driver:
                self.driver.quit()
```

**3. API Workflow Monitoring:**
```python
# Complex API workflow synthetic
class APIWorkflowMonitor:
    def __init__(self, base_url, auth_token):
        self.base_url = base_url
        self.auth_token = auth_token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {auth_token}',
            'Content-Type': 'application/json'
        })
    
    def test_complete_workflow(self):
        """Test complete API workflow: Create -> Read -> Update -> Delete"""
        workflow_start = time.time()
        steps = []
        
        try:
            # Step 1: Create resource
            create_start = time.time()
            create_response = self.session.post(
                f"{self.base_url}/api/users",
                json={"name": "Test User", "email": "test@example.com"}
            )
            steps.append({
                'step': 'create',
                'success': create_response.status_code == 201,
                'duration': time.time() - create_start,
                'status_code': create_response.status_code
            })
            
            if create_response.status_code != 201:
                raise Exception(f"Create failed: {create_response.status_code}")
            
            user_id = create_response.json()['id']
            
            # Step 2: Read resource
            read_start = time.time()
            read_response = self.session.get(f"{self.base_url}/api/users/{user_id}")
            steps.append({
                'step': 'read',
                'success': read_response.status_code == 200,
                'duration': time.time() - read_start,
                'status_code': read_response.status_code
            })
            
            # Step 3: Update resource
            update_start = time.time()
            update_response = self.session.put(
                f"{self.base_url}/api/users/{user_id}",
                json={"name": "Updated User"}
            )
            steps.append({
                'step': 'update',
                'success': update_response.status_code == 200,
                'duration': time.time() - update_start,
                'status_code': update_response.status_code
            })
            
            # Step 4: Delete resource
            delete_start = time.time()
            delete_response = self.session.delete(f"{self.base_url}/api/users/{user_id}")
            steps.append({
                'step': 'delete',
                'success': delete_response.status_code == 204,
                'duration': time.time() - delete_start,
                'status_code': delete_response.status_code
            })
            
            total_duration = time.time() - workflow_start
            overall_success = all(step['success'] for step in steps)
            
            return {
                'workflow': 'crud_workflow',
                'success': overall_success,
                'total_duration': total_duration,
                'steps': steps,
                'timestamp': time.time()
            }
            
        except Exception as e:
            return {
                'workflow': 'crud_workflow',
                'success': False,
                'error': str(e),
                'total_duration': time.time() - workflow_start,
                'steps': steps,
                'timestamp': time.time()
            }
```

---

## 🛠️ Monitoring Tools and Technologies

### Prometheus + Grafana Stack

**Prometheus Configuration:**
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
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
  
  - job_name: 'application'
    static_configs:
      - targets: ['app:8080']
    metrics_path: '/metrics'
    scrape_interval: 5s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

**Grafana Dashboard as Code:**
```json
{
  "dashboard": {
    "title": "Application Performance",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{status}}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(http_requests_total{status=~'5..'}[5m]) / rate(http_requests_total[5m]) * 100",
            "legendFormat": "Error Rate %"
          }
        ]
      }
    ]
  }
}
```

### ELK Stack for Logging

**Elasticsearch Index Template:**
```json
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "timestamp": {"type": "date"},
        "level": {"type": "keyword"},
        "service": {"type": "keyword"},
        "message": {"type": "text"},
        "error": {"type": "text"},
        "user_id": {"type": "keyword"},
        "request_id": {"type": "keyword"}
      }
    }
  }
}
```

### OpenTelemetry Collector

```yaml
# otel-collector.yml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
  memory_limiter:
    limit_mib: 400

exporters:
  prometheus:
    endpoint: "0.0.0.0:8889"
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [jaeger]
    
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, batch]
      exporters: [prometheus]
```

---

## 📚 Best Practices

### 1. Monitoring Anti-Patterns to Avoid

❌ **Monitoring Everything**: Focus on user-facing metrics
❌ **Alert Fatigue**: Too many non-actionable alerts
❌ **Cargo Cult Monitoring**: Copying without understanding
❌ **Magic Number Thresholds**: Static thresholds without context
❌ **Tool Obsession**: Focusing on tools instead of outcomes

### 2. Effective Dashboard Design

✅ **Hierarchy**: Critical metrics at the top
✅ **Context**: Show normal ranges and patterns
✅ **Correlation**: Group related metrics together
✅ **Actionability**: Include links to runbooks
✅ **Audience**: Design for your users (developers, ops, executives)

### 3. Observability Maturity Model

**Level 1 - Basic Monitoring:**
- System metrics (CPU, memory, disk)
- Basic availability checks
- Simple alerting

**Level 2 - Application Monitoring:**
- Application metrics
- Log aggregation
- Dashboard creation

**Level 3 - Observability:**
- Distributed tracing
- Structured logging
- Correlation analysis

**Level 4 - Advanced Observability:**
- Automatic anomaly detection
- Predictive analytics
- Self-healing systems

---

This comprehensive monitoring guide covers the essential concepts, tools, and practices for implementing effective observability in modern systems, with practical examples and real-world implementations.