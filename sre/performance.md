# Performance & Reliability 📈

## Service Level Objectives (SLOs) and Error Budgets

### 1. How do you define effective SLIs and SLOs?

**Answer:**

**SLI (Service Level Indicator) Selection Framework:**

**1. User-Centric Metrics:**
Focus on what users actually experience, not internal system metrics.

```yaml
# Good SLIs - User-focused
availability_sli:
  definition: "Percentage of successful requests"
  measurement: "2xx responses / total responses * 100"
  user_impact: "Users can access the service"

latency_sli:
  definition: "Request response time"
  measurement: "95th percentile of response time"
  user_impact: "Service feels fast and responsive"

# Poor SLIs - System-focused
cpu_utilization:
  definition: "Server CPU usage"
  measurement: "Average CPU percentage"
  user_impact: "Not directly tied to user experience"
```

**2. SLO Definition Best Practices:**

```python
class SLODefinition:
    def __init__(self, name, sli_query, target, window):
        self.name = name
        self.sli_query = sli_query
        self.target = target  # e.g., 99.9 for 99.9%
        self.window = window  # e.g., "30d"
        self.error_budget = 100 - target
        
    def to_config(self):
        return {
            'name': self.name,
            'sli': self.sli_query,
            'target': self.target,
            'window': self.window,
            'error_budget_percent': self.error_budget
        }

# Example SLO definitions
AVAILABILITY_SLO = SLODefinition(
    name="api_availability",
    sli_query="""
    sum(rate(http_requests_total{status!~'5..'}[5m])) /
    sum(rate(http_requests_total[5m])) * 100
    """,
    target=99.9,
    window="30d"
)

LATENCY_SLO = SLODefinition(
    name="api_latency_p95",
    sli_query="histogram_quantile(0.95, http_request_duration_seconds)",
    target=0.2,  # 200ms
    window="30d"
)

QUALITY_SLO = SLODefinition(
    name="data_freshness",
    sli_query="time() - max(data_pipeline_last_success_timestamp)",
    target=300,  # 5 minutes
    window="7d"
)
```

**3. SLO Target Selection:**

```python
class SLOTargetCalculator:
    def __init__(self, historical_data):
        self.historical_data = historical_data
    
    def calculate_target_from_baseline(self, percentile=95):
        """Calculate SLO target based on historical performance"""
        
        # Use historical data to set realistic targets
        baseline_performance = np.percentile(self.historical_data, percentile)
        
        # Apply safety margin (typically 10-20% buffer)
        safety_margin = 0.1
        target = baseline_performance * (1 + safety_margin)
        
        return target
    
    def calculate_error_budget_consumption(self, actual_performance, target, window_days):
        """Calculate error budget consumption rate"""
        
        # Error budget for the window
        error_budget_total = (100 - target) * window_days
        
        # Current error rate
        current_error_rate = 100 - actual_performance
        
        # Budget consumption rate
        consumption_rate = current_error_rate / error_budget_total
        
        return {
            'error_budget_total': error_budget_total,
            'current_error_rate': current_error_rate,
            'consumption_rate': consumption_rate,
            'time_to_exhaustion': error_budget_total / current_error_rate if current_error_rate > 0 else float('inf')
        }
```

---

### 2. How do you implement error budget management?

**Answer:**

**Error Budget Framework:**

**1. Error Budget Calculation:**

```python
from datetime import datetime, timedelta
import math

class ErrorBudgetManager:
    def __init__(self, slo_config):
        self.slo_config = slo_config
        self.prometheus_client = PrometheusClient()
    
    def calculate_error_budget(self, slo_name, window_start, window_end):
        """Calculate error budget for a specific SLO and time window"""
        
        slo = self.slo_config[slo_name]
        window_duration = (window_end - window_start).total_seconds()
        
        # Query actual performance
        actual_sli = self.prometheus_client.query_range(
            slo['sli_query'],
            window_start,
            window_end
        )
        
        # Calculate error budget
        target = slo['target']
        error_budget_percent = 100 - target
        
        # Total allowable errors in the window
        total_requests = self._get_total_requests(window_start, window_end)
        total_error_budget = total_requests * (error_budget_percent / 100)
        
        # Actual errors
        actual_errors = self._get_actual_errors(window_start, window_end)
        
        # Budget remaining
        budget_remaining = total_error_budget - actual_errors
        budget_remaining_percent = (budget_remaining / total_error_budget) * 100
        
        return {
            'slo_name': slo_name,
            'window_start': window_start,
            'window_end': window_end,
            'target_percent': target,
            'actual_percent': self._calculate_actual_sli(actual_sli),
            'error_budget_percent': error_budget_percent,
            'total_error_budget': total_error_budget,
            'consumed_error_budget': actual_errors,
            'remaining_error_budget': budget_remaining,
            'remaining_percent': budget_remaining_percent,
            'burn_rate': self._calculate_burn_rate(actual_errors, window_duration)
        }
    
    def _calculate_burn_rate(self, consumed_budget, window_duration_seconds):
        """Calculate error budget burn rate per hour"""
        window_hours = window_duration_seconds / 3600
        return consumed_budget / window_hours if window_hours > 0 else 0
    
    def check_burn_rate_alerts(self, slo_name):
        """Check if error budget burn rate exceeds thresholds"""
        
        now = datetime.utcnow()
        
        # Check different time windows for burn rate
        windows = {
            '1h': timedelta(hours=1),
            '6h': timedelta(hours=6),
            '24h': timedelta(hours=24)
        }
        
        alerts = []
        
        for window_name, window_duration in windows.items():
            window_start = now - window_duration
            budget_info = self.calculate_error_budget(slo_name, window_start, now)
            
            # Define burn rate thresholds
            thresholds = {
                '1h': 14.4,   # 14.4x normal rate = budget exhausted in 2 hours
                '6h': 6.0,    # 6x normal rate = budget exhausted in 5 hours
                '24h': 3.0    # 3x normal rate = budget exhausted in 10 hours
            }
            
            # Normal burn rate (to exhaust budget exactly over SLO window)
            slo_window_hours = 30 * 24  # 30 days
            normal_burn_rate = 100 / slo_window_hours  # % per hour
            
            actual_burn_rate = budget_info['burn_rate']
            threshold_burn_rate = thresholds[window_name] * normal_burn_rate
            
            if actual_burn_rate > threshold_burn_rate:
                alerts.append({
                    'window': window_name,
                    'actual_burn_rate': actual_burn_rate,
                    'threshold': threshold_burn_rate,
                    'severity': self._get_burn_rate_severity(actual_burn_rate, normal_burn_rate),
                    'time_to_exhaustion': self._calculate_time_to_exhaustion(
                        budget_info['remaining_percent'], 
                        actual_burn_rate
                    )
                })
        
        return alerts
    
    def _get_burn_rate_severity(self, actual_rate, normal_rate):
        """Determine alert severity based on burn rate multiplier"""
        multiplier = actual_rate / normal_rate
        
        if multiplier > 10:
            return 'critical'
        elif multiplier > 5:
            return 'high'
        elif multiplier > 2:
            return 'medium'
        else:
            return 'low'
```

**2. Error Budget Policy:**

```yaml
# error-budget-policy.yml
error_budget_policy:
  slos:
    api_availability:
      target: 99.9
      window: "30d"
      error_budget: 0.1  # 0.1% error budget
      
  burn_rate_alerts:
    - window: "1h"
      threshold: 14.4  # 14.4x normal rate
      severity: "critical"
      action: "page_oncall"
    
    - window: "6h" 
      threshold: 6.0   # 6x normal rate
      severity: "high"
      action: "alert_team"
    
    - window: "24h"
      threshold: 3.0   # 3x normal rate
      severity: "medium"
      action: "create_ticket"
  
  error_budget_exhaustion:
    thresholds:
      - remaining: 10    # 10% budget remaining
        action: "freeze_risky_deployments"
      - remaining: 5     # 5% budget remaining  
        action: "freeze_all_deployments"
      - remaining: 0     # Budget exhausted
        action: "incident_response"
  
  deployment_gates:
    require_error_budget:
      minimum_remaining: 10  # Require 10% budget for deployments
      exceptions:
        - "security_patches"
        - "critical_bug_fixes"
```

**3. Error Budget-Based Deployment Decisions:**

```python
class DeploymentGate:
    def __init__(self, error_budget_manager, policy):
        self.error_budget_manager = error_budget_manager
        self.policy = policy
    
    def can_deploy(self, service_name, deployment_type="normal"):
        """Determine if deployment can proceed based on error budget"""
        
        # Get current error budget status
        now = datetime.utcnow()
        window_start = now - timedelta(days=30)
        
        budget_status = self.error_budget_manager.calculate_error_budget(
            service_name, window_start, now
        )
        
        remaining_percent = budget_status['remaining_percent']
        
        # Check policy rules
        policy_rules = self.policy['error_budget_exhaustion']['thresholds']
        
        # Special handling for emergency deployments
        if deployment_type in self.policy['deployment_gates']['exceptions']:
            return {
                'can_deploy': True,
                'reason': f"Emergency deployment type: {deployment_type}",
                'budget_remaining': remaining_percent
            }
        
        # Check if we have enough error budget
        minimum_required = self.policy['deployment_gates']['require_error_budget']['minimum_remaining']
        
        if remaining_percent < minimum_required:
            return {
                'can_deploy': False,
                'reason': f"Insufficient error budget: {remaining_percent}% remaining, {minimum_required}% required",
                'budget_remaining': remaining_percent,
                'recommended_action': "Wait for error budget to recover or classify as emergency"
            }
        
        # Check burn rate
        burn_rate_alerts = self.error_budget_manager.check_burn_rate_alerts(service_name)
        if any(alert['severity'] in ['critical', 'high'] for alert in burn_rate_alerts):
            return {
                'can_deploy': False,
                'reason': "High error budget burn rate detected",
                'budget_remaining': remaining_percent,
                'burn_rate_alerts': burn_rate_alerts
            }
        
        return {
            'can_deploy': True,
            'reason': "Sufficient error budget available",
            'budget_remaining': remaining_percent
        }
```

---

### 3. How do you implement capacity planning and forecasting?

**Answer:**

**Capacity Planning Framework:**

**1. Resource Utilization Analysis:**

```python
import numpy as np
from sklearn.linear_model import LinearRegression
from datetime import datetime, timedelta

class CapacityPlanner:
    def __init__(self, metrics_client):
        self.metrics_client = metrics_client
        
    def analyze_current_capacity(self, service_name, time_window_days=30):
        """Analyze current resource utilization and capacity"""
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=time_window_days)
        
        # Gather key metrics
        metrics = {
            'cpu_utilization': self._get_metric_percentiles(
                'cpu_utilization', service_name, start_time, end_time
            ),
            'memory_utilization': self._get_metric_percentiles(
                'memory_utilization', service_name, start_time, end_time
            ),
            'request_rate': self._get_metric_percentiles(
                'request_rate', service_name, start_time, end_time
            ),
            'response_time': self._get_metric_percentiles(
                'response_time', service_name, start_time, end_time
            )
        }
        
        # Calculate capacity headroom
        capacity_analysis = {}
        
        for metric_name, percentiles in metrics.items():
            if metric_name in ['cpu_utilization', 'memory_utilization']:
                # For utilization metrics, calculate headroom
                p95_utilization = percentiles['p95']
                headroom = 100 - p95_utilization
                
                capacity_analysis[metric_name] = {
                    'current_p95': p95_utilization,
                    'headroom_percent': headroom,
                    'saturation_risk': 'high' if headroom < 20 else 'medium' if headroom < 40 else 'low'
                }
        
        return capacity_analysis
    
    def forecast_capacity_needs(self, service_name, forecast_days=90):
        """Forecast future capacity needs based on historical trends"""
        
        # Get historical data for trend analysis
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=90)  # 90 days of history
        
        # Get request rate trend (main driver of capacity needs)
        request_rates = self._get_timeseries_data(
            'request_rate', service_name, start_time, end_time
        )
        
        # Prepare data for linear regression
        timestamps = np.array([r['timestamp'].timestamp() for r in request_rates]).reshape(-1, 1)
        values = np.array([r['value'] for r in request_rates])
        
        # Fit linear regression model
        model = LinearRegression()
        model.fit(timestamps, values)
        
        # Forecast future values
        future_timestamps = []
        forecast_start = end_time.timestamp()
        
        for days in range(1, forecast_days + 1):
            future_time = forecast_start + (days * 24 * 3600)
            future_timestamps.append(future_time)
        
        future_timestamps = np.array(future_timestamps).reshape(-1, 1)
        predicted_rates = model.predict(future_timestamps)
        
        # Calculate required capacity
        current_capacity = self._get_current_capacity(service_name)
        current_max_rate = max([r['value'] for r in request_rates])
        
        capacity_forecast = []
        for i, predicted_rate in enumerate(predicted_rates):
            days_ahead = i + 1
            
            # Calculate required instances based on predicted load
            required_capacity = (predicted_rate / current_max_rate) * current_capacity
            
            # Apply safety margin
            safety_margin = 1.2  # 20% buffer
            recommended_capacity = required_capacity * safety_margin
            
            capacity_forecast.append({
                'days_ahead': days_ahead,
                'predicted_request_rate': predicted_rate,
                'required_capacity': required_capacity,
                'recommended_capacity': recommended_capacity,
                'capacity_increase_needed': recommended_capacity > current_capacity
            })
        
        return {
            'current_capacity': current_capacity,
            'forecast': capacity_forecast,
            'trend_slope': model.coef_[0],
            'growth_rate_per_day': (model.coef_[0] / current_max_rate) * 100
        }
    
    def generate_capacity_recommendations(self, service_name):
        """Generate actionable capacity recommendations"""
        
        current_analysis = self.analyze_current_capacity(service_name)
        forecast = self.forecast_capacity_needs(service_name)
        
        recommendations = []
        
        # Check current saturation risks
        for metric, analysis in current_analysis.items():
            if analysis['saturation_risk'] == 'high':
                recommendations.append({
                    'type': 'immediate',
                    'priority': 'high',
                    'metric': metric,
                    'recommendation': f"Scale up {service_name} immediately - {metric} at {analysis['current_p95']:.1f}%",
                    'timeline': 'within 24 hours'
                })
        
        # Check forecast-based recommendations
        forecast_data = forecast['forecast']
        
        # Find when capacity increase will be needed
        for forecast_point in forecast_data:
            if forecast_point['capacity_increase_needed']:
                days_until_needed = forecast_point['days_ahead']
                
                if days_until_needed <= 30:  # Within 30 days
                    recommendations.append({
                        'type': 'planned',
                        'priority': 'medium',
                        'recommendation': f"Plan capacity increase for {service_name} in {days_until_needed} days",
                        'required_capacity': forecast_point['recommended_capacity'],
                        'timeline': f"within {days_until_needed} days"
                    })
                    break
        
        return recommendations
```

**2. Load Testing for Capacity Validation:**

```python
class LoadTestPlanner:
    def __init__(self, capacity_planner):
        self.capacity_planner = capacity_planner
    
    def design_load_test(self, service_name, target_capacity):
        """Design load test to validate capacity assumptions"""
        
        current_analysis = self.capacity_planner.analyze_current_capacity(service_name)
        current_capacity = self.capacity_planner._get_current_capacity(service_name)
        
        # Calculate test parameters
        test_scenarios = []
        
        # Baseline test - current capacity
        test_scenarios.append({
            'name': 'baseline',
            'target_rps': self._get_current_peak_rps(service_name),
            'duration': '10m',
            'ramp_up': '2m',
            'expected_behavior': 'normal performance'
        })
        
        # Stress test - 150% of current capacity
        test_scenarios.append({
            'name': 'stress',
            'target_rps': self._get_current_peak_rps(service_name) * 1.5,
            'duration': '10m',
            'ramp_up': '3m',
            'expected_behavior': 'graceful degradation'
        })
        
        # Peak capacity test - target capacity
        test_scenarios.append({
            'name': 'peak_capacity',
            'target_rps': target_capacity,
            'duration': '15m', 
            'ramp_up': '5m',
            'expected_behavior': 'maintain SLOs'
        })
        
        # Spike test - sudden traffic increase
        test_scenarios.append({
            'name': 'spike',
            'target_rps': target_capacity * 2,
            'duration': '5m',
            'ramp_up': '30s',
            'expected_behavior': 'auto-scaling response'
        })
        
        return {
            'service': service_name,
            'test_scenarios': test_scenarios,
            'success_criteria': self._define_success_criteria(),
            'monitoring_requirements': self._define_monitoring_requirements()
        }
    
    def _define_success_criteria(self):
        """Define what constitutes a successful load test"""
        return {
            'response_time_p95': '< 500ms',
            'error_rate': '< 1%',
            'availability': '> 99.9%',
            'auto_scaling': 'triggers within 2 minutes',
            'resource_utilization': 'CPU < 80%, Memory < 85%'
        }
```

**3. Auto-scaling Configuration:**

```yaml
# auto-scaling-config.yml
auto_scaling:
  cpu_based:
    target_cpu_utilization: 70
    scale_up_threshold: 80
    scale_down_threshold: 30
    cooldown_period: 300  # 5 minutes
    
  request_based:
    target_requests_per_instance: 100
    scale_up_threshold: 120
    scale_down_threshold: 50
    
  custom_metrics:
    queue_depth:
      target_value: 10
      scale_up_threshold: 20
      metric_query: "rabbitmq_queue_messages"
    
    response_time:
      target_value: 200  # ms
      scale_up_threshold: 500  # ms
      metric_query: "histogram_quantile(0.95, http_request_duration_seconds)"

scaling_policies:
  aggressive:
    scale_up_multiplier: 2.0
    scale_down_multiplier: 0.5
    min_instances: 2
    max_instances: 100
    
  conservative:
    scale_up_multiplier: 1.5
    scale_down_multiplier: 0.8
    min_instances: 3
    max_instances: 50
```

---

### 4. How do you implement performance testing strategies?

**Answer:**

**Performance Testing Framework:**

**1. Test Types and Strategies:**

```python
from enum import Enum
import asyncio
import aiohttp
import time
import statistics

class LoadTestType(Enum):
    BASELINE = "baseline"
    STRESS = "stress"
    SPIKE = "spike"
    VOLUME = "volume"
    ENDURANCE = "endurance"

class PerformanceTestRunner:
    def __init__(self, config):
        self.config = config
        self.results = []
        
    async def run_load_test(self, test_type: LoadTestType, target_url: str, test_config: dict):
        """Execute different types of load tests"""
        
        if test_type == LoadTestType.BASELINE:
            return await self._run_baseline_test(target_url, test_config)
        elif test_type == LoadTestType.STRESS:
            return await self._run_stress_test(target_url, test_config)
        elif test_type == LoadTestType.SPIKE:
            return await self._run_spike_test(target_url, test_config)
        elif test_type == LoadTestType.ENDURANCE:
            return await self._run_endurance_test(target_url, test_config)
        
    async def _run_baseline_test(self, url, config):
        """Run baseline performance test with normal load"""
        
        concurrent_users = config.get('concurrent_users', 10)
        duration_seconds = config.get('duration', 300)  # 5 minutes
        
        return await self._execute_load_pattern(
            url, 
            concurrent_users, 
            duration_seconds,
            ramp_up_seconds=60
        )
    
    async def _run_stress_test(self, url, config):
        """Gradually increase load until system breaks"""
        
        initial_users = config.get('initial_users', 10)
        max_users = config.get('max_users', 1000)
        step_size = config.get('step_size', 10)
        step_duration = config.get('step_duration', 120)  # 2 minutes per step
        
        results = []
        current_users = initial_users
        
        while current_users <= max_users:
            print(f"Testing with {current_users} concurrent users...")
            
            result = await self._execute_load_pattern(
                url, current_users, step_duration
            )
            
            results.append({
                'concurrent_users': current_users,
                'result': result
            })
            
            # Check if system is breaking down
            if (result['error_rate'] > 5.0 or 
                result['avg_response_time'] > 5000):  # 5 second threshold
                print(f"System breakdown detected at {current_users} users")
                break
                
            current_users += step_size
        
        return {
            'test_type': 'stress',
            'breakdown_point': current_users,
            'step_results': results
        }
    
    async def _run_spike_test(self, url, config):
        """Test system response to sudden traffic spikes"""
        
        baseline_users = config.get('baseline_users', 10)
        spike_users = config.get('spike_users', 100)
        spike_duration = config.get('spike_duration', 60)  # 1 minute spike
        
        # Run baseline for 2 minutes
        baseline_result = await self._execute_load_pattern(
            url, baseline_users, 120
        )
        
        # Execute spike
        spike_result = await self._execute_load_pattern(
            url, spike_users, spike_duration
        )
        
        # Return to baseline for 2 minutes
        recovery_result = await self._execute_load_pattern(
            url, baseline_users, 120
        )
        
        return {
            'test_type': 'spike',
            'baseline': baseline_result,
            'spike': spike_result,
            'recovery': recovery_result,
            'recovery_time': self._calculate_recovery_time(spike_result, recovery_result)
        }
    
    async def _execute_load_pattern(self, url, concurrent_users, duration_seconds, ramp_up_seconds=0):
        """Execute a specific load pattern"""
        
        start_time = time.time()
        response_times = []
        error_count = 0
        success_count = 0
        
        # Create semaphore for controlling concurrency
        semaphore = asyncio.Semaphore(concurrent_users)
        
        async def make_request(session):
            async with semaphore:
                try:
                    request_start = time.time()
                    async with session.get(url) as response:
                        await response.text()
                        request_time = (time.time() - request_start) * 1000  # ms
                        response_times.append(request_time)
                        
                        if response.status >= 400:
                            return 'error'
                        else:
                            return 'success'
                            
                except Exception as e:
                    return 'error'
        
        # Run test
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            while time.time() - start_time < duration_seconds:
                if len(tasks) < concurrent_users:
                    task = asyncio.create_task(make_request(session))
                    tasks.append(task)
                
                # Collect completed tasks
                done_tasks = [task for task in tasks if task.done()]
                for task in done_tasks:
                    result = await task
                    if result == 'success':
                        success_count += 1
                    else:
                        error_count += 1
                    tasks.remove(task)
                
                await asyncio.sleep(0.1)  # Small delay
            
            # Wait for remaining tasks
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        
        # Calculate metrics
        total_requests = success_count + error_count
        error_rate = (error_count / total_requests) * 100 if total_requests > 0 else 0
        
        return {
            'duration_seconds': duration_seconds,
            'concurrent_users': concurrent_users,
            'total_requests': total_requests,
            'successful_requests': success_count,
            'failed_requests': error_count,
            'error_rate': error_rate,
            'avg_response_time': statistics.mean(response_times) if response_times else 0,
            'p95_response_time': self._percentile(response_times, 95) if response_times else 0,
            'p99_response_time': self._percentile(response_times, 99) if response_times else 0,
            'requests_per_second': total_requests / duration_seconds,
            'throughput': success_count / duration_seconds
        }
    
    def _percentile(self, data, percentile):
        """Calculate percentile of a dataset"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        return sorted_data[min(index, len(sorted_data) - 1)]
```

**2. Performance Test Configuration:**

```yaml
# performance-test-config.yml
performance_tests:
  api_baseline:
    type: "baseline"
    target_url: "https://api.example.com/health"
    concurrent_users: 50
    duration: 600  # 10 minutes
    ramp_up: 120   # 2 minutes
    success_criteria:
      error_rate: "< 1%"
      avg_response_time: "< 200ms"
      p95_response_time: "< 500ms"
  
  api_stress:
    type: "stress"
    target_url: "https://api.example.com/users"
    initial_users: 10
    max_users: 500
    step_size: 25
    step_duration: 180  # 3 minutes per step
    success_criteria:
      breakdown_threshold: "> 300 users"
      graceful_degradation: true
  
  api_spike:
    type: "spike"
    target_url: "https://api.example.com/search"
    baseline_users: 20
    spike_users: 200
    spike_duration: 300  # 5 minutes
    success_criteria:
      spike_error_rate: "< 5%"
      recovery_time: "< 120s"

monitoring:
  metrics_to_track:
    - "response_time_percentiles"
    - "error_rate"
    - "throughput"
    - "cpu_utilization"
    - "memory_usage"
    - "database_connections"
    - "queue_depth"
  
  alert_thresholds:
    error_rate: 5.0
    avg_response_time: 1000  # ms
    cpu_utilization: 80.0
    memory_usage: 85.0
```

**3. Performance Regression Detection:**

```python
class PerformanceRegressionDetector:
    def __init__(self, baseline_storage):
        self.baseline_storage = baseline_storage
        
    def detect_regression(self, current_results, test_name):
        """Detect performance regressions by comparing with baseline"""
        
        baseline = self.baseline_storage.get_baseline(test_name)
        if not baseline:
            # No baseline exists, store current as baseline
            self.baseline_storage.store_baseline(test_name, current_results)
            return {'regression_detected': False, 'reason': 'No baseline available'}
        
        regressions = []
        
        # Check key performance metrics
        metrics_to_check = [
            'avg_response_time',
            'p95_response_time', 
            'p99_response_time',
            'error_rate',
            'throughput'
        ]
        
        for metric in metrics_to_check:
            current_value = current_results.get(metric, 0)
            baseline_value = baseline.get(metric, 0)
            
            regression_threshold = self._get_regression_threshold(metric)
            
            if self._is_regression(metric, current_value, baseline_value, regression_threshold):
                regressions.append({
                    'metric': metric,
                    'current_value': current_value,
                    'baseline_value': baseline_value,
                    'change_percent': ((current_value - baseline_value) / baseline_value) * 100,
                    'threshold': regression_threshold
                })
        
        return {
            'regression_detected': len(regressions) > 0,
            'regressions': regressions,
            'severity': self._calculate_regression_severity(regressions)
        }
    
    def _get_regression_threshold(self, metric):
        """Get acceptable regression threshold for each metric"""
        thresholds = {
            'avg_response_time': 0.15,      # 15% increase is regression
            'p95_response_time': 0.20,      # 20% increase is regression
            'p99_response_time': 0.25,      # 25% increase is regression
            'error_rate': 0.50,             # 50% increase is regression
            'throughput': -0.10             # 10% decrease is regression
        }
        return thresholds.get(metric, 0.10)  # Default 10%
    
    def _is_regression(self, metric, current, baseline, threshold):
        """Determine if current value represents a regression"""
        if baseline == 0:
            return False
            
        change_percent = (current - baseline) / baseline
        
        # For throughput, we want higher values (regression is decrease)
        if metric == 'throughput':
            return change_percent < threshold
        
        # For other metrics, regression is increase
        return change_percent > threshold
```

---

### 5. How do you implement chaos engineering for reliability testing?

**Answer:**

**Chaos Engineering Framework:**

**1. Chaos Experiment Design:**

```python
from abc import ABC, abstractmethod
import random
import time
from datetime import datetime

class ChaosExperiment(ABC):
    def __init__(self, name, description, blast_radius):
        self.name = name
        self.description = description
        self.blast_radius = blast_radius  # scope of impact
        self.steady_state_hypothesis = None
        self.experiment_steps = []
        
    @abstractmethod
    def define_steady_state(self):
        """Define what normal system behavior looks like"""
        pass
    
    @abstractmethod
    def inject_chaos(self):
        """Implement the chaos injection"""
        pass
    
    @abstractmethod
    def verify_hypothesis(self):
        """Check if system maintains steady state during chaos"""
        pass
    
    def run_experiment(self):
        """Execute the complete chaos experiment"""
        
        print(f"Starting chaos experiment: {self.name}")
        
        # 1. Establish baseline
        baseline = self.define_steady_state()
        if not baseline['healthy']:
            return {'status': 'aborted', 'reason': 'System not in steady state'}
        
        # 2. Inject chaos
        chaos_result = self.inject_chaos()
        
        # 3. Monitor system behavior
        verification_result = self.verify_hypothesis()
        
        # 4. Clean up
        self.cleanup()
        
        return {
            'experiment': self.name,
            'baseline': baseline,
            'chaos_injection': chaos_result,
            'verification': verification_result,
            'conclusion': self._analyze_results(verification_result)
        }

class InstanceTerminationExperiment(ChaosExperiment):
    def __init__(self, service_name, instance_percentage=10):
        super().__init__(
            name=f"Instance Termination - {service_name}",
            description=f"Randomly terminate {instance_percentage}% of {service_name} instances",
            blast_radius=f"{instance_percentage}% of {service_name} instances"
        )
        self.service_name = service_name
        self.instance_percentage = instance_percentage
        self.terminated_instances = []
        
    def define_steady_state(self):
        """Verify service is healthy before experiment"""
        
        # Check service health metrics
        health_checks = {
            'availability': self._check_availability(),
            'response_time': self._check_response_time(),
            'error_rate': self._check_error_rate(),
            'instance_count': self._get_healthy_instance_count()
        }
        
        all_healthy = all([
            health_checks['availability'] > 99.0,
            health_checks['response_time'] < 500,  # ms
            health_checks['error_rate'] < 1.0,     # %
            health_checks['instance_count'] >= 3   # minimum instances
        ])
        
        return {
            'healthy': all_healthy,
            'metrics': health_checks,
            'timestamp': datetime.utcnow()
        }
    
    def inject_chaos(self):
        """Terminate random instances"""
        
        available_instances = self._get_service_instances(self.service_name)
        instance_count = len(available_instances)
        
        terminate_count = max(1, int(instance_count * self.instance_percentage / 100))
        
        # Randomly select instances to terminate
        self.terminated_instances = random.sample(available_instances, terminate_count)
        
        termination_results = []
        for instance in self.terminated_instances:
            result = self._terminate_instance(instance['id'])
            termination_results.append({
                'instance_id': instance['id'],
                'termination_time': datetime.utcnow(),
                'success': result
            })
            
            # Add small delay between terminations
            time.sleep(2)
        
        return {
            'terminated_count': len(self.terminated_instances),
            'total_instances': instance_count,
            'termination_results': termination_results
        }
    
    def verify_hypothesis(self):
        """Monitor system behavior during chaos"""
        
        # Monitor for 5 minutes after chaos injection
        monitoring_duration = 300  # seconds
        sample_interval = 30       # seconds
        
        metrics_samples = []
        start_time = time.time()
        
        while time.time() - start_time < monitoring_duration:
            sample = {
                'timestamp': datetime.utcnow(),
                'availability': self._check_availability(),
                'response_time': self._check_response_time(),
                'error_rate': self._check_error_rate(),
                'healthy_instances': self._get_healthy_instance_count()
            }
            
            metrics_samples.append(sample)
            time.sleep(sample_interval)
        
        # Analyze results
        return self._analyze_monitoring_data(metrics_samples)

class NetworkLatencyExperiment(ChaosExperiment):
    def __init__(self, service_name, target_service, latency_ms=1000):
        super().__init__(
            name=f"Network Latency - {service_name} to {target_service}",
            description=f"Inject {latency_ms}ms latency between {service_name} and {target_service}",
            blast_radius=f"Communication between {service_name} and {target_service}"
        )
        self.service_name = service_name
        self.target_service = target_service
        self.latency_ms = latency_ms
        
    def inject_chaos(self):
        """Inject network latency using traffic control"""
        
        # Use tc (traffic control) to add latency
        latency_command = f"""
        tc qdisc add dev eth0 root handle 1: prio
        tc qdisc add dev eth0 parent 1:3 handle 30: netem delay {self.latency_ms}ms
        tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 \\
            match ip dst {self._get_service_ip(self.target_service)} flowid 1:3
        """
        
        result = self._execute_command(latency_command)
        
        return {
            'latency_injected': self.latency_ms,
            'target_service': self.target_service,
            'injection_success': result['success'],
            'injection_time': datetime.utcnow()
        }
    
    def cleanup(self):
        """Remove network latency injection"""
        cleanup_command = "tc qdisc del dev eth0 root"
        self._execute_command(cleanup_command)

class DatabaseConnectionExperiment(ChaosExperiment):
    def __init__(self, service_name, connection_kill_percentage=50):
        super().__init__(
            name=f"Database Connection Chaos - {service_name}",
            description=f"Kill {connection_kill_percentage}% of database connections",
            blast_radius=f"{connection_kill_percentage}% of database connections"
        )
        self.service_name = service_name
        self.connection_kill_percentage = connection_kill_percentage
        
    def inject_chaos(self):
        """Kill database connections"""
        
        # Get active connections
        active_connections = self._get_active_db_connections()
        kill_count = int(len(active_connections) * self.connection_kill_percentage / 100)
        
        connections_to_kill = random.sample(active_connections, kill_count)
        
        killed_connections = []
        for conn in connections_to_kill:
            result = self._kill_db_connection(conn['pid'])
            killed_connections.append({
                'connection_id': conn['pid'],
                'client_addr': conn['client_addr'],
                'kill_success': result
            })
        
        return {
            'total_connections': len(active_connections),
            'killed_count': len(killed_connections),
            'killed_connections': killed_connections
        }
```

**2. Chaos Experiment Configuration:**

```yaml
# chaos-experiments.yml
chaos_experiments:
  instance_termination:
    enabled: true
    schedule: "0 14 * * 1-5"  # Weekdays at 2 PM
    config:
      service_name: "web-service"
      instance_percentage: 20
      monitoring_duration: 300
      rollback_on_failure: true
    
    success_criteria:
      availability_threshold: 99.0
      max_response_time: 1000
      max_error_rate: 5.0
      auto_recovery_time: 120
  
  network_latency:
    enabled: true
    schedule: "0 10 * * 2,4"  # Tuesday and Thursday at 10 AM
    config:
      service_name: "api-service"
      target_service: "database"
      latency_ms: 500
      duration: 600
    
    success_criteria:
      circuit_breaker_activation: true
      timeout_handling: true
      user_experience_degradation: "acceptable"
  
  dependency_failure:
    enabled: true
    schedule: "0 15 * * 3"  # Wednesday at 3 PM
    config:
      service_name: "order-service"
      dependency: "payment-service"
      failure_type: "complete_outage"
      duration: 300
    
    success_criteria:
      graceful_degradation: true
      fallback_activation: true
      data_consistency: maintained

safety_settings:
  blast_radius_limits:
    max_instance_percentage: 30
    max_services_affected: 1
    restricted_hours: ["00:00-06:00", "18:00-23:59"]
  
  abort_conditions:
    - "error_rate > 10%"
    - "availability < 95%"
    - "response_time > 5000ms"
  
  approval_required:
    - "production_environment"
    - "customer_facing_services"
    - "peak_hours"
```

**3. Chaos Engineering Pipeline:**

```python
class ChaosEngineeringPipeline:
    def __init__(self, config):
        self.config = config
        self.experiment_registry = {}
        self.safety_manager = SafetyManager(config['safety_settings'])
        
    def register_experiment(self, experiment):
        """Register a chaos experiment"""
        self.experiment_registry[experiment.name] = experiment
        
    def schedule_experiments(self):
        """Schedule and execute chaos experiments"""
        
        for experiment_name, experiment_config in self.config['chaos_experiments'].items():
            if not experiment_config['enabled']:
                continue
                
            # Check safety constraints
            if not self.safety_manager.is_safe_to_run(experiment_name):
                print(f"Skipping {experiment_name} - safety constraints not met")
                continue
            
            # Execute experiment
            experiment = self._create_experiment(experiment_name, experiment_config)
            result = experiment.run_experiment()
            
            # Store results and generate report
            self._store_experiment_result(experiment_name, result)
            self._generate_report(experiment_name, result)
    
    def _create_experiment(self, name, config):
        """Factory method to create experiment instances"""
        
        experiment_types = {
            'instance_termination': InstanceTerminationExperiment,
            'network_latency': NetworkLatencyExperiment,
            'database_connection': DatabaseConnectionExperiment
        }
        
        experiment_class = experiment_types.get(name)
        if not experiment_class:
            raise ValueError(f"Unknown experiment type: {name}")
            
        return experiment_class(**config['config'])

class SafetyManager:
    def __init__(self, safety_config):
        self.safety_config = safety_config
        
    def is_safe_to_run(self, experiment_name):
        """Check if it's safe to run the experiment"""
        
        # Check time restrictions
        if not self._is_allowed_time():
            return False
            
        # Check system health
        if not self._is_system_healthy():
            return False
            
        # Check blast radius
        if not self._is_blast_radius_acceptable(experiment_name):
            return False
            
        return True
    
    def _is_allowed_time(self):
        """Check if current time is allowed for chaos experiments"""
        current_time = datetime.now().strftime("%H:%M")
        
        restricted_hours = self.safety_config.get('restricted_hours', [])
        for restriction in restricted_hours:
            start_time, end_time = restriction.split('-')
            if start_time <= current_time <= end_time:
                return False
                
        return True
```

---

## 📊 Reliability Metrics and KPIs

### System Reliability Metrics

```python
class ReliabilityMetrics:
    def __init__(self, metrics_store):
        self.metrics_store = metrics_store
    
    def calculate_availability(self, service_name, time_window):
        """Calculate service availability percentage"""
        
        total_time = time_window.total_seconds()
        downtime = self._get_total_downtime(service_name, time_window)
        
        availability = ((total_time - downtime) / total_time) * 100
        return availability
    
    def calculate_mtbf(self, service_name, time_window):
        """Calculate Mean Time Between Failures"""
        
        incidents = self._get_incidents(service_name, time_window)
        if len(incidents) <= 1:
            return float('inf')  # No failures or only one failure
        
        time_between_failures = []
        for i in range(1, len(incidents)):
            time_diff = incidents[i].start_time - incidents[i-1].end_time
            time_between_failures.append(time_diff.total_seconds())
        
        return sum(time_between_failures) / len(time_between_failures)
    
    def calculate_reliability_score(self, service_name, time_window):
        """Calculate overall reliability score (0-100)"""
        
        weights = {
            'availability': 0.4,
            'performance': 0.3, 
            'quality': 0.2,
            'recovery': 0.1
        }
        
        scores = {
            'availability': self._score_availability(service_name, time_window),
            'performance': self._score_performance(service_name, time_window),
            'quality': self._score_quality(service_name, time_window),
            'recovery': self._score_recovery(service_name, time_window)
        }
        
        reliability_score = sum(weights[metric] * scores[metric] for metric in weights)
        
        return {
            'overall_score': reliability_score,
            'component_scores': scores,
            'weights': weights
        }
```

---

This comprehensive performance and reliability guide covers SLOs, error budgets, capacity planning, performance testing, and chaos engineering with practical implementations and real-world examples.