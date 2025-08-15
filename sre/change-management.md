# Change Management 📋

## Safe Deployment Practices and Rollback Strategies

### 1. How do you implement safe deployment strategies?

**Answer:**

**Deployment Strategy Framework:**

```python
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Any, Optional
import time
import threading
from dataclasses import dataclass

class DeploymentStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

class HealthCheckResult(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

@dataclass
class DeploymentConfig:
    service_name: str
    version: str
    strategy: str
    health_check_url: str
    rollback_threshold_error_rate: float = 5.0
    rollback_threshold_latency_ms: float = 1000.0
    canary_percentage: int = 10
    canary_duration_minutes: int = 30

class DeploymentStrategy(ABC):
    def __init__(self, config: DeploymentConfig):
        self.config = config
        self.status = DeploymentStatus.PENDING
        self.start_time = None
        self.end_time = None
        self.health_monitor = HealthMonitor(config.health_check_url)
    
    @abstractmethod
    def deploy(self) -> bool:
        """Execute deployment strategy"""
        pass
    
    @abstractmethod
    def rollback(self) -> bool:
        """Rollback deployment"""
        pass
    
    def check_deployment_health(self) -> HealthCheckResult:
        """Check health of deployment"""
        return self.health_monitor.check_health()

class BlueGreenDeployment(DeploymentStrategy):
    """Blue-Green deployment strategy"""
    
    def __init__(self, config: DeploymentConfig):
        super().__init__(config)
        self.blue_instances = []
        self.green_instances = []
        self.load_balancer = LoadBalancerController()
    
    def deploy(self) -> bool:
        """Execute blue-green deployment"""
        
        self.status = DeploymentStatus.IN_PROGRESS
        self.start_time = time.time()
        
        try:
            # Step 1: Deploy to green environment
            print(f"Deploying {self.config.service_name} v{self.config.version} to green environment")
            if not self._deploy_to_green():
                raise Exception("Green deployment failed")
            
            # Step 2: Health check green environment
            print("Running health checks on green environment")
            if not self._health_check_green():
                raise Exception("Green environment health check failed")
            
            # Step 3: Switch traffic to green
            print("Switching traffic to green environment")
            if not self._switch_to_green():
                raise Exception("Traffic switch failed")
            
            # Step 4: Monitor for a period
            print("Monitoring green environment...")
            if not self._monitor_deployment():
                raise Exception("Post-deployment monitoring detected issues")
            
            # Step 5: Cleanup old blue environment
            print("Cleaning up blue environment")
            self._cleanup_blue()
            
            self.status = DeploymentStatus.SUCCESS
            self.end_time = time.time()
            return True
            
        except Exception as e:
            print(f"Deployment failed: {str(e)}")
            self.rollback()
            return False
    
    def rollback(self) -> bool:
        """Rollback to blue environment"""
        
        print("Rolling back to blue environment")
        
        try:
            # Switch traffic back to blue
            self.load_balancer.switch_to_blue()
            
            # Verify blue environment health
            if self._health_check_blue():
                self.status = DeploymentStatus.ROLLED_BACK
                print("Rollback successful")
                return True
            else:
                print("Blue environment also unhealthy - manual intervention required")
                return False
                
        except Exception as e:
            print(f"Rollback failed: {str(e)}")
            return False
    
    def _deploy_to_green(self) -> bool:
        """Deploy new version to green environment"""
        # Implementation would deploy to green instances
        time.sleep(2)  # Simulate deployment time
        return True
    
    def _health_check_green(self) -> bool:
        """Health check green environment"""
        result = self.health_monitor.check_health()
        return result == HealthCheckResult.HEALTHY
    
    def _switch_to_green(self) -> bool:
        """Switch load balancer to green"""
        return self.load_balancer.switch_to_green()
    
    def _monitor_deployment(self) -> bool:
        """Monitor deployment for issues"""
        
        monitor_duration = 5 * 60  # 5 minutes
        check_interval = 30  # 30 seconds
        
        start_time = time.time()
        
        while time.time() - start_time < monitor_duration:
            metrics = self.health_monitor.get_metrics()
            
            # Check error rate
            if metrics['error_rate'] > self.config.rollback_threshold_error_rate:
                print(f"Error rate too high: {metrics['error_rate']}%")
                return False
            
            # Check latency
            if metrics['p95_latency'] > self.config.rollback_threshold_latency_ms:
                print(f"Latency too high: {metrics['p95_latency']}ms")
                return False
            
            time.sleep(check_interval)
        
        return True

class CanaryDeployment(DeploymentStrategy):
    """Canary deployment strategy"""
    
    def __init__(self, config: DeploymentConfig):
        super().__init__(config)
        self.canary_instances = []
        self.stable_instances = []
        self.traffic_splitter = TrafficSplitter()
    
    def deploy(self) -> bool:
        """Execute canary deployment"""
        
        self.status = DeploymentStatus.IN_PROGRESS
        self.start_time = time.time()
        
        try:
            # Phase 1: Deploy canary instances
            print(f"Deploying canary instances for {self.config.service_name} v{self.config.version}")
            if not self._deploy_canary_instances():
                raise Exception("Canary deployment failed")
            
            # Phase 2: Route small percentage of traffic to canary
            print(f"Routing {self.config.canary_percentage}% traffic to canary")
            self.traffic_splitter.set_canary_percentage(self.config.canary_percentage)
            
            # Phase 3: Monitor canary performance
            print("Monitoring canary performance...")
            if not self._monitor_canary():
                raise Exception("Canary monitoring detected issues")
            
            # Phase 4: Gradual rollout
            rollout_stages = [25, 50, 75, 100]
            
            for percentage in rollout_stages:
                print(f"Increasing canary traffic to {percentage}%")
                self.traffic_splitter.set_canary_percentage(percentage)
                
                if not self._monitor_stage(percentage):
                    raise Exception(f"Issues detected at {percentage}% rollout")
                
                time.sleep(60)  # Wait between stages
            
            # Phase 5: Complete rollout
            print("Canary deployment successful - completing rollout")
            if not self._complete_rollout():
                raise Exception("Rollout completion failed")
            
            self.status = DeploymentStatus.SUCCESS
            self.end_time = time.time()
            return True
            
        except Exception as e:
            print(f"Canary deployment failed: {str(e)}")
            self.rollback()
            return False
    
    def rollback(self) -> bool:
        """Rollback canary deployment"""
        
        print("Rolling back canary deployment")
        
        try:
            # Stop traffic to canary
            self.traffic_splitter.set_canary_percentage(0)
            
            # Remove canary instances
            self._remove_canary_instances()
            
            self.status = DeploymentStatus.ROLLED_BACK
            print("Canary rollback successful")
            return True
            
        except Exception as e:
            print(f"Canary rollback failed: {str(e)}")
            return False
    
    def _deploy_canary_instances(self) -> bool:
        """Deploy canary instances"""
        # Implementation would deploy canary instances
        time.sleep(1)
        return True
    
    def _monitor_canary(self) -> bool:
        """Monitor canary instances"""
        
        duration = self.config.canary_duration_minutes * 60
        check_interval = 30
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            canary_metrics = self.health_monitor.get_canary_metrics()
            stable_metrics = self.health_monitor.get_stable_metrics()
            
            # Compare canary vs stable performance
            if not self._compare_metrics(canary_metrics, stable_metrics):
                return False
            
            time.sleep(check_interval)
        
        return True
    
    def _compare_metrics(self, canary_metrics: Dict, stable_metrics: Dict) -> bool:
        """Compare canary metrics against stable version"""
        
        # Error rate comparison
        error_rate_diff = canary_metrics['error_rate'] - stable_metrics['error_rate']
        if error_rate_diff > 2.0:  # 2% higher error rate is unacceptable
            print(f"Canary error rate {error_rate_diff}% higher than stable")
            return False
        
        # Latency comparison
        latency_diff = canary_metrics['p95_latency'] - stable_metrics['p95_latency']
        if latency_diff > 100:  # 100ms higher latency is unacceptable
            print(f"Canary latency {latency_diff}ms higher than stable")
            return False
        
        return True

class RollingDeployment(DeploymentStrategy):
    """Rolling deployment strategy"""
    
    def __init__(self, config: DeploymentConfig):
        super().__init__(config)
        self.instances = []
        self.batch_size = 2
        self.batch_delay = 60  # seconds between batches
    
    def deploy(self) -> bool:
        """Execute rolling deployment"""
        
        self.status = DeploymentStatus.IN_PROGRESS
        self.start_time = time.time()
        
        try:
            instances = self._get_instances()
            batches = self._create_batches(instances, self.batch_size)
            
            for i, batch in enumerate(batches):
                print(f"Deploying batch {i+1}/{len(batches)}")
                
                # Deploy to batch
                if not self._deploy_batch(batch):
                    raise Exception(f"Batch {i+1} deployment failed")
                
                # Health check batch
                if not self._health_check_batch(batch):
                    raise Exception(f"Batch {i+1} health check failed")
                
                # Wait before next batch (except for last batch)
                if i < len(batches) - 1:
                    time.sleep(self.batch_delay)
            
            self.status = DeploymentStatus.SUCCESS
            self.end_time = time.time()
            return True
            
        except Exception as e:
            print(f"Rolling deployment failed: {str(e)}")
            self.rollback()
            return False
    
    def rollback(self) -> bool:
        """Rollback rolling deployment"""
        
        print("Rolling back deployment")
        
        try:
            instances = self._get_instances()
            batches = self._create_batches(instances, self.batch_size)
            
            # Rollback in reverse order
            for i, batch in enumerate(reversed(batches)):
                print(f"Rolling back batch {len(batches)-i}")
                
                if not self._rollback_batch(batch):
                    print(f"Warning: Batch rollback failed")
                
                time.sleep(10)  # Brief delay between rollback batches
            
            self.status = DeploymentStatus.ROLLED_BACK
            return True
            
        except Exception as e:
            print(f"Rollback failed: {str(e)}")
            return False

class HealthMonitor:
    """Health monitoring for deployments"""
    
    def __init__(self, health_check_url: str):
        self.health_check_url = health_check_url
        self.metrics_cache = {}
        self.cache_ttl = 30  # seconds
    
    def check_health(self) -> HealthCheckResult:
        """Perform health check"""
        
        try:
            import requests
            response = requests.get(self.health_check_url, timeout=5)
            
            if response.status_code == 200:
                return HealthCheckResult.HEALTHY
            elif response.status_code in [503, 502]:
                return HealthCheckResult.DEGRADED
            else:
                return HealthCheckResult.UNHEALTHY
                
        except Exception:
            return HealthCheckResult.UNHEALTHY
    
    def get_metrics(self) -> Dict[str, float]:
        """Get current performance metrics"""
        
        current_time = time.time()
        
        # Use cached metrics if recent
        if ('metrics' in self.metrics_cache and 
            current_time - self.metrics_cache['timestamp'] < self.cache_ttl):
            return self.metrics_cache['metrics']
        
        # Fetch fresh metrics
        metrics = self._fetch_metrics()
        
        self.metrics_cache = {
            'metrics': metrics,
            'timestamp': current_time
        }
        
        return metrics
    
    def _fetch_metrics(self) -> Dict[str, float]:
        """Fetch metrics from monitoring system"""
        
        # In real implementation, this would query Prometheus, DataDog, etc.
        # Simulating metrics here
        import random
        
        return {
            'error_rate': random.uniform(0, 2),  # 0-2% error rate
            'p95_latency': random.uniform(100, 300),  # 100-300ms latency
            'throughput': random.uniform(800, 1200),  # 800-1200 RPS
            'cpu_usage': random.uniform(40, 80),  # 40-80% CPU
            'memory_usage': random.uniform(50, 85)  # 50-85% memory
        }
```

---

### 2. How do you implement automated rollback mechanisms?

**Answer:**

**Automated Rollback Framework:**

```python
from dataclasses import dataclass
from typing import List, Callable, Dict, Any
import time
import threading
import json

@dataclass
class RollbackTrigger:
    name: str
    condition: Callable[[], bool]
    threshold_breaches: int = 3
    evaluation_window_seconds: int = 300
    enabled: bool = True

@dataclass
class RollbackAction:
    name: str
    action: Callable[[], bool]
    timeout_seconds: int = 300
    retry_attempts: int = 3

class AutomatedRollbackManager:
    """Manages automated rollback based on configurable triggers"""
    
    def __init__(self, deployment_id: str):
        self.deployment_id = deployment_id
        self.triggers: List[RollbackTrigger] = []
        self.actions: List[RollbackAction] = []
        self.monitoring_thread = None
        self.is_monitoring = False
        self.rollback_initiated = False
        self.trigger_history = {}
    
    def add_trigger(self, trigger: RollbackTrigger):
        """Add rollback trigger"""
        self.triggers.append(trigger)
        self.trigger_history[trigger.name] = []
    
    def add_action(self, action: RollbackAction):
        """Add rollback action"""
        self.actions.append(action)
    
    def start_monitoring(self):
        """Start monitoring for rollback conditions"""
        
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        print(f"Started rollback monitoring for deployment {self.deployment_id}")
    
    def stop_monitoring(self):
        """Stop rollback monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=10)
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        
        check_interval = 30  # Check every 30 seconds
        
        while self.is_monitoring and not self.rollback_initiated:
            for trigger in self.triggers:
                if not trigger.enabled:
                    continue
                
                try:
                    # Evaluate trigger condition
                    condition_met = trigger.condition()
                    current_time = time.time()
                    
                    # Record trigger evaluation
                    self.trigger_history[trigger.name].append({
                        'timestamp': current_time,
                        'condition_met': condition_met
                    })
                    
                    # Clean old history outside evaluation window
                    cutoff_time = current_time - trigger.evaluation_window_seconds
                    self.trigger_history[trigger.name] = [
                        entry for entry in self.trigger_history[trigger.name]
                        if entry['timestamp'] > cutoff_time
                    ]
                    
                    # Check if threshold is breached
                    if self._should_trigger_rollback(trigger):
                        print(f"Rollback trigger activated: {trigger.name}")
                        self._initiate_rollback(trigger.name)
                        return
                
                except Exception as e:
                    print(f"Error evaluating trigger {trigger.name}: {str(e)}")
            
            time.sleep(check_interval)
    
    def _should_trigger_rollback(self, trigger: RollbackTrigger) -> bool:
        """Check if trigger should initiate rollback"""
        
        recent_breaches = [
            entry for entry in self.trigger_history[trigger.name]
            if entry['condition_met']
        ]
        
        return len(recent_breaches) >= trigger.threshold_breaches
    
    def _initiate_rollback(self, triggered_by: str):
        """Initiate automated rollback"""
        
        if self.rollback_initiated:
            return
        
        self.rollback_initiated = True
        print(f"INITIATING AUTOMATED ROLLBACK - Triggered by: {triggered_by}")
        
        # Stop monitoring
        self.is_monitoring = False
        
        # Execute rollback actions
        for action in self.actions:
            print(f"Executing rollback action: {action.name}")
            
            success = self._execute_action_with_retry(action)
            
            if success:
                print(f"Rollback action {action.name} completed successfully")
            else:
                print(f"Rollback action {action.name} failed - manual intervention required")
        
        print("Automated rollback completed")

    def _execute_action_with_retry(self, action: RollbackAction) -> bool:
        """Execute rollback action with retry logic"""
        
        for attempt in range(action.retry_attempts):
            try:
                print(f"Executing {action.name} (attempt {attempt + 1})")
                
                # Execute with timeout
                result = self._execute_with_timeout(action.action, action.timeout_seconds)
                
                if result:
                    return True
                else:
                    print(f"Action {action.name} returned false")
                    
            except TimeoutError:
                print(f"Action {action.name} timed out")
            except Exception as e:
                print(f"Action {action.name} failed: {str(e)}")
            
            if attempt < action.retry_attempts - 1:
                time.sleep(30)  # Wait before retry
        
        return False

# Example rollback triggers and actions
class DeploymentRollbackTriggers:
    """Common rollback triggers for deployments"""
    
    @staticmethod
    def create_error_rate_trigger(threshold_percent: float = 5.0) -> RollbackTrigger:
        """Create error rate rollback trigger"""
        
        def check_error_rate() -> bool:
            # Query monitoring system for error rate
            current_error_rate = MetricsClient.get_error_rate()
            return current_error_rate > threshold_percent
        
        return RollbackTrigger(
            name="high_error_rate",
            condition=check_error_rate,
            threshold_breaches=3,
            evaluation_window_seconds=300
        )
    
    @staticmethod
    def create_latency_trigger(threshold_ms: float = 1000.0) -> RollbackTrigger:
        """Create latency rollback trigger"""
        
        def check_latency() -> bool:
            current_p95_latency = MetricsClient.get_p95_latency()
            return current_p95_latency > threshold_ms
        
        return RollbackTrigger(
            name="high_latency",
            condition=check_latency,
            threshold_breaches=3,
            evaluation_window_seconds=300
        )
    
    @staticmethod
    def create_availability_trigger(threshold_percent: float = 99.0) -> RollbackTrigger:
        """Create availability rollback trigger"""
        
        def check_availability() -> bool:
            current_availability = MetricsClient.get_availability()
            return current_availability < threshold_percent
        
        return RollbackTrigger(
            name="low_availability",
            condition=check_availability,
            threshold_breaches=2,
            evaluation_window_seconds=180
        )

class DeploymentRollbackActions:
    """Common rollback actions for deployments"""
    
    @staticmethod
    def create_kubernetes_rollback_action(deployment_name: str) -> RollbackAction:
        """Create Kubernetes deployment rollback action"""
        
        def rollback_kubernetes():
            import subprocess
            
            try:
                # Rollback to previous revision
                result = subprocess.run([
                    "kubectl", "rollout", "undo", f"deployment/{deployment_name}"
                ], capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0:
                    # Wait for rollback to complete
                    rollout_result = subprocess.run([
                        "kubectl", "rollout", "status", f"deployment/{deployment_name}",
                        "--timeout=300s"
                    ], capture_output=True, text=True, timeout=320)
                    
                    return rollout_result.returncode == 0
                
                return False
                
            except Exception as e:
                print(f"Kubernetes rollback failed: {str(e)}")
                return False
        
        return RollbackAction(
            name="kubernetes_rollback",
            action=rollback_kubernetes,
            timeout_seconds=300,
            retry_attempts=2
        )
    
    @staticmethod
    def create_traffic_switch_action(load_balancer_config: Dict) -> RollbackAction:
        """Create traffic switch rollback action"""
        
        def switch_traffic():
            try:
                # Switch load balancer to previous version
                load_balancer = LoadBalancerClient(load_balancer_config)
                return load_balancer.switch_to_previous_version()
                
            except Exception as e:
                print(f"Traffic switch failed: {str(e)}")
                return False
        
        return RollbackAction(
            name="traffic_switch",
            action=switch_traffic,
            timeout_seconds=60,
            retry_attempts=3
        )

# Example usage
def setup_automated_rollback(deployment_id: str, service_config: Dict):
    """Setup automated rollback for a deployment"""
    
    rollback_manager = AutomatedRollbackManager(deployment_id)
    
    # Add triggers
    rollback_manager.add_trigger(
        DeploymentRollbackTriggers.create_error_rate_trigger(5.0)
    )
    rollback_manager.add_trigger(
        DeploymentRollbackTriggers.create_latency_trigger(1000.0)
    )
    rollback_manager.add_trigger(
        DeploymentRollbackTriggers.create_availability_trigger(99.0)
    )
    
    # Add actions
    rollback_manager.add_action(
        DeploymentRollbackActions.create_kubernetes_rollback_action(
            service_config['deployment_name']
        )
    )
    rollback_manager.add_action(
        DeploymentRollbackActions.create_traffic_switch_action(
            service_config['load_balancer']
        )
    )
    
    # Start monitoring
    rollback_manager.start_monitoring()
    
    return rollback_manager
```

---

### 3. How do you implement feature flags for safe rollouts?

**Answer:**

**Feature Flag System:**

```python
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, Optional, List, Callable
import json
import time
import threading
from dataclasses import dataclass, asdict

class FeatureFlagStatus(Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    CONDITIONAL = "conditional"

class RolloutStrategy(Enum):
    PERCENTAGE = "percentage"
    USER_LIST = "user_list"
    USER_ATTRIBUTE = "user_attribute"
    GEOGRAPHIC = "geographic"
    TIME_BASED = "time_based"

@dataclass
class UserContext:
    user_id: str
    user_type: str = "regular"
    geographic_region: str = "us"
    experiment_groups: List[str] = None
    custom_attributes: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.experiment_groups is None:
            self.experiment_groups = []
        if self.custom_attributes is None:
            self.custom_attributes = {}

@dataclass
class RolloutRule:
    strategy: RolloutStrategy
    parameters: Dict[str, Any]
    enabled: bool = True

@dataclass
class FeatureFlag:
    name: str
    description: str
    status: FeatureFlagStatus
    default_value: Any = False
    rollout_rules: List[RolloutRule] = None
    created_at: float = None
    updated_at: float = None
    
    def __post_init__(self):
        if self.rollout_rules is None:
            self.rollout_rules = []
        if self.created_at is None:
            self.created_at = time.time()
        if self.updated_at is None:
            self.updated_at = time.time()

class FeatureFlagStore(ABC):
    """Abstract interface for feature flag storage"""
    
    @abstractmethod
    def get_flag(self, flag_name: str) -> Optional[FeatureFlag]:
        pass
    
    @abstractmethod
    def set_flag(self, flag: FeatureFlag):
        pass
    
    @abstractmethod
    def list_flags(self) -> List[FeatureFlag]:
        pass
    
    @abstractmethod
    def delete_flag(self, flag_name: str):
        pass

class InMemoryFeatureFlagStore(FeatureFlagStore):
    """In-memory feature flag store for development/testing"""
    
    def __init__(self):
        self.flags: Dict[str, FeatureFlag] = {}
        self.lock = threading.RWLock()
    
    def get_flag(self, flag_name: str) -> Optional[FeatureFlag]:
        with self.lock.r_locked():
            return self.flags.get(flag_name)
    
    def set_flag(self, flag: FeatureFlag):
        with self.lock.w_locked():
            flag.updated_at = time.time()
            self.flags[flag.name] = flag
    
    def list_flags(self) -> List[FeatureFlag]:
        with self.lock.r_locked():
            return list(self.flags.values())
    
    def delete_flag(self, flag_name: str):
        with self.lock.w_locked():
            if flag_name in self.flags:
                del self.flags[flag_name]

class FeatureFlagEvaluator:
    """Evaluates feature flags based on user context and rollout rules"""
    
    def __init__(self, store: FeatureFlagStore):
        self.store = store
        self.evaluation_cache = {}
        self.cache_ttl = 60  # 1 minute cache
    
    def is_enabled(self, flag_name: str, user_context: UserContext = None) -> bool:
        """Check if feature flag is enabled for user"""
        
        result = self.evaluate_flag(flag_name, user_context)
        return bool(result)
    
    def evaluate_flag(self, flag_name: str, user_context: UserContext = None) -> Any:
        """Evaluate feature flag and return its value"""
        
        # Check cache first
        cache_key = self._get_cache_key(flag_name, user_context)
        cached_result = self._get_cached_result(cache_key)
        
        if cached_result is not None:
            return cached_result
        
        # Get flag from store
        flag = self.store.get_flag(flag_name)
        if not flag:
            return False  # Default to disabled if flag doesn't exist
        
        # Evaluate flag
        result = self._evaluate_flag_rules(flag, user_context)
        
        # Cache result
        self._cache_result(cache_key, result)
        
        return result
    
    def _evaluate_flag_rules(self, flag: FeatureFlag, user_context: UserContext) -> Any:
        """Evaluate flag based on its status and rollout rules"""
        
        if flag.status == FeatureFlagStatus.DISABLED:
            return flag.default_value
        
        if flag.status == FeatureFlagStatus.ENABLED:
            return True  # or flag.enabled_value if it has one
        
        if flag.status == FeatureFlagStatus.CONDITIONAL:
            return self._evaluate_rollout_rules(flag.rollout_rules, user_context)
        
        return flag.default_value
    
    def _evaluate_rollout_rules(self, rules: List[RolloutRule], 
                               user_context: UserContext) -> bool:
        """Evaluate rollout rules to determine if flag should be enabled"""
        
        if not user_context:
            return False
        
        for rule in rules:
            if not rule.enabled:
                continue
            
            if self._evaluate_single_rule(rule, user_context):
                return True
        
        return False
    
    def _evaluate_single_rule(self, rule: RolloutRule, user_context: UserContext) -> bool:
        """Evaluate a single rollout rule"""
        
        if rule.strategy == RolloutStrategy.PERCENTAGE:
            return self._evaluate_percentage_rule(rule.parameters, user_context)
        
        elif rule.strategy == RolloutStrategy.USER_LIST:
            return self._evaluate_user_list_rule(rule.parameters, user_context)
        
        elif rule.strategy == RolloutStrategy.USER_ATTRIBUTE:
            return self._evaluate_user_attribute_rule(rule.parameters, user_context)
        
        elif rule.strategy == RolloutStrategy.GEOGRAPHIC:
            return self._evaluate_geographic_rule(rule.parameters, user_context)
        
        elif rule.strategy == RolloutStrategy.TIME_BASED:
            return self._evaluate_time_based_rule(rule.parameters, user_context)
        
        return False
    
    def _evaluate_percentage_rule(self, params: Dict, user_context: UserContext) -> bool:
        """Evaluate percentage-based rollout"""
        
        percentage = params.get('percentage', 0)
        if percentage <= 0:
            return False
        if percentage >= 100:
            return True
        
        # Use consistent hashing based on user ID
        import hashlib
        
        hash_input = f"{user_context.user_id}".encode()
        hash_value = int(hashlib.md5(hash_input).hexdigest(), 16)
        user_percentage = (hash_value % 100) + 1
        
        return user_percentage <= percentage
    
    def _evaluate_user_list_rule(self, params: Dict, user_context: UserContext) -> bool:
        """Evaluate user list-based rollout"""
        
        user_list = params.get('users', [])
        return user_context.user_id in user_list
    
    def _evaluate_user_attribute_rule(self, params: Dict, user_context: UserContext) -> bool:
        """Evaluate user attribute-based rollout"""
        
        attribute = params.get('attribute')
        values = params.get('values', [])
        
        if attribute == 'user_type':
            return user_context.user_type in values
        elif attribute == 'experiment_group':
            return any(group in values for group in user_context.experiment_groups)
        elif attribute in user_context.custom_attributes:
            return user_context.custom_attributes[attribute] in values
        
        return False
    
    def _evaluate_geographic_rule(self, params: Dict, user_context: UserContext) -> bool:
        """Evaluate geographic-based rollout"""
        
        allowed_regions = params.get('regions', [])
        return user_context.geographic_region in allowed_regions
    
    def _evaluate_time_based_rule(self, params: Dict, user_context: UserContext) -> bool:
        """Evaluate time-based rollout"""
        
        start_time = params.get('start_time')
        end_time = params.get('end_time')
        current_time = time.time()
        
        if start_time and current_time < start_time:
            return False
        
        if end_time and current_time > end_time:
            return False
        
        return True

class FeatureFlagManager:
    """High-level feature flag management"""
    
    def __init__(self, store: FeatureFlagStore):
        self.store = store
        self.evaluator = FeatureFlagEvaluator(store)
        self.metrics_collector = FeatureFlagMetrics()
    
    def create_flag(self, name: str, description: str, 
                   default_value: Any = False) -> FeatureFlag:
        """Create a new feature flag"""
        
        flag = FeatureFlag(
            name=name,
            description=description,
            status=FeatureFlagStatus.DISABLED,
            default_value=default_value
        )
        
        self.store.set_flag(flag)
        return flag
    
    def enable_flag(self, flag_name: str):
        """Enable feature flag for all users"""
        
        flag = self.store.get_flag(flag_name)
        if flag:
            flag.status = FeatureFlagStatus.ENABLED
            self.store.set_flag(flag)
    
    def disable_flag(self, flag_name: str):
        """Disable feature flag for all users"""
        
        flag = self.store.get_flag(flag_name)
        if flag:
            flag.status = FeatureFlagStatus.DISABLED
            self.store.set_flag(flag)
    
    def set_percentage_rollout(self, flag_name: str, percentage: int):
        """Set percentage-based rollout for feature flag"""
        
        flag = self.store.get_flag(flag_name)
        if not flag:
            return
        
        flag.status = FeatureFlagStatus.CONDITIONAL
        flag.rollout_rules = [
            RolloutRule(
                strategy=RolloutStrategy.PERCENTAGE,
                parameters={'percentage': percentage}
            )
        ]
        
        self.store.set_flag(flag)
    
    def add_user_list_rollout(self, flag_name: str, user_ids: List[str]):
        """Add user list-based rollout rule"""
        
        flag = self.store.get_flag(flag_name)
        if not flag:
            return
        
        if flag.status == FeatureFlagStatus.DISABLED:
            flag.status = FeatureFlagStatus.CONDITIONAL
            flag.rollout_rules = []
        
        flag.rollout_rules.append(
            RolloutRule(
                strategy=RolloutStrategy.USER_LIST,
                parameters={'users': user_ids}
            )
        )
        
        self.store.set_flag(flag)
    
    def gradual_rollout(self, flag_name: str, target_percentage: int, 
                       step_size: int = 10, step_interval_minutes: int = 30):
        """Perform gradual percentage rollout"""
        
        def rollout_step():
            flag = self.store.get_flag(flag_name)
            if not flag or flag.status == FeatureFlagStatus.DISABLED:
                return
            
            current_percentage = 0
            for rule in flag.rollout_rules:
                if rule.strategy == RolloutStrategy.PERCENTAGE:
                    current_percentage = rule.parameters.get('percentage', 0)
                    break
            
            if current_percentage < target_percentage:
                new_percentage = min(current_percentage + step_size, target_percentage)
                self.set_percentage_rollout(flag_name, new_percentage)
                
                print(f"Rolled out {flag_name} to {new_percentage}% of users")
                
                if new_percentage < target_percentage:
                    # Schedule next step
                    timer = threading.Timer(
                        step_interval_minutes * 60, 
                        rollout_step
                    )
                    timer.start()
        
        # Start rollout
        rollout_step()
    
    def is_enabled(self, flag_name: str, user_context: UserContext = None) -> bool:
        """Check if feature is enabled for user"""
        
        result = self.evaluator.is_enabled(flag_name, user_context)
        
        # Record metrics
        self.metrics_collector.record_evaluation(flag_name, result, user_context)
        
        return result

class FeatureFlagMetrics:
    """Metrics collection for feature flags"""
    
    def __init__(self):
        self.evaluations = {}
        self.lock = threading.Lock()
    
    def record_evaluation(self, flag_name: str, result: bool, user_context: UserContext):
        """Record feature flag evaluation"""
        
        with self.lock:
            if flag_name not in self.evaluations:
                self.evaluations[flag_name] = {
                    'total_evaluations': 0,
                    'enabled_evaluations': 0,
                    'by_user_type': {},
                    'by_region': {}
                }
            
            stats = self.evaluations[flag_name]
            stats['total_evaluations'] += 1
            
            if result:
                stats['enabled_evaluations'] += 1
            
            if user_context:
                # Track by user type
                user_type = user_context.user_type
                if user_type not in stats['by_user_type']:
                    stats['by_user_type'][user_type] = {'total': 0, 'enabled': 0}
                
                stats['by_user_type'][user_type]['total'] += 1
                if result:
                    stats['by_user_type'][user_type]['enabled'] += 1
                
                # Track by region
                region = user_context.geographic_region
                if region not in stats['by_region']:
                    stats['by_region'][region] = {'total': 0, 'enabled': 0}
                
                stats['by_region'][region]['total'] += 1
                if result:
                    stats['by_region'][region]['enabled'] += 1
    
    def get_flag_stats(self, flag_name: str) -> Dict:
        """Get statistics for a feature flag"""
        
        with self.lock:
            return self.evaluations.get(flag_name, {})

# Example usage
def feature_flag_example():
    """Example of feature flag usage"""
    
    # Setup
    store = InMemoryFeatureFlagStore()
    flag_manager = FeatureFlagManager(store)
    
    # Create feature flag
    flag_manager.create_flag(
        "new_checkout_flow",
        "New streamlined checkout process"
    )
    
    # Start with 5% rollout
    flag_manager.set_percentage_rollout("new_checkout_flow", 5)
    
    # Add specific users for testing
    flag_manager.add_user_list_rollout(
        "new_checkout_flow", 
        ["test_user_1", "test_user_2"]
    )
    
    # Example user contexts
    regular_user = UserContext(
        user_id="user_123",
        user_type="regular",
        geographic_region="us"
    )
    
    premium_user = UserContext(
        user_id="user_456", 
        user_type="premium",
        geographic_region="eu"
    )
    
    # Check if feature is enabled
    for user in [regular_user, premium_user]:
        enabled = flag_manager.is_enabled("new_checkout_flow", user)
        print(f"New checkout enabled for {user.user_id}: {enabled}")
    
    # Gradual rollout to 50% over 2 hours
    flag_manager.gradual_rollout(
        "new_checkout_flow",
        target_percentage=50,
        step_size=10,
        step_interval_minutes=30
    )

# Feature flag decorator for easy integration
def feature_flag(flag_name: str, flag_manager: FeatureFlagManager, 
                default_implementation: Callable = None):
    """Decorator for feature-flagged functions"""
    
    def decorator(new_implementation: Callable):
        def wrapper(*args, **kwargs):
            # Extract user context from arguments
            user_context = kwargs.get('user_context')
            
            if flag_manager.is_enabled(flag_name, user_context):
                return new_implementation(*args, **kwargs)
            elif default_implementation:
                return default_implementation(*args, **kwargs)
            else:
                raise NotImplementedError("Feature not enabled and no default implementation")
        
        return wrapper
    return decorator
```

---

### 4. How do you implement database migration strategies?

**Answer:**

**Database Migration Framework:**

```python
from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any, Optional
import time
import threading
from dataclasses import dataclass
import json

class MigrationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"

class MigrationStrategy(Enum):
    IMMEDIATE = "immediate"
    BLUE_GREEN = "blue_green"
    SHADOW = "shadow"
    GRADUAL = "gradual"

@dataclass
class Migration:
    id: str
    version: str
    description: str
    up_sql: str
    down_sql: str
    strategy: MigrationStrategy = MigrationStrategy.IMMEDIATE
    estimated_duration_seconds: int = 300
    requires_downtime: bool = False
    reversible: bool = True
    dependencies: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []

class DatabaseMigrationManager:
    """Manages database migrations with various strategies"""
    
    def __init__(self, database_config: Dict[str, Any]):
        self.config = database_config
        self.migrations: Dict[str, Migration] = {}
        self.migration_history: List[Dict] = []
        self.lock = threading.Lock()
    
    def register_migration(self, migration: Migration):
        """Register a migration"""
        
        with self.lock:
            self.migrations[migration.id] = migration
    
    def execute_migration(self, migration_id: str) -> bool:
        """Execute a migration based on its strategy"""
        
        migration = self.migrations.get(migration_id)
        if not migration:
            raise ValueError(f"Migration {migration_id} not found")
        
        # Check dependencies
        if not self._check_dependencies(migration):
            raise ValueError(f"Migration dependencies not satisfied: {migration.dependencies}")
        
        print(f"Executing migration {migration_id} using {migration.strategy.value} strategy")
        
        if migration.strategy == MigrationStrategy.IMMEDIATE:
            return self._execute_immediate_migration(migration)
        
        elif migration.strategy == MigrationStrategy.BLUE_GREEN:
            return self._execute_blue_green_migration(migration)
        
        elif migration.strategy == MigrationStrategy.SHADOW:
            return self._execute_shadow_migration(migration)
        
        elif migration.strategy == MigrationStrategy.GRADUAL:
            return self._execute_gradual_migration(migration)
        
        else:
            raise ValueError(f"Unknown migration strategy: {migration.strategy}")
    
    def _execute_immediate_migration(self, migration: Migration) -> bool:
        """Execute migration immediately"""
        
        start_time = time.time()
        
        try:
            self._record_migration_start(migration)
            
            # Create backup if needed
            if migration.reversible:
                backup_id = self._create_backup()
                print(f"Created backup: {backup_id}")
            
            # Execute migration
            print(f"Executing migration SQL...")
            self._execute_sql(migration.up_sql)
            
            # Verify migration
            if not self._verify_migration(migration):
                raise Exception("Migration verification failed")
            
            self._record_migration_success(migration, time.time() - start_time)
            print(f"Migration {migration.id} completed successfully")
            return True
            
        except Exception as e:
            self._record_migration_failure(migration, str(e))
            
            # Attempt rollback if possible
            if migration.reversible:
                print(f"Attempting rollback...")
                self._rollback_migration(migration)
            
            print(f"Migration {migration.id} failed: {str(e)}")
            return False
    
    def _execute_blue_green_migration(self, migration: Migration) -> bool:
        """Execute migration using blue-green strategy"""
        
        try:
            # Phase 1: Create green database
            green_db_config = self._create_green_database()
            print("Created green database")
            
            # Phase 2: Apply migration to green database
            self._execute_sql_on_database(migration.up_sql, green_db_config)
            print("Applied migration to green database")
            
            # Phase 3: Sync data from blue to green
            print("Syncing data to green database...")
            self._sync_data_to_green(green_db_config)
            
            # Phase 4: Verify green database
            if not self._verify_green_database(green_db_config, migration):
                raise Exception("Green database verification failed")
            
            # Phase 5: Switch traffic to green
            print("Switching traffic to green database...")
            self._switch_to_green_database(green_db_config)
            
            # Phase 6: Monitor for issues
            if not self._monitor_green_database(duration_seconds=300):
                raise Exception("Issues detected in green database")
            
            # Phase 7: Cleanup old blue database
            self._cleanup_blue_database()
            
            self._record_migration_success(migration, 0)  # Duration handled separately
            return True
            
        except Exception as e:
            print(f"Blue-green migration failed: {str(e)}")
            
            # Rollback to blue database
            self._switch_to_blue_database()
            self._cleanup_green_database()
            
            self._record_migration_failure(migration, str(e))
            return False
    
    def _execute_shadow_migration(self, migration: Migration) -> bool:
        """Execute migration using shadow strategy"""
        
        try:
            # Phase 1: Create shadow database
            shadow_db_config = self._create_shadow_database()
            print("Created shadow database")
            
            # Phase 2: Apply migration to shadow database
            self._execute_sql_on_database(migration.up_sql, shadow_db_config)
            print("Applied migration to shadow database")
            
            # Phase 3: Dual write to both databases
            print("Starting dual write mode...")
            self._enable_dual_write(shadow_db_config)
            
            # Phase 4: Backfill historical data
            print("Backfilling historical data...")
            self._backfill_shadow_database(shadow_db_config)
            
            # Phase 5: Compare data consistency
            if not self._verify_data_consistency(shadow_db_config):
                raise Exception("Data consistency check failed")
            
            # Phase 6: Shadow read testing
            print("Running shadow read tests...")
            self._run_shadow_read_tests(shadow_db_config, duration_seconds=600)
            
            # Phase 7: Switch to shadow database
            print("Switching to shadow database...")
            self._switch_to_shadow_database(shadow_db_config)
            
            # Phase 8: Cleanup original database
            self._cleanup_original_database()
            
            self._record_migration_success(migration, 0)
            return True
            
        except Exception as e:
            print(f"Shadow migration failed: {str(e)}")
            
            # Cleanup shadow database
            self._disable_dual_write()
            self._cleanup_shadow_database()
            
            self._record_migration_failure(migration, str(e))
            return False
    
    def _execute_gradual_migration(self, migration: Migration) -> bool:
        """Execute migration gradually"""
        
        try:
            # Phase 1: Add new columns/tables (additive changes)
            additive_sql = self._extract_additive_changes(migration.up_sql)
            if additive_sql:
                print("Applying additive changes...")
                self._execute_sql(additive_sql)
            
            # Phase 2: Dual write to old and new schema
            print("Starting dual write mode...")
            self._enable_dual_schema_write()
            
            # Phase 3: Backfill new schema
            print("Backfilling new schema...")
            self._backfill_new_schema()
            
            # Phase 4: Switch reads to new schema
            print("Switching reads to new schema...")
            self._switch_reads_to_new_schema()
            
            # Phase 5: Monitor for issues
            if not self._monitor_new_schema(duration_seconds=1800):  # 30 minutes
                raise Exception("Issues detected with new schema")
            
            # Phase 6: Remove old schema
            print("Removing old schema...")
            old_schema_cleanup_sql = self._extract_cleanup_changes(migration.up_sql)
            if old_schema_cleanup_sql:
                self._execute_sql(old_schema_cleanup_sql)
            
            self._record_migration_success(migration, 0)
            return True
            
        except Exception as e:
            print(f"Gradual migration failed: {str(e)}")
            
            # Rollback gradual changes
            self._rollback_gradual_migration(migration)
            
            self._record_migration_failure(migration, str(e))
            return False
    
    def rollback_migration(self, migration_id: str) -> bool:
        """Rollback a migration"""
        
        migration = self.migrations.get(migration_id)
        if not migration:
            raise ValueError(f"Migration {migration_id} not found")
        
        if not migration.reversible:
            raise ValueError(f"Migration {migration_id} is not reversible")
        
        return self._rollback_migration(migration)
    
    def _rollback_migration(self, migration: Migration) -> bool:
        """Internal rollback implementation"""
        
        try:
            print(f"Rolling back migration {migration.id}...")
            
            if migration.down_sql:
                self._execute_sql(migration.down_sql)
            else:
                # Restore from backup
                latest_backup = self._get_latest_backup()
                if latest_backup:
                    self._restore_from_backup(latest_backup)
                else:
                    raise Exception("No rollback SQL and no backup available")
            
            # Verify rollback
            if not self._verify_rollback(migration):
                raise Exception("Rollback verification failed")
            
            self._record_migration_rollback(migration)
            print(f"Migration {migration.id} rolled back successfully")
            return True
            
        except Exception as e:
            print(f"Rollback failed: {str(e)}")
            return False
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get status of all migrations"""
        
        applied_migrations = [
            entry for entry in self.migration_history
            if entry['status'] == MigrationStatus.COMPLETED.value
        ]
        
        pending_migrations = [
            migration for migration in self.migrations.values()
            if migration.id not in [entry['migration_id'] for entry in applied_migrations]
        ]
        
        return {
            'applied_count': len(applied_migrations),
            'pending_count': len(pending_migrations),
            'applied_migrations': applied_migrations,
            'pending_migrations': [
                {
                    'id': m.id,
                    'version': m.version,
                    'description': m.description,
                    'strategy': m.strategy.value,
                    'estimated_duration': m.estimated_duration_seconds,
                    'requires_downtime': m.requires_downtime
                }
                for m in pending_migrations
            ]
        }
    
    def plan_migration_sequence(self, migration_ids: List[str]) -> List[str]:
        """Plan optimal sequence for multiple migrations"""
        
        # Topological sort based on dependencies
        migrations = [self.migrations[mid] for mid in migration_ids]
        
        # Build dependency graph
        graph = {}
        in_degree = {}
        
        for migration in migrations:
            graph[migration.id] = migration.dependencies
            in_degree[migration.id] = len(migration.dependencies)
        
        # Topological sort
        queue = [mid for mid in migration_ids if in_degree[mid] == 0]
        result = []
        
        while queue:
            current = queue.pop(0)
            result.append(current)
            
            # Reduce in-degree for dependent migrations
            for migration_id in migration_ids:
                if current in graph[migration_id]:
                    in_degree[migration_id] -= 1
                    if in_degree[migration_id] == 0:
                        queue.append(migration_id)
        
        if len(result) != len(migration_ids):
            raise ValueError("Circular dependency detected in migrations")
        
        return result

# Migration safety checks
class MigrationSafetyChecker:
    """Checks migrations for potential safety issues"""
    
    @staticmethod
    def check_migration_safety(migration: Migration) -> List[str]:
        """Check migration for potential safety issues"""
        
        warnings = []
        
        # Check for destructive operations
        destructive_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER COLUMN']
        for keyword in destructive_keywords:
            if keyword in migration.up_sql.upper():
                warnings.append(f"Potentially destructive operation detected: {keyword}")
        
        # Check for large table operations
        if 'ALTER TABLE' in migration.up_sql.upper():
            warnings.append("ALTER TABLE operation detected - may cause table lock")
        
        # Check for index creation on large tables
        if 'CREATE INDEX' in migration.up_sql.upper():
            warnings.append("Index creation detected - may be slow on large tables")
        
        # Check for missing WHERE clause in UPDATE/DELETE
        if 'UPDATE' in migration.up_sql.upper() and 'WHERE' not in migration.up_sql.upper():
            warnings.append("UPDATE without WHERE clause detected")
        
        if 'DELETE' in migration.up_sql.upper() and 'WHERE' not in migration.up_sql.upper():
            warnings.append("DELETE without WHERE clause detected")
        
        return warnings
    
    @staticmethod
    def estimate_migration_duration(migration: Migration) -> int:
        """Estimate migration duration based on SQL analysis"""
        
        base_duration = 30  # Base 30 seconds
        
        # Add time for different operations
        sql_upper = migration.up_sql.upper()
        
        if 'CREATE TABLE' in sql_upper:
            base_duration += 60
        
        if 'ALTER TABLE' in sql_upper:
            base_duration += 300  # 5 minutes for table alterations
        
        if 'CREATE INDEX' in sql_upper:
            base_duration += 600  # 10 minutes for index creation
        
        if 'UPDATE' in sql_upper or 'DELETE' in sql_upper:
            base_duration += 180  # 3 minutes for data modifications
        
        return base_duration

# Example migration definitions
def create_example_migrations():
    """Create example migrations"""
    
    # Simple additive migration
    add_column_migration = Migration(
        id="001_add_user_email_verified",
        version="1.1.0",
        description="Add email_verified column to users table",
        up_sql="""
        ALTER TABLE users 
        ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;
        
        CREATE INDEX idx_users_email_verified 
        ON users(email_verified);
        """,
        down_sql="""
        DROP INDEX idx_users_email_verified;
        ALTER TABLE users DROP COLUMN email_verified;
        """,
        strategy=MigrationStrategy.IMMEDIATE,
        estimated_duration_seconds=120,
        requires_downtime=False
    )
    
    # Complex migration requiring blue-green
    restructure_migration = Migration(
        id="002_restructure_orders_table",
        version="2.0.0", 
        description="Restructure orders table for performance",
        up_sql="""
        -- This would be complex restructuring SQL
        CREATE TABLE orders_new AS SELECT * FROM orders;
        -- ... restructuring logic ...
        """,
        down_sql="""
        -- Rollback logic
        DROP TABLE orders_new;
        """,
        strategy=MigrationStrategy.BLUE_GREEN,
        estimated_duration_seconds=3600,
        requires_downtime=True,
        dependencies=["001_add_user_email_verified"]
    )
    
    return [add_column_migration, restructure_migration]
```

---

## 🚦 Change Control Processes

### Change Advisory Board (CAB) Integration

```yaml
# change-control-config.yml
change_control:
  approval_workflows:
    low_risk:
      required_approvers: 1
      approval_timeout_hours: 24
      auto_approve_conditions:
        - "automated_tests_pass"
        - "change_size < 100_lines"
        - "non_production_environment"
    
    medium_risk:
      required_approvers: 2
      approval_timeout_hours: 48
      required_roles: ["tech_lead", "sre_engineer"]
      additional_checks:
        - "performance_impact_assessment"
        - "rollback_plan_documented"
    
    high_risk:
      required_approvers: 3
      approval_timeout_hours: 72
      required_roles: ["engineering_manager", "sre_lead", "product_owner"]
      mandatory_requirements:
        - "cab_meeting_discussion"
        - "detailed_rollback_plan"
        - "monitoring_plan"
        - "communication_plan"

  change_windows:
    production:
      allowed_times:
        - "tuesday: 02:00-04:00"
        - "thursday: 02:00-04:00"
      blackout_periods:
        - "black_friday_week"
        - "end_of_quarter"
        - "major_holidays"
    
    staging:
      allowed_times: "anytime"
      
  risk_assessment:
    criteria:
      - name: "blast_radius"
        weight: 0.3
        factors: ["users_affected", "systems_impacted"]
      
      - name: "rollback_complexity"
        weight: 0.2
        factors: ["rollback_automation", "data_migration_reversible"]
      
      - name: "change_complexity"
        weight: 0.3
        factors: ["lines_changed", "files_modified", "components_affected"]
      
      - name: "testing_coverage"
        weight: 0.2
        factors: ["test_coverage", "integration_tests", "manual_testing"]
```

---

This comprehensive change management guide covers safe deployment strategies, automated rollbacks, feature flags, database migrations, and change control processes with practical implementations for managing changes safely in production environments.