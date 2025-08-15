# Automation & Toil Reduction 🔄

## Toil Identification and Reduction

### 1. What is toil and how do you identify it?

**Answer:**

**Toil Definition:**
Toil is the operational work tied to running a production service that tends to be manual, repetitive, automatable, tactical, and of no lasting value, and that scales linearly as a service grows.

**Characteristics of Toil:**

```python
class ToilIdentifier:
    def __init__(self):
        self.toil_characteristics = {
            'manual': "Requires human hands-on effort",
            'repetitive': "Same task performed multiple times",
            'automatable': "Could be automated with engineering effort",
            'tactical': "Reactive rather than strategic",
            'no_value': "Doesn't provide lasting improvement",
            'linear_scaling': "Effort increases proportionally with service size"
        }
    
    def evaluate_task(self, task_description, frequency, time_per_execution, automation_effort):
        """Evaluate if a task qualifies as toil"""
        
        toil_score = 0
        
        # Check characteristics
        if self._is_manual(task_description):
            toil_score += 2
        
        if frequency > 5:  # More than 5 times per week
            toil_score += 3  # Repetitive
        
        if automation_effort < time_per_execution * frequency * 4:  # ROI threshold
            toil_score += 3  # Automatable with reasonable effort
        
        if self._is_reactive(task_description):
            toil_score += 2  # Tactical
        
        # Calculate toil priority
        weekly_time_cost = frequency * time_per_execution
        automation_roi = weekly_time_cost * 52 / automation_effort  # Annual ROI
        
        return {
            'is_toil': toil_score >= 6,
            'toil_score': toil_score,
            'weekly_time_cost_hours': weekly_time_cost,
            'automation_effort_hours': automation_effort,
            'automation_roi': automation_roi,
            'priority': self._calculate_priority(toil_score, automation_roi)
        }
    
    def _calculate_priority(self, toil_score, roi):
        """Calculate automation priority"""
        if toil_score >= 8 and roi > 5:
            return 'critical'
        elif toil_score >= 6 and roi > 2:
            return 'high'
        elif toil_score >= 4 and roi > 1:
            return 'medium'
        else:
            return 'low'
```

**Common Examples of Toil:**

```yaml
toil_examples:
  high_toil:
    - name: "Manual deployment process"
      description: "SSH to servers, copy files, restart services"
      frequency: 10  # per week
      time_per_execution: 2  # hours
      automation_potential: "high"
    
    - name: "Log analysis for common errors"
      description: "Grep through logs to find error patterns"
      frequency: 15  # per week
      time_per_execution: 0.5  # hours
      automation_potential: "high"
    
    - name: "Manual capacity provisioning"
      description: "Create new instances when alerts fire"
      frequency: 5   # per week
      time_per_execution: 1  # hour
      automation_potential: "medium"
  
  not_toil:
    - name: "Architecture design reviews"
      description: "Review system design for new features"
      frequency: 2   # per week
      time_per_execution: 3  # hours
      automation_potential: "none"
      reason: "Strategic work requiring human judgment"
    
    - name: "Complex incident investigation"
      description: "Root cause analysis for novel problems"
      frequency: 1   # per week
      time_per_execution: 4  # hours
      automation_potential: "low"
      reason: "Requires human intuition and problem-solving"
```

---

### 2. How do you measure and track toil reduction?

**Answer:**

**Toil Measurement Framework:**

```python
from datetime import datetime, timedelta
import json

class ToilTracker:
    def __init__(self):
        self.tasks = {}
        self.automation_projects = {}
        
    def register_task(self, task_id, task_info):
        """Register a recurring operational task"""
        
        self.tasks[task_id] = {
            'name': task_info['name'],
            'description': task_info['description'],
            'category': task_info['category'],
            'frequency_per_week': task_info['frequency'],
            'avg_time_minutes': task_info['time_minutes'],
            'assigned_team': task_info['team'],
            'automation_status': 'manual',
            'executions': []
        }
    
    def record_execution(self, task_id, execution_time_minutes, executor):
        """Record task execution"""
        
        if task_id not in self.tasks:
            raise ValueError(f"Task {task_id} not registered")
        
        self.tasks[task_id]['executions'].append({
            'timestamp': datetime.utcnow(),
            'duration_minutes': execution_time_minutes,
            'executor': executor
        })
    
    def calculate_toil_metrics(self, time_period_days=30):
        """Calculate toil metrics for reporting"""
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=time_period_days)
        
        total_toil_hours = 0
        toil_by_category = {}
        toil_by_team = {}
        
        for task_id, task in self.tasks.items():
            # Filter executions in time period
            period_executions = [
                exec for exec in task['executions']
                if start_date <= exec['timestamp'] <= end_date
            ]
            
            if not period_executions:
                continue
            
            # Calculate metrics for this task
            task_total_minutes = sum(exec['duration_minutes'] for exec in period_executions)
            task_hours = task_total_minutes / 60
            
            total_toil_hours += task_hours
            
            # Categorize toil
            category = task['category']
            team = task['assigned_team']
            
            toil_by_category[category] = toil_by_category.get(category, 0) + task_hours
            toil_by_team[team] = toil_by_team.get(team, 0) + task_hours
        
        # Calculate percentages
        total_available_hours = self._calculate_team_capacity(time_period_days)
        toil_percentage = (total_toil_hours / total_available_hours) * 100
        
        return {
            'period_days': time_period_days,
            'total_toil_hours': total_toil_hours,
            'toil_percentage': toil_percentage,
            'toil_by_category': toil_by_category,
            'toil_by_team': toil_by_team,
            'top_toil_tasks': self._get_top_toil_tasks(time_period_days)
        }
    
    def track_automation_project(self, project_id, project_info):
        """Track automation project to reduce toil"""
        
        self.automation_projects[project_id] = {
            'name': project_info['name'],
            'target_tasks': project_info['target_tasks'],
            'estimated_hours_saved_per_week': project_info['estimated_savings'],
            'investment_hours': project_info['investment'],
            'status': 'planned',
            'start_date': None,
            'completion_date': None,
            'actual_savings': 0
        }
    
    def measure_automation_impact(self, project_id):
        """Measure actual impact of automation project"""
        
        if project_id not in self.automation_projects:
            raise ValueError(f"Project {project_id} not found")
        
        project = self.automation_projects[project_id]
        
        if project['status'] != 'completed':
            return {'status': 'not_completed'}
        
        # Calculate time savings for target tasks
        before_automation = self._calculate_pre_automation_time(project['target_tasks'])
        after_automation = self._calculate_post_automation_time(project['target_tasks'])
        
        actual_weekly_savings = before_automation - after_automation
        annual_savings = actual_weekly_savings * 52
        roi = annual_savings / project['investment_hours']
        
        return {
            'project_id': project_id,
            'estimated_weekly_savings': project['estimated_hours_saved_per_week'],
            'actual_weekly_savings': actual_weekly_savings,
            'annual_savings': annual_savings,
            'investment_hours': project['investment_hours'],
            'roi': roi,
            'payback_period_weeks': project['investment_hours'] / actual_weekly_savings if actual_weekly_savings > 0 else float('inf')
        }
```

**Toil Metrics Dashboard:**

```json
{
  "toil_dashboard": {
    "overview_metrics": [
      {
        "metric": "Total Toil Hours/Week",
        "current_value": 45,
        "target": "< 30",
        "trend": "decreasing"
      },
      {
        "metric": "Toil Percentage",
        "current_value": 22.5,
        "target": "< 15%",
        "trend": "decreasing"
      },
      {
        "metric": "Automation ROI",
        "current_value": 4.2,
        "target": "> 3.0",
        "trend": "increasing"
      }
    ],
    
    "toil_breakdown": {
      "by_category": {
        "deployments": 15,
        "monitoring": 12,
        "capacity_management": 8,
        "log_analysis": 10
      },
      
      "by_team": {
        "sre": 25,
        "platform": 12,
        "backend": 8
      }
    },
    
    "automation_pipeline": [
      {
        "project": "Automated Deployments",
        "status": "completed",
        "weekly_savings": 15,
        "roi": 6.2
      },
      {
        "project": "Log Analysis Automation",
        "status": "in_progress",
        "expected_completion": "2024-03-15",
        "estimated_savings": 10
      }
    ]
  }
}
```

---

### 3. How do you prioritize automation projects?

**Answer:**

**Automation Prioritization Framework:**

```python
import numpy as np
from dataclasses import dataclass
from typing import List

@dataclass
class AutomationCandidate:
    name: str
    current_weekly_hours: float
    automation_effort_hours: float
    complexity: str  # 'low', 'medium', 'high'
    risk: str        # 'low', 'medium', 'high'
    dependencies: List[str]
    team_capacity: float

class AutomationPrioritizer:
    def __init__(self):
        self.complexity_multipliers = {
            'low': 1.0,
            'medium': 1.5,
            'high': 2.5
        }
        
        self.risk_multipliers = {
            'low': 1.0,
            'medium': 1.3,
            'high': 2.0
        }
    
    def calculate_priority_score(self, candidate: AutomationCandidate):
        """Calculate priority score for automation candidate"""
        
        # Base ROI calculation
        annual_time_savings = candidate.current_weekly_hours * 52
        adjusted_effort = (candidate.automation_effort_hours * 
                          self.complexity_multipliers[candidate.complexity] *
                          self.risk_multipliers[candidate.risk])
        
        roi = annual_time_savings / adjusted_effort if adjusted_effort > 0 else 0
        
        # Time to value (how quickly we see benefits)
        time_to_value = adjusted_effort / candidate.team_capacity
        
        # Impact score (how much time we save)
        impact_score = candidate.current_weekly_hours
        
        # Effort score (lower is better)
        effort_score = 100 / adjusted_effort if adjusted_effort > 0 else 0
        
        # Dependency penalty
        dependency_penalty = len(candidate.dependencies) * 0.1
        
        # Combined priority score
        priority_score = (
            roi * 0.4 +                    # 40% weight on ROI
            impact_score * 0.3 +           # 30% weight on impact
            effort_score * 0.2 +           # 20% weight on ease of implementation
            (1 / time_to_value) * 0.1      # 10% weight on speed to value
        ) - dependency_penalty
        
        return {
            'priority_score': priority_score,
            'roi': roi,
            'time_to_value_weeks': time_to_value,
            'impact_score': impact_score,
            'effort_score': effort_score,
            'risk_adjusted_effort': adjusted_effort
        }
    
    def prioritize_candidates(self, candidates: List[AutomationCandidate]):
        """Prioritize list of automation candidates"""
        
        scored_candidates = []
        
        for candidate in candidates:
            score_data = self.calculate_priority_score(candidate)
            scored_candidates.append({
                'candidate': candidate,
                'scores': score_data
            })
        
        # Sort by priority score (descending)
        scored_candidates.sort(key=lambda x: x['scores']['priority_score'], reverse=True)
        
        return scored_candidates
    
    def generate_automation_roadmap(self, candidates: List[AutomationCandidate], 
                                   quarters: int = 4):
        """Generate quarterly automation roadmap"""
        
        prioritized = self.prioritize_candidates(candidates)
        roadmap = {}
        
        available_capacity_per_quarter = 480  # hours (3 people * 40 hours/week * 4 weeks)
        
        for quarter in range(1, quarters + 1):
            roadmap[f'Q{quarter}'] = {
                'projects': [],
                'total_effort': 0,
                'expected_savings': 0
            }
        
        current_quarter = 1
        current_capacity = available_capacity_per_quarter
        
        for item in prioritized:
            candidate = item['candidate']
            effort = item['scores']['risk_adjusted_effort']
            
            # Check if project fits in current quarter
            if effort <= current_capacity:
                roadmap[f'Q{current_quarter}']['projects'].append({
                    'name': candidate.name,
                    'effort_hours': effort,
                    'weekly_savings': candidate.current_weekly_hours,
                    'roi': item['scores']['roi']
                })
                
                roadmap[f'Q{current_quarter}']['total_effort'] += effort
                roadmap[f'Q{current_quarter}']['expected_savings'] += candidate.current_weekly_hours
                current_capacity -= effort
            
            else:
                # Move to next quarter
                current_quarter += 1
                if current_quarter > quarters:
                    break
                
                current_capacity = available_capacity_per_quarter - effort
                roadmap[f'Q{current_quarter}']['projects'].append({
                    'name': candidate.name,
                    'effort_hours': effort,
                    'weekly_savings': candidate.current_weekly_hours,
                    'roi': item['scores']['roi']
                })
                
                roadmap[f'Q{current_quarter}']['total_effort'] += effort
                roadmap[f'Q{current_quarter}']['expected_savings'] += candidate.current_weekly_hours
        
        return roadmap

# Example usage
automation_candidates = [
    AutomationCandidate(
        name="Automated Deployment Pipeline",
        current_weekly_hours=20,
        automation_effort_hours=120,
        complexity="medium",
        risk="low",
        dependencies=["CI/CD infrastructure"],
        team_capacity=40
    ),
    AutomationCandidate(
        name="Log Analysis Automation",
        current_weekly_hours=15,
        automation_effort_hours=80,
        complexity="low",
        risk="low",
        dependencies=[],
        team_capacity=40
    ),
    AutomationCandidate(
        name="Capacity Management Automation",
        current_weekly_hours=10,
        automation_effort_hours=200,
        complexity="high",
        risk="medium",
        dependencies=["Monitoring system upgrade", "Auto-scaling setup"],
        team_capacity=40
    )
]
```

---

### 4. How do you implement runbook automation?

**Answer:**

**Runbook Automation Framework:**

```python
from abc import ABC, abstractmethod
import yaml
import subprocess
import logging
from datetime import datetime
from enum import Enum

class RunbookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLBACK = "rollback"

class RunbookStep(ABC):
    def __init__(self, name, description, timeout=300):
        self.name = name
        self.description = description
        self.timeout = timeout
        self.status = RunbookStatus.PENDING
        self.start_time = None
        self.end_time = None
        self.output = None
        self.error = None
    
    @abstractmethod
    def execute(self):
        """Execute the runbook step"""
        pass
    
    @abstractmethod
    def rollback(self):
        """Rollback the step if needed"""
        pass
    
    def pre_check(self):
        """Pre-execution validation"""
        return True
    
    def post_check(self):
        """Post-execution validation"""
        return True

class CommandStep(RunbookStep):
    def __init__(self, name, description, command, expected_return_code=0, **kwargs):
        super().__init__(name, description, **kwargs)
        self.command = command
        self.expected_return_code = expected_return_code
    
    def execute(self):
        """Execute shell command"""
        
        self.start_time = datetime.utcnow()
        self.status = RunbookStatus.RUNNING
        
        try:
            result = subprocess.run(
                self.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            self.output = result.stdout
            self.error = result.stderr
            
            if result.returncode == self.expected_return_code:
                self.status = RunbookStatus.SUCCESS
            else:
                self.status = RunbookStatus.FAILED
                self.error = f"Command failed with return code {result.returncode}"
            
        except subprocess.TimeoutExpired:
            self.status = RunbookStatus.FAILED
            self.error = f"Command timed out after {self.timeout} seconds"
        
        except Exception as e:
            self.status = RunbookStatus.FAILED
            self.error = str(e)
        
        finally:
            self.end_time = datetime.utcnow()
        
        return self.status == RunbookStatus.SUCCESS

class HTTPCheckStep(RunbookStep):
    def __init__(self, name, description, url, expected_status=200, **kwargs):
        super().__init__(name, description, **kwargs)
        self.url = url
        self.expected_status = expected_status
    
    def execute(self):
        """Perform HTTP health check"""
        
        import requests
        
        self.start_time = datetime.utcnow()
        self.status = RunbookStatus.RUNNING
        
        try:
            response = requests.get(self.url, timeout=self.timeout)
            self.output = f"Status: {response.status_code}, Response time: {response.elapsed.total_seconds():.2f}s"
            
            if response.status_code == self.expected_status:
                self.status = RunbookStatus.SUCCESS
            else:
                self.status = RunbookStatus.FAILED
                self.error = f"Expected status {self.expected_status}, got {response.status_code}"
        
        except Exception as e:
            self.status = RunbookStatus.FAILED
            self.error = str(e)
        
        finally:
            self.end_time = datetime.utcnow()
        
        return self.status == RunbookStatus.SUCCESS

class DatabaseQueryStep(RunbookStep):
    def __init__(self, name, description, query, expected_result=None, **kwargs):
        super().__init__(name, description, **kwargs)
        self.query = query
        self.expected_result = expected_result
    
    def execute(self):
        """Execute database query"""
        
        self.start_time = datetime.utcnow()
        self.status = RunbookStatus.RUNNING
        
        try:
            # Database connection would be injected
            result = self._execute_query(self.query)
            self.output = str(result)
            
            if self.expected_result is None or result == self.expected_result:
                self.status = RunbookStatus.SUCCESS
            else:
                self.status = RunbookStatus.FAILED
                self.error = f"Expected {self.expected_result}, got {result}"
        
        except Exception as e:
            self.status = RunbookStatus.FAILED
            self.error = str(e)
        
        finally:
            self.end_time = datetime.utcnow()
        
        return self.status == RunbookStatus.SUCCESS

class AutomatedRunbook:
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.steps = []
        self.status = RunbookStatus.PENDING
        self.start_time = None
        self.end_time = None
        self.current_step_index = 0
        self.rollback_on_failure = True
        
    def add_step(self, step: RunbookStep):
        """Add step to runbook"""
        self.steps.append(step)
    
    def execute(self):
        """Execute all runbook steps"""
        
        logging.info(f"Starting runbook execution: {self.name}")
        
        self.start_time = datetime.utcnow()
        self.status = RunbookStatus.RUNNING
        
        try:
            for i, step in enumerate(self.steps):
                self.current_step_index = i
                
                logging.info(f"Executing step {i+1}/{len(self.steps)}: {step.name}")
                
                # Pre-execution check
                if not step.pre_check():
                    raise Exception(f"Pre-check failed for step: {step.name}")
                
                # Execute step
                success = step.execute()
                
                if not success:
                    self.status = RunbookStatus.FAILED
                    if self.rollback_on_failure:
                        self._rollback_steps(i)
                    raise Exception(f"Step failed: {step.name} - {step.error}")
                
                # Post-execution check
                if not step.post_check():
                    self.status = RunbookStatus.FAILED
                    if self.rollback_on_failure:
                        self._rollback_steps(i)
                    raise Exception(f"Post-check failed for step: {step.name}")
                
                logging.info(f"Step completed successfully: {step.name}")
            
            self.status = RunbookStatus.SUCCESS
            logging.info(f"Runbook completed successfully: {self.name}")
        
        except Exception as e:
            logging.error(f"Runbook failed: {self.name} - {str(e)}")
            self.status = RunbookStatus.FAILED
        
        finally:
            self.end_time = datetime.utcnow()
        
        return self.status == RunbookStatus.SUCCESS
    
    def _rollback_steps(self, failed_step_index):
        """Rollback completed steps in reverse order"""
        
        logging.info(f"Rolling back steps for runbook: {self.name}")
        
        for i in range(failed_step_index, -1, -1):
            step = self.steps[i]
            if step.status == RunbookStatus.SUCCESS:
                try:
                    logging.info(f"Rolling back step: {step.name}")
                    step.rollback()
                except Exception as e:
                    logging.error(f"Rollback failed for step {step.name}: {str(e)}")
    
    def get_execution_summary(self):
        """Get execution summary"""
        
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        step_summaries = []
        for step in self.steps:
            step_duration = None
            if step.start_time and step.end_time:
                step_duration = (step.end_time - step.start_time).total_seconds()
            
            step_summaries.append({
                'name': step.name,
                'status': step.status.value,
                'duration_seconds': step_duration,
                'output': step.output,
                'error': step.error
            })
        
        return {
            'runbook_name': self.name,
            'status': self.status.value,
            'duration_seconds': duration,
            'steps': step_summaries
        }

# Runbook Factory for common scenarios
class RunbookFactory:
    @staticmethod
    def create_deployment_runbook(service_name, version):
        """Create automated deployment runbook"""
        
        runbook = AutomatedRunbook(
            name=f"Deploy {service_name} v{version}",
            description=f"Automated deployment of {service_name} version {version}"
        )
        
        # Pre-deployment checks
        runbook.add_step(HTTPCheckStep(
            "Health Check",
            "Verify service is healthy before deployment",
            f"https://{service_name}.example.com/health"
        ))
        
        runbook.add_step(CommandStep(
            "Database Migration",
            "Run database migrations",
            f"kubectl exec deployment/{service_name} -- python manage.py migrate"
        ))
        
        # Deployment
        runbook.add_step(CommandStep(
            "Deploy New Version",
            "Deploy new service version",
            f"kubectl set image deployment/{service_name} {service_name}={service_name}:{version}"
        ))
        
        runbook.add_step(CommandStep(
            "Wait for Rollout",
            "Wait for deployment to complete",
            f"kubectl rollout status deployment/{service_name} --timeout=300s"
        ))
        
        # Post-deployment verification
        runbook.add_step(HTTPCheckStep(
            "Post-deployment Health Check",
            "Verify service is healthy after deployment",
            f"https://{service_name}.example.com/health"
        ))
        
        return runbook
    
    @staticmethod
    def create_incident_response_runbook(service_name):
        """Create incident response runbook"""
        
        runbook = AutomatedRunbook(
            name=f"Incident Response - {service_name}",
            description=f"Automated incident response for {service_name}"
        )
        
        # Diagnosis steps
        runbook.add_step(HTTPCheckStep(
            "Service Availability Check",
            "Check if service is responding",
            f"https://{service_name}.example.com/health"
        ))
        
        runbook.add_step(CommandStep(
            "Check Pod Status",
            "Check Kubernetes pod status",
            f"kubectl get pods -l app={service_name}"
        ))
        
        runbook.add_step(CommandStep(
            "Check Resource Usage",
            "Check CPU and memory usage",
            f"kubectl top pods -l app={service_name}"
        ))
        
        # Recovery steps
        runbook.add_step(CommandStep(
            "Restart Unhealthy Pods",
            "Restart pods that are not ready",
            f"kubectl delete pods -l app={service_name} --field-selector=status.phase!=Running"
        ))
        
        runbook.add_step(CommandStep(
            "Scale Up if Needed",
            "Scale up deployment if under pressure",
            f"kubectl scale deployment/{service_name} --replicas=5"
        ))
        
        return runbook
```

**Runbook Configuration File:**

```yaml
# runbooks.yml
runbooks:
  database_maintenance:
    name: "Weekly Database Maintenance"
    description: "Automated weekly database maintenance tasks"
    schedule: "0 2 * * 0"  # Sunday 2 AM
    steps:
      - type: "command"
        name: "Backup Database"
        command: "pg_dump production_db > /backups/weekly_$(date +%Y%m%d).sql"
        timeout: 1800
      
      - type: "command"
        name: "Analyze Tables"
        command: "psql production_db -c 'ANALYZE;'"
        timeout: 600
      
      - type: "command"
        name: "Vacuum Database"
        command: "psql production_db -c 'VACUUM;'"
        timeout: 3600
      
      - type: "http_check"
        name: "Verify Service Health"
        url: "https://api.example.com/health"
        expected_status: 200

  log_rotation:
    name: "Log Rotation and Cleanup"
    description: "Automated log rotation and cleanup"
    schedule: "0 1 * * *"  # Daily 1 AM
    steps:
      - type: "command"
        name: "Rotate Application Logs"
        command: "logrotate /etc/logrotate.d/application"
      
      - type: "command"
        name: "Compress Old Logs"
        command: "find /var/log -name '*.log.1' -exec gzip {} \\;"
      
      - type: "command"
        name: "Clean Old Archives"
        command: "find /var/log -name '*.gz' -mtime +30 -delete"

triggers:
  alert_based:
    high_error_rate:
      runbook: "incident_response_web_service"
      conditions:
        - "error_rate > 5%"
        - "duration > 5 minutes"
    
    high_latency:
      runbook: "performance_investigation"
      conditions:
        - "p95_latency > 1000ms"
        - "duration > 10 minutes"
```

---

### 5. How do you implement self-healing systems?

**Answer:**

**Self-Healing Architecture:**

```python
from abc import ABC, abstractmethod
import time
import threading
from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Callable

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"

@dataclass
class HealthCheck:
    name: str
    check_function: Callable
    interval_seconds: int
    timeout_seconds: int
    failure_threshold: int
    recovery_threshold: int

class HealingAction(ABC):
    def __init__(self, name, description):
        self.name = name
        self.description = description
    
    @abstractmethod
    def execute(self, context: Dict):
        """Execute the healing action"""
        pass
    
    @abstractmethod
    def can_execute(self, context: Dict) -> bool:
        """Check if action can be executed"""
        pass

class RestartServiceAction(HealingAction):
    def __init__(self, service_name):
        super().__init__(
            "Restart Service",
            f"Restart {service_name} service"
        )
        self.service_name = service_name
        self.max_restarts_per_hour = 3
        self.restart_history = []
    
    def can_execute(self, context: Dict) -> bool:
        """Check if service can be restarted"""
        
        now = time.time()
        # Remove restarts older than 1 hour
        self.restart_history = [
            restart_time for restart_time in self.restart_history
            if now - restart_time < 3600
        ]
        
        # Check if we haven't exceeded restart limit
        return len(self.restart_history) < self.max_restarts_per_hour
    
    def execute(self, context: Dict):
        """Restart the service"""
        
        if not self.can_execute(context):
            return {
                'success': False,
                'reason': 'Max restarts per hour exceeded'
            }
        
        try:
            # Record restart attempt
            self.restart_history.append(time.time())
            
            # Execute restart command
            import subprocess
            result = subprocess.run(
                f"systemctl restart {self.service_name}",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': f"Successfully restarted {self.service_name}"
                }
            else:
                return {
                    'success': False,
                    'reason': f"Restart command failed: {result.stderr}"
                }
        
        except Exception as e:
            return {
                'success': False,
                'reason': f"Exception during restart: {str(e)}"
            }

class ScaleUpAction(HealingAction):
    def __init__(self, service_name, max_replicas=10):
        super().__init__(
            "Scale Up Service",
            f"Scale up {service_name} service"
        )
        self.service_name = service_name
        self.max_replicas = max_replicas
    
    def can_execute(self, context: Dict) -> bool:
        """Check if service can be scaled up"""
        current_replicas = self._get_current_replicas()
        return current_replicas < self.max_replicas
    
    def execute(self, context: Dict):
        """Scale up the service"""
        
        current_replicas = self._get_current_replicas()
        new_replicas = min(current_replicas + 2, self.max_replicas)
        
        try:
            import subprocess
            result = subprocess.run(
                f"kubectl scale deployment/{self.service_name} --replicas={new_replicas}",
                shell=True,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'message': f"Scaled {self.service_name} from {current_replicas} to {new_replicas} replicas"
                }
            else:
                return {
                    'success': False,
                    'reason': f"Scale command failed: {result.stderr}"
                }
        
        except Exception as e:
            return {
                'success': False,
                'reason': f"Exception during scaling: {str(e)}"
            }
    
    def _get_current_replicas(self):
        """Get current number of replicas"""
        # Implementation would query Kubernetes API
        return 3  # Placeholder

class SelfHealingSystem:
    def __init__(self):
        self.health_checks = {}
        self.healing_policies = {}
        self.health_status = {}
        self.failure_counts = {}
        self.running = False
        self.monitor_thread = None
    
    def register_health_check(self, service_name: str, health_check: HealthCheck):
        """Register a health check for a service"""
        self.health_checks[service_name] = health_check
        self.health_status[service_name] = HealthStatus.UNKNOWN
        self.failure_counts[service_name] = 0
    
    def register_healing_policy(self, service_name: str, 
                               trigger_status: HealthStatus,
                               actions: List[HealingAction]):
        """Register healing policy for a service"""
        
        if service_name not in self.healing_policies:
            self.healing_policies[service_name] = {}
        
        self.healing_policies[service_name][trigger_status] = actions
    
    def start_monitoring(self):
        """Start the self-healing monitoring loop"""
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop the monitoring loop"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        
        while self.running:
            for service_name, health_check in self.health_checks.items():
                try:
                    # Execute health check
                    is_healthy = health_check.check_function()
                    
                    # Update health status
                    previous_status = self.health_status[service_name]
                    new_status = self._calculate_health_status(
                        service_name, is_healthy, health_check
                    )
                    
                    self.health_status[service_name] = new_status
                    
                    # Trigger healing if status changed to unhealthy
                    if (previous_status != new_status and 
                        new_status in [HealthStatus.DEGRADED, HealthStatus.UNHEALTHY]):
                        
                        self._trigger_healing(service_name, new_status)
                
                except Exception as e:
                    print(f"Error checking health for {service_name}: {str(e)}")
            
            time.sleep(30)  # Check every 30 seconds
    
    def _calculate_health_status(self, service_name: str, 
                                is_healthy: bool, 
                                health_check: HealthCheck) -> HealthStatus:
        """Calculate health status based on check results"""
        
        if is_healthy:
            # Reset failure count on success
            self.failure_counts[service_name] = max(0, self.failure_counts[service_name] - 1)
            
            if self.failure_counts[service_name] == 0:
                return HealthStatus.HEALTHY
            else:
                return HealthStatus.DEGRADED
        
        else:
            # Increment failure count
            self.failure_counts[service_name] += 1
            
            if self.failure_counts[service_name] >= health_check.failure_threshold:
                return HealthStatus.UNHEALTHY
            else:
                return HealthStatus.DEGRADED
    
    def _trigger_healing(self, service_name: str, health_status: HealthStatus):
        """Trigger healing actions for a service"""
        
        if service_name not in self.healing_policies:
            return
        
        if health_status not in self.healing_policies[service_name]:
            return
        
        actions = self.healing_policies[service_name][health_status]
        
        print(f"Triggering healing for {service_name} (status: {health_status.value})")
        
        for action in actions:
            if action.can_execute({}):
                result = action.execute({})
                
                if result['success']:
                    print(f"Healing action succeeded: {action.name}")
                    # Wait a bit before next action
                    time.sleep(30)
                else:
                    print(f"Healing action failed: {action.name} - {result.get('reason', 'Unknown')}")
            else:
                print(f"Healing action cannot be executed: {action.name}")

# Example implementation
def create_web_service_healing():
    """Create self-healing setup for web service"""
    
    healing_system = SelfHealingSystem()
    
    # Health check function
    def check_web_service_health():
        import requests
        try:
            response = requests.get("http://localhost:8080/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    # Register health check
    healing_system.register_health_check(
        "web-service",
        HealthCheck(
            name="HTTP Health Check",
            check_function=check_web_service_health,
            interval_seconds=30,
            timeout_seconds=5,
            failure_threshold=3,
            recovery_threshold=2
        )
    )
    
    # Register healing policies
    healing_system.register_healing_policy(
        "web-service",
        HealthStatus.DEGRADED,
        [RestartServiceAction("web-service")]
    )
    
    healing_system.register_healing_policy(
        "web-service", 
        HealthStatus.UNHEALTHY,
        [
            RestartServiceAction("web-service"),
            ScaleUpAction("web-service", max_replicas=10)
        ]
    )
    
    return healing_system
```

**Self-Healing Configuration:**

```yaml
# self-healing-config.yml
self_healing:
  services:
    web-api:
      health_checks:
        - name: "HTTP Health Check"
          type: "http"
          url: "http://localhost:8080/health"
          interval: 30
          timeout: 5
          failure_threshold: 3
          recovery_threshold: 2
        
        - name: "Database Connection Check"
          type: "database"
          connection_string: "postgresql://user:pass@db:5432/app"
          query: "SELECT 1"
          interval: 60
          timeout: 10
          failure_threshold: 2
      
      healing_policies:
        degraded:
          - type: "restart_service"
            service: "web-api"
            max_per_hour: 3
        
        unhealthy:
          - type: "restart_service"
            service: "web-api"
          - type: "scale_up"
            service: "web-api"
            max_replicas: 10
          - type: "notify_oncall"
            severity: "high"
    
    database:
      health_checks:
        - name: "Connection Pool Check"
          type: "database"
          query: "SELECT COUNT(*) FROM pg_stat_activity"
          interval: 60
          failure_threshold: 3
      
      healing_policies:
        degraded:
          - type: "restart_connection_pool"
          - type: "analyze_slow_queries"
        
        unhealthy:
          - type: "restart_service"
            service: "postgresql"
          - type: "escalate_to_dba"

circuit_breakers:
  payment_service:
    failure_threshold: 5
    recovery_timeout: 60
    half_open_max_calls: 3
  
  user_service:
    failure_threshold: 10
    recovery_timeout: 30
    half_open_max_calls: 5

monitoring:
  metrics:
    - "healing_actions_total"
    - "service_health_status"
    - "failure_counts"
    - "recovery_times"
  
  alerts:
    - name: "Self-Healing Action Failed"
      condition: "healing_action_failed"
      severity: "high"
    
    - name: "Frequent Healing Actions"
      condition: "healing_actions_per_hour > 10"
      severity: "medium"
```

---

## 🤖 Infrastructure as Code (IaC) Automation

### Terraform Automation

```python
class TerraformAutomation:
    def __init__(self, workspace_dir):
        self.workspace_dir = workspace_dir
    
    def plan_and_apply(self, auto_approve=False):
        """Automated Terraform plan and apply"""
        
        # Terraform plan
        plan_result = subprocess.run([
            "terraform", "plan", 
            "-out=tfplan",
            "-detailed-exitcode"
        ], cwd=self.workspace_dir, capture_output=True, text=True)
        
        if plan_result.returncode == 2:  # Changes detected
            print("Changes detected in Terraform plan")
            
            if auto_approve:
                # Terraform apply
                apply_result = subprocess.run([
                    "terraform", "apply", "tfplan"
                ], cwd=self.workspace_dir, capture_output=True, text=True)
                
                return {
                    'changes_applied': apply_result.returncode == 0,
                    'output': apply_result.stdout,
                    'errors': apply_result.stderr
                }
        
        return {'changes_applied': False, 'reason': 'No changes detected'}

    def validate_and_format(self):
        """Validate and format Terraform code"""
        
        # Format code
        subprocess.run(["terraform", "fmt", "-recursive"], cwd=self.workspace_dir)
        
        # Validate syntax
        validate_result = subprocess.run([
            "terraform", "validate"
        ], cwd=self.workspace_dir, capture_output=True, text=True)
        
        return {
            'valid': validate_result.returncode == 0,
            'errors': validate_result.stderr
        }
```

---

This comprehensive automation guide covers toil identification, measurement, prioritization, runbook automation, and self-healing systems with practical implementations and real-world examples for reducing operational overhead.