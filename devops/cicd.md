# CI/CD Interview Questions 🔄

## Continuous Integration (CI)

### 1. What are the key principles of Continuous Integration?

**Answer:**
Continuous Integration is a development practice where developers integrate code into a shared repository frequently, preferably several times a day.

**Core Principles:**
- **Frequent Integration**: Multiple integrations per day
- **Automated Build**: Every commit triggers a build
- **Automated Testing**: Comprehensive test suite runs automatically
- **Fast Feedback**: Quick notification of integration issues
- **Fail Fast**: Stop the line when builds fail
- **Version Control**: Single source of truth for code

**CI Pipeline Stages:**
1. **Code Commit**: Developer pushes code to repository
2. **Trigger Build**: Webhook or polling triggers pipeline
3. **Code Checkout**: Pipeline pulls latest code
4. **Dependency Installation**: Install required packages
5. **Static Analysis**: Code quality and security checks
6. **Unit Tests**: Fast, isolated tests
7. **Integration Tests**: Component interaction tests
8. **Build Artifacts**: Compile and package application
9. **Artifact Storage**: Store build outputs for deployment

### 2. What is the difference between CI, CD (Continuous Delivery), and CD (Continuous Deployment)?

**Answer:**

| Aspect | Continuous Integration | Continuous Delivery | Continuous Deployment |
|--------|----------------------|-------------------|---------------------|
| **Scope** | Code integration | Deployment ready | Automated production |
| **Automation** | Build and test | Build, test, package | Build, test, deploy |
| **Human Gate** | Code review | Production approval | None |
| **Frequency** | Multiple times/day | On-demand | Every successful build |
| **Risk** | Low | Medium | Higher |

**Continuous Integration Example:**
```yaml
# Basic CI pipeline
ci_pipeline:
  triggers:
    - push to main
    - pull request
  steps:
    - checkout_code
    - install_dependencies
    - run_tests
    - static_analysis
    - build_artifact
```

**Continuous Delivery Example:**
```yaml
# CI + CD pipeline
cd_pipeline:
  stages:
    - ci_stage
    - staging_deployment
    - integration_tests
    - manual_approval  # Human gate
    - production_deployment
```

**Continuous Deployment Example:**
```yaml
# Fully automated pipeline
continuous_deployment:
  stages:
    - ci_stage
    - staging_deployment
    - automated_tests
    - production_deployment  # No human gate
  conditions:
    - all_tests_pass
    - quality_gates_met
```

### 3. What are the best practices for CI pipeline design?

**Answer:**

**Pipeline Structure:**
- **Fast Feedback Loop**: Keep builds under 10 minutes
- **Parallel Execution**: Run independent tests concurrently
- **Pipeline as Code**: Version control pipeline definitions
- **Fail Fast**: Put fastest tests first

**Build Optimization:**
```yaml
# Optimized pipeline structure
pipeline:
  stage1_fast:  # < 2 minutes
    - lint
    - unit_tests
    - security_scan
  
  stage2_medium:  # < 5 minutes
    - integration_tests
    - build_artifacts
    - container_scan
  
  stage3_slow:  # < 10 minutes
    - e2e_tests
    - performance_tests
    - deploy_staging
```

**Quality Gates:**
- **Code Coverage**: Minimum 80% coverage
- **Test Success Rate**: 100% test pass rate
- **Security Scan**: No critical vulnerabilities
- **Performance**: Response time within limits

**Artifact Management:**
- **Immutable Artifacts**: Build once, deploy many times
- **Versioning**: Semantic versioning for releases
- **Storage**: Centralized artifact repository
- **Cleanup**: Automated cleanup of old artifacts

### 4. How do you handle secrets and sensitive data in CI/CD pipelines?

**Answer:**

**Secret Management Strategies:**

**Environment Variables:**
```yaml
# GitHub Actions example
jobs:
  deploy:
    steps:
    - name: Deploy to production
      env:
        DATABASE_URL: ${{ secrets.DATABASE_URL }}
        API_KEY: ${{ secrets.API_KEY }}
      run: ./deploy.sh
```

**Secret Management Tools:**
- **HashiCorp Vault**: Centralized secret management
- **AWS Secrets Manager**: Cloud-native secret storage
- **Azure Key Vault**: Microsoft's secret management
- **Kubernetes Secrets**: Container orchestration secrets

**Best Practices:**
- **Least Privilege**: Minimal required permissions
- **Rotation**: Regular secret rotation
- **Audit Logging**: Track secret access
- **Separation**: Different secrets per environment

**Implementation Example:**
```yaml
# Jenkins pipeline with vault
pipeline {
    agent any
    stages {
        stage('Deploy') {
            steps {
                withVault([
                    vaultSecrets: [
                        [path: 'secret/prod', secretValues: [
                            [envVar: 'DB_PASSWORD', vaultKey: 'db_password'],
                            [envVar: 'API_KEY', vaultKey: 'api_key']
                        ]]
                    ]
                ]) {
                    sh 'kubectl apply -f deployment.yaml'
                }
            }
        }
    }
}
```

## Continuous Deployment (CD)

### 5. What are different deployment strategies?

**Answer:**

**Blue-Green Deployment:**
- **Description**: Two identical environments, switch traffic between them
- **Benefits**: Zero-downtime, quick rollback
- **Drawbacks**: Double infrastructure cost
- **Use Case**: Critical applications requiring zero downtime

```yaml
# Blue-Green deployment example
blue_green_deployment:
  blue_environment:
    status: "current"
    traffic: 100%
  green_environment:
    status: "staging"
    traffic: 0%
  
  deployment_steps:
    1. "Deploy to green environment"
    2. "Run smoke tests on green"
    3. "Switch traffic to green"
    4. "Monitor green environment"
    5. "Decommission blue if successful"
```

**Canary Deployment:**
- **Description**: Gradual rollout to subset of users
- **Benefits**: Risk mitigation, real user feedback
- **Drawbacks**: Complex monitoring required
- **Use Case**: New features with uncertain impact

```yaml
# Canary deployment stages
canary_deployment:
  stage1:
    new_version_traffic: 5%
    duration: "30 minutes"
    success_criteria:
      - error_rate < 0.1%
      - latency_p95 < 200ms
  
  stage2:
    new_version_traffic: 25%
    duration: "1 hour"
    success_criteria:
      - error_rate < 0.1%
      - user_satisfaction > 95%
  
  stage3:
    new_version_traffic: 100%
    success_criteria:
      - all_metrics_normal
```

**Rolling Deployment:**
- **Description**: Gradual replacement of instances
- **Benefits**: Resource efficient, built-in rollback
- **Drawbacks**: Mixed versions during deployment
- **Use Case**: Stateless applications

```yaml
# Kubernetes rolling update
apiVersion: apps/v1
kind: Deployment
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 25%
      maxSurge: 25%
  template:
    spec:
      containers:
      - name: app
        image: myapp:v2.0.0
```

### 6. How do you implement feature flags in CI/CD?

**Answer:**
Feature flags allow deploying code without exposing features to users, enabling safer deployments and gradual rollouts.

**Implementation Strategies:**

**Configuration-Based Flags:**
```python
# Python example with feature flags
import os
from typing import Dict, Any

class FeatureFlags:
    def __init__(self):
        self.flags = {
            'new_checkout_flow': os.getenv('FEATURE_NEW_CHECKOUT', 'false').lower() == 'true',
            'ai_recommendations': os.getenv('FEATURE_AI_RECS', 'false').lower() == 'true',
            'dark_mode': os.getenv('FEATURE_DARK_MODE', 'false').lower() == 'true'
        }
    
    def is_enabled(self, flag_name: str, user_id: str = None) -> bool:
        if flag_name not in self.flags:
            return False
        
        # Simple percentage rollout
        if user_id and flag_name == 'ai_recommendations':
            return hash(user_id) % 100 < 20  # 20% rollout
        
        return self.flags[flag_name]

# Usage in application
flags = FeatureFlags()

def process_checkout(user_id: str):
    if flags.is_enabled('new_checkout_flow', user_id):
        return new_checkout_process(user_id)
    else:
        return legacy_checkout_process(user_id)
```

**Database-Driven Flags:**
```sql
-- Feature flags table
CREATE TABLE feature_flags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    enabled BOOLEAN DEFAULT FALSE,
    rollout_percentage INTEGER DEFAULT 0,
    conditions JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Example flags
INSERT INTO feature_flags (name, enabled, rollout_percentage) VALUES
('new_dashboard', true, 25),
('beta_api', false, 0),
('premium_features', true, 100);
```

**Feature Flag Management:**
```yaml
# Feature flag deployment pipeline
feature_flag_deployment:
  dev_environment:
    new_feature: true
    experimental_ui: true
  
  staging_environment:
    new_feature: true
    experimental_ui: false
  
  production_environment:
    new_feature: false  # Start disabled
    experimental_ui: false
  
  rollout_plan:
    phase1:
      environment: production
      percentage: 5%
      duration: "2 hours"
    phase2:
      environment: production
      percentage: 25%
      duration: "24 hours"
    phase3:
      environment: production
      percentage: 100%
```

### 7. What is GitOps and how does it differ from traditional CI/CD?

**Answer:**
GitOps is a paradigm where Git repositories serve as the single source of truth for declarative infrastructure and application deployment.

**Core Principles:**
- **Declarative**: Entire system described declaratively
- **Versioned and Immutable**: Git as single source of truth
- **Pulled Automatically**: Software agents pull desired state
- **Continuously Reconciled**: System corrects drift

**Traditional CI/CD vs GitOps:**

| Aspect | Traditional CI/CD | GitOps |
|--------|------------------|---------|
| **Deployment Trigger** | Push-based (CI pushes) | Pull-based (agent pulls) |
| **Access Control** | CI system needs cluster access | No external cluster access |
| **Drift Detection** | Manual detection | Automatic detection and correction |
| **Rollback** | Manual or CI-triggered | Git revert triggers rollback |
| **Audit Trail** | CI logs | Git history |

**GitOps Workflow:**
```yaml
# GitOps repository structure
gitops-repo/
├── applications/
│   ├── app1/
│   │   ├── base/
│   │   │   ├── deployment.yaml
│   │   │   └── service.yaml
│   │   └── overlays/
│   │       ├── dev/
│   │       ├── staging/
│   │       └── prod/
│   └── app2/
├── infrastructure/
│   ├── clusters/
│   └── networking/
└── policies/
```

**ArgoCD Application Example:**
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/company/gitops-repo
    targetRevision: HEAD
    path: applications/my-app/overlays/prod
  destination:
    server: https://kubernetes.default.svc
    namespace: production
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

### 8. How do you handle database migrations in CI/CD?

**Answer:**
Database migrations require careful coordination with application deployments to ensure data integrity and minimize downtime.

**Migration Strategies:**

**Backwards Compatible Migrations:**
```sql
-- Phase 1: Add new column (backwards compatible)
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;

-- Phase 2: Populate new column
UPDATE users SET email_verified = TRUE WHERE email_verification_date IS NOT NULL;

-- Phase 3: Remove old column (in next release)
ALTER TABLE users DROP COLUMN email_verification_date;
```

**Blue-Green Database Strategy:**
```yaml
# Database migration pipeline
database_migration:
  blue_green_strategy:
    1. "Create green database from blue backup"
    2. "Apply migrations to green database"
    3. "Run application tests against green database"
    4. "Switch application to green database"
    5. "Verify application functionality"
    6. "Decommission blue database"
```

**Migration Tools Integration:**
```yaml
# Flyway migration in CI/CD
stages:
  - name: "Database Migration"
    script: |
      flyway -url=jdbc:postgresql://db:5432/myapp \
             -user=$DB_USER \
             -password=$DB_PASSWORD \
             -locations=filesystem:migrations \
             migrate
    
  - name: "Application Deployment"
    depends_on: "Database Migration"
    script: |
      kubectl apply -f app-deployment.yaml
```

**Rollback Strategies:**
```yaml
migration_rollback:
  preparation:
    - "Always backup before migration"
    - "Test rollback procedures in staging"
    - "Document rollback steps"
  
  rollback_types:
    schema_rollback:
      method: "Flyway undo migrations"
      limitations: "Not all migrations are reversible"
    
    data_rollback:
      method: "Restore from backup"
      considerations: "Data loss since backup"
    
    application_rollback:
      method: "Deploy previous application version"
      requirement: "Backwards compatible schema"
```

### 9. What are quality gates and how do you implement them?

**Answer:**
Quality gates are checkpoints in the CI/CD pipeline that prevent low-quality code from progressing to the next stage.

**Types of Quality Gates:**

**Code Quality Gates:**
```yaml
# SonarQube quality gate
quality_gate:
  code_coverage:
    threshold: 80%
    action: "fail_if_below"
  
  duplicated_lines:
    threshold: 3%
    action: "fail_if_above"
  
  maintainability_rating:
    threshold: "A"
    action: "fail_if_below"
  
  reliability_rating:
    threshold: "A" 
    action: "fail_if_below"
  
  security_rating:
    threshold: "A"
    action: "fail_if_below"
```

**Performance Quality Gates:**
```yaml
# Performance testing quality gate
performance_gate:
  load_testing:
    response_time_p95: 
      threshold: "200ms"
      action: "fail_if_above"
    
    error_rate:
      threshold: "1%"
      action: "fail_if_above"
    
    throughput:
      threshold: "1000 rps"
      action: "fail_if_below"
```

**Security Quality Gates:**
```yaml
# Security scanning quality gate
security_gate:
  vulnerability_scan:
    critical_vulnerabilities:
      threshold: 0
      action: "fail_if_above"
    
    high_vulnerabilities:
      threshold: 5
      action: "fail_if_above"
  
  secret_detection:
    exposed_secrets:
      threshold: 0
      action: "fail_if_above"
  
  license_compliance:
    prohibited_licenses:
      threshold: 0
      action: "fail_if_above"
```

**Implementation Example:**
```yaml
# Jenkins pipeline with quality gates
pipeline {
    agent any
    stages {
        stage('Code Quality Gate') {
            steps {
                script {
                    def qg = waitForQualityGate()
                    if (qg.status != 'OK') {
                        error "Pipeline aborted due to quality gate failure: ${qg.status}"
                    }
                }
            }
        }
        
        stage('Security Gate') {
            steps {
                script {
                    def securityScan = sh(
                        script: 'security-scanner --format json .',
                        returnStdout: true
                    )
                    def results = readJSON text: securityScan
                    if (results.critical_vulnerabilities > 0) {
                        error "Critical vulnerabilities found: ${results.critical_vulnerabilities}"
                    }
                }
            }
        }
    }
}
```

### 10. How do you implement pipeline monitoring and observability?

**Answer:**
Pipeline monitoring provides visibility into build performance, failure patterns, and overall CI/CD health.

**Key Metrics to Monitor:**

**Pipeline Performance Metrics:**
- **Build Duration**: Time from start to completion
- **Queue Time**: Time waiting for available agents
- **Success Rate**: Percentage of successful builds
- **Frequency**: Number of builds per time period
- **MTTR**: Mean time to recovery from failures

**Implementation Example:**
```yaml
# Pipeline metrics collection
pipeline_metrics:
  build_duration:
    measurement: "time_to_complete"
    alert_threshold: "> 15 minutes"
  
  success_rate:
    measurement: "successful_builds / total_builds"
    alert_threshold: "< 95%"
  
  queue_time:
    measurement: "start_time - queue_time"
    alert_threshold: "> 5 minutes"
```

**Monitoring Stack:**
```yaml
# Prometheus + Grafana monitoring
monitoring:
  data_collection:
    - jenkins_prometheus_plugin
    - github_actions_exporter
    - gitlab_ci_exporter
  
  visualization:
    - grafana_dashboards
    - pipeline_analytics
  
  alerting:
    - slack_notifications
    - email_alerts
    - pagerduty_integration
```

**Dashboard Metrics:**
```yaml
# Key dashboard panels
dashboard_panels:
  build_overview:
    - total_builds_today
    - success_rate_24h
    - average_build_time
    - failed_builds_list
  
  trend_analysis:
    - build_duration_trend
    - success_rate_trend
    - deployment_frequency
  
  pipeline_health:
    - stage_success_rates
    - bottleneck_identification
    - resource_utilization
```