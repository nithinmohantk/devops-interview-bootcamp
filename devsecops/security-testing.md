# Security Testing Interview Questions 🔒

## Static Application Security Testing (SAST)

### 1. What is SAST and how does it work?

**Answer:**
SAST (Static Application Security Testing) analyzes source code, bytecode, or binary code to identify security vulnerabilities without executing the application.

**How SAST Works:**
- **Code Parsing**: Analyzes source code structure and syntax
- **Data Flow Analysis**: Tracks how data moves through the application
- **Control Flow Analysis**: Examines program execution paths
- **Pattern Matching**: Identifies known vulnerable code patterns
- **Taint Analysis**: Tracks potentially malicious input through the system

**SAST Tools and Implementation:**
```yaml
# SonarQube SAST integration
sonarqube_sast:
  installation:
    - "Download SonarQube community edition"
    - "Configure database (PostgreSQL recommended)"
    - "Install language-specific scanners"
  
  integration:
    ci_cd_pipeline:
      - "Add sonar-scanner to build process"
      - "Configure quality gates"
      - "Set up automatic PR decoration"
      - "Configure security hotspot review"
```

**Example SAST Implementation in CI/CD:**
```yaml
# GitHub Actions with SonarCloud
name: SAST Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
      with:
        fetch-depth: 0
    
    - name: Setup Java
      uses: actions/setup-java@v3
      with:
        java-version: '11'
        distribution: 'temurin'
    
    - name: Cache SonarCloud packages
      uses: actions/cache@v3
      with:
        path: ~/.sonar/cache
        key: ${{ runner.os }}-sonar
    
    - name: Run SAST Scan
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      run: |
        ./gradlew sonarqube \
          -Dsonar.projectKey=my-project \
          -Dsonar.organization=my-org \
          -Dsonar.host.url=https://sonarcloud.io
    
    - name: Quality Gate Check
      run: |
        # Wait for quality gate result
        sleep 30
        curl -u ${{ secrets.SONAR_TOKEN }}: \
          "https://sonarcloud.io/api/qualitygates/project_status?projectKey=my-project" \
          | jq '.projectStatus.status' | grep -q "OK"
```

**Common SAST Vulnerabilities Detected:**
- **SQL Injection**: Unsanitized database queries
- **Cross-Site Scripting (XSS)**: Unescaped user input in web pages
- **Command Injection**: Unsafe execution of system commands
- **Path Traversal**: Unrestricted file access
- **Hardcoded Secrets**: Credentials embedded in source code

### 2. What is DAST and how does it complement SAST?

**Answer:**
DAST (Dynamic Application Security Testing) tests running applications by simulating attacks from an external perspective.

**DAST vs SAST Comparison:**

| Aspect | SAST | DAST |
|--------|------|------|
| **Testing Phase** | Development/Build | Runtime |
| **Code Access** | Requires source code | Black-box testing |
| **Coverage** | All code paths | Only accessible paths |
| **False Positives** | Higher | Lower |
| **Runtime Context** | No | Yes |
| **Performance Impact** | None | Can impact application |

**DAST Tools and Implementation:**
```yaml
# OWASP ZAP DAST scan
zap_dast_scan:
  setup:
    - "Start application in test environment"
    - "Configure ZAP proxy settings"
    - "Set up authentication if required"
    - "Define scan scope and exclusions"
  
  scan_types:
    spider_scan:
      purpose: "Discover application endpoints"
      configuration: "Follow links, forms, and AJAX calls"
    
    active_scan:
      purpose: "Test for vulnerabilities"
      configuration: "Inject payloads and analyze responses"
    
    passive_scan:
      purpose: "Analyze traffic"
      configuration: "Monitor requests/responses for issues"
```

**DAST CI/CD Integration Example:**
```yaml
# Jenkins pipeline with OWASP ZAP
pipeline {
    agent any
    stages {
        stage('Deploy to Test') {
            steps {
                sh 'docker-compose up -d'
                sh 'sleep 30' // Wait for app to start
            }
        }
        
        stage('DAST Scan') {
            steps {
                script {
                    // Start ZAP daemon
                    sh 'docker run -d --name zap-daemon -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080'
                    
                    // Wait for ZAP to start
                    sh 'sleep 30'
                    
                    // Run spider scan
                    sh '''
                        curl "http://localhost:8080/JSON/spider/action/scan/?url=http://app:3000"
                        # Wait for spider to complete
                        while [[ $(curl -s "http://localhost:8080/JSON/spider/view/status/" | jq -r '.status') != "100" ]]; do
                            sleep 5
                        done
                    '''
                    
                    // Run active scan
                    sh '''
                        curl "http://localhost:8080/JSON/ascan/action/scan/?url=http://app:3000"
                        # Wait for active scan to complete
                        while [[ $(curl -s "http://localhost:8080/JSON/ascan/view/status/" | jq -r '.status') != "100" ]]; do
                            sleep 10
                        done
                    '''
                    
                    // Generate report
                    sh 'curl "http://localhost:8080/OTHER/core/other/htmlreport/" > zap-report.html'
                    
                    // Check for high-risk issues
                    def highRiskAlerts = sh(
                        script: 'curl -s "http://localhost:8080/JSON/core/view/alertsSummary/" | jq ".alertsSummary.High"',
                        returnStdout: true
                    ).trim()
                    
                    if (highRiskAlerts.toInteger() > 0) {
                        error("High-risk security vulnerabilities found: ${highRiskAlerts}")
                    }
                }
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'zap-report.html',
                        reportName: 'ZAP Security Report'
                    ])
                    sh 'docker stop zap-daemon || true'
                    sh 'docker rm zap-daemon || true'
                }
            }
        }
    }
}
```

### 3. What is IAST and when should you use it?

**Answer:**
IAST (Interactive Application Security Testing) combines elements of SAST and DAST by instrumenting applications to analyze security from within during testing.

**How IAST Works:**
- **Code Instrumentation**: Inserts monitoring code into application
- **Runtime Analysis**: Monitors application behavior during testing
- **Data Flow Tracking**: Follows data from source to sink
- **Vulnerability Detection**: Identifies issues with runtime context

**IAST Implementation Example:**
```java
// Example with Contrast Security IAST agent
// JVM startup with IAST agent
java -javaagent:/path/to/contrast.jar \
     -Dcontrast.api.url=https://app.contrastsecurity.com/Contrast \
     -Dcontrast.api.user_name=agent@company.com \
     -Dcontrast.api.service_key=<service_key> \
     -Dcontrast.api.api_key=<api_key> \
     -jar myapp.jar
```

**IAST Configuration:**
```yaml
# Contrast Security configuration
contrast_config:
  agent:
    language: "java"
    version: "latest"
    
  application:
    name: "my-web-app"
    environment: "qa"
    tags: ["web", "payment"]
    
  security_controls:
    assess:
      enable: true
      sampling: 10  # Sample 10% of requests
      
    protect:
      enable: false  # Runtime protection
      
  reporting:
    level: "medium"  # Report medium and high severity
    exclude_urls:
      - "/health"
      - "/metrics"
```

**IAST Benefits:**
- **Low False Positives**: Runtime context reduces false alarms
- **Development Integration**: Works during normal testing
- **Complete Coverage**: Analyzes actual execution paths
- **Performance Monitoring**: Identifies security-related performance issues

### 4. How do you implement container security scanning?

**Answer:**
Container security scanning identifies vulnerabilities in container images, configurations, and runtime environments.

**Container Security Layers:**
```yaml
container_security_layers:
  image_scanning:
    focus: "Base image and package vulnerabilities"
    tools: ["Trivy", "Clair", "Snyk", "Twistlock"]
    timing: "Build time and registry"
    
  configuration_scanning:
    focus: "Dockerfile best practices"
    tools: ["Hadolint", "Checkov", "Docker Bench"]
    timing: "Build time"
    
  runtime_protection:
    focus: "Runtime behavior monitoring"
    tools: ["Falco", "Sysdig", "Aqua"]
    timing: "Production runtime"
```

**Trivy Security Scanning Example:**
```yaml
# GitHub Actions with Trivy
name: Container Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - name: Checkout code
      uses: actions/checkout@v3
    
    - name: Build Docker image
      run: docker build -t myapp:${{ github.sha }} .
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'myapp:${{ github.sha }}'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
    
    - name: Trivy config scan
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'config'
        scan-ref: '.'
        format: 'table'
    
    - name: Check for critical vulnerabilities
      run: |
        # Scan and fail if critical vulnerabilities found
        trivy image --exit-code 1 --severity CRITICAL myapp:${{ github.sha }}
```

**Dockerfile Security Best Practices:**
```dockerfile
# Secure Dockerfile example
FROM node:16-alpine AS builder

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY --chown=nextjs:nodejs . .
RUN npm run build

# Production stage
FROM node:16-alpine AS runner
WORKDIR /app

# Install security updates
RUN apk upgrade --no-cache

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Copy built application
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start application
CMD ["npm", "start"]
```

### 5. What are security policies as code and how do you implement them?

**Answer:**
Security policies as code define security rules and compliance requirements in a machine-readable format that can be version-controlled and automated.

**Open Policy Agent (OPA) Example:**
```rego
# Kubernetes security policy
package kubernetes.admission

# Deny containers running as root
deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.securityContext.runAsUser == 0
    msg := "Containers must not run as root user"
}

# Require resource limits
deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container '%v' must have memory limits", [container.name])
}

# Deny privileged containers
deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged == true
    msg := sprintf("Container '%v' cannot run in privileged mode", [container.name])
}

# Require specific image registries
deny[msg] {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not starts_with(container.image, "myregistry.com/")
    msg := sprintf("Container '%v' uses unauthorized registry", [container.name])
}
```

**Policy Enforcement in CI/CD:**
```yaml
# Conftest policy validation
name: Policy Validation
on: [push, pull_request]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Conftest
      run: |
        wget https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_Linux_x86_64.tar.gz
        tar xzf conftest_Linux_x86_64.tar.gz
        sudo mv conftest /usr/local/bin
    
    - name: Validate Kubernetes manifests
      run: |
        conftest verify \
          --policy security-policies/ \
          --data examples/ \
          k8s-manifests/*.yaml
    
    - name: Validate Terraform plans
      run: |
        terraform init
        terraform plan -out=tfplan
        terraform show -json tfplan > tfplan.json
        conftest test \
          --policy terraform-policies/ \
          tfplan.json
    
    - name: Validate Docker files
      run: |
        conftest test \
          --policy dockerfile-policies/ \
          Dockerfile
```

**Terraform Security Policy Example:**
```rego
# Terraform security policy
package terraform.security

# Deny public S3 buckets
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.values.block_public_acls == false
    msg := "S3 bucket public access must be blocked"
}

# Require encryption for EBS volumes
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_ebs_volume"
    not resource.values.encrypted
    msg := "EBS volumes must be encrypted"
}

# Require specific instance types
deny[msg] {
    resource := input.planned_values.root_module.resources[_]
    resource.type == "aws_instance"
    not resource.values.instance_type in ["t3.micro", "t3.small", "t3.medium"]
    msg := "Only approved instance types are allowed"
}
```

### 6. How do you implement security testing in microservices?

**Answer:**
Microservices security testing requires a comprehensive approach covering service-to-service communication, API security, and distributed system vulnerabilities.

**Microservices Security Testing Strategy:**
```yaml
microservices_security_testing:
  service_level:
    sast_scanning:
      - "Scan each service's codebase"
      - "Check for service-specific vulnerabilities"
      - "Validate input sanitization"
    
    dependency_scanning:
      - "Scan service dependencies"
      - "Check for known vulnerabilities"
      - "Monitor for new CVEs"
  
  integration_level:
    api_security_testing:
      - "Test API authentication/authorization"
      - "Validate input validation"
      - "Test rate limiting"
    
    service_mesh_security:
      - "Test mTLS configuration"
      - "Validate service identity"
      - "Check traffic encryption"
  
  system_level:
    end_to_end_testing:
      - "Test complete user workflows"
      - "Validate business logic security"
      - "Test cross-service vulnerabilities"
```

**API Security Testing Example:**
```python
# API security testing with pytest
import pytest
import requests
import jwt
from datetime import datetime, timedelta

class TestAPISecurityCohorts:
    base_url = "https://api.example.com"
    
    def test_authentication_required(self):
        """Test that endpoints require authentication"""
        response = requests.get(f"{self.base_url}/api/users")
        assert response.status_code == 401
        assert "authentication required" in response.json()["error"].lower()
    
    def test_invalid_token_rejected(self):
        """Test that invalid tokens are rejected"""
        headers = {"Authorization": "Bearer invalid_token"}
        response = requests.get(f"{self.base_url}/api/users", headers=headers)
        assert response.status_code == 401
    
    def test_expired_token_rejected(self):
        """Test that expired tokens are rejected"""
        # Create expired token
        expired_token = jwt.encode({
            'user_id': 123,
            'exp': datetime.utcnow() - timedelta(hours=1)
        }, 'secret', algorithm='HS256')
        
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = requests.get(f"{self.base_url}/api/users", headers=headers)
        assert response.status_code == 401
    
    def test_authorization_enforcement(self):
        """Test that users can only access their own data"""
        # Get token for user 1
        user1_token = self.get_valid_token(user_id=1)
        headers = {"Authorization": f"Bearer {user1_token}"}
        
        # Try to access user 2's data
        response = requests.get(f"{self.base_url}/api/users/2", headers=headers)
        assert response.status_code == 403
    
    def test_input_validation(self):
        """Test input validation and injection protection"""
        user_token = self.get_valid_token(user_id=1)
        headers = {"Authorization": f"Bearer {user_token}"}
        
        # Test SQL injection
        malicious_input = "'; DROP TABLE users; --"
        response = requests.get(
            f"{self.base_url}/api/search",
            params={"q": malicious_input},
            headers=headers
        )
        assert response.status_code == 400
        assert "invalid input" in response.json()["error"].lower()
    
    def test_rate_limiting(self):
        """Test that rate limiting is enforced"""
        user_token = self.get_valid_token(user_id=1)
        headers = {"Authorization": f"Bearer {user_token}"}
        
        # Make multiple requests quickly
        responses = []
        for _ in range(100):
            response = requests.get(f"{self.base_url}/api/status", headers=headers)
            responses.append(response.status_code)
        
        # Should get rate limited
        assert 429 in responses  # Too Many Requests
```

**Service Mesh Security Testing:**
```yaml
# Istio security policy testing
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: strict-mtls
  namespace: production
spec:
  mtls:
    mode: STRICT

---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: user-service-policy
  namespace: production
spec:
  selector:
    matchLabels:
      app: user-service
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/production/sa/api-gateway"]
  - to:
    - operation:
        methods: ["GET", "POST"]
```

**Contract Testing for Security:**
```javascript
// Pact contract testing for API security
const { Verifier } = require('@pact-foundation/pact');

describe('User Service Security Contract', () => {
  let verifier;
  
  beforeAll(() => {
    verifier = new Verifier({
      providerBaseUrl: 'http://localhost:3000',
      pactUrls: ['./pacts/api-gateway-user-service.json'],
      providerVersion: process.env.GIT_COMMIT,
      requestFilter: (req, res, next) => {
        // Add authentication for contract tests
        req.headers['authorization'] = 'Bearer valid_test_token';
        next();
      }
    });
  });
  
  it('validates security requirements in contracts', async () => {
    const result = await verifier.verifyProvider();
    expect(result).toBeTruthy();
  });
});
```