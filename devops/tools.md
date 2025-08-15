# DevOps Tools & Technologies 🛠️

## Version Control

### 1. What are the main Git workflows used in DevOps?

**Answer:**

**GitFlow:**
- **Main branches**: master/main (production), develop (integration)
- **Feature branches**: feature/* (new features)
- **Release branches**: release/* (preparing releases)
- **Hotfix branches**: hotfix/* (urgent fixes)

**GitHub Flow:**
- **Simpler**: Only main branch and feature branches
- **Process**: Create branch → Make changes → Pull request → Merge
- **Best for**: Continuous deployment environments

**GitLab Flow:**
- **Environment branches**: master → pre-production → production
- **Feature branches**: Merge to master, then promote through environments

### 2. What are Git hooks and how are they used in DevOps?

**Answer:**
Git hooks are scripts that run automatically on certain Git events.

**Common Hooks:**
- **pre-commit**: Run tests, linting before commit
- **pre-push**: Run full test suite before pushing
- **post-receive**: Trigger deployments on server

**DevOps Use Cases:**
- Code quality enforcement
- Automated testing
- Security scanning
- Deployment triggering
- Notification systems

## CI/CD Tools

### 3. Compare Jenkins, GitLab CI, and GitHub Actions

**Answer:**

| Feature | Jenkins | GitLab CI | GitHub Actions |
|---------|---------|-----------|----------------|
| **Hosting** | Self-hosted | SaaS/Self-hosted | SaaS |
| **Configuration** | Web UI/Jenkinsfile | `.gitlab-ci.yml` | `.github/workflows/` |
| **Scalability** | High (with slaves) | High | High |
| **Ecosystem** | Huge plugin library | Integrated GitLab | Growing marketplace |
| **Learning Curve** | Steep | Moderate | Gentle |
| **Cost** | Free (hosting costs) | Free tier/Paid | Free tier/Paid |

### 4. What is a Jenkins Pipeline and its types?

**Answer:**

**Declarative Pipeline:**
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        stage('Test') {
            steps {
                sh 'make test'
            }
        }
    }
}
```

**Scripted Pipeline:**
```groovy
node {
    stage('Build') {
        sh 'make build'
    }
    stage('Test') {
        sh 'make test'
    }
}
```

**Benefits:**
- **Pipeline as Code**: Version controlled
- **Reusability**: Shared libraries
- **Visualization**: Pipeline view
- **Parallel Execution**: Concurrent stages

## Containerization Tools

### 5. Docker vs other containerization technologies

**Answer:**

| Technology | Use Case | Advantages | Disadvantages |
|------------|----------|------------|---------------|
| **Docker** | General containerization | Easy to use, large ecosystem | Security concerns, resource overhead |
| **Podman** | Rootless containers | Better security, systemd integration | Smaller ecosystem |
| **LXC/LXD** | System containers | Better performance, full OS | More complex setup |
| **rkt** | Security-focused | App container standard | Discontinued |

### 6. What are multi-stage Docker builds?

**Answer:**
Multi-stage builds allow using multiple FROM statements to optimize final image size.

**Example:**
```dockerfile
# Build stage
FROM node:16 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Production stage
FROM node:16-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

**Benefits:**
- **Smaller images**: Only production artifacts
- **Security**: No build tools in production
- **Efficiency**: Cached build layers

## Orchestration Tools

### 7. Kubernetes vs Docker Swarm vs other orchestrators

**Answer:**

| Feature | Kubernetes | Docker Swarm | Nomad |
|---------|------------|--------------|-------|
| **Complexity** | High | Low | Medium |
| **Scalability** | Excellent | Good | Good |
| **Ecosystem** | Huge | Docker-centric | HashiCorp stack |
| **Learning Curve** | Steep | Gentle | Moderate |
| **Production Ready** | Yes | Limited | Yes |

### 8. What are Kubernetes operators?

**Answer:**
Operators extend Kubernetes to manage complex, stateful applications.

**Components:**
- **Custom Resources**: Define application-specific objects
- **Controllers**: Watch and reconcile desired state
- **Operator Logic**: Application-specific management logic

**Examples:**
- **Prometheus Operator**: Manages Prometheus instances
- **MySQL Operator**: Handles MySQL clusters
- **Istio Operator**: Manages service mesh

## Infrastructure Tools

### 9. Terraform vs CloudFormation vs Pulumi

**Answer:**

| Tool | Language | Provider Support | State Management |
|------|----------|------------------|------------------|
| **Terraform** | HCL | Multi-cloud | Remote state |
| **CloudFormation** | JSON/YAML | AWS only | AWS managed |
| **Pulumi** | Multiple languages | Multi-cloud | Service/self-managed |

**Terraform Advantages:**
- **Multi-cloud**: Works across providers
- **Mature**: Large community and modules
- **Plan/Apply**: Preview changes before applying

### 10. What is Ansible and its use cases?

**Answer:**
Ansible is an agentless automation tool for configuration management, application deployment, and orchestration.

**Key Features:**
- **Agentless**: Uses SSH/WinRM
- **Declarative**: Playbooks describe desired state
- **Idempotent**: Safe to run multiple times
- **Extensible**: Custom modules and plugins

**Use Cases:**
- **Configuration Management**: Server setup and maintenance
- **Application Deployment**: Automated app deployments
- **Orchestration**: Multi-tier application management
- **Provisioning**: Infrastructure setup

**Example Playbook:**
```yaml
---
- hosts: webservers
  tasks:
    - name: Install nginx
      package:
        name: nginx
        state: present
    - name: Start nginx
      service:
        name: nginx
        state: started
```

## Monitoring Tools

### 11. Prometheus vs other monitoring solutions

**Answer:**

| Tool | Type | Strengths | Use Cases |
|------|------|-----------|-----------|
| **Prometheus** | Pull-based metrics | Kubernetes native, PromQL | Infrastructure monitoring |
| **Grafana** | Visualization | Beautiful dashboards | Metrics visualization |
| **ELK Stack** | Log management | Full-text search, analytics | Log analysis |
| **Datadog** | SaaS monitoring | Easy setup, ML insights | Cloud monitoring |

### 12. What is the ELK/EFK stack?

**Answer:**

**ELK Stack:**
- **Elasticsearch**: Search and analytics engine
- **Logstash**: Data processing pipeline
- **Kibana**: Visualization and exploration

**EFK Stack:**
- **Elasticsearch**: Search and analytics engine
- **Fluentd**: Data collector and processor
- **Kibana**: Visualization and exploration

**Architecture:**
```
Applications → Fluentd/Logstash → Elasticsearch → Kibana
```

**Benefits:**
- **Centralized Logging**: All logs in one place
- **Real-time Analysis**: Near real-time search
- **Scalability**: Distributed architecture
- **Visualization**: Rich dashboards and alerts

## Security Tools

### 13. What are SAST, DAST, and IAST?

**Answer:**

**SAST (Static Application Security Testing):**
- **When**: During development/CI
- **How**: Analyzes source code
- **Tools**: SonarQube, Checkmarx, Veracode
- **Pros**: Early detection, comprehensive coverage
- **Cons**: False positives, no runtime issues

**DAST (Dynamic Application Security Testing):**
- **When**: Running application
- **How**: Tests application externally
- **Tools**: OWASP ZAP, Burp Suite, Nessus
- **Pros**: Real-world testing, fewer false positives
- **Cons**: Later in lifecycle, limited coverage

**IAST (Interactive Application Security Testing):**
- **When**: During testing/staging
- **How**: Instruments application code
- **Tools**: Contrast Security, Seeker
- **Pros**: Accurate results, runtime context
- **Cons**: Performance impact, complexity

### 14. What is container security scanning?

**Answer:**
Container security scanning identifies vulnerabilities in container images.

**Scan Types:**
- **OS Vulnerabilities**: Known CVEs in base images
- **Library Vulnerabilities**: Dependencies and packages
- **Configuration Issues**: Dockerfile best practices
- **Secrets Detection**: Hardcoded credentials

**Tools:**
- **Trivy**: Comprehensive vulnerability scanner
- **Clair**: Static analysis for containers
- **Snyk**: Developer-focused security
- **Twistlock/Prisma**: Enterprise container security

**Best Practices:**
- Scan in CI/CD pipeline
- Use minimal base images
- Regular updates of base images
- Runtime protection