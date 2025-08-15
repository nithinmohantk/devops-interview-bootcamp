# DevSecOps Fundamentals 🛡️

## Core DevSecOps Concepts

### 1. What is DevSecOps and how does it differ from DevOps?

**Answer:**
DevSecOps integrates security practices within the DevOps process, making security a shared responsibility throughout the software development lifecycle.

**Key Differences:**

| Aspect | DevOps | DevSecOps |
|--------|--------|-----------|
| **Security Focus** | Security as afterthought | Security integrated throughout |
| **Responsibility** | Dev + Ops teams | Dev + Sec + Ops teams |
| **Testing** | Functional and performance | Includes security testing |
| **Deployment** | Fast deployment | Secure and fast deployment |
| **Culture** | Collaboration between dev/ops | Security-first culture |

**Core Principles:**
- **Shift Left Security**: Security testing early in development
- **Automation**: Automated security testing and compliance
- **Collaboration**: Security as shared responsibility
- **Continuous Monitoring**: Ongoing security assessment
- **Compliance as Code**: Automated compliance checking

### 2. What is "Shift Left" security?

**Answer:**
Shift Left security means integrating security practices earlier in the software development lifecycle rather than at the end.

**Traditional Approach:**
```
Plan → Code → Build → Test → Deploy → [Security Testing] → Production
```

**Shift Left Approach:**
```
[Security] Plan → [Security] Code → [Security] Build → [Security] Test → [Security] Deploy → Production
```

**Implementation Strategies:**
- **IDE Integration**: Security plugins in development environments
- **Pre-commit Hooks**: Security checks before code commits
- **CI/CD Pipeline**: Automated security testing in build process
- **Developer Training**: Security awareness and secure coding practices

**Benefits:**
- **Cost Reduction**: 30x cheaper to fix vulnerabilities in development vs. production
- **Faster Remediation**: Developers fix issues while context is fresh
- **Improved Quality**: Fewer security issues reach production
- **Cultural Change**: Security becomes part of development workflow

### 3. What are the main components of a DevSecOps pipeline?

**Answer:**

**1. Planning & Design:**
- **Threat Modeling**: Identify potential security threats
- **Security Requirements**: Define security acceptance criteria
- **Risk Assessment**: Evaluate and prioritize security risks

**2. Development:**
- **Secure Coding**: Follow secure coding guidelines
- **IDE Security Plugins**: Real-time vulnerability detection
- **Peer Reviews**: Security-focused code reviews

**3. Source Code Management:**
- **Pre-commit Hooks**: Security checks before commits
- **Branch Protection**: Require security reviews for merges
- **Secrets Management**: Prevent credentials in code

**4. Build & Package:**
- **SAST (Static Application Security Testing)**: Source code analysis
- **Dependency Scanning**: Check for vulnerable dependencies
- **Container Scanning**: Scan container images for vulnerabilities

**5. Testing:**
- **DAST (Dynamic Application Security Testing)**: Runtime security testing
- **IAST (Interactive Application Security Testing)**: Instrumented testing
- **Security Test Cases**: Automated security-specific tests

**6. Deployment:**
- **Infrastructure Security**: Secure configuration management
- **Environment Hardening**: Apply security baselines
- **Compliance Checks**: Automated compliance validation

**7. Production:**
- **Runtime Protection**: RASP (Runtime Application Self-Protection)
- **Monitoring**: Security incident detection and response
- **Continuous Compliance**: Ongoing compliance monitoring

### 4. What is the principle of "Security as Code"?

**Answer:**
Security as Code treats security policies, configurations, and tests as code that can be versioned, tested, and automated.

**Key Components:**

**Policy as Code:**
```yaml
# Example: Open Policy Agent (OPA) policy
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.containers[_].image
    not starts_with(input.request.object.spec.containers[_].image, "approved-registry.com/")
    msg := "Only images from approved registry are allowed"
}
```

**Compliance as Code:**
```yaml
# Example: InSpec compliance test
describe port(443) do
  it { should be_listening }
  its('protocols') { should include 'tcp' }
end

describe ssl(port: 443) do
  its('protocols') { should include 'TLSv1.2' }
  its('ciphers') { should_not include 'RC4' }
end
```

**Security Configuration as Code:**
```yaml
# Example: Terraform security configuration
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
```

**Benefits:**
- **Version Control**: Track security changes over time
- **Automation**: Automated policy enforcement
- **Consistency**: Standardized security configurations
- **Scalability**: Apply security at scale

### 5. What are the OWASP Top 10 and how do they relate to DevSecOps?

**Answer:**
The OWASP Top 10 represents the most critical web application security risks.

**OWASP Top 10 (2021):**

1. **Broken Access Control**: Unauthorized access to resources
2. **Cryptographic Failures**: Weak encryption or exposed sensitive data
3. **Injection**: SQL injection, NoSQL injection, command injection
4. **Insecure Design**: Fundamental security design flaws
5. **Security Misconfiguration**: Improper security settings
6. **Vulnerable and Outdated Components**: Using components with known vulnerabilities
7. **Identification and Authentication Failures**: Weak authentication mechanisms
8. **Software and Data Integrity Failures**: Insecure CI/CD pipelines
9. **Security Logging and Monitoring Failures**: Inadequate logging and monitoring
10. **Server-Side Request Forgery (SSRF)**: Server makes unintended requests

**DevSecOps Integration:**

**Prevention Strategies:**
- **SAST Tools**: Detect injection vulnerabilities in code
- **Dependency Scanning**: Identify vulnerable components
- **Configuration Management**: Prevent misconfigurations
- **Security Testing**: Automated OWASP testing in CI/CD
- **Security Monitoring**: Runtime detection and response

### 6. What is threat modeling and how is it integrated into DevSecOps?

**Answer:**
Threat modeling is a structured approach to identify, quantify, and address security threats in applications.

**STRIDE Model:**
- **Spoofing**: Illegitimate access to authentication information
- **Tampering**: Malicious modification of data
- **Repudiation**: Claims of innocence when action occurred
- **Information Disclosure**: Exposure of sensitive information
- **Denial of Service**: Degrading or denying service
- **Elevation of Privilege**: Gaining unauthorized access

**Process:**
1. **Define Security Objectives**: What needs protection?
2. **Create Application Overview**: Architecture and data flow
3. **Decompose Application**: Break down into components
4. **Identify Threats**: Use STRIDE or PASTA methodology
5. **Document Threats**: Create threat model documentation
6. **Rate Threats**: Prioritize based on risk and impact

**DevSecOps Integration:**
- **Design Phase**: Threat modeling during architecture design
- **Automation**: Automated threat modeling tools
- **Documentation**: Version-controlled threat models
- **Validation**: Security tests based on identified threats

**Tools:**
- **Microsoft Threat Modeling Tool**: Visual threat modeling
- **OWASP Threat Dragon**: Open-source threat modeling
- **Threatspec**: Threat modeling as code

### 7. What is Zero Trust security model?

**Answer:**
Zero Trust is a security model that assumes no trust, regardless of location or previous authentication.

**Core Principles:**
- **Never Trust, Always Verify**: Authenticate and authorize every access
- **Least Privilege Access**: Minimum necessary permissions
- **Assume Breach**: Design assuming attackers are already inside
- **Verify Explicitly**: Use all available data for decisions

**Implementation Components:**

**Identity Verification:**
- **Multi-Factor Authentication (MFA)**: Multiple authentication factors
- **Continuous Authentication**: Ongoing user verification
- **Risk-Based Authentication**: Adaptive authentication based on risk

**Device Security:**
- **Device Compliance**: Ensure devices meet security standards
- **Endpoint Detection**: Monitor device behavior
- **Device Certificates**: Certificate-based device authentication

**Network Security:**
- **Micro-Segmentation**: Isolate network segments
- **Software-Defined Perimeter**: Application-specific access
- **Encrypted Traffic**: All traffic encrypted

**Application Security:**
- **Application-Level Controls**: Per-application access controls
- **API Security**: Secure API access and monitoring
- **Runtime Protection**: Application behavior monitoring

### 8. What is Security Orchestration, Automation, and Response (SOAR)?

**Answer:**
SOAR platforms help security teams manage and respond to security incidents through automation and orchestration.

**Key Capabilities:**

**Security Orchestration:**
- **Workflow Automation**: Predefined incident response workflows
- **Tool Integration**: Connect disparate security tools
- **Process Standardization**: Consistent incident handling

**Security Automation:**
- **Automated Response**: Immediate actions for known threats
- **Data Enrichment**: Automatic threat intelligence gathering
- **Ticket Management**: Automated incident ticket creation

**Security Response:**
- **Incident Management**: Track and manage security incidents
- **Playbooks**: Predefined response procedures
- **Collaboration**: Team coordination during incidents

**SOAR in DevSecOps:**
- **CI/CD Integration**: Automated security responses in pipelines
- **Infrastructure Response**: Automated infrastructure protection
- **Compliance Automation**: Automated compliance reporting
- **Metrics Collection**: Security metrics for continuous improvement

**Popular SOAR Platforms:**
- **Phantom (Splunk)**: Enterprise SOAR platform
- **Demisto (Palo Alto)**: Security orchestration platform
- **IBM Resilient**: Incident response platform
- **Microsoft Sentinel**: Cloud-native SIEM and SOAR

### 9. What are security metrics and KPIs in DevSecOps?

**Answer:**
Security metrics provide quantitative measures of security posture and DevSecOps effectiveness.

**Leading Indicators (Preventive):**
- **Security Training Completion Rate**: % of developers trained
- **Secure Code Review Coverage**: % of code reviewed for security
- **Security Test Coverage**: % of applications with security tests
- **Policy Compliance Rate**: % of systems meeting security policies

**Lagging Indicators (Detective):**
- **Vulnerability Count**: Number of vulnerabilities found
- **Mean Time to Detection (MTTD)**: Time to detect security incidents
- **Mean Time to Response (MTTR)**: Time to respond to incidents
- **Security Incident Frequency**: Number of security incidents

**DevSecOps-Specific Metrics:**
- **Deployment Frequency with Security**: Secure deployments per time period
- **Lead Time for Security Fixes**: Time from vulnerability discovery to fix
- **Change Failure Rate (Security)**: % of deployments causing security issues
- **Security Debt**: Number of known but unresolved security issues

**Implementation Example:**
```yaml
# Security metrics collection
metrics:
  sast_scan_duration: "5 minutes"
  vulnerabilities_found: 12
  critical_vulnerabilities: 2
  security_tests_passed: 95%
  compliance_score: 87%
```

### 10. What is the difference between DevSecOps and SecOps?

**Answer:**

| Aspect | DevSecOps | SecOps |
|--------|-----------|---------|
| **Focus** | Integration throughout SDLC | Operations and incident response |
| **Scope** | Development to production | Production security operations |
| **Team Structure** | Dev + Sec + Ops integration | Dedicated security operations team |
| **Primary Goal** | Secure software delivery | Security monitoring and response |
| **Tools** | SAST, DAST, container scanning | SIEM, SOAR, threat hunting tools |
| **Mindset** | Prevention and early detection | Detection and response |

**DevSecOps Responsibilities:**
- Secure coding practices
- Security testing automation
- Compliance as code
- Secure infrastructure deployment
- Security training for developers

**SecOps Responsibilities:**
- Security monitoring
- Incident response
- Threat hunting
- Forensic analysis
- Security operations center (SOC) management

**Overlap Areas:**
- Security tooling and platforms
- Vulnerability management
- Security metrics and reporting
- Security policy enforcement
- Risk assessment and management

Both approaches are complementary and often work together in mature organizations to provide comprehensive security coverage from development through production operations.