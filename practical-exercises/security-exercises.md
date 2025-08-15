# Security Exercises 🛡️

Practical hands-on exercises for implementing security controls, testing, and compliance in DevOps environments.

## 📋 Exercise Categories

- [🔐 Identity and Access Management](#identity-and-access-management) - IAM, RBAC, and authentication
- [🛡️ Infrastructure Security](#infrastructure-security) - Network security and hardening
- [🔒 Application Security](#application-security) - SAST, DAST, and secure coding
- [📊 Security Monitoring](#security-monitoring) - SIEM, logging, and incident response
- [📋 Compliance and Governance](#compliance-and-governance) - SOC2, ISO27001, and policy management
- [🚨 Incident Response](#incident-response) - Security incident handling and forensics

---

## Identity and Access Management

### Exercise 1: Zero Trust IAM Implementation

**Objective**: Implement a Zero Trust Identity and Access Management system across multi-cloud environments

**Requirements**:
- Set up HashiCorp Vault for secrets management
- Implement RBAC with dynamic credentials
- Configure multi-factor authentication (MFA)
- Set up just-in-time (JIT) access
- Implement policy-as-code for access controls

**Time Limit**: 6 hours

**Deliverables**:

```hcl
# vault-config.tf
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "vault" {
  address = var.vault_address
  token   = var.vault_token
}

# Enable AWS secrets engine
resource "vault_aws_secret_backend" "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
  region     = var.aws_region

  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 7200
}

# AWS role for developers
resource "vault_aws_secret_backend_role" "developer" {
  backend = vault_aws_secret_backend.aws.path
  name    = "developer-role"
  
  credential_type = "iam_user"
  
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "s3:ListBucket",
          "s3:GetObject"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = ["us-east-1", "us-west-2"]
          }
          DateGreaterThan = {
            "aws:CurrentTime" = "08:00:00Z"
          }
          DateLessThan = {
            "aws:CurrentTime" = "18:00:00Z"
          }
        }
      }
    ]
  })
}

# Policy for developer access
resource "vault_policy" "developer_policy" {
  name = "developer-policy"

  policy = <<EOT
# Allow developers to get AWS credentials
path "aws/creds/developer-role" {
  capabilities = ["read"]
}

# Allow developers to read their own secrets
path "secret/data/developers/{{identity.entity.name}}/*" {
  capabilities = ["read", "update"]
}

# Allow reading common secrets
path "secret/data/common/*" {
  capabilities = ["read"]
}

# Deny access to production secrets
path "secret/data/production/*" {
  capabilities = ["deny"]
}
EOT
}

# OIDC auth method for SSO
resource "vault_jwt_auth_backend" "oidc" {
  description  = "OIDC auth backend"
  path         = "oidc"
  type         = "oidc"
  
  oidc_discovery_url = "https://auth.company.com"
  oidc_client_id     = var.oidc_client_id
  oidc_client_secret = var.oidc_client_secret
  
  default_role = "developer"
}

# OIDC role configuration
resource "vault_jwt_auth_backend_role" "developer" {
  backend         = vault_jwt_auth_backend.oidc.path
  role_name       = "developer"
  token_policies  = [vault_policy.developer_policy.name]
  
  bound_audiences = [var.oidc_client_id]
  bound_claims = {
    groups = ["developers", "engineers"]
  }
  
  user_claim      = "email"
  role_type       = "oidc"
  token_ttl       = 3600
  token_max_ttl   = 7200
}

# Enable KV v2 secrets engine
resource "vault_mount" "secret" {
  path        = "secret"
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}
```

```python
# access-request-system.py
import hvac
import jwt
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

class JITAccessManager:
    def __init__(self, vault_url, vault_token):
        self.vault_client = hvac.Client(url=vault_url, token=vault_token)
        self.access_requests = {}
        
    def request_access(self, user_id, resource, duration_hours=1, justification=""):
        """Request just-in-time access to a resource"""
        
        request_id = f"{user_id}_{resource}_{int(time.time())}"
        
        access_request = {
            'id': request_id,
            'user_id': user_id,
            'resource': resource,
            'duration_hours': duration_hours,
            'justification': justification,
            'status': 'pending',
            'requested_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(hours=duration_hours)
        }
        
        self.access_requests[request_id] = access_request
        
        # Auto-approve low-risk requests
        if self._is_auto_approvable(resource, duration_hours):
            return self.approve_access(request_id, "system", "Auto-approved")
        
        return {
            'request_id': request_id,
            'status': 'pending_approval',
            'message': 'Access request submitted for approval'
        }
    
    def approve_access(self, request_id, approver_id, approval_reason=""):
        """Approve and grant access"""
        
        if request_id not in self.access_requests:
            return {'error': 'Access request not found'}
        
        request = self.access_requests[request_id]
        
        if request['status'] != 'pending':
            return {'error': 'Request already processed'}
        
        # Create temporary policy
        policy_name = f"temp_access_{request_id}"
        policy_content = self._generate_temporary_policy(request['resource'])
        
        self.vault_client.sys.create_or_update_policy(
            name=policy_name,
            policy=policy_content
        )
        
        # Create temporary token
        token_response = self.vault_client.auth.token.create(
            policies=[policy_name],
            ttl=f"{request['duration_hours']}h",
            renewable=False,
            meta={
                'user_id': request['user_id'],
                'resource': request['resource'],
                'request_id': request_id
            }
        )
        
        request['status'] = 'approved'
        request['approved_by'] = approver_id
        request['approved_at'] = datetime.utcnow()
        request['temp_token'] = token_response['auth']['client_token']
        request['approval_reason'] = approval_reason
        
        # Schedule cleanup
        self._schedule_cleanup(request_id, request['duration_hours'])
        
        return {
            'request_id': request_id,
            'status': 'approved',
            'temp_token': token_response['auth']['client_token'],
            'expires_at': request['expires_at'].isoformat()
        }
    
    def _is_auto_approvable(self, resource, duration_hours):
        """Determine if request can be auto-approved"""
        auto_approve_resources = [
            'development/*',
            'staging/read-only/*',
            'logs/read/*'
        ]
        
        return (duration_hours <= 4 and 
                any(resource.startswith(pattern.replace('*', '')) 
                    for pattern in auto_approve_resources))
    
    def _generate_temporary_policy(self, resource):
        """Generate temporary Vault policy for resource access"""
        return f'''
path "{resource}" {{
  capabilities = ["read", "list"]
}}

path "auth/token/lookup-self" {{
  capabilities = ["read"]
}}

path "auth/token/renew-self" {{
  capabilities = ["update"]
}}
'''
    
    def _schedule_cleanup(self, request_id, duration_hours):
        """Schedule cleanup of temporary access"""
        # In production, use a proper task queue like Celery
        import threading
        
        def cleanup():
            time.sleep(duration_hours * 3600)
            self._cleanup_access(request_id)
        
        cleanup_thread = threading.Thread(target=cleanup)
        cleanup_thread.daemon = True
        cleanup_thread.start()
    
    def _cleanup_access(self, request_id):
        """Clean up temporary access"""
        if request_id in self.access_requests:
            request = self.access_requests[request_id]
            
            # Revoke token
            try:
                self.vault_client.auth.token.revoke(
                    token=request['temp_token']
                )
            except Exception as e:
                logging.error(f"Failed to revoke token: {e}")
            
            # Delete temporary policy
            policy_name = f"temp_access_{request_id}"
            try:
                self.vault_client.sys.delete_policy(name=policy_name)
            except Exception as e:
                logging.error(f"Failed to delete policy: {e}")
            
            request['status'] = 'expired'
            request['cleaned_up_at'] = datetime.utcnow()

# Flask API endpoints
jit_manager = JITAccessManager(
    vault_url="https://vault.company.com",
    vault_token="your-vault-token"
)

@app.route('/access/request', methods=['POST'])
def request_access():
    data = request.json
    
    result = jit_manager.request_access(
        user_id=data['user_id'],
        resource=data['resource'],
        duration_hours=data.get('duration_hours', 1),
        justification=data.get('justification', '')
    )
    
    return jsonify(result)

@app.route('/access/approve/<request_id>', methods=['POST'])
def approve_access(request_id):
    data = request.json
    
    result = jit_manager.approve_access(
        request_id=request_id,
        approver_id=data['approver_id'],
        approval_reason=data.get('reason', '')
    )
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
```

```yaml
# rbac-policies.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: developer-role
rules:
# Allow developers to read most resources
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
# Allow developers to access logs
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get", "list"]
# Deny access to production namespace
- apiGroups: [""]
  resources: ["*"]
  resourceNames: ["production"]
  verbs: ["*"]
  
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sre-role
rules:
# Full access to monitoring and logging
- apiGroups: [""]
  resources: ["*"]
  verbs: ["*"]
- apiGroups: ["apps", "extensions"]
  resources: ["*"]
  verbs: ["*"]
# Limited production access
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch", "update", "patch"]
  resourceNames: ["production"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: developers-binding
subjects:
- kind: User
  name: developer@company.com
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: developers
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: developer-role
  apiGroup: rbac.authorization.k8s.io
```

**Expected Outcomes**:
- Vault cluster deployed and configured
- Dynamic AWS credentials generation
- RBAC policies implemented
- JIT access system functional
- MFA enforcement configured

**Evaluation Criteria**:
- Security policy effectiveness
- Access control granularity
- Audit trail completeness
- User experience quality
- Compliance adherence

---

## Infrastructure Security

### Exercise 2: Network Security and Micro-segmentation

**Objective**: Implement comprehensive network security controls with micro-segmentation

**Requirements**:
- Configure network segmentation with VPCs/VNets
- Implement security groups and NACLs
- Set up Web Application Firewall (WAF)
- Configure VPN and private connectivity
- Implement network monitoring and intrusion detection

**Time Limit**: 6 hours

**Deliverables**:

```hcl
# network-security.tf
# VPC with multiple security zones
resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "secure-vpc"
    SecurityZone = "enterprise"
  }
}

# DMZ Subnet for public-facing resources
resource "aws_subnet" "dmz" {
  count             = 2
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  map_public_ip_on_launch = true

  tags = {
    Name = "dmz-subnet-${count.index + 1}"
    SecurityZone = "dmz"
  }
}

# Application subnet (private)
resource "aws_subnet" "application" {
  count             = 2
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "app-subnet-${count.index + 1}"
    SecurityZone = "application"
  }
}

# Database subnet (isolated)
resource "aws_subnet" "database" {
  count             = 2
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.${count.index + 20}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "db-subnet-${count.index + 1}"
    SecurityZone = "database"
  }
}

# Security Groups
resource "aws_security_group" "web_tier" {
  name_prefix = "web-tier-sg"
  vpc_id      = aws_vpc.secure_vpc.id

  # HTTPS inbound from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  # HTTP redirect
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP redirect to HTTPS"
  }

  # Outbound to application tier only
  egress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    description     = "To application tier"
  }

  tags = {
    Name = "web-tier-security-group"
  }
}

resource "aws_security_group" "app_tier" {
  name_prefix = "app-tier-sg"
  vpc_id      = aws_vpc.secure_vpc.id

  # Inbound from web tier only
  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
    description     = "From web tier"
  }

  # Outbound to database tier only
  egress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.db_tier.id]
    description     = "To database tier"
  }

  tags = {
    Name = "app-tier-security-group"
  }
}

resource "aws_security_group" "db_tier" {
  name_prefix = "db-tier-sg"
  vpc_id      = aws_vpc.secure_vpc.id

  # Inbound from application tier only
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    description     = "From application tier"
  }

  # No outbound internet access
  tags = {
    Name = "db-tier-security-group"
  }
}

# WAF Configuration
resource "aws_wafv2_web_acl" "main" {
  name  = "security-web-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "rate-limit-rule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }
  }

  # SQL injection protection
  rule {
    name     = "sql-injection-rule"
    priority = 2

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          all_query_arguments {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLInjectionRule"
      sampled_requests_enabled   = true
    }
  }

  # XSS protection
  rule {
    name     = "xss-rule"
    priority = 3

    action {
      block {}
    }

    statement {
      xss_match_statement {
        field_to_match {
          body {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "XSSRule"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name = "security-waf"
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "SecurityWebACL"
    sampled_requests_enabled   = true
  }
}

# Network ACLs for additional security
resource "aws_network_acl" "dmz" {
  vpc_id     = aws_vpc.secure_vpc.id
  subnet_ids = aws_subnet.dmz[*].id

  # Allow HTTPS inbound
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow HTTP inbound
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  # Allow ephemeral ports for responses
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow all outbound
  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "dmz-nacl"
  }
}
```

```python
# network-security-monitor.py
import boto3
import json
import time
from datetime import datetime, timedelta
import logging

class NetworkSecurityMonitor:
    def __init__(self):
        self.ec2 = boto3.client('ec2')
        self.cloudwatch = boto3.client('cloudwatch')
        self.sns = boto3.client('sns')
        
    def monitor_security_groups(self):
        """Monitor security group changes and violations"""
        
        # Get all security groups
        response = self.ec2.describe_security_groups()
        
        violations = []
        
        for sg in response['SecurityGroups']:
            # Check for overly permissive rules
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Check if it's a dangerous port
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 0)
                        
                        if self._is_dangerous_port(from_port, to_port):
                            violations.append({
                                'type': 'overly_permissive_sg',
                                'security_group_id': sg['GroupId'],
                                'rule': rule,
                                'severity': 'high'
                            })
        
        return violations
    
    def _is_dangerous_port(self, from_port, to_port):
        """Check if port range includes dangerous ports"""
        dangerous_ports = [22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432]
        
        for port in dangerous_ports:
            if from_port <= port <= to_port:
                return True
        return False
    
    def monitor_vpc_flow_logs(self):
        """Analyze VPC flow logs for suspicious activity"""
        
        # Query CloudWatch Logs for VPC flow logs
        logs_client = boto3.client('logs')
        
        # Define suspicious patterns
        suspicious_patterns = [
            'REJECT',  # Rejected connections
            ':22 ',    # SSH attempts
            ':3389 ',  # RDP attempts
            ':1433 ',  # SQL Server attempts
        ]
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        for pattern in suspicious_patterns:
            try:
                response = logs_client.start_query(
                    logGroupName='vpc-flow-logs',
                    startTime=int(start_time.timestamp()),
                    endTime=int(end_time.timestamp()),
                    queryString=f'''
                        fields @timestamp, srcaddr, dstaddr, srcport, dstport, action
                        | filter @message like /{pattern}/
                        | stats count() by srcaddr
                        | sort count desc
                        | limit 20
                    '''
                )
                
                query_id = response['queryId']
                
                # Wait for query to complete
                time.sleep(10)
                
                results = logs_client.get_query_results(queryId=query_id)
                
                if results['results']:
                    self._alert_suspicious_activity(pattern, results['results'])
                    
            except Exception as e:
                logging.error(f"Error querying flow logs: {e}")
    
    def _alert_suspicious_activity(self, pattern, results):
        """Send alert for suspicious network activity"""
        
        message = f"""
        Suspicious network activity detected:
        Pattern: {pattern}
        
        Top source IPs:
        """
        
        for result in results[:5]:
            src_ip = result[0]['value']
            count = result[1]['value']
            message += f"\n{src_ip}: {count} attempts"
        
        # Send SNS notification
        self.sns.publish(
            TopicArn='arn:aws:sns:region:account:security-alerts',
            Message=message,
            Subject=f'Network Security Alert: {pattern}'
        )
    
    def check_network_compliance(self):
        """Check network configuration against compliance rules"""
        
        compliance_checks = []
        
        # Check VPC flow logs are enabled
        vpcs = self.ec2.describe_vpcs()['Vpcs']
        
        for vpc in vpcs:
            vpc_id = vpc['VpcId']
            
            # Check if flow logs are enabled
            flow_logs = self.ec2.describe_flow_logs(
                Filter=[
                    {
                        'Name': 'resource-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            
            if not flow_logs['FlowLogs']:
                compliance_checks.append({
                    'check': 'vpc_flow_logs',
                    'status': 'fail',
                    'resource': vpc_id,
                    'message': 'VPC flow logs not enabled'
                })
            else:
                compliance_checks.append({
                    'check': 'vpc_flow_logs',
                    'status': 'pass',
                    'resource': vpc_id,
                    'message': 'VPC flow logs enabled'
                })
        
        return compliance_checks

if __name__ == "__main__":
    monitor = NetworkSecurityMonitor()
    
    # Run security checks
    violations = monitor.monitor_security_groups()
    compliance_results = monitor.check_network_compliance()
    
    print("Security Group Violations:", violations)
    print("Compliance Results:", compliance_results)
    
    # Monitor flow logs
    monitor.monitor_vpc_flow_logs()
```

---

## Application Security

### Exercise 3: Secure CI/CD Pipeline with SAST/DAST

**Objective**: Implement comprehensive security testing in CI/CD pipeline

**Requirements**:
- Integrate SAST (Static Application Security Testing)
- Implement DAST (Dynamic Application Security Testing)
- Set up dependency vulnerability scanning
- Configure security gates and policies
- Implement security reporting and metrics

**Time Limit**: 6 hours

**Deliverables**:

```yaml
# .github/workflows/secure-cicd.yml
name: Secure CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      with:
        fetch-depth: 0

    # SAST - Static Application Security Testing
    - name: Run Semgrep SAST
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/owasp-top-ten
          p/cwe-top-25
        generateSarif: "1"
      env:
        SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}

    - name: Upload Semgrep results to GitHub
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: semgrep.sarif

    # Secret scanning
    - name: Run secret detection
      uses: trufflesecurity/trufflehog@main
      with:
        path: ./
        base: main
        head: HEAD

    # Dependency vulnerability scanning
    - name: Run dependency check
      uses: dependency-check/Dependency-Check_Action@main
      with:
        project: 'secure-app'
        path: '.'
        format: 'ALL'
        args: >
          --enableRetired
          --enableExperimental

    - name: Upload dependency check results
      uses: actions/upload-artifact@v3
      with:
        name: dependency-check-report
        path: reports/

    # License compliance check
    - name: FOSSA Scan
      uses: fossas/fossa-action@main
      with:
        api-key: ${{ secrets.FOSSA_API_KEY }}

  build-and-test:
    needs: security-scan
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install dependencies
      run: npm ci

    - name: Run unit tests
      run: npm test

    - name: Run integration tests
      run: npm run test:integration

    - name: Build application
      run: npm run build

    # Container security scanning
    - name: Build Docker image
      run: |
        docker build -t ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} .

    - name: Scan container image with Trivy
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
        format: 'sarif'
        output: 'trivy-results.sarif'

    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

    # Image signing
    - name: Install Cosign
      uses: sigstore/cosign-installer@v3

    - name: Sign container image
      run: |
        cosign sign --yes ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
      env:
        COSIGN_EXPERIMENTAL: 1

  deploy-staging:
    needs: build-and-test
    runs-on: ubuntu-latest
    environment: staging
    
    steps:
    - name: Deploy to staging
      run: |
        echo "Deploying to staging environment"
        # kubectl apply -f k8s/staging/

    # DAST - Dynamic Application Security Testing
    - name: Wait for deployment
      run: sleep 60

    - name: Run OWASP ZAP DAST scan
      uses: zaproxy/action-full-scan@v0.4.0
      with:
        target: 'https://staging.myapp.com'
        rules_file_name: '.zap/rules.tsv'
        cmd_options: '-a'

    - name: Upload ZAP scan results
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: zap-report
        path: report_html.html

    # Performance security testing
    - name: Run performance security test
      run: |
        docker run --rm -v $(pwd):/workspace \
          owasp/zap2docker-stable zap-baseline.py \
          -t https://staging.myapp.com \
          -J zap-report.json

  security-gate:
    needs: [security-scan, deploy-staging]
    runs-on: ubuntu-latest
    
    steps:
    - name: Download security reports
      uses: actions/download-artifact@v3

    - name: Security gate evaluation
      run: |
        python scripts/security-gate.py \
          --sast-report semgrep.sarif \
          --dependency-report dependency-check-report.xml \
          --container-report trivy-results.sarif \
          --dast-report zap-report.json

  deploy-production:
    needs: security-gate
    runs-on: ubuntu-latest
    environment: production
    if: github.ref == 'refs/heads/main'
    
    steps:
    - name: Deploy to production
      run: |
        echo "Deploying to production environment"
        # kubectl apply -f k8s/production/
```

```python
# scripts/security-gate.py
import json
import sys
import argparse
from pathlib import Path

class SecurityGate:
    def __init__(self):
        self.findings = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        self.policy = {
            'critical': 0,  # No critical vulnerabilities allowed
            'high': 2,      # Maximum 2 high vulnerabilities
            'medium': 10,   # Maximum 10 medium vulnerabilities
            'block_on_secrets': True,  # Block if secrets found
            'license_compliance': True  # Require license compliance
        }
    
    def analyze_sast_report(self, report_path):
        """Analyze SAST SARIF report"""
        try:
            with open(report_path, 'r') as f:
                sarif = json.load(f)
            
            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    level = result.get('level', 'info')
                    rule_id = result.get('ruleId', '')
                    
                    # Map SARIF levels to severity
                    if level == 'error':
                        severity = 'high'
                    elif level == 'warning':
                        severity = 'medium'
                    else:
                        severity = 'low'
                    
                    # Check for secrets
                    if 'secret' in rule_id.lower() or 'password' in rule_id.lower():
                        severity = 'critical'
                    
                    self.findings[severity] += 1
                    
        except Exception as e:
            print(f"Error analyzing SAST report: {e}")
            return False
        
        return True
    
    def analyze_dependency_report(self, report_path):
        """Analyze dependency vulnerability report"""
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            
            for dependency in report.get('dependencies', []):
                for vulnerability in dependency.get('vulnerabilities', []):
                    severity = vulnerability.get('severity', 'low').lower()
                    self.findings[severity] += 1
                    
        except Exception as e:
            print(f"Error analyzing dependency report: {e}")
            return False
        
        return True
    
    def analyze_container_report(self, report_path):
        """Analyze container vulnerability report"""
        try:
            with open(report_path, 'r') as f:
                sarif = json.load(f)
            
            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    properties = result.get('properties', {})
                    severity = properties.get('security-severity', '0.0')
                    
                    # Convert CVSS score to severity
                    score = float(severity)
                    if score >= 9.0:
                        self.findings['critical'] += 1
                    elif score >= 7.0:
                        self.findings['high'] += 1
                    elif score >= 4.0:
                        self.findings['medium'] += 1
                    else:
                        self.findings['low'] += 1
                        
        except Exception as e:
            print(f"Error analyzing container report: {e}")
            return False
        
        return True
    
    def analyze_dast_report(self, report_path):
        """Analyze DAST report"""
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
            
            for alert in report.get('site', [{}])[0].get('alerts', []):
                risk = alert.get('riskcode', '0')
                
                # Map ZAP risk codes to severity
                risk_mapping = {
                    '3': 'high',
                    '2': 'medium',
                    '1': 'low',
                    '0': 'info'
                }
                
                severity = risk_mapping.get(risk, 'info')
                self.findings[severity] += 1
                
        except Exception as e:
            print(f"Error analyzing DAST report: {e}")
            return False
        
        return True
    
    def evaluate_policy(self):
        """Evaluate findings against security policy"""
        violations = []
        
        # Check severity thresholds
        for severity, threshold in self.policy.items():
            if severity in self.findings and self.findings[severity] > threshold:
                violations.append(
                    f"{severity.upper()}: {self.findings[severity]} found, "
                    f"threshold is {threshold}"
                )
        
        return violations
    
    def generate_report(self):
        """Generate security gate report"""
        print("\n=== Security Gate Report ===")
        print(f"Critical: {self.findings['critical']}")
        print(f"High: {self.findings['high']}")
        print(f"Medium: {self.findings['medium']}")
        print(f"Low: {self.findings['low']}")
        print(f"Info: {self.findings['info']}")
        
        violations = self.evaluate_policy()
        
        if violations:
            print("\n❌ SECURITY GATE FAILED")
            print("Policy violations:")
            for violation in violations:
                print(f"  • {violation}")
            return False
        else:
            print("\n✅ SECURITY GATE PASSED")
            return True

def main():
    parser = argparse.ArgumentParser(description='Security Gate Evaluation')
    parser.add_argument('--sast-report', help='SAST SARIF report path')
    parser.add_argument('--dependency-report', help='Dependency check report path')
    parser.add_argument('--container-report', help='Container scan SARIF report path')
    parser.add_argument('--dast-report', help='DAST JSON report path')
    
    args = parser.parse_args()
    
    gate = SecurityGate()
    
    # Analyze all provided reports
    if args.sast_report and Path(args.sast_report).exists():
        gate.analyze_sast_report(args.sast_report)
    
    if args.dependency_report and Path(args.dependency_report).exists():
        gate.analyze_dependency_report(args.dependency_report)
    
    if args.container_report and Path(args.container_report).exists():
        gate.analyze_container_report(args.container_report)
    
    if args.dast_report and Path(args.dast_report).exists():
        gate.analyze_dast_report(args.dast_report)
    
    # Evaluate and report
    success = gate.generate_report()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

```dockerfile
# Multi-stage secure Dockerfile
FROM node:18-alpine AS builder

# Create app directory
WORKDIR /usr/src/app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Security: Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodeapp -u 1001

# Install security updates
RUN apk update && apk upgrade

# Set working directory
WORKDIR /usr/src/app

# Copy built application
COPY --from=builder --chown=nodeapp:nodejs /usr/src/app/dist ./dist
COPY --from=builder --chown=nodeapp:nodejs /usr/src/app/node_modules ./node_modules
COPY --from=builder --chown=nodeapp:nodejs /usr/src/app/package*.json ./

# Security: Remove package manager
RUN apk del apk-tools

# Security: Set proper permissions
RUN chmod -R 755 /usr/src/app

# Switch to non-root user
USER nodeapp

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node dist/health-check.js

# Start application
CMD ["node", "dist/index.js"]
```

---

## Security Monitoring

### Exercise 4: SIEM and Security Analytics Implementation

**Objective**: Implement comprehensive security monitoring and incident detection

**Requirements**:
- Set up centralized logging with ELK stack
- Configure security event correlation
- Implement real-time threat detection
- Create security dashboards and alerting
- Set up automated incident response

**Time Limit**: 8 hours

**Expected Outcomes**:
- ELK stack deployed and configured
- Security event correlation rules
- Real-time threat detection alerts
- Security operations dashboard
- Automated response playbooks

---

## Compliance and Governance

### Exercise 5: SOC2 Compliance Implementation

**Objective**: Implement SOC2 Type II compliance controls and monitoring

**Requirements**:
- Implement access controls and monitoring
- Set up audit logging and retention
- Configure change management processes
- Implement data protection controls
- Create compliance reporting automation

**Expected Outcomes**:
- SOC2 control implementation
- Audit trail automation
- Compliance monitoring dashboard
- Policy enforcement automation
- Regular compliance reports

---

## Incident Response

### Exercise 6: Security Incident Response Automation

**Objective**: Create automated security incident response system

**Requirements**:
- Implement incident detection and classification
- Set up automated containment procedures
- Configure notification and escalation
- Create forensics data collection
- Implement recovery procedures

**Expected Outcomes**:
- Incident response automation
- Forensics data collection
- Automated containment
- Communication workflows
- Recovery procedures

---

## 🎯 Interview Tips

### Security Questions You Should Be Able to Answer:

1. **How would you implement Zero Trust architecture in a cloud environment?**
2. **Explain the difference between SAST, DAST, and IAST security testing**
3. **How do you secure CI/CD pipelines against supply chain attacks?**
4. **What are the key components of a security incident response plan?**
5. **How would you implement compliance monitoring for SOC2/ISO27001?**

### Practical Demonstrations:

1. **Live Security Scanning**: Demonstrate SAST/DAST tools in action
2. **Incident Response**: Walk through incident handling procedures
3. **Compliance Auditing**: Show compliance checking and reporting
4. **Security Architecture**: Design secure cloud architectures

---

## 📚 Additional Resources

- [OWASP Application Security](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Security Controls](https://www.cisecurity.org/controls)
- [SANS Security Training](https://www.sans.org/)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)