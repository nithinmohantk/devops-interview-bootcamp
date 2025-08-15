# Cloud Security Best Practices and Compliance 🛡️

## Cloud Security Fundamentals

### 1. What is the shared responsibility model in cloud security?

**Answer:**

**Shared Responsibility Model:**

```mermaid
graph TB
    subgraph "Customer Responsibility"
        Apps[Applications & Data]
        OS[Operating System]
        Network[Network Controls]
        Firewall[Host-based Firewall]
        Identity[Identity & Access Management]
    end
    
    subgraph "Shared Controls"
        Patch[Patch Management]
        Config[Configuration Management]
        Training[Training & Awareness]
    end
    
    subgraph "Cloud Provider Responsibility"
        Physical[Physical Security]
        Hardware[Hardware Infrastructure]
        Hypervisor[Hypervisor]
        Networking[Network Infrastructure]
        Facilities[Data Centers]
    end
    
    Apps --> Patch
    OS --> Config
    Network --> Training
    
    style Apps fill:#ff5722
    style Physical fill:#4caf50
    style Patch fill:#ff9800
```

**Responsibility by Service Model:**
```yaml
responsibility_matrix:
  iaas:
    customer:
      - "Guest OS patches and updates"
      - "Application configuration"
      - "Data encryption"
      - "Network controls (firewall, VPN)"
      - "Identity and access management"
    
    provider:
      - "Physical infrastructure"
      - "Host OS patches"
      - "Hypervisor security"
      - "Network infrastructure"
      - "Storage encryption at rest"
  
  paas:
    customer:
      - "Application code security"
      - "Data protection"
      - "User access management"
      - "Application-level encryption"
    
    provider:
      - "Platform security"
      - "Runtime environment"
      - "OS and middleware patches"
      - "Infrastructure security"
  
  saas:
    customer:
      - "User access management"
      - "Data classification"
      - "Endpoint protection"
    
    provider:
      - "Application security"
      - "Infrastructure security"
      - "Platform maintenance"
      - "Data center security"
```

### 2. What are the core principles of cloud security?

**Answer:**

**The 6 Pillars of Cloud Security:**

**1. Identity and Access Management (IAM):**
```yaml
iam_principles:
  principle_of_least_privilege:
    - "Grant minimum required permissions"
    - "Regular access reviews"
    - "Time-bound access for elevated privileges"
  
  strong_authentication:
    - "Multi-factor authentication (MFA)"
    - "Strong password policies"
    - "Passwordless authentication where possible"
  
  centralized_identity:
    - "Single sign-on (SSO)"
    - "Federated identity management"
    - "Directory integration"
```

**2. Data Protection:**
```yaml
data_protection:
  encryption:
    at_rest: "AES-256 encryption for stored data"
    in_transit: "TLS 1.3 for data movement"
    in_use: "Application-level encryption"
  
  classification:
    - "Public, Internal, Confidential, Restricted"
    - "Data loss prevention (DLP)"
    - "Automated classification tools"
  
  backup_and_recovery:
    - "Regular automated backups"
    - "Cross-region replication"
    - "Disaster recovery testing"
```

**3. Network Security:**
```yaml
network_security:
  defense_in_depth:
    - "Multiple security layers"
    - "Micro-segmentation"
    - "Zero-trust architecture"
  
  monitoring:
    - "Network traffic analysis"
    - "Intrusion detection/prevention"
    - "Security information and event management (SIEM)"
```

### 3. How do you implement Zero Trust in the cloud?

**Answer:**

**Zero Trust Architecture:**

```mermaid
graph TB
    subgraph "Zero Trust Components"
        Identity[Identity Verification]
        Device[Device Trust]
        Network[Network Segmentation]
        Application[Application Security]
        Data[Data Protection]
    end
    
    subgraph "Policy Engine"
        PAP[Policy Administration Point]
        PDP[Policy Decision Point]
        PEP[Policy Enforcement Point]
    end
    
    subgraph "Trust Assessment"
        Risk[Risk Assessment]
        Context[Contextual Analysis]
        Adaptive[Adaptive Authentication]
    end
    
    Identity --> PAP
    Device --> PDP
    Network --> PEP
    Application --> Risk
    Data --> Context
    
    PAP --> Risk
    PDP --> Context
    PEP --> Adaptive
    
    style Identity fill:#4caf50
    style PAP fill:#2196f3
    style Risk fill:#ff9800
```

**Zero Trust Implementation:**
```yaml
zero_trust_implementation:
  verify_explicitly:
    - "Always authenticate and authorize"
    - "Use all available data points"
    - "Consider device health and location"
  
  least_privilege_access:
    - "Just-in-time (JIT) access"
    - "Just-enough-access (JEA)"
    - "Risk-based conditional access"
  
  assume_breach:
    - "Minimize blast radius"
    - "Segment access"
    - "Verify end-to-end encryption"
    - "Use analytics for threat detection"
```

**Zero Trust Network Access (ZTNA) Example:**
```python
# Example Zero Trust policy engine
from datetime import datetime, timedelta
import json

class ZeroTrustPolicyEngine:
    def __init__(self):
        self.policies = []
        self.risk_factors = {}
    
    def evaluate_access_request(self, user, resource, context):
        """Evaluate access request based on Zero Trust principles"""
        
        # 1. Verify identity
        identity_score = self.verify_identity(user, context)
        
        # 2. Assess device trust
        device_score = self.assess_device_trust(context.get('device', {}))
        
        # 3. Evaluate network location
        network_score = self.evaluate_network_location(context.get('location', {}))
        
        # 4. Check resource sensitivity
        resource_score = self.get_resource_sensitivity(resource)
        
        # 5. Calculate overall risk score
        risk_score = self.calculate_risk_score(
            identity_score, device_score, network_score, resource_score
        )
        
        # 6. Make access decision
        decision = self.make_access_decision(risk_score, resource)
        
        return {
            'decision': decision['access_granted'],
            'conditions': decision.get('conditions', []),
            'risk_score': risk_score,
            'factors': {
                'identity': identity_score,
                'device': device_score,
                'network': network_score,
                'resource': resource_score
            }
        }
    
    def verify_identity(self, user, context):
        """Verify user identity strength"""
        score = 0
        
        # MFA verification
        if context.get('mfa_verified'):
            score += 40
        
        # Recent authentication
        last_auth = context.get('last_authentication')
        if last_auth and (datetime.now() - last_auth) < timedelta(hours=8):
            score += 30
        
        # User behavior analysis
        if self.is_normal_behavior(user, context):
            score += 30
        
        return min(score, 100)
    
    def assess_device_trust(self, device_info):
        """Assess device trustworthiness"""
        score = 0
        
        # Device compliance
        if device_info.get('compliant'):
            score += 40
        
        # Managed device
        if device_info.get('managed'):
            score += 30
        
        # Updated OS
        if device_info.get('os_updated'):
            score += 20
        
        # Endpoint protection
        if device_info.get('endpoint_protection'):
            score += 10
        
        return min(score, 100)
    
    def evaluate_network_location(self, location_info):
        """Evaluate network location risk"""
        score = 100  # Start with full trust
        
        # Unknown location
        if not location_info.get('known_location'):
            score -= 30
        
        # High-risk country
        if location_info.get('country') in ['high_risk_countries']:
            score -= 40
        
        # VPN usage
        if location_info.get('using_vpn') and not location_info.get('approved_vpn'):
            score -= 20
        
        # Corporate network
        if location_info.get('corporate_network'):
            score = 100
        
        return max(score, 0)
    
    def get_resource_sensitivity(self, resource):
        """Get resource sensitivity level"""
        sensitivity_levels = {
            'public': 0,
            'internal': 25,
            'confidential': 50,
            'restricted': 75,
            'top_secret': 100
        }
        
        return sensitivity_levels.get(resource.get('classification', 'internal'), 25)
    
    def calculate_risk_score(self, identity, device, network, resource):
        """Calculate overall risk score"""
        # Weighted average with resource sensitivity as multiplier
        base_score = (identity * 0.4 + device * 0.3 + network * 0.3)
        risk_multiplier = (100 - resource) / 100
        
        return int(base_score * risk_multiplier)
    
    def make_access_decision(self, risk_score, resource):
        """Make access decision based on risk score"""
        sensitivity = self.get_resource_sensitivity(resource)
        
        if sensitivity >= 75:  # Highly sensitive
            threshold = 80
        elif sensitivity >= 50:  # Moderately sensitive
            threshold = 60
        else:  # Low sensitivity
            threshold = 40
        
        if risk_score >= threshold:
            return {'access_granted': True}
        elif risk_score >= threshold - 20:
            return {
                'access_granted': True,
                'conditions': [
                    'Additional MFA required',
                    'Session monitoring enabled',
                    'Time-limited access (4 hours)'
                ]
            }
        else:
            return {'access_granted': False}
    
    def is_normal_behavior(self, user, context):
        """Analyze user behavior patterns"""
        # Simplified behavior analysis
        # In practice, use ML models for behavior analytics
        
        current_time = datetime.now().hour
        user_patterns = self.get_user_patterns(user)
        
        # Check if access time matches user's typical schedule
        if current_time in user_patterns.get('typical_hours', []):
            return True
        
        # Check if location matches user's typical locations
        location = context.get('location', {}).get('country')
        if location in user_patterns.get('typical_locations', []):
            return True
        
        return False
    
    def get_user_patterns(self, user):
        """Get user's historical behavior patterns"""
        # Placeholder for user behavior data
        return {
            'typical_hours': list(range(8, 18)),  # 8 AM to 6 PM
            'typical_locations': ['US', 'CA'],
            'typical_devices': ['laptop', 'mobile']
        }

# Usage example
zt_engine = ZeroTrustPolicyEngine()

access_request = {
    'user': {'id': 'john.doe@company.com', 'role': 'developer'},
    'resource': {'id': 'prod-database', 'classification': 'confidential'},
    'context': {
        'mfa_verified': True,
        'last_authentication': datetime.now() - timedelta(hours=2),
        'device': {
            'compliant': True,
            'managed': True,
            'os_updated': True,
            'endpoint_protection': True
        },
        'location': {
            'known_location': True,
            'country': 'US',
            'corporate_network': False
        }
    }
}

decision = zt_engine.evaluate_access_request(
    access_request['user'],
    access_request['resource'],
    access_request['context']
)

print(f"Access Decision: {decision}")
```

## Cloud Identity and Access Management

### 4. How do you implement robust IAM in multi-cloud environments?

**Answer:**

**Multi-Cloud IAM Architecture:**

```mermaid
graph TB
    subgraph "Central Identity Provider"
        IDP[Identity Provider]
        UserStore[User Directory]
        Policies[Policy Store]
    end
    
    subgraph "AWS"
        AWSIAM[AWS IAM]
        AWSRoles[IAM Roles]
        AWSSSO[AWS SSO]
    end
    
    subgraph "Azure"
        AzureAD[Azure AD]
        AzureRoles[Azure Roles]
        AzurePriv[Privileged Identity Management]
    end
    
    subgraph "GCP"
        GCPIAM[GCP IAM]
        GCPRoles[IAM Roles]
        GCPWorkload[Workload Identity]
    end
    
    IDP --> AWSSSO
    IDP --> AzureAD
    IDP --> GCPIAM
    
    AWSSSO --> AWSRoles
    AzureAD --> AzureRoles
    GCPIAM --> GCPRoles
    
    UserStore --> IDP
    Policies --> IDP
    
    style IDP fill:#4caf50
    style AWSSSO fill:#ff9800
    style AzureAD fill:#2196f3
    style GCPIAM fill:#9c27b0
```

**IAM Best Practices:**
```yaml
iam_best_practices:
  centralized_identity:
    tools:
      - "Azure Active Directory"
      - "Okta"
      - "Auth0"
      - "Ping Identity"
    
    features:
      - "Single Sign-On (SSO)"
      - "Multi-Factor Authentication (MFA)"
      - "Conditional Access"
      - "Identity Governance"
  
  role_based_access:
    design_principles:
      - "Principle of least privilege"
      - "Separation of duties"
      - "Regular access reviews"
      - "Just-in-time access"
    
    implementation:
      - "Use roles instead of users"
      - "Group-based permissions"
      - "Temporary privilege elevation"
      - "Automated deprovisioning"
  
  privileged_access:
    management:
      - "Privileged Access Management (PAM)"
      - "Break-glass procedures"
      - "Session monitoring"
      - "Approval workflows"
```

**Multi-Cloud IAM Implementation:**
```terraform
# Terraform configuration for multi-cloud IAM
# AWS IAM Role for cross-account access
resource "aws_iam_role" "cross_cloud_role" {
  name = "MultiCloudAccessRole"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
  
  tags = {
    Environment = "production"
    Purpose = "multi-cloud-access"
  }
}

# Azure Service Principal for multi-cloud access
resource "azuread_application" "multi_cloud_app" {
  display_name = "MultiCloudAccessApp"
  
  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
    
    resource_access {
      id   = "e1fe6dd8-ba31-4d61-89e7-88639da4683d" # User.Read
      type = "Scope"
    }
  }
}

resource "azuread_service_principal" "multi_cloud_sp" {
  application_id = azuread_application.multi_cloud_app.application_id
  
  tags = ["multi-cloud", "automation"]
}

# GCP Service Account for multi-cloud access
resource "google_service_account" "multi_cloud_sa" {
  account_id   = "multi-cloud-access"
  display_name = "Multi-Cloud Access Service Account"
  description  = "Service account for multi-cloud operations"
}

# IAM Policy for multi-cloud operations
resource "aws_iam_policy" "multi_cloud_policy" {
  name        = "MultiCloudOperationsPolicy"
  description = "Policy for multi-cloud operations"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "s3:ListBucket",
          "rds:DescribeDBInstances",
          "cloudwatch:GetMetricStatistics"
        ]
        Resource = "*"
        Condition = {
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "multi_cloud_policy_attachment" {
  role       = aws_iam_role.cross_cloud_role.name
  policy_arn = aws_iam_policy.multi_cloud_policy.arn
}
```

### 5. What are the best practices for secrets management in the cloud?

**Answer:**

**Secrets Management Strategy:**

```yaml
secrets_management:
  centralized_secrets:
    tools:
      - "HashiCorp Vault"
      - "AWS Secrets Manager"
      - "Azure Key Vault"
      - "GCP Secret Manager"
    
    features:
      - "Encryption at rest and in transit"
      - "Access logging and auditing"
      - "Automatic rotation"
      - "Fine-grained access control"
  
  secrets_lifecycle:
    creation:
      - "Strong entropy generation"
      - "Secure distribution"
      - "Immediate encryption"
    
    rotation:
      - "Automated rotation schedules"
      - "Graceful rollover"
      - "Backward compatibility"
    
    retirement:
      - "Secure deletion"
      - "Revocation processes"
      - "Audit trail maintenance"
```

**HashiCorp Vault Implementation:**
```python
# Python example for HashiCorp Vault integration
import hvac
import json
import logging
from datetime import datetime, timedelta

class SecretsManager:
    def __init__(self, vault_url, vault_token):
        self.client = hvac.Client(url=vault_url, token=vault_token)
        self.logger = logging.getLogger(__name__)
    
    def configure_database_secrets_engine(self):
        """Configure dynamic database credentials"""
        
        # Enable database secrets engine
        self.client.sys.enable_secrets_engine(
            backend_type='database',
            path='database'
        )
        
        # Configure database connection
        self.client.secrets.database.configure(
            name='postgres-db',
            plugin_name='postgresql-database-plugin',
            connection_url='postgresql://{{username}}:{{password}}@postgres:5432/app?sslmode=disable',
            allowed_roles=['app-role'],
            username='vault-admin',
            password='admin-password'
        )
        
        # Create database role
        self.client.secrets.database.create_role(
            name='app-role',
            db_name='postgres-db',
            creation_statements=[
                'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\';',
                'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{{name}}";'
            ],
            default_ttl='1h',
            max_ttl='24h'
        )
    
    def get_dynamic_database_credentials(self, role_name):
        """Get dynamic database credentials"""
        try:
            response = self.client.secrets.database.generate_credentials(
                name=role_name
            )
            
            credentials = {
                'username': response['data']['username'],
                'password': response['data']['password'],
                'lease_id': response['lease_id'],
                'lease_duration': response['lease_duration']
            }
            
            self.logger.info(f"Generated credentials for role: {role_name}")
            return credentials
            
        except Exception as e:
            self.logger.error(f"Failed to generate credentials: {e}")
            raise
    
    def store_static_secret(self, path, secret_data):
        """Store static secret in Vault"""
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data,
                mount_point='secret'
            )
            
            self.logger.info(f"Secret stored at path: {path}")
            
        except Exception as e:
            self.logger.error(f"Failed to store secret: {e}")
            raise
    
    def retrieve_secret(self, path):
        """Retrieve secret from Vault"""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point='secret'
            )
            
            return response['data']['data']
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve secret: {e}")
            raise
    
    def configure_pki_secrets_engine(self):
        """Configure PKI secrets engine for certificate management"""
        
        # Enable PKI secrets engine
        self.client.sys.enable_secrets_engine(
            backend_type='pki',
            path='pki'
        )
        
        # Set max lease TTL
        self.client.sys.tune_secrets_engine(
            path='pki',
            max_lease_ttl='8760h'  # 1 year
        )
        
        # Generate root CA
        response = self.client.secrets.pki.generate_root(
            type='internal',
            common_name='My Internal CA',
            ttl='8760h'
        )
        
        # Configure CA and CRL URLs
        self.client.secrets.pki.set_urls(
            issuing_certificates=['http://vault.example.com:8200/v1/pki/ca'],
            crl_distribution_points=['http://vault.example.com:8200/v1/pki/crl']
        )
        
        # Create role for certificate generation
        self.client.secrets.pki.create_role(
            name='web-server',
            allowed_domains=['example.com'],
            allow_subdomains=True,
            max_ttl='720h'  # 30 days
        )
    
    def generate_certificate(self, role_name, common_name):
        """Generate certificate using PKI engine"""
        try:
            response = self.client.secrets.pki.generate_certificate(
                name=role_name,
                common_name=common_name
            )
            
            return {
                'certificate': response['data']['certificate'],
                'private_key': response['data']['private_key'],
                'ca_chain': response['data']['ca_chain'],
                'expiration': response['data']['expiration']
            }
            
        except Exception as e:
            self.logger.error(f"Failed to generate certificate: {e}")
            raise
    
    def setup_auto_rotation(self, secret_path, rotation_script):
        """Setup automatic secret rotation"""
        
        # This would typically be implemented with Vault's
        # secret rotation capabilities or external automation
        
        rotation_config = {
            'path': secret_path,
            'rotation_period': '30d',
            'script': rotation_script,
            'notification_webhook': 'https://alerts.example.com/webhook'
        }
        
        # Store rotation configuration
        self.store_static_secret(
            f'config/rotation/{secret_path.replace("/", "-")}',
            rotation_config
        )

# Usage example
vault_manager = SecretsManager(
    vault_url='https://vault.example.com:8200',
    vault_token='your-vault-token'
)

# Configure database secrets
vault_manager.configure_database_secrets_engine()

# Get dynamic database credentials
db_creds = vault_manager.get_dynamic_database_credentials('app-role')
print(f"Database credentials: {db_creds['username']}")

# Store API key
vault_manager.store_static_secret(
    'app/api-keys/external-service',
    {'api_key': 'super-secret-api-key', 'environment': 'production'}
)

# Retrieve API key
api_key_data = vault_manager.retrieve_secret('app/api-keys/external-service')
print(f"API Key: {api_key_data['api_key']}")

# Generate SSL certificate
vault_manager.configure_pki_secrets_engine()
cert_data = vault_manager.generate_certificate('web-server', 'app.example.com')
print(f"Certificate expiration: {cert_data['expiration']}")
```

## Cloud Data Protection

### 6. How do you implement comprehensive data encryption in the cloud?

**Answer:**

**Encryption Strategy:**

```mermaid
graph TB
    subgraph "Encryption Layers"
        Application[Application Layer]
        Database[Database Layer]
        Storage[Storage Layer]
        Network[Network Layer]
        Infrastructure[Infrastructure Layer]
    end
    
    subgraph "Key Management"
        HSM[Hardware Security Modules]
        KMS[Key Management Service]
        Vault[HashiCorp Vault]
    end
    
    subgraph "Encryption Types"
        AtRest[Encryption at Rest]
        InTransit[Encryption in Transit]
        InUse[Encryption in Use]
    end
    
    Application --> AtRest
    Database --> InTransit
    Storage --> InUse
    Network --> KMS
    Infrastructure --> HSM
    
    KMS --> Vault
    
    style Application fill:#4caf50
    style KMS fill:#2196f3
    style AtRest fill:#ff9800
```

**Encryption Implementation:**
```yaml
encryption_strategy:
  at_rest:
    techniques:
      - "Full disk encryption"
      - "Database-level encryption"
      - "File system encryption"
      - "Object storage encryption"
    
    key_management:
      - "Customer-managed keys (CMK)"
      - "Hardware Security Modules (HSM)"
      - "Key rotation policies"
      - "Key escrow procedures"
  
  in_transit:
    protocols:
      - "TLS 1.3 for web traffic"
      - "IPSec for VPN connections"
      - "SSH for administrative access"
      - "HTTPS for API communications"
    
    certificates:
      - "PKI infrastructure"
      - "Certificate Authority (CA)"
      - "Automated certificate management"
      - "Certificate transparency logging"
  
  in_use:
    technologies:
      - "Confidential computing"
      - "Trusted Execution Environments (TEE)"
      - "Homomorphic encryption"
      - "Secure multi-party computation"
```

**AWS Encryption Example:**
```terraform
# AWS KMS key for encryption
resource "aws_kms_key" "app_encryption_key" {
  description             = "Encryption key for application data"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow application access"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.app_role.arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
  
  tags = {
    Name        = "app-encryption-key"
    Environment = "production"
  }
}

resource "aws_kms_alias" "app_encryption_key_alias" {
  name          = "alias/app-encryption-key"
  target_key_id = aws_kms_key.app_encryption_key.key_id
}

# S3 bucket with encryption
resource "aws_s3_bucket" "encrypted_data" {
  bucket = "my-encrypted-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted_data" {
  bucket = aws_s3_bucket.encrypted_data.bucket
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.app_encryption_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# RDS instance with encryption
resource "aws_db_instance" "encrypted_database" {
  identifier = "encrypted-app-db"
  
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp2"
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.app_encryption_key.arn
  
  db_name  = "appdb"
  username = "admin"
  password = "changeme"  # Use Secrets Manager in production
  
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = true
  
  tags = {
    Name        = "encrypted-app-database"
    Environment = "production"
  }
}

# EBS volume with encryption
resource "aws_ebs_volume" "encrypted_volume" {
  availability_zone = "us-west-2a"
  size              = 40
  type              = "gp3"
  
  encrypted  = true
  kms_key_id = aws_kms_key.app_encryption_key.arn
  
  tags = {
    Name = "encrypted-app-volume"
  }
}
```

### 7. What are the data classification and data loss prevention strategies?

**Answer:**

**Data Classification Framework:**

```yaml
data_classification:
  classification_levels:
    public:
      description: "Information available to public"
      examples: ["Marketing materials", "Press releases"]
      controls: ["Basic access logging"]
    
    internal:
      description: "Information for internal use"
      examples: ["Internal documentation", "Employee directories"]
      controls: ["Authentication required", "Access logging"]
    
    confidential:
      description: "Sensitive business information"
      examples: ["Financial data", "Customer information"]
      controls: ["Encryption", "Access approval", "DLP monitoring"]
    
    restricted:
      description: "Highly sensitive information"
      examples: ["Trade secrets", "Personal data", "Legal documents"]
      controls: ["Strong encryption", "Multi-person approval", "Audit trails"]
  
  automated_classification:
    techniques:
      - "Pattern matching (regex)"
      - "Machine learning algorithms"
      - "Content inspection"
      - "Metadata analysis"
    
    tools:
      - "Microsoft Purview"
      - "AWS Macie"
      - "Google Cloud DLP API"
      - "Symantec DLP"
```

**DLP Implementation:**
```python
import re
import hashlib
import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

class ClassificationLevel(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

@dataclass
class ClassificationRule:
    name: str
    pattern: str
    classification: ClassificationLevel
    confidence: float
    description: str

class DataClassifier:
    def __init__(self):
        self.rules = []
        self.logger = logging.getLogger(__name__)
        self._load_classification_rules()
    
    def _load_classification_rules(self):
        """Load data classification rules"""
        self.rules = [
            ClassificationRule(
                name="credit_card",
                pattern=r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                classification=ClassificationLevel.RESTRICTED,
                confidence=0.9,
                description="Credit card number pattern"
            ),
            ClassificationRule(
                name="ssn",
                pattern=r'\b\d{3}-\d{2}-\d{4}\b',
                classification=ClassificationLevel.RESTRICTED,
                confidence=0.95,
                description="Social Security Number"
            ),
            ClassificationRule(
                name="email",
                pattern=r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                classification=ClassificationLevel.CONFIDENTIAL,
                confidence=0.8,
                description="Email address"
            ),
            ClassificationRule(
                name="ip_address",
                pattern=r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                classification=ClassificationLevel.INTERNAL,
                confidence=0.7,
                description="IP address"
            ),
            ClassificationRule(
                name="api_key",
                pattern=r'[Aa][Pp][Ii][-_]?[Kk][Ee][Yy][-_]?[:=]\s*[\'"]?[\w\-]{20,}[\'"]?',
                classification=ClassificationLevel.RESTRICTED,
                confidence=0.85,
                description="API key pattern"
            )
        ]
    
    def classify_content(self, content: str, filename: str = None) -> Dict:
        """Classify content based on rules"""
        matches = []
        highest_classification = ClassificationLevel.PUBLIC
        total_confidence = 0
        
        for rule in self.rules:
            pattern_matches = re.finditer(rule.pattern, content, re.IGNORECASE)
            
            for match in pattern_matches:
                matches.append({
                    'rule_name': rule.name,
                    'matched_text': match.group(),
                    'start_pos': match.start(),
                    'end_pos': match.end(),
                    'classification': rule.classification.value,
                    'confidence': rule.confidence,
                    'description': rule.description
                })
                
                # Update highest classification
                if self._is_higher_classification(rule.classification, highest_classification):
                    highest_classification = rule.classification
                
                total_confidence += rule.confidence
        
        # Calculate average confidence
        avg_confidence = total_confidence / len(matches) if matches else 0
        
        result = {
            'filename': filename,
            'classification': highest_classification.value,
            'confidence': min(avg_confidence, 1.0),
            'matches': matches,
            'content_hash': hashlib.sha256(content.encode()).hexdigest()[:16],
            'scan_timestamp': datetime.now().isoformat()
        }
        
        self.logger.info(f"Classified content: {result['classification']} (confidence: {result['confidence']:.2f})")
        return result
    
    def _is_higher_classification(self, level1: ClassificationLevel, level2: ClassificationLevel) -> bool:
        """Check if level1 is higher than level2"""
        hierarchy = {
            ClassificationLevel.PUBLIC: 0,
            ClassificationLevel.INTERNAL: 1,
            ClassificationLevel.CONFIDENTIAL: 2,
            ClassificationLevel.RESTRICTED: 3
        }
        return hierarchy[level1] > hierarchy[level2]

class DLPEngine:
    def __init__(self):
        self.classifier = DataClassifier()
        self.logger = logging.getLogger(__name__)
        self.blocked_patterns = []
        self._load_dlp_policies()
    
    def _load_dlp_policies(self):
        """Load DLP policies"""
        self.policies = {
            'email': {
                'action': 'block',
                'classification_threshold': ClassificationLevel.CONFIDENTIAL
            },
            'file_upload': {
                'action': 'quarantine',
                'classification_threshold': ClassificationLevel.RESTRICTED
            },
            'api_request': {
                'action': 'monitor',
                'classification_threshold': ClassificationLevel.INTERNAL
            }
        }
    
    def scan_content(self, content: str, context: str, filename: str = None) -> Dict:
        """Scan content for DLP violations"""
        classification_result = self.classifier.classify_content(content, filename)
        
        policy = self.policies.get(context, {})
        threshold = policy.get('classification_threshold', ClassificationLevel.PUBLIC)
        action = policy.get('action', 'allow')
        
        # Determine if content violates policy
        content_level = ClassificationLevel(classification_result['classification'])
        violation = self._is_violation(content_level, threshold)
        
        dlp_result = {
            'violation_detected': violation,
            'action_taken': action if violation else 'allow',
            'context': context,
            'policy_applied': policy,
            'classification_result': classification_result
        }
        
        if violation:
            self._handle_violation(dlp_result)
        
        return dlp_result
    
    def _is_violation(self, content_level: ClassificationLevel, threshold: ClassificationLevel) -> bool:
        """Check if content classification violates policy threshold"""
        return self.classifier._is_higher_classification(content_level, threshold) or content_level == threshold
    
    def _handle_violation(self, dlp_result: Dict):
        """Handle DLP violation"""
        action = dlp_result['action_taken']
        
        if action == 'block':
            self.logger.warning(f"DLP BLOCK: {dlp_result['classification_result']['filename']}")
            # Implement blocking logic
            
        elif action == 'quarantine':
            self.logger.warning(f"DLP QUARANTINE: {dlp_result['classification_result']['filename']}")
            # Implement quarantine logic
            
        elif action == 'monitor':
            self.logger.info(f"DLP MONITOR: {dlp_result['classification_result']['filename']}")
            # Implement monitoring/alerting logic
        
        # Send alert to security team
        self._send_security_alert(dlp_result)
    
    def _send_security_alert(self, dlp_result: Dict):
        """Send security alert for DLP violation"""
        alert_data = {
            'event_type': 'dlp_violation',
            'severity': self._get_severity(dlp_result['classification_result']['classification']),
            'timestamp': dlp_result['classification_result']['scan_timestamp'],
            'details': dlp_result
        }
        
        # Implement alerting logic (email, Slack, SIEM, etc.)
        self.logger.error(f"SECURITY ALERT: {alert_data}")
    
    def _get_severity(self, classification: str) -> str:
        """Get alert severity based on classification"""
        severity_map = {
            'public': 'low',
            'internal': 'medium',
            'confidential': 'high',
            'restricted': 'critical'
        }
        return severity_map.get(classification, 'medium')

# Usage example
from datetime import datetime

dlp_engine = DLPEngine()

# Test content with sensitive data
test_content = """
Customer Information:
Name: John Doe
Email: john.doe@example.com
Credit Card: 4532-1234-5678-9012
SSN: 123-45-6789
API Key: api_key="sk-1234567890abcdef1234567890"
"""

# Scan content for email context
result = dlp_engine.scan_content(test_content, 'email', 'customer_data.txt')

print(f"Violation Detected: {result['violation_detected']}")
print(f"Action Taken: {result['action_taken']}")
print(f"Classification: {result['classification_result']['classification']}")
print(f"Matches Found: {len(result['classification_result']['matches'])}")

for match in result['classification_result']['matches']:
    print(f"- {match['rule_name']}: {match['description']}")
```

## Cloud Security Monitoring

### 8. How do you implement comprehensive security monitoring and incident response?

**Answer:**

**Security Monitoring Architecture:**

```mermaid
graph TB
    subgraph "Data Sources"
        CloudTrail[CloudTrail Logs]
        VPCFlow[VPC Flow Logs]
        AppLogs[Application Logs]
        WAF[WAF Logs]
        DNS[DNS Logs]
    end
    
    subgraph "Collection & Processing"
        LogShip[Log Shipping]
        Normalize[Normalization]
        Enrich[Enrichment]
    end
    
    subgraph "Analysis"
        SIEM[SIEM Platform]
        ML[ML Analytics]
        ThreatIntel[Threat Intelligence]
    end
    
    subgraph "Response"
        Alerts[Alert Management]
        SOAR[Security Orchestration]
        Incident[Incident Response]
    end
    
    CloudTrail --> LogShip
    VPCFlow --> LogShip
    AppLogs --> LogShip
    WAF --> LogShip
    DNS --> LogShip
    
    LogShip --> Normalize
    Normalize --> Enrich
    Enrich --> SIEM
    
    SIEM --> ML
    ML --> ThreatIntel
    ThreatIntel --> Alerts
    
    Alerts --> SOAR
    SOAR --> Incident
    
    style SIEM fill:#4caf50
    style ML fill:#2196f3
    style SOAR fill:#ff9800
```

**Security Monitoring Implementation:**
```python
import json
import boto3
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum

class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: ThreatLevel
    description: str
    raw_data: Dict[str, Any]
    indicators: List[str]
    
class SecurityMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cloudtrail = boto3.client('cloudtrail')
        self.cloudwatch = boto3.client('cloudwatch')
        self.sns = boto3.client('sns')
        self.security_rules = self._load_security_rules()
    
    def _load_security_rules(self) -> Dict:
        """Load security detection rules"""
        return {
            'failed_logins': {
                'pattern': 'ConsoleLogin',
                'condition': 'errorCode',
                'threshold': 5,
                'timeframe': 300,  # 5 minutes
                'severity': ThreatLevel.MEDIUM
            },
            'root_account_usage': {
                'pattern': 'root',
                'condition': 'userIdentity.type',
                'threshold': 1,
                'timeframe': 3600,  # 1 hour
                'severity': ThreatLevel.HIGH
            },
            'unauthorized_api_calls': {
                'pattern': 'AccessDenied',
                'condition': 'errorCode',
                'threshold': 10,
                'timeframe': 600,  # 10 minutes
                'severity': ThreatLevel.MEDIUM
            },
            'privilege_escalation': {
                'patterns': ['AttachUserPolicy', 'CreateRole', 'AssumeRole'],
                'condition': 'eventName',
                'threshold': 3,
                'timeframe': 1800,  # 30 minutes
                'severity': ThreatLevel.HIGH
            },
            'data_exfiltration': {
                'patterns': ['GetObject', 'DownloadDBLogFilePortion'],
                'condition': 'eventName',
                'threshold': 100,
                'timeframe': 3600,  # 1 hour
                'severity': ThreatLevel.CRITICAL
            }
        }
    
    def analyze_cloudtrail_events(self, start_time: datetime, end_time: datetime) -> List[SecurityEvent]:
        """Analyze CloudTrail events for security threats"""
        security_events = []
        
        try:
            # Get CloudTrail events
            response = self.cloudtrail.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxItems=50
            )
            
            events = response.get('Events', [])
            
            # Group events for analysis
            event_groups = self._group_events_by_rule(events)
            
            # Analyze each group against security rules
            for rule_name, rule_events in event_groups.items():
                threat_events = self._analyze_event_group(rule_name, rule_events)
                security_events.extend(threat_events)
            
        except Exception as e:
            self.logger.error(f"Error analyzing CloudTrail events: {e}")
        
        return security_events
    
    def _group_events_by_rule(self, events: List[Dict]) -> Dict[str, List[Dict]]:
        """Group events by security rules"""
        grouped = {}
        
        for event in events:
            for rule_name, rule_config in self.security_rules.items():
                if self._event_matches_rule(event, rule_config):
                    if rule_name not in grouped:
                        grouped[rule_name] = []
                    grouped[rule_name].append(event)
        
        return grouped
    
    def _event_matches_rule(self, event: Dict, rule_config: Dict) -> bool:
        """Check if event matches security rule"""
        condition = rule_config['condition']
        
        if 'pattern' in rule_config:
            pattern = rule_config['pattern']
            event_value = self._get_nested_value(event, condition)
            return pattern in str(event_value) if event_value else False
        
        elif 'patterns' in rule_config:
            patterns = rule_config['patterns']
            event_value = self._get_nested_value(event, condition)
            return str(event_value) in patterns if event_value else False
        
        return False
    
    def _get_nested_value(self, data: Dict, key_path: str) -> Any:
        """Get nested value from dictionary using dot notation"""
        keys = key_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    def _analyze_event_group(self, rule_name: str, events: List[Dict]) -> List[SecurityEvent]:
        """Analyze grouped events for threats"""
        rule_config = self.security_rules[rule_name]
        threshold = rule_config['threshold']
        timeframe = rule_config['timeframe']
        severity = rule_config['severity']
        
        security_events = []
        
        # Check if threshold is exceeded within timeframe
        if len(events) >= threshold:
            # Group events by time windows
            time_windows = self._group_events_by_timeframe(events, timeframe)
            
            for window_start, window_events in time_windows.items():
                if len(window_events) >= threshold:
                    security_event = SecurityEvent(
                        event_id=hashlib.md5(f"{rule_name}_{window_start}".encode()).hexdigest(),
                        timestamp=datetime.now(),
                        source='cloudtrail',
                        event_type=rule_name,
                        severity=severity,
                        description=f"Detected {len(window_events)} {rule_name} events in {timeframe} seconds",
                        raw_data={'events': window_events, 'rule': rule_config},
                        indicators=self._extract_indicators(window_events)
                    )
                    security_events.append(security_event)
        
        return security_events
    
    def _group_events_by_timeframe(self, events: List[Dict], timeframe: int) -> Dict[datetime, List[Dict]]:
        """Group events by time windows"""
        windows = {}
        
        for event in events:
            event_time = event.get('EventTime')
            if event_time:
                # Round down to timeframe boundary
                window_start = datetime(
                    event_time.year, event_time.month, event_time.day,
                    event_time.hour, (event_time.minute // (timeframe // 60)) * (timeframe // 60)
                )
                
                if window_start not in windows:
                    windows[window_start] = []
                windows[window_start].append(event)
        
        return windows
    
    def _extract_indicators(self, events: List[Dict]) -> List[str]:
        """Extract threat indicators from events"""
        indicators = set()
        
        for event in events:
            # Extract IP addresses
            source_ip = event.get('SourceIPAddress')
            if source_ip:
                indicators.add(f"ip:{source_ip}")
            
            # Extract user identities
            user_identity = event.get('UserIdentity', {})
            if user_identity.get('userName'):
                indicators.add(f"user:{user_identity['userName']}")
            
            # Extract resource ARNs
            for resource in event.get('Resources', []):
                if resource.get('ResourceName'):
                    indicators.add(f"resource:{resource['ResourceName']}")
        
        return list(indicators)
    
    def create_security_incident(self, security_event: SecurityEvent) -> Dict:
        """Create security incident from security event"""
        incident = {
            'incident_id': f"INC-{security_event.event_id}",
            'title': f"Security Alert: {security_event.event_type}",
            'description': security_event.description,
            'severity': security_event.severity.value,
            'status': 'open',
            'created_at': security_event.timestamp.isoformat(),
            'source_event': {
                'event_id': security_event.event_id,
                'source': security_event.source,
                'indicators': security_event.indicators
            },
            'containment_actions': self._get_containment_actions(security_event),
            'investigation_steps': self._get_investigation_steps(security_event)
        }
        
        return incident
    
    def _get_containment_actions(self, security_event: SecurityEvent) -> List[str]:
        """Get recommended containment actions"""
        actions = []
        
        if security_event.event_type == 'failed_logins':
            actions.extend([
                "Review account lockout policies",
                "Check for credential stuffing attacks",
                "Consider IP blocking for repeated failures"
            ])
        
        elif security_event.event_type == 'root_account_usage':
            actions.extend([
                "Immediately review root account activity",
                "Disable root account access keys if any",
                "Enable CloudTrail logging if not enabled",
                "Review IAM policies and roles"
            ])
        
        elif security_event.event_type == 'privilege_escalation':
            actions.extend([
                "Review and revoke unnecessary permissions",
                "Audit recent IAM changes",
                "Check for unauthorized role assumptions",
                "Consider emergency access restrictions"
            ])
        
        elif security_event.event_type == 'data_exfiltration':
            actions.extend([
                "Immediately block suspicious IP addresses",
                "Review data access patterns",
                "Check for unauthorized data downloads",
                "Consider emergency data access restrictions"
            ])
        
        return actions
    
    def _get_investigation_steps(self, security_event: SecurityEvent) -> List[str]:
        """Get recommended investigation steps"""
        steps = [
            "Collect and preserve all relevant logs",
            "Identify scope of potential compromise",
            "Review user and system activities",
            "Check for persistence mechanisms",
            "Assess potential data exposure",
            "Document timeline of events"
        ]
        
        return steps
    
    def send_security_alert(self, security_event: SecurityEvent, incident: Dict):
        """Send security alert notifications"""
        try:
            # Create alert message
            alert_message = {
                'alert_type': 'security_incident',
                'severity': security_event.severity.value,
                'event_type': security_event.event_type,
                'description': security_event.description,
                'incident_id': incident['incident_id'],
                'indicators': security_event.indicators,
                'timestamp': security_event.timestamp.isoformat(),
                'containment_actions': incident['containment_actions']
            }
            
            # Send to SNS topic
            self.sns.publish(
                TopicArn='arn:aws:sns:us-west-2:123456789012:security-alerts',
                Message=json.dumps(alert_message, indent=2),
                Subject=f"SECURITY ALERT: {security_event.event_type.upper()}"
            )
            
            self.logger.warning(f"Security alert sent: {incident['incident_id']}")
            
        except Exception as e:
            self.logger.error(f"Failed to send security alert: {e}")

# Usage example
monitor = SecurityMonitor()

# Analyze recent events
end_time = datetime.now()
start_time = end_time - timedelta(hours=1)

security_events = monitor.analyze_cloudtrail_events(start_time, end_time)

for event in security_events:
    print(f"Security Event Detected:")
    print(f"- Type: {event.event_type}")
    print(f"- Severity: {event.severity.value}")
    print(f"- Description: {event.description}")
    print(f"- Indicators: {event.indicators}")
    
    # Create incident
    incident = monitor.create_security_incident(event)
    print(f"- Incident ID: {incident['incident_id']}")
    
    # Send alert
    monitor.send_security_alert(event, incident)
    print("---")
```

This comprehensive cloud security guide covers fundamental principles, identity and access management, data protection, encryption strategies, data classification, DLP implementation, and security monitoring with practical examples and code implementations for multi-cloud environments.