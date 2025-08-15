# Terraform Infrastructure as Code Interview Questions 🚀

## Terraform Fundamentals

### 1. Explain Terraform's core concepts and workflow

**Answer:**

Terraform is an Infrastructure as Code (IaC) tool that allows you to define and provision infrastructure using declarative configuration files.

```mermaid
graph TB
    Config[Configuration Files] --> Init[terraform init]
    Init --> Plan[terraform plan]
    Plan --> Apply[terraform apply]
    Apply --> State[State File]
    State --> Destroy[terraform destroy]
    
    subgraph "Core Components"
        Provider[Providers]
        Resource[Resources] 
        Module[Modules]
        Variable[Variables]
        Output[Outputs]
    end
    
    Config --> Provider
    Config --> Resource
    Config --> Module
    Config --> Variable
    Config --> Output
    
    style Config fill:#4caf50
    style State fill:#2196f3
    style Provider fill:#ff9800
```

**Basic Terraform Structure:**
```hcl
# main.tf
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  
  backend "s3" {
    bucket = "terraform-state-bucket"
    key    = "infrastructure/terraform.tfstate"
    region = "us-west-2"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "Terraform"
    }
  }
}

# variables.tf
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}
```

### 2. How do you manage Terraform state effectively?

**Answer:**

```mermaid
graph TB
    Local[Local State] --> Remote[Remote State]
    Remote --> Backend[State Backend]
    Backend --> Lock[State Locking]
    
    subgraph "Backend Options"
        S3[AWS S3]
        GCS[Google Cloud Storage]
        Azure[Azure Storage]
        Consul[HashiCorp Consul]
        Postgres[PostgreSQL]
    end
    
    subgraph "State Management"
        Workspace[Workspaces]
        Import[State Import]
        Refresh[State Refresh]
        Move[State Move]
    end
    
    Backend --> S3
    Backend --> GCS
    Backend --> Azure
    
    Lock --> Workspace
    Lock --> Import
    Lock --> Refresh
    Lock --> Move
    
    style Remote fill:#4caf50
    style Lock fill:#f44336
    style Workspace fill:#2196f3
```

**Remote State Configuration:**
```hcl
# backend.tf
terraform {
  backend "s3" {
    bucket         = "terraform-state-${var.environment}"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
    
    # Prevent accidental state file deletion
    versioning = true
  }
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "terraform_state_lock" {
  name           = "terraform-state-lock"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name = "Terraform State Lock Table"
  }
}

# S3 bucket for state storage
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state-${var.environment}-${random_id.bucket_suffix.hex}"
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

### 3. Explain Terraform modules and their best practices

**Answer:**

```mermaid
graph TB
    Root[Root Module] --> Child1[VPC Module]
    Root --> Child2[EC2 Module]
    Root --> Child3[RDS Module]
    
    Child1 --> Subnet[Subnet Resources]
    Child1 --> IGW[Internet Gateway]
    Child1 --> RT[Route Tables]
    
    Child2 --> Instance[EC2 Instances]
    Child2 --> SG[Security Groups]
    Child2 --> ELB[Load Balancer]
    
    Child3 --> DB[RDS Instance]
    Child3 --> DBSub[DB Subnet Group]
    Child3 --> DBSec[DB Security Group]
    
    style Root fill:#4caf50
    style Child1 fill:#2196f3
    style Child2 fill:#ff9800
    style Child3 fill:#9c27b0
```

**Module Structure:**
```
modules/
├── vpc/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── README.md
├── ec2/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── README.md
└── rds/
    ├── main.tf
    ├── variables.tf
    ├── outputs.tf
    └── README.md
```

**VPC Module Example:**
```hcl
# modules/vpc/main.tf
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-vpc"
  })
}

resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)
  
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-public-${count.index + 1}"
    Type = "Public"
  })
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-igw"
  })
}

# modules/vpc/variables.tf
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default     = {}
}

# modules/vpc/outputs.tf
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}
```

**Using the Module:**
```hcl
# main.tf (root module)
module "vpc" {
  source = "./modules/vpc"
  
  vpc_cidr             = "10.0.0.0/16"
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  availability_zones   = ["us-west-2a", "us-west-2b"]
  name_prefix          = "production"
  
  tags = {
    Environment = "production"
    Project     = "web-app"
  }
}

module "ec2" {
  source = "./modules/ec2"
  
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.public_subnet_ids
  instance_type     = "t3.medium"
  key_name          = "production-key"
  
  tags = {
    Environment = "production"
    Project     = "web-app"
  }
}
```

## Advanced Terraform Concepts

### 4. How do you handle complex resource dependencies and provisioning?

**Answer:**

```mermaid
graph TB
    subgraph "Dependency Management"
        Implicit[Implicit Dependencies]
        Explicit[Explicit Dependencies]
        Data[Data Sources]
    end
    
    subgraph "Provisioning"
        Local[Local Provisioners]
        Remote[Remote Provisioners]
        FileP[File Provisioners]
        Null[Null Resources]
    end
    
    subgraph "Lifecycle Management"
        Create[create_before_destroy]
        Prevent[prevent_destroy]
        Ignore[ignore_changes]
    end
    
    Implicit --> Data
    Explicit --> Null
    Data --> Remote
    
    Local --> Create
    Remote --> Prevent
    FileP --> Ignore
    
    style Implicit fill:#4caf50
    style Remote fill:#2196f3
    style Create fill:#ff9800
```

**Complex Dependencies Example:**
```hcl
# Data source for existing resources
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}

# Resource with explicit dependencies
resource "aws_instance" "web" {
  count = var.instance_count
  
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name              = aws_key_pair.deployer.key_name
  vpc_security_group_ids = [aws_security_group.web.id]
  subnet_id             = element(aws_subnet.public.*.id, count.index)
  
  # Explicit dependency
  depends_on = [
    aws_internet_gateway.main,
    aws_route_table_association.public
  ]
  
  # Lifecycle management
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [ami]
  }
  
  # User data provisioning
  user_data = templatefile("${path.module}/user_data.sh", {
    db_endpoint = aws_db_instance.main.endpoint
    app_version = var.app_version
  })
  
  tags = {
    Name = "web-server-${count.index + 1}"
  }
}

# Null resource for custom provisioning
resource "null_resource" "web_provisioning" {
  count = length(aws_instance.web)
  
  triggers = {
    instance_id = aws_instance.web[count.index].id
    app_version = var.app_version
  }
  
  connection {
    type        = "ssh"
    user        = "ubuntu"
    private_key = file(var.private_key_path)
    host        = aws_instance.web[count.index].public_ip
  }
  
  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y docker.io",
      "sudo systemctl start docker",
      "sudo systemctl enable docker",
      "sudo docker run -d -p 80:8080 myapp:${var.app_version}"
    ]
  }
  
  provisioner "local-exec" {
    command = "echo 'Instance ${aws_instance.web[count.index].id} provisioned'"
  }
}
```

### 5. How do you implement Terraform workspaces and environment management?

**Answer:**

```mermaid
graph TB
    Default[Default Workspace] --> Dev[Development]
    Default --> Staging[Staging]
    Default --> Prod[Production]
    
    subgraph "Environment-Specific"
        DevVars[dev.tfvars]
        StagingVars[staging.tfvars]
        ProdVars[prod.tfvars]
    end
    
    subgraph "Shared Configuration"
        Modules[Reusable Modules]
        Backend[Remote Backend]
        Provider[Provider Config]
    end
    
    Dev --> DevVars
    Staging --> StagingVars
    Prod --> ProdVars
    
    DevVars --> Modules
    StagingVars --> Modules
    ProdVars --> Modules
    
    Modules --> Backend
    Backend --> Provider
    
    style Default fill:#4caf50
    style Modules fill:#2196f3
    style Backend fill:#ff9800
```

**Workspace Configuration:**
```hcl
# main.tf with workspace-aware configuration
locals {
  environment = terraform.workspace
  
  # Environment-specific configurations
  config = {
    dev = {
      instance_type = "t3.micro"
      instance_count = 1
      db_instance_class = "db.t3.micro"
      multi_az = false
    }
    staging = {
      instance_type = "t3.small"
      instance_count = 2
      db_instance_class = "db.t3.small"
      multi_az = false
    }
    prod = {
      instance_type = "t3.medium"
      instance_count = 3
      db_instance_class = "db.t3.large"
      multi_az = true
    }
  }
  
  current_config = local.config[local.environment]
}

# Environment-specific resource naming
resource "aws_instance" "web" {
  count = local.current_config.instance_count
  
  ami           = data.aws_ami.ubuntu.id
  instance_type = local.current_config.instance_type
  
  tags = {
    Name        = "${local.environment}-web-${count.index + 1}"
    Environment = local.environment
  }
}

# Conditional resource creation
resource "aws_db_instance" "main" {
  count = local.environment == "prod" ? 1 : 0
  
  identifier     = "${local.environment}-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = local.current_config.db_instance_class
  multi_az       = local.current_config.multi_az
  
  allocated_storage = 20
  storage_encrypted = true
  
  db_name  = "app_db"
  username = "admin"
  password = var.db_password
  
  tags = {
    Name        = "${local.environment}-database"
    Environment = local.environment
  }
}
```

**Environment Variable Files:**
```hcl
# environments/dev.tfvars
aws_region = "us-west-2"
environment = "dev"
instance_type = "t3.micro"
min_size = 1
max_size = 2
desired_capacity = 1

# environments/staging.tfvars
aws_region = "us-west-2"
environment = "staging"
instance_type = "t3.small"
min_size = 2
max_size = 4
desired_capacity = 2

# environments/prod.tfvars
aws_region = "us-west-2"
environment = "prod"
instance_type = "t3.medium"
min_size = 3
max_size = 10
desired_capacity = 3
```

**Workspace Management Commands:**
```bash
# Create and switch to workspaces
terraform workspace new dev
terraform workspace new staging
terraform workspace new prod

# List workspaces
terraform workspace list

# Switch workspace
terraform workspace select prod

# Plan with environment-specific variables
terraform plan -var-file="environments/prod.tfvars"

# Apply with workspace
terraform apply -var-file="environments/prod.tfvars"
```

## Multi-Cloud Terraform

### 6. How do you implement multi-cloud infrastructure with Terraform?

**Answer:**

```mermaid
graph TB
    TF[Terraform Configuration] --> AWS[AWS Provider]
    TF --> Azure[Azure Provider]
    TF --> GCP[GCP Provider]
    
    subgraph "AWS Resources"
        EC2[EC2 Instances]
        RDS[RDS Database]
        S3[S3 Buckets]
    end
    
    subgraph "Azure Resources"
        VM[Virtual Machines]
        SQL[Azure SQL]
        Blob[Blob Storage]
    end
    
    subgraph "GCP Resources"
        Compute[Compute Engine]
        CloudSQL[Cloud SQL]
        GCS[Cloud Storage]
    end
    
    AWS --> EC2
    AWS --> RDS
    AWS --> S3
    
    Azure --> VM
    Azure --> SQL
    Azure --> Blob
    
    GCP --> Compute
    GCP --> CloudSQL
    GCP --> GCS
    
    style TF fill:#4caf50
    style AWS fill:#ff9800
    style Azure fill:#2196f3
    style GCP fill:#9c27b0
```

**Multi-Cloud Configuration:**
```hcl
# providers.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# Configure AWS Provider
provider "aws" {
  alias  = "us_west"
  region = "us-west-2"
}

provider "aws" {
  alias  = "us_east"
  region = "us-east-1"
}

# Configure Azure Provider
provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

# Configure GCP Provider
provider "google" {
  project = var.gcp_project_id
  region  = "us-central1"
}

# Multi-cloud resources
module "aws_infrastructure" {
  source = "./modules/aws"
  
  providers = {
    aws = aws.us_west
  }
  
  environment = var.environment
  region      = "us-west-2"
}

module "azure_infrastructure" {
  source = "./modules/azure"
  
  environment      = var.environment
  location         = "East US"
  resource_group   = "rg-${var.environment}"
}

module "gcp_infrastructure" {
  source = "./modules/gcp"
  
  project_id  = var.gcp_project_id
  region      = "us-central1"
  environment = var.environment
}

# Cross-cloud networking (example with VPN)
resource "aws_customer_gateway" "azure_gateway" {
  bgp_asn    = 65000
  ip_address = module.azure_infrastructure.vpn_gateway_ip
  type       = "ipsec.1"
  
  tags = {
    Name = "Azure-Gateway"
  }
}

# Data sharing between clouds
data "aws_s3_bucket_object" "shared_config" {
  bucket = module.aws_infrastructure.config_bucket
  key    = "shared/config.json"
}

resource "google_storage_bucket_object" "shared_config" {
  name   = "shared-config.json"
  bucket = module.gcp_infrastructure.config_bucket
  source = data.aws_s3_bucket_object.shared_config.body
}
```

### 7. How do you implement Terraform testing and validation?

**Answer:**

```mermaid
graph TB
    Code[Terraform Code] --> Validate[terraform validate]
    Validate --> Format[terraform fmt]
    Format --> Plan[terraform plan]
    Plan --> Test[Terratest]
    Test --> Security[Security Scan]
    Security --> Deploy[terraform apply]
    
    subgraph "Testing Tools"
        TTest[Terratest (Go)]
        Kitchen[Test Kitchen]
        Inspec[InSpec]
        Conftest[Conftest/OPA]
    end
    
    subgraph "Security Tools"
        TFSec[tfsec]
        Checkov[Checkov]
        Terrascan[Terrascan]
        Sentinel[Sentinel]
    end
    
    Test --> TTest
    Test --> Kitchen
    Test --> Inspec
    
    Security --> TFSec
    Security --> Checkov
    Security --> Terrascan
    Security --> Sentinel
    
    style Code fill:#4caf50
    style Test fill:#2196f3
    style Security fill:#f44336
```

**Terratest Example:**
```go
// test/terraform_aws_vpc_test.go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/gruntwork-io/terratest/modules/aws"
    "github.com/stretchr/testify/assert"
)

func TestTerraformAwsVpc(t *testing.T) {
    t.Parallel()

    // Configure Terraform options
    terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
        TerraformDir: "../examples/vpc",
        Vars: map[string]interface{}{
            "vpc_cidr": "10.0.0.0/16",
            "environment": "test",
        },
        EnvVars: map[string]string{
            "AWS_DEFAULT_REGION": "us-west-2",
        },
    })

    // Clean up resources with "terraform destroy" at the end of the test
    defer terraform.Destroy(t, terraformOptions)

    // Run "terraform init" and "terraform apply"
    terraform.InitAndApply(t, terraformOptions)

    // Get the VPC ID from Terraform outputs
    vpcId := terraform.Output(t, terraformOptions, "vpc_id")
    
    // Verify the VPC exists and has expected properties
    vpc := aws.GetVpcById(t, vpcId, "us-west-2")
    assert.Equal(t, "10.0.0.0/16", vpc.CidrBlock)
    
    // Test subnet creation
    publicSubnetIds := terraform.OutputList(t, terraformOptions, "public_subnet_ids")
    assert.Len(t, publicSubnetIds, 2)
    
    // Verify subnets are in different AZs
    for _, subnetId := range publicSubnetIds {
        subnet := aws.GetSubnetById(t, subnetId, "us-west-2")
        assert.True(t, subnet.MapPublicIpOnLaunch)
    }
}
```

**Validation and Security:**
```hcl
# validation.tf
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  
  validation {
    condition = contains([
      "t3.micro", "t3.small", "t3.medium",
      "t3.large", "m5.large", "m5.xlarge"
    ], var.instance_type)
    error_message = "Instance type must be a valid EC2 instance type."
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
  
  validation {
    condition     = can(regex("^(dev|staging|prod)$", var.environment))
    error_message = "Environment must be dev, staging, or prod."
  }
}

# Custom validation function
locals {
  validate_cidr = can(cidrhost(var.vpc_cidr, 0))
}

resource "null_resource" "validate_cidr" {
  count = local.validate_cidr ? 0 : 1
  
  provisioner "local-exec" {
    command = "echo 'Invalid CIDR block: ${var.vpc_cidr}' && exit 1"
  }
}
```

**Security Scanning with tfsec:**
```yaml
# .tfsec.yml
exclude:
  - aws-ec2-no-public-ingress-sgr
  - aws-s3-encryption-customer-key

custom_checks:
  - name: "custom-s3-versioning"
    description: "S3 buckets must have versioning enabled"
    resource_type: "aws_s3_bucket"
    severity: "HIGH"
    rule: |
      resource.versioning[0].enabled == true

severity_overrides:
  aws-s3-enable-bucket-logging: ERROR
  aws-ec2-enforce-http-token-imds: HIGH

minimum_severity: MEDIUM

custom_checks:
  - check: "CUS001"
    description: "Ensure all resources are tagged with Environment"
    impact: "Resources without environment tags cannot be tracked"
    resolution: "Add Environment tag to all resources"
    severity: "HIGH"
    frameworks:
      - terraform
    terraform:
      requires_providers:
        - aws
      custom_check:
        RequiredLabels:
          - "Environment"
```

## Terraform Enterprise and Team Workflows

### 8. How do you implement Terraform in a team environment with proper governance?

**Answer:**

```mermaid
graph TB
    Dev[Developer] --> PR[Pull Request]
    PR --> CI[CI Pipeline]
    CI --> Plan[terraform plan]
    Plan --> Review[Code Review]
    Review --> Approve[Approval]
    Approve --> CD[CD Pipeline]
    CD --> Apply[terraform apply]
    
    subgraph "Governance"
        Policy[Sentinel Policies]
        RBAC[Role-Based Access]
        Approval[Approval Workflows]
        Audit[Audit Logging]
    end
    
    subgraph "State Management"
        Remote[Remote State]
        Lock[State Locking]
        Backup[State Backup]
    end
    
    Plan --> Policy
    Review --> RBAC
    Approve --> Approval
    Apply --> Audit
    
    Apply --> Remote
    Remote --> Lock
    Lock --> Backup
    
    style CI fill:#4caf50
    style Policy fill:#f44336
    style Remote fill:#2196f3
```

**GitHub Actions Workflow:**
```yaml
# .github/workflows/terraform.yml
name: Terraform

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  TF_VERSION: 1.5.0
  AWS_REGION: us-west-2

jobs:
  terraform:
    name: Terraform
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      pull-requests: write
      
    steps:
    - name: Checkout
      uses: actions/checkout@v3
      
    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v2
      with:
        terraform_version: ${{ env.TF_VERSION }}
        
    - name: Configure AWS Credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}
        
    - name: Terraform Format
      id: fmt
      run: terraform fmt -check -recursive
      continue-on-error: true
      
    - name: Terraform Init
      id: init
      run: terraform init
      
    - name: Terraform Validate
      id: validate
      run: terraform validate -no-color
      
    - name: Terraform Plan
      id: plan
      if: github.event_name == 'pull_request'
      run: terraform plan -no-color -out=tfplan
      continue-on-error: true
      
    - name: Update Pull Request
      uses: actions/github-script@v6
      if: github.event_name == 'pull_request'
      env:
        PLAN: "terraform\n${{ steps.plan.outputs.stdout }}"
      with:
        script: |
          const output = `#### Terraform Format and Style 🖌\`${{ steps.fmt.outcome }}\`
          #### Terraform Initialization ⚙️\`${{ steps.init.outcome }}\`
          #### Terraform Validation 🤖\`${{ steps.validate.outcome }}\`
          #### Terraform Plan 📖\`${{ steps.plan.outcome }}\`
          
          <details><summary>Show Plan</summary>
          
          \`\`\`\n
          ${process.env.PLAN}
          \`\`\`
          
          </details>
          
          *Pushed by: @${{ github.actor }}, Action: \`${{ github.event_name }}\`*`;
          
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: output
          })
          
    - name: Terraform Plan Status
      if: steps.plan.outcome == 'failure'
      run: exit 1
      
    - name: Terraform Apply
      if: github.ref == 'refs/heads/main' && github.event_name == 'push'
      run: terraform apply -auto-approve tfplan
      
    - name: Security Scan
      uses: aquasecurity/tfsec-action@v1.0.0
      with:
        soft_fail: true
```

**Terraform Cloud/Enterprise Configuration:**
```hcl
# versions.tf
terraform {
  cloud {
    organization = "my-org"
    
    workspaces {
      tags = ["production", "web-app"]
    }
  }
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Sentinel policy example
# policy.sentinel
import "tfplan/v2" as tfplan

# Deny if any S3 bucket is created without encryption
deny_unencrypted_s3_buckets = rule {
    all tfplan.resource_changes as _, resource_changes {
        resource_changes.type is not "aws_s3_bucket" or
        resource_changes.change.after.server_side_encryption_configuration is not null
    }
}

main = rule {
    deny_unencrypted_s3_buckets
}
```

This comprehensive Terraform section covers fundamentals, state management, modules, advanced concepts, multi-cloud deployment, testing, validation, and team workflows. Each topic includes practical examples, code snippets, and Mermaid diagrams to help with interview preparation and real-world implementation.

## Terraform Automation and DevOps Integration

### 9. Automate Terraform workflows with Python and CI/CD

**Answer:**

**Python Terraform Automation Framework:**
```python
#!/usr/bin/env python3
# terraform_automation.py
import subprocess
import json
import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class TerraformConfig:
    """Configuration for Terraform operations"""
    working_dir: str
    backend_config: Dict[str, str]
    var_files: List[str]
    environment: str
    auto_approve: bool = False
    
class TerraformAutomation:
    """Comprehensive Terraform automation class"""
    
    def __init__(self, config: TerraformConfig):
        self.config = config
        self.working_dir = Path(config.working_dir)
        self.terraform_bin = self._find_terraform_binary()
        
    def _find_terraform_binary(self) -> str:
        """Find Terraform binary in PATH"""
        terraform_path = subprocess.run(['which', 'terraform'], 
                                      capture_output=True, text=True)
        if terraform_path.returncode != 0:
            raise RuntimeError("Terraform binary not found in PATH")
        return terraform_path.stdout.strip()
    
    def _run_command(self, cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command and return the result"""
        logger.info(f"Running: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            cwd=self.working_dir,
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.stdout:
            logger.info(f"STDOUT: {result.stdout}")
        if result.stderr:
            logger.error(f"STDERR: {result.stderr}")
            
        if check and result.returncode != 0:
            raise RuntimeError(f"Command failed with return code {result.returncode}")
            
        return result
    
    def plan(self, out_file: Optional[str] = None) -> Dict[str, Any]:
        """Generate Terraform execution plan"""
        logger.info("Generating Terraform plan...")
        
        cmd = [self.terraform_bin, 'plan', '-no-color', '-input=false']
        
        # Add variable files
        for var_file in self.config.var_files:
            cmd.extend(['-var-file', var_file])
            
        # Add output file if specified
        if out_file:
            cmd.extend(['-out', out_file])
            
        result = self._run_command(cmd, check=False)
        
        # Parse plan output for changes
        plan_info = self._parse_plan_output(result.stdout)
        plan_info['success'] = result.returncode == 0
        
        return plan_info
    
    def apply(self, plan_file: Optional[str] = None) -> bool:
        """Apply Terraform configuration"""
        logger.info("Applying Terraform configuration...")
        
        cmd = [self.terraform_bin, 'apply', '-no-color', '-input=false']
        
        if plan_file:
            cmd.append(plan_file)
        else:
            # Add variable files if not using plan file
            for var_file in self.config.var_files:
                cmd.extend(['-var-file', var_file])
                
        if self.config.auto_approve:
            cmd.append('-auto-approve')
            
        result = self._run_command(cmd)
        return result.returncode == 0

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Terraform Automation Tool')
    parser.add_argument('action', choices=['plan', 'apply', 'destroy'], 
                       help='Terraform action to perform')
    parser.add_argument('-c', '--config', required=True,
                       help='Configuration file path')
    
    args = parser.parse_args()
    
    # Implementation continues...

if __name__ == "__main__":
    main()
```

**PowerShell Script for Windows Terraform Automation:**
```powershell
# terraform-automation.ps1
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("plan", "apply", "destroy")]
    [string]$Action,
    
    [Parameter(Mandatory=$true)]
    [string]$Environment,
    
    [Parameter(Mandatory=$false)]
    [string]$WorkingDirectory = ".\infrastructure",
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoApprove
)

# Function to run Terraform commands
function Invoke-TerraformCommand {
    param(
        [string[]]$Arguments,
        [string]$WorkingDir = $WorkingDirectory
    )
    
    Write-Host "Running: terraform $($Arguments -join ' ')" -ForegroundColor Green
    
    try {
        $process = Start-Process -FilePath "terraform" -ArgumentList $Arguments -WorkingDirectory $WorkingDir -Wait -PassThru -NoNewWindow
        return $process.ExitCode -eq 0
    }
    catch {
        Write-Error "Error running terraform: $($_.Exception.Message)"
        return $false
    }
}

# Main execution logic
switch ($Action) {
    "plan" {
        $planArgs = @("plan", "-input=false", "-var-file=environments\$Environment.tfvars")
        Invoke-TerraformCommand $planArgs
    }
    "apply" {
        $applyArgs = @("apply", "-input=false", "-var-file=environments\$Environment.tfvars")
        if ($AutoApprove) { $applyArgs += "-auto-approve" }
        Invoke-TerraformCommand $applyArgs
    }
    "destroy" {
        $destroyArgs = @("destroy", "-input=false", "-var-file=environments\$Environment.tfvars")
        if ($AutoApprove) { $destroyArgs += "-auto-approve" }
        Invoke-TerraformCommand $destroyArgs
    }
}
```

**Advanced GitHub Actions Workflow:**
```yaml
# .github/workflows/terraform-advanced.yml
name: Advanced Terraform CI/CD Pipeline

on:
  push:
    branches: [main, develop]
    paths: ['infrastructure/**']
  pull_request:
    branches: [main]
    paths: ['infrastructure/**']

env:
  TF_VERSION: 1.5.7
  AWS_REGION: us-west-2

jobs:
  terraform-validate:
    name: Validate and Security Scan
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: infrastructure
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v2
      with:
        terraform_version: ${{ env.TF_VERSION }}
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}
    
    - name: Terraform Format Check
      run: terraform fmt -check -recursive
    
    - name: Terraform Init
      run: terraform init
    
    - name: Terraform Validate
      run: terraform validate
    
    - name: Run tfsec Security Scan
      uses: aquasecurity/tfsec-action@v1.0.3
      with:
        working_directory: infrastructure
        soft_fail: true
    
    - name: Cost Estimation with Infracost
      uses: infracost/actions/setup@v2
      with:
        api-key: ${{ secrets.INFRACOST_API_KEY }}
    
    - name: Generate Infracost diff
      run: |
        infracost breakdown --path=. \
          --format=json \
          --out-file=/tmp/infracost-base.json
    
    - name: Terraform Plan
      run: |
        terraform plan -var-file=environments/staging.tfvars -no-color -out=tfplan
      env:
        TF_VAR_environment: staging
    
    - name: Generate Plan Summary
      run: |
        terraform show -json tfplan > plan.json
        python3 ../scripts/plan_analyzer.py plan.json

  terraform-apply:
    name: Apply Terraform Changes
    needs: terraform-validate
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    environment: production
    defaults:
      run:
        working-directory: infrastructure
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v2
      with:
        terraform_version: ${{ env.TF_VERSION }}
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}
    
    - name: Terraform Init
      run: terraform init
    
    - name: Terraform Apply
      run: |
        terraform apply -var-file=environments/production.tfvars -auto-approve
      env:
        TF_VAR_environment: production
    
    - name: Extract Terraform Outputs
      run: terraform output -json > terraform-outputs.json
    
    - name: Post-deployment Tests
      run: |
        python3 ../scripts/post_deployment_tests.py terraform-outputs.json
    
    - name: Upload Outputs
      uses: actions/upload-artifact@v3
      with:
        name: terraform-outputs
        path: infrastructure/terraform-outputs.json
    
    - name: Notify Slack
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
      if: always()
```

**Bash Script for Multi-Environment Deployment:**
```bash
#!/bin/bash
# deploy-multi-env.sh
set -e

# Configuration
ENVIRONMENTS=("dev" "staging" "prod")
TERRAFORM_DIR="./infrastructure"
PARALLEL_DEPLOYMENTS=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to validate environment
validate_environment() {
    local env=$1
    local var_file="$TERRAFORM_DIR/environments/${env}.tfvars"
    
    if [[ ! -f "$var_file" ]]; then
        error "Variable file not found: $var_file"
        return 1
    fi
    
    log "Environment $env validated"
    return 0
}

# Function to deploy to single environment
deploy_environment() {
    local env=$1
    local action=${2:-plan}
    
    log "Starting $action for environment: $env"
    
    cd "$TERRAFORM_DIR"
    
    # Initialize Terraform
    terraform init -input=false
    
    # Select workspace
    terraform workspace select "$env" 2>/dev/null || terraform workspace new "$env"
    
    # Validate configuration
    if ! terraform validate; then
        error "Terraform validation failed for $env"
        return 1
    fi
    
    case $action in
        "plan")
            terraform plan -var-file="environments/${env}.tfvars" -out="${env}.tfplan"
            ;;
        "apply")
            if [[ -f "${env}.tfplan" ]]; then
                terraform apply -auto-approve "${env}.tfplan"
            else
                terraform apply -var-file="environments/${env}.tfvars" -auto-approve
            fi
            ;;
        "destroy")
            terraform destroy -var-file="environments/${env}.tfvars" -auto-approve
            ;;
        *)
            error "Unknown action: $action"
            return 1
            ;;
    esac
    
    log "$action completed for environment: $env"
    cd - > /dev/null
}

# Function to deploy all environments
deploy_all_environments() {
    local action=${1:-plan}
    
    if [[ "$PARALLEL_DEPLOYMENTS" == "true" ]]; then
        log "Starting parallel deployment..."
        
        for env in "${ENVIRONMENTS[@]}"; do
            (
                validate_environment "$env" && deploy_environment "$env" "$action"
            ) &
        done
        
        wait
        log "All parallel deployments completed"
    else
        log "Starting sequential deployment..."
        
        for env in "${ENVIRONMENTS[@]}"; do
            if validate_environment "$env"; then
                deploy_environment "$env" "$action"
            else
                error "Skipping deployment for $env due to validation failure"
            fi
        done
        
        log "All sequential deployments completed"
    fi
}

# Function to show deployment status
show_status() {
    log "Deployment Status Overview"
    echo "========================="
    
    for env in "${ENVIRONMENTS[@]}"; do
        cd "$TERRAFORM_DIR"
        
        if terraform workspace select "$env" 2>/dev/null; then
            echo -e "Environment: ${GREEN}$env${NC}"
            
            # Get workspace info
            terraform workspace show
            
            # Show last apply time if state exists
            if terraform state list >/dev/null 2>&1; then
                echo "  Resources: $(terraform state list | wc -l)"
                echo "  Last modified: $(terraform state pull | jq -r '.serial')"
            else
                echo "  Status: No resources deployed"
            fi
        else
            echo -e "Environment: ${RED}$env${NC} (not initialized)"
        fi
        
        echo ""
        cd - > /dev/null
    done
}

# Function to cleanup old plan files
cleanup() {
    log "Cleaning up temporary files..."
    find "$TERRAFORM_DIR" -name "*.tfplan" -delete
    log "Cleanup completed"
}

# Main function
main() {
    local action=${1:-plan}
    local environment=${2:-"all"}
    
    log "Multi-environment Terraform deployment script"
    log "Action: $action, Environment: $environment"
    
    # Validate Terraform installation
    if ! command -v terraform &> /dev/null; then
        error "Terraform is not installed or not in PATH"
        exit 1
    fi
    
    # Check if working directory exists
    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        error "Terraform directory not found: $TERRAFORM_DIR"
        exit 1
    fi
    
    case $environment in
        "all")
            deploy_all_environments "$action"
            ;;
        "status")
            show_status
            ;;
        *)
            if [[ " ${ENVIRONMENTS[*]} " =~ " $environment " ]]; then
                validate_environment "$environment" && deploy_environment "$environment" "$action"
            else
                error "Unknown environment: $environment"
                echo "Available environments: ${ENVIRONMENTS[*]}"
                exit 1
            fi
            ;;
    esac
    
    # Cleanup on success
    trap cleanup EXIT
}

# Usage information
usage() {
    echo "Usage: $0 [ACTION] [ENVIRONMENT]"
    echo ""
    echo "Actions:"
    echo "  plan     - Generate and show an execution plan"
    echo "  apply    - Apply the changes required to reach the desired state"
    echo "  destroy  - Destroy the Terraform-managed infrastructure"
    echo ""
    echo "Environments:"
    echo "  all      - All environments (${ENVIRONMENTS[*]})"
    echo "  status   - Show status of all environments"
    for env in "${ENVIRONMENTS[@]}"; do
        echo "  $env"
    done
    echo ""
    echo "Examples:"
    echo "  $0 plan dev              # Plan for dev environment"
    echo "  $0 apply all             # Apply to all environments"
    echo "  $0 status                # Show status of all environments"
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    "")
        usage
        exit 1
        ;;
    *)
        main "$@"
        ;;
esac
```