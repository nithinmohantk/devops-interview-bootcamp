# Cloud Exercises ☁️

Practical hands-on exercises for cloud architecture, migration, optimization, and multi-cloud management.

## 📋 Exercise Categories

- [🏗️ Cloud Architecture](#cloud-architecture) - Design and implement scalable cloud solutions
- [🔄 Cloud Migration](#cloud-migration) - Migrate applications and data to the cloud
- [⚡ Performance Optimization](#performance-optimization) - Optimize cloud resources and costs
- [🌐 Multi-Cloud Management](#multi-cloud-management) - Manage workloads across multiple cloud providers
- [📊 Cloud Monitoring](#cloud-monitoring) - Implement comprehensive cloud monitoring
- [🛡️ Cloud Security](#cloud-security) - Secure cloud infrastructures and workloads

---

## Cloud Architecture

### Exercise 1: Three-Tier Web Application on AWS

**Objective**: Design and implement a scalable three-tier web application architecture on AWS

**Requirements**:
- Web tier with load balancer and auto-scaling
- Application tier with multiple availability zones
- Database tier with read replicas and backup strategy
- Use Infrastructure as Code (Terraform)

**Time Limit**: 4 hours

**Deliverables**:

```hcl
# main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = var.aws_region
}

# VPC Configuration
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "three-tier-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "three-tier-igw"
  }
}

# Public Subnets for Web Tier
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-${count.index + 1}"
    Tier = "web"
  }
}

# Private Subnets for Application Tier
resource "aws_subnet" "private_app" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 10}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "private-app-subnet-${count.index + 1}"
    Tier = "application"
  }
}

# Private Subnets for Database Tier
resource "aws_subnet" "private_db" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.${count.index + 20}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "private-db-subnet-${count.index + 1}"
    Tier = "database"
  }
}

# Application Load Balancer
resource "aws_lb" "web" {
  name               = "three-tier-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false

  tags = {
    Name = "three-tier-alb"
  }
}

# Launch Template for Web Tier
resource "aws_launch_template" "web" {
  name_prefix   = "web-tier-"
  image_id      = data.aws_ami.amazon_linux.id
  instance_type = "t3.micro"
  
  vpc_security_group_ids = [aws_security_group.web.id]
  
  user_data = base64encode(templatefile("${path.module}/user_data/web_tier.sh", {
    app_lb_dns = aws_lb.app.dns_name
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "web-tier-instance"
      Tier = "web"
    }
  }
}

# Auto Scaling Group for Web Tier
resource "aws_autoscaling_group" "web" {
  name                = "web-tier-asg"
  vpc_zone_identifier = aws_subnet.public[*].id
  target_group_arns   = [aws_lb_target_group.web.arn]
  health_check_type   = "ELB"
  
  min_size         = 2
  max_size         = 6
  desired_capacity = 2

  launch_template {
    id      = aws_launch_template.web.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "web-tier-asg"
    propagate_at_launch = false
  }
}

# RDS Database
resource "aws_db_subnet_group" "main" {
  name       = "three-tier-db-subnet-group"
  subnet_ids = aws_subnet.private_db[*].id

  tags = {
    Name = "three-tier-db-subnet-group"
  }
}

resource "aws_db_instance" "main" {
  identifier             = "three-tier-db"
  allocated_storage      = 20
  max_allocated_storage  = 100
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  db_name                = "app_database"
  username               = var.db_username
  password               = var.db_password
  
  vpc_security_group_ids = [aws_security_group.database.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = true

  tags = {
    Name = "three-tier-database"
  }
}

# Read Replica
resource "aws_db_instance" "replica" {
  identifier                = "three-tier-db-replica"
  replicate_source_db       = aws_db_instance.main.identifier
  instance_class            = "db.t3.micro"
  publicly_accessible      = false
  auto_minor_version_upgrade = false
  
  tags = {
    Name = "three-tier-database-replica"
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}
```

**Expected Outcomes**:
- Functional three-tier architecture
- Auto-scaling web tier (2-6 instances)
- High availability across multiple AZs
- Secure database with read replica
- Load balancer with health checks

**Evaluation Criteria**:
- Infrastructure code quality
- Security best practices
- Cost optimization
- Documentation quality
- Performance considerations

---

## Cloud Migration

### Exercise 2: Legacy Application Migration to GCP

**Objective**: Migrate a legacy monolithic application to Google Cloud Platform using a phased approach

**Scenario**: You have a legacy e-commerce application with:
- Web frontend (PHP/Apache)
- Application server (Java/Tomcat)
- Database (MySQL)
- File storage (local filesystem)
- Background jobs (cron)

**Requirements**:
- Phase 1: Lift and shift to Compute Engine
- Phase 2: Modernize with Cloud SQL and Cloud Storage
- Phase 3: Containerize and deploy to GKE
- Implement monitoring and alerting

**Time Limit**: 8 hours

**Deliverables**:

```python
# migration-orchestrator.py
import os
import subprocess
import time
from google.cloud import storage
from google.cloud import sql_v1

class CloudMigrationOrchestrator:
    def __init__(self, project_id):
        self.project_id = project_id
        self.storage_client = storage.Client()
        self.sql_client = sql_v1.SqlInstancesServiceClient()
    
    def phase1_lift_and_shift(self):
        """Phase 1: Migrate to Compute Engine"""
        print("Starting Phase 1: Lift and Shift to Compute Engine")
        
        # Create VM instance
        subprocess.run([
            'gcloud', 'compute', 'instances', 'create', 'legacy-app-vm',
            '--zone=us-central1-a',
            '--machine-type=n1-standard-2',
            '--image-family=ubuntu-2004-lts',
            '--image-project=ubuntu-os-cloud',
            '--metadata-from-file=startup-script=startup.sh',
            '--tags=http-server,https-server'
        ])
        
        time.sleep(120)
        self.verify_application_health()
        print("Phase 1 completed successfully")
    
    def phase2_modernize_data(self):
        """Phase 2: Migrate to managed services"""
        print("Starting Phase 2: Migrating to Cloud SQL and Cloud Storage")
        
        # Create Cloud SQL instance
        subprocess.run([
            'gcloud', 'sql', 'instances', 'create', 'legacy-db',
            '--database-version=MYSQL_8_0',
            '--tier=db-n1-standard-2',
            '--region=us-central1'
        ])
        
        # Create storage bucket
        bucket = self.storage_client.create_bucket('legacy-app-storage')
        print(f"Created bucket: {bucket.name}")
        
        self.migrate_database()
        self.migrate_files_to_storage()
        print("Phase 2 completed successfully")
    
    def phase3_containerize(self):
        """Phase 3: Containerize and deploy to GKE"""
        print("Starting Phase 3: Containerization and GKE deployment")
        
        # Build container image
        subprocess.run([
            'gcloud', 'builds', 'submit', '--tag', 
            f'gcr.io/{self.project_id}/legacy-app:v1.0'
        ])
        
        # Create GKE cluster
        subprocess.run([
            'gcloud', 'container', 'clusters', 'create', 'legacy-cluster',
            '--zone=us-central1-a',
            '--num-nodes=3',
            '--machine-type=n1-standard-2'
        ])
        
        # Deploy to Kubernetes
        subprocess.run(['kubectl', 'apply', '-f', 'kubernetes-deployment.yaml'])
        print("Phase 3 completed successfully")

if __name__ == "__main__":
    orchestrator = CloudMigrationOrchestrator('your-project-id')
    
    try:
        orchestrator.phase1_lift_and_shift()
        orchestrator.phase2_modernize_data()
        orchestrator.phase3_containerize()
        print("Migration completed successfully!")
    except Exception as e:
        print(f"Migration failed: {e}")
```

---

## Performance Optimization

### Exercise 3: Auto-Scaling and Performance Tuning

**Objective**: Implement comprehensive auto-scaling and performance optimization

**Requirements**:
- Implement horizontal and vertical auto-scaling
- Set up performance monitoring
- Optimize database performance
- Implement caching strategies
- Create load testing scenarios

**Time Limit**: 6 hours

**Deliverables**:

```yaml
# horizontal-pod-autoscaler.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: web-app
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
      selectPolicy: Max
```

---

## Multi-Cloud Management

### Exercise 4: Multi-Cloud Deployment with Terraform

**Objective**: Deploy and manage applications across AWS, Azure, and GCP

**Requirements**:
- Deploy identical infrastructure on all three providers
- Implement cross-cloud networking
- Set up multi-cloud monitoring
- Create disaster recovery strategy

**Expected Outcomes**:
- Working infrastructure on AWS, Azure, and GCP
- Cross-cloud connectivity established
- Unified monitoring dashboard
- Cost comparison report

---

## Cloud Monitoring

### Exercise 5: Comprehensive Monitoring Setup

**Objective**: Implement end-to-end monitoring for a multi-tier application

**Requirements**:
- Infrastructure monitoring (CPU, memory, disk, network)
- Application performance monitoring (APM)
- Log aggregation and analysis
- Custom metrics and alerting
- SLA monitoring and reporting

**Expected Outcomes**:
- Grafana dashboard with all metrics
- Alerting rules configured
- Log analysis queries
- SLA compliance reports

---

## Cloud Security

### Exercise 6: Zero Trust Security Implementation

**Objective**: Implement Zero Trust security model for cloud infrastructure

**Requirements**:
- Identity and access management (IAM)
- Network security and micro-segmentation
- Data encryption at rest and in transit
- Security monitoring and incident response
- Compliance reporting

**Expected Outcomes**:
- Zero Trust architecture implemented
- Security policies enforced
- Audit logs and compliance reports
- Security monitoring dashboards

---

## 🎯 Interview Tips

### Technical Questions You Should Be Able to Answer:

1. **How would you design a highly available, scalable web application on AWS?**
2. **Explain the differences between horizontal and vertical scaling**
3. **How do you implement disaster recovery across multiple cloud regions?**
4. **What are the key considerations for cloud cost optimization?**
5. **How would you migrate a legacy application to microservices in the cloud?**

### Practical Demonstrations:

1. **Live Infrastructure Provisioning**: Write Terraform code live
2. **Troubleshooting**: Debug failed deployments and infrastructure issues
3. **Cost Analysis**: Calculate and optimize cloud costs
4. **Security Assessment**: Identify and fix security vulnerabilities

---

## 📚 Additional Resources

- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [Azure Architecture Center](https://docs.microsoft.com/en-us/azure/architecture/)
- [Google Cloud Architecture Framework](https://cloud.google.com/architecture/framework)
- [Terraform Documentation](https://www.terraform.io/docs)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
