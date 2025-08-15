# Cloud Fundamentals 📚

## Core Cloud Concepts

### 1. What are the main cloud service models?

**Answer:**

**Infrastructure as a Service (IaaS):**
- **Definition**: Virtualized computing resources over the internet
- **Examples**: AWS EC2, Azure VMs, Google Compute Engine
- **Responsibility**: OS, runtime, applications (customer), hardware, networking (provider)
- **Use Cases**: Lift-and-shift migrations, development environments

**Platform as a Service (PaaS):**
- **Definition**: Application development and deployment platform
- **Examples**: AWS Elastic Beanstalk, Azure App Service, Google App Engine
- **Responsibility**: Applications and data (customer), OS, runtime, middleware (provider)
- **Use Cases**: Web applications, APIs, microservices

**Software as a Service (SaaS):**
- **Definition**: Ready-to-use software applications
- **Examples**: Office 365, Salesforce, Gmail
- **Responsibility**: Configuration (customer), everything else (provider)
- **Use Cases**: Email, CRM, productivity tools

### 2. What are the cloud deployment models?

**Answer:**

**Public Cloud:**
- **Definition**: Services offered over public internet
- **Advantages**: Cost-effective, scalable, no maintenance
- **Disadvantages**: Less control, security concerns
- **Examples**: AWS, Azure, GCP

**Private Cloud:**
- **Definition**: Dedicated cloud infrastructure for single organization
- **Advantages**: Better security, compliance, control
- **Disadvantages**: Higher costs, maintenance overhead
- **Examples**: VMware vSphere, OpenStack

**Hybrid Cloud:**
- **Definition**: Combination of public and private clouds
- **Advantages**: Flexibility, cost optimization, compliance
- **Disadvantages**: Complexity, integration challenges
- **Use Cases**: Burst to cloud, data sovereignty

**Multi-Cloud:**
- **Definition**: Using multiple cloud providers
- **Advantages**: Avoid vendor lock-in, best-of-breed services
- **Disadvantages**: Complexity, management overhead
- **Strategy**: Risk mitigation, optimization

### 3. What is cloud-native architecture?

**Answer:**
Cloud-native architecture leverages cloud computing advantages to build and run scalable applications.

**Key Principles:**
- **Microservices**: Loosely coupled, independently deployable services
- **Containers**: Lightweight, portable application packaging
- **DevOps**: Continuous integration and delivery
- **Automation**: Infrastructure as code, automated scaling

**12-Factor App Principles:**
1. **Codebase**: One codebase in version control
2. **Dependencies**: Explicitly declare dependencies
3. **Config**: Store config in environment
4. **Backing Services**: Treat as attached resources
5. **Build/Release/Run**: Separate stages
6. **Processes**: Execute as stateless processes
7. **Port Binding**: Export services via port binding
8. **Concurrency**: Scale via process model
9. **Disposability**: Fast startup and shutdown
10. **Dev/Prod Parity**: Keep environments similar
11. **Logs**: Treat logs as event streams
12. **Admin Processes**: Run as one-off processes

### 4. What is serverless computing?

**Answer:**
Serverless is a cloud execution model where the cloud provider manages server provisioning and scaling.

**Characteristics:**
- **Event-driven**: Functions triggered by events
- **Stateless**: No persistent server state
- **Auto-scaling**: Automatic scaling based on demand
- **Pay-per-use**: Pay only for execution time

**Services:**
- **Function as a Service (FaaS)**: AWS Lambda, Azure Functions
- **Backend as a Service (BaaS)**: Firebase, AWS Amplify
- **Serverless Containers**: AWS Fargate, Azure Container Instances

**Benefits:**
- **Cost Efficiency**: No idle time charges
- **Scalability**: Automatic scaling
- **Reduced Operations**: No server management
- **Faster Development**: Focus on business logic

**Limitations:**
- **Cold Starts**: Initial latency
- **Vendor Lock-in**: Platform-specific APIs
- **Limited Runtime**: Execution time limits
- **Debugging Complexity**: Distributed system challenges

### 5. What is edge computing?

**Answer:**
Edge computing brings computation and data storage closer to users to reduce latency and bandwidth usage.

**Key Concepts:**
- **Edge Locations**: Data centers closer to users
- **Content Delivery**: Static and dynamic content
- **Computing at Edge**: Processing near data source
- **Reduced Latency**: Faster response times

**Cloud Edge Services:**
- **AWS CloudFront**: CDN with edge computing
- **Azure CDN**: Content delivery network
- **Google Cloud CDN**: Global content delivery
- **AWS Lambda@Edge**: Serverless at edge

**Use Cases:**
- **Content Delivery**: Static websites, media streaming
- **IoT Processing**: Real-time sensor data processing
- **Mobile Applications**: Reduced app latency
- **Gaming**: Low-latency gaming experiences

## Cloud Architecture Patterns

### 6. What are common cloud architecture patterns?

**Answer:**

**Auto Scaling Pattern:**
- **Purpose**: Automatically adjust resources based on demand
- **Implementation**: Load balancers + auto scaling groups
- **Benefits**: Cost optimization, performance consistency

**Circuit Breaker Pattern:**
- **Purpose**: Prevent cascade failures in distributed systems
- **Implementation**: Monitor service health, fail fast
- **Benefits**: System stability, graceful degradation

**Bulkhead Pattern:**
- **Purpose**: Isolate critical resources
- **Implementation**: Separate connection pools, thread pools
- **Benefits**: Fault isolation, improved reliability

**Event Sourcing Pattern:**
- **Purpose**: Store state changes as events
- **Implementation**: Event store + event replay
- **Benefits**: Audit trail, temporal queries, rebuild state

### 7. What is the Well-Architected Framework?

**Answer:**
Well-Architected Framework provides guidance for building secure, reliable, efficient cloud architectures.

**Five Pillars:**

**1. Operational Excellence:**
- **Principles**: Operations as code, frequent small changes
- **Key Practices**: Automation, monitoring, documentation
- **Tools**: CloudFormation, CloudWatch, AWS Config

**2. Security:**
- **Principles**: Defense in depth, least privilege
- **Key Practices**: Identity management, data encryption
- **Tools**: IAM, KMS, Security Groups

**3. Reliability:**
- **Principles**: Recover from failures, scale horizontally
- **Key Practices**: Multi-AZ deployments, backup strategies
- **Tools**: Auto Scaling, RDS Multi-AZ, ELB

**4. Performance Efficiency:**
- **Principles**: Democratize advanced technologies
- **Key Practices**: Right-sizing, caching, monitoring
- **Tools**: CloudFront, ElastiCache, CloudWatch

**5. Cost Optimization:**
- **Principles**: Pay for what you need
- **Key Practices**: Right-sizing, reserved instances
- **Tools**: Cost Explorer, Trusted Advisor, Spot Instances

### 8. What is disaster recovery in the cloud?

**Answer:**
Disaster recovery (DR) ensures business continuity during outages or disasters.

**RTO vs RPO:**
- **RTO (Recovery Time Objective)**: Maximum downtime
- **RPO (Recovery Point Objective)**: Maximum data loss

**DR Strategies:**

**1. Backup and Restore:**
- **RTO**: Hours to days
- **RPO**: Hours
- **Cost**: Low
- **Use Case**: Non-critical applications

**2. Pilot Light:**
- **RTO**: Minutes to hours
- **RPO**: Minutes
- **Cost**: Medium
- **Use Case**: Core systems running minimal

**3. Warm Standby:**
- **RTO**: Minutes
- **RPO**: Minutes
- **Cost**: Medium-High
- **Use Case**: Scaled-down replica running

**4. Multi-Site Active/Active:**
- **RTO**: Seconds to minutes
- **RPO**: Near-zero
- **Cost**: High
- **Use Case**: Mission-critical applications

## Cloud Migration

### 9. What are the main cloud migration strategies (6 Rs)?

**Answer:**

**1. Rehost (Lift and Shift):**
- **Definition**: Move applications without changes
- **Benefits**: Fast migration, minimal risk
- **Drawbacks**: No cloud optimization
- **Use Case**: Legacy applications, time constraints

**2. Replatform (Lift, Tinker, and Shift):**
- **Definition**: Minor optimizations for cloud
- **Benefits**: Some cloud benefits, manageable changes
- **Drawbacks**: Limited optimization
- **Use Case**: Database migrations, managed services

**3. Repurchase (Drop and Shop):**
- **Definition**: Move to SaaS solution
- **Benefits**: Reduced maintenance, modern features
- **Drawbacks**: Feature gaps, vendor lock-in
- **Use Case**: CRM, ERP, email systems

**4. Refactor/Re-architect:**
- **Definition**: Redesign for cloud-native
- **Benefits**: Full cloud benefits, scalability
- **Drawbacks**: High effort, risk
- **Use Case**: Business-critical applications

**5. Retire:**
- **Definition**: Shut down unused applications
- **Benefits**: Cost savings, reduced complexity
- **Use Case**: Redundant or obsolete systems

**6. Retain (Revisit):**
- **Definition**: Keep on-premises for now
- **Benefits**: No migration risks
- **Use Case**: Compliance requirements, recent investments

### 10. What factors should be considered for cloud migration?

**Answer:**

**Technical Factors:**
- **Application Dependencies**: Database, integrations
- **Performance Requirements**: Latency, throughput
- **Compliance**: Data residency, regulations
- **Security**: Data classification, access controls

**Business Factors:**
- **Cost**: Migration cost vs. ongoing savings
- **Timeline**: Business deadlines, resource availability
- **Risk Tolerance**: Acceptable downtime, rollback plans
- **Skills**: Team expertise, training needs

**Assessment Tools:**
- **AWS Application Discovery Service**: Inventory and dependencies
- **Azure Migrate**: Assessment and migration planning
- **Google Cloud Migration Center**: Migration guidance

**Migration Phases:**
1. **Assessment**: Current state analysis
2. **Planning**: Migration strategy and timeline
3. **Pilot**: Small-scale migration test
4. **Migration**: Full-scale migration execution
5. **Optimization**: Post-migration improvements