# SRE Fundamentals 📊

## Core SRE Concepts

### 1. What is Site Reliability Engineering (SRE)?

**Answer:**
SRE is an engineering discipline that applies software engineering principles to infrastructure and operations problems to create scalable and reliable software systems.

**Core Philosophy:**
- **Engineering Approach**: Treat operations as a software problem
- **Automation**: Automate manual operational tasks
- **Reliability**: Balance feature velocity with system reliability
- **Measurement**: Use data-driven decisions for reliability

**SRE vs Traditional Operations:**

| Aspect | Traditional Ops | SRE |
|--------|----------------|-----|
| **Approach** | Manual processes | Engineering and automation |
| **Background** | System administration | Software engineering |
| **Focus** | Keeping systems running | Reliability engineering |
| **Scaling** | Add more people | Build better systems |
| **Change** | Risk averse | Managed risk taking |

**Key Responsibilities:**
- **Availability**: Ensure systems are available and performant
- **Latency**: Minimize system response times
- **Performance**: Optimize system efficiency
- **Efficiency**: Manage resource utilization
- **Change Management**: Enable safe, frequent releases
- **Monitoring**: Implement comprehensive observability
- **Emergency Response**: Handle incidents and outages
- **Capacity Planning**: Ensure adequate resources

### 2. What are Service Level Indicators (SLIs), Service Level Objectives (SLOs), and Service Level Agreements (SLAs)?

**Answer:**

**Service Level Indicators (SLIs):**
- **Definition**: Quantitative measures of service level
- **Examples**: Request latency, error rate, throughput, availability
- **Characteristics**: Measurable, meaningful, simple

**Common SLIs:**
```
Request Latency: 95th percentile latency < 100ms
Error Rate: (failed requests / total requests) < 0.1%
Availability: (successful requests / total requests) > 99.9%
Throughput: requests per second
```

**Service Level Objectives (SLOs):**
- **Definition**: Target values for SLIs over a specific time period
- **Purpose**: Define acceptable service reliability
- **Example**: "99.9% of requests will complete in under 100ms over a rolling 30-day period"

**Service Level Agreements (SLAs):**
- **Definition**: Business contract between service provider and customer
- **Consequences**: Financial penalties for not meeting SLAs
- **Relationship**: SLAs are typically less stringent than SLOs

**Hierarchy:**
```
SLA (99.5%) < SLO (99.9%) < Internal Target (99.95%)
```

### 3. What is an Error Budget?

**Answer:**
An error budget represents the amount of downtime or errors a service can have while still meeting its SLO.

**Calculation:**
```
Error Budget = 100% - SLO
If SLO = 99.9%, then Error Budget = 0.1%

For a 30-day period:
Total time = 30 × 24 × 60 = 43,200 minutes
Error budget = 43,200 × 0.001 = 43.2 minutes
```

**Error Budget Policy:**
- **Budget Available**: Continue normal feature development
- **Budget Exhausted**: Freeze feature releases, focus on reliability
- **Budget Burn Rate**: Monitor consumption rate

**Benefits:**
- **Shared Incentives**: Aligns development and operations goals
- **Data-Driven Decisions**: Objective reliability vs. feature tradeoffs
- **Risk Management**: Quantified approach to taking risks
- **Innovation Balance**: Prevents both excessive caution and recklessness

**Example Policy:**
```yaml
error_budget_policy:
  slo: 99.9%
  measurement_window: 30 days
  actions:
    - threshold: 0%
      action: "Feature freeze, all hands on reliability"
    - threshold: 25%
      action: "Reliability review for all releases"
    - threshold: 50%
      action: "Additional monitoring and testing"
```

### 4. What is toil in SRE context?

**Answer:**
Toil is manual, repetitive, automatable work that scales linearly with service size and has no long-term value.

**Characteristics of Toil:**
- **Manual**: Requires human intervention
- **Repetitive**: Same work performed repeatedly
- **Automatable**: Could be automated with engineering effort
- **Tactical**: Reactive rather than strategic
- **No Value**: Doesn't provide lasting improvement
- **Linear Growth**: Scales with service size

**Examples of Toil:**
- **Manual Deployments**: Clicking through deployment steps
- **Ticket Response**: Manually processing routine requests
- **Log Analysis**: Manual log investigation for common issues
- **Capacity Management**: Manual resource provisioning
- **Configuration Updates**: Manual configuration changes

**Toil Reduction Strategies:**
- **Automation**: Automate repetitive tasks
- **Self-Service**: Enable users to solve their own problems
- **Better Tooling**: Improve existing tools and processes
- **Documentation**: Reduce knowledge transfer overhead
- **Process Improvement**: Eliminate unnecessary work

**Measuring Toil:**
```
Toil Percentage = (Toil Hours / Total Work Hours) × 100%
Target: < 50% of SRE time should be spent on toil
```

### 5. What are the key principles of incident management?

**Answer:**

**Incident Response Phases:**

**1. Detection:**
- **Automated Alerting**: Systems detect and alert on issues
- **Manual Discovery**: Users or employees report problems
- **Monitoring**: Proactive monitoring identifies degradation

**2. Response:**
- **Incident Commander**: Single point of coordination
- **Communication**: Clear, frequent status updates
- **Mitigation**: Focus on restoring service, not finding root cause

**3. Recovery:**
- **Service Restoration**: Return to normal operation
- **Monitoring**: Verify full recovery
- **Communication**: Notify stakeholders of resolution

**4. Post-Incident:**
- **Postmortem**: Blameless analysis of incident
- **Action Items**: Specific improvements to prevent recurrence
- **Documentation**: Update runbooks and procedures

**Incident Roles:**

**Incident Commander:**
- **Responsibilities**: Coordinate response, make decisions
- **Authority**: Override normal processes during incidents
- **Communication**: Single source of truth for incident status

**Technical Lead:**
- **Responsibilities**: Hands-on technical investigation and fixes
- **Focus**: Root cause analysis and remediation
- **Coordination**: Work with Incident Commander on strategy

**Communications Lead:**
- **Responsibilities**: External and internal communications
- **Stakeholders**: Customers, executives, support teams
- **Updates**: Regular status updates and final resolution notice

### 6. What makes a good postmortem?

**Answer:**
A good postmortem facilitates learning and prevents incident recurrence through blameless analysis.

**Key Elements:**

**Timeline:**
- **Chronological sequence** of events
- **Decision points** and actions taken
- **Detection and response times**
- **External factors** and dependencies

**Root Cause Analysis:**
- **Contributing factors** that led to the incident
- **System weaknesses** that allowed the incident
- **Process gaps** that delayed detection or response

**Action Items:**
- **Specific, actionable** improvements
- **Clear ownership** and deadlines
- **Prevention** and **detection** improvements
- **Follow-up** tracking and verification

**Blameless Culture:**
- **Focus on systems** not individuals
- **Learning opportunity** not punishment
- **Psychological safety** to share information
- **Process improvement** over blame assignment

**Example Structure:**
```markdown
# Postmortem: Service Outage on 2024-01-15

## Summary
30-minute outage affecting 15% of users due to database connection pool exhaustion

## Timeline
- 14:00: Deploy v2.3.4 with new feature
- 14:15: Connection pool exhaustion begins
- 14:20: First customer reports errors
- 14:25: Monitoring alerts trigger
- 14:30: Incident declared, rollback initiated
- 14:45: Service fully restored

## Root Cause
New feature created 10x more database connections than expected

## Action Items
1. [ ] Add connection pool monitoring (Owner: DB Team, Due: 2024-01-30)
2. [ ] Load testing for DB connections (Owner: SRE, Due: 2024-02-15)
3. [ ] Circuit breaker implementation (Owner: Dev Team, Due: 2024-02-28)
```

### 7. What is chaos engineering?

**Answer:**
Chaos engineering is the discipline of experimenting on systems to build confidence in their capability to withstand turbulent conditions.

**Principles:**
- **Build Hypothesis**: Define steady state behavior
- **Vary Real-World Events**: Simulate realistic failure scenarios
- **Run Experiments**: Controlled experiments in production
- **Minimize Blast Radius**: Limit impact of experiments
- **Automate**: Run experiments continuously

**Chaos Experiments:**

**Infrastructure Level:**
- **Server Failures**: Randomly terminate instances
- **Network Partitions**: Simulate network splits
- **Resource Exhaustion**: CPU, memory, disk pressure
- **Clock Skew**: Time synchronization issues

**Application Level:**
- **Service Dependencies**: Simulate downstream service failures
- **Database Issues**: Connection failures, slow queries
- **Third-Party APIs**: External service degradation
- **Data Corruption**: Simulate corrupt data scenarios

**Implementation:**
```yaml
# Chaos Monkey experiment
experiment:
  name: "ec2-instance-termination"
  description: "Randomly terminate EC2 instances"
  steady_state:
    - title: "Service is available"
      provider: "http"
      url: "https://api.example.com/health"
      expected_status: 200
  method:
    - title: "Terminate random EC2 instance"
      provider: "aws"
      type: "ec2-terminate-instance"
      filters:
        - tag: "Environment=Production"
```

**Tools:**
- **Chaos Monkey**: Instance termination (Netflix)
- **Litmus**: Kubernetes chaos engineering
- **Gremlin**: Comprehensive chaos engineering platform
- **Chaos Toolkit**: Open-source chaos engineering

### 8. What is observability and how does it differ from monitoring?

**Answer:**

**Monitoring:**
- **Definition**: Collecting and alerting on known failure modes
- **Approach**: Predefined metrics and dashboards
- **Questions**: "Is the system working?"
- **Scope**: Known knowns and known unknowns

**Observability:**
- **Definition**: Understanding internal system state from external outputs
- **Approach**: Exploratory analysis of system behavior
- **Questions**: "Why is the system behaving this way?"
- **Scope**: Unknown unknowns and emergent behaviors

**Three Pillars of Observability:**

**1. Metrics:**
- **Time-series data** aggregated over time
- **Examples**: CPU utilization, request rate, error count
- **Use Cases**: Alerting, trending, capacity planning

**2. Logs:**
- **Discrete events** with timestamp and context
- **Examples**: Application logs, audit logs, error logs
- **Use Cases**: Debugging, compliance, root cause analysis

**3. Traces:**
- **Request path** through distributed systems
- **Examples**: Microservice call chains, database queries
- **Use Cases**: Performance optimization, dependency mapping

**Modern Additions:**

**4. Events:**
- **Discrete occurrences** in the system
- **Examples**: Deployments, configuration changes, user actions
- **Use Cases**: Correlation analysis, change tracking

**Implementation Stack:**
```yaml
observability_stack:
  metrics:
    - prometheus
    - grafana
  logs:
    - elasticsearch
    - logstash
    - kibana
  traces:
    - jaeger
    - zipkin
  apm:
    - new_relic
    - datadog
```

### 9. What is capacity planning in SRE?

**Answer:**
Capacity planning ensures systems have adequate resources to handle expected load while maintaining SLOs.

**Key Components:**

**Demand Forecasting:**
- **Historical Analysis**: Past usage patterns and growth trends
- **Business Planning**: Expected feature launches and marketing campaigns
- **Seasonal Patterns**: Holiday traffic, business cycles
- **External Factors**: Market events, competitive actions

**Resource Planning:**
- **Compute Capacity**: CPU, memory, network bandwidth
- **Storage Capacity**: Disk space, database capacity
- **Network Capacity**: Bandwidth, connection limits
- **Third-Party Services**: API rate limits, SaaS quotas

**Capacity Models:**

**Linear Growth Model:**
```
Required Capacity = Current Usage × (1 + Growth Rate) × Safety Factor
```

**Organic Growth Model:**
```python
def capacity_forecast(current_load, growth_rate, time_period, safety_factor=1.2):
    future_load = current_load * (1 + growth_rate) ** time_period
    return future_load * safety_factor
```

**Planning Process:**
1. **Collect Data**: Historical usage, growth trends
2. **Forecast Demand**: Predict future resource needs
3. **Plan Provisioning**: When and how much to add
4. **Monitor and Adjust**: Track actual vs. predicted usage

**Headroom Planning:**
- **Safety Margin**: Buffer for unexpected growth
- **Lead Time**: Time to provision new resources
- **Redundancy**: Additional capacity for failures

### 10. What are SRE team models and structures?

**Answer:**

**Team Models:**

**1. Kitchen Sink SRE:**
- **Description**: SRE team responsible for everything
- **Pros**: Clear ownership, full control
- **Cons**: Doesn't scale, becomes operational bottleneck
- **Best For**: Small organizations, single critical service

**2. Infrastructure SRE:**
- **Description**: SRE manages shared infrastructure platforms
- **Pros**: Enables product teams, economies of scale
- **Cons**: Platform may not meet all needs
- **Best For**: Large organizations with many services

**3. Embedded SRE:**
- **Description**: SRE engineers embedded in product teams
- **Pros**: Deep product knowledge, aligned incentives
- **Cons**: Diluted SRE expertise, inconsistent practices
- **Best For**: Critical products requiring dedicated focus

**4. Consulting SRE:**
- **Description**: SRE provides guidance and tools to product teams
- **Pros**: Scales SRE knowledge, maintains product ownership
- **Cons**: Less hands-on control, requires mature teams
- **Best For**: Organizations transitioning to SRE

**Organizational Patterns:**

**SRE Rotation:**
- **On-call rotations** with defined responsibilities
- **Primary/Secondary** on-call structure
- **Follow-the-sun** coverage for global services

**Collaboration Models:**
- **SLO Reviews**: Regular service reliability assessments
- **Postmortem Reviews**: Cross-team learning sessions
- **Architecture Reviews**: SRE input on system design
- **Capacity Planning**: Joint planning with product teams

**Skills and Responsibilities:**
- **Software Engineering**: 50-60% of time on engineering
- **Systems Engineering**: Understanding of system architecture
- **Automation**: Building tools and reducing toil
- **Incident Response**: On-call and emergency response
- **Monitoring**: Observability and alerting systems