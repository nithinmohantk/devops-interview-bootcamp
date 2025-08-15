# Real-World SRE Scenarios 🎯

## Production Incident Scenarios

### 1. E-commerce Platform Black Friday Outage

**Scenario:**
It's Black Friday at 2 PM EST, your e-commerce platform is experiencing 10x normal traffic (500K concurrent users), and the checkout service is failing with timeouts. Error rate has spiked to 15%, and the business is losing $50K per minute.

**Your Investigation and Response:**

```python
# Incident Response Timeline and Actions

import time
from datetime import datetime
from typing import Dict, List, Any

class BlackFridayIncidentResponse:
    def __init__(self):
        self.incident_id = "INC-2024-BF-001"
        self.severity = "P0"  # Business critical
        self.start_time = datetime.now()
        self.timeline = []
        self.metrics = {}
        
    def minute_0_detection(self):
        """Initial incident detection"""
        
        # Monitoring alerts fired
        alerts = [
            "Checkout service error rate > 10% for 5 minutes",
            "Payment processing latency > 5 seconds",
            "Customer complaints spiking on social media"
        ]
        
        self.timeline.append({
            'time': '14:00',
            'action': 'Incident detected via monitoring alerts',
            'details': alerts,
            'responder': 'automated_monitoring'
        })
        
        # Immediate triage questions
        triage_questions = [
            "What changed recently?",
            "Is this affecting all users or specific segments?", 
            "Are other services impacted?",
            "What's our current capacity vs load?"
        ]
        
        return triage_questions
    
    def minute_2_initial_assessment(self):
        """Quick damage assessment"""
        
        assessment = {
            'affected_users': '~200K users unable to checkout',
            'business_impact': '$100K revenue at risk',
            'systems_affected': ['checkout-service', 'payment-gateway', 'inventory-service'],
            'geographic_impact': 'US and Canada primarily',
            'error_patterns': [
                '95% database timeout errors',
                '5% payment gateway failures'
            ]
        }
        
        self.timeline.append({
            'time': '14:02',
            'action': 'Initial impact assessment completed',
            'details': assessment,
            'responder': 'incident_commander'
        })
        
        return assessment
    
    def minute_5_hypothesis_formation(self):
        """Form initial hypothesis based on symptoms"""
        
        # Analyze symptoms
        symptoms = {
            'primary': 'Database connection timeouts in checkout service',
            'secondary': 'High CPU usage on database servers',
            'tertiary': 'Queue backup in payment processing'
        }
        
        # Check recent changes
        recent_changes = [
            "Deployed checkout-service v2.1.3 at 13:45 (15 min ago)",
            "Database maintenance window completed at 12:00",
            "Added Black Friday promotional pricing rules at 13:30"
        ]
        
        # Initial hypothesis
        hypothesis = """
        PRIMARY HYPOTHESIS: Database connection pool exhaustion
        - New checkout service version may have connection leak
        - 10x traffic hitting connection limits
        - Promotional pricing rules adding DB query complexity
        
        SECONDARY HYPOTHESIS: Insufficient database capacity
        - Black Friday load exceeding planned capacity
        - Database servers reaching resource limits
        """
        
        self.timeline.append({
            'time': '14:05',
            'action': 'Hypothesis formed',
            'details': {'symptoms': symptoms, 'changes': recent_changes, 'hypothesis': hypothesis},
            'responder': 'sre_team'
        })
        
        return hypothesis
    
    def minute_8_immediate_mitigation(self):
        """Quick wins to reduce impact"""
        
        immediate_actions = [
            {
                'action': 'Scale up checkout service instances',
                'command': 'kubectl scale deployment checkout-service --replicas=20',
                'expected_impact': 'Distribute load, reduce per-instance connection pressure',
                'risk': 'May worsen connection pool exhaustion'
            },
            {
                'action': 'Enable read replicas for checkout queries',
                'command': 'Update checkout service config to use read replicas',
                'expected_impact': 'Reduce load on primary database',
                'risk': 'Read lag could cause data inconsistency'
            },
            {
                'action': 'Increase database connection pool limits',
                'command': 'Update DB config: max_connections=500 (from 200)',
                'expected_impact': 'Allow more concurrent connections',
                'risk': 'Could overwhelm database server resources'
            }
        ]
        
        # Execute highest-impact, lowest-risk action first
        selected_action = immediate_actions[1]  # Read replicas
        
        self.timeline.append({
            'time': '14:08',
            'action': f"Implementing immediate mitigation: {selected_action['action']}",
            'details': selected_action,
            'responder': 'sre_engineer'
        })
        
        return selected_action
    
    def minute_15_detailed_investigation(self):
        """Deep dive investigation while mitigation is in progress"""
        
        investigation_findings = {
            'database_analysis': {
                'connection_usage': '190/200 connections in use (95%)',
                'slow_queries': [
                    'SELECT * FROM products WHERE category_id IN (...) - 2.3s avg',
                    'UPDATE inventory SET quantity = ... - 1.8s avg'
                ],
                'lock_analysis': '15 table locks detected on inventory table',
                'resource_usage': 'CPU: 85%, Memory: 78%, Disk I/O: 92%'
            },
            
            'application_analysis': {
                'new_deployment_diff': {
                    'added_features': ['real-time inventory validation', 'complex pricing calculations'],
                    'database_queries': 'Increased from 3 to 8 queries per checkout attempt',
                    'connection_handling': 'No obvious connection leaks in code'
                },
                'traffic_patterns': {
                    'requests_per_second': '15,000 (normal: 1,500)',
                    'checkout_attempts': '8,000/min (normal: 800/min)',
                    'conversion_rate': '2% (normal: 12%) - broken funnel'
                }
            },
            
            'infrastructure_analysis': {
                'load_balancer': 'Healthy, distributing traffic evenly',
                'kubernetes_cluster': 'Node utilization at 45%, plenty of capacity',
                'network': 'No packet loss detected',
                'external_dependencies': 'Payment gateway reporting normal operation'
            }
        }
        
        # Root cause identified
        root_cause = """
        ROOT CAUSE: Feature introduced in v2.1.3 performs real-time inventory 
        validation using complex queries that lock inventory table. Under 10x load,
        these locks cascade causing connection pool exhaustion.
        
        CONTRIBUTING FACTORS:
        1. New feature not load tested at Black Friday scale
        2. Database connection pool size not increased for new query patterns
        3. Inventory table not optimized for high-concurrency reads
        """
        
        self.timeline.append({
            'time': '14:15',
            'action': 'Root cause identified',
            'details': {'investigation': investigation_findings, 'root_cause': root_cause},
            'responder': 'sre_team'
        })
        
        return root_cause
    
    def minute_20_implement_fix(self):
        """Implement targeted fix based on root cause"""
        
        fix_options = [
            {
                'option': 'Quick rollback to v2.1.2',
                'implementation_time': '5 minutes',
                'risk': 'Lose new Black Friday features',
                'impact': 'Should restore service immediately'
            },
            {
                'option': 'Disable real-time inventory validation',
                'implementation_time': '2 minutes',
                'risk': 'May oversell some items',
                'impact': 'Reduce database load significantly'
            },
            {
                'option': 'Optimize inventory queries + increase connection pool',
                'implementation_time': '15 minutes',
                'risk': 'May not be fast enough',
                'impact': 'Full fix while keeping features'
            }
        ]
        
        # Choose fastest, safest fix
        chosen_fix = fix_options[1]  # Disable real-time validation
        
        implementation_steps = [
            "Deploy feature flag to disable real-time inventory validation",
            "Increase database connection pool to 400 connections",
            "Monitor error rates and response times",
            "Prepare rollback if fix doesn't work"
        ]
        
        self.timeline.append({
            'time': '14:20',
            'action': 'Implementing targeted fix',
            'details': {'chosen_fix': chosen_fix, 'steps': implementation_steps},
            'responder': 'development_team'
        })
        
        return chosen_fix
    
    def minute_25_monitor_recovery(self):
        """Monitor system recovery after fix"""
        
        recovery_metrics = {
            'error_rate': {
                'before_fix': '15%',
                'after_fix': '2%',
                'target': '<1%'
            },
            'response_time': {
                'before_fix': '8.5s p95',
                'after_fix': '1.2s p95', 
                'target': '<2s p95'
            },
            'database_connections': {
                'before_fix': '190/200 (95%)',
                'after_fix': '120/400 (30%)',
                'target': '<80%'
            },
            'business_metrics': {
                'checkout_success_rate': 'Recovered to 95% (from 45%)',
                'revenue_per_minute': '$45K (approaching normal $50K)',
                'customer_complaints': 'Decreasing rapidly'
            }
        }
        
        self.timeline.append({
            'time': '14:25',
            'action': 'System recovery confirmed',
            'details': recovery_metrics,
            'responder': 'monitoring_team'
        })
        
        return recovery_metrics
    
    def minute_30_incident_closure(self):
        """Close incident and plan follow-up"""
        
        closure_summary = {
            'incident_duration': '30 minutes',
            'resolution': 'Disabled real-time inventory validation via feature flag',
            'business_impact': {
                'estimated_revenue_loss': '$150K',
                'affected_customers': '~50K checkout attempts failed',
                'reputation_impact': 'Moderate - Black Friday issues reported on social media'
            },
            'immediate_follow_up': [
                'Deploy proper fix with optimized queries by 16:00',
                'Re-enable inventory validation with circuit breaker',
                'Scale database cluster for evening traffic spike'
            ]
        }
        
        self.timeline.append({
            'time': '14:30',
            'action': 'Incident closed',
            'details': closure_summary,
            'responder': 'incident_commander'
        })
        
        return closure_summary
    
    def generate_post_mortem_items(self):
        """Generate action items for post-mortem"""
        
        action_items = [
            {
                'item': 'Implement load testing for all Black Friday features',
                'owner': 'QA Team',
                'due_date': '2024-01-15',
                'priority': 'High'
            },
            {
                'item': 'Add database connection pool monitoring and alerting',
                'owner': 'SRE Team', 
                'due_date': '2024-01-10',
                'priority': 'High'
            },
            {
                'item': 'Create circuit breaker for inventory validation service',
                'owner': 'Backend Team',
                'due_date': '2024-01-20',
                'priority': 'Medium'
            },
            {
                'item': 'Optimize inventory table for high-concurrency workloads',
                'owner': 'DBA Team',
                'due_date': '2024-02-01', 
                'priority': 'Medium'
            },
            {
                'item': 'Establish Black Friday specific capacity planning',
                'owner': 'SRE Team',
                'due_date': '2024-08-01',
                'priority': 'High'
            }
        ]
        
        return action_items
```

**Key Learning Points:**
- **Speed vs. Accuracy**: Balance quick mitigation with proper investigation
- **Business Context**: $50K/minute loss drives decision-making urgency
- **Feature Flags**: Critical for quick feature rollbacks without deployments
- **Load Testing**: Complex features need testing at scale
- **Monitoring Gaps**: Connection pool utilization monitoring was missing

---

### 2. Multi-Region Service Degradation

**Scenario:**
Your globally distributed application is experiencing inconsistent performance across regions. Users in Europe report 10-second load times while US users see normal performance. The issue started 2 hours ago and affects 30% of your user base.

**Investigation Approach:**

```python
class MultiRegionIncidentAnalysis:
    def __init__(self):
        self.regions = ['us-east-1', 'eu-west-1', 'ap-southeast-1']
        self.affected_regions = ['eu-west-1']
        self.services = ['web-api', 'user-service', 'content-service', 'database']
        
    def analyze_regional_performance(self):
        """Analyze performance across all regions"""
        
        regional_metrics = {
            'us-east-1': {
                'response_time_p95': '150ms',
                'error_rate': '0.2%',
                'throughput': '5000 rps',
                'cpu_utilization': '45%',
                'memory_utilization': '60%',
                'database_latency': '25ms'
            },
            'eu-west-1': {
                'response_time_p95': '8500ms',  # Problem region
                'error_rate': '12%',
                'throughput': '800 rps',  # Much lower
                'cpu_utilization': '85%',  # High
                'memory_utilization': '78%',
                'database_latency': '2500ms'  # Very high
            },
            'ap-southeast-1': {
                'response_time_p95': '180ms',
                'error_rate': '0.3%',
                'throughput': '2000 rps',
                'cpu_utilization': '50%',
                'memory_utilization': '65%',
                'database_latency': '45ms'
            }
        }
        
        # Identify the pattern
        analysis = self._analyze_performance_pattern(regional_metrics)
        return regional_metrics, analysis
    
    def _analyze_performance_pattern(self, metrics):
        """Analyze the performance degradation pattern"""
        
        patterns = {
            'isolated_to_eu': True,
            'database_latency_correlation': True,
            'throughput_drop_correlation': True,
            'resource_exhaustion_signs': True
        }
        
        hypothesis = """
        PATTERN ANALYSIS:
        1. Issue isolated to EU region only
        2. Database latency 100x higher in EU
        3. Throughput dropped 85% in EU
        4. CPU/Memory utilization high in EU
        
        LIKELY CAUSES:
        - Database connectivity issue in EU
        - Network partition between EU services and DB
        - Database replication lag in EU
        - EU-specific infrastructure problem
        """
        
        return {
            'patterns': patterns,
            'hypothesis': hypothesis,
            'next_steps': [
                'Check database replication status',
                'Analyze network connectivity between EU services and DB',
                'Review recent infrastructure changes in EU',
                'Check DNS resolution in EU region'
            ]
        }
    
    def investigate_database_replication(self):
        """Deep dive into database replication issues"""
        
        replication_status = {
            'primary_db': {
                'location': 'us-east-1',
                'status': 'healthy',
                'connections': '150/500',
                'replication_lag': '0ms'
            },
            'eu_read_replica': {
                'location': 'eu-west-1',
                'status': 'degraded',
                'connections': '480/500',  # Nearly maxed out
                'replication_lag': '45 seconds',  # Very high lag
                'last_recovery': '2 hours ago',  # Matches incident start
                'error_logs': [
                    'Connection reset by peer',
                    'Replication timeout',
                    'Slow query: SELECT * FROM large_table (avg: 8.5s)'
                ]
            }
        }
        
        # Root cause found
        root_cause = """
        ROOT CAUSE IDENTIFIED: EU database read replica failure
        
        SEQUENCE OF EVENTS:
        1. EU read replica experienced connectivity issues 2 hours ago
        2. Replica fell behind primary by 45 seconds
        3. Application connections maxed out EU replica (480/500)
        4. Slow queries backing up, causing cascading timeouts
        5. EU services unable to get fresh data, performance degraded
        
        IMMEDIATE FIX: Failover EU traffic to primary DB in US
        PERMANENT FIX: Restore EU replica replication, optimize queries
        """
        
        return replication_status, root_cause
    
    def implement_emergency_failover(self):
        """Implement emergency failover strategy"""
        
        failover_plan = {
            'phase_1': {
                'action': 'Redirect EU read traffic to US primary DB',
                'implementation': [
                    'Update EU service configs to point to US primary',
                    'Enable connection pooling with higher limits',
                    'Add retry logic for cross-region latency'
                ],
                'expected_impact': 'Higher latency (200-300ms) but functional service',
                'risk': 'Increased load on US primary, higher latency for EU users'
            },
            'phase_2': {
                'action': 'Scale US primary to handle additional load',
                'implementation': [
                    'Increase US primary DB instance size',
                    'Add additional connection pools',
                    'Enable query caching for EU requests'
                ],
                'expected_impact': 'Stabilize performance under additional load'
            },
            'phase_3': {
                'action': 'Restore EU replica',
                'implementation': [
                    'Stop EU replica',
                    'Restore from latest backup',
                    'Re-establish replication from primary',
                    'Gradually shift EU traffic back to replica'
                ],
                'expected_impact': 'Return to normal architecture and performance'
            }
        }
        
        # Execute phase 1 immediately
        execution_result = self._execute_failover_phase_1()
        
        return failover_plan, execution_result
    
    def _execute_failover_phase_1(self):
        """Execute immediate failover"""
        
        steps = [
            {
                'step': 'Update EU service configuration',
                'command': 'kubectl patch configmap eu-services-config --patch="data: {db_host: us-primary.db.internal}"',
                'status': 'completed',
                'duration': '30 seconds'
            },
            {
                'step': 'Restart EU services to pick up new config',
                'command': 'kubectl rollout restart deployment -l region=eu-west-1',
                'status': 'completed', 
                'duration': '2 minutes'
            },
            {
                'step': 'Verify EU services connecting to US DB',
                'command': 'Check connection logs and metrics',
                'status': 'completed',
                'duration': '1 minute'
            }
        ]
        
        result = {
            'execution_time': '3.5 minutes',
            'success': True,
            'metrics_after_failover': {
                'eu_response_time': '250ms p95',  # Much better
                'eu_error_rate': '1.2%',  # Greatly improved
                'eu_throughput': '4200 rps',  # Restored
                'us_primary_load': '75%'  # Higher but manageable
            }
        }
        
        return result
    
    def monitor_recovery_and_plan_restoration(self):
        """Monitor failover and plan proper restoration"""
        
        monitoring_results = {
            'eu_user_experience': {
                'response_time': 'Improved from 8.5s to 250ms',
                'success_rate': 'Improved from 88% to 98.8%',
                'user_complaints': 'Significantly reduced'
            },
            'infrastructure_stability': {
                'us_primary_performance': 'Stable under increased load',
                'cross_region_bandwidth': 'Well within limits',
                'connection_pooling': 'Effective'
            },
            'business_impact': {
                'eu_revenue_recovery': '95% of normal levels',
                'customer_satisfaction': 'Improving',
                'support_ticket_volume': 'Decreased by 80%'
            }
        }
        
        restoration_plan = {
            'timeline': '4-hour restoration window',
            'steps': [
                {
                    'time': 'Hour 1',
                    'action': 'Rebuild EU replica from backup',
                    'risk': 'Low - no user impact'
                },
                {
                    'time': 'Hour 2-3', 
                    'action': 'Re-establish replication and verify sync',
                    'risk': 'Low - background process'
                },
                {
                    'time': 'Hour 4',
                    'action': 'Gradual traffic shift back to EU replica',
                    'risk': 'Medium - monitor for replication issues'
                }
            ],
            'rollback_plan': 'Keep US primary as fallback for 24 hours'
        }
        
        return monitoring_results, restoration_plan
```

**Key Learning Points:**
- **Regional Isolation**: Problems often isolated to specific regions
- **Database Replication**: Critical failure point in multi-region setups
- **Emergency Failover**: Cross-region failover as temporary solution
- **Gradual Restoration**: Careful migration back to proper architecture
- **Monitoring Coverage**: Need region-specific monitoring and alerting

---

### 3. Memory Leak in Production Service

**Scenario:**
A critical microservice is experiencing a gradual memory leak. Memory usage has increased from 2GB to 8GB over the past week. The service is now triggering OOM kills every 6 hours, causing brief outages. Auto-scaling is masking the problem but costs are spiraling.

**Investigation and Resolution:**

```python
class MemoryLeakInvestigation:
    def __init__(self):
        self.service_name = "user-profile-service"
        self.investigation_tools = ['heapdumps', 'memory_profiling', 'metrics_analysis']
        self.timeline = []
        
    def analyze_memory_growth_pattern(self):
        """Analyze memory usage patterns over time"""
        
        memory_timeline = {
            'week_1': {
                'baseline_memory': '2.1GB',
                'peak_memory': '2.8GB',
                'pattern': 'Normal sawtooth pattern with GC'
            },
            'week_2': {
                'baseline_memory': '3.2GB',  # Baseline increasing
                'peak_memory': '4.1GB',
                'pattern': 'Baseline trending upward'
            },
            'week_3': {
                'baseline_memory': '4.8GB',
                'peak_memory': '6.2GB', 
                'pattern': 'Clear memory leak pattern'
            },
            'current_week': {
                'baseline_memory': '6.5GB',
                'peak_memory': '8.0GB',
                'oom_kills': 3,
                'pattern': 'Critical - approaching container limits'
            }
        }
        
        # Correlation analysis
        correlations = self._analyze_correlations()
        
        leak_characteristics = {
            'growth_rate': '~500MB per week',
            'growth_pattern': 'Linear increase in baseline memory',
            'gc_effectiveness': 'Decreasing over time',
            'heap_dump_analysis': 'Required for object identification'
        }
        
        return memory_timeline, correlations, leak_characteristics
    
    def _analyze_correlations(self):
        """Look for correlations with deployment and traffic"""
        
        return {
            'deployments': {
                'v2.1.0': 'Deployed 3 weeks ago - leak started',
                'v2.1.1': 'Deployed 2 weeks ago - leak continued',
                'v2.1.2': 'Deployed 1 week ago - leak persists'
            },
            'traffic_patterns': {
                'correlation_with_load': 'Memory growth faster during high traffic',
                'correlation_with_requests': 'Possible - need deeper analysis'
            },
            'feature_releases': {
                'user_activity_tracking': 'New feature in v2.1.0',
                'enhanced_caching': 'Updated caching layer in v2.1.0'
            }
        }
    
    def capture_and_analyze_heap_dump(self):
        """Capture heap dump and analyze memory usage"""
        
        heap_dump_process = {
            'capture': {
                'command': 'kubectl exec user-profile-service-pod -- jcmd <pid> GC.run_finalization',
                'heap_dump_command': 'kubectl exec user-profile-service-pod -- jcmd <pid> VM.classloader_stats',
                'heap_size': '7.2GB at time of capture'
            },
            'analysis_tools': [
                'Eclipse Memory Analyzer (MAT)',
                'JProfiler', 
                'JVisualVM'
            ]
        }
        
        # Simulated heap dump analysis results
        heap_analysis = {
            'largest_objects': [
                {
                    'class': 'java.util.concurrent.ConcurrentHashMap',
                    'instances': 1,
                    'size': '3.2GB',
                    'retained_size': '3.2GB',
                    'suspected_leak': True
                },
                {
                    'class': 'com.company.UserActivityEvent',
                    'instances': 15_000_000,
                    'size': '2.1GB', 
                    'retained_size': '2.1GB',
                    'suspected_leak': True
                },
                {
                    'class': 'java.lang.String',
                    'instances': 45_000_000,
                    'size': '1.8GB',
                    'retained_size': '1.0GB',
                    'suspected_leak': False  # Normal for string pool
                }
            ],
            
            'gc_roots': [
                'Static field: UserActivityTracker.eventCache (3.2GB)',
                'Thread local: RequestContext.userEvents (500MB per thread)'
            ],
            
            'leak_suspects': [
                {
                    'suspect': 'UserActivityTracker.eventCache',
                    'description': 'ConcurrentHashMap never cleared, grows indefinitely',
                    'evidence': '15M UserActivityEvent objects retained',
                    'confidence': 'High'
                }
            ]
        }
        
        return heap_dump_process, heap_analysis
    
    def code_analysis_and_root_cause(self):
        """Analyze code to confirm memory leak source"""
        
        code_review = {
            'suspected_component': 'UserActivityTracker',
            'introduced_in': 'v2.1.0',
            'code_snippet': '''
            // PROBLEMATIC CODE
            public class UserActivityTracker {
                // This map grows without bounds!
                private static final ConcurrentHashMap<String, List<UserActivityEvent>> eventCache 
                    = new ConcurrentHashMap<>();
                
                public void trackActivity(String userId, UserActivityEvent event) {
                    eventCache.computeIfAbsent(userId, k -> new ArrayList<>()).add(event);
                    // MISSING: Cache eviction logic!
                }
                
                // No cleanup method called anywhere
                public void clearUserEvents(String userId) {
                    eventCache.remove(userId);  // Never called!
                }
            }
            ''',
            
            'root_cause_analysis': {
                'problem': 'Static cache without eviction policy',
                'impact': 'Accumulates user activity events indefinitely',
                'growth_rate': '~200 events per active user per day',
                'user_base': '75,000 active users',
                'memory_per_event': '~140 bytes',
                'daily_growth': '75K users * 200 events * 140 bytes = ~2.1GB/day'
            }
        }
        
        # Fix options analysis
        fix_options = [
            {
                'option': 'Add TTL-based cache eviction',
                'implementation_time': '2 hours',
                'risk': 'Low',
                'effectiveness': 'High',
                'code_change': 'Use Caffeine cache with expiration'
            },
            {
                'option': 'Move to external cache (Redis)',
                'implementation_time': '8 hours',
                'risk': 'Medium',
                'effectiveness': 'High', 
                'code_change': 'Replace in-memory cache with Redis'
            },
            {
                'option': 'Disable activity tracking temporarily',
                'implementation_time': '30 minutes',
                'risk': 'Low',
                'effectiveness': 'High',
                'code_change': 'Feature flag to disable tracking'
            }
        ]
        
        return code_review, fix_options
    
    def implement_immediate_fix(self):
        """Implement quick fix to stop the leak"""
        
        immediate_fix = {
            'approach': 'Feature flag + cache size limit',
            'implementation': [
                {
                    'step': 'Deploy feature flag to disable activity tracking',
                    'code': '''
                    @Value("${user.activity.tracking.enabled:true}")
                    private boolean activityTrackingEnabled;
                    
                    public void trackActivity(String userId, UserActivityEvent event) {
                        if (!activityTrackingEnabled) return;  // Quick disable
                        // ... existing code
                    }
                    ''',
                    'deployment_time': '15 minutes'
                },
                {
                    'step': 'Add emergency cache size limit',
                    'code': '''
                    private static final int MAX_CACHE_SIZE = 10000;
                    
                    public void trackActivity(String userId, UserActivityEvent event) {
                        if (eventCache.size() > MAX_CACHE_SIZE) {
                            // Emergency cleanup - remove oldest entries
                            cleanupOldestEntries();
                        }
                        // ... existing code
                    }
                    ''',
                    'deployment_time': '30 minutes'
                }
            ]
        }
        
        # Monitor fix effectiveness
        fix_monitoring = {
            'metrics_to_watch': [
                'Memory usage trend',
                'GC frequency and duration',
                'OOM kill events',
                'Application functionality'
            ],
            'expected_results': {
                'memory_stabilization': 'Within 2 hours',
                'oom_elimination': 'Immediate',
                'cost_reduction': '60% reduction in compute costs'
            }
        }
        
        return immediate_fix, fix_monitoring
    
    def implement_permanent_solution(self):
        """Implement proper long-term solution"""
        
        permanent_solution = {
            'design': {
                'cache_strategy': 'LRU cache with TTL',
                'max_size': '50,000 entries',
                'ttl': '24 hours',
                'eviction_policy': 'Size and time-based'
            },
            
            'implementation': '''
            // FIXED CODE using Caffeine cache
            public class UserActivityTracker {
                private final Cache<String, List<UserActivityEvent>> eventCache = 
                    Caffeine.newBuilder()
                        .maximumSize(50_000)
                        .expireAfterWrite(24, TimeUnit.HOURS)
                        .removalListener((key, value, cause) -> 
                            log.debug("Evicted cache entry: {} ({})", key, cause))
                        .build();
                
                public void trackActivity(String userId, UserActivityEvent event) {
                    if (!activityTrackingEnabled) return;
                    
                    eventCache.get(userId, k -> new ArrayList<>()).add(event);
                    
                    // Optional: Limit events per user
                    List<UserActivityEvent> userEvents = eventCache.getIfPresent(userId);
                    if (userEvents != null && userEvents.size() > 1000) {
                        userEvents.removeIf(e -> e.getTimestamp() < 
                            Instant.now().minus(Duration.ofDays(1)).toEpochMilli());
                    }
                }
            }
            ''',
            
            'testing_plan': [
                'Load test with cache eviction enabled',
                'Memory usage monitoring over 48 hours',
                'Functionality verification for activity tracking',
                'Performance impact assessment'
            ],
            
            'deployment_strategy': {
                'approach': 'Blue-green deployment',
                'validation': 'Monitor memory usage for 4 hours before full rollout',
                'rollback_plan': 'Keep feature flag to disable if issues arise'
            }
        }
        
        return permanent_solution
    
    def post_incident_improvements(self):
        """Identify improvements to prevent future memory leaks"""
        
        prevention_measures = [
            {
                'measure': 'Memory usage monitoring and alerting',
                'implementation': [
                    'Alert on memory growth > 10% week-over-week',
                    'Alert on GC frequency increase',
                    'Dashboard showing memory trends by service'
                ],
                'owner': 'SRE Team'
            },
            {
                'measure': 'Automated heap dump collection',
                'implementation': [
                    'Trigger heap dump before OOM kill',
                    'Automated heap dump analysis pipeline',
                    'Integration with alerting system'
                ],
                'owner': 'Platform Team'
            },
            {
                'measure': 'Code review guidelines for memory management',
                'implementation': [
                    'Mandatory review for static collections',
                    'Cache design review requirements',
                    'Memory leak testing in CI/CD'
                ],
                'owner': 'Engineering Teams'
            },
            {
                'measure': 'Load testing with memory profiling',
                'implementation': [
                    'Include memory usage in performance tests',
                    'Long-running stability tests',
                    'Memory leak detection automation'
                ],
                'owner': 'QA Team'
            }
        ]
        
        return prevention_measures
```

**Key Learning Points:**
- **Pattern Recognition**: Linear memory growth indicates systematic leak
- **Heap Dump Analysis**: Essential for identifying leak sources
- **Code Review**: Static collections without eviction are common culprits
- **Immediate vs Permanent**: Feature flags for quick fixes, proper design for long-term
- **Prevention**: Monitoring and testing prevent future incidents

---

### 4. Security Incident: Data Breach Response

**Scenario:**
Your security team alerts you that suspicious API activity has been detected. An attacker appears to have gained unauthorized access to user data through a compromised API endpoint. You need to assess the scope, contain the breach, and restore security.

**Incident Response:**

```python
class SecurityIncidentResponse:
    def __init__(self):
        self.incident_type = "data_breach"
        self.severity = "P0"
        self.discovery_time = "2024-01-15 14:30:00"
        self.response_team = ['security_lead', 'sre_lead', 'legal_counsel', 'ciso']
        
    def immediate_assessment_and_containment(self):
        """First 15 minutes: Assess and contain"""
        
        initial_findings = {
            'detection_source': 'SIEM alert: Unusual API access patterns',
            'suspicious_activity': {
                'api_endpoint': '/api/v1/users/profile',
                'request_volume': '15,000 requests in 10 minutes (normal: 200)',
                'source_ips': ['185.234.123.45', '192.168.1.100', '10.0.0.50'],
                'user_agents': ['curl/7.68.0', 'python-requests/2.25.1'],
                'response_patterns': 'Systematic user ID enumeration (1-50000)'
            },
            'data_at_risk': [
                'User profile information',
                'Email addresses', 
                'Phone numbers',
                'Account metadata'
            ]
        }
        
        # Immediate containment actions
        containment_actions = [
            {
                'action': 'Block suspicious IP addresses',
                'implementation': 'kubectl patch networkpolicy api-access --patch="spec: {ingress: [{from: [{namespaceSelector: {matchLabels: {name: trusted}}}]}]}"',
                'status': 'completed',
                'time': '14:32'
            },
            {
                'action': 'Rate limit API endpoint',
                'implementation': 'Update Istio VirtualService to add rate limiting',
                'status': 'completed', 
                'time': '14:35'
            },
            {
                'action': 'Enable detailed API logging',
                'implementation': 'Increase log level to capture all API requests',
                'status': 'completed',
                'time': '14:37'
            },
            {
                'action': 'Notify incident response team',
                'implementation': 'PagerDuty alert sent to security and SRE teams',
                'status': 'completed',
                'time': '14:38'
            }
        ]
        
        return initial_findings, containment_actions
    
    def detailed_forensic_analysis(self):
        """Deep dive forensic investigation"""
        
        forensic_timeline = {
            '14:00': 'First suspicious request logged',
            '14:15': 'Request volume spike begins',
            '14:20': 'Systematic user enumeration detected',
            '14:25': 'Data exfiltration pattern identified',
            '14:30': 'SIEM alert triggered',
            '14:32': 'Incident response initiated'
        }
        
        attack_analysis = {
            'attack_vector': {
                'method': 'API endpoint exploitation',
                'vulnerability': 'Missing authentication on profile endpoint',
                'entry_point': '/api/v1/users/profile/{user_id}',
                'authentication_bypass': 'Endpoint accessible without valid token'
            },
            
            'attacker_behavior': {
                'reconnaissance': 'API endpoint discovery via directory traversal',
                'exploitation': 'Systematic user ID enumeration',
                'data_collection': 'Bulk profile data extraction',
                'persistence': 'No evidence of persistent access mechanisms'
            },
            
            'data_compromised': {
                'user_profiles_accessed': '~45,000 user records',
                'data_fields_exposed': [
                    'user_id', 'email', 'phone', 'name', 
                    'registration_date', 'last_login'
                ],
                'sensitive_data_excluded': [
                    'passwords (hashed)', 'payment_info', 'ssn'
                ],
                'estimated_records': '45,000 users (30% of user base)'
            }
        }
        
        # Root cause analysis
        root_cause = {
            'primary_cause': 'Missing authentication middleware on user profile endpoint',
            'contributing_factors': [
                'API endpoint deployed without proper security review',
                'Missing rate limiting on public endpoints',
                'Insufficient API access monitoring',
                'No user enumeration protection'
            ],
            'vulnerability_introduced': 'v2.3.1 deployment (2 weeks ago)',
            'code_diff': '''
            // VULNERABLE CODE (introduced in v2.3.1)
            @GetMapping("/api/v1/users/profile/{userId}")
            public ResponseEntity<UserProfile> getUserProfile(@PathVariable Long userId) {
                // MISSING: Authentication check!
                UserProfile profile = userService.getProfile(userId);
                return ResponseEntity.ok(profile);
            }
            
            // SHOULD HAVE BEEN:
            @GetMapping("/api/v1/users/profile/{userId}")
            @PreAuthorize("hasRole('USER') and #userId == authentication.principal.userId")
            public ResponseEntity<UserProfile> getUserProfile(@PathVariable Long userId) {
                UserProfile profile = userService.getProfile(userId);
                return ResponseEntity.ok(profile);
            }
            '''
        }
        
        return forensic_timeline, attack_analysis, root_cause
    
    def impact_assessment_and_notification(self):
        """Assess business impact and handle notifications"""
        
        impact_assessment = {
            'data_breach_scope': {
                'affected_users': 45000,
                'data_sensitivity': 'PII (Personal Identifiable Information)',
                'compliance_impact': 'GDPR, CCPA reporting required',
                'geographic_distribution': {
                    'EU': 15000,  # GDPR applies
                    'US_California': 8000,  # CCPA applies  
                    'Other_US': 20000,
                    'Other_regions': 2000
                }
            },
            
            'business_impact': {
                'regulatory_fines': 'Potential GDPR fines up to €20M or 4% revenue',
                'reputation_damage': 'High - data security concerns',
                'customer_churn_risk': 'Estimated 5-10% churn rate',
                'legal_costs': 'Investigation and defense costs',
                'operational_impact': 'Security hardening requirements'
            },
            
            'technical_impact': {
                'service_availability': 'API rate limiting may affect performance',
                'system_integrity': 'No evidence of data modification',
                'ongoing_risk': 'Low - vulnerability patched'
            }
        }
        
        # Notification requirements
        notification_plan = {
            'regulatory_notifications': [
                {
                    'authority': 'EU Data Protection Authorities',
                    'deadline': '72 hours from discovery',
                    'status': 'notification_prepared',
                    'requirements': 'GDPR Article 33 breach notification'
                },
                {
                    'authority': 'California Attorney General',
                    'deadline': 'Without unreasonable delay',
                    'status': 'notification_prepared',
                    'requirements': 'CCPA breach notification'
                }
            ],
            
            'customer_notifications': {
                'affected_users': 'Email notification within 72 hours',
                'communication_strategy': 'Transparent about breach, steps taken',
                'support_resources': 'Dedicated support line, FAQ page',
                'remediation_offers': 'Free credit monitoring for affected users'
            },
            
            'stakeholder_communications': [
                'Board of directors briefing',
                'Executive team notification',
                'Public relations strategy',
                'Customer support team briefing'
            ]
        }
        
        return impact_assessment, notification_plan
    
    def remediation_and_hardening(self):
        """Implement fixes and security hardening"""
        
        immediate_fixes = [
            {
                'fix': 'Deploy authentication patch',
                'implementation': '''
                @GetMapping("/api/v1/users/profile/{userId}")
                @PreAuthorize("hasRole('USER') and @userSecurityService.canAccessProfile(authentication, #userId)")
                public ResponseEntity<UserProfile> getUserProfile(
                    @PathVariable Long userId, 
                    Authentication authentication) {
                    
                    UserProfile profile = userService.getProfile(userId);
                    return ResponseEntity.ok(profile);
                }
                ''',
                'timeline': 'Deployed within 2 hours',
                'validation': 'Security testing completed'
            },
            
            {
                'fix': 'Implement comprehensive API rate limiting',
                'implementation': '''
                # Istio rate limiting configuration
                apiVersion: networking.istio.io/v1alpha3
                kind: EnvoyFilter
                metadata:
                  name: api-rate-limit
                spec:
                  configPatches:
                  - applyTo: HTTP_FILTER
                    match:
                      context: SIDECAR_INBOUND
                    patch:
                      operation: INSERT_BEFORE
                      value:
                        name: envoy.filters.http.local_ratelimit
                        typed_config:
                          "@type": type.googleapis.com/udpa.type.v1.TypedStruct
                          type_url: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
                          value:
                            stat_prefix: local_rate_limiter
                            token_bucket:
                              max_tokens: 100
                              tokens_per_fill: 100
                              fill_interval: 60s
                ''',
                'timeline': 'Deployed within 4 hours'
            }
        ]
        
        security_hardening = [
            {
                'area': 'API Security',
                'measures': [
                    'Implement OAuth 2.0 / JWT authentication on all endpoints',
                    'Add request signing for sensitive operations',
                    'Implement API versioning with deprecation strategy',
                    'Add comprehensive input validation and sanitization'
                ]
            },
            {
                'area': 'Access Controls',
                'measures': [
                    'Implement role-based access control (RBAC)',
                    'Add user-level data access policies',
                    'Implement audit logging for all data access',
                    'Add anomaly detection for unusual access patterns'
                ]
            },
            {
                'area': 'Monitoring and Detection',
                'measures': [
                    'Enhanced SIEM rules for API abuse',
                    'Real-time anomaly detection',
                    'Automated threat response workflows',
                    'User behavior analytics (UBA)'
                ]
            },
            {
                'area': 'Compliance and Governance',
                'measures': [
                    'Regular security assessments',
                    'Penetration testing program',
                    'Security code review process',
                    'Data privacy impact assessments'
                ]
            }
        ]
        
        return immediate_fixes, security_hardening
    
    def incident_closure_and_lessons_learned(self):
        """Close incident and document lessons learned"""
        
        incident_summary = {
            'duration': '6 hours from detection to full remediation',
            'root_cause': 'Missing authentication on API endpoint',
            'impact': '45,000 user records accessed',
            'resolution': 'Authentication implemented, rate limiting added',
            'cost_estimate': '$500K (regulatory, legal, remediation costs)'
        }
        
        lessons_learned = [
            {
                'lesson': 'Security reviews mandatory for all API changes',
                'action': 'Implement security review gate in CI/CD pipeline',
                'owner': 'Security Team',
                'due_date': '2024-02-01'
            },
            {
                'lesson': 'API endpoints should be secure by default',
                'action': 'Create secure API development framework',
                'owner': 'Platform Team',
                'due_date': '2024-02-15'
            },
            {
                'lesson': 'Need faster detection of API abuse',
                'action': 'Implement real-time API anomaly detection',
                'owner': 'SRE Team',
                'due_date': '2024-02-10'
            },
            {
                'lesson': 'Incident response communication needs improvement',
                'action': 'Create security incident communication playbook',
                'owner': 'Legal/Comms Team',
                'due_date': '2024-01-30'
            }
        ]
        
        compliance_follow_up = {
            'regulatory_filings': 'All required notifications submitted',
            'audit_requirements': 'External security audit scheduled',
            'ongoing_monitoring': 'Enhanced monitoring for 12 months',
            'customer_communication': 'Follow-up communications planned'
        }
        
        return incident_summary, lessons_learned, compliance_follow_up
```

**Key Learning Points:**
- **Rapid Containment**: Block attack sources immediately while investigating
- **Forensic Analysis**: Detailed timeline and evidence collection
- **Compliance Requirements**: GDPR/CCPA have strict notification timelines  
- **Root Cause**: Simple authentication oversight with major impact
- **Security Hardening**: Comprehensive improvements beyond just the fix

---

## 🎯 Interview Questions and Scenarios

### Common SRE Scenario Interview Questions

**1. "Walk me through how you would handle a service that's experiencing intermittent 500 errors affecting 5% of requests."**

**Structured Response Framework:**
```
1. IMMEDIATE ASSESSMENT (0-5 minutes)
   - Check monitoring dashboards for error patterns
   - Identify affected endpoints/users/regions
   - Assess business impact and escalate if needed

2. HYPOTHESIS FORMATION (5-15 minutes)  
   - Correlate with recent deployments
   - Check infrastructure changes
   - Analyze error logs for patterns
   - Form initial hypothesis

3. INVESTIGATION & MITIGATION (15-45 minutes)
   - Test hypothesis with targeted investigation
   - Implement quick wins if available
   - Gather more detailed evidence
   - Plan proper fix

4. RESOLUTION & VERIFICATION (45+ minutes)
   - Implement root cause fix
   - Monitor for improvement
   - Verify resolution
   - Plan preventive measures
```

**2. "How would you design a monitoring strategy for a new microservice?"**

**Comprehensive Answer:**
```
MONITORING PYRAMID:
├── Business Metrics (Top)
│   ├── Conversion rates, revenue impact
│   └── User journey completion rates
├── Application Metrics (Middle)  
│   ├── Request rate, latency, errors
│   ├── Database query performance
│   └── External dependency health
└── Infrastructure Metrics (Base)
    ├── CPU, memory, disk, network
    ├── Container/pod health
    └── Cluster resource utilization

IMPLEMENTATION:
1. Instrument code with metrics (Prometheus)
2. Structured logging (ELK stack)
3. Distributed tracing (Jaeger/Zipkin)
4. Alerting on SLI violations
5. Dashboards for different audiences
```

**3. "Describe how you would implement a zero-downtime deployment strategy."**

**Strategic Response:**
```
STRATEGY SELECTION:
- Blue-Green: For major changes, database migrations
- Canary: For gradual rollouts, A/B testing
- Rolling: For routine updates, stateless services

IMPLEMENTATION COMPONENTS:
1. Health checks and readiness probes
2. Load balancer configuration
3. Database migration strategy
4. Monitoring and rollback triggers
5. Traffic splitting mechanisms

SAFETY MEASURES:
- Automated rollback triggers
- Feature flags for instant disable
- Comprehensive testing pipeline
- Staged rollout process
```

---

## 📚 Scenario-Based Learning Resources

### SRE Simulation Exercises

```python
class SRESimulationPlatform:
    """Platform for practicing SRE scenarios"""
    
    def __init__(self):
        self.scenarios = {
            'beginner': [
                'Simple service restart scenarios',
                'Basic monitoring alert investigation',
                'Log analysis exercises'
            ],
            'intermediate': [
                'Multi-service failure debugging',
                'Performance degradation investigation', 
                'Capacity planning exercises'
            ],
            'advanced': [
                'Multi-region outage simulation',
                'Security incident response',
                'Complex performance optimization'
            ]
        }
    
    def generate_scenario(self, difficulty: str, domain: str):
        """Generate realistic SRE scenario for practice"""
        
        scenario_templates = {
            'latency_spike': {
                'symptoms': 'P95 latency increased from 200ms to 2s',
                'context': 'E-commerce checkout during peak hours',
                'red_herrings': ['CPU usage normal', 'Memory usage stable'],
                'root_cause': 'Database query optimization needed',
                'learning_objectives': ['Performance debugging', 'Database optimization']
            },
            
            'cascade_failure': {
                'symptoms': 'Multiple services failing simultaneously',
                'context': 'Microservices architecture during traffic spike',
                'red_herrings': ['Individual service health looks good'],
                'root_cause': 'Shared database connection pool exhaustion',
                'learning_objectives': ['Systems thinking', 'Dependency analysis']
            }
        }
        
        return scenario_templates
    
    def validate_response(self, scenario_id: str, user_response: dict):
        """Validate user's incident response"""
        
        evaluation_criteria = {
            'triage_speed': 'How quickly did you identify severity?',
            'hypothesis_quality': 'Was your initial hypothesis logical?',
            'investigation_approach': 'Did you use systematic debugging?',
            'mitigation_effectiveness': 'Were your fixes appropriate?',
            'communication': 'Did you communicate clearly with stakeholders?',
            'prevention': 'Did you identify preventive measures?'
        }
        
        return evaluation_criteria
```

### Practice Incident Response

**Daily SRE Challenges:**
- **Monday**: Monitoring alert triage and investigation
- **Tuesday**: Performance optimization scenario  
- **Wednesday**: Deployment and rollback simulation
- **Thursday**: Multi-region architecture design
- **Friday**: Post-mortem analysis and improvement planning

---

This comprehensive scenarios guide provides real-world SRE situations with detailed investigation approaches, resolution strategies, and key learning points that demonstrate practical application of SRE principles and practices.