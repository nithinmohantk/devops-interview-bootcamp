# Microsoft Azure Interview Questions 🌐

## Core Azure Services

### 1. Explain Azure's main compute services and their use cases

**Answer:**

| Service | Type | Use Case | Management | Scaling |
|---------|------|----------|------------|---------|
| **Virtual Machines** | IaaS | Full control, legacy apps | High | VM Scale Sets |
| **App Service** | PaaS | Web apps, APIs | Low | Auto-scaling |
| **Container Instances** | CaaS | Simple containerization | Low | Manual |
| **Kubernetes Service (AKS)** | CaaS | Container orchestration | Medium | HPA/VPA |
| **Functions** | FaaS | Event-driven, serverless | Minimal | Automatic |

**Azure Virtual Machines:**
```yaml
# ARM Template for VM
vm_config:
  vmSize: "Standard_B2s"
  imageReference:
    publisher: "Canonical"
    offer: "0001-com-ubuntu-server-focal"
    sku: "20_04-lts-gen2"
  osProfile:
    computerName: "webserver"
    adminUsername: "azureuser"
    linuxConfiguration:
      disablePasswordAuthentication: true
      ssh:
        publicKeys:
          - path: "/home/azureuser/.ssh/authorized_keys"
            keyData: "ssh-rsa AAAAB3N..."
```

### 2. What is Azure Resource Manager (ARM) and how does it work?

**Answer:**

Azure Resource Manager is the deployment and management service for Azure that provides a management layer for creating, updating, and deleting resources.

```mermaid
graph TB
    A[Client Tools] --> B[Azure Resource Manager]
    B --> C[Resource Providers]
    C --> D[Azure Resources]
    
    A1[Azure Portal] --> B
    A2[Azure CLI] --> B
    A3[PowerShell] --> B
    A4[REST API] --> B
    A5[ARM Templates] --> B
    
    C --> C1[Microsoft.Compute]
    C --> C2[Microsoft.Storage]
    C --> C3[Microsoft.Network]
    C --> C4[Microsoft.Web]
    
    style B fill:#0078d4
    style C fill:#40e0d0
```

**ARM Template Example:**
```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "storageAccountName": {
      "type": "string",
      "metadata": {
        "description": "Name of the storage account"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2021-02-01",
      "name": "[parameters('storageAccountName')]",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "Standard_LRS"
      },
      "kind": "StorageV2",
      "properties": {
        "accessTier": "Hot"
      }
    }
  ]
}
```

### 3. Explain Azure networking components and how they work together

**Answer:**

Azure networking provides connectivity between Azure resources, on-premises networks, and the internet.

```mermaid
graph TB
    Internet[Internet] --> AG[Application Gateway]
    Internet --> LB[Load Balancer]
    
    AG --> VM1[VM 1]
    AG --> VM2[VM 2]
    LB --> VM3[VM 3]
    LB --> VM4[VM 4]
    
    subgraph VNet[Virtual Network]
        subgraph Subnet1[Web Subnet]
            VM1
            VM2
        end
        subgraph Subnet2[App Subnet]
            VM3
            VM4
        end
        subgraph Subnet3[Data Subnet]
            DB[(Database)]
        end
    end
    
    VM3 --> DB
    VM4 --> DB
    
    VNet --> VPN[VPN Gateway]
    VPN --> OnPrem[On-Premises]
    
    style VNet fill:#e1f5fe
    style AG fill:#81c784
    style LB fill:#ffb74d
```

**Network Security Group Example:**
```json
{
  "type": "Microsoft.Network/networkSecurityGroups",
  "name": "web-nsg",
  "properties": {
    "securityRules": [
      {
        "name": "Allow-HTTP",
        "properties": {
          "protocol": "Tcp",
          "sourcePortRange": "*",
          "destinationPortRange": "80",
          "sourceAddressPrefix": "*",
          "destinationAddressPrefix": "*",
          "access": "Allow",
          "priority": 100,
          "direction": "Inbound"
        }
      },
      {
        "name": "Allow-HTTPS",
        "properties": {
          "protocol": "Tcp",
          "sourcePortRange": "*",
          "destinationPortRange": "443",
          "sourceAddressPrefix": "*",
          "destinationAddressPrefix": "*",
          "access": "Allow",
          "priority": 110,
          "direction": "Inbound"
        }
      }
    ]
  }
}
```

## Azure Storage Services

### 4. Compare Azure Storage types and their use cases

**Answer:**

| Storage Type | Performance | Use Case | Pricing | Redundancy Options |
|--------------|-------------|----------|---------|-------------------|
| **Blob Storage** | Standard/Premium | Object storage, data lakes | Low | LRS, ZRS, GRS, RA-GRS |
| **File Storage** | Standard/Premium | File shares, lift-and-shift | Medium | LRS, ZRS, GRS |
| **Queue Storage** | Standard | Message queuing | Low | LRS, ZRS, GRS |
| **Table Storage** | Standard | NoSQL key-value | Low | LRS, ZRS, GRS |
| **Disk Storage** | Standard/Premium/Ultra | VM disks | Varies | LRS, ZRS |

```mermaid
graph LR
    App[Application] --> Blob[Blob Storage]
    App --> File[File Storage]
    App --> Queue[Queue Storage]
    App --> Table[Table Storage]
    
    VM[Virtual Machine] --> Disk[Managed Disks]
    
    Blob --> B1[Hot Tier]
    Blob --> B2[Cool Tier]
    Blob --> B3[Archive Tier]
    
    style Blob fill:#ff9800
    style File fill:#4caf50
    style Queue fill:#2196f3
    style Table fill:#9c27b0
    style Disk fill:#f44336
```

### 5. How do you implement Azure Blob Storage lifecycle management?

**Answer:**

```json
{
  "rules": [
    {
      "name": "transitionToCool",
      "type": "Lifecycle",
      "definition": {
        "filters": {
          "blobTypes": ["blockBlob"],
          "prefixMatch": ["logs/"]
        },
        "actions": {
          "baseBlob": {
            "tierToCool": {
              "daysAfterModificationGreaterThan": 30
            },
            "tierToArchive": {
              "daysAfterModificationGreaterThan": 90
            },
            "delete": {
              "daysAfterModificationGreaterThan": 365
            }
          }
        }
      }
    }
  ]
}
```

```mermaid
graph LR
    A[Hot Tier] --> B[Cool Tier]
    B --> C[Archive Tier]
    C --> D[Delete]
    
    A --> |30 days| B
    B --> |60 days| C
    C --> |275 days| D
    
    style A fill:#ff5722
    style B fill:#2196f3
    style C fill:#607d8b
    style D fill:#9e9e9e
```

## Azure Identity and Security

### 6. Explain Azure Active Directory and its components

**Answer:**

Azure AD is Microsoft's cloud-based identity and access management service.

```mermaid
graph TB
    subgraph "Azure AD Tenant"
        Users[Users]
        Groups[Groups]
        Apps[Applications]
        Devices[Devices]
    end
    
    subgraph "Authentication"
        MFA[Multi-Factor Auth]
        SSO[Single Sign-On]
        SAML[SAML/OAuth]
    end
    
    subgraph "Authorization"
        RBAC[Role-Based Access Control]
        PIM[Privileged Identity Management]
        CAP[Conditional Access]
    end
    
    Users --> MFA
    Users --> RBAC
    Groups --> RBAC
    Apps --> SSO
    Apps --> SAML
    
    MFA --> CAP
    RBAC --> PIM
    
    style Users fill:#4caf50
    style MFA fill:#ff9800
    style RBAC fill:#2196f3
```

**Custom Role Definition:**
```json
{
  "Name": "Virtual Machine Operator",
  "Description": "Can monitor and restart virtual machines",
  "Actions": [
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/restart/action"
  ],
  "NotActions": [
    "Microsoft.Compute/virtualMachines/delete"
  ],
  "AssignableScopes": [
    "/subscriptions/{subscription-id}/resourceGroups/production"
  ]
}
```

### 7. How do you implement Azure Key Vault for secrets management?

**Answer:**

```powershell
# Create Key Vault
az keyvault create \
  --name "myKeyVault" \
  --resource-group "myResourceGroup" \
  --location "East US" \
  --enable-soft-delete \
  --enable-purge-protection

# Store secret
az keyvault secret set \
  --vault-name "myKeyVault" \
  --name "DatabaseConnectionString" \
  --value "Server=myserver;Database=mydb;User=user;Password=pass"

# Grant access to managed identity
az keyvault set-policy \
  --name "myKeyVault" \
  --object-id "{managed-identity-id}" \
  --secret-permissions get list
```

```mermaid
sequenceDiagram
    participant App as Application
    participant MSI as Managed Identity
    participant AAD as Azure AD
    participant KV as Key Vault
    
    App->>MSI: Request token
    MSI->>AAD: Authenticate
    AAD->>MSI: Return token
    MSI->>App: Return token
    App->>KV: Request secret (with token)
    KV->>AAD: Validate token
    AAD->>KV: Token valid
    KV->>App: Return secret
```

## Azure DevOps and CI/CD

### 8. Design an Azure DevOps CI/CD pipeline architecture

**Answer:**

```mermaid
graph TB
    Dev[Developer] --> Git[Git Repository]
    Git --> CI[Continuous Integration]
    CI --> Build[Build Pipeline]
    Build --> Test[Test Pipeline]
    Test --> Artifact[Build Artifacts]
    
    Artifact --> CD[Continuous Deployment]
    CD --> Dev_Env[Development]
    Dev_Env --> QA[QA Environment]
    QA --> Prod[Production]
    
    subgraph "Azure DevOps"
        Git
        CI
        Build
        Test
        CD
    end
    
    subgraph "Azure Services"
        Dev_Env --> AKS1[AKS Cluster]
        QA --> AKS2[AKS Cluster]
        Prod --> AKS3[AKS Cluster]
    end
    
    style CI fill:#4caf50
    style CD fill:#ff9800
    style AKS1 fill:#2196f3
    style AKS2 fill:#ff5722
    style AKS3 fill:#9c27b0
```

**Azure Pipeline YAML:**
```yaml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: 'ubuntu-latest'

variables:
  buildConfiguration: 'Release'
  imageName: 'myapp'
  containerRegistry: 'myregistry.azurecr.io'

stages:
- stage: Build
  jobs:
  - job: BuildAndTest
    steps:
    - task: DotNetCoreCLI@2
      displayName: 'Build application'
      inputs:
        command: 'build'
        configuration: '$(buildConfiguration)'
    
    - task: DotNetCoreCLI@2
      displayName: 'Run tests'
      inputs:
        command: 'test'
        projects: '**/*Tests.csproj'
    
    - task: Docker@2
      displayName: 'Build and push image'
      inputs:
        containerRegistry: '$(containerRegistry)'
        repository: '$(imageName)'
        command: 'buildAndPush'
        Dockerfile: '**/Dockerfile'

- stage: Deploy
  dependsOn: Build
  jobs:
  - deployment: DeployToAKS
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: KubernetesManifest@0
            displayName: 'Deploy to AKS'
            inputs:
              action: 'deploy'
              manifests: '$(Pipeline.Workspace)/manifests/*.yaml'
```

## Azure Monitoring and Logging

### 9. How do you implement comprehensive monitoring in Azure?

**Answer:**

```mermaid
graph TB
    subgraph "Data Sources"
        VM[Virtual Machines]
        App[Applications]
        AKS[AKS Clusters]
        DB[Databases]
    end
    
    subgraph "Azure Monitor"
        Metrics[Azure Monitor Metrics]
        Logs[Azure Monitor Logs]
        Insights[Application Insights]
    end
    
    subgraph "Alerting & Actions"
        Alerts[Azure Alerts]
        Actions[Action Groups]
        Auto[Auto-scaling]
    end
    
    subgraph "Visualization"
        Dashboard[Azure Dashboards]
        Workbooks[Azure Workbooks]
        Grafana[Grafana]
    end
    
    VM --> Metrics
    App --> Insights
    AKS --> Logs
    DB --> Metrics
    
    Metrics --> Alerts
    Logs --> Alerts
    Insights --> Alerts
    
    Alerts --> Actions
    Actions --> Auto
    
    Metrics --> Dashboard
    Logs --> Workbooks
    Insights --> Grafana
    
    style Metrics fill:#4caf50
    style Logs fill:#2196f3
    style Insights fill:#ff9800
    style Alerts fill:#f44336
```

**Application Insights Configuration:**
```json
{
  "ApplicationInsights": {
    "InstrumentationKey": "your-instrumentation-key",
    "EnableAdaptiveSampling": true,
    "EnableQuickPulseMetricStream": true,
    "EnableHeartbeat": true,
    "EnableDiagnosticsTelemetryModule": true
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    },
    "ApplicationInsights": {
      "LogLevel": {
        "Default": "Information"
      }
    }
  }
}
```

### 10. Explain Azure Cost Management and optimization strategies

**Answer:**

```mermaid
graph TB
    subgraph "Cost Monitoring"
        Budget[Budgets]
        Alerts[Cost Alerts]
        Analysis[Cost Analysis]
    end
    
    subgraph "Optimization"
        Advisor[Azure Advisor]
        Reservations[Reserved Instances]
        Spot[Spot Instances]
        Sizing[Right-sizing]
    end
    
    subgraph "Governance"
        Policy[Azure Policy]
        Tags[Resource Tags]
        RBAC[Access Control]
    end
    
    Budget --> Alerts
    Analysis --> Advisor
    Advisor --> Reservations
    Advisor --> Sizing
    
    Policy --> Tags
    Tags --> Analysis
    RBAC --> Budget
    
    style Budget fill:#4caf50
    style Advisor fill:#2196f3
    style Policy fill:#ff9800
```

**Cost Management Strategies:**

1. **Resource Tagging:**
```json
{
  "tags": {
    "Environment": "Production",
    "Project": "WebApp",
    "Owner": "DevTeam",
    "CostCenter": "IT-001",
    "AutoShutdown": "Yes"
  }
}
```

2. **Auto-shutdown Policy:**
```json
{
  "properties": {
    "displayName": "Auto-shutdown VMs",
    "policyRule": {
      "if": {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Compute/virtualMachines"
          },
          {
            "field": "tags['Environment']",
            "equals": "Development"
          }
        ]
      },
      "then": {
        "effect": "deployIfNotExists",
        "details": {
          "type": "Microsoft.DevTestLab/schedules",
          "name": "[concat('shutdown-computevm-', resourceGroup().name)]"
        }
      }
    }
  }
}
```

## Azure Kubernetes Service (AKS)

### 11. How do you design and implement an AKS cluster with security best practices?

**Answer:**

```mermaid
graph TB
    subgraph "Control Plane"
        API[API Server]
        ETCD[etcd]
        Scheduler[Scheduler]
        Controller[Controller Manager]
    end
    
    subgraph "Node Pools"
        System[System Node Pool]
        User[User Node Pool]
        Spot[Spot Node Pool]
    end
    
    subgraph "Security"
        AAD[Azure AD Integration]
        RBAC[Kubernetes RBAC]
        PSP[Pod Security Policies]
        NP[Network Policies]
    end
    
    subgraph "Networking"
        CNI[Azure CNI]
        LB[Load Balancer]
        Ingress[Ingress Controller]
    end
    
    API --> System
    API --> User
    API --> Spot
    
    AAD --> RBAC
    RBAC --> PSP
    PSP --> NP
    
    CNI --> LB
    LB --> Ingress
    
    style API fill:#4caf50
    style AAD fill:#2196f3
    style CNI fill:#ff9800
```

**AKS Cluster Configuration:**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aks-cluster-config
data:
  cluster.yaml: |
    resource_group: "aks-rg"
    cluster_name: "production-aks"
    kubernetes_version: "1.28.0"
    
    node_pools:
      system:
        vm_size: "Standard_DS2_v2"
        node_count: 3
        max_pods: 30
        os_disk_size: 100
        
      user:
        vm_size: "Standard_DS3_v2"
        node_count: 5
        min_count: 3
        max_count: 10
        enable_auto_scaling: true
        
    network:
      network_plugin: "azure"
      service_cidr: "10.0.0.0/16"
      dns_service_ip: "10.0.0.10"
      pod_cidr: "10.244.0.0/16"
      
    security:
      enable_rbac: true
      aad_integration: true
      network_policy: "calico"
      private_cluster: true
```

This comprehensive Azure section covers core services, networking, storage, security, DevOps, monitoring, and Kubernetes. Each question includes practical examples, code snippets, and Mermaid diagrams to illustrate the concepts clearly for interview preparation.