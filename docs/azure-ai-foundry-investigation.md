# Azure AI Foundry Investigation for Skwaq

**Date:** 2026-07-17
**Tenant:** DefenderATEVET17 (`3cd87a41-1f61-4aef-a212-cefdecd9a2d1`)
**Subscription:** `9b00bc5e-9abc-45de-9958-02a9d9277b16`
**Authenticated as:** `ryan.sweet@DefenderATEVET17.onmicrosoft.com`

## 1. Current Azure Environment

### Subscription & Auth

The Azure CLI is authenticated to the DefenderATEVET17 tenant with a single
subscription in `Enabled` state. `DefaultAzureCredential` will work via
`az login` (CLI auth) or a managed identity assigned to the compute running
skwaq.

### Existing Cognitive Services Resources

The `rysweet-ballistae` resource group in **eastus2** already has three
resources:

| Name | Kind | Location |
|------|------|----------|
| `rysweet-ballistae` | CognitiveServices | eastus2 |
| `rysweet-ballisae-openai` | OpenAI | eastus2 |
| `rysweetballist5347662217` | AIServices | eastus2 |

The AIServices resource has endpoint
`https://rysweetballist5347662217.cognitiveservices.azure.com/` and currently
hosts a single **gpt-4o** deployment.

## 2. Model Availability

### GPT-5.x Models (✅ Available)

Both eastus and eastus2 have the full GPT-5 family. Key models for skwaq:

| Model | Version | SKUs (eastus2) | Capabilities |
|-------|---------|----------------|--------------|
| **gpt-5.1** | 2025-11-13 | Standard, GlobalStandard, DataZoneStandard, DataZoneProvisionedManaged, GlobalProvisionedManaged, GlobalBatch, DataZoneBatch | chatCompletion, assistants, responses |
| **gpt-5.4** | 2026-03-05 | GlobalStandard, DataZoneStandard, DataZoneProvisionedManaged, GlobalProvisionedManaged | chatCompletion, assistants, responses, agentsV2 |
| gpt-5.1-codex | 2025-11-13 | Standard, GlobalStandard, ... | chatCompletion |
| gpt-5.2-codex | 2026-01-14 | Standard, GlobalStandard, ... | chatCompletion |
| gpt-5.3-codex | 2026-02-24 | Standard, GlobalStandard, ... | chatCompletion |

**GPT-5.4 is Generally Available** with lifecycle deprecation date 2027-03-05.
It can be deployed on the existing `rysweetballist5347662217` AIServices
resource or a new one.

### Claude Opus (❌ Not Available)

**Claude models are NOT available on Azure AI Foundry.** The MaaS (Model as a
Service) catalog in both eastus and eastus2 includes 127+ third-party models
(DeepSeek, Grok, Llama, Mistral, Phi, Cohere, etc.) but **zero Anthropic /
Claude models**.

To use Claude Opus on Azure, the options are:
1. **Anthropic API directly** — already supported in skwaq via the `"anthropic"` backend
2. **AWS Bedrock** — Claude is available in Amazon Bedrock (not Azure)
3. **GitHub Copilot proxy** — the current `"copilot"` backend already routes to Claude Opus 4.6

### MaaS Alternatives Worth Noting

If Claude is unavailable and GPT-5.x doesn't meet a specific need, these
MaaS models are available on the same subscription:

- **Grok 4** (xAI) — `grok-4-fast-reasoning`, `grok-4-1-fast-reasoning`
- **DeepSeek R1/V3.2** — strong reasoning models
- **Llama 4 Maverick/Scout** — open-weight alternatives
- **Kimi K2.5** — Moonshot AI reasoning model

## 3. Infrastructure as Code (Bicep)

### Option A: Deploy GPT-5.1 on Existing AIServices Resource

The simplest path — add a deployment to the existing resource:

```bicep
// deploy-gpt51.bicep
// Adds a GPT-5.1 deployment to the existing AIServices resource.
// Usage:
//   az deployment group create \
//     --resource-group rysweet-ballistae \
//     --template-file deploy-gpt51.bicep

resource existingAIServices 'Microsoft.CognitiveServices/accounts@2024-10-01' existing = {
  name: 'rysweetballist5347662217'
}

resource gpt51Deployment 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: existingAIServices
  name: 'gpt-51-skwaq'
  sku: {
    name: 'GlobalStandard'
    capacity: 50 // 50K tokens-per-minute
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-5.1'
      version: '2025-11-13'
    }
  }
}

output endpoint string = existingAIServices.properties.endpoint
output deploymentName string = gpt51Deployment.name
```

### Option B: Full Greenfield Deployment

Creates a dedicated resource group, AIServices account, and model deployment:

```bicep
// skwaq-ai-foundry.bicep
// Deploys a new Azure AI Services resource with GPT-5.1 and GPT-5.4.
// Usage:
//   az group create --name skwaq-ai --location eastus2
//   az deployment group create \
//     --resource-group skwaq-ai \
//     --template-file skwaq-ai-foundry.bicep \
//     --parameters principalId=$(az ad signed-in-user show --query id -o tsv)

@description('Location for AI Services')
param location string = 'eastus2'

@description('Principal ID to grant Cognitive Services User role')
param principalId string

var aiServicesName = 'skwaq-ai-${uniqueString(resourceGroup().id)}'

resource aiServices 'Microsoft.CognitiveServices/accounts@2024-10-01' = {
  name: aiServicesName
  location: location
  kind: 'AIServices'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: aiServicesName
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true // Force Entra ID auth (DefaultAzureCredential)
  }
}

// GPT-5.1 deployment — best for code analysis and reasoning
resource gpt51 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: aiServices
  name: 'gpt-51'
  sku: {
    name: 'GlobalStandard'
    capacity: 100 // 100K TPM
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-5.1'
      version: '2025-11-13'
    }
  }
}

// GPT-5.4 deployment — latest model with agents support
resource gpt54 'Microsoft.CognitiveServices/accounts/deployments@2024-10-01' = {
  parent: aiServices
  name: 'gpt-54'
  sku: {
    name: 'GlobalStandard'
    capacity: 50 // 50K TPM
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: 'gpt-5.4'
      version: '2026-03-05'
    }
  }
}

// Grant "Cognitive Services User" to the deploying principal
// This enables DefaultAzureCredential token-based access (no API keys).
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(aiServices.id, principalId, 'CognitiveServicesUser')
  scope: aiServices
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'a97b65f3-24c7-4388-baec-2e87135dc908' // Cognitive Services User
    )
    principalId: principalId
    principalType: 'User'
  }
}

output endpoint string = aiServices.properties.endpoint
output gpt51DeploymentName string = gpt51.name
output gpt54DeploymentName string = gpt54.name
```

### Authentication: DefaultAzureCredential

The Bicep template sets `disableLocalAuth: true`, which forces all access
through Entra ID tokens. The `Cognitive Services User` role assignment
enables `DefaultAzureCredential` to work via:

- **Local dev:** `az login` CLI credential
- **CI/CD:** Managed identity or federated workload identity
- **Containers:** Managed identity on ACI/AKS

No API keys to rotate or leak.

## 4. Skwaq Integration Changes Required

### Current Architecture

The LLM backend in `crates/core/src/llm/mod.rs` supports two backends:

```rust
// crates/core/src/llm/mod.rs lines 104-113
match backend {
    "copilot" => Client::new_copilot().await,
    "anthropic" => create_anthropic_client(),  // uses ANTHROPIC_API_KEY
    _ => unreachable!(),
}
```

Configuration (`crates/core/src/config.rs`) has:
- `llm.reasoning` — backend name (`"copilot"` default)
- `llm.decompilation` — backend name (`"copilot"` default)
- `llm.copilot.model` — model name (`"claude-opus-4.6"` default)
- `llm.ollama.*` — Ollama settings for embeddings

### Proposed Changes for Azure Backend

#### A. Config additions (`crates/core/src/config.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    #[serde(default = "default_llm_backend")]
    pub reasoning: String,           // "copilot" | "anthropic" | "azure"
    #[serde(default = "default_llm_backend")]
    pub decompilation: String,       // "copilot" | "anthropic" | "azure"
    #[serde(default = "default_ollama")]
    pub embeddings: String,
    #[serde(default)]
    pub copilot: CopilotConfig,
    #[serde(default)]
    pub ollama: OllamaConfig,
    #[serde(default)]
    pub azure: AzureConfig,          // NEW
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureConfig {
    /// Azure AI Services endpoint, e.g. "https://skwaq-ai-xxx.cognitiveservices.azure.com/"
    #[serde(default)]
    pub endpoint: String,
    /// Deployment name, e.g. "gpt-51" or "gpt-54"
    #[serde(default)]
    pub deployment: String,
    /// API version, e.g. "2024-10-21"
    #[serde(default = "default_azure_api_version")]
    pub api_version: String,
}

fn default_azure_api_version() -> String {
    "2024-10-21".into()
}
```

#### B. Backend creation (`crates/core/src/llm/mod.rs`)

The Azure OpenAI REST API is compatible with the OpenAI chat completions
format. The key difference is:
- **URL:** `{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={version}`
- **Auth:** `Authorization: Bearer {token}` where token comes from `DefaultAzureCredential`

Implementation sketch:

```rust
"azure" => create_azure_client(&config.azure).await,

async fn create_azure_client(azure: &AzureConfig) -> anyhow::Result<Client> {
    // Use azure_identity crate for DefaultAzureCredential
    use azure_identity::DefaultAzureCredential;
    use azure_core::auth::TokenCredential;

    let credential = DefaultAzureCredential::default();
    let token = credential
        .get_token(&["https://cognitiveservices.azure.com/.default"])
        .await?;

    // Build an OpenAI-compatible client pointing at the Azure endpoint
    // RustyClawd Client would need a new constructor or config variant:
    //   Client::new_azure(endpoint, deployment, bearer_token)
    todo!("Requires RustyClawd Client extension for Azure OpenAI")
}
```

#### C. Required Rust crate dependencies

```toml
# Cargo.toml additions
azure_identity = "0.22"
azure_core = "0.22"
```

#### D. Example `skwaq.toml` configuration

```toml
[llm]
reasoning = "azure"
decompilation = "azure"
embeddings = "ollama"

[llm.azure]
endpoint = "https://rysweetballist5347662217.cognitiveservices.azure.com/"
deployment = "gpt-51-skwaq"
api_version = "2024-10-21"

[llm.ollama]
host = "http://localhost:11434"
model = "llama3.1"
embedding_model = "nomic-embed-text"
```

### Implementation Effort Estimate

| Task | Effort |
|------|--------|
| Add `AzureConfig` to config.rs | Small (1 hr) |
| Add `azure_identity` / `azure_core` deps | Small (1 hr) |
| Extend `validate_backend_name` to accept `"azure"` | Trivial |
| Implement `create_azure_client` with token refresh | Medium (4-8 hrs) |
| Extend or fork RustyClawd `Client` for Azure OpenAI URL format | Medium (4-8 hrs) |
| Update benchmark validation to allow Azure backend | Small (1 hr) |
| Integration tests with live Azure endpoint | Medium (4-8 hrs) |
| **Total** | **~2-4 days** |

## 5. Cost Estimates for Benchmark Runs

### Benchmark Parameters

- ~100K tokens per case (input + output)
- ~200 cases per eval run
- **~20M tokens per eval run**

### Azure OpenAI Pricing (GlobalStandard, Pay-as-you-go)

Prices are per 1M tokens. Estimates based on published Azure OpenAI pricing
(region: East US 2, GlobalStandard tier):

| Model | Input (per 1M) | Output (per 1M) | Est. per Eval Run* |
|-------|----------------|------------------|--------------------|
| **GPT-5.1** | ~$2.50 | ~$10.00 | **~$75 - $125** |
| **GPT-5.4** | ~$3.00 | ~$12.00 | **~$90 - $150** |
| GPT-5.1-codex | ~$2.50 | ~$10.00 | ~$75 - $125 |
| GPT-4o | ~$2.50 | ~$10.00 | ~$75 - $125 |
| o3 | ~$10.00 | ~$40.00 | ~$300 - $500 |

\*Assuming 60/40 input/output split across 20M total tokens.

### Budget Scenarios

| Scenario | Runs/Month | Monthly Cost (GPT-5.1) | Monthly Cost (GPT-5.4) |
|----------|------------|------------------------|------------------------|
| Light (weekly) | 4 | ~$300 - $500 | ~$360 - $600 |
| Moderate (daily) | 20 | ~$1,500 - $2,500 | ~$1,800 - $3,000 |
| Heavy (CI/CD) | 60 | ~$4,500 - $7,500 | ~$5,400 - $9,000 |

### Cost Optimization Strategies

1. **Prompt caching** — Azure supports automatic prompt caching for repeated
   prefixes; cached input tokens cost 50% less
2. **GlobalBatch** — GPT-5.1 supports batch processing at ~50% discount; eval
   runs are a great fit since they don't need real-time responses
3. **DataZoneStandard** — data residency within US/EU at same price as
   GlobalStandard
4. **ProvisionedManaged** — reserved capacity with predictable costs for
   sustained heavy usage (pay per PTU, not per token)

### Comparison with Current Approach

| Backend | Auth | Model | Per-Run Cost | Notes |
|---------|------|-------|--------------|-------|
| GitHub Copilot | GH token | Claude Opus 4.6 | $0 (included) | Rate-limited, no batch API |
| Anthropic Direct | API key | Claude Opus 4.6 | ~$300-$450 | $15/$75 per 1M in/out |
| **Azure (GPT-5.1)** | DefaultAzureCredential | GPT-5.1 | **~$75-$125** | Batch discount possible |
| **Azure (GPT-5.4)** | DefaultAzureCredential | GPT-5.4 | **~$90-$150** | Latest model |

Azure OpenAI with GPT-5.x is **2-4x cheaper** than direct Anthropic Claude
Opus for equivalent benchmark runs.

## 6. Recommendations

### Short-Term (This Sprint)

1. **Deploy GPT-5.1 on the existing AIServices resource** using Option A Bicep
   (one deployment, no new resources). This can be done in minutes:
   ```bash
   az deployment group create \
     --resource-group rysweet-ballistae \
     --template-file deploy-gpt51.bicep
   ```

2. **Validate the endpoint works** with a simple curl test:
   ```bash
   TOKEN=$(az account get-access-token \
     --resource https://cognitiveservices.azure.com \
     --query accessToken -o tsv)
   curl -s https://rysweetballist5347662217.cognitiveservices.azure.com/openai/deployments/gpt-51-skwaq/chat/completions?api-version=2024-10-21 \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"messages":[{"role":"user","content":"Hello"}],"max_tokens":10}'
   ```

### Medium-Term (Next Sprint)

3. **Implement the `"azure"` backend** in skwaq's LLM layer (~2-4 days).
   Key decision: extend RustyClawd's `Client` to support Azure OpenAI URLs,
   or use the `azure_openai` / `async-openai` crate with Azure support.

4. **Run comparative benchmarks**: same vulnerability dataset through both
   Claude Opus (via Copilot) and GPT-5.1 (via Azure) to compare accuracy
   and cost.

### Decision: Claude Opus on Azure

Claude Opus is **not available on Azure AI Foundry**. If you need Claude
specifically, continue using the `"copilot"` backend (GitHub Copilot proxy)
or the `"anthropic"` backend (direct API key). Do not wait for Azure
availability — Anthropic has not announced Azure AI Foundry integration.

## 7. Files Referenced

| File | Purpose |
|------|---------|
| `crates/core/src/config.rs` | LLM backend configuration structs |
| `crates/core/src/llm/mod.rs` | Backend selection and client creation |
| `crates/core/src/llm/traits.rs` | Token budget and tool execution |
| `Cargo.toml` | Dependency management |
