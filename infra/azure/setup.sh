#!/usr/bin/env bash
# infra/azure/setup.sh — Idempotent Azure AI Foundry setup for skwaq.
#
# Deploys model endpoints and configures RBAC. Safe to run multiple times.
# Requires: az CLI authenticated (az login), jq.
#
# Usage:
#   ./infra/azure/setup.sh                    # Deploy all configured models
#   ./infra/azure/setup.sh --models gpt-5.4   # Deploy specific model only
#   ./infra/azure/setup.sh --dry-run          # Show what would be deployed

set -euo pipefail

# ── Configuration (override via env vars) ──────────────────────────
RG="${SKWAQ_AZURE_RG:-rysweet-ballistae}"
ACCOUNT="${SKWAQ_AZURE_ACCOUNT:-rysweetballist5347662217}"
LOCATION="${SKWAQ_AZURE_LOCATION:-eastus2}"
SKU="${SKWAQ_AZURE_SKU:-GlobalStandard}"
CAPACITY="${SKWAQ_AZURE_CAPACITY:-1000}"
API_VERSION="2025-12-01"
DRY_RUN=false
MODELS_FILTER=""

# ── Model definitions ──────────────────────────────────────────────
# Format: name|version|format|deployment_suffix
MODELS=(
  "gpt-5.4|2026-03-05|OpenAI|gpt-54-skwaq"
  "gpt-5.4|2026-03-05|OpenAI|gpt-54-skwaq-2"
  "gpt-5.4|2026-03-05|OpenAI|gpt-54-skwaq-3"
  "claude-opus-4-6|1|Anthropic|claude-opus-46"
  "claude-opus-4-6|1|Anthropic|claude-opus-46-2"
)

# ── Parse args ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    --dry-run) DRY_RUN=true; shift ;;
    --models) MODELS_FILTER="$2"; shift 2 ;;
    --capacity) CAPACITY="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ── Helpers ────────────────────────────────────────────────────────
log() { echo "  [setup] $*"; }

deploy_model() {
  local name="$1" version="$2" format="$3" deployment="$4"

  # Check if deployment already exists
  local exists
  exists=$(az cognitiveservices account deployment show \
    --name "$ACCOUNT" --resource-group "$RG" \
    --deployment-name "$deployment" \
    --query "name" -o tsv 2>/dev/null || echo "")

  if [[ -n "$exists" ]]; then
    log "✓ $deployment already exists (skipping)"
    return 0
  fi

  if $DRY_RUN; then
    log "Would deploy: $deployment ($name v$version, $format, ${CAPACITY}K TPM)"
    return 0
  fi

  log "Deploying $deployment ($name v$version, $format, ${CAPACITY}K TPM)..."

  if [[ "$format" == "Anthropic" ]]; then
    # Anthropic MaaS models require modelProviderData via REST API
    az rest --method PUT \
      --url "https://management.azure.com/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$RG/providers/Microsoft.CognitiveServices/accounts/$ACCOUNT/deployments/$deployment?api-version=$API_VERSION" \
      --body "{
        \"sku\": {\"name\": \"$SKU\", \"capacity\": $CAPACITY},
        \"properties\": {
          \"model\": {\"format\": \"$format\", \"name\": \"$name\", \"version\": \"$version\"},
          \"modelProviderData\": {\"industry\": \"Technology\", \"organizationName\": \"Microsoft\", \"countryCode\": \"US\"}
        }
      }" --query "name" -o tsv 2>&1 || {
        log "⚠ $deployment failed (may need quota increase for $name)"
        return 1
      }
  else
    # OpenAI models use standard Bicep deployment
    az cognitiveservices account deployment create \
      --name "$ACCOUNT" --resource-group "$RG" \
      --deployment-name "$deployment" \
      --model-name "$name" --model-version "$version" \
      --model-format "$format" \
      --sku-name "$SKU" --sku-capacity "$CAPACITY" \
      --query "name" -o tsv 2>&1 || {
        log "⚠ $deployment failed"
        return 1
      }
  fi

  log "✓ $deployment deployed"
}

# ── Main ───────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════╗"
echo "║  SKWAQ Azure AI Foundry Setup                   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
log "Resource group: $RG"
log "Account: $ACCOUNT"
log "Location: $LOCATION"
log "SKU: $SKU, Capacity: ${CAPACITY}K TPM"
echo ""

SUCCEEDED=0
SKIPPED=0
FAILED=0

for model_def in "${MODELS[@]}"; do
  IFS='|' read -r name version format deployment <<< "$model_def"

  # Filter if --models specified
  if [[ -n "$MODELS_FILTER" ]] && [[ "$name" != *"$MODELS_FILTER"* ]]; then
    continue
  fi

  if deploy_model "$name" "$version" "$format" "$deployment"; then
    SUCCEEDED=$((SUCCEEDED + 1))
  else
    FAILED=$((FAILED + 1))
  fi
done

echo ""
log "Done: $SUCCEEDED succeeded, $FAILED failed"

# ── Generate skwaq.toml snippet ────────────────────────────────────
ENDPOINT=$(az cognitiveservices account show --name "$ACCOUNT" --resource-group "$RG" --query "properties.endpoint" -o tsv 2>/dev/null)
GPT_DEPLOYMENTS=$(for m in "${MODELS[@]}"; do IFS='|' read -r n v f d <<< "$m"; [[ "$f" == "OpenAI" ]] && echo -n "$d,"; done)
CLAUDE_DEPLOYMENTS=$(for m in "${MODELS[@]}"; do IFS='|' read -r n v f d <<< "$m"; [[ "$f" == "Anthropic" ]] && echo -n "$d,"; done)

echo ""
echo "── Add to skwaq.toml ──────────────────────────────"
echo "[llm.azure]"
echo "endpoint = \"$ENDPOINT\""
echo "# GPT-5.4 (round-robin across ${GPT_DEPLOYMENTS%,}):"
echo "deployment = \"${GPT_DEPLOYMENTS%,}\""
echo "# Or Claude Opus 4.6 (if quota approved):"
echo "# deployment = \"${CLAUDE_DEPLOYMENTS%,}\""
echo "api_version = \"2024-10-21\""
