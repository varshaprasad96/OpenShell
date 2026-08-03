#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Configure the workspace inference route so the in-sandbox agent's LLM calls to
# `inference.local` are forwarded to a real provider with the operator's key
# injected outbound. This is what lets the driver hand the sandbox only a DUMMY
# api_key while the agent still reaches the model — the real credential never
# enters the sandbox.
#
# Run this AFTER bootstrap-kind.sh create (the gateway must be registered) and
# with a port-forward held open (bootstrap-kind.sh forward). It talks to the
# gateway via the local `openshell` CLI.
#
# Usage:
#   ANTHROPIC_API_KEY=sk-ant-... demo/openhands/setup-inference.sh
#
# Environment overrides:
#   OPENHANDS_PROVIDER        provider config name          (default: anthropic)
#   OPENHANDS_PROVIDER_TYPE   provider type                 (default: anthropic)
#   OPENHANDS_CREDENTIAL_ENV  env var holding the API key   (default: ANTHROPIC_API_KEY)
#   OPENHANDS_ROUTE_MODEL     model id forced for the route (default: claude-sonnet-4-5)
#   OPENSHELL_GATEWAY         gateway name to target        (default: local)
#   OPENSHELL_BIN             openshell CLI binary          (default: openshell)

set -euo pipefail

PROVIDER="${OPENHANDS_PROVIDER:-anthropic}"
PROVIDER_TYPE="${OPENHANDS_PROVIDER_TYPE:-anthropic}"
CREDENTIAL_ENV="${OPENHANDS_CREDENTIAL_ENV:-ANTHROPIC_API_KEY}"
ROUTE_MODEL="${OPENHANDS_ROUTE_MODEL:-claude-sonnet-4-5}"
GATEWAY_NAME="${OPENSHELL_GATEWAY:-local}"
OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"

export OPENSHELL_GATEWAY="${GATEWAY_NAME}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

command -v "${OPENSHELL_BIN}" >/dev/null 2>&1 \
  || die "'${OPENSHELL_BIN}' CLI not found on PATH. Build openshell-cli or set OPENSHELL_BIN."

# The credential must be present in this shell so the CLI can read KEY=VALUE from
# the environment (we pass the bare KEY form, which resolves to the env value).
[[ -n "${!CREDENTIAL_ENV:-}" ]] \
  || die "\$${CREDENTIAL_ENV} is not set. Export your provider API key first."

log "Creating provider '${PROVIDER}' (type=${PROVIDER_TYPE}) from \$${CREDENTIAL_ENV}"
# `--credential KEY` (bare, no =VALUE) tells the CLI to read the value from the
# environment variable of that name. The key is stored gateway-side only.
if ! "${OPENSHELL_BIN}" provider create \
  --name "${PROVIDER}" \
  --type "${PROVIDER_TYPE}" \
  --credential "${CREDENTIAL_ENV}" 2>/tmp/openshell-provider.err; then
  if grep -qiE 'already exists|conflict' /tmp/openshell-provider.err; then
    log "Provider '${PROVIDER}' already exists; reusing it."
  else
    cat /tmp/openshell-provider.err >&2
    die "provider create failed"
  fi
fi

log "Setting inference route -> provider='${PROVIDER}', model='${ROUTE_MODEL}'"
"${OPENSHELL_BIN}" inference set --provider "${PROVIDER}" --model "${ROUTE_MODEL}"

log "Inference route configured. Verify with: ${OPENSHELL_BIN} inference get"
cat <<EOF

The in-sandbox agent can now reach the model via https://inference.local.
Run the demo:
  cd demo/openhands && uv run driver.py --model "anthropic/${ROUTE_MODEL}"
EOF
