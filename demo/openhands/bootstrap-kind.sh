#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Bootstrap a local kind cluster running the OpenShell gateway for the
# OpenHands demo. This mirrors tasks/scripts/helm-k3s-local.sh (the paved-road
# k3d flow) but targets kind:
#
#   1. create a kind cluster
#   2. install the upstream agent-sandbox CRDs + controller (agents.x-k8s.io)
#   3. load the sandbox images kind cannot pull for us (base + the OpenHands
#      demo image) — skaffold handles gateway/supervisor loading itself because
#      it detects the "kind-" kube-context and uses `kind load`
#   4. deploy the gateway via `skaffold run` (ci/values-skaffold.yaml: plaintext
#      + unauthenticated dev auth)
#   5. register the gateway with the local `openshell` CLI
#
# Usage:
#   demo/openhands/bootstrap-kind.sh create     # stand everything up
#   demo/openhands/bootstrap-kind.sh forward    # foreground port-forward (run in its own terminal)
#   demo/openhands/bootstrap-kind.sh status
#   demo/openhands/bootstrap-kind.sh delete

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CLUSTER_NAME="${OPENHANDS_KIND_CLUSTER:-openhands-openshell}"
KIND_CONTEXT="kind-${CLUSTER_NAME}"
NAMESPACE="${OPENHANDS_NAMESPACE:-openshell}"

# Pinned upstream agent-sandbox release. The Kubernetes driver supports the
# v1beta1 Sandbox API introduced in v0.5.0.
AGENT_SANDBOX_VERSION="${AGENT_SANDBOX_VERSION:-v0.5.0}"

# Community base sandbox image (public on ghcr) and the demo image built from
# demo/openhands/Dockerfile. The demo image name contains "/" and ":" so
# OpenShell treats it as a complete reference (crates/openshell-core/src/image.rs).
BASE_SANDBOX_IMAGE="${OPENHANDS_BASE_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"
DEMO_IMAGE="${OPENHANDS_DEMO_IMAGE:-openshell-demo/openhands-sandbox:dev}"
OPENHANDS_VERSION="${OPENHANDS_VERSION:-1.40.0}"

# Local port forwarded to the gateway's gRPC service (:8080). The registered
# gateway endpoint uses this port, so `forward` and the driver must reuse it.
GATEWAY_LOCAL_PORT="${OPENHANDS_GATEWAY_PORT:-8090}"
GATEWAY_ENDPOINT="http://127.0.0.1:${GATEWAY_LOCAL_PORT}"
GATEWAY_NAME="${OPENHANDS_GATEWAY_NAME:-local}"

OPENSHELL_BIN="${OPENSHELL_BIN:-openshell}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || die "$1 not found on PATH. $2"
}

require_tools() {
  require docker "Install Docker Desktop (macOS) or Docker Engine (Linux)."
  docker info >/dev/null 2>&1 || die "Docker does not appear to be running."
  require kind "Install kind: https://kind.sigs.k8s.io/ (or 'brew install kind')."
  require kubectl "Run: mise install"
  require mise "Install mise: https://mise.jdx.dev/ (skaffold/helm are provided through it)."
}

kube() { kubectl --context "${KIND_CONTEXT}" "$@"; }

cluster_exists() { kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; }

cmd_create() {
  require_tools

  if cluster_exists; then
    log "kind cluster '${CLUSTER_NAME}' already exists."
  else
    log "Creating kind cluster '${CLUSTER_NAME}'..."
    kind create cluster --name "${CLUSTER_NAME}" --wait 120s
  fi
  kubectl config use-context "${KIND_CONTEXT}" >/dev/null

  log "Installing agent-sandbox ${AGENT_SANDBOX_VERSION} (CRDs + controller)..."
  local manifest="https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/manifest.yaml"
  kube apply -f "${manifest}"
  kube wait --for=condition=established --timeout=90s crd/sandboxes.agents.x-k8s.io

  log "Preloading base sandbox image into the cluster: ${BASE_SANDBOX_IMAGE}"
  docker image inspect "${BASE_SANDBOX_IMAGE}" >/dev/null 2>&1 || docker pull "${BASE_SANDBOX_IMAGE}"
  kind load docker-image "${BASE_SANDBOX_IMAGE}" --name "${CLUSTER_NAME}"

  log "Building and loading the OpenHands demo image: ${DEMO_IMAGE}"
  docker build \
    --build-arg "BASE_IMAGE=${BASE_SANDBOX_IMAGE}" \
    --build-arg "OPENHANDS_VERSION=${OPENHANDS_VERSION}" \
    -t "${DEMO_IMAGE}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${SCRIPT_DIR}"
  kind load docker-image "${DEMO_IMAGE}" --name "${CLUSTER_NAME}"

  log "Deploying the gateway via skaffold (builds + loads gateway/supervisor, helm installs)..."
  # skaffold reads the current kube-context; it detects the kind cluster from
  # the "kind-" prefix and loads locally built images with `kind load`.
  #
  # SKAFFOLD_STATUS_CHECK=false: skaffold only builds + `helm install`, then
  # returns immediately instead of blocking on rollout. The freshly-installed
  # gateway pod crash-loops until we apply the state-dir fix below, so we own the
  # readiness wait ourselves rather than letting skaffold time out on it.
  ( cd "${ROOT}/deploy/helm/openshell" && SKAFFOLD_STATUS_CHECK=false mise run helm:skaffold:run )

  fix_gateway_state_dir

  log "Waiting for the gateway to become ready..."
  # The chart deploys the gateway as a StatefulSet by default; fall back to a
  # Deployment if the topology changes.
  if ! kube -n "${NAMESPACE}" rollout status statefulset/openshell --timeout=180s 2>/dev/null; then
    kube -n "${NAMESPACE}" rollout status deployment/openshell --timeout=180s
  fi

  register_gateway

  cat <<EOF

$(log "kind cluster '${CLUSTER_NAME}' is ready.")
  Context:  ${KIND_CONTEXT}
  Gateway:  ${GATEWAY_ENDPOINT} (registered as '${GATEWAY_NAME}')
  Sandbox image for the demo: ${DEMO_IMAGE}

Next:
  1. In a separate terminal, keep a port-forward open:
       demo/openhands/bootstrap-kind.sh forward
  2. Run the demo driver:
       cd demo/openhands && uv run driver.py
EOF
}

# Point the gateway's credential/state directory at its writable persistent
# volume. The chart runs the gateway as a non-root UID with no HOME set, so the
# default state path ($HOME/.local/state -> /.local/state) is unwritable and the
# process crash-loops on startup. The StatefulSet already mounts a writable PVC
# at /var/openshell (fsGroup 1000); XDG_STATE_HOME redirects state there.
#
# This is applied post-install rather than baked into the chart to keep the demo
# self-contained (no edits to deploy/helm/openshell). A StatefulSet rolling
# update will not replace a pod that never became Ready, so the crash-looping
# pod is deleted explicitly to force recreation with the new env.
fix_gateway_state_dir() {
  if ! kube -n "${NAMESPACE}" get statefulset/openshell >/dev/null 2>&1; then
    return 0  # Deployment topology (no PVC): nothing to redirect.
  fi
  log "Redirecting gateway state to the writable PVC (XDG_STATE_HOME=/var/openshell)..."
  kube -n "${NAMESPACE}" set env statefulset/openshell XDG_STATE_HOME=/var/openshell
  kube -n "${NAMESPACE}" delete pod openshell-0 --ignore-not-found >/dev/null 2>&1 || true
}

# Register the gateway with the CLI using a short-lived port-forward, so the
# on-disk gateway metadata (endpoint + auth mode) is written for the SDK's
# from_active_cluster() to consume later.
register_gateway() {
  if ! command -v "${OPENSHELL_BIN}" >/dev/null 2>&1; then
    warn "'${OPENSHELL_BIN}' CLI not found; skipping gateway registration."
    warn "Build it (cargo build -p openshell-cli) or set OPENSHELL_BIN, then run:"
    warn "  ${OPENSHELL_BIN} gateway add ${GATEWAY_ENDPOINT} --local --name ${GATEWAY_NAME}"
    return 0
  fi

  log "Registering gateway '${GATEWAY_NAME}' (${GATEWAY_ENDPOINT})..."
  kube -n "${NAMESPACE}" port-forward "svc/openshell" "${GATEWAY_LOCAL_PORT}:8080" >/dev/null 2>&1 &
  local pf_pid=$!
  # shellcheck disable=SC2064
  trap "kill ${pf_pid} >/dev/null 2>&1 || true" RETURN

  wait_for_port "${GATEWAY_LOCAL_PORT}" || die "gateway port-forward never came up"
  "${OPENSHELL_BIN}" gateway add "${GATEWAY_ENDPOINT}" --local --name "${GATEWAY_NAME}"
}

wait_for_port() {
  local port="$1" i
  for i in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
      exec 3>&- 3<&- 2>/dev/null || true
      return 0
    fi
    sleep 1
  done
  return 1
}

cmd_forward() {
  require kubectl "Run: mise install"
  log "Forwarding ${GATEWAY_ENDPOINT} -> svc/openshell:8080 (Ctrl-C to stop)"
  exec kubectl --context "${KIND_CONTEXT}" -n "${NAMESPACE}" \
    port-forward "svc/openshell" "${GATEWAY_LOCAL_PORT}:8080"
}

cmd_status() {
  require kind "Install kind."
  kind get clusters
  if cluster_exists; then
    kube -n "${NAMESPACE}" get pods 2>/dev/null || true
  fi
}

cmd_delete() {
  require kind "Install kind."
  if cluster_exists; then
    kind delete cluster --name "${CLUSTER_NAME}"
    log "Deleted kind cluster '${CLUSTER_NAME}'."
  else
    log "No kind cluster named '${CLUSTER_NAME}'."
  fi
  if command -v "${OPENSHELL_BIN}" >/dev/null 2>&1; then
    "${OPENSHELL_BIN}" gateway remove "${GATEWAY_NAME}" >/dev/null 2>&1 || true
  fi
}

usage() {
  cat >&2 <<EOF
usage: $(basename "$0") <create|forward|status|delete>

  create    Create the kind cluster, install agent-sandbox, load images,
            deploy the gateway, and register it with the CLI.
  forward    Foreground port-forward ${GATEWAY_ENDPOINT} -> gateway (run in its own terminal).
  status    Show clusters and gateway pods.
  delete    Delete the kind cluster and deregister the gateway.

Environment overrides: OPENHANDS_KIND_CLUSTER, OPENHANDS_NAMESPACE,
  AGENT_SANDBOX_VERSION, OPENHANDS_BASE_SANDBOX_IMAGE, OPENHANDS_DEMO_IMAGE,
  OPENHANDS_VERSION, OPENHANDS_GATEWAY_PORT, OPENHANDS_GATEWAY_NAME, OPENSHELL_BIN.
EOF
}

main() {
  case "${1:-}" in
    create) cmd_create ;;
    forward) cmd_forward ;;
    status) cmd_status ;;
    delete) cmd_delete ;;
    -h | --help | help) usage ;;
    "") usage; exit 1 ;;
    *) die "unknown command '${1}'" ;;
  esac
}

main "$@"
