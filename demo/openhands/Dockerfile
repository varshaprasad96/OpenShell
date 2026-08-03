# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Demo sandbox image: OpenShell base + the OpenHands agent-server.
#
# This image runs INSIDE an OpenShell sandbox. The OpenShell supervisor is
# forced as PID 1 by every compute driver, so this image deliberately sets no
# ENTRYPOINT/CMD — the agent-server is launched on demand via `ExecSandbox`
# (see driver.py). All four OpenHands packages are pinned to the same version
# because their sibling dependencies are not enforced by package metadata
# (OpenHands issue #4156).

ARG BASE_IMAGE=ghcr.io/nvidia/openshell-community/sandboxes/base:latest
FROM ${BASE_IMAGE}

# Keep in lockstep across all four OpenHands packages.
ARG OPENHANDS_VERSION=1.40.0

USER root

# System deps the agent-server needs at runtime:
#   python3/pip  - run the server and install wheels
#   tmux         - required by TerminalTool (libtmux drives a tmux session)
#   curl         - health checks + the demo's blocked-egress command
# The base image is community-published and its package manager is not
# guaranteed, so detect apt/apk and fall back to whatever is preinstalled.
RUN set -eux; \
    if command -v apt-get >/dev/null 2>&1; then \
        apt-get update; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            python3 python3-pip python3-venv tmux curl ca-certificates; \
        rm -rf /var/lib/apt/lists/*; \
    elif command -v apk >/dev/null 2>&1; then \
        apk add --no-cache python3 py3-pip tmux curl ca-certificates; \
    fi

# Install uv (fast, reproducible resolver) then the pinned OpenHands stack into
# a dedicated venv. The base image's system Python is externally-managed
# (PEP 668), so we install into /opt/openhands and put it first on PATH — this
# makes `python3 -m openhands.agent_server` (see driver.py) resolve to the venv.
ENV OPENHANDS_VENV=/opt/openhands
ENV PATH=${OPENHANDS_VENV}/bin:${PATH}
RUN set -eux; \
    (pip3 install --no-cache-dir --break-system-packages uv \
        || pip3 install --no-cache-dir uv); \
    uv venv --python python3 "${OPENHANDS_VENV}"; \
    VIRTUAL_ENV="${OPENHANDS_VENV}" uv pip install --no-cache \
        "openhands-sdk==${OPENHANDS_VERSION}" \
        "openhands-tools==${OPENHANDS_VERSION}" \
        "openhands-workspace==${OPENHANDS_VERSION}" \
        "openhands-agent-server==${OPENHANDS_VERSION}" \
        libtmux

# Fail the build loudly if the base image lacked a tool and no package manager
# was available to add it — better here than at demo time.
RUN set -eux; python3 --version; tmux -V; curl --version | head -n1; \
    python3 -c "import openhands.agent_server"

# No WORKDIR is set: the agent-server is launched with an explicit `cd` into the
# policy-writable work dir (/sandbox, see driver.py), and the base image's own
# entrypoint/PATH conventions are left intact.

# Intentionally no ENTRYPOINT/CMD — the OpenShell supervisor owns PID 1.
