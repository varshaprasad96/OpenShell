# OpenHands inside an OpenShell sandbox

This demo runs an [OpenHands](https://github.com/OpenHands/software-agent-sdk) coding
agent whose entire loop — every bash command, every file edit, and the agent's own LLM
calls — executes **inside** an OpenShell sandbox on a local `kind` Kubernetes cluster.

The security thesis: OpenShell enforces egress policy at Layer 7 inside each sandbox.
Because the agent loop runs there (not on the host), a default-deny network policy
polices the agent itself. The agent stays fully functional — its model calls are routed
through `inference.local` with the real operator key injected outbound — while it holds
only a dummy key and cannot reach any unapproved host. A `curl` to an unlisted domain
returns the proxy's HTTP 403 and an OCSF `CONNECT denied` event.

## How it works

The `openhands-agent-server` runs as a process inside the sandbox, bound to loopback.
The driver on the host:

1. creates the sandbox from a custom image (OpenShell base + OpenHands),
2. applies a default-deny network policy,
3. launches the agent-server via `exec` (the OpenShell supervisor owns PID 1, so the
   image sets no entrypoint),
4. tunnels the loopback port out over an authenticated gateway forward, and
5. connects with the OpenHands remote client (`Workspace(host=...)` →
   `RemoteConversation`), which runs the agent loop server-side.

```
host                          kind cluster / OpenShell sandbox
─────────────────────         ─────────────────────────────────────────────
driver.py
  │ create + policy set
  │ exec: agent-server ─────► 127.0.0.1:8000 (openhands-agent-server)
  │ forward :8000  ◄────────► loopback tunnel (setns, bypasses egress policy)
  │ RemoteConversation ─────► agent loop runs here
  │                             ├─ bash / file tools → sandbox filesystem
  │                             └─ LLM calls → inference.local ─► L7 proxy ─► provider
  │                                            unapproved host ─► L7 proxy ─► 403 DENY
```

## Prerequisites

- Docker, `kind`, `kubectl`, and `mise` (provides `skaffold`/`helm`).
- The `openshell` CLI on `PATH` (build it with `cargo build -p openshell-cli`), or set
  `OPENSHELL_BIN`.
- The OpenShell Python SDK's protobuf stubs, generated once with `mise run python:proto`.
  The driver imports the SDK directly from `python/openshell/` (no package install), so
  the stubs must exist before the first run.
- `uv` for running the Python driver.
- An Anthropic API key (or adapt `setup-inference.sh` for another provider).

## Run it

Stand up the cluster, gateway, and images:

```shell
demo/openhands/bootstrap-kind.sh create
```

In a second terminal, hold a port-forward to the gateway open (the driver and CLI reuse
it):

```shell
demo/openhands/bootstrap-kind.sh forward
```

Configure the inference route so `inference.local` resolves and the real key is injected
outbound (the sandbox only ever sees a dummy key):

```shell
export ANTHROPIC_API_KEY=sk-ant-...
demo/openhands/setup-inference.sh
```

Run the agent:

```shell
cd demo/openhands
uv run driver.py
```

The driver creates a sandbox, runs the default task (write and execute a small Python
program), prints the produced file, then demonstrates blocked egress before tearing the
sandbox down. Pass `--keep` to leave the sandbox running for inspection, or `--task` to
change the prompt.

## The money shot

After the agent finishes, the driver runs an unapproved `curl` from inside the sandbox:

```
[driver] attempting unapproved egress to https://example.com (expected: DENIED)
  exit_code=56
  stdout='000'
  stderr='curl: (56) CONNECT tunnel failed, response 403'
[driver] egress blocked as expected (default-deny network policy)
```

To capture the OCSF `CONNECT denied` event as a structured artifact, enable JSONL OCSF
logging on the gateway (it is off by default) and read
`/var/log/openshell-ocsf.log` from the sandbox, or watch the sandbox's stderr shorthand,
which is always on.

Confirm the real key never entered the sandbox:

```shell
uv run driver.py --keep --no-agent    # stand up sandbox + server, skip the task
# then, against the printed sandbox name:
openshell exec <sandbox-name> -- env | grep -i anthropic   # prints nothing
```

## Files

| File | Purpose |
|------|---------|
| `bootstrap-kind.sh` | Create the kind cluster, install agent-sandbox CRDs, load images, deploy the gateway, register it with the CLI. |
| `Dockerfile` | Demo sandbox image: OpenShell base + pinned OpenHands stack. |
| `setup-inference.sh` | Create the provider and set the workspace inference route. |
| `policy.yaml` | Default-deny sandbox network policy. |
| `driver.py` | The host driver: create → exec server → tunnel → RemoteConversation → egress demo → teardown. |
| `pyproject.toml` | Host-side driver dependencies (OpenHands client + OpenShell SDK). |

## Configuration

The driver and scripts read environment overrides (see each file's header for the full
list). The common ones:

| Variable | Default | Used by |
|----------|---------|---------|
| `OPENSHELL_GATEWAY` | `local` | gateway/cluster name |
| `OPENHANDS_DEMO_IMAGE` | `openshell-demo/openhands-sandbox:dev` | sandbox image |
| `OPENHANDS_MODEL` | `anthropic/claude-sonnet-4-5` | LLM model string |
| `OPENHANDS_VERSION` | `1.40.0` | pinned OpenHands version |
| `ANTHROPIC_API_KEY` | — | provider credential (setup-inference.sh) |

## Teardown

```shell
demo/openhands/bootstrap-kind.sh delete
```
