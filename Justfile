# PR Review Agent — build & deploy commands

# Create and install a GitHub App (one-time setup, run before first provision)
create-app:
    uv run python scripts/create_app.py

# Build cloud-init.yaml from template + source files
build:
    python3 scripts/build.py
    @echo "✓ cloud-init.yaml is ready"

# Validate the built cloud-init.yaml (requires cloud-init installed)
validate: build
    #!/usr/bin/env bash
    if ! command -v cloud-init &>/dev/null; then
        echo "Note: cloud-init not installed, skipping validation"
        exit 0
    fi
    cloud-init schema --config-file cloud-init.yaml

# Deploy agent files to a running server. The host is auto-discovered when omitted.
deploy host="":
    #!/usr/bin/env bash
    set -euo pipefail
    target='{{host}}'
    if [[ -z "$target" ]]; then target="$(uv run python scripts/status.py --ssh-target)"; fi
    scp src/agent.py src/prompt.md "$target":/opt/pr-review/
    ssh "$target" 'chown review:review /opt/pr-review/agent.py /opt/pr-review/prompt.md && systemctl restart pr-review'
    echo "✓ Deployed and restarted on $target"

# Log Codex in with ChatGPT/device auth as the review service user
codex-login host="":
    #!/usr/bin/env bash
    set -euo pipefail
    target='{{host}}'
    if [[ -z "$target" ]]; then target="$(uv run python scripts/status.py --ssh-target)"; fi
    ssh -t "$target" 'install -d -m 700 -o review -g review /home/review/.codex && sudo -u review env HOME=/home/review CODEX_HOME=/home/review/.codex codex login --device-auth && systemctl restart pr-review'
    echo "✓ Codex login complete and pr-review restarted on $target"

# Smoke-test Codex as the review service user
codex-smoke host="":
    #!/usr/bin/env bash
    set -euo pipefail
    target='{{host}}'
    if [[ -z "$target" ]]; then target="$(uv run python scripts/status.py --ssh-target)"; fi
    ssh -n "$target" 'cd /opt/pr-review && sudo -u review env HOME=/home/review CODEX_HOME=/home/review/.codex codex --sandbox read-only --ask-for-approval never exec --skip-git-repo-check --ignore-user-config --ignore-rules "Respond with exactly OK."'

# Tail service logs. The host is auto-discovered when omitted.
logs host="":
    #!/usr/bin/env bash
    set -euo pipefail
    target='{{host}}'
    if [[ -z "$target" ]]; then target="$(uv run python scripts/status.py --ssh-target)"; fi
    ssh -t "$target" 'journalctl -u pr-review -f'

# Provision a new server (build + create + configure — fully automated)
provision:
    uv run python scripts/provision.py

# Destroy the server and clean up tunnel/DNS (pass "yes" to confirm)
destroy confirm="":
    @[ "{{ confirm }}" = "yes" ] || (echo "This will delete the server and all associated resources."; echo "Run: just destroy yes"; exit 1)
    uv run python scripts/destroy.py --yes

# Check server status and health
status:
    uv run python scripts/status.py

# Run tests
test:
    uv run --group dev python -m pytest tests/ -v

# Clean build artifacts
clean:
    rm -f cloud-init.yaml
