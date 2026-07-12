#!/usr/bin/env python3
"""Provision a Hetzner server with the PR review agent — fully automated.

Reads configuration from .env, creates a server via the Hetzner API,
waits for cloud-init, injects GitHub App credentials and reviewer config,
sets up a Cloudflare Tunnel, and starts the service.

Requires ``just create-app`` to have been run first (GitHub App + webhook
are configured there).

Usage:
    python3 scripts/provision.py          # provision from .env
    just provision                        # same via Justfile
"""

import base64
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

import requests
from hcloud import APIException, Client
from hcloud.images import Image
from hcloud.locations import Location
from hcloud.server_types import ServerType
from hcloud.ssh_keys import SSHKey

# ---------------------------------------------------------------------------
# Reuse the existing build system and shared utilities
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import (  # noqa: E402
    SSH_OPTS,
    ProvisionError,
    cf_request,
    load_config,
    ssh,
    wait_for_cloud_init,
    wait_for_ssh,
)
from build import BuildError, build  # noqa: E402
from destroy import (  # noqa: E402
    delete_dns_record,
    delete_server,
    delete_tunnel,
)


# ---------------------------------------------------------------------------
# SSH key management
# ---------------------------------------------------------------------------
def _query_agent(sock: str | None = None) -> list[str]:
    """Query an SSH agent for its public keys.

    If *sock* is provided it is passed via ``SSH_AUTH_SOCK``; otherwise
    the default agent (whatever ``SSH_AUTH_SOCK`` already points to) is
    used.  Returns a list of key lines (one per key), or an empty list.
    """
    env = None
    if sock:
        env = {**os.environ, "SSH_AUTH_SOCK": sock}
    try:
        result = subprocess.run(
            ["ssh-add", "-L"], capture_output=True, text=True,
            timeout=5, env=env,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return []


def _identity_agent_from_ssh_config() -> str | None:
    """Parse ``~/.ssh/config`` for an ``IdentityAgent`` directive.

    Returns the expanded socket path, or ``None`` if not configured.
    Handles tilde (``~/...``) expansion.
    """
    config_path = Path.home() / ".ssh" / "config"
    if not config_path.exists():
        return None
    try:
        for line in config_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("identityagent"):
                _, _, value = stripped.partition(" ")
                value = value.strip().strip('"')
                if value.startswith("~/"):
                    value = str(Path.home() / value[2:])
                if Path(value).exists():
                    return value
    except OSError:
        pass
    return None


def _collect_agent_keys() -> list[tuple[str, str]]:
    """Collect all keys from available SSH agents.

    Returns a list of ``(label, key_line)`` tuples.
    """
    results: list[tuple[str, str]] = []
    agents: list[tuple[str, str | None]] = [
        ("default agent", None),
    ]
    identity_agent = _identity_agent_from_ssh_config()
    if identity_agent:
        agents.append(("IdentityAgent (SSH config)", identity_agent))

    for label, sock in agents:
        for key_line in _query_agent(sock):
            results.append((label, key_line))
    return results


def _match_key_by_comment(keys: list[tuple[str, str]], comment: str) -> str | None:
    """Find a key whose comment field matches the given string.

    Comparison is case-insensitive.  Returns the key line or ``None``.
    """
    needle = comment.lower()
    for _label, key_line in keys:
        parts = key_line.split(None, 2)
        key_comment = parts[2] if len(parts) >= 3 else ""
        if key_comment.lower() == needle:
            return key_line
    return None


def find_local_pubkey(config: dict | None = None) -> str:
    """Find the user's SSH public key. Returns the public key content.

    If ``config`` contains an ``SSH_KEY`` value, it is used to select
    the key explicitly:

    * **File path** (contains ``/`` or ends with ``.pub``): read the
      file directly.  Tilde expansion is applied.
    * **Comment string** (anything else): match against the comment
      field of keys from all available SSH agents.

    Without ``SSH_KEY`` the function auto-discovers keys in this order:

    1. Standard file paths (``~/.ssh/id_{ed25519,ecdsa,rsa}.pub``)
    2. Default SSH agent (``SSH_AUTH_SOCK``)
    3. ``IdentityAgent`` from ``~/.ssh/config`` (1Password, Secretive, …)
    """
    ssh_key_hint = (config or {}).get("SSH_KEY", "").strip()

    # ── Explicit selection via SSH_KEY ──────────────────────────────
    if ssh_key_hint:
        is_path = "/" in ssh_key_hint or ssh_key_hint.endswith(".pub")
        if is_path:
            # Treat as file path
            expanded = ssh_key_hint
            if expanded.startswith("~/"):
                expanded = str(Path.home() / expanded[2:])
            path = Path(expanded)
            if not path.is_file():
                raise ProvisionError(f"SSH_KEY file not found: {path}")
            pubkey = path.read_text().strip()
            print(f"  Using SSH key from file: {path}")
            return pubkey
        else:
            # Treat as agent key comment
            agent_keys = _collect_agent_keys()
            key_line = _match_key_by_comment(agent_keys, ssh_key_hint)
            if key_line:
                print(f"  Using SSH key matching comment: {ssh_key_hint}")
                return key_line
            # List available comments to help the user
            available = []
            for _label, kl in agent_keys:
                parts = kl.split(None, 2)
                if len(parts) >= 3:
                    available.append(parts[2])
            hint = ""
            if available:
                hint = "\n  Available keys:\n" + "\n".join(
                    f"    - {c}" for c in available
                )
            raise ProvisionError(
                f"No SSH key found with comment matching '{ssh_key_hint}'.{hint}"
            )

    # ── Auto-discovery ─────────────────────────────────────────────
    candidates = [
        Path.home() / ".ssh" / "id_ed25519.pub",
        Path.home() / ".ssh" / "id_ecdsa.pub",
        Path.home() / ".ssh" / "id_rsa.pub",
    ]
    for path in candidates:
        if path.exists():
            return path.read_text().strip()

    # Fallback: first key from any available agent
    agent_keys = _collect_agent_keys()
    if agent_keys:
        label, key_line = agent_keys[0]
        parts = key_line.split()
        key_comment = parts[2] if len(parts) >= 3 else "(no comment)"
        print(f"  Using SSH key from {label}: {parts[0]} {key_comment}")
        return key_line

    raise ProvisionError(
        "No SSH public key found. Expected ~/.ssh/id_ed25519.pub, "
        "~/.ssh/id_ecdsa.pub, or ~/.ssh/id_rsa.pub — or a key loaded in "
        "ssh-agent / IdentityAgent (1Password, Secretive, etc.). "
        "You can also set SSH_KEY in .env to select a specific key."
    )


def _local_key_fingerprint(pubkey_content: str) -> str:
    """Compute the MD5 fingerprint of a local SSH public key.

    Returns the fingerprint in the ``aa:bb:cc:...`` format used by Hetzner.

    Uses a temporary file rather than ``ssh-keygen -lf -`` (stdin) because
    reading from stdin requires OpenSSH >= 6.9.
    """
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".pub", delete=True) as tmp:
        tmp.write(pubkey_content)
        tmp.flush()
        result = subprocess.run(
            ["ssh-keygen", "-lf", tmp.name, "-E", "md5"],
            capture_output=True, text=True, timeout=10,
        )
    if result.returncode != 0:
        raise ProvisionError(f"ssh-keygen failed: {result.stderr.strip()}")
    # Output format: "2048 MD5:aa:bb:cc:... comment (RSA)"
    return result.stdout.split()[1].removeprefix("MD5:")


def ensure_ssh_key(client: Client, pubkey_content: str, name: str = "pr-review") -> tuple[SSHKey, bool]:
    """Find or create the SSH key on Hetzner (matched by fingerprint).

    Returns ``(key, was_created)`` — the bool indicates whether the key was
    newly created (True) or already existed and was reused (False).

    Compares cryptographic fingerprints rather than raw key text so that
    differing comment fields (e.g. ``user@newhost`` vs ``user@oldhost``)
    don't cause a false "different key" mismatch.
    """
    try:
        key = client.ssh_keys.create(name=name, public_key=pubkey_content)
        print(f"  Created SSH key '{name}' on Hetzner")
        return key, True
    except APIException as e:
        if e.code == "uniqueness_error":
            local_fp = _local_key_fingerprint(pubkey_content)
            for key in client.ssh_keys.get_all():
                if key.fingerprint == local_fp:
                    print(f"  Reusing SSH key '{key.name}' on Hetzner")
                    return key, False
            # Name collision with a different key
            raise ProvisionError(
                f"SSH key named '{name}' already exists on Hetzner but doesn't match "
                f"your local public key. Rename the existing SSH key in the Hetzner "
                f"console (key is named after SERVER_NAME='{name}')."
            ) from e
        raise ProvisionError(f"Failed to create/find SSH key: {e}") from e


# ---------------------------------------------------------------------------
# Hetzner server
# ---------------------------------------------------------------------------
def create_server(client: Client, config: dict, ssh_key: SSHKey, cloud_init: str):
    """Create a Hetzner server with cloud-init user data."""
    name = config["SERVER_NAME"]

    # Fail-fast if server already exists
    existing = client.servers.get_by_name(name)
    if existing:
        raise ProvisionError(
            f"Server '{name}' already exists (id={existing.id}, ip={existing.public_net.ipv4.ip}). "
            f"Run `just destroy` first."
        )

    print(f"  Creating server '{name}' ({config['SERVER_TYPE']} in {config['SERVER_LOCATION']})...")
    response = client.servers.create(
        name=name,
        server_type=ServerType(name=config["SERVER_TYPE"]),
        image=Image(name=config["SERVER_IMAGE"]),
        location=Location(name=config["SERVER_LOCATION"]),
        ssh_keys=[ssh_key],
        user_data=cloud_init,
    )
    server = response.server
    print(f"  Server created: id={server.id}")

    # Wait for Hetzner to report it as running
    print("  Waiting for server status 'running'...", end="", flush=True)
    for _ in range(60):
        try:
            server = client.servers.get_by_id(server.id)
        except APIException:
            # Transient API error — keep polling
            print(".", end="", flush=True)
            time.sleep(5)
            continue
        if server.status == "running":
            print(" ok")
            return server
        if server.status in ("error", "off"):
            print()
            raise ProvisionError(
                f"Server entered state '{server.status}' — check Hetzner console"
            )
        print(".", end="", flush=True)
        time.sleep(5)
    raise ProvisionError("Server did not reach 'running' status in time")


# ---------------------------------------------------------------------------
# Auth injection
# ---------------------------------------------------------------------------
def _upsert_env_var(ip: str, key: str, value: str, *, label: str = ""):
    """Upsert a single key=value into the server's /opt/pr-review/.env.

    Value is piped via stdin to avoid exposing it in process args.

    NOTE: ``key`` is interpolated into the remote shell command.  This is safe
    because all callers pass hard-coded key names (``GH_APP_ID`` etc.), never
    user-supplied input.  Do not expose this as a general-purpose API.
    """
    if not re.match(r"^[A-Z_][A-Z0-9_]*$", key):
        raise ValueError(f"Unsafe env key: {key!r}")
    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{ip}",
         f"VALUE=$(cat) && "
         f"TMPFILE=$(mktemp -p /opt/pr-review/) && "
         f"{{ grep -v '^{key}=' /opt/pr-review/.env || true; }} > \"$TMPFILE\" && "
         f"chmod 600 \"$TMPFILE\" && "
         f"chown review:review \"$TMPFILE\" && "
         f"mv \"$TMPFILE\" /opt/pr-review/.env && "
         f"printf '{key}=%s\\n' \"${{VALUE}}\" >> /opt/pr-review/.env && "
         f"grep -q '^{key}=' /opt/pr-review/.env"],
        input=value, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        display = label or key
        raise ProvisionError(
            f"Env var injection failed for {display} (rc={result.returncode})\n"
            f"stderr: {result.stderr.strip()}"
        )


def deploy_agent_files(ip: str, root: Path):
    """Copy agent.py and prompt.md to the server via SCP.

    These files are not embedded in cloud-init because Hetzner's user_data
    limit is 32 KB and agent.py alone exceeds that.
    """
    src_dir = root / "src"
    for filename in ("agent.py", "prompt.md"):
        local = src_dir / filename
        if not local.is_file():
            raise ProvisionError(f"Source file not found: {local}")
        result = subprocess.run(
            ["scp", *SSH_OPTS, str(local), f"root@{ip}:/opt/pr-review/{filename}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            raise ProvisionError(
                f"Failed to copy {filename} to server (rc={result.returncode})\n"
                f"stderr: {result.stderr.strip()}"
            )
    # Fix ownership (cloud-init creates the directory as root)
    ssh(ip, "chown review:review /opt/pr-review/agent.py /opt/pr-review/prompt.md")
    print("  Copied agent.py and prompt.md to server")


def _maybe_login_codex(ip: str, config: dict):
    """Seed Codex ChatGPT auth for the review user when configured.

    CODEX_ACCESS_TOKEN is consumed over stdin and is not written to the
    service env file. If absent, the user can run ``codex login`` manually
    as the ``review`` user after provisioning.
    """
    if config.get("REVIEW_ENGINE", "codex").strip().lower() != "codex":
        return

    token = config.get("CODEX_ACCESS_TOKEN", "").strip()
    if not token:
        print("  Codex access token not set; run Codex login manually after provisioning")
        return

    print("  Seeding Codex login for review user...")
    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{ip}",
         "install -d -m 700 -o review -g review /home/review/.codex && "
         "sudo -u review env CODEX_HOME=/home/review/.codex "
         "codex login --with-access-token"],
        input=token, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise ProvisionError(
            f"Codex login failed (rc={result.returncode})\n"
            f"stderr: {result.stderr.strip()}"
        )


def inject_auth(ip: str, config: dict):
    """Inject GitHub App credentials and reviewer configuration into the server.

    Copies the App private key PEM and upserts env vars into the service
    env file.  Uses stdin for all secret values to avoid process-arg exposure.
    Re-running is safe (upsert logic).
    """
    # Preflight: verify gh CLI is installed (cloud-init may not have finished)
    try:
        ssh(ip, "command -v gh", timeout=10, label="check gh installed")
    except ProvisionError:
        raise ProvisionError(
            f"GitHub CLI (gh) not found on server. "
            f"Check cloud-init logs: ssh root@{ip} cloud-init status --long"
        )
    if config.get("REVIEW_ENGINE", "codex").strip().lower() == "codex":
        try:
            ssh(ip, "command -v codex", timeout=10, label="check codex installed")
        except ProvisionError:
            raise ProvisionError(
                f"Codex CLI not found on server. "
                f"Check cloud-init logs: ssh root@{ip} cloud-init status --long"
            )

    # Copy GitHub App private key to the server
    print("  Injecting GitHub App private key...")
    pem_path = Path(config["GH_APP_PRIVATE_KEY_FILE"])
    if not pem_path.is_file():
        raise ProvisionError(f"Private key not found: {pem_path}")
    pem_content = pem_path.read_text()

    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{ip}",
         "cat > /opt/pr-review/github-app.pem && "
         "chmod 600 /opt/pr-review/github-app.pem && "
         "chown review:review /opt/pr-review/github-app.pem"],
        input=pem_content, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise ProvisionError(
            f"PEM injection failed (rc={result.returncode})\n"
            f"stderr: {result.stderr.strip()}"
        )

    # Inject GitHub App env vars
    print("  Injecting GitHub App configuration...")
    _upsert_env_var(ip, "GH_APP_ID", config["GH_APP_ID"])
    _upsert_env_var(ip, "GH_INSTALLATION_ID", config["GH_INSTALLATION_ID"])
    _upsert_env_var(ip, "GH_APP_PRIVATE_KEY_FILE", "/opt/pr-review/github-app.pem")
    _upsert_env_var(ip, "GITHUB_WEBHOOK_SECRET", config["GITHUB_WEBHOOK_SECRET"],
                    label="GITHUB_WEBHOOK_SECRET")

    # Reviewer configuration. CODEX_ACCESS_TOKEN is intentionally excluded:
    # if present, it is consumed once by _maybe_login_codex and never stored
    # in the service env file where untrusted review prompts could reach it.
    print("  Injecting reviewer configuration...")
    for key in (
        "REVIEW_ENGINE",
        "CODEX_MODEL",
        "CODEX_SANDBOX",
        "CODEX_APPROVAL_POLICY",
        "CODEX_TIMEOUT_SECONDS",
        "CODEX_WEB_SEARCH",
        "CODEX_EPHEMERAL",
        "CODEX_IGNORE_USER_CONFIG",
        "CODEX_IGNORE_RULES",
    ):
        if config.get(key):
            _upsert_env_var(ip, key, config[key])

    _maybe_login_codex(ip, config)


# ---------------------------------------------------------------------------
# Cloudflare Tunnel
# ---------------------------------------------------------------------------
def setup_tunnel(config: dict, server_ip: str, created: dict | None = None) -> str:
    """Create a Cloudflare Tunnel, configure DNS, and install on the server.

    If a tunnel with the same name already exists, reuses it instead of
    creating a duplicate.  ``created`` is updated progressively so that
    ``_auto_cleanup`` can clean up resources even if this function fails
    mid-way (e.g. after DNS creation but before cloudflared install).
    """
    if created is None:
        created = {}
    token = config["CF_API_TOKEN"]
    account = config["CF_ACCOUNT_ID"]
    zone = config["CF_ZONE_ID"]
    hostname = config["TUNNEL_HOSTNAME"]
    tunnel_name = config.get("SERVER_NAME", "pr-review")

    # Validate hostname belongs to the configured zone
    zone_data = cf_request("GET", f"/zones/{zone}", token)
    zone_name = zone_data.get("result", {}).get("name", "")
    if not zone_name:
        raise ProvisionError(
            f"Could not read zone name for CF_ZONE_ID={zone} — "
            f"check that the zone ID is correct and the API token has access"
        )
    if not hostname.endswith(f".{zone_name}") and hostname != zone_name:
        raise ProvisionError(
            f"TUNNEL_HOSTNAME '{hostname}' does not belong to zone '{zone_name}' "
            f"(CF_ZONE_ID={zone}). Check your .env configuration."
        )

    # 1. Create tunnel (or reuse existing)
    existing = cf_request(
        "GET", f"/accounts/{account}/cfd_tunnel",
        token, params={"name": tunnel_name, "is_deleted": "false"},
    )
    existing_tunnels = existing.get("result", [])
    if existing_tunnels:
        tunnel_id = existing_tunnels[0]["id"]
        print(f"  Reusing existing Cloudflare Tunnel '{tunnel_name}' ({tunnel_id})")
    else:
        print(f"  Creating Cloudflare Tunnel '{tunnel_name}'...")
        tunnel_secret = base64.b64encode(secrets.token_bytes(32)).decode()
        data = cf_request(
            "POST", f"/accounts/{account}/cfd_tunnel",
            token, json={"name": tunnel_name, "tunnel_secret": tunnel_secret},
        )
        tunnel_id = data["result"]["id"]
        print(f"  Tunnel created: {tunnel_id}")
    created["tunnel"] = tunnel_name

    # 2. Configure ingress
    print("  Configuring tunnel ingress...")
    cf_request(
        "PUT", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/configurations",
        token, json={
            "config": {
                "ingress": [
                    {"hostname": hostname, "service": "http://localhost:80"},
                    {"service": "http_status:404"},
                ],
            },
        },
    )

    # 3. Create DNS CNAME (skip if it already exists)
    print(f"  Creating DNS record {hostname} -> tunnel...")
    existing_dns = cf_request(
        "GET", f"/zones/{zone}/dns_records",
        token, params={"name": hostname, "type": "CNAME"},
    )
    if existing_dns.get("result"):
        record = existing_dns["result"][0]
        print(f"  DNS record already exists (id={record['id']}), updating...")
        cf_request(
            "PUT", f"/zones/{zone}/dns_records/{record['id']}",
            token, json={
                "type": "CNAME",
                "name": hostname,
                "content": f"{tunnel_id}.cfargotunnel.com",
                "proxied": True,
            },
        )
    else:
        cf_request(
            "POST", f"/zones/{zone}/dns_records",
            token, json={
                "type": "CNAME",
                "name": hostname,
                "content": f"{tunnel_id}.cfargotunnel.com",
                "proxied": True,
            },
        )
    created["dns"] = hostname

    # 4. Get connector token
    print("  Getting tunnel connector token...")
    data = cf_request("GET", f"/accounts/{account}/cfd_tunnel/{tunnel_id}/token", token)
    connector_token = data["result"]

    # 5. Install and start cloudflared on the server.
    # Uninstall first so re-provisioning doesn't fail on "already installed".
    # Read token into a shell variable via stdin so it never appears in
    # process args (/proc/*/cmdline).  The variable is only visible to
    # the shell process itself.
    print("  Installing cloudflared tunnel on server...")
    result = subprocess.run(
        ["ssh", *SSH_OPTS, f"root@{server_ip}",
         "cloudflared service uninstall 2>/dev/null || true;"
         " TUNNEL_TOKEN=$(cat) && cloudflared service install \"$TUNNEL_TOKEN\""],
        input=connector_token, capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise ProvisionError(
            f"cloudflared install failed (rc={result.returncode})\n"
            f"stderr: {result.stderr.strip()}"
        )

    return hostname



def _auto_cleanup(created: dict, config: dict):
    """Best-effort cleanup of partially created resources on failure."""
    if not created:
        return
    print("\nCleaning up partially created resources...", file=sys.stderr)

    # Reverse order: DNS -> tunnel -> server -> SSH key
    cleanup_steps = []
    if "dns" in created:
        cleanup_steps.append(("DNS record", delete_dns_record))
    if "tunnel" in created:
        cleanup_steps.append(("tunnel", delete_tunnel))
    if "server" in created:
        cleanup_steps.append(("server", delete_server))

    for label, fn in cleanup_steps:
        try:
            fn(config)
            print(f"  Cleaned up {label}", file=sys.stderr)
        except Exception as e:
            print(f"  Warning: failed to clean up {label}: {e}", file=sys.stderr)

    # SSH key cleanup — uses hcloud Client directly (not a destroy.py function)
    if "ssh_key" in created:
        try:
            client = Client(token=config["HCLOUD_TOKEN"])
            key = client.ssh_keys.get_by_name(created["ssh_key"])
            if key:
                client.ssh_keys.delete(key)
                print(f"  Cleaned up SSH key '{created['ssh_key']}'", file=sys.stderr)
        except Exception as e:
            print(f"  Warning: failed to clean up SSH key: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    root = Path(__file__).resolve().parent.parent
    created = {}  # Track created resources for error reporting
    config = {}   # Initialized before try so _auto_cleanup always has a valid ref

    try:
        # 1. Config
        print("[1/9] Loading configuration...")
        config = load_config(root)

        # 2. Build cloud-init
        print("[2/9] Building cloud-init.yaml...")
        cloud_init = build(root)

        # 3. SSH key
        print("[3/9] Setting up SSH key...")
        pubkey = find_local_pubkey(config)
        client = Client(token=config["HCLOUD_TOKEN"])
        ssh_key, key_created = ensure_ssh_key(client, pubkey, name=config["SERVER_NAME"])
        if key_created:
            created["ssh_key"] = ssh_key.name

        # 4. Create server
        print("[4/9] Creating Hetzner server...")
        server = create_server(client, config, ssh_key, cloud_init)
        ip = server.public_net.ipv4.ip
        created["server"] = config["SERVER_NAME"]
        print(f"  Server IP: {ip}")

        # 5. Wait for boot
        print("[5/9] Waiting for server to be ready...")
        wait_for_ssh(ip)
        wait_for_cloud_init(ip)

        # 6. Deploy agent files (not embedded in cloud-init due to 32KB limit)
        print("[6/9] Deploying agent code...")
        deploy_agent_files(ip, root)

        # 7. Inject auth
        print("[7/9] Injecting auth tokens...")
        inject_auth(ip, config)

        # 8. Cloudflare Tunnel (setup_tunnel updates `created` progressively)
        print("[8/9] Setting up Cloudflare Tunnel...")
        hostname = setup_tunnel(config, ip, created=created)

        # 9. Enable + start service (webhook is configured by `just create-app`)
        # Enable here (not in cloud-init) so a premature reboot before auth
        # injection won't cause crash-loop restarts.
        print("[9/9] Starting service...")
        ssh(ip, "systemctl enable --now pr-review")

        # Verify the service actually started (retry to allow systemd to settle)
        print("  Verifying service started...", end="", flush=True)
        svc_status = "unknown"
        for _ in range(6):
            time.sleep(2)
            svc_status = ssh(
                ip, "systemctl is-active pr-review 2>/dev/null || echo inactive",
                timeout=10,
            )
            if svc_status == "active":
                break
            print(".", end="", flush=True)
        if svc_status != "active":
            print()
            raise ProvisionError(
                f"Service pr-review is '{svc_status}' after restart. "
                f"Check logs: ssh root@{ip} journalctl -u pr-review --no-pager -n 50"
            )
        print(" ok")

        # Summary
        print()
        print("=" * 60)
        print("  PROVISIONING COMPLETE")
        print()
        print(f"  Server:   {config['SERVER_NAME']} ({ip})")
        print(f"  Webhook:  https://{hostname}/webhook")
        print(f"  SSH:      ssh root@{ip}")
        print(f"  Logs:     ssh root@{ip} journalctl -u pr-review -f")
        print(f"  Health:   ssh root@{ip} curl -s localhost:8081/health")
        print("=" * 60)

    except (ProvisionError, BuildError, APIException) as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        _auto_cleanup(created, config)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        _auto_cleanup(created, config)
        sys.exit(1)


if __name__ == "__main__":
    main()
