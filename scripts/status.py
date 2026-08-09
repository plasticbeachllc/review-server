#!/usr/bin/env python3
"""Check the status of a provisioned PR review server.

Reports server status from Hetzner and optionally checks the service health
via SSH.

Exit codes:
    0 — server running and healthy
    1 — server exists but not running (e.g. off, starting)
    2 — server running but unhealthy (service down or health check failed)
    3 — server not found (not provisioned)

Usage:
    python3 scripts/status.py
    python3 scripts/status.py --ssh-target
    just status
"""

import json
import subprocess
import sys
from pathlib import Path

import requests
from hcloud import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import ProvisionError, load_config, ssh  # noqa: E402


def main(argv: list[str] | None = None):
    argv = [] if argv is None else argv
    if argv not in ([], ["--ssh-target"]):
        print("Usage: status.py [--ssh-target]", file=sys.stderr)
        sys.exit(64)

    root = Path(__file__).resolve().parent.parent

    try:
        config = load_config(root, required_keys=["HCLOUD_TOKEN"])
    except ProvisionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    name = config["SERVER_NAME"]
    client = Client(token=config["HCLOUD_TOKEN"])
    server = client.servers.get_by_name(name)

    if not server:
        print(f"Server '{name}' not found on Hetzner (not provisioned).")
        sys.exit(3)  # exit 3 = not found

    ip = server.public_net.ipv4.ip
    if argv == ["--ssh-target"]:
        if server.status != "running":
            print(
                f"ERROR: Server '{name}' is '{server.status}', not running.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"root@{ip}")
        return

    print(f"Server:   {name} (id={server.id})")
    print(f"Status:   {server.status}")
    print(f"IP:       {ip}")
    print(f"Type:     {server.server_type.name}")
    print(f"Location: {server.location.name}")
    print(f"Created:  {server.created.isoformat()}")

    # Connection info (always shown regardless of SSH availability)
    hostname = config.get("TUNNEL_HOSTNAME", "")
    if hostname:
        print(f"Webhook:  https://{hostname}/webhook")
    print(f"SSH:      ssh root@{ip}")
    print(f"Logs:     ssh root@{ip} journalctl -u pr-review -f")

    if server.status != "running":
        print(f"\nServer is '{server.status}', not running — skipping health checks.")
        sys.exit(1)  # exit 1 = not running

    # Check service health via SSH
    healthy = True
    print()
    try:
        svc = ssh(ip, "systemctl is-active pr-review 2>/dev/null || echo inactive", timeout=10)
        print(f"Service:  {svc}")
        if svc != "active":
            healthy = False
    except (ProvisionError, subprocess.TimeoutExpired, OSError):
        print("Service:  (SSH unreachable)")
        healthy = False

    try:
        # Port 8081 is the dedicated Caddy health endpoint (separate from the
        # application on PORT=8080); see infra/cloud-init.tmpl.yaml.
        health = ssh(ip, "curl -sf localhost:8081/health 2>/dev/null || echo '{\"status\":\"unreachable\"}'", timeout=10)
        try:
            health_ok = json.loads(health).get("status") == "healthy"
        except (json.JSONDecodeError, AttributeError):
            health_ok = False
        print(f"Health:   {'healthy' if health_ok else f'(unhealthy: {health.strip()})'}")
        if not health_ok:
            healthy = False
    except (ProvisionError, subprocess.TimeoutExpired, OSError):
        print("Health:   (check failed)")
        healthy = False

    # Check tunnel reachability from the outside (if configured)
    if hostname:
        try:
            resp = requests.get(f"https://{hostname}/health", timeout=10)
            if resp.status_code == 200:
                print("Tunnel:   reachable")
            else:
                print(f"Tunnel:   HTTP {resp.status_code}")
                healthy = False
        except requests.RequestException:
            print("Tunnel:   unreachable")
            healthy = False

    if not healthy:
        sys.exit(2)  # exit 2 = running but unhealthy


if __name__ == "__main__":
    main(sys.argv[1:])
