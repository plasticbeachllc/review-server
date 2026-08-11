#!/usr/bin/env python3
"""Authenticate Codex on an existing review server.

The login secret is sent to Codex over SSH stdin and is never added to the
remote service environment or a process argument.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import SSH_OPTS, ProvisionError, load_config  # noqa: E402


REMOTE_LOGIN_PREFIX = (
    "install -d -m 700 -o review -g review /home/review/.codex && "
    "sudo -u review env HOME=/home/review CODEX_HOME=/home/review/.codex "
    "codex login"
)

REMOTE_SET_MODE = r"""
set -eu
mode="$1"
tmpfile=$(mktemp -p /opt/pr-review/)
{ grep -v '^CODEX_AUTH_MODE=' /opt/pr-review/.env || true; } > "$tmpfile"
printf 'CODEX_AUTH_MODE=%s\n' "$mode" >> "$tmpfile"
chmod 600 "$tmpfile"
chown review:review "$tmpfile"
mv "$tmpfile" /opt/pr-review/.env
systemctl restart pr-review
systemctl is-active --quiet pr-review
""".strip()


def resolve_mode(config: dict, requested: str = "") -> str:
    """Resolve a CLI override or the CODEX_AUTH_MODE configuration value."""
    mode = (requested or config.get("CODEX_AUTH_MODE", "chatgpt")).strip().lower()
    if mode not in ("chatgpt", "api-key"):
        raise ProvisionError("Codex auth mode must be 'chatgpt' or 'api-key'")
    return mode


def _secret(config: dict, mode: str) -> tuple[str, str] | None:
    """Return (secret, login flag), reading a piped API key when necessary."""
    if mode == "chatgpt":
        token = os.environ.get("CODEX_ACCESS_TOKEN") or config.get("CODEX_ACCESS_TOKEN", "")
        return (token.strip(), "--with-access-token") if token.strip() else None

    key = os.environ.get("OPENAI_API_KEY") or config.get("OPENAI_API_KEY", "")
    if not key.strip() and not sys.stdin.isatty():
        key = sys.stdin.read()
    key = key.strip()
    if not key:
        raise ProvisionError(
            "API-key login requires OPENAI_API_KEY or a key piped on stdin"
        )
    if not key.startswith("sk-"):
        raise ProvisionError("OPENAI_API_KEY has an unexpected format")
    return key, "--with-api-key"


def login(target: str, mode: str, config: dict):
    """Log in remotely, record the selected mode, and restart the service."""
    credential = _secret(config, mode)
    child_env = os.environ.copy()
    child_env.pop("OPENAI_API_KEY", None)
    child_env.pop("CODEX_ACCESS_TOKEN", None)
    if credential is None:
        login_result = subprocess.run(
            ["ssh", "-t", *SSH_OPTS, target, f"{REMOTE_LOGIN_PREFIX} --device-auth"],
            text=True,
            env=child_env,
        )
    else:
        secret, login_flag = credential
        login_result = subprocess.run(
            ["ssh", "-T", *SSH_OPTS, target, f"{REMOTE_LOGIN_PREFIX} {login_flag}"],
            input=secret,
            text=True,
            env=child_env,
        )
    if login_result.returncode != 0:
        raise ProvisionError(f"Codex {mode} login failed (rc={login_result.returncode})")

    update_result = subprocess.run(
        ["ssh", "-T", *SSH_OPTS, target, "bash", "-s", "--", mode],
        input=REMOTE_SET_MODE,
        text=True,
        env=child_env,
    )
    if update_result.returncode != 0:
        raise ProvisionError(
            f"Codex login succeeded but service configuration failed "
            f"(rc={update_result.returncode})"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="SSH target, for example root@203.0.113.10")
    parser.add_argument("--mode", default="", help="chatgpt or api-key; defaults to .env")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    try:
        config = load_config(root, required_keys=[])
        mode = resolve_mode(config, args.mode)
        login(args.target, mode, config)
    except ProvisionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"Codex {mode} login complete; pr-review restarted on {args.target}")


if __name__ == "__main__":
    main()
