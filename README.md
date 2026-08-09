# PR Review Server

Deploy a self-hosted GitHub App that reviews pull requests with Codex using your ChatGPT subscription.

## Runbook

You need:

- [just](https://github.com/casey/just), [uv](https://docs.astral.sh/uv/), Python 3.10+, and an SSH key on your computer
- A Hetzner Cloud project, a Cloudflare-managed domain, GitHub admin access, and a ChatGPT plan with Codex access

### 1. Clone and configure

```bash
git clone https://github.com/plasticbeachllc/review-server.git
cd review-server
cp .env.example .env
```

Open `.env` and fill in these six values. Leave everything else at its default.

| Value | Where to get it |
|---|---|
| `HCLOUD_TOKEN` | Hetzner project → Security → API Tokens; create a Read & Write token |
| `CF_API_TOKEN` | [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens); grant Zone/DNS/Edit and Account/Cloudflare Tunnel/Edit |
| `CF_ACCOUNT_ID` | Cloudflare domain overview → API |
| `CF_ZONE_ID` | Cloudflare domain overview → API |
| `TUNNEL_HOSTNAME` | A new hostname on that domain, such as `pr-review.example.com` |
| `GITHUB_OWNER` | The GitHub organization or username that will install the App |

The provisioner automatically finds a standard SSH public key or a key from your SSH agent. If needed, generate one with `ssh-keygen -t ed25519`, or set `SSH_KEY` in `.env` to a public-key path or agent key comment.

### 2. Create the GitHub App

```bash
just create-app
```

Your browser opens twice. Approve **Create GitHub App**, then install it on the repositories you want reviewed. The command saves the App credentials in `.env` and `github-app.pem`.

### 3. Provision the server

```bash
just provision
```

In about 3–5 minutes this creates the Hetzner VM, configures the Cloudflare Tunnel and DNS, installs the service, and prints the webhook and server details.

### 4. Authenticate Codex and verify

```bash
just codex-login
just codex-smoke
just status
```

Complete the device-code login in your browser. The commands automatically find the provisioned server from `.env`; you do not need to copy its IP address.

Open a pull request in an installed repository. A review should appear within 1–3 minutes. Use `just logs` to watch it run.

> If your ChatGPT workspace provides Codex access tokens, you can set `CODEX_ACCESS_TOKEN` before provisioning and skip `just codex-login`. The token is consumed once and is not stored on the server.

## What it does

The App reviews non-draft pull requests when they are opened, updated, or marked ready for review. It gathers the diff and relevant file contents, asks Codex for concise actionable feedback, and posts the result as a PR comment. On a force-push, it collapses older reviews and cancels any review of the superseded commit.

```text
GitHub webhook → Cloudflare Tunnel → Caddy → Python agent → Codex CLI → PR comment
```

## Customize reviews

Edit [`src/prompt.md`](src/prompt.md), then run:

```bash
just deploy
```

The prompt supports `{pr_number}`, `{repo}`, `{pr_title}`, `{pr_body}`, `{truncation_note}`, `{file_contents}`, and `{diff}`.

Common runtime settings live in `.env`:

| Setting | Default | Purpose |
|---|---:|---|
| `CODEX_MODEL` | `gpt-5.6-terra` | Review model |
| `MAX_WORKERS` | `4` | Concurrent reviews |
| `MAX_FILE_CHARS` | `80000` | File-content context limit |
| `DEBOUNCE_SECONDS` | `10` | Delay after a force-push |
| `CODEX_TIMEOUT_SECONDS` | `300` | Per-review timeout |
| `CODEX_WEB_SEARCH` | `disabled` | Web-search access during reviews |

See [`.env.example`](.env.example) for all settings. Run `just deploy` after prompt or agent changes; run `just provision` again to apply provisioning changes to a new server.

## Operations

| Command | Purpose |
|---|---|
| `just status` | Show server, service, health, and tunnel status |
| `just logs` | Follow live service logs |
| `just deploy` | Upload the current agent and prompt, then restart |
| `just codex-login` | Authenticate or re-authenticate Codex |
| `just codex-smoke` | Verify Codex works as the service user |
| `just destroy yes` | Delete the VM, tunnel, and DNS record; preserve the GitHub App |
| `just test` | Run the test suite |

`deploy`, `logs`, `codex-login`, and `codex-smoke` auto-discover the server. You can still pass an explicit SSH target, for example `just logs root@203.0.113.10`.

## Troubleshooting

- Start with `just status`, then `just logs`.
- For Codex authentication errors, run `just codex-login` followed by `just codex-smoke`.
- For GitHub posting errors, verify the App is installed on the repository and check `/opt/pr-review/.env` and `/opt/pr-review/github-app.pem` permissions.
- For tunnel errors, check the Cloudflare Zero Trust dashboard and `systemctl status cloudflared` on the server.
- If provisioning cannot find an SSH key, set `SSH_KEY` in `.env` to a `.pub` file or an SSH-agent key comment.

## Security

- Only SSH is open inbound; webhook traffic reaches Caddy through an outbound Cloudflare Tunnel.
- Every webhook is verified with HMAC-SHA256.
- The agent and Codex run as an unprivileged `review` user under a hardened systemd service.
- GitHub credentials and Codex login state have restrictive permissions, and Codex subprocesses receive a sanitized environment.
- Codex runs with a read-only sandbox, no approval prompts, web search disabled, ephemeral sessions, and user/repository rules ignored by default.

## Development

```bash
just test
just build
just validate  # validates cloud-init when the cloud-init CLI is installed
```

## License

MIT — see [LICENSE](LICENSE).
