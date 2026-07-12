# PR Review Server

A self-hosted agent that automatically reviews pull requests using Codex CLI with your ChatGPT subscription. When a PR is opened or updated on your GitHub account (org or personal), the agent posts a concise, actionable review comment. Force-pushes automatically collapse old reviews so the conversation stays clean.

```
GitHub webhook → Cloudflare Tunnel → Caddy → Python agent → Codex CLI → PR comment
```

---

## Why this exists

|  | PR Review Server | GitHub Copilot code review | Typical SaaS reviewers |
|--|--|--|--|
| **Cost** | ~$4/mo server + your existing ChatGPT/Codex access | $19/user/mo or higher | $15–50/user/mo |
| **Privacy** | Code stays on your server | Sent to GitHub/Microsoft | Sent to third party |
| **Customizable** | Edit one Markdown file to change the review focus | Limited configuration | Varies |
| **Self-hosted** | Full control | No | Rarely |

---

## Prerequisites

Install on your local machine:

- [**just**](https://github.com/casey/just) — command runner (`brew install just` / `cargo install just`)
- [**uv**](https://docs.astral.sh/uv/) — Python package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **Python 3.10+** (`python3 --version` to check)
- An **SSH key** — see [SSH key setup](#ssh-key-setup) below

You also need accounts with:

- [**Hetzner Cloud**](https://console.hetzner.cloud/) (server hosting, ~$4/mo)
- [**Cloudflare**](https://dash.cloudflare.com/) (tunnel + DNS, free tier works)
- A **domain name** managed by Cloudflare DNS — cheap TLDs like `.xyz` or `.click` work fine (~$2/year via [Cloudflare Registrar](https://www.cloudflare.com/products/registrar/))
- [**GitHub**](https://github.com/) account (org or personal) with admin access (to create and install a GitHub App)
- A **ChatGPT subscription with Codex access**

### SSH key setup

The provisioning script needs your SSH public key to upload to Hetzner. If you already have a key at `~/.ssh/id_ed25519.pub` (or `id_ecdsa` / `id_rsa`), you're all set — the script auto-discovers it.

**Don't have one?** Generate one:

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

Accept the default path. A passphrase is optional.

<details>
<summary>Advanced: multiple keys, 1Password, or explicit selection</summary>

The auto-discovery order is: standard `.pub` files → default SSH agent → `IdentityAgent` from `~/.ssh/config` (1Password, Secretive, etc.).

To select a specific key, set `SSH_KEY` in `.env`:

```env
# Point to a specific .pub file:
SSH_KEY=~/.ssh/my_hetzner_key.pub

# Or match a 1Password / agent key by its comment:
SSH_KEY=Hetzner - GitHub Webhooks
```

**1Password SSH agent** works automatically — the script reads the `IdentityAgent` directive from `~/.ssh/config`. If you have multiple keys in 1Password, set `SSH_KEY` to the key's comment (the name shown in 1Password). To list available keys:

```bash
SSH_AUTH_SOCK="$HOME/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock" ssh-add -L
```

The comment is the third field on each line (e.g. `ssh-ed25519 AAAA... Hetzner - GitHub Webhooks`). If this says "The agent has no identities", enable the SSH agent in 1Password → Settings → Developer → SSH Agent.

</details>

---

## Runbook

### Step 1: Clone and configure `.env`

```bash
git clone https://github.com/plasticbeachllc/claude-review-server.git
cd claude-review-server
cp .env.example .env
```

Open `.env` in your editor. You need to fill in **6 values** — the rest are defaults or auto-populated later.

#### `HCLOUD_TOKEN`

1. Go to [Hetzner Cloud Console](https://console.hetzner.cloud/)
2. Select your project (or create one)
3. Left sidebar → **Security** → **API Tokens**
4. Click **Generate API Token**, name it anything, select **Read & Write**
5. Copy the token — it's only shown once

#### `CF_API_TOKEN`

1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use **Create Custom Token** (not a template)
4. Add two permissions:
   - **Zone** → **DNS** → **Edit**
   - **Account** → **Cloudflare Tunnel** → **Edit**
5. Under Zone Resources, select **Include** → **Specific zone** → pick your domain
6. Click **Continue to summary** → **Create Token**
7. Copy the token — it's only shown once

#### `CF_ACCOUNT_ID` and `CF_ZONE_ID`

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) → click your domain
2. Both IDs are in the right sidebar under **API** — Account ID on top, Zone ID below

#### `TUNNEL_HOSTNAME`

A subdomain of the domain you selected above, e.g. `pr-review.example.com`.

#### `GITHUB_OWNER`

Your GitHub org or username as it appears in the URL (`github.com/my-org` → `my-org`).

#### Codex ChatGPT authentication

Do **not** set an OpenAI API key for this harness if you want reviews to use your ChatGPT subscription.

There are two supported ChatGPT-backed paths:

1. **Device login after provisioning**: leave `CODEX_ACCESS_TOKEN` unset, run `just provision`, then run `just codex-login root@<server-ip>` and complete the device-code login in your browser.
2. **Codex access token during provisioning**: if your ChatGPT workspace supports Codex access tokens, set `CODEX_ACCESS_TOKEN` locally in `.env`. Provisioning consumes it once with `codex login --with-access-token` for the `review` user and does not store it in `/opt/pr-review/.env`.

<details>
<summary>What your <code>.env</code> should look like after this step</summary>

```env
# ── Runtime ──────────────────────────────────────
REVIEW_WORKDIR=/opt/pr-review/workspace          # leave as-is
MAX_WORKERS=4                                     # leave as-is
PORT=8080                                         # leave as-is

# ── Hetzner Cloud ────────────────────────────────
HCLOUD_TOKEN=aBcDeFgHiJkLmNoPqRsTuVwXyZ...       # ← you filled this in
SERVER_NAME=pr-review                             # leave as-is
SERVER_TYPE=cax11                                 # leave as-is
SERVER_LOCATION=nbg1                              # leave as-is
SERVER_IMAGE=ubuntu-24.04                         # leave as-is

# ── GitHub App (auto-populated by just create-app) ──
GH_APP_ID=                                        # ← auto-populated in Step 2
GH_APP_PRIVATE_KEY_FILE=github-app.pem            # ← auto-populated in Step 2
GH_INSTALLATION_ID=                               # ← auto-populated in Step 2
GITHUB_WEBHOOK_SECRET=                            # ← auto-populated in Step 2

# ── Codex reviewer ───────────────────────────────
REVIEW_ENGINE=codex                                # leave as-is
CODEX_SANDBOX=read-only                            # leave as-is
CODEX_APPROVAL_POLICY=never                        # leave as-is
CODEX_WEB_SEARCH=disabled                          # leave as-is
# CODEX_ACCESS_TOKEN=                              # optional one-time login seed

# ── Cloudflare ───────────────────────────────────
CF_API_TOKEN=aBcDeFgHiJkLmNoPqRsTuVwXyZ...       # ← you filled this in
CF_ACCOUNT_ID=abc123def456...                     # ← you filled this in
CF_ZONE_ID=789ghi012jkl...                        # ← you filled this in
TUNNEL_HOSTNAME=pr-review.example.com             # ← you filled this in

# ── GitHub ───────────────────────────────────────
GITHUB_OWNER=my-org                               # ← you filled this in
```

</details>

### Step 2: Create the GitHub App

```bash
just create-app
```

This opens your browser twice — click **Create GitHub App**, then **Install** on your account. The script captures the credentials automatically.

When it finishes, `GH_APP_ID`, `GH_INSTALLATION_ID`, `GITHUB_WEBHOOK_SECRET` are filled in your `.env` and a `github-app.pem` file appears in the project root. Don't edit these values manually.

### Step 3: Provision the server

```bash
just provision
```

This takes 3–5 minutes. It validates your config, creates the Hetzner VM, waits for it to boot, injects secrets, sets up the Cloudflare Tunnel + DNS, and starts the service.

When it finishes, you'll see:

```
══════════════════════════════════════════════════════════════
  PROVISIONING COMPLETE

  Server:   pr-review (123.45.67.89)
  Webhook:  https://pr-review.example.com/webhook
  SSH:      ssh root@123.45.67.89
  Logs:     ssh root@123.45.67.89 journalctl -u pr-review -f
  Health:   ssh root@123.45.67.89 curl -s localhost:8081/health
══════════════════════════════════════════════════════════════
```

### Step 4: Log Codex in and verify it works

If you did not set `CODEX_ACCESS_TOKEN` before provisioning, log Codex in with your ChatGPT subscription:

```bash
just codex-login root@<server-ip>
```

Follow the device-code instructions in your browser. Then smoke-test Codex as the service user:

```bash
just codex-smoke root@<server-ip>
```

```bash
just status
```

You should see an OK status. Then open a PR on any repo where the app is installed — a review comment should appear within 1–3 minutes. Watch it live:

```bash
ssh root@<server-ip> journalctl -u pr-review -f
```

---

## Updating

### Agent code

After editing `src/agent.py` or `src/prompt.md`, hot-deploy without re-provisioning:

```bash
just deploy root@<server-ip>     # copies files + restarts service
just status                       # check health
ssh root@<server-ip> journalctl -u pr-review -f   # tail logs
```

Find your server IP in the `just provision` output or via `just status`.

### Codex CLI version

The server installs Codex CLI with the official non-interactive installer. To update on a running server:

```bash
ssh root@<server-ip> CODEX_NON_INTERACTIVE=1 CODEX_INSTALL_DIR=/usr/local/bin sh -c 'curl -fsSL https://chatgpt.com/codex/install.sh | sh'
ssh root@<server-ip> systemctl restart pr-review
```

### GPG signing keys

Provisioning pins the SHA-256 hashes of vendor GPG keys (GitHub CLI, Caddy, Cloudflare) to guard against supply-chain tampering. If a vendor rotates their key, provisioning will fail with a clear error. To update a hash:

```bash
curl -fsSL <key-url> | sha256sum
```

Replace the old hash in `infra/cloud-init.tmpl.yaml` and update the reference in `.env.example`. The key URLs are:

| Vendor | Key URL |
|--------|---------|
| GitHub CLI | `https://cli.github.com/packages/githubcli-archive-keyring.gpg` |
| Caddy | `https://dl.cloudsmith.io/public/caddy/stable/gpg.key` |
| Cloudflare | `https://pkg.cloudflare.com/cloudflare-main.gpg` |

---

## Destroying

```bash
just destroy yes
```

Deletes the Hetzner server, Cloudflare Tunnel, and DNS record. The GitHub App is preserved — re-run `just provision` any time to recreate without repeating `just create-app`.

Verify: `just status` should exit with code 3. To reprovision from scratch: `just destroy yes && just provision`.

---

## How it works

1. **Webhook received** — GitHub sends a PR event; the agent verifies the HMAC-SHA256 signature and skips drafts
2. **Context gathered** — fetches the diff via `gh` CLI and full file contents via the GitHub API; large PRs are smart-truncated (lockfiles, generated code, and vendor files dropped first, largest files first)
3. **Review posted** — Codex CLI reviews the diff using a customizable prompt and posts a comment within 1–2 minutes
4. **Force-push handling** — prior reviews are collapsed under a `<details>` tag; in-flight reviews are restarted

---

## Customization

### Change what Codex reviews

Edit `src/prompt.md`. This is the prompt template sent to Codex for each review.

Available template variables: `{pr_number}`, `{repo}`, `{pr_title}`, `{pr_body}`, `{truncation_note}`, `{file_contents}`, `{diff}`.

After editing, deploy with `just deploy root@<server-ip>`.

### Configuration

| Setting | Where | Default |
|---------|-------|---------|
| Review prompt | `src/prompt.md` | Correctness + security + performance |
| Concurrent reviews | `MAX_WORKERS` in `.env` | 4 |
| Diff size limit | `max_chars` in `smart_truncate_diff()` | 40,000 chars |
| File contents limit | `MAX_FILE_CHARS` in `.env` | 80,000 chars |
| Debounce delay | `DEBOUNCE_SECONDS` in `.env` | 10 seconds |
| Low-priority file patterns | `LOW_PRIORITY_PATTERNS` in `src/agent.py` | Lockfiles, generated, vendor, SVGs |

---

<details>
<summary>Project structure</summary>

```
src/
  agent.py               # Webhook listener + review logic
  prompt.md              # Review prompt template — edit this!
scripts/
  create_app.py          # GitHub App creation (manifest flow)
  provision.py           # One-command server provisioning
  destroy.py             # Clean teardown of all resources
  status.py              # Health + status checks
  build.py               # Assembles cloud-init.yaml from template
  _jwt.py                # GitHub App JWT generation
  _common.py             # Shared utilities
infra/
  cloud-init.tmpl.yaml   # Server provisioning template
tests/
  test_agent.py          # Unit tests
  test_provision.py      # Provisioning tests
  test_status.py         # Status command tests
  conftest.py            # Pytest fixtures
Justfile                 # All commands: build, test, deploy, provision, destroy
.env.example             # Configuration template
```

</details>

---

## Commands

| Command | What it does |
|---------|-------------|
| `just create-app` | Create GitHub App + webhook, install on account (one-time) |
| `just provision` | Create server + tunnel (fully automated) |
| `just status` | Check server health and status |
| `just deploy root@host` | Push code changes to a running server |
| `just codex-login root@host` | Log Codex in with ChatGPT device auth as the review user |
| `just codex-smoke root@host` | Smoke-test Codex as the review user |
| `just build` | Assemble cloud-init.yaml from template |
| `just validate` | Build + validate cloud-init.yaml schema (requires `cloud-init` CLI) |
| `just test` | Run unit tests |
| `just destroy yes` | Tear down server + tunnel + DNS (App preserved) |
| `just clean` | Remove built cloud-init.yaml |

---

## Alternative: manual setup

If you'd rather provision the server yourself (or use a different cloud provider), you can set things up step by step.

<details>
<summary>Manual setup instructions</summary>

### 1. Build cloud-init.yaml

```bash
just build
```

### 2. Create a server

Use any VPS with Ubuntu 24.04. Paste the contents of `cloud-init.yaml` as the cloud-init user data.

Wait 3–5 minutes for provisioning to complete.

### 3. Set up a Cloudflare Tunnel

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a tunnel**
2. Choose **Cloudflared**, name it (e.g. `pr-review`)
3. SSH into your server and install cloudflared:

```bash
ssh root@<server-ip>
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] \
  https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main" \
  | tee /etc/apt/sources.list.d/cloudflared.list
apt-get update && apt-get install -y cloudflared
cloudflared service install <YOUR_TUNNEL_TOKEN>
```

4. In the Cloudflare dashboard, add a public hostname:
   - **Service:** `http://localhost:80`
   - **Subdomain/Domain:** whatever you want (e.g. `pr-review.yourdomain.com`)

### 4. Configure the server

From your local machine, copy the GitHub App private key:

```bash
scp github-app.pem root@<server-ip>:/opt/pr-review/github-app.pem
```

Then SSH in and finish configuration:

```bash
ssh root@<server-ip>

# Add credentials to /opt/pr-review/.env:
#   GH_APP_ID=<from .env>
#   GH_INSTALLATION_ID=<from .env>
#   GH_APP_PRIVATE_KEY_FILE=/opt/pr-review/github-app.pem
#   GITHUB_WEBHOOK_SECRET=<from .env>
#   REVIEW_ENGINE=codex
#   CODEX_SANDBOX=read-only
#   CODEX_APPROVAL_POLICY=never
#   CODEX_WEB_SEARCH=disabled

# Log Codex in as the review user:
sudo -u review env HOME=/home/review CODEX_HOME=/home/review/.codex codex login --device-auth

# Fix permissions
chown review:review /opt/pr-review/github-app.pem
chmod 600 /opt/pr-review/github-app.pem

# Start the agent
systemctl start pr-review

# Verify
curl http://localhost:8080/health
# → {"status":"healthy"}
```

### 5. Create the GitHub App

If you didn't use `just create-app`, create the app manually:

1. GitHub → **Settings → Developer settings → GitHub Apps → New GitHub App**
2. Set permissions: `Contents: Read`, `Pull requests: Read & write`
3. Subscribe to **Pull request** events
4. Set webhook URL to `https://<your-hostname>/webhook`
5. Install the app on your account
6. Add `GH_APP_ID`, `GH_INSTALLATION_ID`, `GITHUB_WEBHOOK_SECRET` to your `.env`
7. Save the private key as `github-app.pem`

### 6. Test it

Open a PR. You should see a review comment within 1–2 minutes.

</details>

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Webhook returns 404 | The agent only responds to `POST /webhook` and `GET /health` |
| Agent won't start | `journalctl -u pr-review --no-pager -n 30` — usually a missing env var |
| Codex auth errors | Run `just codex-login root@<server-ip>` to re-authenticate, then `just codex-smoke root@<server-ip>` |
| Reviews aren't posting | Check App credentials in `/opt/pr-review/.env` and PEM file permissions |
| Tunnel not connecting | `systemctl status cloudflared` and check Cloudflare Zero Trust dashboard |

---

## Security

- **No inbound ports** — Cloudflare Tunnel connects outbound; no ports are opened on the server
- **HMAC signature verification** — every webhook payload is cryptographically verified
- **Isolated service user** — the agent runs as an unprivileged `review` user, not root
- **Systemd hardening** — `ProtectSystem=strict`, `PrivateTmp=yes`, restricted capabilities
- **Token isolation** — GitHub App credentials and Codex login state are stored in root-owned/review-owned files with restrictive permissions; Codex review subprocesses run with a sanitized environment

---

## License

MIT — see [LICENSE](LICENSE).
