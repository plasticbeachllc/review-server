"""Tests for provisioning scripts (config loading, API construction)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Config loading ─────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestLoadConfig:
    def _write_env(self, tmp_path: Path, content: str) -> Path:
        env = tmp_path / ".env"
        env.write_text(content)
        return tmp_path

    def _full_env(self, **overrides) -> str:
        defaults = {
            "HCLOUD_TOKEN": "hc-test-token",
            "GH_APP_ID": "12345",
            "GH_APP_PRIVATE_KEY_FILE": "github-app.pem",
            "GH_INSTALLATION_ID": "67890",
            "GITHUB_WEBHOOK_SECRET": "whsec_test",
            "CF_API_TOKEN": "cf-test-token",
            "CF_ACCOUNT_ID": "cf-account-123",
            "CF_ZONE_ID": "cf-zone-456",
            "TUNNEL_HOSTNAME": "pr-review.example.com",
            "GITHUB_OWNER": "myorg",
        }
        defaults.update(overrides)
        return "\n".join(f"{k}={v}" for k, v in defaults.items())

    def test_loads_valid_config(self, tmp_path):
        from _common import load_config

        root = self._write_env(tmp_path, self._full_env())
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "hc-test-token"
        assert config["GITHUB_OWNER"] == "myorg"

    def test_applies_defaults(self, tmp_path):
        from _common import load_config

        root = self._write_env(tmp_path, self._full_env())
        config = load_config(root)
        assert config["SERVER_NAME"] == "pr-review"
        assert config["SERVER_TYPE"] == "cax11"
        assert config["SERVER_LOCATION"] == "nbg1"
        assert config["SERVER_IMAGE"] == "ubuntu-24.04"

    def test_overrides_defaults(self, tmp_path):
        from _common import load_config

        env = self._full_env() + "\nSERVER_TYPE=cx32\nSERVER_LOCATION=hel1"
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["SERVER_TYPE"] == "cx32"
        assert config["SERVER_LOCATION"] == "hel1"

    def test_missing_required_key_raises(self, tmp_path):
        from _common import ProvisionError, load_config

        # Missing HCLOUD_TOKEN
        env = self._full_env(HCLOUD_TOKEN="")
        root = self._write_env(tmp_path, env)
        with pytest.raises(ProvisionError, match="HCLOUD_TOKEN"):
            load_config(root)

    def test_multiple_missing_keys(self, tmp_path):
        from _common import ProvisionError, load_config

        root = self._write_env(tmp_path, "SERVER_NAME=test\n")
        with pytest.raises(ProvisionError) as exc:
            load_config(root)
        msg = str(exc.value)
        assert "HCLOUD_TOKEN" in msg
        assert "GH_APP_ID" in msg

    def test_missing_env_file_raises(self, tmp_path):
        from _common import ProvisionError, load_config

        with pytest.raises(ProvisionError, match=".env not found"):
            load_config(tmp_path)

    def test_ignores_comments_and_blanks(self, tmp_path):
        from _common import load_config

        env = "# This is a comment\n\n" + self._full_env()
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "hc-test-token"

    def test_strips_surrounding_quotes(self, tmp_path):
        from _common import load_config

        env = self._full_env(
            HCLOUD_TOKEN='"hc-quoted-double"',
            CF_API_TOKEN="'cf-quoted-single'",
        )
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "hc-quoted-double"
        assert config["CF_API_TOKEN"] == "cf-quoted-single"

    def test_preserves_value_with_equals(self, tmp_path):
        from _common import load_config

        env = self._full_env(CF_API_TOKEN="abc=def=ghi")
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["CF_API_TOKEN"] == "abc=def=ghi"

    def test_strips_inline_comments(self, tmp_path):
        from _common import load_config

        env = self._full_env(HCLOUD_TOKEN="real-token # this is a comment")
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "real-token"

    def test_preserves_hash_without_leading_space(self, tmp_path):
        from _common import load_config

        # A bare # without a leading space is NOT an inline comment
        env = self._full_env(HCLOUD_TOKEN="token#nospace")
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "token#nospace"

    def test_preserves_hash_in_quoted_values(self, tmp_path):
        from _common import load_config

        # Inline comments are not stripped inside quoted values
        env = self._full_env(HCLOUD_TOKEN='"value # with hash"')
        root = self._write_env(tmp_path, env)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "value # with hash"

    def test_strips_export_prefix(self, tmp_path):
        from _common import load_config

        # Shell-compatible .env files may prefix lines with "export"
        lines = self._full_env().replace("HCLOUD_TOKEN=", "export HCLOUD_TOKEN=")
        root = self._write_env(tmp_path, lines)
        config = load_config(root)
        assert config["HCLOUD_TOKEN"] == "hc-test-token"


# ── SSH key detection ──────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestFindLocalPubkey:
    def test_finds_ed25519(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey()
        assert content.startswith("ssh-ed25519")

    def test_finds_ecdsa(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ecdsa.pub").write_text("ecdsa-sha2-nistp256 AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey()
        assert content.startswith("ecdsa-sha2")

    def test_falls_back_to_rsa(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_rsa.pub").write_text("ssh-rsa AAAA... user@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey()
        assert content.startswith("ssh-rsa")

    def test_raises_when_no_key(self, tmp_path):
        from _common import ProvisionError
        from provision import find_local_pubkey

        with patch("provision.Path.home", return_value=tmp_path):
            with pytest.raises(ProvisionError, match="No SSH public key"):
                find_local_pubkey()

    def test_ssh_key_file_path(self, tmp_path):
        from provision import find_local_pubkey

        key_file = tmp_path / "custom_key.pub"
        key_file.write_text("ssh-ed25519 AAAA... custom@host")

        content = find_local_pubkey({"SSH_KEY": str(key_file)})
        assert content == "ssh-ed25519 AAAA... custom@host"

    def test_ssh_key_file_with_tilde(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "my_key.pub").write_text("ssh-ed25519 AAAA... tilde@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey({"SSH_KEY": "~/.ssh/my_key.pub"})
        assert content == "ssh-ed25519 AAAA... tilde@host"

    def test_ssh_key_file_not_found(self, tmp_path):
        from _common import ProvisionError
        from provision import find_local_pubkey

        with pytest.raises(ProvisionError, match="SSH_KEY file not found"):
            find_local_pubkey({"SSH_KEY": str(tmp_path / "nope.pub")})

    def test_ssh_key_comment_match(self):
        from provision import find_local_pubkey

        agent_keys = [
            ("agent", "ssh-ed25519 AAAA1 Hetzner - Plane"),
            ("agent", "ssh-ed25519 AAAA2 Hetzner - Webhooks"),
            ("agent", "ssh-ed25519 AAAA3 DigitalOcean"),
        ]
        with patch("provision._collect_agent_keys", return_value=agent_keys):
            content = find_local_pubkey({"SSH_KEY": "Hetzner - Webhooks"})
        assert content == "ssh-ed25519 AAAA2 Hetzner - Webhooks"

    def test_ssh_key_comment_case_insensitive(self):
        from provision import find_local_pubkey

        agent_keys = [
            ("agent", "ssh-ed25519 AAAA1 My Server Key"),
        ]
        with patch("provision._collect_agent_keys", return_value=agent_keys):
            content = find_local_pubkey({"SSH_KEY": "my server key"})
        assert content == "ssh-ed25519 AAAA1 My Server Key"

    def test_ssh_key_comment_no_match(self):
        from _common import ProvisionError
        from provision import find_local_pubkey

        agent_keys = [
            ("agent", "ssh-ed25519 AAAA1 Hetzner - Plane"),
            ("agent", "ssh-ed25519 AAAA2 DigitalOcean"),
        ]
        with patch("provision._collect_agent_keys", return_value=agent_keys):
            with pytest.raises(ProvisionError, match="No SSH key found with comment"):
                find_local_pubkey({"SSH_KEY": "NonExistent Key"})

    def test_ssh_key_comment_no_match_lists_available(self):
        from _common import ProvisionError
        from provision import find_local_pubkey

        agent_keys = [
            ("agent", "ssh-ed25519 AAAA1 Hetzner - Plane"),
            ("agent", "ssh-ed25519 AAAA2 DigitalOcean"),
        ]
        with patch("provision._collect_agent_keys", return_value=agent_keys):
            with pytest.raises(ProvisionError, match="Hetzner - Plane"):
                find_local_pubkey({"SSH_KEY": "NonExistent Key"})

    def test_ssh_key_empty_string_triggers_auto_discovery(self, tmp_path):
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAA... auto@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey({"SSH_KEY": ""})
        assert content == "ssh-ed25519 AAAA... auto@host"

    def test_auto_discovery_picks_first_agent_key(self, tmp_path):
        from provision import find_local_pubkey

        agent_keys = [
            ("IdentityAgent (SSH config)", "ssh-ed25519 AAAA1 First Key"),
            ("IdentityAgent (SSH config)", "ssh-ed25519 AAAA2 Second Key"),
        ]
        with (
            patch("provision.Path.home", return_value=tmp_path),
            patch("provision._collect_agent_keys", return_value=agent_keys),
        ):
            content = find_local_pubkey()
        assert content == "ssh-ed25519 AAAA1 First Key"

    def test_file_path_takes_priority_over_auto_discovery(self, tmp_path):
        """SSH_KEY file path should be used even if standard keys exist."""
        from provision import find_local_pubkey

        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 DEFAULT default@host")

        custom = tmp_path / "custom.pub"
        custom.write_text("ssh-ed25519 CUSTOM custom@host")

        with patch("provision.Path.home", return_value=tmp_path):
            content = find_local_pubkey({"SSH_KEY": str(custom)})
        assert content == "ssh-ed25519 CUSTOM custom@host"


# ── Cloudflare API request construction ────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestCfRequest:
    @patch("_common.requests.request")
    def test_sends_auth_header(self, mock_request):
        from _common import cf_request

        mock_request.return_value = MagicMock(
            json=lambda: {"success": True, "result": {}},
        )
        cf_request("GET", "/test/path", "my-cf-token")

        call_kwargs = mock_request.call_args
        assert call_kwargs[1]["headers"]["Authorization"] == "Bearer my-cf-token"

    @patch("_common.requests.request")
    def test_raises_on_api_error(self, mock_request):
        from _common import ProvisionError, cf_request

        mock_request.return_value = MagicMock(
            status_code=403,
            json=lambda: {
                "success": False,
                "errors": [{"code": 1000, "message": "bad request"}],
            },
        )
        with pytest.raises(ProvisionError, match=r"Cloudflare API error \(HTTP 403\)"):
            cf_request("GET", "/test", "token")

    @patch("_common.requests.request")
    def test_handles_204_no_content(self, mock_request):
        from _common import cf_request

        mock_request.return_value = MagicMock(status_code=204)
        result = cf_request("DELETE", "/test/path", "my-token")

        assert result == {"success": True, "result": None}


# ── Destroy script ─────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestDestroy:
    @patch("destroy.Client")
    def test_delete_server_by_name(self, MockClient):
        from destroy import delete_server

        mock_server = MagicMock(id=123)
        mock_client = MockClient.return_value
        mock_client.servers.get_by_name.return_value = mock_server

        config = {"HCLOUD_TOKEN": "hc-test", "SERVER_NAME": "pr-review"}
        delete_server(config)

        mock_client.servers.delete.assert_called_once_with(mock_server)


# ── Auto-cleanup on provision failure ─────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestAutoCleanup:
    def test_auto_cleanup_calls_destroy_functions(self):
        from provision import _auto_cleanup

        config = {"SERVER_NAME": "test", "GITHUB_OWNER": "org", "TUNNEL_HOSTNAME": "h"}
        created = {"server": "test", "tunnel": "h", "dns": "h"}

        with patch("provision.delete_dns_record") as dd, \
             patch("provision.delete_tunnel") as dt, \
             patch("provision.delete_server") as ds:
            _auto_cleanup(created, config)

        dd.assert_called_once_with(config)
        dt.assert_called_once_with(config)
        ds.assert_called_once_with(config)

    def test_auto_cleanup_skips_when_empty(self):
        from provision import _auto_cleanup

        # Should not raise or call anything
        _auto_cleanup({}, {})

    def test_auto_cleanup_continues_on_failure(self):
        from provision import _auto_cleanup

        config = {"SERVER_NAME": "test"}
        created = {"server": "test", "tunnel": "h", "dns": "h"}

        with patch("provision.delete_dns_record", side_effect=Exception("boom")), \
             patch("provision.delete_tunnel") as dt, \
             patch("provision.delete_server") as ds:
            # Should not raise despite delete_dns_record failing
            _auto_cleanup(created, config)

        dt.assert_called_once()
        ds.assert_called_once()

    def test_auto_cleanup_cleans_dns_without_tunnel(self):
        """DNS should be cleaned up even if tunnel tracking is absent."""
        from provision import _auto_cleanup

        config = {"SERVER_NAME": "test"}
        # DNS was created but setup_tunnel failed before recording "tunnel"
        created = {"server": "test", "dns": "h"}

        with patch("provision.delete_dns_record") as dd, \
             patch("provision.delete_server") as ds:
            _auto_cleanup(created, config)

        dd.assert_called_once_with(config)
        ds.assert_called_once_with(config)

    def test_main_handles_config_failure_without_unbound_error(self):
        """Regression test: load_config failure must not cause UnboundLocalError."""
        from _common import ProvisionError
        from provision import main

        with patch("provision.load_config", side_effect=ProvisionError("bad .env")):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1


# ── setup_tunnel ──────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestSetupTunnel:
    def _config(self):
        return {
            "CF_API_TOKEN": "cf-tok",
            "CF_ACCOUNT_ID": "acct-1",
            "CF_ZONE_ID": "zone-1",
            "TUNNEL_HOSTNAME": "review.example.com",
            "SERVER_NAME": "pr-review",
        }

    def _zone_response(self):
        """Zone validation response for review.example.com."""
        return {"result": {"name": "example.com"}}

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_creates_new_tunnel_and_dns(self, mock_cf, mock_run):
        from provision import setup_tunnel

        # cf_request responses in order:
        # 0. GET zone (validation)
        # 1. GET tunnels (empty — no existing)
        # 2. POST create tunnel
        # 3. PUT ingress config
        # 4. GET DNS records (empty — no existing)
        # 5. POST create DNS
        # 6. GET connector token
        mock_cf.side_effect = [
            self._zone_response(),
            {"result": []},
            {"result": {"id": "tun-123"}},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "connector-token-value"},
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        hostname = setup_tunnel(self._config(), "1.2.3.4")

        assert hostname == "review.example.com"
        # Verify tunnel creation was POSTed (index shifted +1 for zone check)
        assert mock_cf.call_args_list[2][0][0] == "POST"
        # Verify DNS creation was POSTed
        assert mock_cf.call_args_list[5][0][0] == "POST"

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_reuses_existing_tunnel(self, mock_cf, mock_run):
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),                                # GET zone
            {"result": [{"id": "existing-tun"}]},  # GET tunnels — found existing
            {"result": {}},                          # PUT ingress config
            {"result": []},                          # GET DNS records
            {"result": {}},                          # POST create DNS
            {"result": "token-val"},                 # GET connector token
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        hostname = setup_tunnel(self._config(), "1.2.3.4")

        assert hostname == "review.example.com"
        # call 0 is GET zone, call 1 is GET tunnels, call 2 is PUT ingress
        assert mock_cf.call_args_list[1][0][0] == "GET"
        assert mock_cf.call_args_list[2][0][0] == "PUT"

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_updates_existing_dns_record(self, mock_cf, mock_run):
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),                               # GET zone
            {"result": [{"id": "tun-1"}]},                    # GET tunnels — existing
            {"result": {}},                                     # PUT ingress
            {"result": [{"id": "dns-rec-1"}]},                 # GET DNS — existing record
            {"result": {}},                                     # PUT update DNS
            {"result": "tok"},                                  # GET connector token
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        setup_tunnel(self._config(), "1.2.3.4")

        # DNS step should be PUT (update), not POST (create) — index shifted +1
        dns_call = mock_cf.call_args_list[4]
        assert dns_call[0][0] == "PUT"
        assert "dns-rec-1" in dns_call[0][1]

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_raises_on_cloudflared_install_failure(self, mock_cf, mock_run):
        from _common import ProvisionError
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),
            {"result": [{"id": "tun-1"}]},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "tok"},
        ]
        mock_run.return_value = MagicMock(returncode=1, stderr="install failed")

        with pytest.raises(ProvisionError, match="cloudflared install failed"):
            setup_tunnel(self._config(), "1.2.3.4")

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_updates_created_dict_progressively(self, mock_cf, mock_run):
        """setup_tunnel should track tunnel and DNS in `created` for cleanup."""
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),
            {"result": []},
            {"result": {"id": "tun-new"}},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "tok"},
        ]
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        created = {}
        setup_tunnel(self._config(), "1.2.3.4", created=created)

        assert "tunnel" in created
        assert "dns" in created

    @patch("provision.subprocess.run")
    @patch("provision.cf_request")
    def test_tracks_dns_even_if_cloudflared_fails(self, mock_cf, mock_run):
        """DNS should be tracked even if cloudflared install fails after."""
        from _common import ProvisionError
        from provision import setup_tunnel

        mock_cf.side_effect = [
            self._zone_response(),
            {"result": [{"id": "tun-1"}]},
            {"result": {}},
            {"result": []},
            {"result": {}},
            {"result": "tok"},
        ]
        mock_run.return_value = MagicMock(returncode=1, stderr="fail")

        created = {}
        with pytest.raises(ProvisionError):
            setup_tunnel(self._config(), "1.2.3.4", created=created)

        # DNS and tunnel should be tracked even though cloudflared failed
        assert "tunnel" in created
        assert "dns" in created

    @patch("provision.cf_request")
    def test_raises_on_zone_mismatch(self, mock_cf):
        """TUNNEL_HOSTNAME must belong to the zone identified by CF_ZONE_ID."""
        from _common import ProvisionError
        from provision import setup_tunnel

        # Zone is otherdomain.com, but hostname is review.example.com
        mock_cf.return_value = {"result": {"name": "otherdomain.com"}}

        with pytest.raises(ProvisionError, match="does not belong to zone"):
            setup_tunnel(self._config(), "1.2.3.4")


# ── wait_for_ssh ──────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestWaitForSsh:
    @patch("_common.time.sleep")
    @patch("_common.ssh")
    def test_returns_when_ssh_ready(self, mock_ssh, mock_sleep):
        from _common import wait_for_ssh

        mock_ssh.return_value = "ready"
        wait_for_ssh("1.2.3.4", timeout=30)

        mock_ssh.assert_called_once()
        mock_sleep.assert_not_called()

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_retries_on_failure_then_succeeds(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_ssh

        # First call fails, second succeeds
        mock_ssh.side_effect = [ProvisionError("refused"), "ready"]
        # time() returns: start, check1 (still in window), check2 (still in window)
        mock_time.side_effect = [0, 1, 6]

        wait_for_ssh("1.2.3.4", timeout=30)

        assert mock_ssh.call_count == 2
        assert mock_sleep.call_count == 1

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_raises_after_timeout(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_ssh

        mock_ssh.side_effect = ProvisionError("refused")
        # time() returns: start, check1 (in window → retry), check2 (past deadline)
        mock_time.side_effect = [0, 1, 301]

        with pytest.raises(ProvisionError, match="SSH not reachable after 300s"):
            wait_for_ssh("1.2.3.4", timeout=300)

        # Verify the retry loop actually executed at least once
        assert mock_ssh.call_count >= 1
        assert mock_sleep.call_count >= 1


# ── wait_for_cloud_init ──────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestWaitForCloudInit:
    @patch("_common.time.sleep")
    @patch("_common.ssh")
    def test_returns_when_done(self, mock_ssh, mock_sleep):
        from _common import wait_for_cloud_init

        mock_ssh.return_value = json.dumps({"status": "done"})
        wait_for_cloud_init("1.2.3.4", timeout=60)

        mock_ssh.assert_called_once()

    @patch("_common.time.sleep")
    @patch("_common.ssh")
    def test_raises_cloud_init_error(self, mock_ssh, mock_sleep):
        from _common import CloudInitError, wait_for_cloud_init

        mock_ssh.return_value = json.dumps({
            "status": "error",
            "extended_status": "modules failed",
        })

        with pytest.raises(CloudInitError, match="cloud-init failed"):
            wait_for_cloud_init("1.2.3.4", timeout=60)

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_raises_after_timeout(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_cloud_init

        mock_ssh.return_value = json.dumps({"status": "running"})
        # time() returns: deadline calc, while-check, while-check (past deadline)
        mock_time.side_effect = [0, 1, 601]

        with pytest.raises(ProvisionError, match="cloud-init did not finish"):
            wait_for_cloud_init("1.2.3.4", timeout=600)

    @patch("_common.time.sleep")
    @patch("_common.ssh")
    def test_raises_on_degraded_status(self, mock_ssh, mock_sleep):
        from _common import CloudInitError, wait_for_cloud_init

        # First call returns degraded status; second fetches --long diagnostic
        mock_ssh.side_effect = [
            json.dumps({"status": "degraded"}),
            "status: degraded\ndetail: some modules failed",
        ]

        with pytest.raises(CloudInitError, match="cloud-init degraded"):
            wait_for_cloud_init("1.2.3.4", timeout=60)

    @patch("_common.time.sleep")
    @patch("_common.time.time")
    @patch("_common.ssh")
    def test_retries_on_transient_ssh_failure(self, mock_ssh, mock_time, mock_sleep):
        from _common import ProvisionError, wait_for_cloud_init

        # First call fails with SSH error, second returns done
        mock_ssh.side_effect = [
            ProvisionError("connection refused"),
            json.dumps({"status": "done"}),
        ]
        # time() calls: deadline calc, while-check, while-check
        mock_time.side_effect = [0, 1, 15]

        wait_for_cloud_init("1.2.3.4", timeout=60)

        assert mock_ssh.call_count == 2


# ── inject_auth ──────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestInjectAuth:
    def _config(self, tmp_path=None):
        config = {
            "GH_APP_ID": "12345",
            "GH_INSTALLATION_ID": "67890",
            "GH_APP_PRIVATE_KEY_FILE": "github-app.pem",
            "GITHUB_WEBHOOK_SECRET": "whsec_test",
        }
        if tmp_path:
            pem = tmp_path / "github-app.pem"
            pem.write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")
            config["GH_APP_PRIVATE_KEY_FILE"] = str(pem)
        return config

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_raises_when_gh_not_installed(self, mock_ssh, mock_run):
        from _common import ProvisionError
        from provision import inject_auth

        mock_ssh.side_effect = ProvisionError("command not found")

        with pytest.raises(ProvisionError, match="GitHub CLI.*not found"):
            inject_auth("1.2.3.4", self._config())

        # subprocess.run should not have been called (gh check failed first)
        mock_run.assert_not_called()

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_raises_when_codex_not_installed(self, mock_ssh, mock_run):
        from _common import ProvisionError
        from provision import inject_auth

        mock_ssh.side_effect = ["/usr/bin/gh", ProvisionError("command not found")]

        with pytest.raises(ProvisionError, match="Codex CLI.*not found"):
            inject_auth("1.2.3.4", self._config())

        mock_run.assert_not_called()

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_raises_on_pem_injection_failure(self, mock_ssh, mock_run, tmp_path):
        from _common import ProvisionError
        from provision import inject_auth

        mock_ssh.return_value = "/usr/bin/gh"
        # PEM copy fails
        mock_run.return_value = MagicMock(
            returncode=1, stderr="permission denied", stdout="",
        )

        with pytest.raises(ProvisionError, match="PEM injection failed"):
            inject_auth("1.2.3.4", self._config(tmp_path))

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_succeeds_with_all_steps(self, mock_ssh, mock_run, tmp_path):
        from provision import inject_auth

        mock_ssh.return_value = "/usr/bin/gh"
        # 5 subprocess.run calls: PEM copy + 4 GitHub App env vars
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        inject_auth("1.2.3.4", self._config(tmp_path))  # should not raise

        # 1 PEM copy + 4 env var upserts (GH_APP_ID, GH_INSTALLATION_ID,
        # GH_APP_PRIVATE_KEY_FILE, GITHUB_WEBHOOK_SECRET)
        assert mock_run.call_count == 5

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_pipes_pem_via_stdin(self, mock_ssh, mock_run, tmp_path):
        from provision import inject_auth

        mock_ssh.return_value = "/usr/bin/gh"
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        inject_auth("1.2.3.4", self._config(tmp_path))

        # First subprocess.run call copies PEM content via stdin
        first_call = mock_run.call_args_list[0]
        assert "BEGIN RSA PRIVATE KEY" in first_call[1]["input"]

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_codex_access_token_is_consumed_not_stored(self, mock_ssh, mock_run, tmp_path):
        from provision import inject_auth

        mock_ssh.return_value = "/usr/bin/gh"
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")
        config = self._config(tmp_path)
        config["CODEX_ACCESS_TOKEN"] = "codex-access-token"

        inject_auth("1.2.3.4", config)

        login_call = mock_run.call_args_list[-1]
        assert "codex login --with-access-token" in login_call[0][0][-1]
        assert login_call[1]["input"] == "codex-access-token"
        all_commands = "\n".join(call[0][0][-1] for call in mock_run.call_args_list)
        assert "CODEX_ACCESS_TOKEN" not in all_commands

    @patch("provision.subprocess.run")
    @patch("provision.ssh")
    def test_raises_when_pem_missing(self, mock_ssh, mock_run):
        from _common import ProvisionError
        from provision import inject_auth

        mock_ssh.return_value = "/usr/bin/gh"

        config = self._config()
        config["GH_APP_PRIVATE_KEY_FILE"] = "/nonexistent/path.pem"

        with pytest.raises(ProvisionError, match="Private key not found"):
            inject_auth("1.2.3.4", config)
