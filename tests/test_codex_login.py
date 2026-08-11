"""Tests for switching Codex authentication on an existing server."""

import io
from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.usefixtures("scripts_on_path")
class TestCodexLogin:
    def test_resolves_configured_and_requested_modes(self):
        from codex_login import resolve_mode

        assert resolve_mode({"CODEX_AUTH_MODE": "api-key"}) == "api-key"
        assert resolve_mode({"CODEX_AUTH_MODE": "api-key"}, "chatgpt") == "chatgpt"

    def test_rejects_invalid_mode(self):
        from _common import ProvisionError
        from codex_login import resolve_mode

        with pytest.raises(ProvisionError, match="chatgpt.*api-key"):
            resolve_mode({}, "other")

    @patch("codex_login.subprocess.run")
    def test_chatgpt_mode_uses_device_auth_when_token_is_absent(
        self, mock_run, monkeypatch
    ):
        from codex_login import login

        monkeypatch.delenv("CODEX_ACCESS_TOKEN", raising=False)
        mock_run.return_value = MagicMock(returncode=0)

        login("root@example", "chatgpt", {})

        login_call, update_call = mock_run.call_args_list
        assert "-t" in login_call.args[0]
        assert "codex login --device-auth" in login_call.args[0][-1]
        assert update_call.args[0][-1] == "chatgpt"

    @patch("codex_login.subprocess.run")
    def test_chatgpt_access_token_is_piped_not_passed_as_argument(
        self, mock_run, monkeypatch
    ):
        from codex_login import login

        monkeypatch.setenv("CODEX_ACCESS_TOKEN", "codex-token")
        mock_run.return_value = MagicMock(returncode=0)

        login("root@example", "chatgpt", {})

        login_call = mock_run.call_args_list[0]
        assert "codex login --with-access-token" in login_call.args[0][-1]
        assert login_call.kwargs["input"] == "codex-token"
        assert "codex-token" not in " ".join(login_call.args[0])
        assert "CODEX_ACCESS_TOKEN" not in login_call.kwargs["env"]

    @patch("codex_login.subprocess.run")
    def test_api_key_from_stdin_is_piped_not_passed_as_argument(
        self, mock_run, monkeypatch
    ):
        from codex_login import login

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setattr("codex_login.sys.stdin", io.StringIO("sk-project-test\n"))
        mock_run.return_value = MagicMock(returncode=0)

        login("root@example", "api-key", {})

        login_call, update_call = mock_run.call_args_list
        assert "codex login --with-api-key" in login_call.args[0][-1]
        assert login_call.kwargs["input"] == "sk-project-test"
        assert "sk-project-test" not in " ".join(login_call.args[0])
        assert "OPENAI_API_KEY" not in login_call.kwargs["env"]
        assert update_call.args[0][-1] == "api-key"
        assert "CODEX_AUTH_MODE" in update_call.kwargs["input"]
