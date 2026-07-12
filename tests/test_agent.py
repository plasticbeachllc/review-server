"""Tests for agent.py core functions."""

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import textwrap
import threading
from http.server import HTTPServer
from threading import Thread
from unittest.mock import MagicMock, patch

import pytest

# Set required env vars before importing agent (module-level checks)
os.environ.setdefault("GITHUB_WEBHOOK_SECRET", "test-secret-key")

# GitHub App env vars — agent validates these at import time.
# Use a persistent temp dir that is cleaned up via atexit.
_test_pem_dir = tempfile.mkdtemp()
_test_pem_file = os.path.join(_test_pem_dir, "test-key.pem")
if not os.path.exists(_test_pem_file):
    with open(_test_pem_file, "w") as f:
        f.write("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n")

import atexit, shutil  # noqa: E402
atexit.register(shutil.rmtree, _test_pem_dir, ignore_errors=True)

os.environ.setdefault("GH_APP_ID", "12345")
os.environ.setdefault("GH_INSTALLATION_ID", "67890")
os.environ.setdefault("GH_APP_PRIVATE_KEY_FILE", _test_pem_file)

from agent import (
    DEBOUNCE_SECONDS,
    REVIEW_MARKER,
    WebhookHandler,
    _b64url,
    _bump_generation,
    _generate_jwt,
    _get_installation_token,
    _gh_env,
    _is_current,
    _PRReviewState,
    _codex_command,
    _reviewer_command,
    _reviewer_env,
    _review_state,
    _review_state_lock,
    _schedule_review,
    _shutting_down,
    _token_cache,
    _token_lock,
    already_reviewed,
    collapse_old_reviews,
    extract_diff_filenames,
    fetch_file_contents,
    format_file_contents,
    is_low_priority,
    review_pr,
    smart_truncate_diff,
    verify_signature,
)


@pytest.fixture(autouse=True)
def _mock_gh_env(monkeypatch):
    """Prevent real JWT generation / token exchange in all tests.

    Tests that specifically test _gh_env or _get_installation_token
    override this with their own patches.
    """
    monkeypatch.setattr(
        "agent._gh_env",
        lambda: {**os.environ, "GH_TOKEN": "ghs_test_installation_token"},
    )


# ── JWT generation ──────────────────────────────────────


class TestJWTGeneration:
    def test_b64url_no_padding(self):
        result = _b64url(b"test data")
        assert "=" not in result

    def test_generate_jwt_structure(self, rsa_key_pair):
        jwt = _generate_jwt("12345", str(rsa_key_pair))
        parts = jwt.split(".")
        assert len(parts) == 3  # header.payload.signature

    def test_generate_jwt_with_bad_key_raises(self, tmp_path):
        bad_key = tmp_path / "bad.pem"
        bad_key.write_text("not a real key")
        with pytest.raises(RuntimeError, match="openssl signing failed"):
            _generate_jwt("12345", str(bad_key))


class TestInstallationToken:
    def test_gh_env_contains_gh_token(self):
        """_gh_env() should return an env dict with GH_TOKEN set."""
        # Mock _get_installation_token to avoid real API calls
        with patch("agent._get_installation_token", return_value="ghs_test_token"):
            env = _gh_env()
        assert env["GH_TOKEN"] == "ghs_test_token"

    def test_token_cache_reuses_valid_token(self):
        """Cached tokens should be reused when not near expiry."""
        import time as _time

        with _token_lock:
            _token_cache.token = "cached_token"
            _token_cache.expires_at = _time.time() + 3600  # 1 hour from now

        try:
            token = _get_installation_token()
            assert token == "cached_token"
        finally:
            with _token_lock:
                _token_cache.token = ""
                _token_cache.expires_at = 0.0

    def test_token_cache_refreshes_near_expiry(self):
        """Tokens near expiry should trigger a refresh."""
        import time as _time

        with _token_lock:
            _token_cache.token = "old_token"
            _token_cache.expires_at = _time.time() + 60  # only 1 min left (< 5 min buffer)

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({
            "token": "new_token",
            "expires_at": "2099-01-01T00:00:00Z",
        }).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        try:
            with patch("agent._generate_jwt", return_value="fake.jwt.token"), \
                 patch("agent.urllib.request.urlopen", return_value=mock_resp):
                token = _get_installation_token()
            assert token == "new_token"
        finally:
            with _token_lock:
                _token_cache.token = ""
                _token_cache.expires_at = 0.0


class TestReviewerCommand:
    def test_codex_command_uses_noninteractive_read_only_defaults(self):
        cmd = _codex_command("Review this")
        assert cmd[0] == "codex"
        assert "exec" in cmd
        assert cmd.index("--sandbox") < cmd.index("exec")
        assert cmd.index("--ask-for-approval") < cmd.index("exec")
        assert "--skip-git-repo-check" in cmd
        assert cmd[cmd.index("--sandbox") + 1] == "read-only"
        assert cmd[cmd.index("--ask-for-approval") + 1] == "never"
        assert "web_search=\"disabled\"" in cmd
        assert cmd[-1] == "Review this"

    def test_reviewer_command_defaults_to_codex(self):
        cmd = _reviewer_command("Review")
        assert cmd[0] == "codex"
        assert "exec" in cmd

    def test_codex_env_strips_review_server_secrets(self, monkeypatch):
        monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "whsec")
        monkeypatch.setenv("GH_APP_ID", "123")
        monkeypatch.setenv("GH_INSTALLATION_ID", "456")
        monkeypatch.setenv("GH_APP_PRIVATE_KEY_FILE", "/secret.pem")
        monkeypatch.setenv("CODEX_ACCESS_TOKEN", "codex-access")
        monkeypatch.setenv("CODEX_API_KEY", "codex-api")

        env = _reviewer_env()

        assert "PATH" in env
        assert "CODEX_HOME" in env
        assert "GITHUB_WEBHOOK_SECRET" not in env
        assert "GH_APP_ID" not in env
        assert "GH_INSTALLATION_ID" not in env
        assert "GH_APP_PRIVATE_KEY_FILE" not in env
        assert "CODEX_ACCESS_TOKEN" not in env
        assert "CODEX_API_KEY" not in env


# ── verify_signature ─────────────────────────────────────


class TestVerifySignature:
    SECRET = "test-secret-key"

    def _sign(self, payload: bytes) -> str:
        return "sha256=" + hmac.new(
            self.SECRET.encode(), payload, hashlib.sha256
        ).hexdigest()

    def test_valid_signature(self):
        payload = b'{"action":"opened"}'
        sig = self._sign(payload)
        assert verify_signature(payload, sig) is True

    def test_invalid_signature(self):
        payload = b'{"action":"opened"}'
        assert verify_signature(payload, "sha256=badhex") is False

    def test_missing_prefix(self):
        payload = b'{"action":"opened"}'
        raw = hmac.new(
            self.SECRET.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert verify_signature(payload, raw) is False

    def test_empty_signature(self):
        assert verify_signature(b"hello", "") is False

    def test_tampered_payload(self):
        payload = b'{"action":"opened"}'
        sig = self._sign(payload)
        assert verify_signature(b'{"action":"closed"}', sig) is False


# ── is_low_priority ──────────────────────────────────────


class TestIsLowPriority:
    @pytest.mark.parametrize(
        "filename",
        [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Cargo.lock",
            "go.sum",
            "composer.lock",
            "dist/bundle.min.js",
            "styles/app.min.css",
            "src/__snapshots__/App.test.tsx.snap",
            "icons/logo.svg",
            "vendor/github.com/lib/pq/conn.go",
            "proto/api.pb.go",
            "uv.lock",
            "poetry.lock",
            "Pipfile.lock",
            "Gemfile.lock",
            "bun.lockb",
        ],
    )
    def test_low_priority_files(self, filename):
        assert is_low_priority(filename) is True

    @pytest.mark.parametrize(
        "filename",
        [
            "src/main.py",
            "lib/auth.ts",
            "README.md",
            "Dockerfile",
            "agent.py",
            "tests/test_handler.py",
            ".github/workflows/ci.yml",
        ],
    )
    def test_high_priority_files(self, filename):
        assert is_low_priority(filename) is False


# ── smart_truncate_diff ──────────────────────────────────


def _make_diff(files: dict[str, int]) -> str:
    """Build a fake diff with files of given sizes (in chars of content)."""
    parts = []
    for name, size in files.items():
        header = f"diff --git a/{name} b/{name}\n"
        body = "+" + "x" * (size - len(header) - 2) + "\n"
        parts.append(header + body)
    return "".join(parts)


class TestSmartTruncateDiff:
    def test_small_diff_unchanged(self):
        diff = _make_diff({"src/main.py": 100})
        result, note = smart_truncate_diff(diff, max_chars=1000)
        assert result == diff
        assert note == ""

    def test_drops_low_priority_first(self):
        diff = _make_diff({
            "src/main.py": 500,
            "package-lock.json": 500,
        })
        result, note = smart_truncate_diff(diff, max_chars=600)
        assert "src/main.py" in result
        assert "package-lock.json" not in result
        assert "1 file(s) omitted" in note
        assert "package-lock.json" in note

    def test_drops_larger_files_first_within_same_priority(self):
        diff = _make_diff({
            "src/small.py": 100,
            "src/medium.py": 300,
            "src/large.py": 600,
        })
        result, note = smart_truncate_diff(diff, max_chars=500)
        assert "src/small.py" in result
        assert "src/medium.py" in result
        assert "src/large.py" not in result

    def test_truncation_note_lists_dropped_files(self):
        diff = _make_diff({
            "a.py": 100,
            "b.py": 200,
            "c.py": 300,
        })
        _, note = smart_truncate_diff(diff, max_chars=150)
        assert "omitted" in note

    def test_truncation_note_caps_at_10_names(self):
        files = {f"file{i}.py": 100 for i in range(15)}
        diff = _make_diff(files)
        _, note = smart_truncate_diff(diff, max_chars=200)
        assert "..." in note

    def test_empty_diff(self):
        result, note = smart_truncate_diff("", max_chars=100)
        assert result == ""
        assert note == ""

    def test_exact_limit(self):
        diff = _make_diff({"src/main.py": 100})
        result, note = smart_truncate_diff(diff, max_chars=len(diff))
        assert result == diff
        assert note == ""


# ── extract_diff_filenames ───────────────────────────────


class TestExtractDiffFilenames:
    def test_extracts_modified_files(self):
        diff = textwrap.dedent("""\
            diff --git a/src/main.py b/src/main.py
            index abc..def 100644
            --- a/src/main.py
            +++ b/src/main.py
            @@ -1,3 +1,4 @@
            +import os
             import sys
            diff --git a/src/utils.py b/src/utils.py
            index abc..def 100644
            --- a/src/utils.py
            +++ b/src/utils.py
            @@ -10,3 +10,4 @@
            +# comment
        """)
        assert extract_diff_filenames(diff) == ["src/main.py", "src/utils.py"]

    def test_excludes_deleted_files(self):
        diff = textwrap.dedent("""\
            diff --git a/keep.py b/keep.py
            index abc..def 100644
            --- a/keep.py
            +++ b/keep.py
            @@ -1 +1,2 @@
            +new line
            diff --git a/removed.py b/removed.py
            deleted file mode 100644
            index abc..000
            --- a/removed.py
            +++ /dev/null
            @@ -1,5 +0,0 @@
            -old content
        """)
        result = extract_diff_filenames(diff)
        assert "keep.py" in result
        assert "removed.py" not in result

    def test_excludes_dev_null_deletions(self):
        diff = textwrap.dedent("""\
            diff --git a/gone.py b/gone.py
            index abc..000
            --- a/gone.py
            +++ /dev/null
            @@ -1 +0,0 @@
            -bye
        """)
        assert extract_diff_filenames(diff) == []

    def test_handles_new_files(self):
        diff = textwrap.dedent("""\
            diff --git a/new.py b/new.py
            new file mode 100644
            index 000..abc
            --- /dev/null
            +++ b/new.py
            @@ -0,0 +1,3 @@
            +hello
        """)
        assert extract_diff_filenames(diff) == ["new.py"]

    def test_handles_renames(self):
        diff = textwrap.dedent("""\
            diff --git a/old_name.py b/new_name.py
            similarity index 95%
            rename from old_name.py
            rename to new_name.py
            index abc..def 100644
            --- a/old_name.py
            +++ b/new_name.py
            @@ -1 +1 @@
            -old
            +new
        """)
        assert extract_diff_filenames(diff) == ["new_name.py"]

    def test_no_duplicates(self):
        # Same file appearing somehow won't duplicate
        diff = (
            "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n+x\n"
        )
        assert extract_diff_filenames(diff) == ["f.py"]

    def test_empty_diff(self):
        assert extract_diff_filenames("") == []

    def test_diff_header_as_last_line(self):
        """diff --git line at EOF with no subsequent lines."""
        diff = "diff --git a/trailing.py b/trailing.py"
        assert extract_diff_filenames(diff) == ["trailing.py"]

    def test_diff_header_only_one_line_after(self):
        """diff --git with only an index line following (no +++ line)."""
        diff = (
            "diff --git a/mode.py b/mode.py\n"
            "index abc..def 100755\n"
        )
        assert extract_diff_filenames(diff) == ["mode.py"]


# ── format_file_contents ────────────────────────────────


class TestFormatFileContents:
    def test_formats_files(self):
        files = [("src/main.py", "import os\n")]
        result, note = format_file_contents(files, max_chars=10_000)
        assert "### src/main.py" in result
        assert "import os" in result
        assert note == ""

    def test_truncates_large_files(self):
        files = [
            ("small.py", "x" * 100),
            ("big.py", "y" * 5000),
        ]
        result, note = format_file_contents(files, max_chars=200)
        assert "small.py" in result
        assert "big.py" not in result
        assert "1 file(s) contents omitted" in note
        assert "big.py" in note

    def test_drops_low_priority_first(self):
        files = [
            ("src/app.py", "x" * 300),
            ("package-lock.json", "y" * 300),
        ]
        result, note = format_file_contents(files, max_chars=400)
        assert "src/app.py" in result
        assert "package-lock.json" not in result

    def test_empty_input(self):
        result, note = format_file_contents([], max_chars=10_000)
        assert result == ""
        assert note == ""

    def test_note_caps_at_10_names(self):
        files = [(f"f{i}.py", "x" * 100) for i in range(15)]
        _, note = format_file_contents(files, max_chars=200)
        assert "..." in note

    def test_all_files_fit(self):
        files = [
            ("a.py", "aaa"),
            ("b.py", "bbb"),
        ]
        result, note = format_file_contents(files, max_chars=100_000)
        assert "a.py" in result
        assert "b.py" in result
        assert note == ""

    def test_exact_boundary(self):
        """A single file whose formatted entry exactly hits max_chars."""
        files = [("x.py", "hello")]
        entry = "### x.py\n~~~\nhello\n~~~\n"
        result, note = format_file_contents(files, max_chars=len(entry))
        assert result == entry
        assert note == ""

    def test_single_file_too_large(self):
        """One file exceeds budget — result is empty, note lists it."""
        files = [("huge.py", "x" * 10_000)]
        result, note = format_file_contents(files, max_chars=50)
        assert result == ""
        assert "huge.py" in note
        assert "1 file(s) contents omitted" in note

    def test_all_dropped(self):
        """Multiple files, all too large — every file dropped."""
        files = [
            ("a.py", "x" * 500),
            ("b.py", "y" * 500),
        ]
        result, note = format_file_contents(files, max_chars=10)
        assert result == ""
        assert "2 file(s) contents omitted" in note

    def test_mixed_priority_under_pressure(self):
        """High-priority small file kept; low-priority file and large high-priority dropped."""
        files = [
            ("src/small.py", "x" * 50),
            ("package-lock.json", "y" * 50),
            ("src/big.py", "z" * 5000),
        ]
        # Budget fits only one small file (~76 chars formatted)
        result, note = format_file_contents(files, max_chars=100)
        assert "src/small.py" in result
        assert "package-lock.json" not in result
        assert "src/big.py" not in result
        assert "2 file(s) contents omitted" in note

    def test_output_wraps_in_code_blocks(self):
        """Each file gets a markdown header and tilde-fenced code block."""
        files = [("app.py", "print('hi')")]
        result, _ = format_file_contents(files, max_chars=10_000)
        assert result.startswith("### app.py\n~~~\n")
        assert result.endswith("\n~~~\n")

    def test_no_double_blank_lines_between_files(self):
        """Multiple files are joined without extra blank lines."""
        files = [
            ("a.py", "aaa"),
            ("b.py", "bbb"),
        ]
        result, _ = format_file_contents(files, max_chars=100_000)
        # Each entry ends with \n, so joining directly gives \n###
        # There should be no \n\n### (double blank line) between entries
        assert "\n\n###" not in result
        assert "### a.py" in result
        assert "### b.py" in result


# ── fetch_file_contents ─────────────────────────────────


class TestFetchFileContents:
    """Tests for fetch_file_contents filter logic (mocked subprocess)."""

    VALID_SHA = "a" * 40  # valid 40-char hex SHA

    def _make_run(self, responses: dict[str, bytes]):
        """Return a fake subprocess.run that returns bytes content keyed by filename."""
        class FakeResult:
            def __init__(self, stdout, returncode=0):
                self.stdout = stdout
                self.returncode = returncode
                self.stderr = b""

        def fake_run(cmd, **kwargs):
            # Extract filename from the gh api URL:
            #   repos/{repo}/contents/{path}?ref={sha}
            url = cmd[2]  # "repos/owner/repo/contents/path?ref=sha"
            path_part = url.split("/contents/")[1].split("?")[0]
            if path_part in responses:
                return FakeResult(responses[path_part])
            return FakeResult(b"", returncode=1)

        return fake_run

    def test_skips_low_priority_files(self, monkeypatch):
        fake = self._make_run({"package-lock.json": b"{}", "app.py": b"code"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["package-lock.json", "app.py"])
        names = [name for name, _ in result]
        assert "app.py" in names
        assert "package-lock.json" not in names

    def test_caps_at_15_files(self, monkeypatch):
        all_files = [f"file{i}.py" for i in range(20)]
        responses = {f: f"content_{f}".encode() for f in all_files}
        fake = self._make_run(responses)
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, all_files)
        assert len(result) == 15

    def test_skips_api_failures(self, monkeypatch):
        fake = self._make_run({})  # all files return rc=1
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["missing.py"])
        assert result == []

    def test_skips_empty_content(self, monkeypatch):
        fake = self._make_run({"empty.py": b""})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["empty.py"])
        assert result == []

    def test_skips_oversized_files(self, monkeypatch):
        fake = self._make_run({"huge.py": b"x" * 60_000})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["huge.py"])
        assert result == []

    def test_skips_binary_files(self, monkeypatch):
        fake = self._make_run({"image.py": b"header\x00binary_data"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["image.py"])
        assert result == []

    def test_passes_non_null_non_ascii_files(self, monkeypatch):
        """Files with non-ASCII bytes but no null bytes are accepted (not false-positive)."""
        # Valid UTF-8 with high bytes — should NOT be rejected
        fake = self._make_run({"text.py": b"\xc3\xa9\xc3\xa0 unicode ok"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["text.py"])
        assert len(result) == 1
        assert result[0][0] == "text.py"

    def test_returns_valid_files(self, monkeypatch):
        fake = self._make_run({"good.py": b"import os\nprint('hello')\n"})
        monkeypatch.setattr("agent.subprocess.run", fake)
        result = fetch_file_contents("owner/repo", self.VALID_SHA, ["good.py"])
        assert len(result) == 1
        assert result[0] == ("good.py", "import os\nprint('hello')\n")

    def test_rejects_invalid_sha(self, monkeypatch):
        """Invalid head_sha format returns empty list without making API calls."""
        call_count = 0
        def no_calls(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
        monkeypatch.setattr("agent.subprocess.run", no_calls)
        result = fetch_file_contents("owner/repo", "not-a-sha", ["file.py"])
        assert result == []
        assert call_count == 0

    def test_rejects_invalid_repo_format(self, monkeypatch):
        """Malformed repo names (e.g. path traversal) are rejected without API calls."""
        call_count = 0
        def no_calls(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
        monkeypatch.setattr("agent.subprocess.run", no_calls)
        # Path traversal attempt
        result = fetch_file_contents("owner/../evil", self.VALID_SHA, ["file.py"])
        assert result == []
        assert call_count == 0
        # Missing slash
        result = fetch_file_contents("noslash", self.VALID_SHA, ["file.py"])
        assert result == []
        assert call_count == 0

    def test_url_encodes_filenames(self, monkeypatch):
        """Filenames with spaces/special chars are URL-encoded in the API call."""
        captured_urls = []
        class FakeResult:
            stdout = b"content"
            returncode = 0
            stderr = b""
        def capture_run(cmd, **kwargs):
            captured_urls.append(cmd[2])
            return FakeResult()
        monkeypatch.setattr("agent.subprocess.run", capture_run)
        fetch_file_contents("owner/repo", self.VALID_SHA, ["path/to/my file.py"])
        assert len(captured_urls) == 1
        assert "my%20file.py" in captured_urls[0]
        assert "my file.py" not in captured_urls[0]


# ── prompt template rendering ────────────────────────────


class TestPromptRendering:
    """Verify the prompt template renders correctly with all placeholders."""

    def test_template_renders_with_file_contents(self):
        from agent import get_prompt_template
        template = get_prompt_template()

        def esc(s):
            return s.replace("{", "{{").replace("}", "}}")

        # Should not raise KeyError for any placeholder
        result = template.format(
            pr_number=42,
            repo="owner/repo",
            pr_title=esc("Add feature"),
            pr_body=esc("Implements X"),
            truncation_note="",
            file_contents=esc("### app.py\n~~~\nprint('hi')\n~~~\n"),
            diff=esc("+import os\n"),
        )
        assert "PR #42" in result
        assert "owner/repo" in result
        assert "### app.py" in result
        assert "+import os" in result

    def test_template_renders_with_empty_file_contents(self):
        from agent import get_prompt_template
        template = get_prompt_template()

        def esc(s):
            return s.replace("{", "{{").replace("}", "}}")

        result = template.format(
            pr_number=1,
            repo="a/b",
            pr_title=esc("Fix"),
            pr_body=esc("(none)"),
            truncation_note="",
            file_contents="",
            diff=esc("+x\n"),
        )
        assert "a/b" in result
        assert "+x" in result

    def test_template_handles_braces_in_file_contents(self):
        """File contents with { and } don't break .format()."""
        from agent import get_prompt_template
        template = get_prompt_template()

        def esc(s):
            return s.replace("{", "{{").replace("}", "}}")

        code_with_braces = "def main():\n    d = {key: value}\n    return d\n"
        result = template.format(
            pr_number=1,
            repo="a/b",
            pr_title=esc("Fix"),
            pr_body=esc("(none)"),
            truncation_note="",
            file_contents=esc(code_with_braces),
            diff=esc("+x\n"),
        )
        assert "{key: value}" in result

    def test_empty_placeholders_no_triple_blank_lines(self):
        """Empty truncation_note and file_contents don't produce triple+ blank lines
        after collapsing (as done in review_pr)."""
        import re as re_mod
        from agent import get_prompt_template
        template = get_prompt_template()

        def esc(s):
            return s.replace("{", "{{").replace("}", "}}")

        result = template.format(
            pr_number=1,
            repo="a/b",
            pr_title=esc("Fix"),
            pr_body=esc("(none)"),
            truncation_note="",
            file_contents="",
            diff=esc("+x\n"),
        )
        # Simulate the same collapsing done in review_pr
        result = re_mod.sub(r"\n{3,}", "\n\n", result)
        assert "\n\n\n" not in result
        # Content should still be present
        assert "Diff (changes to review):" in result


# ── build.py ─────────────────────────────────────────────


@pytest.mark.usefixtures("scripts_on_path")
class TestBuild:
    def test_build_produces_valid_output(self):
        from build import build
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        output = build(root)
        assert output.startswith("#cloud-config")
        assert "{{FILE:" not in output
        assert "agent.py" in output
        assert "prompt.md" in output

    def test_build_raises_on_missing_file(self, tmp_path):
        from build import build, BuildError

        # Write a template referencing a file that doesn't exist
        infra = tmp_path / "infra"
        infra.mkdir()
        template = infra / "cloud-init.tmpl.yaml"
        template.write_text("content: |\n  {{FILE:nonexistent.py}}\n")
        with pytest.raises(BuildError, match="nonexistent.py"):
            build(tmp_path)

    def test_build_rejects_path_traversal(self, tmp_path):
        from build import build, BuildError

        infra = tmp_path / "infra"
        infra.mkdir()
        template = infra / "cloud-init.tmpl.yaml"
        template.write_text("content: |\n  {{FILE:../../etc/passwd}}\n")
        with pytest.raises(BuildError, match="path traversal"):
            build(tmp_path)


# ── already_reviewed ────────────────────────────────────


def _subprocess_result(returncode=0, stdout="", stderr=""):
    """Build a mock subprocess.CompletedProcess."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestAlreadyReviewed:
    @patch("agent.subprocess.run")
    def test_returns_true_when_comments_found(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="2\n")
        assert already_reviewed("owner/repo", 42) is True

    @patch("agent.subprocess.run")
    def test_returns_false_when_no_comments(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="0\n")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_returns_false_on_empty_output(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_returns_false_on_non_numeric_output(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="error: not found\n")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_returns_false_on_command_failure(self, mock_run):
        mock_run.return_value = _subprocess_result(returncode=1, stdout="")
        assert already_reviewed("owner/repo", 42) is False

    @patch("agent.subprocess.run")
    def test_passes_correct_args(self, mock_run):
        mock_run.return_value = _subprocess_result(stdout="0\n")
        already_reviewed("org/my-repo", 99)

        args = mock_run.call_args[0][0]
        assert args[0] == "gh"
        # Verify --repo flag is followed by the repo name
        repo_idx = args.index("--repo")
        assert args[repo_idx + 1] == "org/my-repo"
        # PR number should be passed as a positional string arg
        assert "99" in args

    @patch("agent.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="gh", timeout=30))
    def test_propagates_timeout(self, mock_run):
        with pytest.raises(subprocess.TimeoutExpired):
            already_reviewed("owner/repo", 42)


# ── collapse_old_reviews ────────────────────────────────


def _jq_json_line(obj: dict) -> str:
    """Simulate jq's @json filter: double-encode a dict as a JSON string."""
    return json.dumps(json.dumps(obj))


class TestCollapseOldReviews:
    @patch("agent.subprocess.run")
    def test_collapses_uncollapsed_reviews(self, mock_run):
        line = _jq_json_line({
            "id": 123,
            "body": f"{REVIEW_MARKER}\n## Review\nLooks good!",
        })
        # First call: list comments; second call: PATCH
        mock_run.side_effect = [
            _subprocess_result(stdout=line + "\n"),
            _subprocess_result(),
        ]

        collapse_old_reviews("owner/repo", 7)

        assert mock_run.call_count == 2
        patch_call = mock_run.call_args_list[1]
        args = patch_call[0][0]
        assert "PATCH" in args
        # Find the endpoint arg containing the comment ID
        endpoint_args = [a for a in args if "/issues/comments/" in a]
        assert any("123" in a for a in endpoint_args)
        # The -f body=... arg should contain <details>
        body_arg = [a for a in args if "body=" in a and "<details>" in a]
        assert len(body_arg) == 1
        assert "Previous review (superseded)" in body_arg[0]

    @patch("agent.subprocess.run")
    def test_skips_already_collapsed_reviews(self, mock_run):
        # The jq filter already excludes comments containing <details>,
        # so the gh api call returns empty
        mock_run.return_value = _subprocess_result(stdout="")
        collapse_old_reviews("owner/repo", 7)
        assert mock_run.call_count == 1  # only the list call

    @patch("agent.subprocess.run")
    def test_handles_multiple_comments(self, mock_run):
        comments = "\n".join(
            _jq_json_line({"id": i, "body": f"{REVIEW_MARKER}\nReview #{i}"})
            for i in [10, 20, 30]
        )
        mock_run.side_effect = [
            _subprocess_result(stdout=comments + "\n"),
            _subprocess_result(),  # PATCH #10
            _subprocess_result(),  # PATCH #20
            _subprocess_result(),  # PATCH #30
        ]

        collapse_old_reviews("owner/repo", 5)

        # 1 list + 3 PATCH calls
        assert mock_run.call_count == 4

    @patch("agent.subprocess.run")
    def test_noop_when_list_fails(self, mock_run):
        mock_run.return_value = _subprocess_result(returncode=1, stderr="API error")
        collapse_old_reviews("owner/repo", 5)
        assert mock_run.call_count == 1

    @patch("agent.subprocess.run")
    def test_skips_malformed_json_lines(self, mock_run):
        output = "not-json\n" + _jq_json_line({"id": 1, "body": f"{REVIEW_MARKER}\nOk"})
        mock_run.side_effect = [
            _subprocess_result(stdout=output + "\n"),
            _subprocess_result(),  # PATCH for the valid one
        ]

        collapse_old_reviews("owner/repo", 3)

        # Should still patch the valid comment
        assert mock_run.call_count == 2

    @patch("agent.subprocess.run")
    def test_skips_comment_with_missing_id(self, mock_run):
        output = _jq_json_line({"body": f"{REVIEW_MARKER}\nno id"})
        mock_run.side_effect = [
            _subprocess_result(stdout=output + "\n"),
        ]

        collapse_old_reviews("owner/repo", 3)

        # Only the list call, no PATCH because id is missing
        assert mock_run.call_count == 1

    @patch("agent.subprocess.run")
    def test_deduplicates_marker_in_collapsed_body(self, mock_run):
        """Marker appears once at the top of the collapsed body, not duplicated inside <details>."""
        original_body = f"{REVIEW_MARKER}\n## Review\nGreat code!"
        line = _jq_json_line({"id": 5, "body": original_body})
        mock_run.side_effect = [
            _subprocess_result(stdout=line + "\n"),
            _subprocess_result(),
        ]

        collapse_old_reviews("owner/repo", 1)

        patch_args = mock_run.call_args_list[1][0][0]
        body_arg = [a for a in patch_args if a.startswith("body=")][0]
        assert body_arg.count(REVIEW_MARKER) == 1

    @patch("agent.subprocess.run")
    def test_handles_newlines_in_body(self, mock_run):
        """@json encoding ensures bodies with newlines don't break line-based parsing."""
        body_with_newlines = f"{REVIEW_MARKER}\n## Review\n\nLine 1\nLine 2\nLine 3"
        line = _jq_json_line({"id": 42, "body": body_with_newlines})
        mock_run.side_effect = [
            _subprocess_result(stdout=line + "\n"),
            _subprocess_result(),
        ]

        collapse_old_reviews("owner/repo", 1)

        assert mock_run.call_count == 2
        patch_args = mock_run.call_args_list[1][0][0]
        body_arg = [a for a in patch_args if a.startswith("body=")][0]
        assert "<details>" in body_arg
        assert "Line 1" in body_arg


# ── review_pr ───────────────────────────────────────────


def _find_call_with_arg(mock_run, arg):
    """Find a subprocess.run call whose argv list contains `arg` as an exact element."""
    return next(
        (c for c in mock_run.call_args_list if arg in c[0][0]),
        None,
    )


class TestReviewPr:
    """Tests for the main review_pr orchestration function."""

    def _call_review(self, repo, pr_number, title, action):
        """Helper to call review_pr with proper generation tracking."""
        pr_key = f"{repo}#{pr_number}"
        gen = _bump_generation(pr_key)
        review_pr(repo, pr_number, title, action, pr_key, gen)

    def _mock_reviewer(self, stdout="LGTM", returncode=0):
        proc = MagicMock()
        proc.communicate.return_value = (stdout, "")
        proc.returncode = returncode
        return proc

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="Review {repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_happy_path_opened(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            # already_reviewed: gh pr view --json comments
            _subprocess_result(stdout="0\n"),
            # gh pr diff
            _subprocess_result(stdout="diff --git a/f.py b/f.py\n+hello\n"),
            # gh pr view --json body,headRefOid
            _subprocess_result(stdout='{"body":"Fix the bug","headRefOid":"a"}\n'),
            # gh pr comment
            _subprocess_result(stdout="https://github.com/owner/repo/pull/1#comment"),
        ]
        mock_popen.return_value = self._mock_reviewer("LGTM, no issues found.")

        self._call_review("owner/repo", 1, "Fix bug", "opened")

        # Verify reviewer was called with the prompt
        mock_popen.assert_called_once()
        # Verify comment was posted
        assert mock_run.call_count == 4

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_skips_already_reviewed_on_opened(self, mock_template, mock_run):
        mock_run.return_value = _subprocess_result(stdout="1\n")

        self._call_review("owner/repo", 1, "Fix bug", "opened")

        # Only already_reviewed call, nothing else
        assert mock_run.call_count == 1

    @patch("agent.already_reviewed", return_value=True)
    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_ready_for_review_skips_already_reviewed_check(self, mock_template, mock_run, mock_popen, mock_ar):
        mock_run.side_effect = [
            # collapse_old_reviews: gh api list comments (no uncollapsed)
            _subprocess_result(stdout=""),
            # gh pr diff
            _subprocess_result(stdout="diff --git a/f.py b/f.py\n+change\n"),
            # gh pr view --json body,headRefOid
            _subprocess_result(stdout='{"body":"Ready now","headRefOid":"a"}\n'),
            # gh pr comment
            _subprocess_result(stdout="https://github.com/owner/repo/pull/1#comment"),
        ]
        mock_popen.return_value = self._mock_reviewer("Looks good.")

        self._call_review("owner/repo", 1, "Fix bug", "ready_for_review")

        # already_reviewed is never consulted for ready_for_review
        mock_ar.assert_not_called()
        # But the review still proceeds
        mock_popen.assert_called_once()

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_synchronize_collapses_old_reviews(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            # collapse_old_reviews: gh api list comments (no uncollapsed)
            _subprocess_result(stdout=""),
            # gh pr diff
            _subprocess_result(stdout="diff --git a/f.py b/f.py\n+change\n"),
            # gh pr view --json body,headRefOid
            _subprocess_result(stdout='{"body":"Updated"}\n'),
            # gh pr comment
            _subprocess_result(),
        ]
        mock_popen.return_value = self._mock_reviewer("Looks good.")

        self._call_review("owner/repo", 2, "Update feature", "synchronize")

        # First call should be the collapse_old_reviews (gh api), not already_reviewed
        assert _find_call_with_arg(mock_run,"api") is not None
        # Verify "Updated Review" header in posted comment
        comment_call = _find_call_with_arg(mock_run, "--body")
        assert comment_call is not None
        comment_args = comment_call[0][0]
        body_idx = comment_args.index("--body") + 1
        assert "Updated Review" in comment_args[body_idx]

    @patch("agent.subprocess.run")
    def test_returns_on_diff_failure(self, mock_run):
        mock_run.side_effect = [
            # already_reviewed
            _subprocess_result(stdout="0\n"),
            # gh pr diff — fails
            _subprocess_result(returncode=1, stderr="not found"),
        ]

        self._call_review("owner/repo", 1, "Fix", "opened")

        # Should stop after diff failure — no reviewer or comment calls
        assert mock_run.call_count == 2

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_returns_on_empty_diff(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),     # already_reviewed
            _subprocess_result(stdout="   \n"),   # gh pr diff — whitespace only
            _subprocess_result(stdout='{"body":"desc"}\n'),  # gh pr view --json body,headRefOid
        ]

        self._call_review("owner/repo", 1, "Empty PR", "opened")

        # Should stop after detecting empty diff — no reviewer or comment calls
        assert mock_run.call_count == 3

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_returns_on_reviewer_failure(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(stdout='{"body":"body"}\n'),            # pr info
        ]
        mock_popen.return_value = self._mock_reviewer("", returncode=1)

        self._call_review("owner/repo", 1, "Fix", "opened")

        # Should not attempt to post comment
        assert mock_run.call_count == 3

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_returns_on_empty_reviewer_output(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(stdout='{"body":"body"}\n'),            # pr info
        ]
        mock_popen.return_value = self._mock_reviewer("   \n")

        self._call_review("owner/repo", 1, "Fix", "opened")

        assert mock_run.call_count == 3

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_handles_comment_post_failure(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(stdout='{"body":"body"}\n'),            # pr info
            _subprocess_result(returncode=1, stderr="post failed"),    # comment fails
        ]
        mock_popen.return_value = self._mock_reviewer("Review text")

        # Should not raise
        self._call_review("owner/repo", 1, "Fix", "opened")
        assert mock_run.call_count == 4

    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_handles_timeout(self, mock_template, mock_run):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),  # already_reviewed
            subprocess.TimeoutExpired(cmd="gh", timeout=60),
        ]

        # Should not raise — timeout is caught after already_reviewed + diff fetch
        self._call_review("owner/repo", 1, "Fix", "opened")
        assert mock_run.call_count == 2

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_escapes_braces_in_title_and_body(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),
            _subprocess_result(stdout='{"body":"body with {braces}"}\n'),
            _subprocess_result(),  # comment
        ]
        mock_popen.return_value = self._mock_reviewer("Review output")

        # Title with braces should not cause a KeyError in .format()
        self._call_review("owner/repo", 1, "Fix {something}", "opened")

        # Verify reviewer was called (format didn't crash)
        mock_popen.assert_called_once()

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_opened_header(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),
            _subprocess_result(stdout='{"body":"body"}\n'),
            _subprocess_result(),  # comment
        ]
        mock_popen.return_value = self._mock_reviewer("Review")

        self._call_review("owner/repo", 1, "Fix", "opened")

        comment_call = _find_call_with_arg(mock_run, "--body")
        assert comment_call is not None
        comment_args = comment_call[0][0]
        body_idx = comment_args.index("--body") + 1
        assert "Review" in comment_args[body_idx]  # "📝 Review" header
        assert "Updated" not in comment_args[body_idx]

    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    @patch("agent.get_prompt_template", return_value="{repo}#{pr_number}: {pr_title}\n{pr_body}\n{truncation_note}\n{file_contents}\n{diff}")
    def test_pr_body_fallback_when_fetch_fails(self, mock_template, mock_run, mock_popen):
        mock_run.side_effect = [
            _subprocess_result(stdout="0\n"),                           # already_reviewed
            _subprocess_result(stdout="diff --git a/x b/x\n+ok\n"),   # diff
            _subprocess_result(returncode=1, stderr="err"),            # body fetch fails
            _subprocess_result(),                                      # comment
        ]
        mock_popen.return_value = self._mock_reviewer("Review")

        self._call_review("owner/repo", 1, "Fix", "opened")

        # Reviewer should still be called — body defaults to ""
        mock_popen.assert_called_once()


# ── WebhookHandler ──────────────────────────────────────

SECRET = "test-secret-key"


def _sign_payload(payload: bytes) -> str:
    return "sha256=" + hmac.new(
        SECRET.encode(), payload, hashlib.sha256
    ).hexdigest()


def _make_pr_payload(action="opened", draft=False, number=1, title="Test PR"):
    return json.dumps({
        "action": action,
        "pull_request": {
            "number": number,
            "title": title,
            "draft": draft,
        },
        "repository": {"full_name": "owner/repo"},
    }).encode()


@pytest.fixture()
def http_server():
    """Start a WebhookHandler on a random port, yield (host, port), then shut down."""
    server = HTTPServer(("127.0.0.1", 0), WebhookHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield ("127.0.0.1", port)
    server.shutdown()


class TestWebhookHandlerGet:
    def test_health_endpoint(self, http_server):
        import urllib.request
        host, port = http_server
        req = urllib.request.Request(f"http://{host}:{port}/health")
        resp = urllib.request.urlopen(req)
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["status"] == "healthy"

    def test_unknown_get_returns_404(self, http_server):
        import urllib.request
        import urllib.error
        host, port = http_server
        req = urllib.request.Request(f"http://{host}:{port}/unknown")
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req)
        assert exc.value.code == 404


class TestWebhookHandlerPost:
    @staticmethod
    def _wait_for_call(mock, timeout=2.0):
        """Poll until *mock* has been called (handler processes after 200)."""
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if mock.call_count > 0:
                return
            time.sleep(0.01)

    def _post(self, http_server, path, payload, headers=None):
        import http.client
        host, port = http_server
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request("POST", path, body=payload, headers=headers or {})
        resp = conn.getresponse()
        status = resp.status
        try:
            body = resp.read()
        except ConnectionError:
            body = b""
        conn.close()
        return status, body

    def test_wrong_path_returns_404(self, http_server):
        payload = b'{"test": true}'
        status, _ = self._post(http_server, "/wrong", payload)
        assert status == 404

    def test_missing_signature_returns_403(self, http_server):
        payload = _make_pr_payload()
        headers = {"Content-Length": str(len(payload))}
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 403

    def test_invalid_signature_returns_403(self, http_server):
        payload = _make_pr_payload()
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": "sha256=invalid",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 403

    def test_valid_signature_returns_200(self, http_server):
        payload = _make_pr_payload()
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "ping",
        }
        status, body = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        assert json.loads(body)["ok"] is True

    @patch("agent._schedule_review")
    def test_pr_opened_submits_review(self, mock_schedule, http_server):
        payload = _make_pr_payload(action="opened", number=42, title="My PR")
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200

        self._wait_for_call(mock_schedule)
        mock_schedule.assert_called_once()
        args = mock_schedule.call_args[0]
        assert args[0] == "owner/repo#42"  # pr_key
        assert args[1] == 0                # delay=0 for opened (no debounce)
        assert args[2] == "owner/repo"     # repo
        assert args[3] == 42              # pr_number
        assert args[4] == "My PR"         # title
        assert args[5] == "opened"        # action
        assert isinstance(args[6], int)   # generation

    @patch("agent._schedule_review")
    def test_pr_synchronize_submits_review(self, mock_schedule, http_server):
        payload = _make_pr_payload(action="synchronize", number=10)
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200

        self._wait_for_call(mock_schedule)
        mock_schedule.assert_called_once()
        call_args = mock_schedule.call_args
        # Verify delay=DEBOUNCE_SECONDS for synchronize events
        assert call_args[0][1] == DEBOUNCE_SECONDS
        assert call_args[0][2] == "owner/repo"
        assert call_args[0][3] == 10
        assert call_args[0][5] == "synchronize"

    @patch("agent._schedule_review")
    def test_pr_closed_does_not_submit(self, mock_schedule, http_server):
        payload = _make_pr_payload(action="closed")
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_schedule.assert_not_called()

    @patch("agent._schedule_review")
    def test_draft_pr_skipped(self, mock_schedule, http_server):
        payload = _make_pr_payload(action="opened", draft=True)
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_schedule.assert_not_called()

    @patch("agent._schedule_review")
    def test_ready_for_review_triggers_review(self, mock_schedule, http_server):
        payload = _make_pr_payload(action="ready_for_review", draft=False)
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        self._wait_for_call(mock_schedule)
        mock_schedule.assert_called_once()
        args = mock_schedule.call_args.args
        assert args[1] == 0, "expected zero debounce delay for ready_for_review"
        assert args[5] == "ready_for_review", "expected action forwarded correctly"

    @patch("agent._schedule_review")
    def test_ready_for_review_draft_still_skipped(self, mock_schedule, http_server):
        # GitHub guarantees draft=false in ready_for_review payloads, but
        # we test the guard defensively in case of malformed webhooks.
        payload = _make_pr_payload(action="ready_for_review", draft=True)
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "pull_request",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_schedule.assert_not_called()

    @patch("agent._schedule_review")
    def test_non_pr_event_ignored(self, mock_schedule, http_server):
        payload = _make_pr_payload()
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
            "X-GitHub-Event": "push",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_schedule.assert_not_called()

    def test_oversized_payload_returns_413(self, http_server):
        # Relies on do_POST checking Content-Length *before* reading the body.
        # We send a small payload with an inflated Content-Length header to
        # avoid pushing 5MB over loopback. If the handler is ever refactored
        # to read-then-check, this test must be updated to send an actual
        # oversized payload.
        payload = b"x" * 1024
        headers = {
            "Content-Length": "5000001",
            "X-Hub-Signature-256": "sha256=dummy",
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 413

    @patch("agent._schedule_review")
    def test_missing_event_header_returns_200_no_submit(self, mock_schedule, http_server):
        """A valid signature but no X-GitHub-Event should return 200 but not submit."""
        payload = _make_pr_payload()
        sig = _sign_payload(payload)
        headers = {
            "Content-Length": str(len(payload)),
            "X-Hub-Signature-256": sig,
        }
        status, _ = self._post(http_server, "/webhook", payload, headers)
        assert status == 200
        mock_schedule.assert_not_called()


# ── get_prompt_template ─────────────────────────────────


class TestGetPromptTemplate:
    def test_returns_prompt_content(self):
        from agent import get_prompt_template
        template = get_prompt_template()
        assert "{pr_number}" in template
        assert "{diff}" in template

    def test_is_idempotent(self):
        from agent import get_prompt_template
        t1 = get_prompt_template()
        t2 = get_prompt_template()
        assert t1 is t2  # cached — same object


# ── JSONFormatter ───────────────────────────────────────


class TestJSONFormatter:
    def test_formats_log_as_json(self):
        import logging
        from agent import JSONFormatter

        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello world", args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["msg"] == "hello world"
        assert parsed["level"] == "INFO"
        assert "ts" in parsed

    def test_includes_exception_info(self):
        import logging
        from agent import JSONFormatter

        formatter = JSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="", lineno=0,
            msg="failure", args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exc" in parsed
        assert "ValueError" in parsed["exc"]


# ── Generation tracking ─────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_review_state():
    """Reset module-level review state between tests."""
    yield
    with _review_state_lock:
        for state in _review_state.values():
            if state.timer is not None:
                state.timer.cancel()
        _review_state.clear()
    _shutting_down.clear()


class TestBumpGeneration:
    def test_first_bump_returns_1(self):
        assert _bump_generation("org/repo#1") == 1

    def test_successive_bumps_increment(self):
        _bump_generation("org/repo#2")
        assert _bump_generation("org/repo#2") == 2
        assert _bump_generation("org/repo#2") == 3

    def test_independent_prs_have_separate_generations(self):
        assert _bump_generation("org/repo#10") == 1
        assert _bump_generation("org/repo#20") == 1
        assert _bump_generation("org/repo#10") == 2
        assert _bump_generation("org/repo#20") == 2

    def test_kills_active_process_on_bump(self):
        pr_key = "org/repo#3"
        _bump_generation(pr_key)

        mock_proc = MagicMock()
        with _review_state_lock:
            _review_state[pr_key].process = mock_proc

        _bump_generation(pr_key)

        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_not_called()  # communicate() is the sole wait

    def test_cancels_pending_timer_on_bump(self):
        pr_key = "org/repo#4"
        _bump_generation(pr_key)

        mock_timer = MagicMock()
        with _review_state_lock:
            _review_state[pr_key].timer = mock_timer

        _bump_generation(pr_key)

        mock_timer.cancel.assert_called_once()

    def test_handles_already_dead_process(self):
        pr_key = "org/repo#5"
        _bump_generation(pr_key)

        mock_proc = MagicMock()
        mock_proc.terminate.side_effect = OSError("No such process")
        with _review_state_lock:
            _review_state[pr_key].process = mock_proc

        # Should not raise
        gen = _bump_generation(pr_key)
        assert gen == 2


class TestIsCurrent:
    def test_current_generation_returns_true(self):
        gen = _bump_generation("org/repo#100")
        assert _is_current("org/repo#100", gen) is True

    def test_stale_generation_returns_false(self):
        gen1 = _bump_generation("org/repo#101")
        _bump_generation("org/repo#101")  # gen2
        assert _is_current("org/repo#101", gen1) is False

    def test_unknown_pr_returns_false(self):
        assert _is_current("org/repo#999", 1) is False

    def test_shutting_down_returns_false(self):
        gen = _bump_generation("org/repo#102")
        _shutting_down.set()
        assert _is_current("org/repo#102", gen) is False


class TestReviewPrCancellation:
    """Test that review_pr bails out when superseded."""

    def _mock_diff(self, returncode=0):
        return MagicMock(
            returncode=returncode,
            stdout="diff --git a/f.py b/f.py\n+hello\n",
            stderr="",
        )

    def _mock_body(self):
        return MagicMock(returncode=0, stdout='{"body":"PR body","headRefOid":"' + "a" * 40 + '"}')

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{file_contents}{diff}")
    @patch("agent.subprocess.run")
    def test_skips_diff_fetch_when_superseded(self, mock_run, _mock_tpl):
        pr_key = "org/repo#50"
        gen = _bump_generation(pr_key)
        _bump_generation(pr_key)  # supersede

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        review_pr("org/repo", 50, "title", "synchronize", pr_key, gen)

        # _is_current fails before any subprocess calls, so nothing should run.
        assert mock_run.call_count == 0

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{file_contents}{diff}")
    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    def test_skips_reviewer_when_superseded_after_diff(self, mock_run, mock_popen, _mock_tpl):
        pr_key = "org/repo#51"
        gen = _bump_generation(pr_key)

        # subprocess.run calls: collapse_old_reviews (returns nothing), diff, body
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # collapse api
            self._mock_diff(),  # diff
            self._mock_body(),  # body
        ]

        # Supersede after diff fetch but before reviewer. We do this by making
        # _is_current return False on the second call (before reviewer).
        call_count = 0

        def fake_is_current(key, g):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return True  # pass the first check (before start)
            return False  # fail the second check (before reviewer)

        with patch("agent._is_current", side_effect=fake_is_current):
            review_pr("org/repo", 51, "title", "synchronize", pr_key, gen)

        mock_popen.assert_not_called()

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{file_contents}{diff}")
    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    def test_skips_posting_when_superseded_after_reviewer(self, mock_run, mock_popen, _mock_tpl):
        pr_key = "org/repo#52"
        gen = _bump_generation(pr_key)

        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="", stderr=""),  # collapse api
            self._mock_diff(),  # diff
            self._mock_body(),  # body
        ]

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("Review output", "")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        call_count = 0

        def fake_is_current(key, g):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return True  # pass checks before start and before reviewer
            return False  # fail the check before posting

        with patch("agent._is_current", side_effect=fake_is_current):
            review_pr("org/repo", 52, "title", "synchronize", pr_key, gen)

        # Should not have posted a comment
        for call in mock_run.call_args_list:
            args = call[0][0]
            assert args[:3] != ["gh", "pr", "comment"], \
                "Should not post comment for superseded review"

    @patch("agent.get_prompt_template", return_value="{pr_number}{repo}{pr_title}{pr_body}{truncation_note}{file_contents}{diff}")
    @patch("agent.subprocess.Popen")
    @patch("agent.subprocess.run")
    def test_handles_killed_reviewer_process(self, mock_run, mock_popen, _mock_tpl):
        """When reviewer is killed by signal, review_pr logs and exits cleanly."""
        pr_key = "org/repo#53"
        gen = _bump_generation(pr_key)

        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="0\n"),  # already_reviewed
            self._mock_diff(),  # diff (no collapse for "opened")
            self._mock_body(),  # body
        ]

        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("", "")
        mock_proc.returncode = -15  # killed by SIGTERM
        mock_popen.return_value = mock_proc

        # Should not raise
        review_pr("org/repo", 53, "title", "opened", pr_key, gen)

        # No comment posted
        for call in mock_run.call_args_list:
            args = call[0][0]
            assert args[:3] != ["gh", "pr", "comment"]


class TestScheduleReview:
    """Tests for _schedule_review debounce timer."""

    @patch("agent.executor")
    def test_immediate_submit_with_zero_delay(self, mock_executor):
        """delay=0 fires the timer immediately, submitting to executor."""
        pr_key = "org/repo#60"
        gen = _bump_generation(pr_key)

        _schedule_review(pr_key, 0, "org/repo", 60, "title", "opened", gen)

        # Timer(0, ...) fires essentially immediately; give it a moment.
        import time
        time.sleep(0.1)

        mock_executor.submit.assert_called_once()
        call_args = mock_executor.submit.call_args
        assert call_args[0][0] == review_pr
        assert call_args[0][1] == "org/repo"
        assert call_args[0][2] == 60
        assert call_args[0][4] == "opened"
        assert call_args[0][5] == pr_key
        assert call_args[0][6] == gen

    @patch("agent.executor")
    def test_timer_registered_in_state(self, mock_executor):
        """_schedule_review stores the timer in _review_state."""
        pr_key = "org/repo#61"
        gen = _bump_generation(pr_key)

        _schedule_review(pr_key, 9999, "org/repo", 61, "title", "synchronize", gen)

        with _review_state_lock:
            state = _review_state[pr_key]
            assert state.timer is not None

        # Clean up — cancel the long timer
        state.timer.cancel()

    @patch("agent.executor")
    def test_bump_cancels_pending_timer(self, mock_executor):
        """A second bump cancels the first timer before it fires."""
        import time

        pr_key = "org/repo#62"
        gen1 = _bump_generation(pr_key)

        _schedule_review(pr_key, 9999, "org/repo", 62, "title", "synchronize", gen1)

        with _review_state_lock:
            timer1 = _review_state[pr_key].timer

        # Second push arrives — cancels the pending timer.
        gen2 = _bump_generation(pr_key)

        # Timer.cancel() sets the internal finished event; wait for thread exit.
        timer1.join(timeout=1)
        assert timer1.is_alive() is False

        # Schedule a new review with 0 delay.
        _schedule_review(pr_key, 0, "org/repo", 62, "title", "synchronize", gen2)

        time.sleep(0.1)

        # Only the second review should have been submitted.
        mock_executor.submit.assert_called_once()
        call_args = mock_executor.submit.call_args
        assert call_args[0][6] == gen2

    @patch("agent.executor")
    def test_stale_generation_prevents_submit(self, mock_executor):
        """_schedule_review with a stale generation does not submit."""
        import time

        pr_key = "org/repo#63"
        gen1 = _bump_generation(pr_key)
        # Immediately supersede so _is_current(pr_key, gen1) is False.
        _bump_generation(pr_key)

        # Schedule with the stale generation — _submit callback will check
        # _is_current and bail out.
        _schedule_review(pr_key, 0, "org/repo", 63, "title", "synchronize", gen1)

        time.sleep(0.1)

        mock_executor.submit.assert_not_called()

    @patch("agent.executor")
    def test_rapid_syncs_coalesce(self, mock_executor):
        """Multiple rapid synchronize events should coalesce into one review."""
        pr_key = "org/repo#64"

        # Simulate 3 rapid pushes (each bump cancels the previous timer).
        for _ in range(3):
            gen = _bump_generation(pr_key)

        # Only schedule after the last push.
        _schedule_review(pr_key, 0, "org/repo", 64, "title", "synchronize", gen)

        import time
        time.sleep(0.1)

        mock_executor.submit.assert_called_once()
        assert mock_executor.submit.call_args[0][6] == gen  # latest generation
