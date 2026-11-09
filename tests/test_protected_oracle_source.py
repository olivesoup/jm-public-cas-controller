"""Source-level tests execute the *actual* protected-base Oracle body, not a duplicate.
All GitHub API responses are local mocks; no owner tokens, networks, REST mutations.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".github" / "workflows" / "jm-cas-controller-protected-oracle.yml"
PREFIX = "          python3 - <<'PY'\n"
SUFFIX = "\n          PY"
REPO = "olivesoup/jm-public-cas-controller"
BASE = "8" * 40
HEAD = "9" * 40


def oracle_source():
    text = SOURCE.read_text(encoding="utf-8")
    assert text.count(PREFIX) == 1, "Oracle Python start must be unique"
    content = text.split(PREFIX, 1)[1].split(SUFFIX, 1)[0]
    assert content, "Oracle Python source empty"
    return textwrap.dedent(content) + "\n"


class JsonResponse(io.BytesIO):
    status = 200

    def __init__(self, value):
        super().__init__(json.dumps(value).encode("utf-8"))


class OracleContract(unittest.TestCase):
    def setUp(self):
        self.event = {"number": 9, "pull_request": {
            "head": {"sha": HEAD}, "base": {"sha": BASE}}}
        self.pr = {
            "number": 9, "state": "open", "draft": False,
            "head": {"sha": HEAD, "repo": {"full_name": REPO}},
            "base": {"sha": BASE, "ref": "master", "repo": {"full_name": REPO}},
        }
        self.branch = {"protected": True, "commit": {"sha": BASE}}
        self.files = [{"filename": "README.md", "status": "modified"}]

    def execute(self, env_overrides=None):
        script = oracle_source()
        compiled = compile(script, str(SOURCE), "exec")
        with tempfile.TemporaryDirectory() as directory:
            event_file = Path(directory) / "event.json"
            event_file.write_text(json.dumps(self.event), encoding="utf-8")
            env = {
                "GITHUB_REPOSITORY": REPO,
                "GITHUB_EVENT_NAME": "pull_request_target",
                "GITHUB_EVENT_PATH": str(event_file),
                "GITHUB_SHA": BASE,
                "GH_TOKEN": "FAKE_LOCAL_TEST_ONLY_TOKEN",
            }
            env.update(env_overrides or {})

            def fake_urlopen(request, timeout=None):
                url = request.full_url
                if not url.startswith("https://api.github.com/repos/" + REPO):
                    raise AssertionError("Oracle API endpoint changed")
                if request.get_header("Authorization") != "Bearer " + env["GH_TOKEN"]:
                    raise AssertionError("Oracle API auth header invalid")
                path = url.split("/repos/" + REPO, 1)[1]
                if path == "/pulls/9":
                    return JsonResponse(self.pr)
                if path == "/branches/master":
                    return JsonResponse(self.branch)
                if path.startswith("/pulls/9/files?per_page=100&page="):
                    page = int(path.rsplit("=", 1)[1])
                    return JsonResponse(self.files if page == 1 else [])
                raise AssertionError("Unknown Oracle GitHub GET path: " + path)

            output = io.StringIO()
            with mock.patch.dict(os.environ, env), \
                 mock.patch.object(urllib.request, "urlopen", side_effect=fake_urlopen), \
                 contextlib.redirect_stdout(output):
                exec(compiled, {"__name__": "__main__"})
            return output.getvalue()

    def deny(self, message, env_overrides=None):
        with self.assertRaises(SystemExit) as ctx:
            self.execute(env_overrides)
        self.assertIn(message, str(ctx.exception))

    def test_embedded_python_compiles(self):
        compile(oracle_source(), str(SOURCE), "exec")

    def test_allowed_document_path(self):
        self.assertIn("SOURCE_SCOPE_PASS_NOT_CAS_REAL_GATE", self.execute())

    def test_allowed_cas_source_update(self):
        self.files = [{"filename": "scripts/OwnerSafeOp.ps1", "status": "modified"}]
        self.assertIn("SOURCE_SCOPE_PASS_NOT_CAS_REAL_GATE", self.execute())

    def test_protected_workflow_changed_is_denied(self):
        self.files = [{"filename": ".github/workflows/injected.yml", "status": "modified"}]
        self.deny("PROTECTED_OR_UNLISTED_PATH")

    def test_rename_from_protected_workflow_is_denied(self):
        self.files = [{"filename": "scripts/op.ps1",
                       "previous_filename": ".github/workflows/previous.yml",
                       "status": "renamed"}]
        self.deny("PROTECTED_OR_UNLISTED_PATH")

    def test_unprotected_master_is_denied(self):
        self.branch["protected"] = False
        self.deny("EXACT_HEAD_BASE_IDENTITY")

    def test_head_drift_is_denied(self):
        self.pr["head"]["sha"] = "1" * 40
        self.deny("EXACT_HEAD_BASE_IDENTITY")

    def test_base_drift_is_denied(self):
        self.pr["base"]["sha"] = "1" * 40
        self.deny("EXACT_HEAD_BASE_IDENTITY")

    def test_fork_is_denied(self):
        self.pr["head"]["repo"]["full_name"] = "attacker/sandbox"
        self.deny("EXACT_HEAD_BASE_IDENTITY")

    def test_draft_is_denied(self):
        self.pr["draft"] = True
        self.deny("EXACT_HEAD_BASE_IDENTITY")

    def test_empty_diff_is_denied(self):
        self.files = []
        self.deny("EMPTY_CHANGE")

    def test_missing_api_token_is_denied(self):
        self.deny("NO_READ_TOKEN", {"GH_TOKEN": ""})

    def test_unexpected_event_is_denied(self):
        self.deny("WRONG_EVENT", {"GITHUB_EVENT_NAME": "pull_request"})


if __name__ == "__main__":
    unittest.main()
