"""Runs a repository's pytest suite at a branch, with a read-only token.

Its network reaches Forgejo and nothing else. The suite name was authorized by the
enforcement point; it is checked again here before it becomes part of a path.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading

from .http import Rejected

_NAME = re.compile(r"[a-z][a-z0-9_-]*")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")


def routes(forge_url: str, token: str) -> dict:
    lock = threading.Lock()
    runs: list[dict] = []

    def run(body):
        repo, branch, suite = body["repo"], body["branch"], body["suite"]
        if not (_REPO.fullmatch(repo) and _NAME.fullmatch(suite)) or branch.startswith("-"):
            raise Rejected("unexpected repository, branch or suite name")
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "GIT_TERMINAL_PROMPT": "0",
                   "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                   "GIT_CONFIG_VALUE_0": f"Authorization: token {token}"}
            clone = subprocess.run(["git", "clone", "-q", "--depth", "1", "-b", branch,
                                    f"{forge_url}/{repo}.git", "src"],
                                   cwd=tmp, env=env, capture_output=True, text=True, timeout=120)
            if clone.returncode != 0:
                result = {"passed": False, "summary": "checkout failed"}
            else:
                # The suite runs without the token in its environment.
                test_env = {"PATH": env["PATH"], "HOME": tmp, "PYTHONDONTWRITEBYTECODE": "1"}
                done = subprocess.run(["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", f"tests/{suite}"],
                                      cwd=f"{tmp}/src", env=test_env, capture_output=True, text=True, timeout=300)
                lines = [line for line in done.stdout.splitlines() if line.strip()]
                result = {"passed": done.returncode == 0, "summary": lines[-1] if lines else f"exit {done.returncode}"}
        record = {"repo": repo, "branch": branch, "suite": suite, **result}
        with lock:
            runs.append(record)
        return record

    return {
        "GET /health": lambda _: {"ok": True},
        "GET /runs": lambda _: {"runs": list(runs)},
        "POST /run": run,
    }
