"""A real Forgejo instance as the SCM service behind the enforcement point.

The enforcement point talks to Forgejo's API with an admin token, the broad
ambient credential AG-1.10 is about, and the service account is on the push
allowlist of the protected `main` branch, as bot accounts usually are.

Normalization asks Forgejo itself: repository names, the default branch
behind `HEAD`, and symbolic links are resolved from the repository, not from
a copy of the seed. After every write the file is read back at the canonical
path, so a forge that stored it somewhere else would be noticed.

Each `ForgejoSCM` deletes and recreates the seed repositories, so every world
starts from the same state. Test runs and deployments are recorded by the
harness in this mode.
"""

from __future__ import annotations

import base64
import json
import posixpath
import re
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .scm import SEED, ServiceError, link_target

_REPO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
MAX_SYMLINK_HOPS = 8


class ForgejoSCM:
    def __init__(self, url: str, token: str) -> None:
        self.url = url.rstrip("/")
        self._token = token
        self.version = self._api("GET", "/version")["version"]
        self.description = f"Forgejo {self.version}"
        self.responsibility = (f"{self.description} for repositories and pull requests, through its API with an "
                               "admin token; test runs and deployments recorded by the AG-1 harness")
        self.service_user = self._api("GET", "/user")["login"]
        self.deployments: list[dict] = []
        self.test_runs: list[dict] = []
        self._reset()

    # HTTP

    def _api(self, method: str, path: str, body: dict | None = None, missing_ok: bool = False):
        data = json.dumps(body).encode() if body is not None else None
        req = Request(f"{self.url}/api/v1{path}", data=data, method=method,
                      headers={"Authorization": f"token {self._token}", "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except HTTPError as exc:
            if missing_ok and exc.code == 404:
                return None
            raise ServiceError(f"Forgejo {method} {path}: {exc.code} {exc.read()[:200]!r}") from exc
        return json.loads(raw) if raw else None

    @staticmethod
    def _path(path: str) -> str:
        return quote(path.lstrip("/"))

    def _contents(self, repo: str, path: str, ref: str):
        return self._api("GET", f"/repos/{repo}/contents/{self._path(path)}?ref={quote(ref, safe='')}",
                         missing_ok=True)

    # Seeding

    def _reset(self) -> None:
        for repo in SEED:
            owner, name = repo.split("/")
            self._api("DELETE", f"/repos/{repo}", missing_ok=True)
            if self._api("GET", f"/orgs/{owner}", missing_ok=True) is None:
                self._api("POST", "/orgs", {"username": owner})
            self._api("POST", f"/orgs/{owner}/repos", {"name": name, "default_branch": SEED[repo]["default_branch"]})
            self._push_seed(repo)
            self._api("POST", f"/repos/{repo}/branch_protections", {
                "rule_name": SEED[repo]["default_branch"],
                "enable_push": True,
                "enable_push_whitelist": True,
                "push_whitelist_usernames": [self.service_user],
                "required_approvals": 1,
            })
        self._wait_ready()

    def _push_seed(self, repo: str) -> None:
        spec = SEED[repo]
        default = spec["default_branch"]
        order = [default] + [b for b in spec["branches"] if b != default]
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)

            def git(*args: str) -> None:
                subprocess.run(["git", "-c", "user.name=ag1-seed", "-c", "user.email=seed@ag1.invalid",
                                "-c", "commit.gpgsign=false", *args],
                               cwd=work, check=True, capture_output=True)

            git("init", "-q", "-b", default)
            for branch in order:
                if branch != default:
                    git("checkout", "-q", "-B", branch, default)
                    git("rm", "-rq", "--ignore-unmatch", ".")
                for path, content in spec["branches"][branch].items():
                    target = work / path.lstrip("/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content)
                for link, rel in spec["symlinks"].items():
                    target = work / link.lstrip("/")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(rel)
                git("add", "-A")
                git("commit", "-q", "--allow-empty", "-m", f"seed {branch}")
            git("-c", f"http.extraHeader=Authorization: token {self._token}",
                "push", "-q", f"{self.url}/{repo}.git", *order)

    def _wait_ready(self, timeout: float = 30) -> None:
        deadline = time.monotonic() + timeout
        # Right after a push Forgejo still treats the repository as empty and lists
        # every path as an empty directory, so wait until each seeded file is served.
        for repo, spec in SEED.items():
            for branch, files in spec["branches"].items():
                for path in files:
                    while not isinstance(self._contents(repo, path, branch), dict):
                        if time.monotonic() > deadline:
                            raise ServiceError(f"Forgejo did not serve {repo}@{branch}:{path} after seeding")
                        time.sleep(0.2)

    # Canonical-form helpers used by the enforcement point

    def canonical_repo(self, name: str) -> str:
        # Anything Forgejo might rewrite (a .git suffix, other characters) is left
        # as given, so it cannot match a grant: refuse rather than guess.
        if not _REPO_NAME.fullmatch(name) or name.lower().endswith(".git"):
            return name
        found = self._api("GET", f"/repos/{name}", missing_ok=True)
        return found["full_name"] if found else name.lower()

    def resolve_ref(self, repo: str, ref: str) -> str:
        if ref.startswith("refs/heads/"):
            ref = ref[len("refs/heads/"):]
        if ref == "HEAD":
            found = self._api("GET", f"/repos/{repo}", missing_ok=True) if _REPO_NAME.fullmatch(repo) else None
            if found:
                return found["default_branch"]
        return ref

    def resolve_symlinks(self, repo: str, path: str, ref: str | None = None) -> str:
        if not _REPO_NAME.fullmatch(repo):
            return path
        if ref is None:
            ref = self.resolve_ref(repo, "HEAD")
        parts = [p for p in path.split("/") if p]
        resolved, i, hops = "", 0, 0
        while i < len(parts):
            candidate = f"{resolved}/{parts[i]}"
            entry = self._contents(repo, candidate, ref)
            if entry is None:  # does not exist yet: the rest is taken literally
                return posixpath.join(candidate, *parts[i + 1:])
            if isinstance(entry, dict) and entry.get("type") == "symlink":
                hops += 1
                if hops > MAX_SYMLINK_HOPS:
                    raise ServiceError(f"too many symbolic links resolving {path}")
                parts = [p for p in link_target(candidate, entry["target"]).split("/") if p] + parts[i + 1:]
                resolved, i = "", 0
                continue
            resolved, i = candidate, i + 1
        return resolved or "/"

    # Operations, executed with the service's admin token

    def execute(self, tool: str, args: dict) -> str:
        if tool == "repo.read":
            self._api("GET", f"/repos/{args['repo']}")
            return f"read {args['repo']}"
        if tool == "repo.write":
            return self._write(args["repo"], args["branch"], args["path"], args.get("content", ""))
        if tool == "pr.create":
            pr = self._api("POST", f"/repos/{args['repo']}/pulls",
                           {"head": args["head"], "base": args["base"], "title": f"Merge {args['head']}"})
            return f"opened PR #{pr['number']} {args['head']} -> {args['base']}"
        if tool == "test.run":
            self.test_runs.append(dict(args))
            return f"ran {args['suite']} tests on {args['branch']}"
        if tool in ("deploy.staging", "deploy.production"):
            self.deployments.append({"tool": tool, **args})
            return f"{tool} {args['artifact']}"
        raise KeyError(tool)

    def _write(self, repo: str, branch: str, path: str, content: str) -> str:
        existing = self._contents(repo, path, branch)
        body = {"branch": branch, "message": f"ag1: update {path}",
                "content": base64.b64encode(content.encode()).decode()}
        if isinstance(existing, dict):
            body["sha"] = existing["sha"]
            self._api("PUT", f"/repos/{repo}/contents/{self._path(path)}", body)
        else:
            self._api("POST", f"/repos/{repo}/contents/{self._path(path)}", body)
        if self.file(repo, branch, path) != content:
            raise ServiceError(f"Forgejo did not store the write at the canonical path {path}")
        return f"wrote {repo}@{branch}:{path}"

    # State

    def head(self, repo: str, branch: str) -> str:
        found = self._api("GET", f"/repos/{repo}/branches/{quote(branch, safe='')}", missing_ok=True)
        return found["commit"]["id"] if found else ""

    def file(self, repo: str, branch: str, path: str) -> str | None:
        entry = self._contents(repo, path, branch)
        if not isinstance(entry, dict) or entry.get("type") != "file":
            return None
        return base64.b64decode(entry["content"]).decode()

    def pull_requests(self) -> list[dict]:
        out = []
        for repo in SEED:
            for pr in self._api("GET", f"/repos/{repo}/pulls?state=all") or []:
                out.append({"repo": repo, "number": pr["number"], "head": pr["head"]["ref"], "base": pr["base"]["ref"]})
        return out
