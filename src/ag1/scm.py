"""In-memory stand-in for an SCM and CI/CD service.

The service holds a broad credential of its own (it can write any branch of
any repository and deploy anywhere). That is deliberate: AG-1.10 checks that
the service acts on the authority an agent presents, not on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Repo:
    default_branch: str
    branches: dict[str, dict[str, str]]
    # Symbolic links inside the repository: link path -> target path.
    symlinks: dict[str, str] = field(default_factory=dict)


class MockSCM:
    SERVICE_CREDENTIAL = "scm-service-admin"  # broad, ambient authority

    def __init__(self) -> None:
        self.repos: dict[str, Repo] = {
            "org/repo-a": Repo(
                default_branch="main",
                branches={
                    "main": {
                        "/src/parser/lexer.c": "/* vulnerable lexer */",
                        "/.github/workflows/release.yml": "name: release",
                    },
                    "fix/cve-2026-1234": {
                        "/src/parser/lexer.c": "/* vulnerable lexer */",
                        "/.github/workflows/release.yml": "name: release",
                    },
                },
                symlinks={"/src/parser/ci": "/.github/workflows"},
            ),
            "org/repo-b": Repo(
                default_branch="main",
                branches={"main": {"/README.md": "repo b"}},
            ),
        }
        self.pull_requests: list[dict] = []
        self.deployments: list[dict] = []
        self.test_runs: list[dict] = []

    # Canonical-form helpers used by the enforcement point.
    def canonical_repo(self, name: str) -> str:
        lowered = name.strip().lower()
        for repo in self.repos:
            if repo.lower() == lowered:
                return repo
        return lowered

    def resolve_ref(self, repo: str, ref: str) -> str:
        r = self.repos.get(repo)
        if ref.startswith("refs/heads/"):
            ref = ref[len("refs/heads/"):]
        if ref == "HEAD" and r is not None:
            return r.default_branch
        return ref

    def resolve_symlinks(self, repo: str, path: str) -> str:
        r = self.repos.get(repo)
        if r is None:
            return path
        for link, target in r.symlinks.items():
            if path == link or path.startswith(link + "/"):
                return target + path[len(link):]
        return path

    # Operations, executed with the service's own credential.
    def execute(self, tool: str, args: dict) -> str:
        if tool == "repo.read":
            return f"read {args['repo']}"
        if tool == "repo.write":
            branch = self.repos[args["repo"]].branches.setdefault(args["branch"], {})
            branch[args["path"]] = args.get("content", "")
            return f"wrote {args['repo']}@{args['branch']}:{args['path']}"
        if tool == "pr.create":
            self.pull_requests.append(dict(args))
            return f"opened PR {args['head']} -> {args['base']}"
        if tool == "test.run":
            self.test_runs.append(dict(args))
            return f"ran {args['suite']} tests on {args['branch']}"
        if tool in ("deploy.staging", "deploy.production"):
            self.deployments.append({"tool": tool, **args})
            return f"{tool} {args['artifact']}"
        raise KeyError(tool)
