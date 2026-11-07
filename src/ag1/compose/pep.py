"""An AG-1 reference enforcement point as its own service.

It runs the same `EnforcementPoint` as in-process mode, with its own evidence key,
its own audience and origin configuration, and the services it fronts reached over
the network: Forgejo with the admin token, the test service, and the staging sink.
"""

from __future__ import annotations

import threading

from .. import report
from ..gateway import EnforcementPoint, Request
from .http import call
from .wire import decision_to_json, request_from_json, unb64


class ComposeService:
    """Forgejo for repositories and pull requests; tests and deployments in their own services."""

    def __init__(self, forge, test_url: str, sink_url: str) -> None:
        self.forge = forge
        self.test_url = test_url
        self.sink_url = sink_url
        self.description = f"{forge.description} with a separate test service and staging sink"
        self.responsibility = (f"{forge.description} for repositories and pull requests, through its API with an "
                               "admin token; pytest suites run by the test service with a read-only token; "
                               "deployments recorded by a staging sink")
        self.deployments: list[dict] = []
        self.test_runs: list[dict] = []

    def canonical_repo(self, name):
        return self.forge.canonical_repo(name)

    def resolve_ref(self, repo, ref):
        return self.forge.resolve_ref(repo, ref)

    def resolve_symlinks(self, repo, path, ref=None):
        return self.forge.resolve_symlinks(repo, path, ref)

    def execute(self, tool: str, args: dict) -> str:
        if tool == "test.run":
            run = call(f"{self.test_url}/run", {k: args[k] for k in ("repo", "branch", "suite")})
            return f"ran {args['suite']} tests on {args['branch']}: {run['summary']}"
        if tool in ("deploy.staging", "deploy.production"):
            call(f"{self.sink_url}/deploy", {"tool": tool, "artifact": args["artifact"]})
            return f"{tool} {args['artifact']}"
        return self.forge.execute(tool, args)

    def head(self, repo, branch):
        return self.forge.head(repo, branch)

    def file(self, repo, branch, path):
        return self.forge.file(repo, branch, path)

    def pull_requests(self):
        return self.forge.pull_requests()


def routes(gateway: EnforcementPoint, trusted_root: str) -> dict:
    lock = threading.Lock()  # one decision at a time keeps the evidence chain in order
    adapter = gateway.adapter

    def handle(body):
        try:
            req = request_from_json(adapter, body)
        except Exception as exc:  # undecodable: a refusal with a record, not a server error
            req = Request(str(body.get("actor", "")), [], str(body.get("tool", "")), {}, None,
                          intent=str(body.get("intent", "")))
            with lock:
                return decision_to_json(gateway.refuse(req, f"MalformedRequest: {type(exc).__name__}"))
        with lock:
            return decision_to_json(gateway.handle(req))

    def revocations(body):
        with lock:
            gateway.verifier.apply_revocation(unb64(body["list"]))
        return {"ok": True}

    def evidence(_):
        with lock:
            return report.bundle(gateway, adapter, trusted_root, gateway.scm)

    return {
        "GET /health": lambda _: {"ok": True},
        "GET /anchors": lambda _: {"trusted_root": trusted_root, "evidence_key": gateway.evidence_public_key_hex},
        "GET /evidence": evidence,
        "POST /handle": handle,
        "POST /revocations": revocations,
    }
