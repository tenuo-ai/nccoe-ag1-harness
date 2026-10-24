"""The steps' view of a compose deployment.

`RemoteAdapter` presents the usual adapter interface, but every signature is made by
the key holder that holds the signer's key; the driver holds grants, proofs and
approvals (what an observer of the traffic could hold) and no private keys.
`RemoteGateway` sends each request from the presenting party's own container to an
enforcement point, and reads that enforcement point's evidence back.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..scenario import CONTROL_DOMAIN, DEVELOPMENT_DOMAIN, TEST_DOMAIN
from ..spec import DelegationRejected
from .http import RemoteError, call
from .pep import ComposeService
from .wire import b64, caps_to_json, decision_from_json, gate_to_json, party, request_to_json, unb64

# Which key holder keeps a party's key. Anything else (other workloads, untrusted
# issuers, someone who is not an approver) belongs to the thief.
PLACEMENT = {
    "task-authorization-system": "issuer",
    "release-manager": "approver",
    "orchestrator": "orchestrator",
    "concurrent-reader": "orchestrator",
    "patch-agent": "patch-agent",
    "test-runner": "test-runner",
    "remote-test-runner": "test-runner",
    "short-lived-runner": "test-runner",
    "release-agent": "release-agent",
}
THIEF = "thief"
PEPS = {"gateway": "main", "receiving": "receiving", "other_service": "other-service", "baseline": "baseline"}


@dataclass
class RemotePrincipal:
    name: str
    trust_domain: str
    public_id: str
    host: str  # base URL of the key holder that keeps the private key


class RemoteAdapter:
    def __init__(self, inner, keyholders: dict[str, str]) -> None:
        self.inner = inner
        self.keyholders = keyholders
        self.name = inner.name
        self.version = inner.version
        self.capabilities = inner.capabilities

    def __getattr__(self, attr):  # encoding, inspection and verification stay local
        return getattr(self.inner, attr)

    def host_for(self, name: str) -> str:
        return self.keyholders[PLACEMENT.get(name, THIEF)]

    def new_principal(self, name: str, trust_domain: str = "local") -> RemotePrincipal:
        found = call(f"{self.host_for(name)}/principals", {"name": name, "trust_domain": trust_domain})
        # Only so evidence written here can label it; enforcement points keep their own labels.
        self.inner.public_principal(name, found["public_id"], found["trust_domain"])
        return RemotePrincipal(name, found["trust_domain"], found["public_id"], self.host_for(name))

    def _grant(self, url: str, body: dict):
        return self.inner.from_bytes(unb64(call(url, body)["grant"]))

    def issue(self, issuer, holder, caps, ttl, task=None, gate=None):
        return self._grant(f"{issuer.host}/issue", {"signer": issuer.public_id, "holder": party(holder),
                                                    "caps": caps_to_json(caps), "ttl": ttl, "task": task,
                                                    "gate": gate_to_json(gate)})

    def delegate(self, parent, parent_holder, child, caps, ttl, terminal=False):
        try:
            return self._grant(f"{parent_holder.host}/delegate", {
                "signer": parent_holder.public_id, "parent": b64(self.inner.to_bytes(parent)),
                "child": party(child), "caps": caps_to_json(caps), "ttl": ttl, "terminal": terminal})
        except RemoteError as exc:
            if exc.status == 409:
                raise DelegationRejected(exc.body.get("error", "")) from None
            raise

    def prove(self, chain, holder, tool, args):
        found = call(f"{holder.host}/prove", {"holder": holder.public_id, "tool": tool, "args": args,
                                              "chain": self.inner.encode_chain(chain) if chain else None})
        return self.inner.proof_from_bytes(unb64(found["proof"]))

    def approve(self, approver, grant, holder, tool, args, ttl=None):
        found = call(f"{approver.host}/approve", {"approver": approver.public_id,
                                                  "grant": b64(self.inner.to_bytes(grant)),
                                                  "holder": party(holder), "tool": tool, "args": args, "ttl": ttl})
        return self.inner.approval_from_bytes(unb64(found["approval"]))

    def verifier(self, trusted_root):
        return self.inner.verifier(getattr(trusted_root, "public_id", trusted_root))


class RemoteGateway:
    def __init__(self, name: str, url: str, adapter: RemoteAdapter) -> None:
        self.name = name
        self.url = url
        self.adapter = adapter

    def handle(self, req):
        host = self.adapter.host_for(req.actor)
        found = call(f"{host}/send", {"pep": self.name, "request": request_to_json(self.adapter.inner, req)})
        return decision_from_json(found)

    def bundle(self) -> dict:
        return call(f"{self.url}/evidence")

    @property
    def evidence(self) -> list[dict]:
        return self.bundle()["records"]

    @cached_property
    def evidence_public_key_hex(self) -> str:
        return call(f"{self.url}/anchors")["evidence_key"]

    @property
    def evidence_public_key(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.evidence_public_key_hex))


class ComposeObserver:
    """What the steps check afterwards: Forgejo read with the driver's own admin token, and
    the test service's and sink's records since this world was built."""

    def __init__(self, forge, test_url: str, sink_url: str) -> None:
        self.forge = forge
        self.test_url = test_url
        self.sink_url = sink_url
        described = ComposeService(forge, test_url, sink_url)
        self.description = described.description
        self.responsibility = described.responsibility
        self._deployments_from = len(call(f"{sink_url}/deployments")["deployments"])
        self._runs_from = len(call(f"{test_url}/runs")["runs"])

    @property
    def deployments(self) -> list[dict]:
        return call(f"{self.sink_url}/deployments")["deployments"][self._deployments_from:]

    @property
    def test_runs(self) -> list[dict]:
        return call(f"{self.test_url}/runs")["runs"][self._runs_from:]

    def __getattr__(self, attr):
        return getattr(self.forge, attr)


@dataclass
class ComposeConfig:
    keyholders: dict[str, str]
    peps: dict[str, str]
    test_url: str
    sink_url: str
    forge: object  # a callable returning a fresh service view, reset to the seed


def deployment(config: ComposeConfig):
    """A `scenario.use_deployment` factory for the services in `config`."""

    def build(adapter) -> dict:
        remote = RemoteAdapter(adapter, config.keyholders)
        p = remote.new_principal
        parties = {
            "issuer": p("task-authorization-system", CONTROL_DOMAIN),
            "approver": p("release-manager", CONTROL_DOMAIN),
            "orchestrator": p("orchestrator", DEVELOPMENT_DOMAIN),
            "patch": p("patch-agent", DEVELOPMENT_DOMAIN),
            "runner": p("test-runner", TEST_DOMAIN),
            "release": p("release-agent", DEVELOPMENT_DOMAIN),
        }
        scm = ComposeObserver(config.forge(), config.test_url, config.sink_url)
        gateways = {key: RemoteGateway(name, config.peps[name], remote) for key, name in PEPS.items()}
        issuer = parties["issuer"]

        def revoke(grants: list) -> dict:
            return call(f"{issuer.host}/revoke", {"signer": issuer.public_id,
                                                  "grants": [b64(adapter.to_bytes(g)) for g in grants]})

        return {**parties, "adapter": remote, "scm": scm, **gateways, "revoke": revoke, "deployment": "compose"}

    return build
