"""Holds the private keys of one deployment's parties; every signature is made here.

Other services know these parties only by public identifier. A delegation names the
child by public key, the parent's holder signs it here, and requests are sent to
enforcement points from here, so each agent's traffic leaves its own container.
"""

from __future__ import annotations

import threading
import time

from ..spec import ApprovalGate, DelegationRejected
from .http import Rejected, call
from .wire import b64, caps_from_json, party, unb64


def routes(adapter, identities: list[tuple[str, str]], peps: dict[str, str]) -> dict:
    """`identities`: (name, trust domain) of the parties this deployment keeps for its whole life."""
    lock = threading.Lock()
    stable = {name: adapter.new_principal(name, domain) for name, domain in identities}
    held = {p.public_id: p for p in stable.values()}
    revoked: dict[str, list] = {}  # signer -> grants revoked so far (a revocation list is cumulative)
    versions: dict[str, int] = {}

    def signer(public_id: str):
        p = held.get(public_id)
        if p is None:
            raise Rejected("that key is not held by this service")
        return p

    def public(data: dict):
        return adapter.public_principal(data["name"], data["public_id"], data.get("trust_domain", "local"))

    def new_principal(body):
        name = body["name"]
        if name in stable:
            return party(stable[name])
        p = adapter.new_principal(name, body.get("trust_domain", "local"))
        with lock:
            held[p.public_id] = p
        return party(p)

    def issue(body):
        gate = body.get("gate")
        if gate:
            gate = ApprovalGate(tuple(gate["tools"]), [public(a) for a in gate["approvers"]], gate["threshold"])
        grant = adapter.issue(signer(body["signer"]), public(body["holder"]), caps_from_json(body["caps"]),
                              body["ttl"], task=body.get("task"), gate=gate)
        return {"grant": b64(adapter.to_bytes(grant))}

    def delegate(body):
        try:
            grant = adapter.delegate(adapter.from_bytes(unb64(body["parent"])), signer(body["signer"]),
                                     public(body["child"]), caps_from_json(body["caps"]), body["ttl"],
                                     terminal=body.get("terminal", False))
        except DelegationRejected as exc:
            raise Rejected(str(exc)) from exc
        return {"grant": b64(adapter.to_bytes(grant))}

    def prove(body):
        chain = adapter.decode_chain(body["chain"]) if body.get("chain") else []
        proof = adapter.prove(chain, signer(body["holder"]), body["tool"], body["args"])
        return {"proof": b64(adapter.proof_to_bytes(proof))}

    def approve(body):
        approval = adapter.approve(signer(body["approver"]), adapter.from_bytes(unb64(body["grant"])),
                                   public(body["holder"]), body["tool"], body["args"], ttl=body.get("ttl"))
        return {"approval": b64(adapter.approval_to_bytes(approval))}

    def revoke(body):
        issuer = signer(body["signer"])
        with lock:
            grants = revoked.setdefault(issuer.public_id, [])
            grants.extend(adapter.from_bytes(unb64(g)) for g in body["grants"])
            versions[issuer.public_id] = versions.get(issuer.public_id, 0) + 1
            data = adapter.revocation(issuer, grants, versions[issuer.public_id])
        t0 = time.perf_counter()
        for url in peps.values():
            call(f"{url}/revocations", {"list": b64(data)})
        return {"ms": (time.perf_counter() - t0) * 1000, "enforcement_points": len(peps)}

    def send(body):
        url = peps.get(body["pep"])
        if url is None:
            raise Rejected(f"unknown enforcement point {body['pep']!r}")
        return call(f"{url}/handle", body["request"])

    return {
        "GET /health": lambda _: {"ok": True},
        "GET /identities": lambda _: {"identities": [party(p) for p in stable.values()]},
        "POST /principals": new_principal,
        "POST /issue": issue,
        "POST /delegate": delegate,
        "POST /prove": prove,
        "POST /approve": approve,
        "POST /revoke": revoke,
        "POST /send": send,
    }
