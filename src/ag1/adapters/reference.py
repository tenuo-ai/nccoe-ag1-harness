"""A small AG-1 adapter written from ADAPTERS.md, with no dependency beyond `cryptography`.

Grants are JSON objects signed with Ed25519, and each link carries the hash of its parent.
It is a readable example of the adapter contract and the default for a first run. It is not
an authorization implementation to deploy: it has no key management, no persistent replay or
revocation state, and no remote operation, so compose mode needs another adapter.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .. import spec

PROOF_WINDOW_SECS = 60


def canon(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _constraint(c) -> list:
    if isinstance(c, spec.Exact):
        return ["exact", c.value]
    if isinstance(c, spec.OneOf):
        return ["one_of", list(c.values)]
    if isinstance(c, spec.Under):
        return ["under", c.root]
    return ["any"]


def _matches(c: list, value) -> bool:
    kind = c[0]
    if kind == "any":
        return True
    if kind == "exact":
        return value == c[1]
    if kind == "one_of":
        return value in c[1]
    return isinstance(value, str) and (value == c[1] or value.startswith(c[1].rstrip("/") + "/"))


def _within(parent: list, child: list) -> bool:
    if parent[0] == "any":
        return True
    if child[0] == "any":
        return False
    if parent[0] == "exact":
        return child == parent
    if parent[0] == "one_of":
        values = child[1] if child[0] == "one_of" else [child[1]]
        return child[0] in ("exact", "one_of") and set(values) <= set(parent[1])
    return child[0] in ("exact", "under") and _matches(parent, child[1])


def _verify_signature(public_id: str, signature: str, data: bytes) -> None:
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_id)).verify(bytes.fromhex(signature), data)


@dataclass
class Key:
    name: str
    key: Ed25519PrivateKey
    trust_domain: str = "local"

    @property
    def public_id(self) -> str:
        return self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


@dataclass
class Grant:
    payload: dict
    signature: str

    @property
    def body(self) -> bytes:
        return canon(self.payload)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


class Verifier:
    def __init__(self, root) -> None:
        self.root = getattr(root, "public_id", root)
        self.revoked: set[str] = set()
        self.seen_proofs: set[bytes] = set()
        self.used_approvals: set[str] = set()

    def check_link(self, parent: Grant, link: Grant) -> None:
        """What a link must satisfy beyond its signature and its parent's hash."""
        above, this = parent.payload, link.payload
        if this["issuer"] != above["holder"] or above["terminal"]:
            raise spec.Denied("ChainError: link not signed by the parent's holder, or parent is terminal")
        if this["expires"] > above["expires"]:
            raise spec.Denied("ChainError: link outlives its parent")
        for tool, args in this["caps"].items():
            parent_args = above["caps"].get(tool)
            if parent_args is None or set(args) != set(parent_args):
                raise spec.Denied(f"Widened: {tool}")
            if not all(_within(parent_args[name], args[name]) for name in args):
                raise spec.Denied(f"Widened: {tool}")

    def verify_chain(self, chain, *, as_of=None) -> None:
        now = time.time() if as_of is None else as_of
        if not chain:
            raise spec.Denied("EmptyChain")
        previous = None
        for link in chain:
            p = link.payload
            try:
                _verify_signature(p["issuer"], link.signature, link.body)
            except Exception as exc:
                raise spec.Denied("SignatureInvalid: link") from exc
            if previous is None:
                if p["issuer"] != self.root or p["parent"] is not None:
                    raise spec.Denied("UntrustedRoot")
            else:
                if p["parent"] != previous.digest:
                    raise spec.Denied("ChainError: parent hash")
                self.check_link(previous, link)
            if now >= p["expires"]:
                raise spec.Denied("Expired")
            if p["id"] in self.revoked:
                raise spec.Denied("Revoked")
            previous = link

    def authorize(self, chain, tool, signed_args, constraint_args, proof, approvals) -> None:
        self.verify_chain(chain)
        leaf = chain[-1].payload
        if proof is None:
            raise spec.Denied("MissingSignature")
        if proof in self.seen_proofs:
            raise spec.Denied("Replay")
        try:
            at = int(proof[:10])
            _verify_signature(leaf["holder"], proof[10:].decode(), canon([leaf["id"], tool, signed_args, at]))
        except Exception as exc:
            raise spec.Denied("SignatureInvalid: proof") from exc
        if abs(time.time() - at) > PROOF_WINDOW_SECS:
            raise spec.Denied("StaleProof")
        caps = leaf["caps"].get(tool)
        if caps is None:
            raise spec.Denied("ToolNotAuthorized")
        if set(constraint_args) != set(caps) or not all(_matches(caps[k], constraint_args[k]) for k in caps):
            raise spec.Denied("ConstraintViolation")
        used = self._check_approvals(chain[0].payload["gate"], leaf, tool, signed_args, approvals)
        self.seen_proofs.add(proof)
        self.used_approvals.update(used)

    def _check_approvals(self, gate, leaf, tool, signed_args, approvals) -> list[str]:
        if not gate or tool not in gate["tools"]:
            return []
        wanted = hashlib.sha256(canon([leaf["id"], tool, signed_args, leaf["holder"]])).hexdigest()
        for approval in approvals or []:
            body = json.loads(approval["body"])
            if body["nonce"] in self.used_approvals:
                raise spec.Denied("ApprovalReuse")
            if body["approver"] not in gate["approvers"] or body["request"] != wanted or time.time() >= body["expires"]:
                continue
            try:
                _verify_signature(body["approver"], approval["signature"], approval["body"].encode())
            except Exception:
                continue
            return [body["nonce"]]
        raise spec.Denied("InvalidApproval" if approvals else "ApprovalGateTriggered")

    def install_revocation(self, issuer, grants) -> None:
        if issuer.public_id != self.root:
            raise spec.Denied("untrusted revocation issuer")
        self.revoked.update(g.payload["id"] for g in grants)


class ReferenceAdapter:
    name = "reference"
    version = "1"
    capabilities = spec.AdapterCapabilities("holder_signed", "offline_chain", "structured_signed")
    verifier_class = Verifier

    def new_principal(self, name, trust_domain="local"):
        return Key(name, Ed25519PrivateKey.generate(), trust_domain)

    def _sign(self, signer, holder, caps, ttl, parent=None, task=None, gate=None, terminal=False) -> Grant:
        payload = {
            "id": uuid.uuid4().hex, "issuer": signer.public_id, "holder": holder.public_id,
            "expires": time.time() + ttl, "task": task, "terminal": terminal,
            "parent": parent.digest if parent else None,
            "caps": {tool: {k: _constraint(c) for k, c in args.items()} for tool, args in caps.items()},
            "gate": {"tools": list(gate.tools), "approvers": [p.public_id for p in gate.approvers]} if gate else None,
        }
        return Grant(payload, signer.key.sign(canon(payload)).hex())

    def issue(self, issuer, holder, caps, ttl, task=None, gate=None):
        return self._sign(issuer, holder, caps, ttl, task=task, gate=gate)

    def delegate(self, parent, parent_holder, child, caps, ttl, terminal=False):
        grant = self._sign(parent_holder, child, caps, ttl, parent=parent, task=parent.payload["task"], terminal=terminal)
        try:
            Verifier(None).check_link(parent, grant)
        except spec.Denied as exc:
            raise spec.DelegationRejected(str(exc)) from exc
        return grant

    def forge_link(self, parent, signer, child, caps, ttl, terminal=False):
        return self._sign(signer, child, caps, ttl, parent=parent, task=parent.payload["task"], terminal=terminal)

    def prove(self, chain, holder, tool, args, at=None):
        at = int(time.time()) if at is None else at
        return b"%010d" % at + holder.key.sign(canon([chain[-1].payload["id"], tool, args, at])).hex().encode()

    def approve(self, approver, grant, holder, tool, args, ttl=None):
        body = json.dumps({
            "nonce": uuid.uuid4().hex, "approver": approver.public_id, "identity": f"{approver.name}@example.org",
            "expires": time.time() + (ttl or 300),
            "request": hashlib.sha256(canon([grant.payload["id"], tool, args, holder.public_id])).hexdigest(),
        })
        return {"body": body, "signature": approver.key.sign(body.encode()).hex()}

    def verifier(self, trusted_root):
        return self.verifier_class(trusted_root)

    def info(self, grant):
        p = grant.payload
        return spec.GrantInfo(p["id"], p["issuer"], p["holder"], list(p["caps"]), str(p["expires"]), p["task"])

    def approval_info(self, approval):
        body = json.loads(approval["body"])
        return {"approver": body["approver"], "approver_identity": body["identity"], "expires_at": body["expires"]}

    def expires_at(self, grant):
        return grant.payload["expires"]

    def to_bytes(self, grant):
        return canon({"payload": grant.payload, "signature": grant.signature})

    def from_bytes(self, data):
        found = json.loads(data)
        return Grant(found["payload"], found["signature"])

    def encode_chain(self, chain):
        return base64.b64encode(canon([{"payload": g.payload, "signature": g.signature} for g in chain])).decode()

    def decode_chain(self, encoded):
        return [Grant(g["payload"], g["signature"]) for g in json.loads(base64.b64decode(encoded))]

    def signed_content(self, grant):
        return grant.body
