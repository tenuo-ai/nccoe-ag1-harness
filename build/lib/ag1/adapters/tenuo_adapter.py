"""Adapter for Tenuo warrants (Attenuating Authorization Tokens)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime

import cbor2
import tenuo
from tenuo import (
    Authorizer,
    NonceStore,
    SignedRevocationList,
    SigningKey,
    PublicKey,
    Warrant,
    compute_request_hash,
    decode_warrant_stack_base64,
    encode_warrant_stack,
)
from tenuo.approval import ApprovalRequest, sign_approval

from .. import spec


@dataclass
class TenuoPrincipal:
    name: str
    key: SigningKey
    trust_domain: str = "local"

    @property
    def public_id(self) -> str:
        return self.key.public_key.to_bytes().hex()


def _constraint(c: spec.Constraint):
    if isinstance(c, spec.Exact):
        return tenuo.Exact(c.value)
    if isinstance(c, spec.OneOf):
        return tenuo.OneOf(list(c.values))
    if isinstance(c, spec.Under):
        return tenuo.Subpath(c.root)
    if isinstance(c, spec.AnyValue):
        return tenuo.Wildcard()
    raise TypeError(f"unsupported constraint {c!r}")


def _approval_nonce(approval) -> bytes:
    return bytes(cbor2.loads(approval.payload).get("nonce", b"")) or bytes(approval.signature)


def _apply(builder, caps: spec.Capabilities):
    for tool, args in caps.items():
        builder = builder.capability(tool, **{k: _constraint(v) for k, v in args.items()})
    return builder


CLOCK_TOLERANCE_SECS = 2  # production deployments typically allow more; see README


class TenuoVerifier:
    """Tenuo's Authorizer plus the two deployment choices it leaves to the caller.

    `Authorizer` verifies the chain, proof of possession, constraints,
    expiry, revocation and approval binding. Replay of an identical request
    within the proof window, and reuse of an approval, are only stopped if the
    enforcement point remembers what it has seen, so this verifier does.
    """

    def __init__(self, root: TenuoPrincipal | str) -> None:
        public_key = (PublicKey.from_bytes(bytes.fromhex(root))
                      if isinstance(root, str) else root.key.public_key)
        self._authorizer = Authorizer(trusted_roots=[public_key])
        self._authorizer.set_clock_tolerance(CLOCK_TOLERANCE_SECS)
        self._nonces = NonceStore(ttl_seconds=self._authorizer.pop_validity_secs() + CLOCK_TOLERANCE_SECS)
        self._used_approvals: set[bytes] = set()
        self._revocation_version = 0

    def authorize(self, chain, tool, signed_args, constraint_args, proof, approvals):
        if proof is not None and self._nonces.is_replay(bytes(proof)):
            raise spec.Denied("Replay: this proof of possession has already been used")
        approval_nonces = [_approval_nonce(a) for a in approvals or []]
        if any(n in self._used_approvals for n in approval_nonces):
            raise spec.Denied("ApprovalReuse: this approval has already been used")
        try:
            self._authorizer.check_chain_with_pop_args(
                chain=chain, tool=tool, pop_args=signed_args, constraint_args=constraint_args,
                signature=proof, approvals=approvals,
            )
        except Exception as exc:
            raise spec.Denied(f"{type(exc).__name__}: {exc}") from exc
        # Record only after success, so a failed attempt cannot burn a legitimate request.
        if proof is not None:
            self._nonces.check_and_record(bytes(proof))
        self._used_approvals.update(approval_nonces)

    def verify_chain(self, chain):
        self._authorizer.verify_chain(chain)

    def install_revocation(self, issuer: TenuoPrincipal, grants):
        self._revocation_version += 1
        builder = SignedRevocationList.builder()
        for g in grants:
            builder = builder.revoke(g.id)
        self._authorizer.set_revocation_list(builder.version(self._revocation_version).build(issuer.key))


class TenuoAdapter:
    name = "tenuo"
    version = tenuo.__version__
    capabilities = spec.AdapterCapabilities(
        delegation_mode="holder_signed",
        verification_mode="offline_chain",
        artifact_mode="structured_signed",
    )

    def __init__(self) -> None:
        self._trust_domains: dict[str, str] = {}

    def new_principal(self, name: str, trust_domain: str = "local") -> TenuoPrincipal:
        principal = TenuoPrincipal(name, SigningKey.generate(), trust_domain)
        self._trust_domains[principal.public_id] = trust_domain
        return principal

    def issue(self, issuer, holder, caps, ttl, task=None, gate=None):
        b = _apply(Warrant.mint_builder(), caps)
        if gate is not None:
            b = (b.approval_gates({t: None for t in gate.tools})
                 .required_approvers([p.key.public_key for p in gate.approvers])
                 .min_approvals(gate.threshold))
        b = b.holder(holder.key.public_key).ttl(ttl)
        if task:
            b = b.session_id(task)
        return b.mint(issuer.key)

    def delegate(self, parent, parent_holder, child, caps, ttl, terminal=False):
        try:
            b = _apply(parent.grant_builder(), caps).holder(child.key.public_key).ttl(ttl)
            if terminal:
                b = b.terminal()
            return b.grant(parent_holder.key)
        except Exception as exc:
            raise spec.DelegationRejected(f"{type(exc).__name__}: {exc}") from exc

    def prove(self, chain, holder, tool, args):
        return bytes(chain[-1].sign(holder.key, tool, args, int(time.time())))

    def approve(self, approver, grant, holder, tool, args, ttl: int | None = None):
        request_hash = compute_request_hash(grant.id, tool, args, holder.key.public_key)
        request = ApprovalRequest(tool=tool, arguments=args, warrant_id=grant.id, request_hash=request_hash)
        return sign_approval(request, approver.key, external_id=f"{approver.name}@example.org", ttl_seconds=ttl)

    def verifier(self, trusted_root):
        return TenuoVerifier(trusted_root)

    def info(self, grant) -> spec.GrantInfo:
        return spec.GrantInfo(
            grant_id=grant.id,
            issuer=grant.issuer.to_bytes().hex(),
            holder=grant.authorized_holder.to_bytes().hex(),
            tools=list(grant.tools),
            expires_at=str(grant.expires_at()),
            task=grant.session_id,
            extra={
                "issuer_trust_domain": self._trust_domains.get(grant.issuer.to_bytes().hex(), "unknown"),
                "holder_trust_domain": self._trust_domains.get(grant.authorized_holder.to_bytes().hex(), "unknown"),
            },
        )

    def approval_info(self, approval) -> dict:
        payload = cbor2.loads(approval.payload)
        return {
            "approver": approval.approver_key.to_bytes().hex(),
            "approver_identity": payload.get("external_id"),
            "approved_at": payload.get("approved_at"),
            "expires_at": payload.get("expires_at"),
            "request_hash": bytes(payload.get("request_hash", b"")).hex(),
        }

    def expires_at(self, grant) -> float:
        value = grant.expires_at()
        if isinstance(value, datetime):
            return value.timestamp()
        return datetime.fromisoformat(str(value)).timestamp()

    def encode_chain(self, chain) -> str:
        return encode_warrant_stack(chain)

    def decode_chain(self, encoded: str) -> list:
        return decode_warrant_stack_base64(encoded)

    def to_bytes(self, grant) -> bytes:
        return bytes(grant.to_bytes())

    def from_bytes(self, data: bytes):
        return Warrant.from_bytes(data)

    def signed_content(self, grant) -> bytes:
        return bytes(grant.payload_bytes)
