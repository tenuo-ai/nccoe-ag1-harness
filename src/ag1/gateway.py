"""Policy enforcement point in front of the SCM and CI/CD service.

Every tool call passes through `EnforcementPoint.handle`, which:

1. normalizes the request arguments to their canonical form,
2. verifies the presented delegation chain against the trusted root only
   (no call to the issuer), the caller's proof of possession over the raw
   arguments it signed, the warrant constraints over the canonical
   arguments, revocation, expiry, and any required approvals,
3. executes the call with the service's own credential only if all of that
   passes, and
4. appends a signed authorization evidence record (Comment 5).
"""

from __future__ import annotations

import json
import posixpath
import time
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from tenuo import Authorizer, PublicKey, SignedRevocationList, Warrant, encode_warrant_stack
import tenuo

from .scm import MockSCM


class NormalizationError(ValueError):
    pass


def key_hex(key: PublicKey) -> str:
    return key.to_bytes().hex()


@dataclass
class Request:
    actor: str
    chain: list[Warrant]
    tool: str
    args: dict
    signature: bytes | None
    approvals: list | None = None
    # What the scenario intends this call to be. Used only for the utility
    # measures; the enforcement point never sees or uses it.
    intent: str = "legit"


@dataclass
class Decision:
    allowed: bool
    reason: str
    canonical_args: dict
    result: str | None = None

    @property
    def verdict(self) -> str:
        return "allowed" if self.allowed else "denied"


@dataclass
class EnforcementPoint:
    trusted_root: PublicKey
    scm: MockSCM
    enforce: bool = True
    evidence: list[dict] = field(default_factory=list)
    _signer: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    def __post_init__(self) -> None:
        self.authorizer = Authorizer(trusted_roots=[self.trusted_root])

    @property
    def evidence_public_key(self) -> Ed25519PublicKey:
        return self._signer.public_key()

    def install_revocation_list(self, srl: SignedRevocationList) -> None:
        self.authorizer.set_revocation_list(srl)

    # Normalization (Comment 3): constraints are evaluated on the form the
    # tool will execute, not on the string the agent sent.
    def normalize(self, tool: str, args: dict) -> dict:
        out = dict(args)
        if "repo" in out:
            out["repo"] = self.scm.canonical_repo(str(out["repo"]))
        repo = out.get("repo", "")
        for ref_key in ("branch", "head", "base"):
            if ref_key in out:
                out[ref_key] = self.scm.resolve_ref(repo, str(out[ref_key]))
        if "path" in out:
            out["path"] = self._canonical_path(repo, str(out["path"]))
        return out

    def _canonical_path(self, repo: str, path: str) -> str:
        decoded = path
        for _ in range(5):  # decode repeatedly to defeat double encoding
            nxt = unquote(decoded)
            if nxt == decoded:
                break
            decoded = nxt
        decoded = unicodedata.normalize("NFC", decoded)
        if any(ord(ch) < 0x20 for ch in decoded):
            raise NormalizationError("control character in path")
        if not decoded.startswith("/"):
            decoded = "/" + decoded
        canonical = posixpath.normpath(decoded)
        return posixpath.normpath(self.scm.resolve_symlinks(repo, canonical))

    def handle(self, req: Request) -> Decision:
        try:
            canonical = self.normalize(req.tool, req.args)
        except NormalizationError as exc:
            decision = Decision(False, f"NormalizationError: {exc}", {})
            self._record(req, decision)
            return decision

        if not self.enforce:
            # Baseline for comparison: the service acts on its own credential.
            decision = Decision(True, "ambient service credential", canonical,
                                self.scm.execute(req.tool, canonical))
            self._record(req, decision)
            return decision

        try:
            self.authorizer.check_chain_with_pop_args(
                chain=req.chain,
                tool=req.tool,
                pop_args=req.args,
                constraint_args=canonical,
                signature=req.signature,
                approvals=req.approvals,
            )
        except Exception as exc:  # every Tenuo failure is a denial
            decision = Decision(False, f"{type(exc).__name__}: {exc}", canonical)
            self._record(req, decision)
            return decision

        decision = Decision(True, "authorized", canonical, self.scm.execute(req.tool, canonical))
        self._record(req, decision)
        return decision

    def _record(self, req: Request, decision: Decision) -> None:
        links = [
            {
                "warrant_id": w.id,
                "issuer": key_hex(w.issuer),
                "holder": key_hex(w.authorized_holder),
                "tools": list(w.tools),
                "expires_at": str(w.expires_at()),
                "task": w.session_id,
            }
            for w in req.chain
        ]
        body = {
            "seq": len(self.evidence) + 1,
            "time": int(time.time()),
            "actor": req.actor,
            "tool": req.tool,
            "requested_args": req.args,
            "canonical_args": decision.canonical_args,
            "decision": decision.verdict,
            "reason": decision.reason,
            "approvals": len(req.approvals or []),
            "root_principal": links[0]["issuer"] if links else None,
            "presenter": links[-1]["holder"] if links else None,
            "task": links[0]["task"] if links else None,
            "delegation_lineage": links,
            "authorization_chain": encode_warrant_stack(req.chain) if req.chain else None,
            "verifier": f"tenuo {tenuo.__version__}",
            "outcome": decision.result,
            "enforced": self.enforce,
            "intent": req.intent,
        }
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
        self.evidence.append({"record": body, "signature": self._signer.sign(payload).hex()})
