"""Policy enforcement point in front of the SCM and CI/CD service.

Every tool call passes through `EnforcementPoint.handle`, which:

1. normalizes the request arguments to their canonical form (harness-side,
   the same for every implementation),
2. asks the implementation's verifier to authorize the canonical arguments,
   with proof of possession checked over the arguments the caller signed,
3. executes the call with the service's own credential only if authorized,
4. appends a signed authorization evidence record (Comment 5).
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .adapters.base import Adapter, Principal
from .scm import Service, ServiceError
from .spec import Denied


class NormalizationError(ValueError):
    pass


@dataclass
class Request:
    actor: str
    chain: list
    tool: str
    args: dict
    proof: Any
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


MAX_PATH = 4096
GENESIS = "0" * 64


def record_payload(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()


def audit_time(body: dict) -> int:
    """When authority was checked; a tool call can outlast its grant. Earlier bundles only have `time`."""
    return body.get("checked_at", body["time"])


_FLAG = re.compile(r"^--([a-z][a-z0-9-]*)(?:=(.*))?$")
_SHELL_OPERATORS = set(";|&`$<>()")


def parse_argv(argv: str) -> dict:
    """Parse a command line into structured flags; refuse anything that is not a flag."""
    if any(ch in _SHELL_OPERATORS for ch in argv):
        raise NormalizationError("shell operator in command line")
    try:
        tokens = shlex.split(argv)
    except ValueError as exc:
        raise NormalizationError(f"unparseable command line: {exc}") from exc
    out: dict = {}
    i = 0
    while i < len(tokens):
        m = _FLAG.match(tokens[i])
        if not m:
            raise NormalizationError(f"unexpected argument {tokens[i]!r}")
        key = m.group(1).replace("-", "_")
        if m.group(2) is not None:
            value = m.group(2)
        elif i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
            i += 1
            value = tokens[i]
        else:
            value = "true"
        if key in out:
            raise NormalizationError(f"flag --{m.group(1)} given more than once")
        out[key] = value
        i += 1
    return out


@dataclass
class EnforcementPoint:
    adapter: Adapter
    trusted_root: Principal
    scm: Service
    name: str = "main"
    audience: str | None = None
    trust_domain: str = "service-domain"
    trusted_origin_principals: set[str] | None = None
    enforce: bool = True
    evidence: list[dict] = field(default_factory=list)
    _signer: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    _head: str = GENESIS

    def __post_init__(self) -> None:
        self.verifier = self.adapter.verifier(self.trusted_root)

    @property
    def evidence_public_key(self) -> Ed25519PublicKey:
        return self._signer.public_key()

    @property
    def evidence_public_key_hex(self) -> str:
        return self.evidence_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    @property
    def evidence_head(self) -> str:
        return self._head

    def checkpoint(self, header: dict | None = None) -> dict:
        """Sign the current head, record count, and bundle header.

        Dropping trailing records, or editing the header (implementation,
        declared capabilities, trusted root), is then detectable.
        """
        body = {"type": "ag1-evidence-checkpoint", "terminal_hash": self._head, "records": len(self.evidence),
                "header": header or {}}
        return {"checkpoint": body, "signature": self._signer.sign(record_payload(body)).hex()}

    # Normalization (Comment 3): constraints are evaluated on the form the
    # tool will execute, not on the string the agent sent.
    def normalize(self, tool: str, args: dict) -> dict:
        out = dict(args)
        if "argv" in out:
            flags = parse_argv(str(out.pop("argv")))
            for key, value in flags.items():
                if key in out and out[key] != value:
                    raise NormalizationError(f"--{key} conflicts with an explicit argument")
                out[key] = value
        for key in ("repo", "branch", "head", "base", "suite", "artifact"):
            if key in out and not isinstance(out[key], str):
                raise NormalizationError(f"{key} must be a string, not {type(out[key]).__name__}")
        if "repo" in out:
            out["repo"] = self.scm.canonical_repo(out["repo"])
        repo = out.get("repo", "")
        for ref_key in ("branch", "head", "base"):
            if ref_key in out:
                out[ref_key] = self.scm.resolve_ref(repo, out[ref_key])
        if "path" in out:
            out["path"] = self._canonical_path(repo, out["path"], out.get("branch"))
        return out

    def _canonical_path(self, repo: str, path, ref: str | None = None) -> str:
        # Refuse anything ambiguous rather than guess how a downstream tool will read it.
        if not isinstance(path, str):
            raise NormalizationError(f"path must be a string, not {type(path).__name__}")
        if len(path) > MAX_PATH:
            raise NormalizationError("path too long")
        decoded = path
        for _ in range(5):  # decode repeatedly to defeat double encoding
            try:
                nxt = unquote(decoded, errors="strict")
            except UnicodeDecodeError as exc:
                raise NormalizationError("invalid percent-encoding in path") from exc
            if nxt == decoded:
                break
            decoded = nxt
        else:
            raise NormalizationError("path is encoded too many times")
        decoded = unicodedata.normalize("NFC", decoded)
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in decoded):
            raise NormalizationError("control character in path")
        if "\\" in decoded:
            raise NormalizationError("backslash in path")
        for ch in decoded:
            # Characters that some platforms or normalizations turn into a separator or a dot,
            # such as fullwidth solidus (U+FF0F) or division slash (U+2215).
            if ch not in "/." and not ch.isascii() and unicodedata.normalize("NFKC", ch) in ("/", "\\", "."):
                raise NormalizationError(f"look-alike separator U+{ord(ch):04X} in path")
            if ch in "∕⁄⧸／﹨＼":
                raise NormalizationError(f"look-alike separator U+{ord(ch):04X} in path")
        if not decoded.startswith("/"):
            decoded = "/" + decoded
        canonical = posixpath.normpath(decoded)
        return posixpath.normpath(self.scm.resolve_symlinks(repo, canonical, ref))

    def handle(self, req: Request) -> Decision:
        checked_at = int(time.time())
        try:
            canonical = self.normalize(req.tool, req.args)
        except (NormalizationError, ServiceError) as exc:
            decision = Decision(False, f"NormalizationError: {exc}", {})
            self._record(req, decision, checked_at)
            return decision

        if not self.enforce:
            # Baseline for comparison: the service acts on its own credential.
            decision = Decision(True, "ambient service credential", canonical,
                                self.scm.execute(req.tool, canonical))
            self._record(req, decision, checked_at)
            return decision

        try:
            if self.audience is not None and canonical.get("audience") != self.audience:
                raise Denied(f"AudienceMismatch: expected {self.audience}")
            self.verifier.authorize(req.chain, req.tool, req.args, canonical, req.proof, req.approvals)
            if self.trusted_origin_principals is not None:
                if not req.chain:
                    raise Denied("OriginatingPrincipalMissing: no root grant")
                origin = self.adapter.info(req.chain[0]).holder
                if origin not in self.trusted_origin_principals:
                    raise Denied("OriginatingPrincipalUntrusted: root holder is not trusted")
        except Denied as exc:
            decision = Decision(False, str(exc), canonical)
            self._record(req, decision, checked_at)
            return decision

        decision = Decision(True, "authorized", canonical, self.scm.execute(req.tool, canonical))
        self._record(req, decision, checked_at)
        return decision

    def _record(self, req: Request, decision: Decision, checked_at: int) -> None:
        links = [vars(self.adapter.info(g)) for g in req.chain]
        approvals = []
        for a in req.approvals or []:
            try:
                approvals.append(self.adapter.approval_info(a))
            except Exception as exc:  # record what we can, never fail the call over it
                approvals.append({"unreadable": type(exc).__name__})
        body = {
            "seq": len(self.evidence) + 1,
            "time": int(time.time()),
            "checked_at": checked_at,
            "actor": req.actor,
            "tool": req.tool,
            "requested_args": req.args,
            "canonical_args": decision.canonical_args,
            "decision": decision.verdict,
            "reason": decision.reason,
            "approvals": approvals,
            "root_principal": links[0]["issuer"] if links else None,
            "originating_principal": links[0]["holder"] if links else None,
            "presenter": links[-1]["holder"] if links else None,
            "audience": self.audience,
            "enforcement_trust_domain": self.trust_domain,
            "task": links[0]["task"] if links else None,
            "delegation_lineage": links,
            "authorization_chain": self.adapter.encode_chain(req.chain) if req.chain else None,
            "implementation": f"{self.adapter.name} {self.adapter.version}",
            "outcome": decision.result,
            "enforced": self.enforce,
            "intent": req.intent,
            # Hash of the previous record, so a deleted or reordered record breaks the chain.
            "prev": self._head,
        }
        payload = record_payload(body)
        signature = self._signer.sign(payload)
        self.evidence.append({"record": body, "signature": signature.hex()})
        self._head = hashlib.sha256(payload + signature).hexdigest()
