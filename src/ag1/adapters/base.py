"""The contract an implementation fills in to be evaluated by the AG-1 steps.

The harness owns the scenario, the mock SCM/CI service, argument
normalization, and the evidence records. The adapter owns everything about
the authorization artifact: how grants are issued and delegated, how a
request proves possession, how a chain is verified, and how revocation and
approvals work.

See ADAPTERS.md for what each method must do and which AG-1 steps use it.
"""

from __future__ import annotations

import inspect
from typing import Any, Protocol, runtime_checkable

from ..spec import AdapterCapabilities, ApprovalGate, Capabilities, GrantInfo


@runtime_checkable
class Principal(Protocol):
    name: str
    trust_domain: str

    @property
    def public_id(self) -> str:
        """Stable public identifier, e.g. a key thumbprint."""


@runtime_checkable
class Verifier(Protocol):
    def authorize(self, chain: list, tool: str, signed_args: dict, constraint_args: dict,
                  proof: Any, approvals: list | None) -> None:
        """Raise `spec.Denied` unless the chain authorizes `tool` for `constraint_args`.

        `signed_args` are the exact arguments the presenter signed; `constraint_args`
        are their normalized form, which is what constraints must be checked against.
        Verification must use only the trusted root this verifier was created with.
        An identical request that was already authorized, and an approval that was
        already used, must be refused.
        """

    def verify_chain(self, chain: list, *, as_of: int | None = None) -> None:
        """Verify every link to the trusted root; optionally at a signed authorization time.

        With no timestamp, validate against the current time. Historical verification
        is for auditing only, never for authorizing execution.
        """

    def install_revocation(self, issuer: Principal, grants: list) -> None:
        """Make `grants`, and everything delegated from them, fail from now on."""


@runtime_checkable
class Adapter(Protocol):
    name: str
    version: str
    capabilities: AdapterCapabilities

    def new_principal(self, name: str, trust_domain: str = "local") -> Principal: ...

    def issue(self, issuer: Principal, holder: Principal, caps: Capabilities, ttl: int,
              task: str | None = None, gate: ApprovalGate | None = None) -> Any:
        """Issue a root grant from the trusted issuer to `holder`."""

    def delegate(self, parent: Any, parent_holder: Principal, child: Principal, caps: Capabilities,
                 ttl: int, terminal: bool = False) -> Any:
        """Obtain a child grant authorized by `parent_holder` and `parent`.

        The adapter may have the holder sign the child or may exchange the
        parent at an authorization server. Raise `spec.DelegationRejected` if
        the child would widen the parent, if `parent_holder` does not hold
        `parent`, or if `parent` cannot delegate. An adapter may instead clamp
        a requested lifetime to the parent's.
        """

    def prove(self, chain: list, holder: Principal, tool: str, args: dict) -> Any:
        """Proof that `holder` presents this request, bound to `tool` and `args`."""

    def approve(self, approver: Principal, grant: Any, holder: Principal, tool: str, args: dict,
                ttl: int | None = None) -> Any:
        """A signed approval bound to this exact request, valid for `ttl` seconds (adapter default if None)."""

    def verifier(self, trusted_root: Principal | str) -> Verifier:
        """Create a verifier from a principal or its portable public identifier."""

    def info(self, grant: Any) -> GrantInfo: ...

    def approval_info(self, approval: Any) -> dict:
        """Auditable fields of an approval: approver, approver identity, validity."""

    def expires_at(self, grant: Any) -> float:
        """Expiry as a Unix timestamp, for comparing a child with its parent."""

    def encode_chain(self, chain: list) -> str:
        """Portable encoding carried in evidence records."""

    def decode_chain(self, encoded: str) -> list: ...

    def to_bytes(self, grant: Any) -> bytes: ...

    def from_bytes(self, data: bytes) -> Any: ...

    def signed_content(self, grant: Any) -> bytes:
        """The bytes the signature covers, to tell a content change from an encoding change."""


def require_audit_time(verifier: Verifier) -> None:
    """Fail clearly here, because a TypeError during audit would read as an invalid chain."""
    if "as_of" not in inspect.signature(verifier.verify_chain).parameters:
        raise TypeError(f"{type(verifier).__name__}.verify_chain must accept as_of; see ADAPTERS.md")
