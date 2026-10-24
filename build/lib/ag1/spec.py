"""Implementation-neutral vocabulary for grants.

Scenarios describe authority with these types. An adapter translates them
into its own format (an OAuth authorization_details entry, a capability
token caveat, a policy, and so on).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union


@dataclass(frozen=True)
class AdapterCapabilities:
    """Architecture choices reported with every result.

    They keep the harness from implying that holder-signed capability chains,
    offline verification, or structured artifacts are the only conforming
    implementation patterns.
    """

    delegation_mode: str  # holder_signed | authorization_server
    verification_mode: str  # offline_chain | online_introspection | hybrid
    artifact_mode: str  # structured_signed | opaque

    def __post_init__(self) -> None:
        allowed = {
            "delegation_mode": ("holder_signed", "authorization_server"),
            "verification_mode": ("offline_chain", "online_introspection", "hybrid"),
            "artifact_mode": ("structured_signed", "opaque"),
        }
        for name, values in allowed.items():
            if getattr(self, name) not in values:
                raise ValueError(f"{name} must be one of {values}, not {getattr(self, name)!r}")


@dataclass(frozen=True)
class Exact:
    value: str


@dataclass(frozen=True)
class OneOf:
    values: tuple[str, ...]


@dataclass(frozen=True)
class Under:
    """A path equal to `root` or below it, compared after normalization."""

    root: str


@dataclass(frozen=True)
class AnyValue:
    """The argument must be present but may take any value."""


Constraint = Union[Exact, OneOf, Under, AnyValue]

# tool name -> argument name -> constraint. Arguments not listed are not allowed.
Capabilities = dict[str, dict[str, Constraint]]


@dataclass
class ApprovalGate:
    tools: tuple[str, ...]
    approvers: list  # Principals whose signed approval satisfies the gate
    threshold: int = 1


@dataclass
class GrantInfo:
    grant_id: str
    issuer: str  # public identifier of the signer of this link
    holder: str  # public identifier of the principal it is bound to
    tools: list[str]
    expires_at: str
    task: str | None = None
    extra: dict = field(default_factory=dict)


class DelegationRejected(Exception):
    """Raised by an adapter when a child grant cannot be created or would widen its parent."""


class Denied(Exception):
    """Raised by a verifier when a request is not authorized. The message is the reason."""
