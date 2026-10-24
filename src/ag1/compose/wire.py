"""How grants, constraints, requests and decisions cross the network."""

from __future__ import annotations

import base64

from ..gateway import Decision, Request
from ..spec import AnyValue, ApprovalGate, Exact, OneOf, Under


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def caps_to_json(caps: dict) -> dict:
    def one(c) -> dict:
        if isinstance(c, Exact):
            return {"exact": c.value}
        if isinstance(c, OneOf):
            return {"one_of": list(c.values)}
        if isinstance(c, Under):
            return {"under": c.root}
        if isinstance(c, AnyValue):
            return {"any": True}
        raise TypeError(f"unsupported constraint {c!r}")
    return {tool: {arg: one(c) for arg, c in args.items()} for tool, args in caps.items()}


def caps_from_json(data: dict) -> dict:
    def one(c: dict):
        if "exact" in c:
            return Exact(c["exact"])
        if "one_of" in c:
            return OneOf(tuple(c["one_of"]))
        if "under" in c:
            return Under(c["under"])
        if c.get("any"):
            return AnyValue()
        raise ValueError(f"unknown constraint {c!r}")
    return {tool: {arg: one(c) for arg, c in args.items()} for tool, args in data.items()}


def party(p) -> dict:
    return {"name": p.name, "trust_domain": p.trust_domain, "public_id": p.public_id}


def gate_to_json(gate: ApprovalGate | None) -> dict | None:
    if gate is None:
        return None
    return {"tools": list(gate.tools), "approvers": [party(p) for p in gate.approvers], "threshold": gate.threshold}


def request_to_json(adapter, req: Request) -> dict:
    return {
        "actor": req.actor,
        "chain": adapter.encode_chain(req.chain) if req.chain else None,
        "tool": req.tool,
        "args": req.args,
        "proof": b64(adapter.proof_to_bytes(req.proof)) if req.proof is not None else None,
        "approvals": [b64(adapter.approval_to_bytes(a)) for a in req.approvals or []] or None,
        # Recorded in evidence for the utility measures; never used for a decision.
        "intent": req.intent,
    }


def request_from_json(adapter, data: dict) -> Request:
    return Request(
        actor=data["actor"],
        chain=adapter.decode_chain(data["chain"]) if data.get("chain") else [],
        tool=data["tool"],
        args=data["args"],
        proof=adapter.proof_from_bytes(unb64(data["proof"])) if data.get("proof") else None,
        approvals=[adapter.approval_from_bytes(unb64(a)) for a in data["approvals"]] if data.get("approvals") else None,
        intent=data.get("intent", "legit"),
    )


def decision_to_json(d: Decision) -> dict:
    return {"allowed": d.allowed, "reason": d.reason, "canonical_args": d.canonical_args, "result": d.result}


def decision_from_json(data: dict) -> Decision:
    return Decision(data["allowed"], data["reason"], data["canonical_args"], data.get("result"))
