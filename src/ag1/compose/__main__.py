"""Run one compose role: `python -m ag1.compose {keyholder,pep,test-service,sink}`.

Configuration comes from the environment; tokens are read from files (Docker secrets).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

from ..adapters import DEFAULT, load  # noqa: E402
from ..gateway import EnforcementPoint  # noqa: E402
from . import keyholder, pep, sink, testservice  # noqa: E402
from .http import call, make_server  # noqa: E402

PORT = 8000


def _pairs(value: str) -> dict[str, str]:
    """`a=x,b=y` -> {"a": "x", "b": "y"}"""
    return dict(item.split("=", 1) for item in value.split(",") if item)


def _secret(name: str) -> str:
    with open(os.environ[name], encoding="utf-8") as f:
        return f.read().strip()


def _identity(url: str, name: str, wait: float = 120) -> dict:
    deadline = time.monotonic() + wait
    while True:
        try:
            for found in call(f"{url}/identities")["identities"]:
                if found["name"] == name:
                    return found
            raise LookupError(f"{url} holds no identity {name!r}")
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ag1.compose")
    parser.add_argument("role", choices=("keyholder", "pep", "test-service", "sink"))
    role = parser.parse_args(argv).role
    env = os.environ
    adapter = load(env.get("AG1_ADAPTER", DEFAULT))

    if role == "keyholder":
        identities = [tuple(i.split("@", 1)) for i in env.get("AG1_IDENTITIES", "").split(",") if i]
        routes = keyholder.routes(adapter, identities, _pairs(env.get("AG1_PEPS", "")))
    elif role == "pep":
        from ..forgejo import ForgejoSCM
        issuer = _identity(env["AG1_ISSUER_URL"], "task-authorization-system")
        # The baseline has no origin to check and no route to the agents' key holders.
        origin = _identity(env["AG1_ORIGIN_URL"], "orchestrator") if env.get("AG1_ORIGIN_URL") else None
        for found in filter(None, (issuer, origin)):  # who belongs to which domain, fetched once at startup
            adapter.public_principal(found["name"], found["public_id"], found["trust_domain"])
        service = pep.ComposeService(ForgejoSCM(env["AG1_FORGEJO_URL"], _secret("AG1_FORGEJO_TOKEN_FILE"), reset=False),
                                     env["AG1_TEST_SERVICE_URL"], env["AG1_SINK_URL"])
        gateway = EnforcementPoint(
            adapter=adapter, trusted_root=issuer["public_id"], scm=service, name=env["AG1_PEP_NAME"],
            audience=env.get("AG1_AUDIENCE") or None, trust_domain=env.get("AG1_TRUST_DOMAIN", "service-domain"),
            trusted_origin_principals={origin["public_id"]} if env.get("AG1_ORIGIN_ALLOWLIST") == "1" else None,
            enforce=env.get("AG1_ENFORCE", "1") == "1",
        )
        routes = pep.routes(gateway, issuer["public_id"])
        print(f"enforcement point {gateway.name}: evidence key {gateway.evidence_public_key_hex}", flush=True)
    elif role == "test-service":
        routes = testservice.routes(env["AG1_FORGEJO_URL"], _secret("AG1_FORGEJO_READ_TOKEN_FILE"))
    else:
        routes = sink.routes()

    make_server(routes, PORT).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
