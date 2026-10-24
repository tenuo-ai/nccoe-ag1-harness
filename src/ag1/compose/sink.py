"""The staging deployment target: records what it is asked to deploy, and nothing more."""

from __future__ import annotations

import threading


def routes() -> dict:
    lock = threading.Lock()
    deployments: list[dict] = []

    def deploy(body):
        with lock:
            deployments.append({"tool": body["tool"], "artifact": body["artifact"]})
        return {"ok": True}

    return {
        "GET /health": lambda _: {"ok": True},
        "GET /deployments": lambda _: {"deployments": list(deployments)},
        "POST /deploy": deploy,
    }
