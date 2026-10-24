"""Run every AG-1 step against an adapter and write results/results.md and results/results.json."""

from __future__ import annotations

import argparse
import os
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)

from . import report, scenario  # noqa: E402
from .adapters import ADAPTERS, load  # noqa: E402
from .scm import MockSCM  # noqa: E402
from .steps import STEPS, evidence_run, utility_run  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ag1", description=__doc__)
    parser.add_argument("--adapter", default="tenuo",
                        help=f"registered name ({', '.join(ADAPTERS)}) or module:Class")
    parser.add_argument("--mode", choices=("in-process", "compose"), default="in-process",
                        help="in-process (default), or compose: every party and enforcement point a separate "
                             "service, configured by the AG1_* variables compose.yaml sets for the driver")
    parser.add_argument("--service", choices=("mock", "forgejo"), default="mock",
                        help="in-process: SCM service behind the enforcement point (default: in-memory mock)")
    parser.add_argument("--forgejo-url", default=os.environ.get("AG1_FORGEJO_URL"),
                        help="with --service forgejo: base URL (default $AG1_FORGEJO_URL); the admin token is "
                             "read from $AG1_FORGEJO_TOKEN. The acme/repo-a and acme/repo-b repositories are "
                             "deleted and recreated for every world")
    parser.add_argument("--out", type=Path, default=Path("results"))
    parser.add_argument("--verify", type=Path, metavar="RESULTS_DIR",
                        help="verify an exported evidence bundle and exit")
    parser.add_argument("--trusted-root", metavar="HEX",
                        help="with --verify: the trusted root public key, obtained outside the bundle")
    parser.add_argument("--evidence-key", metavar="[NAME=]HEX", action="append",
                        help="with --verify: an evidence signing public key, obtained outside the bundle; for a "
                             "compose run, one NAME=HEX per enforcement point")
    args = parser.parse_args(argv)

    adapter = load(args.adapter)
    if args.verify is not None:
        if not (args.trusted_root and args.evidence_key):
            parser.error("--verify needs --trusted-root and --evidence-key from a source other than the bundle")
        if len(args.evidence_key) == 1 and "=" not in args.evidence_key[0]:
            verification = report.verify_bundle(args.verify, adapter, args.trusted_root, args.evidence_key[0])
        else:
            keys = dict(k.split("=", 1) for k in args.evidence_key)
            verification = report.verify_bundles(args.verify, adapter, args.trusted_root, keys)
        print(f"evidence: {verification}")
        return 0 if verification["valid"] else 1
    if args.mode == "compose":
        scenario.use_deployment(_compose_deployment())
    else:
        scenario.use_deployment(None)
    if args.service == "forgejo":
        token = os.environ.get("AG1_FORGEJO_TOKEN")
        if not (args.forgejo_url and token):
            parser.error("--service forgejo needs --forgejo-url (or $AG1_FORGEJO_URL) and $AG1_FORGEJO_TOKEN")
        from .forgejo import ForgejoSCM
        scenario.use_service(lambda: ForgejoSCM(args.forgejo_url, token))
    else:
        scenario.use_service(MockSCM)
    results = [step(adapter) for step in STEPS]
    utility = utility_run(adapter)
    evidence_world = evidence_run(adapter)
    print(f"implementation: {adapter.name} {adapter.version}")
    print(f"service: {evidence_world.scm.description}")
    for r in results:
        print(f"{'MET    ' if r.passed else 'NOT MET'}  {r.step_id:8} {r.title}")
        for c in r.checks:
            if not c.applicable:
                print(f"           - {c.description}: not applicable ({c.detail})")
            elif not c.passed:
                print(f"           - {c.description}: expected {c.expected}, observed {c.observed} {c.detail}")
    print(f"\nutility: {utility}")
    if args.mode == "compose":
        # Each enforcement point exports its own log and signs its own checkpoint.
        report.write(results, utility, args.out, adapter, evidence_world.scm)
        report.write_bundles(args.out, {g.name: g.bundle() for g in evidence_world.gateways})
        keys = " ".join(f"--evidence-key {g.name}={g.evidence_public_key_hex}" for g in evidence_world.gateways)
    else:
        report.write(results, utility, args.out, adapter, evidence_world.scm, evidence_world=evidence_world)
        keys = f"--evidence-key {evidence_world.gateway.evidence_public_key_hex}"
    print(f"wrote {args.out / 'results.md'}")
    anchors = f"--trusted-root {evidence_world.issuer.public_id} {keys}"
    print("record these anchors outside the results directory; the bundle cannot vouch for itself")
    print(f"anchors: {anchors}")
    print(f"verify with: {parser.prog} --adapter {args.adapter} --verify {args.out} {anchors}")
    return 0 if all(r.passed for r in results) and utility["mistaken_denials"] == 0 else 1


def _compose_deployment():
    from .compose.driver import ComposeConfig, deployment
    from .compose.__main__ import _pairs
    from .forgejo import ForgejoSCM

    env = os.environ
    url = env["AG1_FORGEJO_URL"]
    with open(env["AG1_FORGEJO_TOKEN_FILE"], encoding="utf-8") as f:
        token = f.read().strip()
    return deployment(ComposeConfig(
        keyholders=_pairs(env["AG1_KEYHOLDERS"]), peps=_pairs(env["AG1_PEPS"]),
        test_url=env["AG1_TEST_SERVICE_URL"], sink_url=env["AG1_SINK_URL"],
        forge=lambda: ForgejoSCM(url, token),
    ))


if __name__ == "__main__":
    sys.exit(main())
