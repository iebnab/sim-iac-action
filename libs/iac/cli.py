"""The customer-side entry point of the IaC and CI Action: build one results document
from the tool outputs on the runner, never from source or state.

    uv run --no-project --with pyyaml==6.0.2 -m libs.iac.cli iac \
        --root envs/rehearsal --trivy trivy.json --trivy-status ok \
        --plan plan.json --plan-status ok --out iac-results.json
    uv run --no-project --with pyyaml==6.0.2 -m libs.iac.cli ci \
        --workflows .github/workflows --zizmor zizmor.json --zizmor-status ok \
        [--ruleset ruleset.json] --out ci-results.json

`--plan` is the output of `tofu show -json` over the plan's `-out` file; the plan file
itself and the JSON stay on the runner, and nothing is printed but counts. A tool whose
step failed is passed with status `error`, so the upload records a gap instead of a
clean result.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from libs.iac.normalize import (
    divergence_results,
    state_drift_results,
    trivy_config_results,
    zizmor_results,
)
from libs.iac.upload import (
    CLASS_CI,
    CLASS_IAC,
    PINNED_TOOLS,
    SCHEMA,
    TOOL_PLAN,
    TOOL_PUBLISH_RULE,
    TOOL_TRIVY,
    TOOL_ZIZMOR,
)
from libs.iac.workflow_rules import assess_publish_requires_scan


def _load(path: str | None, status: str) -> tuple[object, str]:
    if status != "ok" or not path or not Path(path).is_file():
        return None, "error"
    try:
        return json.loads(Path(path).read_text()), "ok"
    except ValueError:
        return None, "error"


def _tool(name: str, status: str) -> dict[str, str]:
    return {"name": name, "version": PINNED_TOOLS[name], "status": status}


def _now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def build_iac(root: str, trivy: object, trivy_status: str, plan: object, plan_status: str):
    results = []
    if trivy_status == "ok" and isinstance(trivy, dict):
        results += trivy_config_results(trivy)
    if plan_status == "ok" and isinstance(plan, dict):
        results += state_drift_results(plan) + divergence_results(plan)
    return {
        "schema": SCHEMA,
        "class": CLASS_IAC,
        "root": root,
        "collected_at": _now(),
        "tools": [_tool(TOOL_TRIVY, trivy_status), _tool(TOOL_PLAN, plan_status)],
        "results": results,
    }


def build_ci(workflows: dict, zizmor: object, zizmor_status: str, ruleset: object):
    results = zizmor_results(zizmor) if zizmor_status == "ok" else []
    for v in assess_publish_requires_scan(
        workflows, ruleset if isinstance(ruleset, dict) else None
    ):
        results.append(
            {
                "rule": v.rule,
                "address": f"{v.job}.{v.reason}" if v.job else v.reason,
                "location": v.workflow if v.workflow != "ruleset" else "",
                "attributes": [],
            }
        )
    return {
        "schema": SCHEMA,
        "class": CLASS_CI,
        "collected_at": _now(),
        "tools": [_tool(TOOL_ZIZMOR, zizmor_status), _tool(TOOL_PUBLISH_RULE, "ok")],
        "results": results,
    }


def _read_workflows(directory: Path) -> dict:
    import yaml

    out = {}
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        out[f"{directory.as_posix()}/{path.name}"] = yaml.safe_load(path.read_text()) or {}
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="iac-ci-results")
    sub = p.add_subparsers(dest="class_", required=True)
    i = sub.add_parser(CLASS_IAC)
    i.add_argument("--root", required=True)
    i.add_argument("--trivy")
    i.add_argument("--trivy-status", default="ok")
    i.add_argument("--plan")
    i.add_argument("--plan-status", default="ok")
    i.add_argument("--out", required=True)
    c = sub.add_parser(CLASS_CI)
    c.add_argument("--workflows", required=True)
    c.add_argument("--zizmor")
    c.add_argument("--zizmor-status", default="ok")
    c.add_argument("--ruleset")
    c.add_argument("--out", required=True)
    a = p.parse_args(argv)
    if a.class_ == CLASS_IAC:
        trivy, ts = _load(a.trivy, a.trivy_status)
        plan, ps = _load(a.plan, a.plan_status)
        doc = build_iac(a.root, trivy, ts, plan, ps)
    else:
        zizmor, zs = _load(a.zizmor, a.zizmor_status)
        ruleset, _ = _load(a.ruleset, "ok") if a.ruleset else (None, "ok")
        doc = build_ci(_read_workflows(Path(a.workflows)), zizmor, zs, ruleset)
    Path(a.out).write_text(json.dumps(doc, sort_keys=True))
    statuses = ",".join(f"{t['name']}={t['status']}" for t in doc["tools"])
    print(f"{a.class_}: {len(doc['results'])} results ({statuses})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
