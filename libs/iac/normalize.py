"""Normalizers of the customer-side tool outputs into the results an upload carries.

Each takes one tool's own JSON output and keeps only rule identities and locations:
rule ids, resource addresses, file and line, and the *names* of changed attributes,
never a value. Terraform source and state never leave the customer's runner; a plan is
read from its `-out` file through `tofu show -json` and only its addresses, actions and
attribute names come out of here.

- `trivy_config_results`: `trivy config --format json` (Trivy 0.72.0), every FAIL
  misconfiguration as `iac:trivy:<ID>`.
- `state_drift_results`: the refresh-only plan's `resource_drift` (the live estate
  differs from recorded state: observed state drift), as `iac:drift`.
- `divergence_results`: the normal plan's `resource_changes` other than no-op and read
  (declared configuration differs from the refreshed live estate: declared
  configuration divergence), as `iac:divergence`.
- `zizmor_results`: `zizmor --format json`, every finding as `ci:zizmor:<ident>`.

Pure: plain data in, plain data out.
Refs: docs/architecture/adrs/0108-iac-and-ci-assessment.md.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "RULE_DIVERGENCE",
    "RULE_DRIFT",
    "divergence_results",
    "state_drift_results",
    "trivy_config_results",
    "zizmor_results",
]

RULE_DRIFT = "iac:drift"
RULE_DIVERGENCE = "iac:divergence"


def _result(rule: str, address: str, location: str = "", attributes=()) -> dict[str, Any]:
    return {
        "rule": rule,
        "address": address,
        "location": location,
        "attributes": sorted(set(attributes)),
    }


def trivy_config_results(doc: Mapping) -> list[dict[str, Any]]:
    """The failed misconfigurations of a Trivy config report. The rule id drops Trivy's
    `AVD-` prefix (`AVD-GCP-0001` and `GCP-0001` are one rule); messages and code
    excerpts, which can quote values, are not kept."""
    out = []
    for target in doc.get("Results") or ():
        file = str(target.get("Target") or "")
        for mis in target.get("Misconfigurations") or ():
            if str(mis.get("Status", "FAIL")).upper() != "FAIL":
                continue
            rule_id = str(mis.get("ID") or mis.get("AVDID") or "").removeprefix("AVD-")
            if not rule_id:
                continue
            cause = mis.get("CauseMetadata") or {}
            line = cause.get("StartLine")
            location = f"{file}:{line}" if line else file
            out.append(_result(f"iac:trivy:{rule_id}", str(cause.get("Resource") or ""), location))
    return out


def _mapping(value: object) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _changed_attributes(change: Mapping) -> list[str]:
    """Top-level attribute names whose before and after differ, or that are unknown
    after apply; the values themselves are compared here and dropped."""
    before = _mapping(change.get("before"))
    after = _mapping(change.get("after"))
    unknown = _mapping(change.get("after_unknown"))
    names = set(before) | set(after) | set(unknown)
    return sorted(n for n in names if before.get(n) != after.get(n) or unknown.get(n) is True)


def _changes(entries) -> list[tuple[str, list[str], list[str]]]:
    out = []
    for rc in entries or ():
        change = rc.get("change") or {}
        actions = [str(a) for a in change.get("actions") or ()]
        if actions in (["no-op"], ["read"]) or not actions:
            continue
        out.append((str(rc.get("address") or ""), actions, _changed_attributes(change)))
    return out


def state_drift_results(plan: Mapping) -> list[dict[str, Any]]:
    """Observed state drift: each resource whose live object differs from the state."""
    return [
        {**_result(RULE_DRIFT, addr, attributes=attrs), "actions": acts}
        for addr, acts, attrs in _changes(plan.get("resource_drift"))
    ]


def divergence_results(plan: Mapping) -> list[dict[str, Any]]:
    """Declared configuration divergence: each resource an apply would change."""
    return [
        {**_result(RULE_DIVERGENCE, addr, attributes=attrs), "actions": acts}
        for addr, acts, attrs in _changes(plan.get("resource_changes"))
    ]


def _zizmor_location(finding: Mapping) -> str:
    for loc in finding.get("locations") or ():
        symbolic = loc.get("symbolic") or {}
        key = symbolic.get("key") or {}
        local = key.get("Local") or {}
        path = local.get("verbatim_path") or ""
        concrete = (loc.get("concrete") or {}).get("location") or {}
        line = (concrete.get("start_point") or {}).get("row")
        if path:
            return f"{path}:{int(line) + 1}" if isinstance(line, int) else str(path)
    return ""


def zizmor_results(doc) -> list[dict[str, Any]]:
    """Every zizmor finding as `ci:zizmor:<ident>` at its first location; the
    annotation text, which can quote workflow content, is not kept."""
    out = []
    for finding in doc or ():
        ident = str(finding.get("ident") or "")
        if ident:
            out.append(_result(f"ci:zizmor:{ident}", "", _zizmor_location(finding)))
    return out
