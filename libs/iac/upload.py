"""The results-only upload contract of the customer-side IaC and CI Action, and its
assessment into findings, reached rules and gaps.

The Action uploads one document per declared Terraform root (class `iac`) and one per
repository (class `ci`). The repository is never named in the body: it comes from the
verified GitHub OIDC claims. The document carries only rule identities and locations:

    {"schema": "iac-ci-results/1", "class": "iac" | "ci",
     "root": "<declared root path>",          # class iac only
     "collected_at": "<RFC 3339>",
     "tools": [{"name": "trivy", "version": "0.72.0", "status": "ok" | "error"}, ...],
     "results": [{"rule": "...", "address": "...", "location": "file:line",
                  "attributes": ["name", ...], "actions": ["update", ...]}]}

`parse_upload` refuses anything else: an unknown key, a value-shaped string (anything
outside the narrow identifier alphabet), an oversized document. A value can therefore
not travel in an upload, whatever the Action does.

`assess_upload` maps the tools to the rules they own: a tool that ran clean at its
pinned version reaches its registered rules; an errored, missing or differently-versioned
tool leaves its rules as gaps, so the subject is not assessed for them, and none of its
results resolves anything.
Refs: docs/architecture/adrs/0108-iac-and-ci-assessment.md.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

__all__ = [
    "CLASS_CI",
    "CLASS_IAC",
    "PINNED_TOOLS",
    "SCHEMA",
    "Assessment",
    "IacUpload",
    "TransientIacFinding",
    "UploadInvalid",
    "assess_upload",
    "parse_upload",
]

SCHEMA = "iac-ci-results/1"
CLASS_IAC = "iac"
CLASS_CI = "ci"

TOOL_TRIVY = "trivy"
TOOL_PLAN = "tofu-plan"
TOOL_ZIZMOR = "zizmor"
TOOL_PUBLISH_RULE = "publish-rule"

# The pinned version each tool's results are accepted at; another version is a gap.
PINNED_TOOLS: Mapping[str, str] = {
    TOOL_TRIVY: "0.72.0",
    TOOL_PLAN: "1.13.9",
    TOOL_ZIZMOR: "1.32.0",
    TOOL_PUBLISH_RULE: "1",
}

# The tools each class must run, and the rule ids (exact or prefix) each owns.
_CLASS_TOOLS: Mapping[str, tuple[str, ...]] = {
    CLASS_IAC: (TOOL_TRIVY, TOOL_PLAN),
    CLASS_CI: (TOOL_ZIZMOR, TOOL_PUBLISH_RULE),
}
_TOOL_RULES: Mapping[str, tuple[str, ...]] = {
    TOOL_TRIVY: ("iac:trivy:",),
    TOOL_PLAN: ("iac:drift", "iac:divergence"),
    TOOL_ZIZMOR: ("ci:zizmor:",),
    TOOL_PUBLISH_RULE: ("ci:publish_requires_scan",),
}

_MAX_RESULTS = 5000
_MAX_ATTRIBUTES = 200
_TOP_KEYS = frozenset({"schema", "class", "root", "collected_at", "tools", "results"})
_RESULT_KEYS = frozenset({"rule", "address", "location", "attributes", "actions"})
_TOOL_KEYS = frozenset({"name", "version", "status"})
_RULE = re.compile(r"^(iac|ci):[A-Za-z0-9_:.-]{1,120}$")
# A Terraform address (`module.m.google_storage_bucket.b["k"]`), a path, a location.
_ADDRESS = re.compile(r'^[A-Za-z0-9_.\-\[\]"/]{0,400}$')
_LOCATION = re.compile(r"^[A-Za-z0-9_./\-]{0,400}(:[0-9]{1,7})?$")
_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")
_ROOT = re.compile(r"^[A-Za-z0-9_./\-]{1,300}$")
_ACTIONS = frozenset({"create", "update", "delete", "read", "no-op"})


class UploadInvalid(ValueError):
    """The document breaks the contract; nothing of it is stored."""


@dataclass(frozen=True)
class ToolRun:
    name: str
    version: str
    status: str


@dataclass(frozen=True)
class IacUpload:
    class_: str
    root: str
    collected_at: datetime.datetime
    tools: tuple[ToolRun, ...]
    results: tuple[Mapping, ...]


def _check(cond: bool, msg: str) -> None:
    if not cond:
        raise UploadInvalid(msg)


def _str(value: object, pattern: re.Pattern, what: str) -> str:
    _check(isinstance(value, str) and bool(pattern.match(value)), f"invalid {what}")
    return value  # type: ignore[return-value]


def parse_upload(doc: object) -> IacUpload:
    """Validate an uploaded document against the results-only contract. Pure."""
    _check(isinstance(doc, Mapping), "document is not an object")
    assert isinstance(doc, Mapping)
    _check(set(doc) <= _TOP_KEYS, "unknown top-level key")
    _check(doc.get("schema") == SCHEMA, "unsupported schema")
    class_ = doc.get("class")
    _check(class_ in _CLASS_TOOLS, "unknown class")
    root = ""
    if class_ == CLASS_IAC:
        root = _str(doc.get("root"), _ROOT, "root")
    else:
        _check("root" not in doc, "a ci upload names no root")
    try:
        collected = datetime.datetime.fromisoformat(str(doc.get("collected_at")))
    except ValueError as exc:
        raise UploadInvalid("invalid collected_at") from exc
    _check(collected.tzinfo is not None, "collected_at has no offset")
    tools = []
    for t in doc.get("tools") or ():
        _check(isinstance(t, Mapping) and set(t) <= _TOOL_KEYS, "invalid tool entry")
        _check(t.get("status") in ("ok", "error"), "invalid tool status")
        tools.append(
            ToolRun(
                _str(t.get("name"), _NAME, "tool name"),
                _str(t.get("version"), _NAME, "tool version"),
                str(t["status"]),
            )
        )
    raw_results = doc.get("results") or []
    _check(isinstance(raw_results, list) and len(raw_results) <= _MAX_RESULTS, "results")
    results = []
    for r in raw_results:
        _check(isinstance(r, Mapping) and set(r) <= _RESULT_KEYS, "invalid result entry")
        attrs = r.get("attributes") or []
        _check(isinstance(attrs, list) and len(attrs) <= _MAX_ATTRIBUTES, "attributes")
        actions = r.get("actions") or []
        _check(isinstance(actions, list) and set(actions) <= _ACTIONS, "actions")
        results.append(
            {
                "rule": _str(r.get("rule"), _RULE, "rule"),
                "address": _str(r.get("address", ""), _ADDRESS, "address"),
                "location": _str(r.get("location", ""), _LOCATION, "location"),
                "attributes": sorted({_str(a, _NAME, "attribute") for a in attrs}),
                "actions": sorted(set(actions)),
            }
        )
    return IacUpload(str(class_), root, collected, tuple(tools), tuple(results))


def _owner_tool(rule: str) -> str | None:
    for tool, owned in _TOOL_RULES.items():
        if any(rule == o or (o.endswith(":") and rule.startswith(o)) for o in owned):
            return tool
    return None


@dataclass(frozen=True)
class TransientIacFinding:
    """One FAIL an upload reports on its subject, before it is bound to a finding row."""

    rule_id: str
    address: str
    location: str
    attributes: tuple[str, ...]
    dedup_key: str

    @property
    def title(self) -> str:
        where = self.address or self.location
        return f"{self.rule_id} at {where}" if where else self.rule_id


@dataclass(frozen=True)
class Assessment:
    """What one upload evidences about its subject: the registered rules it reached, the
    gaps (rule and reason) and its failures. Only a reached rule's absence of a failure
    may resolve an earlier one."""

    reached: frozenset[str]
    gaps: tuple[Mapping[str, str], ...]
    findings: tuple[TransientIacFinding, ...]
    tool_versions: Mapping[str, str] = field(default_factory=dict)
    # The rule ids, or rule-id prefixes ending in `:`, whose findings this upload speaks
    # for: every rule of each tool that ran clean, registered or not.
    owned: tuple[str, ...] = ()


def _dedup(subject: str, rule: str, address: str, location: str) -> str:
    key = "\x1f".join((subject, rule, address or location))
    return "iac:" + hashlib.sha256(key.encode()).hexdigest()


def assess_upload(upload: IacUpload, registered: Iterable[str], *, subject: str) -> Assessment:
    """The upload's evidence against the `registered` rule ids of its producer. Pure.

    A tool reaches its registered rules when it ran with status `ok` at its pinned
    version; otherwise each of its registered rules is a gap with the reason. A result
    of a tool that did not reach its rules is dropped, never half-counted. A result
    whose rule no tool of the class owns is dropped, so one tool can never speak for
    another's rules."""
    registered = frozenset(registered)
    tools = {t.name: t for t in upload.tools}
    reached: set[str] = set()
    gaps: list[dict[str, str]] = []
    ok_tools: set[str] = set()
    for tool in _CLASS_TOOLS[upload.class_]:
        owned = sorted(r for r in registered if _owner_tool(r) == tool)
        run = tools.get(tool)
        if run is None:
            reason = "tool_not_run"
        elif run.status != "ok":
            reason = "tool_error"
        elif run.version != PINNED_TOOLS[tool]:
            reason = "tool_version_not_pinned"
        else:
            ok_tools.add(tool)
            reached.update(owned)
            continue
        gaps.extend({"rule": r, "reason": reason} for r in owned)
    findings = {}
    for r in upload.results:
        tool = _owner_tool(r["rule"])
        if tool not in ok_tools or tool not in _CLASS_TOOLS[upload.class_]:
            continue
        f = TransientIacFinding(
            r["rule"],
            r["address"],
            r["location"],
            tuple(r["attributes"]),
            _dedup(subject, r["rule"], r["address"], r["location"]),
        )
        findings.setdefault(f.dedup_key, f)
    return Assessment(
        frozenset(reached),
        tuple(gaps),
        tuple(sorted(findings.values(), key=lambda f: f.dedup_key)),
        {t.name: t.version for t in upload.tools},
        tuple(sorted(o for t in ok_tools for o in _TOOL_RULES[t])),
    )
