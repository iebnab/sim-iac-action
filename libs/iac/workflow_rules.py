"""The CI workflow rules that run customer-side, over a repository's own workflow files.

The platform never reads repository contents (workflow files are repository content),
so these rules run in the customer's CI Action next to zizmor and only their results
are uploaded. Every function here is pure: parsed workflow documents in, violations out.

`ci:publish_requires_scan` (one rule id, several violation reasons) holds the scan gate
before publish:

- every publish, sign or deploy job depends (transitively, through `needs`) on a scan
  job, and has no `if:` that runs it after a failure (`always()`, `failure()`,
  `cancelled()`);
- no scan or upload step, and no scan job, carries `continue-on-error`;
- the scanned reference is a needed job's output (the build output digest), never a
  literal or a tag;
- the required pull-request check `pr-scan` holds no credential (no `id-token` or other
  write permission, no secret, no environment, no `if:`, checkout without persisted
  credentials), uses no cache and no repository script, and pins
  `permissions: contents: read` on its workflow and its job;
- the `main` ruleset requires `pr-scan` from the GitHub Actions source.

`unpinned_uses` is the pinning rule the platform applies to every workflow it writes
and to the Action itself: each `uses:` is a local path, a full 40-hex commit SHA or a
container image by sha256 digest.
Refs: docs/architecture/adrs/0108-iac-and-ci-assessment.md.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

__all__ = [
    "PR_SCAN_JOB",
    "RULE_PUBLISH_REQUIRES_SCAN",
    "Violation",
    "assess_publish_requires_scan",
    "unpinned_uses",
]

RULE_PUBLISH_REQUIRES_SCAN = "ci:publish_requires_scan"
PR_SCAN_JOB = "pr-scan"
# The GitHub Actions app id a ruleset names as the source of a required check.
GITHUB_ACTIONS_APP_ID = 15368

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
# A needed job's output, by attribute (`needs.build.outputs.digest`) or by index
# (`needs.build.outputs[format('digest-{0}', matrix.image)]`).
_OUTPUT_REF = re.compile(r"needs\.([A-Za-z0-9_-]+)\.outputs(\.[A-Za-z0-9_-]+|\[)")
_FAILURE_COND = re.compile(r"\b(always|failure|cancelled)\s*\(")
# A Trivy invocation that scans something; installing or printing its version is not.
_SCAN_TOOL = re.compile(r"\btrivy\s+(image|fs|rootfs|sbom|repo|config|vm|k8s)\b|trivy-action")
_PUBLISH = re.compile(
    r"\b(cosign\s+(sign|attest)|crane\s+(copy|cp|push|tag)|skopeo\s+copy|"
    r"docker\s+push|gcloud\s+run\s+deploy|kubectl\s+(apply|set\s+image|rollout)|"
    r"helm\s+(upgrade|install)|(tofu|terraform)\s+apply)\b"
)
# A command that runs code from the checked-out tree rather than a fixed command
# written in the workflow: a relative path, a shell or interpreter over a file, a
# build tool, a package script.
_INTERPRETER = "pyth" + "on"
_REPO_SCRIPT = re.compile(
    r"(^|[\s;&|(])(\./\S|(bash|sh|zsh)\s+[^-\s]|make\b|"
    + _INTERPRETER
    + r"3?\s+[^-\s]|node\s+\S|npm\s+run\b|yarn\s+\S|pnpm\s+\S|just\b|task\b)"
)
_FIXED_BUILD = re.compile(r"^\s*docker\s+build\b")
_CACHE_ACTIONS = ("actions/cache",)


@dataclass(frozen=True, order=True)
class Violation:
    """One failure of a rule at one place: the workflow file, the job (empty for a
    workflow-level or ruleset violation) and why."""

    rule: str
    workflow: str
    job: str
    reason: str


def _steps(job: Mapping) -> list[Mapping]:
    return [s for s in job.get("steps") or () if isinstance(s, Mapping)]


def _step_text(step: Mapping) -> str:
    parts = [str(step.get("run") or ""), str(step.get("uses") or "")]
    for key in ("with", "env"):
        values = step.get(key)
        if isinstance(values, Mapping):
            parts.extend(f"{k}={v}" for k, v in values.items())
    return "\n".join(parts)


def _needs(job: Mapping) -> tuple[str, ...]:
    needs = job.get("needs")
    if isinstance(needs, str):
        return (needs,)
    if isinstance(needs, list):
        return tuple(str(n) for n in needs)
    return ()


def _truthy_flag(value: object) -> bool:
    """`continue-on-error` counts unless it is literally false: an expression may be
    true at run time."""
    return value not in (None, False, "false")


def _is_scan_step(step: Mapping) -> bool:
    return bool(_SCAN_TOOL.search(_step_text(step)))


def _is_upload_step(step: Mapping) -> bool:
    return "api/ingest" in _step_text(step) or "upload" in str(step.get("id") or "")


def _is_scan_job(job: Mapping) -> bool:
    """A job that scans and does not itself publish: a publish job that also runs Trivy
    (to build an attestation predicate) is still judged as a publish job."""
    return any(_is_scan_step(s) for s in _steps(job)) and not _is_publish_job(job)


def _is_publish_job(job: Mapping) -> bool:
    for step in _steps(job):
        text = _step_text(step)
        if _PUBLISH.search(text):
            return True
        uses = str(step.get("uses") or "")
        with_ = step.get("with") if isinstance(step.get("with"), Mapping) else {}
        if "build-push-action" in uses and str(with_.get("push", "")).lower() == "true":
            return True
    return False


def _ancestors(jobs: Mapping[str, Mapping], name: str) -> set[str]:
    seen: set[str] = set()
    stack = list(_needs(jobs.get(name) or {}))
    while stack:
        n = stack.pop()
        if n in seen:
            continue
        seen.add(n)
        stack.extend(_needs(jobs.get(n) or {}))
    return seen


def _triggers(workflow: Mapping) -> set[str]:
    # PyYAML reads the bare key `on` as the boolean True.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, Mapping):
        return {str(t) for t in on}
    return set()


def _release_chain(path: str, workflow: Mapping) -> list[Violation]:
    jobs = workflow.get("jobs") or {}
    out: list[Violation] = []
    scan_jobs = {n for n, j in jobs.items() if isinstance(j, Mapping) and _is_scan_job(j)}
    for name, job in jobs.items():
        if not isinstance(job, Mapping) or name == PR_SCAN_JOB:
            continue
        upstream_of_scan = any(name in _ancestors(jobs, s) for s in scan_jobs)
        if name in scan_jobs:
            if _truthy_flag(job.get("continue-on-error")):
                out.append(_v(path, name, "continue_on_error_on_scan"))
            for step in _steps(job):
                if (_is_scan_step(step) or _is_upload_step(step)) and _truthy_flag(
                    step.get("continue-on-error")
                ):
                    out.append(_v(path, name, "continue_on_error_on_scan"))
                if _is_scan_step(step):
                    refs = {m.group(1) for m in _OUTPUT_REF.finditer(_step_text(step))}
                    if not refs or not refs <= _ancestors(jobs, name):
                        out.append(_v(path, name, "scan_of_other_digest"))
            continue
        if not _is_publish_job(job) or upstream_of_scan:
            continue
        if not (_ancestors(jobs, name) & scan_jobs):
            out.append(_v(path, name, "publish_without_needs_scan"))
        cond = job.get("if")
        if cond is not None and _FAILURE_COND.search(str(cond)):
            out.append(_v(path, name, "if_always_on_publish"))
        if _truthy_flag(job.get("continue-on-error")):
            out.append(_v(path, name, "continue_on_error_on_publish"))
    return out


def _read_only(perms: object) -> bool:
    return isinstance(perms, Mapping) and dict(perms) == {"contents": "read"}


def _pr_scan(path: str, workflow: Mapping) -> list[Violation]:
    jobs = workflow.get("jobs") or {}
    job = jobs.get(PR_SCAN_JOB)
    if not isinstance(job, Mapping):
        return []
    out: list[Violation] = []
    if "pull_request_target" not in _triggers(workflow):
        out.append(_v(path, PR_SCAN_JOB, "pr_scan_not_from_main_copy"))
    if not _read_only(workflow.get("permissions")) or not _read_only(job.get("permissions")):
        out.append(_v(path, PR_SCAN_JOB, "pr_scan_permissions_not_pinned"))
    if "if" in job:
        out.append(_v(path, PR_SCAN_JOB, "pr_scan_with_credentials"))
    if job.get("environment") is not None:
        out.append(_v(path, PR_SCAN_JOB, "pr_scan_with_credentials"))
    perms = job.get("permissions")
    if isinstance(perms, Mapping) and "id-token" in perms:
        out.append(_v(path, PR_SCAN_JOB, "pr_scan_with_credentials"))
    if "secrets." in repr(job):
        out.append(_v(path, PR_SCAN_JOB, "pr_scan_with_credentials"))
    for step in _steps(job):
        uses = str(step.get("uses") or "")
        with_ = step.get("with") if isinstance(step.get("with"), Mapping) else {}
        if (
            uses.startswith("actions/checkout@")
            and str(with_.get("persist-credentials", "true")).lower() != "false"
        ):
            out.append(_v(path, PR_SCAN_JOB, "pr_scan_with_credentials"))
        text = _step_text(step)
        if (
            uses.startswith(_CACHE_ACTIONS)
            or (uses.startswith("actions/setup-") and "cache" in with_)
            or "type=gha" in text
            or "cache-from" in with_
            or "cache-to" in with_
        ):
            out.append(_v(path, PR_SCAN_JOB, "cache_in_pr_scan"))
        if uses.startswith("./"):
            out.append(_v(path, PR_SCAN_JOB, "repo_script_in_pr_scan"))
        for line in str(step.get("run") or "").splitlines():
            if _FIXED_BUILD.match(line):
                continue
            if _REPO_SCRIPT.search(line):
                out.append(_v(path, PR_SCAN_JOB, "repo_script_in_pr_scan"))
                break
    return out


def _ruleset(ruleset: Mapping | None) -> list[Violation]:
    if ruleset is None:
        return []
    for rule in ruleset.get("rules") or ():
        if not isinstance(rule, Mapping) or rule.get("type") != "required_status_checks":
            continue
        params = rule.get("parameters") or {}
        for check in params.get("required_status_checks") or ():
            if (
                isinstance(check, Mapping)
                and check.get("context") == PR_SCAN_JOB
                and check.get("integration_id") == GITHUB_ACTIONS_APP_ID
            ):
                return []
    return [_v("ruleset", "", "ruleset_without_scan_check")]


def _v(path: str, job: str, reason: str) -> Violation:
    return Violation(RULE_PUBLISH_REQUIRES_SCAN, path, job, reason)


def assess_publish_requires_scan(
    workflows: Mapping[str, Mapping], ruleset: Mapping | None = None
) -> list[Violation]:
    """Every violation of `ci:publish_requires_scan` over the repository's workflow
    files (path to parsed document) and, when given, the ruleset on `main`. An empty
    list is a pass. Pure."""
    out: set[Violation] = set()
    for path, wf in workflows.items():
        if not isinstance(wf, Mapping):
            continue
        out.update(_release_chain(path, wf))
        out.update(_pr_scan(path, wf))
    out.update(_ruleset(ruleset))
    return sorted(out)


def _uses_of(doc: Mapping) -> Iterable[str]:
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, Mapping):
            continue
        if isinstance(job.get("uses"), str):
            yield job["uses"]
        for step in _steps(job):
            if isinstance(step.get("uses"), str):
                yield step["uses"]
    runs = doc.get("runs")
    if isinstance(runs, Mapping):
        for step in runs.get("steps") or ():
            if isinstance(step, Mapping) and isinstance(step.get("uses"), str):
                yield step["uses"]


def unpinned_uses(doc: Mapping) -> list[str]:
    """Every `uses:` of a workflow or composite action that is not pinned: a local path,
    `owner/repo[/path]@<40-hex sha>` or `docker://...@sha256:<digest>` pass. Pure."""
    bad = []
    for uses in _uses_of(doc):
        if uses.startswith("./"):
            continue
        if uses.startswith("docker://"):
            if not _DIGEST.search(uses):
                bad.append(uses)
            continue
        _, _, ref = uses.partition("@")
        if not _SHA.match(ref):
            bad.append(uses)
    return bad
