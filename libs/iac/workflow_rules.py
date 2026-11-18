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
- only executable steps count: a scan or upload step (or job) whose `if:` is not
  provably true, and any scan or upload named only in a comment, never counts; the scan
  job must upload, and the upload reads the same build digest expressions the scan did;
- a scan or upload is recognized only as a bounded command (`libs/iac/shell_contract.py`):
  one `trivy image` (or the pinned scan Action) whose reference is `<repository>@<build
  digest expression>` traced through the step's own variables, and one `curl --fail` to
  the ingest API; `echo`, quoted text, shell control flow, `&&`, `||`, pipes, subshells,
  `set +e`, an unknown option or a nested shell is `scan_gate_not_assessable`, never
  passed;
- the scanned reference is a needed job's output (the build output digest), never a
  literal or a tag;
- the required pull-request check `pr-scan` runs the CI Action in assess-only mode over
  the merge commit's workflows (`pr_scan_without_ci_assessment`), holds no credential
  (no `id-token` or other write permission, no secret, no environment, no `if:`, checkout
  without persisted credentials), uses no cache and no repository script, and pins
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

from libs.iac.shell_contract import UPLOAD_ENDPOINT, RunAnalysis, analyse_run, bound_digest

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


_NESTED_SHELL = re.compile(r"\b(eval|xargs)\b|\b(bash|sh|zsh)\s+-\w*c\b")


def _steps(job: Mapping) -> list[Mapping]:
    return [s for s in job.get("steps") or () if isinstance(s, Mapping)]


def _with(step: Mapping) -> Mapping:
    """The step's `with` mapping, empty when it has none."""
    values = step.get("with")
    return values if isinstance(values, Mapping) else {}


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


def _provably_true(cond: object) -> bool:
    """An `if:` that certainly runs the step or job: absent, or literally true
    (`success()` is true on the path to a gated job). Anything else - false, or an
    expression this cannot evaluate - is not provably true."""
    if cond is None or cond is True:
        return True
    if not isinstance(cond, str):
        return False
    inner = cond.strip()
    if inner.startswith("${{") and inner.endswith("}}"):
        inner = inner[3:-2].strip()
    return inner in ("true", "success()")


def _code(step: Mapping) -> str:
    """The step's shell lines without comments: full-line comments and trailing
    ` # ...` comments never count as commands."""
    lines = []
    for line in str(step.get("run") or "").splitlines():
        if line.strip().startswith("#"):
            continue
        lines.append(re.sub(r"\s#.*$", "", line))
    return "\n".join(lines)


def _unsupported_shape(step: Mapping) -> bool:
    """A command shape the assessor cannot follow (a nested shell, `eval`, `xargs`, a
    shell other than bash or sh): the gate is not assessed, never passed."""
    shell = step.get("shell")
    if shell is not None and str(shell).split()[0] not in ("bash", "sh"):
        return True
    return bool(_NESTED_SHELL.search(_code(step)))


def _is_scan_step(step: Mapping) -> bool:
    """An executable step that runs a scan: not skipped by an `if:`, and the scan is in
    a command or the Action it uses, not in a comment."""
    if not _provably_true(step.get("if")):
        return False
    text = "\n".join([_code(step), str(step.get("uses") or ""), str(dict(_with(step)))])
    return bool(_SCAN_TOOL.search(text))


def _is_upload_step(step: Mapping) -> bool:
    """An executable step whose commands post to the ingest API."""
    if not _provably_true(step.get("if")):
        return False
    code = _code(step)
    return bool(re.search(r"\b(curl|wget)\b", code)) and bool(UPLOAD_ENDPOINT.search(code))


def _is_scan_job(job: Mapping) -> bool:
    """A job that scans and does not itself publish: a publish job that also runs Trivy
    (to build an attestation predicate) is still judged as a publish job. A job whose
    own `if:` is not provably true is no scan."""
    if not _provably_true(job.get("if")):
        return False
    return any(_is_scan_step(s) for s in _steps(job)) and not _is_publish_job(job)


def _is_publish_job(job: Mapping) -> bool:
    for step in _steps(job):
        text = _step_text(step)
        if _PUBLISH.search(text):
            return True
        uses = str(step.get("uses") or "")
        with_ = _with(step)
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


def _env_of(*owners: Mapping) -> dict[str, str]:
    """The variables the given workflow, job and step `env` blocks set, later owners
    overriding earlier ones."""
    scope: dict[str, str] = {}
    for owner in owners:
        env = owner.get("env")
        if isinstance(env, Mapping):
            scope.update({str(k): str(v) for k, v in env.items()})
    return scope


def _contract(step: Mapping, scope: Mapping[str, str]) -> RunAnalysis:
    """What the step's script, or the pinned scan Action it uses, proves."""
    env = {**scope, **_env_of(step)}
    run = analyse_run(_code(step), env)
    if "trivy-action" not in str(step.get("uses") or ""):
        return run
    with_ = _with(step)
    if run.gap or with_.get("scan-type") not in (None, "image"):
        return RunAnalysis(gap=True)
    ref = str(with_.get("image-ref") or "")
    return RunAnalysis((*run.scans, ref), run.upload_exprs)


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
            scanned: set[str] = set()
            uploaded: set[str] = set()
            uploads = 0
            scope = _env_of(workflow, job)
            for step in _steps(job):
                is_scan = _is_scan_step(step)
                is_upload = _is_upload_step(step)
                if not (is_scan or is_upload):
                    continue
                uploads += is_upload
                if _truthy_flag(step.get("continue-on-error")):
                    out.append(_v(path, name, "continue_on_error_on_scan"))
                contract = _contract(step, scope)
                if contract.gap or _unsupported_shape(step) or (is_scan and not contract.scans):
                    out.append(_v(path, name, "scan_gate_not_assessable"))
                    continue
                for ref in contract.scans:
                    expr = bound_digest(ref)
                    refs = {m.group(1) for m in _OUTPUT_REF.finditer(expr or "")}
                    if not refs or not refs <= _ancestors(jobs, name):
                        out.append(_v(path, name, "scan_of_other_digest"))
                    elif expr:
                        scanned.add(expr)
                uploaded |= contract.upload_exprs
            if not uploads:
                out.append(_v(path, name, "scan_without_upload"))
            elif scanned and scanned != uploaded:
                out.append(_v(path, name, "scan_upload_digest_mismatch"))
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


def _is_ci_assessment(step: Mapping) -> bool:
    """A step that runs the CI Action's assessment of the workflows without uploading:
    always runs, cannot be swallowed, and is the `ci` class in assess-only mode."""
    with_ = _with(step)
    return (
        "/iac-action@" in str(step.get("uses") or "")
        and "if" not in step
        and not _truthy_flag(step.get("continue-on-error"))
        and with_.get("class") == "ci"
        and str(with_.get("assess-only")).lower() == "true"
    )


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
    if not any(_is_ci_assessment(s) for s in _steps(job)):
        out.append(_v(path, PR_SCAN_JOB, "pr_scan_without_ci_assessment"))
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
        with_ = _with(step)
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
