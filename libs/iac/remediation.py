"""Remediation content of the IaC and CI rules: what to change and where.

Keyed by rule id or by rule-id prefix (the Trivy and zizmor rule families carry the
tool's own guidance under their id; ours names the Terraform or workflow change). Drift
and divergence name the two ways back to an agreed state: re-apply the declared
configuration, or import or adopt the live change into it. Pure data.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

__all__ = ["Remediation", "remediation_for"]


@dataclass(frozen=True)
class Remediation:
    summary: str
    steps: tuple[str, ...]
    reference: str = ""


_EXACT: Mapping[str, Remediation] = {
    "iac:drift": Remediation(
        "The live resource differs from the Terraform state: a change was made outside Terraform.",
        (
            "Decide which side is right for each attribute the finding names.",
            "If the declared configuration is right: run the locked plan and apply it "
            "from CI, which reverts the live change.",
            "If the live change is right: write it into the configuration (or run "
            "`tofu import` for a resource created outside Terraform), then plan until the "
            "drift is gone.",
            "Stop the out-of-band path that made the change.",
        ),
        "https://opentofu.org/docs/cli/commands/plan/#planning-modes",
    ),
    "iac:divergence": Remediation(
        "The declared configuration and the live estate disagree: an apply would change "
        "the resource.",
        (
            "Review the attributes and actions the finding names.",
            "Apply the reviewed configuration from the main branch through CI, or revert "
            "the configuration change that has not been applied.",
        ),
        "https://opentofu.org/docs/cli/commands/apply/",
    ),
    "ci:publish_requires_scan": Remediation(
        "A publish, sign or deploy job can run without a passing image scan of the "
        "exact digest it publishes.",
        (
            "Make every publish, sign and deploy job `needs:` the scan job, with no "
            "`if: always()` or failure condition.",
            "Remove `continue-on-error` from the scan and upload steps.",
            "Scan the build job's output digest (`needs.build.outputs.digest`), never a tag.",
            "Keep `pr-scan` on `pull_request_target` with `permissions: contents: read` "
            "on the workflow and the job, no secret, environment, `id-token`, cache, "
            "repository script or `if:`.",
            "Require `pr-scan` from GitHub Actions in the ruleset on main.",
        ),
    ),
}

_PREFIX: Mapping[str, Remediation] = {
    "iac:trivy:": Remediation(
        "Trivy found a misconfiguration in the Terraform root.",
        (
            "Open the rule's page (the id after `iac:trivy:`) for the attribute to set.",
            "Change the Terraform attribute at the reported location and apply through CI.",
        ),
        "https://avd.aquasec.com/misconfig/",
    ),
    "ci:zizmor:": Remediation(
        "zizmor found a weakness in a GitHub Actions workflow.",
        (
            "Open the audit's page (the id after `ci:zizmor:`) for the fix.",
            "Change the workflow at the reported location on a pull request.",
        ),
        "https://docs.zizmor.sh/audits/",
    ),
}


def remediation_for(rule_id: str) -> Remediation | None:
    """The remediation of a rule, or None for a rule this module does not cover."""
    if rule_id in _EXACT:
        return _EXACT[rule_id]
    for prefix, rem in _PREFIX.items():
        if rule_id.startswith(prefix):
            return rem
    return None
