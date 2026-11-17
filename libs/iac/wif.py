"""The GitHub OIDC workload identity binding of the IaC Action's Google Cloud access,
derived from the repository's live OIDC subject configuration.

A repository that uses an immutable subject (`GET /repos/{owner}/{repo}/actions/oidc/
customization/sub` answers `use_immutable_subject: true`) issues tokens whose `sub`
starts `repo:<owner>@<owner_id>/<repo>@<repo_id>`, never the name-based
`repo:<owner>/<repo>:ref:...`. A binding written against the name-based subject would
match no token; one written against names alone would match a repository re-created
under the same name. The attribute condition therefore binds the numeric repository and
owner ids, `refs/heads/main` and the workflow's `workflow_ref`, and is derived only after
the live configuration is read and checked against the registered ids.

Pure: the caller reads the customization endpoint and passes its JSON in.
Refs: docs/architecture/adrs/0108-iac-and-ci-assessment.md.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

__all__ = ["WifBinding", "WifConfigError", "derive_binding"]

MAIN_REF = "refs/heads/main"
_WORKFLOW_REF = re.compile(
    r"^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+/\.github/workflows/[A-Za-z0-9_.\-]+@refs/heads/main$"
)


class WifConfigError(ValueError):
    """The live subject configuration does not support an id-bound condition."""


@dataclass(frozen=True)
class WifBinding:
    subject_prefix: str
    attribute_mapping: Mapping[str, str]
    attribute_condition: str


def derive_binding(
    customization: Mapping[str, object],
    *,
    owner: str,
    repository: str,
    repository_id: int,
    repository_owner_id: int,
    workflow_ref: str,
) -> WifBinding:
    """The provider's attribute mapping and condition for one repository's workflow.

    Refuses a repository without an immutable subject (its tokens would carry the
    name-based subject this binding is meant never to rely on), and a workflow_ref that
    is not an ordinary workflow file on `main` of that repository. Pure."""
    if customization.get("use_immutable_subject") is not True:
        raise WifConfigError("the repository does not use an immutable OIDC subject")
    if not _WORKFLOW_REF.match(workflow_ref) or not workflow_ref.startswith(
        f"{owner}/{repository}/"
    ):
        raise WifConfigError("workflow_ref is not a workflow of this repository on main")
    if "'" in workflow_ref:
        raise WifConfigError("workflow_ref cannot be quoted")
    prefix = f"repo:{owner}@{repository_owner_id}/{repository}@{repository_id}"
    mapping = {
        "google.subject": "assertion.sub",
        "attribute.repository_id": "assertion.repository_id",
        "attribute.repository_owner_id": "assertion.repository_owner_id",
        "attribute.ref": "assertion.ref",
        "attribute.workflow_ref": "assertion.workflow_ref",
    }
    condition = " && ".join(
        (
            f"assertion.repository_id == '{repository_id}'",
            f"assertion.repository_owner_id == '{repository_owner_id}'",
            f"assertion.ref == '{MAIN_REF}'",
            f"assertion.workflow_ref == '{workflow_ref}'",
        )
    )
    return WifBinding(prefix, mapping, condition)
