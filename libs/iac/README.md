# libs/iac

> **Status: IMPLEMENTED**

Pure IaC and CI results code, imported by the platform (ingest, analysis) and run on the
customer's runner by the IaC Action (`deploy/ci-integration/github/iac-action`).

- `normalize.py`: Trivy config, separate OpenTofu refresh-only (observed drift) and
  normal (declared divergence) plan JSON, and zizmor output to rule ids, addresses,
  locations and attribute names; never values.
- `workflow_rules.py`: `ci:publish_requires_scan` and `unpinned_uses`. Only executable
  steps count (`if:` provably true, not a comment); reasons include
  `publish_without_needs_scan`, `scan_without_upload`, `scan_upload_digest_mismatch`,
  `pr_scan_without_ci_assessment` and `scan_gate_not_assessable` (a command outside the
  bounded contract: a gap, never a pass).
- `shell_contract.py`: the bounded scan and upload command contract (digest traced
  through the step's variables into the actual arguments).
- `upload.py`: the results-only upload contract and its assessment (reached rules, gaps,
  findings).
- `cli.py`: the Action's results builder. Configuration-only roots omit the plan tool,
  leaving drift and divergence not assessed. `ci --gate` is the assess-only run
  `pr-scan` makes (fails on any zizmor or `ci:publish_requires_scan` finding but the
  reviewed dangerous-triggers exception on `pr-scan.yml`). `wif.py`: the GCP workload
  identity binding.
- `remediation.py`: remediation content per rule family.

Tests: `tests/libs/iac`, `tests/deploy/test_iac_ci_workflows.py`.
Refs: docs/architecture/adrs/0108-iac-and-ci-assessment.md.
