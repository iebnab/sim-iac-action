# sim-iac-action

Synthetic test fixture. The IaC and CI results Action, vendored with the results
builder (libs/iac) at the same commit. Use it at a full commit SHA:

    uses: ./.iac-action/deploy/ci-integration/github/iac-action

after checking out this repository at that SHA into .iac-action.
