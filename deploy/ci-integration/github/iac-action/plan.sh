#!/usr/bin/env bash
# Plan one declared Terraform root and scan it, writing results files only.
#
#   plan.sh <root dir> <out dir>
#
# The plan goes to a file (`-out`) and is read only by `tofu show -json` into
# <out>/plan.json, which the results builder reduces to addresses, actions and attribute
# names. Nothing of the plan or of the tools' diagnostics is printed: the job log carries
# only each step's status, because a plan can hold any value of the configuration or the
# state. Locking stays on (`-lock=true`): the state lock object is taken and released on
# the backend like any locked plan.
#
# Writes <out>/status.env with TRIVY_STATUS and PLAN_STATUS (ok or error).
set -uo pipefail

root="$1"
out="$2"
mkdir -p "$out"
trivy_status=ok
plan_status=ok

if ! tofu -chdir="$root" init -input=false -lock=true -no-color >"$out/init.log" 2>&1; then
  plan_status=error
fi
if [ "$plan_status" = ok ]; then
  # -detailed-exitcode: 0 no changes, 2 changes, anything else a failed plan.
  rc=0
  tofu -chdir="$root" plan -input=false -lock=true -refresh=true -detailed-exitcode \
    -no-color -out="$out/plan.bin" >"$out/plan.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    plan_status=error
  fi
fi
if [ "$plan_status" = ok ] && ! tofu -chdir="$root" show -json -no-color "$out/plan.bin" \
    >"$out/plan.json" 2>"$out/show.log"; then
  plan_status=error
fi
rm -f "$out/plan.bin" "$out/init.log" "$out/plan.log" "$out/show.log"

if ! trivy config --quiet --format json --output "$out/trivy.json" "$root" \
    >/dev/null 2>"$out/trivy.log"; then
  trivy_status=error
fi
rm -f "$out/trivy.log"

printf 'TRIVY_STATUS=%s\nPLAN_STATUS=%s\n' "$trivy_status" "$plan_status" >"$out/status.env"
echo "plan: ${plan_status}; trivy config: ${trivy_status}"
