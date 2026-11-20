#!/usr/bin/env bash
# Plan one declared Terraform root and scan it, writing results files only.
#
#   plan.sh <root dir> <out dir> [plan|config-only]
#
# Two locked plans are kept locally: refresh-only observes changes since the recorded
# state, and the ordinary plan compares declared configuration to the refreshed estate.
# Neither plan is applied. Only the results builder reads their JSON; source, values
# and tool diagnostics never enter the job log or upload.
#
# Writes <out>/status.env with TRIVY_STATUS and PLAN_STATUS (ok, error or skipped).
set -uo pipefail

root="$1"
out="$2"
mode="${3:-plan}"
mkdir -p "$out"
trivy_status=ok
plan_status=skipped

if [ "$mode" = plan ]; then
  plan_status=ok
  if ! tofu -chdir="$root" init -input=false -lock=true -no-color >"$out/init.log" 2>&1; then
    plan_status=error
  fi
  for kind in refresh plan; do
    if [ "$plan_status" != ok ]; then break; fi
    args=()
    if [ "$kind" = refresh ]; then args=(-refresh-only); fi
    rc=0
    tofu -chdir="$root" plan -input=false -lock=true -refresh=true -detailed-exitcode \
      "${args[@]}" -no-color -out="$out/$kind.bin" >"$out/$kind.log" 2>&1 || rc=$?
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
      plan_status=error
    elif ! tofu -chdir="$root" show -json -no-color "$out/$kind.bin" \
        >"$out/$kind.json" 2>"$out/show.log"; then
      plan_status=error
    fi
  done
elif [ "$mode" != config-only ]; then
  echo "unknown plan mode" >&2
  exit 2
fi
rm -f "$out/refresh.bin" "$out/plan.bin" "$out/init.log" "$out/refresh.log" \
  "$out/plan.log" "$out/show.log"

if ! trivy config --quiet --format json --output "$out/trivy.json" "$root" \
    >/dev/null 2>"$out/trivy.log"; then
  trivy_status=error
fi
rm -f "$out/trivy.log"

printf 'TRIVY_STATUS=%s\nPLAN_STATUS=%s\n' "$trivy_status" "$plan_status" >"$out/status.env"
echo "plan: ${plan_status}; trivy config: ${trivy_status}"
