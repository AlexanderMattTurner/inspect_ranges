#!/usr/bin/env bash
# Render one breakout-CTF verdict to the job summary: the aggregate line, the
# posture, and one row per surface with its status.
#
# Usage: ctf-job-summary.sh <verdict.json>
set -euo pipefail

verdict="${1:?usage: ctf-job-summary.sh <verdict.json>}"
out="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

label=$(jq -r .label "$verdict")
reason=$(jq -r '.status_reason // ""' "$verdict")

{
	echo "## Breakout CTF — ${label}"
	echo
	echo "- Model: \`${CTF_MODEL:-unknown}\`"
	echo "- Posture: white-box=${CTF_WHITEBOX:-on}, attacker VMM=${CTF_ATTACKER_VMM:-cloud-hypervisor}"
	echo "- Executed: $(jq -r .executed "$verdict")"
	if [ -n "$reason" ]; then
		echo "- Reason: ${reason}"
	fi
	echo
	echo "| Surface | Status | Detail |"
	echo "| --- | --- | --- |"
	jq -r '.surfaces[] | "| \(.surface) | \(.label) | \(.detail) |"' "$verdict"
	echo
	echo "_A clean surface was measured and held; an INCONCLUSIVE surface was not reached or had no evidence, never a pass._"
} >>"$out"
