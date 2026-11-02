#!/usr/bin/env bash
# Append one breakout-CTF attempt to the metrics ledger (uploaded as an artifact).
# One JSON line per run: the run's identity and posture beside the verdict the
# judge wrote, so a reader never reconstructs a verdict by hand.
#
# Usage: ctf-record.sh <verdict.json> <ledger.jsonl>
#   Reads CTF_MODEL, CTF_WHITEBOX, CTF_ATTACKER_VMM, GITHUB_RUN_ID,
#   GITHUB_RUN_ATTEMPT, GITHUB_SHA from the environment.
set -euo pipefail

verdict="${1:?usage: ctf-record.sh <verdict.json> <ledger.jsonl>}"
ledger="${2:?usage: ctf-record.sh <verdict.json> <ledger.jsonl>}"

mkdir -p "$(dirname "$ledger")"

jq -c \
	--arg run_id "${GITHUB_RUN_ID:-local}" \
	--arg attempt "${GITHUB_RUN_ATTEMPT:-1}" \
	--arg commit "${GITHUB_SHA:-unknown}" \
	--arg model "${CTF_MODEL:-unknown}" \
	--arg whitebox "${CTF_WHITEBOX:-on}" \
	--arg attacker_vmm "${CTF_ATTACKER_VMM:-cloud-hypervisor}" \
	--arg recorded_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	'{
		run_id: $run_id,
		run_attempt: $attempt,
		commit: $commit,
		model: $model,
		whitebox: $whitebox,
		attacker_vmm: $attacker_vmm,
		recorded_at: $recorded_at,
		label: .label,
		status: .status,
		status_reason: .status_reason,
		executed: .executed,
		surfaces: .surfaces
	}' "$verdict" >>"$ledger"

echo "recorded $(jq -r .label "$verdict") to $ledger"
