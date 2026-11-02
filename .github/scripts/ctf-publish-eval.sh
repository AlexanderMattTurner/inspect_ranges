#!/usr/bin/env bash
# Publish the breakout CTF run's native .eval log, the verdict, and a
# self-contained Inspect viewer bundle to Cloudflare R2, for a durable link
# beyond GitHub's artifact retention. Mirrors the reference harness's transcript
# publish, adapted: our log is already a native .eval, so it bundles directly
# with `inspect view bundle` (no redaction/export dance).
#
# Credentials come from the environment (repo/org secrets). When any are absent
# — a fork PR, or a repo that has not configured R2 — this is a clean no-op so
# the workflow never fails on a missing bucket.
#
# Env:
#   CTF_LOG              path to the run's .eval (set by the eval step)
#   RUN_ID, RUN_ATTEMPT  the per-run key
#   R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_ACCOUNT_ID, R2_BUCKET  R2 creds
#   R2_PUBLIC_BASE_URL   optional public base (e.g. https://pub-xxxx.r2.dev) for a clickable link
set -euo pipefail

log="${CTF_LOG:-}"
if [ -z "$log" ] || [ ! -f "$log" ]; then
	echo "no .eval at CTF_LOG (${log:-unset}) — nothing to publish."
	exit 0
fi

if [ -z "${R2_ACCESS_KEY_ID:-}" ] || [ -z "${R2_SECRET_ACCESS_KEY:-}" ] ||
	[ -z "${R2_ACCOUNT_ID:-}" ] || [ -z "${R2_BUCKET:-}" ]; then
	echo "R2 credentials absent — skipping .eval upload."
	echo "Set the R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_ACCOUNT_ID and" >&2
	echo "R2_BUCKET secrets (and optionally R2_PUBLIC_BASE_URL) to enable it." >&2
	exit 0
fi

command -v rclone >/dev/null 2>&1 || sudo apt-get install -y -q rclone

# Configure the `r2` remote entirely through the environment, so no credential
# is ever written to a config file on disk.
export RCLONE_CONFIG_R2_TYPE=s3
export RCLONE_CONFIG_R2_PROVIDER=Cloudflare
export RCLONE_CONFIG_R2_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
export RCLONE_CONFIG_R2_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
export RCLONE_CONFIG_R2_ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

prefix="breakout-ctf/${RUN_ID:?}-${RUN_ATTEMPT:?}"

echo "building the Inspect viewer bundle"
uv run inspect view bundle --log-dir "$(dirname "$log")" --output-dir viewer --overwrite

echo "uploading to r2:${R2_BUCKET}/${prefix}"
rclone copyto "$log" "r2:${R2_BUCKET}/${prefix}/$(basename "$log")" --retries 5
if [ -f verdict.json ]; then
	rclone copyto verdict.json "r2:${R2_BUCKET}/${prefix}/verdict.json" --retries 5
fi
rclone copy viewer "r2:${R2_BUCKET}/${prefix}/viewer" --retries 5

{
	echo "### Breakout CTF — published to R2"
	echo ""
	echo "- eval log: \`${prefix}/$(basename "$log")\`"
	echo "- verdict: \`${prefix}/verdict.json\`"
	if [ -n "${R2_PUBLIC_BASE_URL:-}" ]; then
		echo "- [Open the run in the Inspect viewer](${R2_PUBLIC_BASE_URL%/}/${prefix}/viewer/index.html)"
	else
		echo "- viewer: \`${prefix}/viewer/index.html\` (set R2_PUBLIC_BASE_URL for a clickable link)"
	fi
} >>"${GITHUB_STEP_SUMMARY:-/dev/stdout}"

echo "published."
