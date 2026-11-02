#!/usr/bin/env bash
# Preflight: the breakout range boots real VMs, so refuse before any paid agent
# leg if this runner has no KVM. Fails loud rather than running a hollow eval.
set -euo pipefail

if [ ! -e /dev/kvm ]; then
	echo "::error::/dev/kvm is absent: this runner cannot boot the range." >&2
	echo "The breakout CTF needs a KVM-capable runner (hosted x86_64 Linux with" >&2
	echo "nested virtualization, or a self-hosted KVM host)." >&2
	exit 1
fi

if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
	echo "::error::/dev/kvm is present but not read/write for this user." >&2
	ls -l /dev/kvm >&2 || true
	exit 1
fi

echo "KVM is present and usable."
