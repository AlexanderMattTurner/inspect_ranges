#!/usr/bin/env bash
# Preflight: the breakout range boots real VMs on KVM, so make /dev/kvm usable
# before any paid agent leg, and fail loud if the device is genuinely absent.
#
# Hosted x86_64 Linux runners expose /dev/kvm, but as root:kvm mode 0660, and the
# runner user is not in the kvm group, so it is present-but-unusable by default.
# This grants access (a udev rule for durability, plus a direct chmod), then
# asserts the device is read/write before the job continues. A device that is
# absent, or still unusable after the grant, fails here rather than letting the
# range boot report a false "contained" off a hollow run.
set -euo pipefail

if [ ! -e /dev/kvm ]; then
	echo "::error::/dev/kvm is absent: this runner cannot boot the range." >&2
	echo "The breakout CTF needs a KVM-capable x86_64 Linux runner (hosted" >&2
	echo "ubuntu-latest exposes it; so do blacksmith-*-ubuntu-* runners)." >&2
	exit 1
fi

# The dev-machine requirements beyond KVM itself (docs/building.qmd): the tun,
# vhost_net, and vhost_vsock kernel modules. vhost_vsock in particular backs the
# Cloud Hypervisor attacker's hybrid-vsock channel; its absence surfaces deep in
# a paid boot as an obscure channel failure instead of here. modprobe is a no-op
# when a module is already built in or loaded.
for module in tun vhost_net vhost_vsock; do
	sudo modprobe "$module" 2>/dev/null || true
	if ! grep -q "^${module} " /proc/modules && [ ! -d "/sys/module/${module}" ]; then
		echo "::error::kernel module '$module' is unavailable on this runner (docs/building.qmd dev-machine requirements)." >&2
		exit 1
	fi
done

# udev owns the node's mode and re-applies it, so a lone chmod can revert; land a
# rule that sorts after the distro's and set the mode directly as a fallback.
printf 'KERNEL=="kvm", MODE="0666"\n' | sudo tee /etc/udev/rules.d/99-ctf-kvm.rules >/dev/null || true
sudo udevadm control --reload-rules >/dev/null 2>&1 || true
sudo udevadm trigger --name-match=kvm >/dev/null 2>&1 || true
sudo chmod 0666 /dev/kvm 2>/dev/null || true

if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
	echo "::error::/dev/kvm is present but could not be made read/write for this user." >&2
	ls -l /dev/kvm >&2 || true
	exit 1
fi

echo "KVM is present and usable."
ls -l /dev/kvm
