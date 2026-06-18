#!/usr/bin/env bash
# Creates a 2 GB swap file if none exists, and sets swappiness=10.
# Safe to run multiple times (idempotent).
set -euo pipefail

if swapon --show | grep -q /swapfile; then
  echo "Swap already active on /swapfile — nothing to do."
  exit 0
fi

fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile

grep -qxF '/swapfile none swap sw 0 0' /etc/fstab \
  || echo '/swapfile none swap sw 0 0' >> /etc/fstab

grep -qxF 'vm.swappiness=10' /etc/sysctl.conf \
  || echo 'vm.swappiness=10' >> /etc/sysctl.conf
sysctl -w vm.swappiness=10

echo "Swap configured (2 GB, swappiness=10)."
