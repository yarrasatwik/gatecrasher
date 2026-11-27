#!/usr/bin/env bash
# End-to-end Gatecrasher run against the self-hosted lab, for recording.
# Prerequisites: make lab-up lab-seed, and the storefront running (make shop).
set -euo pipefail
cd "$(dirname "$0")/.."
GC=bin/gatecrasher
step() { printf '\n\033[1;36m▸ %s\033[0m\n' "$*"; }

step "Restore the Acme Shop lab"
$GC lab reset

step "Audit: outside view + inside map + live replay"
$GC audit --parity 1000

step "Fix: review each plan and type the environment name to approve"
$GC fix-all || true

step "Re-audit after the approved fixes"
$GC audit --parity 0 || true

step "Tamper-evident record of every decision"
$GC audit-log | tail -5
