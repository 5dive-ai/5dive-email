#!/usr/bin/env bash
# DIVE-8405 — the box's real filters on the CI runner, for the end-to-end run:
# rspamd as the package ships it, and ClamAV's clamd with ONE test-only
# signature (the EICAR test file, as hex so this file never reads as infected)
# and no signature download. Prints the env lines e2e.ts reads.
set -euo pipefail
exec 3>&1 1>&2   # only the env lines reach stdout ($GITHUB_ENV)
sudo apt-get update -q >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q rspamd clamav-daemon >/dev/null
sudo systemctl stop clamav-freshclam clamav-daemon 2>/dev/null || true
EICAR_HEX=58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a
printf 'E2E.Eicar-Test-Signature:0:*:%s\n' "$EICAR_HEX" >"${RUNNER_TEMP:-/tmp}/e2e.ndb"
sudo install -o clamav -g clamav -m 644 "${RUNNER_TEMP:-/tmp}/e2e.ndb" /var/lib/clamav/e2e.ndb
sudo install -d -o clamav -g clamav /run/clamav
# The stock config (socket /run/clamav/clamd.ctl, mode 666, ScanMail on); the
# unit refuses to start without the downloaded databases, so clamd directly.
sudo clamd
for _ in $(seq 60); do [[ -S /run/clamav/clamd.ctl ]] && break; sleep 1; done
[[ -S /run/clamav/clamd.ctl ]] || { sudo tail -20 /var/log/clamav/clamav.log >&2 || true; exit 1; }
sudo systemctl restart rspamd
for _ in $(seq 60); do curl -sf http://127.0.0.1:11333/ping >/dev/null && break; sleep 1; done
curl -sf http://127.0.0.1:11333/ping >/dev/null || { sudo journalctl -u rspamd --no-pager | tail -20 >&2; exit 1; }
echo "EMAIL_E2E_CLAMD=/run/clamav/clamd.ctl" >&3
echo "EMAIL_E2E_RSPAMD=http://127.0.0.1:11333" >&3
