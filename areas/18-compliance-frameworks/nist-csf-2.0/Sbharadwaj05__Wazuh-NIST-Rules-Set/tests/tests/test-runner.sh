#!/usr/bin/env bash
# tests/test-runner.sh
#
# Drives wazuh-logtest against the sample logs in tests/sample-logs and checks
# that each rule fires on its trigger log and stays silent on its benign log.
#
# Must be run from the repository root, on a machine with the Wazuh manager
# installed, after the rules, decoders and lists have been deployed:
#
#   sudo ./tests/test-runner.sh
#
# Exits non-zero if any test fails or errors, so it is safe to use in CI.

LOGTEST=${LOGTEST:-/var/ossec/bin/wazuh-logtest}

PASS=0
FAIL=0
ERROR=0
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

preflight() {
  if [ ! -x "$LOGTEST" ]; then
    echo -e "${RED}[ABORT]${NC} $LOGTEST not found or not executable."
    echo "        This script needs a local Wazuh manager. Set LOGTEST=/path/to/wazuh-logtest"
    echo "        to point it elsewhere. For checks that run without a manager, use:"
    echo "            python3 tests/evidence_validator.py"
    exit 2
  fi

  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ABORT]${NC} wazuh-logtest needs root. Re-run with: sudo $0"
    exit 2
  fi

  if ! printf 'preflight\n' | "$LOGTEST" 2>&1 | grep -q "Phase"; then
    echo -e "${RED}[ABORT]${NC} $LOGTEST ran but produced no phase output."
    echo "        Check that wazuh-manager is running and the ruleset compiles:"
    echo "            /var/ossec/bin/wazuh-analysisd -t"
    exit 2
  fi
}

# Extract the rule IDs wazuh-logtest reported, one per line.
# Matches both "id: '100018'" and "id: 100018".
extract_rule_ids() {
  sed -nE "s/^[[:space:]]*id:[[:space:]]*'?([0-9]+)'?.*/\1/p"
}

run_test() {
  local rule_id=$1
  local log_file=$2
  local should_trigger=$3  # "true" or "false"
  local test_name=$4

  if [ ! -f "$log_file" ]; then
    echo -e "${YELLOW}[ERROR]${NC} $test_name - sample log not found: $log_file"
    ERROR=$((ERROR + 1))
    return
  fi

  # Feed the whole file in one session so frequency rules keep their state.
  local raw
  raw=$("$LOGTEST" < "$log_file" 2>&1)

  # A silent rule and a broken harness look identical if we only check for the
  # absence of an ID, which is how every benign test used to pass vacuously.
  # Require proof that logtest actually processed the input.
  if ! printf '%s' "$raw" | grep -q "Phase"; then
    echo -e "${YELLOW}[ERROR]${NC} $test_name - wazuh-logtest produced no output for $log_file"
    ERROR=$((ERROR + 1))
    return
  fi

  local fired
  fired=$(printf '%s\n' "$raw" | extract_rule_ids)

  # Exact match on the whole line — a substring match would let rule 1000180
  # satisfy a test for rule 100018.
  if printf '%s\n' "$fired" | grep -Fxq "$rule_id"; then
    if [ "$should_trigger" = "true" ]; then
      echo -e "${GREEN}[PASS]${NC} $test_name - Rule $rule_id fired as expected"
      PASS=$((PASS + 1))
    else
      echo -e "${RED}[FAIL]${NC} $test_name - Rule $rule_id fired on benign log (false positive)"
      FAIL=$((FAIL + 1))
    fi
  else
    if [ "$should_trigger" = "true" ]; then
      echo -e "${RED}[FAIL]${NC} $test_name - Rule $rule_id did NOT fire (expected trigger)"
      echo "        rules that did fire: ${fired//$'\n'/ }"
      FAIL=$((FAIL + 1))
    else
      echo -e "${GREEN}[PASS]${NC} $test_name - Rule $rule_id correctly silent on benign log"
      PASS=$((PASS + 1))
    fi
  fi
}

preflight

# Run all tests
run_test 100018 "tests/sample-logs/de-cm-01/ssh-bruteforce/trigger.log" true "SSH brute force - trigger"
run_test 100018 "tests/sample-logs/de-cm-01/ssh-bruteforce/benign.log" false "SSH brute force - benign"

run_test 100002 "tests/sample-logs/pr-aa-05/sudo-privilege-escalation/trigger.log" true "Sudo privilege escalation - trigger"
run_test 100002 "tests/sample-logs/pr-aa-05/sudo-privilege-escalation/benign.log" false "Sudo privilege escalation - benign"

run_test 100003 "tests/sample-logs/pr-aa-01/new-user-account/trigger.log" true "New user account - trigger"
run_test 100003 "tests/sample-logs/pr-aa-01/new-user-account/benign.log" false "New user account - benign"

run_test 100004 "tests/sample-logs/de-cm-09/cron-modification/trigger.log" true "Cron job modification - trigger"
run_test 100004 "tests/sample-logs/de-cm-09/cron-modification/benign.log" false "Cron job modification - benign"

run_test 100005 "tests/sample-logs/de-cm-01/outbound-rare-port/trigger.log" true "Outbound rare port - trigger"
run_test 100005 "tests/sample-logs/de-cm-01/outbound-rare-port/benign.log" false "Outbound rare port - benign"

run_test 100006 "tests/sample-logs/pr-ds-01/passwd-shadow-read/trigger.log" true "Passwd shadow read - trigger"
run_test 100006 "tests/sample-logs/pr-ds-01/passwd-shadow-read/benign.log" false "Passwd shadow read - benign"

run_test 100007 "tests/sample-logs/de-ae-02/web-shell-indicators/trigger.log" true "Web shell indicators - trigger"
run_test 100007 "tests/sample-logs/de-ae-02/web-shell-indicators/benign.log" false "Web shell indicators - benign"

run_test 100008 "tests/sample-logs/de-ae-03/large-file-exfiltration/trigger.log" true "Large file exfiltration - trigger"
run_test 100008 "tests/sample-logs/de-ae-03/large-file-exfiltration/benign.log" false "Large file exfiltration - benign"

run_test 100009 "tests/sample-logs/de-cm-09/windows-audit-cleared/trigger.log" true "Windows audit cleared - trigger"
run_test 100009 "tests/sample-logs/de-cm-09/windows-audit-cleared/benign.log" false "Windows audit cleared - benign"

run_test 100010 "tests/sample-logs/de-cm-01/psexec-lateral-movement/trigger.log" true "PSExec lateral movement - trigger"
run_test 100010 "tests/sample-logs/de-cm-01/psexec-lateral-movement/benign.log" false "PSExec lateral movement - benign"

# Rule 100011 is frequency-based (needs 5+ events in 300s).
# By feeding all logs at once to wazuh-logtest, state is preserved!
run_test 100011 "tests/sample-logs/de-ae-02/repeated-auth-failures/trigger.log" true "Windows logon failure frequency (100011) - trigger"
run_test 100011 "tests/sample-logs/de-ae-02/repeated-auth-failures/benign.log" false "Windows logon failure - benign"

run_test 100012 "tests/sample-logs/rs-an-08/process-injection/trigger.log" true "Process injection - trigger"
run_test 100012 "tests/sample-logs/rs-an-08/process-injection/benign.log" false "Process injection - benign"

run_test 100013 "tests/sample-logs/id-ra-03/dns-c2-domain/trigger.log" true "DNS C2 domain - trigger"
run_test 100013 "tests/sample-logs/id-ra-03/dns-c2-domain/benign.log" false "DNS C2 domain - benign"

run_test 100014 "tests/sample-logs/pr-ds-01/sensitive-permission-change/trigger.log" true "Sensitive permission change - trigger"
run_test 100014 "tests/sample-logs/pr-ds-01/sensitive-permission-change/benign.log" false "Sensitive permission change - benign"

# Run rule 100015 check dynamically based on the current system hour
current_hour=$(date +%H)
if [ "$current_hour" -lt 8 ] || [ "$current_hour" -ge 18 ]; then
  run_test 100015 "tests/sample-logs/de-cm-09/after-hours-service-install/trigger.log" true "After-hours service install - trigger (evaluated outside business hours)"
else
  run_test 100015 "tests/sample-logs/de-cm-09/after-hours-service-install/trigger.log" false "After-hours service install - trigger (evaluated during business hours, expected silent)"
fi
run_test 100015 "tests/sample-logs/de-cm-09/after-hours-service-install/benign.log" false "After-hours service install - benign"

run_test 100019 "tests/sample-logs/pr-ds-01/passwd-modification/trigger.log" true "/etc/passwd modified - trigger"
run_test 100019 "tests/sample-logs/pr-ds-01/passwd-modification/benign.log" false "/etc/passwd modified - benign"

run_test 100020 "tests/sample-logs/pr-ds-01/shadow-modification/trigger.log" true "/etc/shadow modified - trigger"
run_test 100020 "tests/sample-logs/pr-ds-01/shadow-modification/benign.log" false "/etc/shadow modified - benign"

run_test 100021 "tests/sample-logs/pr-aa-05/authorized-keys-modification/trigger.log" true "SSH authorized_keys modified - trigger"
run_test 100021 "tests/sample-logs/pr-aa-05/authorized-keys-modification/benign.log" false "SSH authorized_keys modified - benign"

run_test 100022 "tests/sample-logs/pr-aa-05/suid-sgid-set/trigger.log" true "SUID/SGID bit set - trigger"
run_test 100022 "tests/sample-logs/pr-aa-05/suid-sgid-set/benign.log" false "SUID/SGID bit set - benign"

run_test 100023 "tests/sample-logs/de-cm-09/kernel-module-loaded/trigger.log" true "Kernel module loaded - trigger"
run_test 100023 "tests/sample-logs/de-cm-09/kernel-module-loaded/benign.log" false "Kernel module loaded - benign"

run_test 100024 "tests/sample-logs/de-cm-09/log-file-deleted/trigger.log" true "Log file deleted - trigger"
run_test 100024 "tests/sample-logs/de-cm-09/log-file-deleted/benign.log" false "Log file deleted - benign"

run_test 100025 "tests/sample-logs/de-ae-02/execution-from-tmp/trigger.log" true "Execution from /tmp - trigger"
run_test 100025 "tests/sample-logs/de-ae-02/execution-from-tmp/benign.log" false "Execution from /tmp - benign"

run_test 100026 "tests/sample-logs/de-cm-09/root-crontab-modification/trigger.log" true "Root crontab modification - trigger"
run_test 100026 "tests/sample-logs/de-cm-09/root-crontab-modification/benign.log" false "Root crontab modification - benign"


run_test 100027 "tests/sample-logs/de-ae-02/powershell-encoded/trigger.log" true "PowerShell encoded command - trigger"
run_test 100027 "tests/sample-logs/de-ae-02/powershell-encoded/benign.log" false "PowerShell encoded command - benign"

run_test 100028 "tests/sample-logs/de-ae-02/powershell-download/trigger.log" true "PowerShell download - trigger"
run_test 100028 "tests/sample-logs/de-ae-02/powershell-download/benign.log" false "PowerShell download - benign"

run_test 100029 "tests/sample-logs/de-ae-02/schtasks-create/trigger.log" true "Schtasks create - trigger"
run_test 100029 "tests/sample-logs/de-ae-02/schtasks-create/benign.log" false "Schtasks create - benign"

run_test 100030 "tests/sample-logs/de-ae-02/registry-run/trigger.log" true "Registry Run key - trigger"
run_test 100030 "tests/sample-logs/de-ae-02/registry-run/benign.log" false "Registry Run key - benign"

run_test 100031 "tests/sample-logs/de-ae-02/vssadmin-delete/trigger.log" true "Vssadmin delete - trigger"
run_test 100031 "tests/sample-logs/de-ae-02/vssadmin-delete/benign.log" false "Vssadmin delete - benign"

run_test 100032 "tests/sample-logs/pr-aa-01/new-admin/trigger.log" true "New Admin - trigger"
run_test 100032 "tests/sample-logs/pr-aa-01/new-admin/benign.log" false "New Admin - benign"

run_test 100033 "tests/sample-logs/pr-aa-05/rdp-port-change/trigger.log" true "RDP Port Change - trigger"
run_test 100033 "tests/sample-logs/pr-aa-05/rdp-port-change/benign.log" false "RDP Port Change - benign"

run_test 100034 "tests/sample-logs/de-ae-02/wmi-event/trigger.log" true "WMI Event Subscription - trigger"
run_test 100034 "tests/sample-logs/de-ae-02/wmi-event/benign.log" false "WMI Event Subscription - benign"

run_test 100035 "tests/sample-logs/de-ae-02/lsass-access/trigger.log" true "LSASS Memory Access - trigger"
run_test 100035 "tests/sample-logs/de-ae-02/lsass-access/benign.log" false "LSASS Memory Access - benign"

run_test 100036 "tests/sample-logs/de-ae-02/mimikatz/trigger.log" true "Mimikatz - trigger"
run_test 100036 "tests/sample-logs/de-ae-02/mimikatz/benign.log" false "Mimikatz - benign"

run_test 100037 "tests/sample-logs/de-cm-01/pass-the-hash/trigger.log" true "Pass-the-Hash - trigger"
run_test 100037 "tests/sample-logs/de-cm-01/pass-the-hash/benign.log" false "Pass-the-Hash - benign"

run_test 100038 "tests/sample-logs/id-ra-03/dcsync/trigger.log" true "DCSync - trigger"
run_test 100038 "tests/sample-logs/id-ra-03/dcsync/benign.log" false "DCSync - benign"

run_test 100039 "tests/sample-logs/id-ra-03/kerberoasting/trigger.log" true "Kerberoasting - trigger"
run_test 100039 "tests/sample-logs/id-ra-03/kerberoasting/benign.log" false "Kerberoasting - benign"

run_test 100040 "tests/sample-logs/de-ae-02/lockouts/trigger.log" true "Multiple Lockouts frequency (100040) - trigger"
run_test 100040 "tests/sample-logs/de-ae-02/lockouts/benign.log" false "Multiple Lockouts - benign"

run_test 100041 "tests/sample-logs/pr-aa-05/linux-shadow/trigger.log" true "Linux Shadow Read - trigger"
run_test 100041 "tests/sample-logs/pr-aa-05/linux-shadow/benign.log" false "Linux Shadow Read - benign"

run_test 100042 "tests/sample-logs/de-ae-02/reverse-shell/trigger.log" true "Reverse Shell - trigger"
run_test 100042 "tests/sample-logs/de-ae-02/reverse-shell/benign.log" false "Reverse Shell - benign"

run_test 100043 "tests/sample-logs/de-ae-02/base64-cmd/trigger.log" true "Base64 Command - trigger"
run_test 100043 "tests/sample-logs/de-ae-02/base64-cmd/benign.log" false "Base64 Command - benign"

run_test 100044 "tests/sample-logs/de-ae-03/dns-tunnel/trigger.log" true "DNS Tunnel - trigger"
run_test 100044 "tests/sample-logs/de-ae-03/dns-tunnel/benign.log" false "DNS Tunnel - benign"

run_test 100045 "tests/sample-logs/de-ae-03/tor-exit/trigger.log" true "TOR Exit Node - trigger"
run_test 100045 "tests/sample-logs/de-ae-03/tor-exit/benign.log" false "TOR Exit Node - benign"

run_test 100046 "tests/sample-logs/de-ae-02/beaconing/trigger.log" true "Beaconing frequency (100046) - trigger"
run_test 100046 "tests/sample-logs/de-ae-02/beaconing/benign.log" false "Beaconing - benign"

run_test 100047 "tests/sample-logs/de-ae-02/certutil/trigger.log" true "Certutil - trigger"
run_test 100047 "tests/sample-logs/de-ae-02/certutil/benign.log" false "Certutil - benign"

run_test 100048 "tests/sample-logs/de-ae-02/regsvr32/trigger.log" true "Regsvr32 - trigger"
run_test 100048 "tests/sample-logs/de-ae-02/regsvr32/benign.log" false "Regsvr32 - benign"

current_hour=$(date +%H)
if [ "$current_hour" -lt 6 ] || [ "$current_hour" -ge 18 ]; then
  run_test 100049 "tests/sample-logs/gv-po-01/admin-hours/trigger.log" true "Admin Hours - trigger (outside business hours)"
else
  run_test 100049 "tests/sample-logs/gv-po-01/admin-hours/trigger.log" false "Admin Hours - trigger (during business hours, expected silent)"
fi
run_test 100049 "tests/sample-logs/gv-po-01/admin-hours/benign.log" false "Admin Hours - benign"

run_test 100050 "tests/sample-logs/rc-rp-01/backup-fail/trigger.log" true "Backup Failure - trigger"
run_test 100050 "tests/sample-logs/rc-rp-01/backup-fail/benign.log" false "Backup Failure - benign"

echo ""
echo "--- Batch 6 Additions ---"
run_test 100051 "tests/sample-logs/de-ae-04/sysmon-event-log-cleared/trigger.log" true "Sysmon log cleared - trigger"
run_test 100051 "tests/sample-logs/de-ae-04/sysmon-event-log-cleared/benign.log" false "Sysmon log cleared - benign"
run_test 100052 "tests/sample-logs/de-ae-04/windows-defender-tampering/trigger.log" true "Defender tamper - trigger"
run_test 100052 "tests/sample-logs/de-ae-04/windows-defender-tampering/benign.log" false "Defender tamper - benign"
run_test 100053 "tests/sample-logs/de-ae-04/execution-from-recycle-bin/trigger.log" true "Recycle bin exec - trigger"
run_test 100053 "tests/sample-logs/de-ae-04/execution-from-recycle-bin/benign.log" false "Recycle bin exec - benign"

echo ""
echo "Results: $PASS passed, $FAIL failed, $ERROR errored"

if [ "$ERROR" -gt 0 ]; then
  echo -e "${YELLOW}Errored tests did not run — treat them as unknown, not as passes.${NC}"
fi

if [ "$FAIL" -gt 0 ] || [ "$ERROR" -gt 0 ]; then
  exit 1
fi
exit 0
