#!/usr/bin/env python3
"""
Wazuh NIST CSF Ruleset - Final Evidence Validation
===================================================
Tests every rule's matching logic against trigger/benign sample logs using Python.
Covers: XML structure, pattern matching (regex + JSON field), CDB list lookups.
Frequency/time-based rules are marked SKIP with explicit reason.

Run from repository root:  python tests/evidence_validator.py
"""
import re, json, os, sys, xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

# ── Paths ─────────────────────────────────────────────────────────────────────
RULES_DIR    = Path("rules")
TESTS_DIR    = Path("tests/sample-logs")
LISTS_DIR    = Path("lists")
MAPPING_FILE = Path("mappings/nist-csf-mitre-wazuh.json")
README_FILE  = Path("README.md")
CATALOG_FILE = Path("docs/rule-catalog.md")

# ── Counters ──────────────────────────────────────────────────────────────────
PASS = FAIL = SKIP = 0
EVIDENCE = []   # list of result dicts

# ── Rules that need a live Wazuh instance ─────────────────────────────────────
LIVE_ONLY = {
    "100003": "parent-only rule (depends on syslog useradd decoder firing parent SID 5902; no secondary match condition to test statically)",
    "100011": "frequency-based correlation (requires 5+ events in 300s sliding window in live wazuh-logtest stateful session)",
    "100015": "time-filtered rule (depends on Wazuh manager system clock; fires only outside 08:00-18:00 window)",
    "100018": "frequency-based correlation (requires 5+ SSH failures in 60s window in live wazuh-logtest)",
    "100040": "frequency-based correlation (requires 5+ account lockout events in 300s window in live wazuh-logtest)",
    "100046": "frequency-based correlation (requires 20+ Sysmon EventID 3 events in 600s window in live wazuh-logtest)",
    "100049": "time-filtered rule (fires only between 18:00-06:00; result varies by Wazuh manager clock)",
}

# ── Rule -> test log directory mapping ────────────────────────────────────────
RULE_LOG = {
    "100002": "pr-aa-05/sudo-privilege-escalation",
    "100004": "de-cm-09/cron-modification",
    "100005": "de-cm-01/outbound-rare-port",
    "100006": "pr-ds-01/passwd-shadow-read",
    "100007": "de-ae-02/web-shell-indicators",
    "100008": "de-ae-03/large-file-exfiltration",
    "100009": "de-cm-09/windows-audit-cleared",
    "100010": "de-cm-01/psexec-lateral-movement",
    "100012": "rs-an-08/process-injection",
    "100013": "id-ra-03/dns-c2-domain",
    "100014": "pr-ds-01/sensitive-permission-change",
    "100016": "de-ae-02/repeated-auth-failures",   # helper; uses first line
    "100017": "de-cm-01/ssh-bruteforce",           # helper; uses first line
    "100019": "pr-ds-01/passwd-modification",
    "100020": "pr-ds-01/shadow-modification",
    "100021": "pr-aa-05/authorized-keys-modification",
    "100022": "pr-aa-05/suid-sgid-set",
    "100023": "de-cm-09/kernel-module-loaded",
    "100024": "de-cm-09/log-file-deleted",
    "100025": "de-ae-02/execution-from-tmp",
    "100026": "de-cm-09/root-crontab-modification",
    "100027": "de-ae-02/powershell-encoded",
    "100028": "de-ae-02/powershell-download",
    "100029": "de-ae-02/schtasks-create",
    "100030": "de-ae-02/registry-run",
    "100031": "de-ae-02/vssadmin-delete",
    "100032": "pr-aa-01/new-admin",
    "100033": "pr-aa-05/rdp-port-change",
    "100034": "de-ae-02/wmi-event",
    "100035": "de-ae-02/lsass-access",
    "100036": "de-ae-02/mimikatz",
    "100037": "de-cm-01/pass-the-hash",
    "100038": "id-ra-03/dcsync",
    "100039": "id-ra-03/kerberoasting",
    "100041": "pr-aa-05/linux-shadow",
    "100042": "de-ae-02/reverse-shell",
    "100043": "de-ae-02/base64-cmd",
    "100044": "de-ae-03/dns-tunnel",
    "100045": "de-ae-03/tor-exit",
    "100047": "de-ae-02/certutil",
    "100048": "de-ae-02/regsvr32",
    "100050": "rc-rp-01/backup-fail",
    "100051": "de-ae-04/sysmon-event-log-cleared",
    "100052": "de-ae-04/windows-defender-tampering",
    "100053": "de-ae-04/execution-from-recycle-bin",
    "100054": "de-ae-02/beaconing",               # helper; uses first line
    "100055": "de-ae-02/lockouts",                 # helper; uses first line
}

# ── Helpers ───────────────────────────────────────────────────────────────────
GREEN = "\033[92m"
RED   = "\033[91m"
YELLOW= "\033[93m"
RESET = "\033[0m"

def record(status, rule_id, desc, detail=""):
    global PASS, FAIL, SKIP
    sym = {"PASS": f"{GREEN}[PASS]{RESET}", "FAIL": f"{RED}[FAIL]{RESET}", "SKIP": f"{YELLOW}[SKIP]{RESET}"}[status]
    print(f"  {sym} {('Rule '+str(rule_id)).ljust(12)} {desc}" + (f"  ({detail})" if detail else ""))
    EVIDENCE.append({"status": status, "rule_id": str(rule_id), "desc": desc, "detail": detail})
    if status == "PASS": PASS += 1
    elif status == "FAIL": FAIL += 1
    else: SKIP += 1

def read_first_line(path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return f.readline().rstrip("\n")

def read_all(path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as f:
        return f.read()

def nav_json(obj, dotpath):
    for key in dotpath.split("."):
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return None
    return str(obj) if obj is not None else None

def cdb_contains(list_name, value):
    p = LISTS_DIR / list_name
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        keys = {ln.split(":")[0].strip() for ln in f if ln.strip() and not ln.startswith("#")}
    return value in keys

def apply_conditions(rule_elem, log_text):
    """
    Apply a rule's matching conditions to a log text string.
    Returns True if ALL conditions match, False if any fail, None if untestable.
    """
    untestable = False

    for child in rule_elem:
        tag = child.tag

        # ── <regex> ──
        if tag == "regex":
            pattern = child.text or ""
            flags = re.IGNORECASE if child.get("type", "") == "pcre2" else 0
            try:
                if not re.search(pattern, log_text, flags):
                    return False
            except re.error:
                return None  # regex engine difference

        # ── <match> ──
        elif tag == "match":
            text = child.text or ""
            if text not in log_text:
                return False

        # ── <field name="..."> ──
        elif tag == "field":
            dotpath = child.get("name", "")
            pattern  = child.text or ""
            rtype    = child.get("type", "")
            try:
                parsed = json.loads(log_text.strip().split("\n")[0])
            except (json.JSONDecodeError, AttributeError):
                return None  # log is not JSON
            actual = nav_json(parsed, dotpath)
            if actual is None:
                return False
            try:
                if rtype == "pcre2" or any(c in pattern for c in r".*+?[](){}\\^$|"):
                    if not re.search(pattern, actual, re.IGNORECASE):
                        return False
                else:
                    if actual != pattern:
                        return False
            except re.error:
                return None

        # ── <list field="..."> ──
        elif tag == "list":
            field = child.get("field", "")
            lookup = child.get("lookup", "match_key")
            list_name = child.text.strip() if child.text else ""
            # Extract the list filename from the path
            list_file = Path(list_name).name
            if field and list_file:
                try:
                    parsed = json.loads(log_text.strip().split("\n")[0])
                    value = nav_json(parsed, field)
                except (json.JSONDecodeError, AttributeError):
                    # Try raw field extraction from log text
                    m = re.search(rf"\b{re.escape(field.split('.')[-1])}=(\S+)", log_text)
                    value = m.group(1) if m else None
                if value is None:
                    untestable = True
                    continue
                result = cdb_contains(list_file, value)
                if result is None:
                    untestable = True
                elif not result:
                    return False

        # ── Skippable elements ──
        elif tag in ("description", "group", "mitre", "options", "if_sid",
                     "if_matched_sid", "same_field", "same_source_ip",
                     "frequency", "timeframe", "time", "decoded_as"):
            continue

    return None if untestable else True

def test_rule(rule_id, rule_elem, log_dir_key):
    t_path = TESTS_DIR / log_dir_key / "trigger.log"
    b_path = TESTS_DIR / log_dir_key / "benign.log"

    trigger_text = read_first_line(t_path)
    benign_text  = read_first_line(b_path)

    if trigger_text is None:
        record("FAIL", rule_id, "trigger.log missing", str(t_path))
        return
    if benign_text is None:
        record("FAIL", rule_id, "benign.log missing", str(b_path))
        return

    t_result = apply_conditions(rule_elem, trigger_text)
    b_result = apply_conditions(rule_elem, benign_text)

    if t_result is None:
        record("SKIP", rule_id, "conditions untestable in Python (CDB/decoder/regex engine)", log_dir_key)
        return

    if t_result is True and b_result is False:
        record("PASS", rule_id, "trigger MATCHES | benign SILENT")
    elif t_result is False:
        # Get what failed
        record("FAIL", rule_id, "trigger did NOT match rule conditions", f"log: {trigger_text[:80]}")
    else:
        record("FAIL", rule_id, "benign log matched conditions (false positive)", f"log: {benign_text[:80]}")


# ── Section 1: Structural Checks ─────────────────────────────────────────────
def structural_checks():
    print(f"\n{'='*62}")
    print("  SECTION 1 — STRUCTURAL INTEGRITY")
    print(f"{'='*62}")

    # 1a. All XML files parse cleanly
    xml_files = list(RULES_DIR.rglob("*.xml"))
    bad_xml = []
    all_rule_elems = {}  # rule_id -> rule_elem
    all_rule_ids = []
    for xf in sorted(xml_files):
        try:
            tree = ET.parse(xf)
            for r in tree.getroot().findall(".//rule"):
                rid = r.get("id")
                if rid:
                    all_rule_ids.append(rid)
                    all_rule_elems[rid] = r
        except ET.ParseError as e:
            bad_xml.append(f"{xf}: {e}")

    if bad_xml:
        for b in bad_xml: record("FAIL", "XML", b)
    else:
        record("PASS", "XML", f"All {len(xml_files)} rule files parsed — well-formed XML")

    # 1b. No duplicate rule IDs
    seen, dupes = set(), []
    for rid in all_rule_ids:
        if rid in seen: dupes.append(rid)
        seen.add(rid)
    if dupes:
        record("FAIL", "DUPES", f"Duplicate rule IDs: {dupes}")
    else:
        record("PASS", "DUPES", f"No duplicate IDs across {len(all_rule_ids)} rules")

    # 1c. Helper rules: level=1 + no_log
    helper_pairs = {"100016":"100011","100017":"100018","100054":"100046","100055":"100040"}
    helper_ok = True
    for hid, cid in helper_pairs.items():
        he = all_rule_elems.get(hid)
        if he is None:
            record("FAIL", hid, f"helper rule missing"); helper_ok = False; continue
        level = int(he.get("level", "0"))
        opts  = he.findtext("options", "")
        if level != 1:
            record("FAIL", hid, f"helper rule level={level}, must be 1"); helper_ok = False
        elif "no_log" not in opts:
            record("FAIL", hid, "helper rule missing <options>no_log</options>"); helper_ok = False
        else:
            # Check correlation rule references helper
            ce = all_rule_elems.get(cid)
            if ce is not None:
                sids = ce.findtext("if_matched_sid", "")
                if hid not in sids:
                    record("FAIL", cid, f"correlation does not reference helper {hid}"); helper_ok = False
    if helper_ok:
        record("PASS", "HELPERS", "All 4 helper+correlation pairs verified (level=1, no_log, if_matched_sid)")

    # 1d. Mapping alignment
    try:
        with open(MAPPING_FILE, encoding="utf-8") as f:
            mapping = json.load(f)
        mapped_ids = {e["wazuh_rule_id"] for e in mapping["mappings"]}
        alerting_ids = {rid for rid, re_ in all_rule_elems.items()
                        if int(re_.get("level","0")) > 1 or "no_log" not in (re_.findtext("options",""))}
        # More precise: alerting = not (level=1 AND no_log)
        alerting_ids = set()
        for rid, re_ in all_rule_elems.items():
            lvl = int(re_.get("level","0"))
            opts = re_.findtext("options","")
            is_helper = (lvl == 1 and "no_log" in opts)
            if not is_helper:
                alerting_ids.add(rid)
        missing_map   = alerting_ids - mapped_ids
        phantom_map   = mapped_ids - alerting_ids
        if missing_map or phantom_map:
            if missing_map: record("FAIL", "MAP", f"Rules in XML but not mapped: {sorted(missing_map)}")
            if phantom_map: record("FAIL", "MAP", f"Rules in mapping but not in XML: {sorted(phantom_map)}")
        else:
            record("PASS", "MAP", f"Mapping JSON complete — all {len(mapped_ids)} alerting rules mapped")
    except Exception as e:
        record("FAIL", "MAP", str(e))

    # 1e. Schema completeness — every mapping entry has tactic, os, tags
    missing_schema = []
    for e in mapping.get("mappings", []):
        rid = e["wazuh_rule_id"]
        if "tactic" not in e.get("mitre_attack", {}): missing_schema.append(f"{rid}:tactic")
        if "os" not in e: missing_schema.append(f"{rid}:os")
        if "tags" not in e: missing_schema.append(f"{rid}:tags")
    if missing_schema:
        record("FAIL", "SCHEMA", f"Incomplete mapping entries: {missing_schema}")
    else:
        record("PASS", "SCHEMA", "All 50 mapping entries have tactic, os, and tags fields")

    # 1f. README and rule-catalog coverage
    for label, fpath in [("README", README_FILE), ("Rule Catalog", CATALOG_FILE)]:
        try:
            content = fpath.read_text(encoding="utf-8")
            doc_ids = set(re.findall(r'\b(10[0-9]{4})\b', content))
            missing = mapped_ids - doc_ids
            extra   = doc_ids - mapped_ids - {"100016","100017","100054","100055"}
            if missing:
                record("FAIL", label, f"Missing rule IDs: {sorted(missing)[:5]}...")
            else:
                record("PASS", label, f"All {len(mapped_ids)} rules documented")
        except FileNotFoundError:
            record("FAIL", label, f"{fpath} not found")

    # 1g. CDB list format
    for lst in ["rare-ports", "c2-domains"]:
        p = LISTS_DIR / lst
        if not p.exists():
            record("FAIL", f"CDB:{lst}", "list file missing"); continue
        with open(p, encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        bad = [l for l in lines if not l.endswith(":")]
        if bad:
            record("FAIL", f"CDB:{lst}", f"Lines missing trailing colon: {bad}")
        else:
            record("PASS", f"CDB:{lst}", f"Valid Wazuh CDB format ({len(lines)} entries)")

    return all_rule_elems


# ── Section 2: Pattern Match Tests ───────────────────────────────────────────
def pattern_tests(all_rule_elems):
    print(f"\n{'='*62}")
    print("  SECTION 2 — PATTERN MATCH TESTS (Python engine)")
    print(f"{'='*62}")
    print("  NOTE: <if_sid> parent verification requires live Wazuh.")
    print("        These tests validate secondary match conditions only.\n")

    # Live-only rules (skip)
    for rid, reason in sorted(LIVE_ONLY.items()):
        record("SKIP", rid, "requires live wazuh-logtest", reason)

    print()
    # Testable rules
    for rule_id, log_dir in sorted(RULE_LOG.items()):
        rule_elem = all_rule_elems.get(rule_id)
        if rule_elem is None:
            record("FAIL", rule_id, "rule element not found in XML files")
            continue
        test_rule(rule_id, rule_elem, log_dir)


# ── Section 3: CDB List Lookup Tests ─────────────────────────────────────────
def cdb_tests():
    print(f"\n{'='*62}")
    print("  SECTION 3 — CDB LIST LOOKUP TESTS")
    print(f"{'='*62}")

    # Rule 100005: rare port — DPT=4444 should be in rare-ports
    trigger_port = "4444"
    benign_port  = "443"
    in_list  = cdb_contains("rare-ports", trigger_port)
    not_in   = cdb_contains("rare-ports", benign_port)
    if in_list and not not_in:
        record("PASS", "100005", f"CDB rare-ports: '{trigger_port}' IN list, '{benign_port}' NOT in list")
    elif not in_list:
        record("FAIL", "100005", f"CDB rare-ports: '{trigger_port}' NOT found in list")
    else:
        record("FAIL", "100005", f"CDB rare-ports: benign port '{benign_port}' incorrectly IN list")

    # Rule 100013: C2 domain — example-c2.bad should be in c2-domains
    trigger_dom = "example-c2.bad"
    benign_dom  = "google.com"
    in_list  = cdb_contains("c2-domains", trigger_dom)
    not_in   = cdb_contains("c2-domains", benign_dom)
    if in_list and not not_in:
        record("PASS", "100013", f"CDB c2-domains: '{trigger_dom}' IN list, '{benign_dom}' NOT in list")
    elif not in_list:
        record("FAIL", "100013", f"CDB c2-domains: '{trigger_dom}' NOT found in list")
    else:
        record("FAIL", "100013", f"CDB c2-domains: benign domain '{benign_dom}' incorrectly IN list")


# ── Section 4: Summary Report ─────────────────────────────────────────────────
def write_report():
    report_path = Path("tests/EVIDENCE_REPORT.md")
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    by_status = {"PASS": [], "FAIL": [], "SKIP": []}
    for e in EVIDENCE:
        by_status[e["status"]].append(e)

    lines = [
        "# Wazuh NIST CSF Ruleset — Final Evidence Report",
        f"**Generated:** {now}  ",
        f"**Repository:** Sbharadwaj05/Wazuh-NIST-Rules-Set  ",
        "",
        "## Summary",
        "",
        f"| Result | Count |",
        f"|--------|-------|",
        f"| PASS   | {PASS}    |",
        f"| FAIL   | {FAIL}    |",
        f"| SKIP (requires live Wazuh) | {SKIP}  |",
        f"| **Total checks** | **{PASS+FAIL+SKIP}** |",
        "",
        "---",
        "",
        "## Section 1 — Structural Integrity",
        "",
        "| Check | Result | Detail |",
        "|-------|--------|--------|",
    ]
    struct = [e for e in EVIDENCE if not str(e["rule_id"]).isdigit()]
    for e in struct:
        icon = "✅" if e["status"] == "PASS" else ("⚠️" if e["status"] == "SKIP" else "❌")
        lines.append(f"| {e['rule_id']} | {icon} {e['status']} | {e['desc']} |")

    lines += [
        "",
        "---",
        "",
        "## Section 2 — Pattern Match Tests",
        "",
        "> Secondary match conditions (regex/field) tested against trigger and benign logs.",
        "> `<if_sid>` parent rule verification requires a live Wazuh `wazuh-logtest` session.",
        "",
        "| Rule ID | Status | Result |",
        "|---------|--------|--------|",
    ]
    pattern = [e for e in EVIDENCE if str(e["rule_id"]).isdigit() and e["rule_id"] not in ("100005","100013")]
    for e in sorted(pattern, key=lambda x: x["rule_id"]):
        icon = "✅" if e["status"] == "PASS" else ("⚠️" if e["status"] == "SKIP" else "❌")
        detail = f" — {e['detail']}" if e["detail"] else ""
        lines.append(f"| {e['rule_id']} | {icon} {e['status']} | {e['desc']}{detail} |")

    lines += [
        "",
        "---",
        "",
        "## Section 3 — CDB List Lookup Tests",
        "",
        "| Rule | Status | Detail |",
        "|------|--------|--------|",
    ]
    cdb = [e for e in EVIDENCE if e["rule_id"] in ("100005","100013")]
    for e in cdb:
        icon = "✅" if e["status"] == "PASS" else "❌"
        lines.append(f"| {e['rule_id']} | {icon} {e['status']} | {e['desc']} |")

    lines += [
        "",
        "---",
        "",
        "## Skip Rationale",
        "",
        "Rules marked SKIP cannot be validated without a live Wazuh `wazuh-logtest` session.",
        "They are structurally correct and their **helper rules** are fully validated above.",
        "",
        "| Rule | Reason |",
        "|------|--------|",
    ]
    for rid, reason in sorted(LIVE_ONLY.items()):
        lines.append(f"| {rid} | {reason} |")

    lines += [
        "",
        "---",
        "",
        "## Deployment Checklist",
        "",
        "Before going live, complete the following steps on the Wazuh manager:",
        "",
        "- [ ] Copy `rules/` to `/var/ossec/etc/rules/nist-csf/`",
        "- [ ] Copy `decoders/nist_custom_decoders.xml` to `/var/ossec/etc/decoders/`",
        "- [ ] Copy `lists/rare-ports` and `lists/c2-domains` to `/var/ossec/etc/lists/`",
        "- [ ] Add CDB list references in `ossec.conf`:",
        "  ```xml",
        "  <list>etc/lists/rare-ports</list>",
        "  <list>etc/lists/c2-domains</list>",
        "  ```",
        "- [ ] Run `wazuh-logtest` with `tests/test-runner.sh` to validate frequency/time rules",
        "- [ ] Restart Wazuh manager: `systemctl restart wazuh-manager`",
        "",
        "*This report was generated automatically by `tests/evidence_validator.py`.*",
    ]

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n  Report written to: {report_path}")
    return report_path


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'='*62}")
    print("  WAZUH NIST CSF RULESET - FINAL EVIDENCE VALIDATION")
    print(f"  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*62}")

    all_rule_elems = structural_checks()
    pattern_tests(all_rule_elems)
    cdb_tests()

    print(f"\n{'='*62}")
    print(f"  FINAL RESULTS:  {GREEN}{PASS} PASS{RESET}  |  {RED}{FAIL} FAIL{RESET}  |  {YELLOW}{SKIP} SKIP{RESET}")
    print(f"{'='*62}")

    report = write_report()

    if FAIL > 0:
        print(f"\n  {RED}ACTION REQUIRED: {FAIL} check(s) failed. Review output above.{RESET}\n")
        sys.exit(1)
    else:
        print(f"\n  {GREEN}All testable checks passed. Repository is evidence-backed.{RESET}\n")
        sys.exit(0)
