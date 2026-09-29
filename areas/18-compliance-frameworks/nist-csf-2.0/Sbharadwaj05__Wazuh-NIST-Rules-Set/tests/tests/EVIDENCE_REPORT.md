# Wazuh NIST CSF Ruleset — Final Evidence Report
**Generated:** 2026-05-23 15:38 UTC  
**Repository:** Sbharadwaj05/Wazuh-NIST-Rules-Set  

## Summary

| Result | Count |
|--------|-------|
| PASS   | 57    |
| FAIL   | 0    |
| SKIP (requires live Wazuh) | 8  |
| **Total checks** | **65** |

---

## Section 1 — Structural Integrity

| Check | Result | Detail |
|-------|--------|--------|
| XML | ✅ PASS | All 50 rule files parsed — well-formed XML |
| DUPES | ✅ PASS | No duplicate IDs across 54 rules |
| HELPERS | ✅ PASS | All 4 helper+correlation pairs verified (level=1, no_log, if_matched_sid) |
| MAP | ✅ PASS | Mapping JSON complete — all 50 alerting rules mapped |
| SCHEMA | ✅ PASS | All 50 mapping entries have tactic, os, and tags fields |
| README | ✅ PASS | All 50 rules documented |
| Rule Catalog | ✅ PASS | All 50 rules documented |
| CDB:rare-ports | ✅ PASS | Valid Wazuh CDB format (6 entries) |
| CDB:c2-domains | ✅ PASS | Valid Wazuh CDB format (3 entries) |

---

## Section 2 — Pattern Match Tests

> Secondary match conditions (regex/field) tested against trigger and benign logs.
> `<if_sid>` parent rule verification requires a live Wazuh `wazuh-logtest` session.

| Rule ID | Status | Result |
|---------|--------|--------|
| 100002 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100003 | ⚠️ SKIP | requires live wazuh-logtest — parent-only rule (depends on syslog useradd decoder firing parent SID 5902; no secondary match condition to test statically) |
| 100004 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100006 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100007 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100008 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100009 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100010 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100011 | ⚠️ SKIP | requires live wazuh-logtest — frequency-based correlation (requires 5+ events in 300s sliding window in live wazuh-logtest stateful session) |
| 100012 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100014 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100015 | ⚠️ SKIP | requires live wazuh-logtest — time-filtered rule (depends on Wazuh manager system clock; fires only outside 08:00-18:00 window) |
| 100016 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100017 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100018 | ⚠️ SKIP | requires live wazuh-logtest — frequency-based correlation (requires 5+ SSH failures in 60s window in live wazuh-logtest) |
| 100019 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100020 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100021 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100022 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100023 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100024 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100025 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100026 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100027 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100028 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100029 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100030 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100031 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100032 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100033 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100034 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100035 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100036 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100037 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100038 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100039 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100040 | ⚠️ SKIP | requires live wazuh-logtest — frequency-based correlation (requires 5+ account lockout events in 300s window in live wazuh-logtest) |
| 100041 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100042 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100043 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100044 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100045 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100046 | ⚠️ SKIP | requires live wazuh-logtest — frequency-based correlation (requires 20+ Sysmon EventID 3 events in 600s window in live wazuh-logtest) |
| 100047 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100048 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100049 | ⚠️ SKIP | requires live wazuh-logtest — time-filtered rule (fires only between 18:00-06:00; result varies by Wazuh manager clock) |
| 100050 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100051 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100052 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100053 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100054 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100055 | ✅ PASS | trigger MATCHES | benign SILENT |

---

## Section 3 — CDB List Lookup Tests

| Rule | Status | Detail |
|------|--------|--------|
| 100005 | ❌ SKIP | conditions untestable in Python (CDB/decoder/regex engine) |
| 100013 | ✅ PASS | trigger MATCHES | benign SILENT |
| 100005 | ✅ PASS | CDB rare-ports: '4444' IN list, '443' NOT in list |
| 100013 | ✅ PASS | CDB c2-domains: 'example-c2.bad' IN list, 'google.com' NOT in list |

---

## Skip Rationale

Rules marked SKIP cannot be validated without a live Wazuh `wazuh-logtest` session.
They are structurally correct and their **helper rules** are fully validated above.

| Rule | Reason |
|------|--------|
| 100003 | parent-only rule (depends on syslog useradd decoder firing parent SID 5902; no secondary match condition to test statically) |
| 100011 | frequency-based correlation (requires 5+ events in 300s sliding window in live wazuh-logtest stateful session) |
| 100015 | time-filtered rule (depends on Wazuh manager system clock; fires only outside 08:00-18:00 window) |
| 100018 | frequency-based correlation (requires 5+ SSH failures in 60s window in live wazuh-logtest) |
| 100040 | frequency-based correlation (requires 5+ account lockout events in 300s window in live wazuh-logtest) |
| 100046 | frequency-based correlation (requires 20+ Sysmon EventID 3 events in 600s window in live wazuh-logtest) |
| 100049 | time-filtered rule (fires only between 18:00-06:00; result varies by Wazuh manager clock) |

---

## Deployment Checklist

Before going live, complete the following steps on the Wazuh manager:

- [ ] Copy `rules/` to `/var/ossec/etc/rules/nist-csf/`
- [ ] Copy `decoders/nist_custom_decoders.xml` to `/var/ossec/etc/decoders/`
- [ ] Copy `lists/rare-ports` and `lists/c2-domains` to `/var/ossec/etc/lists/`
- [ ] Add CDB list references in `ossec.conf`:
  ```xml
  <list>etc/lists/rare-ports</list>
  <list>etc/lists/c2-domains</list>
  ```
- [ ] Run `wazuh-logtest` with `tests/test-runner.sh` to validate frequency/time rules
- [ ] Restart Wazuh manager: `systemctl restart wazuh-manager`

*This report was generated automatically by `tests/evidence_validator.py`.*