#!/usr/bin/env bash
# ============================================================
# Wazuh DB Compliance — CI logtest harness
# Wazuh 4.14.5 | Database Activity Monitoring
# ============================================================
# Para cada DBMS suportado, envia sample logs para PUT /logtest
# da API Wazuh e valida que a rule custom esperada dispara.
#
# Devolve exit code != 0 se qualquer expectativa falhar.
#
# Pré-requisitos:
#   - WAZUH_API_URL: ex. https://wazuh.example.org:55000
#   - WAZUH_API_USER, WAZUH_API_PASS: credenciais com permissão logtest:run
#   - curl, jq, python3
#
# Uso:
#   export WAZUH_API_URL=https://wazuh.example.org:55000
#   export WAZUH_API_USER=wazuh-wui
#   export WAZUH_API_PASS='...'
#   ./tests/run-ci-logtest.sh
#
# CI (GitHub Actions / GitLab CI):
#   - Adiciona as 3 vars como secrets
#   - Job step: bash tests/run-ci-logtest.sh
# ============================================================
set -euo pipefail

: "${WAZUH_API_URL:?WAZUH_API_URL not set}"
: "${WAZUH_API_USER:?WAZUH_API_USER not set}"
: "${WAZUH_API_PASS:?WAZUH_API_PASS not set}"

API="$WAZUH_API_URL"
USER_FAIL=0
USER_PASS=0
USER_XFAIL=0
SUMMARY=""

# ---- auth ----
echo "[*] Authenticating to $API as $WAZUH_API_USER"
TOKEN=$(curl -sk -X POST -u "$WAZUH_API_USER:$WAZUH_API_PASS" \
  "$API/security/user/authenticate" -m 8 \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")
if [[ -z "$TOKEN" ]]; then
  echo "[!] Authentication failed"; exit 1
fi
echo "[+] Got JWT (${#TOKEN} chars)"

# ---- helper ----
# logtest_assert <label> <log_format> <location> <event_json_string>
#                <expected_rule_id|->|XFAIL:<id>>
logtest_assert() {
  local label="$1" lf="$2" loc="$3" ev="$4" expect="$5"
  local body resp got_id got_lvl got_dec status
  body=$(python3 -c "import json,sys; print(json.dumps({'log_format':'$lf','location':'$loc','event':sys.argv[1]}))" "$ev")
  resp=$(curl -sk -X PUT "$API/logtest" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$body" -m 10)
  got_id=$(echo "$resp" | python3 -c "import sys,json; o=json.load(sys.stdin)['data']['output']; print(o.get('rule',{}).get('id','-'))")
  got_lvl=$(echo "$resp" | python3 -c "import sys,json; o=json.load(sys.stdin)['data']['output']; print(o.get('rule',{}).get('level','-'))")
  got_dec=$(echo "$resp" | python3 -c "import sys,json; o=json.load(sys.stdin)['data']['output']; print(o.get('decoder',{}).get('name','-'))")

  if [[ "$expect" == XFAIL:* ]]; then
    # Expected fail — we know the custom rule doesn't fire yet.
    if [[ "$got_id" == "${expect#XFAIL:}" ]]; then
      status="XPASS"; USER_FAIL=$((USER_FAIL+1))
    else
      status="XFAIL"; USER_XFAIL=$((USER_XFAIL+1))
    fi
  elif [[ "$expect" == *"|"* ]]; then
    # Alternation: "100201|100206" — accept any listed rule_id.
    # Used for time-of-day-dependent rules (e.g. off-hours overrides).
    if echo "$expect" | tr '|' '\n' | grep -qx "$got_id"; then
      status="PASS"; USER_PASS=$((USER_PASS+1))
    else
      status="FAIL"; USER_FAIL=$((USER_FAIL+1))
    fi
  elif [[ "$got_id" == "$expect" ]]; then
    status="PASS"; USER_PASS=$((USER_PASS+1))
  else
    status="FAIL"; USER_FAIL=$((USER_FAIL+1))
  fi
  printf "  %-6s  %-30s  expected=%-7s  got=rule.id=%s level=%s decoder=%s\n" \
    "$status" "$label" "$expect" "$got_id" "$got_lvl" "$got_dec"
  SUMMARY+="$status|$label|expected=$expect|got=$got_id|level=$got_lvl|decoder=$got_dec"$'\n'
}

echo
echo "================ MariaDB / Percona Audit JSON ================"
logtest_assert "mysql.connect.ok" json /var/log/mysql/audit.log \
  '{"audit_record":{"name":"Connect","timestamp":"2024-01-15T10:30:00 UTC","command_class":"connect","connection_id":"12345","status":0,"user":"app_user","host":"appserver","ip":"192.168.1.100","db":"prod_db"}}' \
  "100201|100206"
# nota: 100206 = "MySQL: Acesso fora de horário" (level 10, time-based override).
# Em horário laboral dispara 100201 (level 3); fora de horário dispara 100206.
# Aceitamos ambos porque é comportamento correto da rule.
logtest_assert "mysql.create_table" json /var/log/mysql/audit.log \
  '{"audit_record":{"name":"Query","timestamp":"2024-01-15T10:30:02 UTC","command_class":"create_table","connection_id":"12345","status":0,"sqltext":"CREATE TABLE logs_backup (id INT)","user":"dba_user","host":"mgmt","ip":"10.0.0.10","db":"prod_db"}}' \
  100204
logtest_assert "mysql.auth_fail" json /var/log/mysql/audit.log \
  '{"audit_record":{"name":"Connect","timestamp":"2024-01-15T10:31:00 UTC","command_class":"connect","connection_id":"12346","status":1045,"user":"baduser","host":"external","ip":"203.0.113.45","db":""}}' \
  100202

echo
echo "================ MariaDB / server_audit CSV =================="
logtest_assert "mariadb.connect.ok"    syslog /var/log/mysql/server_audit.log \
  "20260527 22:14:00,db-mariadb-01,app_user,192.168.1.100,42,0,CONNECT,prod_db,,0" \
  100260
logtest_assert "mariadb.failed_connect" syslog /var/log/mysql/server_audit.log \
  "20260527 22:15:00,db-mariadb-01,baduser,203.0.113.45,42,0,FAILED_CONNECT,,,1045" \
  100261

echo
echo "================ Microsoft SQL Server ========================"
logtest_assert "mssql.login.ok"      syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:00","source":"mssql_audit","action_id":"LGIS","succeeded":true,"server_principal_name":"app_saga","database_name":"SAGA","object_name":"","statement":"","client_ip":"192.168.100.50","application_name":"SAGA Application"}' \
  "100270|100283"
# 100283 = "MSSQL: Login fora de horário" (off-hours override de 100270).
logtest_assert "mssql.login.failed"  syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:01","source":"mssql_audit","action_id":"LGFL","succeeded":false,"server_principal_name":"baduser","database_name":"master","object_name":"","statement":"","client_ip":"203.0.113.45","application_name":"sqlcmd"}' \
  100271
logtest_assert "mssql.priv.grant"    syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:10","source":"mssql_audit","action_id":"GRTO","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"","statement":"GRANT SELECT","client_ip":"192.168.100.10","application_name":"SSMS"}' \
  100273
logtest_assert "mssql.ddl.create"    syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:11","source":"mssql_audit","action_id":"CR","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"temp_export","statement":"CREATE TABLE temp_export (id INT)","client_ip":"192.168.100.10","application_name":"SSMS"}' \
  100275
logtest_assert "mssql.ddl.drop"      syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:12","source":"mssql_audit","action_id":"DR","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"logs_antigos","statement":"DROP TABLE logs_antigos","client_ip":"192.168.100.10","application_name":"SSMS"}' \
  100276
logtest_assert "mssql.select.benign"   syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:13","source":"mssql_audit","action_id":"SL","succeeded":true,"server_principal_name":"app_saga","database_name":"SAGA","object_name":"clientes","statement":"SELECT nif, iban FROM clientes","client_ip":"192.168.100.50","application_name":"SAGA"}' \
  "-"
# A rule 100277 (exfiltration) só dispara quando o statement bate em
# SELECT.+INTO  |OPENROWSET|BULK INSERT  — testamos um statement que sim.
logtest_assert "mssql.select.exfil"    syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:13","source":"mssql_audit","action_id":"SL","succeeded":true,"server_principal_name":"app_saga","database_name":"SAGA","object_name":"clientes","statement":"SELECT nif, iban, nome INTO #temp_export FROM clientes","client_ip":"192.168.100.50","application_name":"SAGA Application"}' \
  100277
logtest_assert "mssql.alter_server"  syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:14","source":"mssql_audit","action_id":"ALSS","succeeded":true,"server_principal_name":"sa","database_name":"master","object_name":"","statement":"ALTER SERVER STATE","client_ip":"192.168.100.8","application_name":"sqlcmd"}' \
  100281
logtest_assert "mssql.backup"        syslog /var/log/mssql/audit.log \
  '{"ts":"2024-01-15T10:30:15","source":"mssql_audit","action_id":"BKDB","succeeded":true,"server_principal_name":"dba_admin","database_name":"SAGA","object_name":"","statement":"BACKUP DATABASE [SAGA]","client_ip":"192.168.100.10","application_name":"SQL Server Agent"}' \
  100282

echo
echo "================ PostgreSQL pgAudit =========================="
# Fix aplicado em 2026-05-27 22:05: program_name literal 'postgresql'
# (sem regex ^...$) faz com que os custom decoders ganhem ao built-in.
logtest_assert "pg.auth_fail"        syslog /var/log/postgresql/postgresql.log \
  'Jan 15 10:30:04 dbserver postgresql[1235]: [1-1] FATAL:  password authentication failed for user "baduser"' \
  100211
logtest_assert "pg.audit_ddl"        syslog /var/log/postgresql/postgresql.log \
  'Jan 15 10:30:02 dbserver postgresql[1234]: [3-1] LOG:  AUDIT: SESSION,1,1,DDL,CREATE TABLE,TABLE,public.clientes,CREATE TABLE clientes,<not logged>' \
  100214

echo
echo "================ Cross-talk regression (Defeito A) ==========="
# Negative test: pgAudit native MUST NOT match mariadb-server-audit.
# We expect rule.id "-" (no match). Use a sentinel.
logtest_assert "neg.pg_in_mariadb"   syslog /var/log/postgresql/postgresql.log \
  '2026-05-27 22:16:00.123 UTC [99999] app_user@prod_db LOG:  AUDIT: SESSION,1,1,DDL,DROP TABLE,TABLE,public.t,DROP TABLE t,<not logged>' \
  "-"

echo
echo "================ SUMMARY ====================================="
printf "PASS:  %d\nFAIL:  %d\nXFAIL: %d\n" \
  "$USER_PASS" "$USER_FAIL" "$USER_XFAIL"

if (( USER_FAIL > 0 )); then
  echo
  echo "Failures:"
  echo "$SUMMARY" | grep -E "^(FAIL|XPASS)" || true
  exit 1
fi
echo "[+] All assertions passed (XFAIL allowed)."
