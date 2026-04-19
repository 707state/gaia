#!/usr/bin/env bash
# Web API integration tests for gaia kernel livepatch endpoints.
#
# Tests every REST endpoint involved in kernel livepatch config management:
#   GET/POST/PUT/DELETE /api/v1/config/kernel-livepatch
#   GET  /api/v1/kernel-livepatch/status
#   POST /api/v1/kernel-livepatch/reload
#   POST /api/v1/config/toggle  (kernel_livepatch section)
#
# Also tests that unrelated endpoints are not broken by the new code.
#
# Usage:
#   bash tests/test_web_api.sh [BASE_URL]
#   BASE_URL defaults to http://localhost:17890
#
# The gaia daemon must be running before executing this script.
# It does NOT need root — only the reload endpoint triggers actual insmod.

set -euo pipefail

BASE="${1:-http://localhost:17890}"
PASS=0; FAIL=0

# ── Helpers ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $*"; FAIL=$((FAIL + 1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }
section() { echo -e "\n${CYAN}=== $* ===${NC}"; }

# curl wrapper: returns body, sets HTTP_STATUS
http() {
  local method="$1" url="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    HTTP_STATUS=$(curl -s -o /tmp/gaia_test_body -w "%{http_code}" \
      -X "$method" "$url" \
      -H "Content-Type: application/json" \
      -d "$body")
  else
    HTTP_STATUS=$(curl -s -o /tmp/gaia_test_body -w "%{http_code}" \
      -X "$method" "$url")
  fi
  BODY=$(cat /tmp/gaia_test_body)
}

assert_status() {
  local expected="$1" label="$2"
  if [[ "$HTTP_STATUS" == "$expected" ]]; then
    pass "$label (HTTP $HTTP_STATUS)"
  else
    fail "$label — expected HTTP $expected, got $HTTP_STATUS. Body: $BODY"
  fi
}

assert_contains() {
  local needle="$1" label="$2"
  if echo "$BODY" | grep -q "$needle"; then
    pass "$label (found: $needle)"
  else
    fail "$label — expected '$needle' in body. Got: $BODY"
  fi
}

assert_not_contains() {
  local needle="$1" label="$2"
  if ! echo "$BODY" | grep -q "$needle"; then
    pass "$label (absent: $needle)"
  else
    fail "$label — expected '$needle' to be absent. Got: $BODY"
  fi
}

assert_json_array_len() {
  local expected="$1" label="$2"
  local actual
  actual=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
  if [[ "$actual" == "$expected" ]]; then
    pass "$label (array length $actual)"
  else
    fail "$label — expected array length $expected, got $actual. Body: $BODY"
  fi
}

json_field() {
  local field="$1"
  echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d$field)" 2>/dev/null || echo "?"
}

json_array_field() {
  local index="$1" field="$2"
  echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[$index]$field)" 2>/dev/null || echo "?"
}

# ── Connectivity check ────────────────────────────────────────────────────────
section "Connectivity"
info "Target: $BASE"

http GET "$BASE/api/v1/state"
if [[ "$HTTP_STATUS" == "200" ]]; then
  pass "Daemon reachable at $BASE"
else
  echo -e "${RED}FATAL: Cannot reach $BASE (HTTP $HTTP_STATUS). Is gaia running?${NC}"
  exit 1
fi

# ── Setup: disable all existing targets so reload tests start from clean state ─
section "Setup"

http GET "$BASE/api/v1/config/kernel-livepatch"
assert_status 200 "GET /config/kernel-livepatch returns 200"
INITIAL_COUNT=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
info "Initial kernel_livepatch targets: $INITIAL_COUNT"

# Disable every existing target so the reload tests control enabled state precisely
for idx in $(seq 0 $((INITIAL_COUNT - 1))); do
  EXISTING=$(echo "$BODY" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(d[$idx]['old_func']+'|'+str(d[$idx]['func_ret'])+'|'+d[$idx]['func_args']+'|'+str(d[$idx]['new_func_body']))" \
    2>/dev/null || echo "")
  OLD_FUNC=$(echo "$EXISTING" | cut -d'|' -f1)
  FUNC_RET=$(echo "$EXISTING"  | cut -d'|' -f2)
  FUNC_ARGS=$(echo "$EXISTING" | cut -d'|' -f3)
  FUNC_BODY=$(echo "$EXISTING" | cut -d'|' -f4-)
  # Fetch the full object and patch enabled=false
  DISABLE_JSON=$(echo "$BODY" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); d[$idx]['enabled']=False; print(json.dumps(d[$idx]))" 2>/dev/null)
  if [[ -n "$DISABLE_JSON" ]]; then
    http PUT "$BASE/api/v1/config/kernel-livepatch/$idx" "$DISABLE_JSON"
    info "Setup: disabled existing target[$idx] ($OLD_FUNC)"
  fi
done

# ── POST: add a target ────────────────────────────────────────────────────────
section "POST /api/v1/config/kernel-livepatch — add target"

TARGET_JSON='{
  "old_func": "cmdline_proc_show",
  "new_func_body": "    seq_puts(m, \"GAIA_TEST\\n\");\n    return 0;",
  "func_ret": "static int",
  "func_args": "struct seq_file *m, void *v",
  "obj_name": null,
  "enabled": true
}'

http POST "$BASE/api/v1/config/kernel-livepatch" "$TARGET_JSON"
assert_status 200 "POST adds target, returns 200"
assert_json_array_len $((INITIAL_COUNT + 1)) "Response array has one more entry"
assert_contains "cmdline_proc_show" "Response contains new old_func"
# Check the newly added entry at NEW_INDEX has enabled=true
NEW_ENABLED=$(echo "$BODY" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d[$INITIAL_COUNT]['enabled'])" 2>/dev/null || echo "?")
if [[ "$NEW_ENABLED" == "True" ]]; then
  pass "New target is enabled by default"
else
  fail "New target is enabled by default — expected True at index $INITIAL_COUNT, got $NEW_ENABLED. Body: $BODY"
fi

# Record the index of the newly added target
NEW_INDEX=$INITIAL_COUNT
info "New target index: $NEW_INDEX"

# ── GET: verify persisted ─────────────────────────────────────────────────────
section "GET /api/v1/config/kernel-livepatch — verify persisted"

http GET "$BASE/api/v1/config/kernel-livepatch"
assert_status 200 "GET returns 200 after add"
assert_json_array_len $((INITIAL_COUNT + 1)) "GET shows correct count after add"
assert_contains "cmdline_proc_show" "GET shows added target"

ENABLED_VAL=$(json_array_field $NEW_INDEX "['enabled']")
if [[ "$ENABLED_VAL" == "True" ]]; then
  pass "GET: target[$NEW_INDEX].enabled is true"
else
  fail "GET: target[$NEW_INDEX].enabled expected True, got $ENABLED_VAL"
fi

# ── PUT: toggle enabled=false ─────────────────────────────────────────────────
section "PUT /api/v1/config/kernel-livepatch/{index} — disable target"

DISABLED_JSON='{
  "old_func": "cmdline_proc_show",
  "new_func_body": "    seq_puts(m, \"GAIA_TEST\\n\");\n    return 0;",
  "func_ret": "static int",
  "func_args": "struct seq_file *m, void *v",
  "obj_name": null,
  "enabled": false
}'

http PUT "$BASE/api/v1/config/kernel-livepatch/$NEW_INDEX" "$DISABLED_JSON"
assert_status 200 "PUT disable returns 200"
assert_contains "cmdline_proc_show" "PUT response still contains the target"

ENABLED_AFTER=$(json_array_field $NEW_INDEX "['enabled']")
if [[ "$ENABLED_AFTER" == "False" ]]; then
  pass "PUT: target[$NEW_INDEX].enabled is now false"
else
  fail "PUT: target[$NEW_INDEX].enabled expected False, got $ENABLED_AFTER"
fi

# ── GET: verify disable persisted ────────────────────────────────────────────
section "GET — verify disable persisted"

http GET "$BASE/api/v1/config/kernel-livepatch"
assert_status 200 "GET after disable returns 200"
ENABLED_PERSISTED=$(json_array_field $NEW_INDEX "['enabled']")
if [[ "$ENABLED_PERSISTED" == "False" ]]; then
  pass "GET: disabled state persisted"
else
  fail "GET: expected enabled=False after PUT, got $ENABLED_PERSISTED"
fi

# ── PUT: toggle enabled=true ──────────────────────────────────────────────────
section "PUT /api/v1/config/kernel-livepatch/{index} — re-enable target"

ENABLED_JSON='{
  "old_func": "cmdline_proc_show",
  "new_func_body": "    seq_puts(m, \"GAIA_TEST\\n\");\n    return 0;",
  "func_ret": "static int",
  "func_args": "struct seq_file *m, void *v",
  "obj_name": null,
  "enabled": true
}'

http PUT "$BASE/api/v1/config/kernel-livepatch/$NEW_INDEX" "$ENABLED_JSON"
assert_status 200 "PUT re-enable returns 200"

ENABLED_REENABLED=$(json_array_field $NEW_INDEX "['enabled']")
if [[ "$ENABLED_REENABLED" == "True" ]]; then
  pass "PUT: target[$NEW_INDEX].enabled is true again"
else
  fail "PUT: expected enabled=True after re-enable, got $ENABLED_REENABLED"
fi

# ── PUT: out-of-bounds index returns 404 ─────────────────────────────────────
section "PUT out-of-bounds index"

http PUT "$BASE/api/v1/config/kernel-livepatch/9999" "$ENABLED_JSON"
assert_status 404 "PUT with out-of-bounds index returns 404"

# ── POST /config/toggle — kernel_livepatch section ───────────────────────────
section "POST /api/v1/config/toggle — kernel_livepatch section"

TOGGLE_OFF="{\"section\": \"kernel_livepatch\", \"index\": $NEW_INDEX, \"enabled\": false}"
http POST "$BASE/api/v1/config/toggle" "$TOGGLE_OFF"
assert_status 200 "Toggle kernel_livepatch off returns 200"

# The toggle endpoint returns the full MonitorPolicy
TOGGLE_ENABLED=$(echo "$BODY" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d['hotpatch']['kernel_livepatch'][$NEW_INDEX]['enabled'])" \
  2>/dev/null || echo "?")
if [[ "$TOGGLE_ENABLED" == "False" ]]; then
  pass "Toggle: kernel_livepatch[$NEW_INDEX].enabled=false in policy response"
else
  fail "Toggle off: expected False in policy, got $TOGGLE_ENABLED"
fi

TOGGLE_ON="{\"section\": \"kernel_livepatch\", \"index\": $NEW_INDEX, \"enabled\": true}"
http POST "$BASE/api/v1/config/toggle" "$TOGGLE_ON"
assert_status 200 "Toggle kernel_livepatch on returns 200"

TOGGLE_ENABLED2=$(echo "$BODY" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d['hotpatch']['kernel_livepatch'][$NEW_INDEX]['enabled'])" \
  2>/dev/null || echo "?")
if [[ "$TOGGLE_ENABLED2" == "True" ]]; then
  pass "Toggle: kernel_livepatch[$NEW_INDEX].enabled=true in policy response"
else
  fail "Toggle on: expected True in policy, got $TOGGLE_ENABLED2"
fi

# ── Toggle with invalid section returns 400 ───────────────────────────────────
section "POST /api/v1/config/toggle — invalid section"

http POST "$BASE/api/v1/config/toggle" '{"section": "nonexistent_section", "index": 0, "enabled": true}'
assert_status 400 "Toggle with unknown section returns 400"

# ── GET /kernel-livepatch/status ──────────────────────────────────────────────
section "GET /api/v1/kernel-livepatch/status"

http GET "$BASE/api/v1/kernel-livepatch/status"
assert_status 200 "GET /kernel-livepatch/status returns 200"
# Response must be a JSON array (may be empty if no modules loaded)
if echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert isinstance(d, list)" 2>/dev/null; then
  pass "Status response is a JSON array"
else
  fail "Status response is not a JSON array. Got: $BODY"
fi

# ── POST /kernel-livepatch/reload — no enabled targets ───────────────────────
section "POST /api/v1/kernel-livepatch/reload — with enabled targets disabled"

# First disable the target so reload has nothing to do
http POST "$BASE/api/v1/config/toggle" \
  "{\"section\": \"kernel_livepatch\", \"index\": $NEW_INDEX, \"enabled\": false}"

http POST "$BASE/api/v1/kernel-livepatch/reload"
assert_status 200 "Reload with no enabled targets returns 200"
assert_contains '"success":true' "Reload with no enabled targets reports success"
assert_contains "no enabled" "Reload message explains no targets"

# Re-enable for subsequent tests
http POST "$BASE/api/v1/config/toggle" \
  "{\"section\": \"kernel_livepatch\", \"index\": $NEW_INDEX, \"enabled\": true}"

# ── POST /kernel-livepatch/reload — with enabled target (build attempt) ───────
section "POST /api/v1/kernel-livepatch/reload — with enabled target"

http POST "$BASE/api/v1/kernel-livepatch/reload"
assert_status 200 "Reload with enabled target returns 200"
# We don't assert success here — it may fail if not root or no kernel-devel,
# but the endpoint must always return 200 with a structured response.
RELOAD_SUCCESS=$(json_field "['success']")
RELOAD_MSG=$(json_field "['message']")
info "Reload result: success=$RELOAD_SUCCESS, message=$RELOAD_MSG"
if [[ "$RELOAD_SUCCESS" == "True" || "$RELOAD_SUCCESS" == "False" ]]; then
  pass "Reload response has boolean 'success' field"
else
  fail "Reload response missing 'success' field. Body: $BODY"
fi
if echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'message' in d" 2>/dev/null; then
  pass "Reload response has 'message' field"
else
  fail "Reload response missing 'message' field"
fi

# ── Kernel patch effect verification ─────────────────────────────────────────
# Verifies the patch actually replaced the kernel function (not just API success).
# Requires daemon running as root.  Skipped gracefully if reload is unavailable.
#
# Toggle and PUT now trigger an async background sync in the daemon, so after
# changing enabled state we poll /proc/cmdline (max 15s) instead of fixed sleep.
section "Kernel patch effect — /proc/cmdline changes"

# Helper: poll /proc/cmdline until it equals $1 or timeout (15s)
wait_cmdline() {
  local expected="$1" label="$2"
  for _ in $(seq 1 30); do
    local val; val=$(cat /proc/cmdline)
    if [[ "$val" == "$expected" ]]; then
      pass "$label (confirmed in /proc/cmdline)"
      return 0
    fi
    sleep 0.5
  done
  fail "$label — timed out waiting for /proc/cmdline = '$expected', got '$(cat /proc/cmdline)'"
  return 1
}

# Helper: poll until /proc/cmdline no longer equals $1 (max 15s)
wait_cmdline_gone() {
  local patched="$1" label="$2"
  for _ in $(seq 1 30); do
    local val; val=$(cat /proc/cmdline)
    if [[ "$val" != "$patched" ]]; then
      pass "$label (confirmed /proc/cmdline restored)"
      return 0
    fi
    sleep 0.5
  done
  fail "$label — timed out, /proc/cmdline still = '$patched'"
  return 1
}

# Use explicit reload to activate the patch and get the module name
http POST "$BASE/api/v1/kernel-livepatch/reload"
EFFECT_RELOAD_SUCCESS=$(json_field "['success']")
EFFECT_MODULE=$(json_field "['module_name']")

if [[ "$EFFECT_RELOAD_SUCCESS" != "True" ]]; then
  info "Reload not successful (running without root?), skipping kernel effect checks"
else
  # 1. /proc/cmdline must show the patched value
  wait_cmdline "GAIA_TEST" "Kernel patch active after reload"

  # 2. sysfs enabled must be 1
  SYSFS="/sys/kernel/livepatch/${EFFECT_MODULE}/enabled"
  if [[ -f "$SYSFS" ]]; then
    SYSFS_VAL=$(cat "$SYSFS")
    if [[ "$SYSFS_VAL" == "1" ]]; then
      pass "sysfs $SYSFS = 1 (patch enabled)"
    else
      fail "sysfs $SYSFS = $SYSFS_VAL, expected 1"
    fi
  else
    fail "sysfs entry $SYSFS not found after successful reload"
  fi

  # 3. Status API must report the module as enabled
  http GET "$BASE/api/v1/kernel-livepatch/status"
  STATUS_ACTIVE=$(echo "$BODY" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(any(m['enabled'] for m in d))" 2>/dev/null || echo "False")
  if [[ "$STATUS_ACTIVE" == "True" ]]; then
    pass "Status API: at least one module enabled=true"
  else
    fail "Status API shows no enabled modules after reload. Body: $BODY"
  fi

  # 4. Status API module name matches what reload returned
  STATUS_HAS_MODULE=$(echo "$BODY" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(any(m['name']=='$EFFECT_MODULE' for m in d))" \
    2>/dev/null || echo "False")
  if [[ "$STATUS_HAS_MODULE" == "True" ]]; then
    pass "Status API: module '$EFFECT_MODULE' present in status list"
  else
    fail "Status API: module '$EFFECT_MODULE' not found. Body: $BODY"
  fi

  # 5. Toggle off → daemon auto-syncs in background → patch removed without reload
  http POST "$BASE/api/v1/config/toggle" \
    "{\"section\": \"kernel_livepatch\", \"index\": $NEW_INDEX, \"enabled\": false}"
  assert_status 200 "Toggle off returns 200"

  wait_cmdline_gone "GAIA_TEST" "Patch auto-removed after toggle off (no explicit reload)"

  # 6. sysfs entry must be gone after auto-unload
  for _ in $(seq 1 30); do
    [[ ! -f "$SYSFS" ]] && break
    sleep 0.5
  done
  if [[ ! -f "$SYSFS" ]]; then
    pass "sysfs entry $SYSFS removed after toggle off"
  else
    fail "sysfs entry $SYSFS still exists after toggle off"
  fi

  # 7. Toggle back on → daemon auto-applies patch again without explicit reload
  http POST "$BASE/api/v1/config/toggle" \
    "{\"section\": \"kernel_livepatch\", \"index\": $NEW_INDEX, \"enabled\": true}"
  assert_status 200 "Toggle on returns 200"

  wait_cmdline "GAIA_TEST" "Patch auto-applied after toggle on (no explicit reload)"

  # 8. PUT enabled=false → same auto-sync behaviour
  http PUT "$BASE/api/v1/config/kernel-livepatch/$NEW_INDEX" '{
    "old_func": "cmdline_proc_show",
    "new_func_body": "    seq_puts(m, \"GAIA_TEST\\n\");\n    return 0;",
    "func_ret": "static int",
    "func_args": "struct seq_file *m, void *v",
    "obj_name": null,
    "enabled": false
  }'
  assert_status 200 "PUT enabled=false returns 200"

  wait_cmdline_gone "GAIA_TEST" "Patch auto-removed after PUT enabled=false"

  # Re-enable via PUT for the DELETE test below
  http PUT "$BASE/api/v1/config/kernel-livepatch/$NEW_INDEX" '{
    "old_func": "cmdline_proc_show",
    "new_func_body": "    seq_puts(m, \"GAIA_TEST\\n\");\n    return 0;",
    "func_ret": "static int",
    "func_args": "struct seq_file *m, void *v",
    "obj_name": null,
    "enabled": true
  }'
fi

# ── DELETE /config/kernel-livepatch/{index} ───────────────────────────────────
section "DELETE /api/v1/config/kernel-livepatch/{index}"

http DELETE "$BASE/api/v1/config/kernel-livepatch/$NEW_INDEX"
assert_status 200 "DELETE returns 200"
assert_json_array_len $INITIAL_COUNT "Array length back to initial after delete"
# Verify the array shrank back — the specific test entry (index NEW_INDEX) is gone
AFTER_DELETE_LEN=$(echo "$BODY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
if [[ "$AFTER_DELETE_LEN" == "$INITIAL_COUNT" ]]; then
  pass "Deleted target no longer in response (length back to $INITIAL_COUNT)"
else
  fail "Deleted target still present — expected length $INITIAL_COUNT, got $AFTER_DELETE_LEN"
fi

# ── GET: verify delete persisted ─────────────────────────────────────────────
section "GET — verify delete persisted"

http GET "$BASE/api/v1/config/kernel-livepatch"
assert_status 200 "GET after delete returns 200"
assert_json_array_len $INITIAL_COUNT "GET shows original count after delete"

# ── Regression: existing endpoints unaffected ─────────────────────────────────
section "Regression — existing endpoints unaffected"

http GET "$BASE/api/v1/state"
assert_status 200 "GET /state still works"

http GET "$BASE/api/v1/config"
assert_status 200 "GET /config still works"
assert_contains "sensitive_prefixes" "Config still has sensitive_prefixes"
assert_contains "hotpatch" "Config still has hotpatch section"

http GET "$BASE/api/v1/config/hotpatch"
assert_status 200 "GET /config/hotpatch still works"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
TOTAL=$((PASS + FAIL))
if [[ $FAIL -eq 0 ]]; then
  echo -e "${GREEN}All $TOTAL tests passed.${NC}"
else
  echo -e "${RED}$FAIL/$TOTAL tests FAILED.${NC}"
  exit 1
fi
