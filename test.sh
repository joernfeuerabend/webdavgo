#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jörn Feuerabend

# test.sh – 150 success criteria: MVP, admin-ui, SEARCH grammar, creationdate, shares, share-list-fields, migrations,
# sync conformance (conditional requests, ETags, atomic PUT, SEARCH Date/orderby/limit, 401 vs 503),
# server foundation (config file/flags, temp-file cleanup, graceful shutdown, auth cache, request limits),
# internet readiness (brute-force protection, slow-body limits, shutdown race, TLS via ACME against Pebble),
# admin hardening (TLS-only admin listener, mandatory TOTP, CSRF and security headers, session
# invalidation, brute-force overview, effective configuration), deployment (install/uninstall,
# require_tls, setup-info, settings precedence, Domain & certificate wizard against Pebble on :443,
# HTTP/2 stream limit, brute-force table eviction, session epoch, slow reads, CLI schema checks),
# log files (access_log/server_log, reopen on SIGUSR1).
# Starts/restarts the server as needed, prints PASS/FAIL, exits non-zero on failure.
#
# Admin requests go to https://localhost:8443 and trust the server's self-signed
# certificate through its file (--cacert), not -k. TOTP codes come from
# tools/totpcode, a separate Go program built once below: oathtool is not
# installed by default on macOS, and keeping the generator out of the server
# binary means the test checks the server against an independent
# implementation.

set -euo pipefail

# Usage: ./test.sh [Cn | Cn-Cm]...
# Without arguments every criterion runs. With arguments only the named
# criteria and ranges are reported, and the run ends as soon as the last of
# them has been checked. The script is one sequence whose criteria build on
# each other's state, so the steps before a selected criterion still run;
# selecting early criteria is fast, late ones save little.
SELECTED=" "
for arg in "$@"; do
    if [[ "$arg" =~ ^C([0-9]+)(-C?([0-9]+))?$ ]]; then
        lo=${BASH_REMATCH[1]}; hi=${BASH_REMATCH[3]:-$lo}
        for ((n = lo; n <= hi; n++)); do SELECTED+="C$n "; done
    else
        echo "usage: $0 [Cn | Cn-Cm]..." >&2; exit 2
    fi
done
# REMAINING holds the selected criteria not checked yet.
REMAINING="$SELECTED"

WEBDAV_URL="http://localhost:8080"
WEBGUI_URL="https://localhost:8443"
STDOUT_FILE="/tmp/webdavgo_test_stdout.txt"
# A log line is "<time> <LEVEL> <message> <attrs>", the time in RFC 3339
# with milliseconds. LOG matches up to the time, LOGMSG up to the message,
# so "${LOGMSG}request " finds the message, never an attribute value.
LOG='^[0-9]\{4\}-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9][Z+-][0-9:]*'
LOGMSG="$LOG [A-Z][A-Z]* "
PASS=0
FAIL=0
SERVER_PID=""

# All test data lives here — never touches the repo's live data/ directory.
TEST_DIR=$(mktemp -d /tmp/webdavgo_test.XXXXXX)
# Resolve symlinks (macOS: /tmp → /private/tmp) so the server and sqlite3 share
# the same canonical path for WAL coordination.
TEST_DIR=$(cd "$TEST_DIR" && pwd -P)
# Deliberately not ./data: C77 proves the server uses data_dir from the config
# file and creates nothing under its working directory's ./data.
DATA_DIR="$TEST_DIR/store"
CONFIG_FILE="$TEST_DIR/webdavgo.toml"
TEST_DB="$DATA_DIR/webdavgo.db"
# The admin listener's self-signed certificate; curl trusts exactly this file.
ADMIN_CA="$DATA_DIR/certs/admin-selfsigned.crt"
TOTP_BIN="$TEST_DIR/totpcode"
go build -o "$TOTP_BIN" ./tools/totpcode
# curl does not show the server's HTTP/2 SETTINGS; tools/h2settings does (C132).
H2_BIN="$TEST_DIR/h2settings"
go build -o "$H2_BIN" ./tools/h2settings

check() {
    local label="$1" result="$2" id="${1%%:*}"
    if [[ "$SELECTED" != " " && "$SELECTED" != *" $id "* ]]; then return; fi
    if [[ "$result" == "pass" ]]; then echo "PASS: $label"; ((PASS++)) || true
    else echo "FAIL: $label"; ((FAIL++)) || true; fi
    REMAINING="${REMAINING/ $id / }"
    if [[ "$SELECTED" != " " && "$REMAINING" == " " ]]; then summary; fi
}

# summary prints the totals and ends the run (the EXIT trap cleans up).
summary() {
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    [[ "$FAIL" -eq 0 ]] && exit 0
    exit 1
}

# write_config writes the test config; arguments are extra TOML lines.
# read_header_timeout is short so C87 does not have to wait 10 s.
# Brute-force protection is relaxed unless the arguments set it: the earlier
# criteria send far more failed logins from localhost than the defaults
# allow, and C90-C94 test the limits with their own small values. The rate
# limit for requests without credentials is relaxed the same way.
write_config() {
    {
        echo "data_dir = \"$DATA_DIR\""
        echo 'read_header_timeout = "2s"'
        local line relaxed=yes unauth_relaxed=yes
        for line in "$@"; do
            echo "$line"
            [[ "$line" == bruteforce_* ]] && relaxed=no
            [[ "$line" == unauth_* ]] && unauth_relaxed=no
        done
        if [[ "$relaxed" == yes ]]; then
            echo 'bruteforce_ip_threshold = 100000'
            echo 'bruteforce_account_threshold = 100000'
        fi
        if [[ "$unauth_relaxed" == yes ]]; then
            echo 'unauth_rate = 100000'
            echo 'unauth_burst = 100000'
        fi
    } >"$CONFIG_FILE"
}
write_config

# start_server passes its arguments to the server as extra flags.
start_server() {
    go build -o "$TEST_DIR/webdavgo" ./cmd/webdavgo
    start_binary webdavgo "$@"
}

# start_binary starts $TEST_DIR/$1 with the test config; further arguments
# are extra flags.
start_binary() {
    local bin="$1"; shift
    rm -f "$STDOUT_FILE"
    # exec so SERVER_PID is the server itself; bash 3.2 does not exec the last
    # command of a subshell, and stop_server would otherwise orphan the server.
    (cd "$TEST_DIR" && exec "./$bin" -config "$CONFIG_FILE" "$@") >"$STDOUT_FILE" 2>&1 &
    SERVER_PID=$!
    for i in $(seq 1 20); do
        curl -s --max-time .3 "$WEBDAV_URL/" >/dev/null 2>&1 && break
        sleep 0.25
    done
    sleep 0.4
}

stop_server() {
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
}

PEBBLE_PID=""
CHALL_PID=""

cleanup() {
    stop_server
    [[ -n "$PEBBLE_PID" ]] && kill "$PEBBLE_PID" 2>/dev/null || true
    [[ -n "$CHALL_PID" ]] && kill "$CHALL_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "$STDOUT_FILE"
    rm -rf "$TEST_DIR"
    rm -f /tmp/webdavgo_newer_fail.txt
}
trap cleanup EXIT

# ---- admin helpers -----------------------------------------------------------

# gui is curl against the admin listener.
gui() { curl -s --cacert "$ADMIN_CA" "$@"; }

# agui sends an authenticated admin request the way the browser UI does:
# session cookie, CSRF header (as HTMX sends it) and the listener's own Origin.
agui() { gui -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "Origin: $WEBGUI_URL" "$@"; }

# cookie_of prints the session cookie set in the response headers $1.
cookie_of() { echo "$1" | grep -io 'webdavgo_session=[0-9a-f]*' | head -1 || true; }

# status_line prints the status code of the response headers $1.
status_line() { echo "$1" | head -1 | awk '{print $2}' || true; }

# location_of prints the Location header of the response headers $1.
location_of() { echo "$1" | grep -i '^location:' | head -1 | awk '{print $2}' | tr -d '\r' || true; }

# csrf_of prints the CSRF token found on page $2 of session $1.
csrf_of() {
    gui -H "Cookie: $1" "$WEBGUI_URL$2" | grep -o 'name="csrf_token" value="[0-9a-f]*"' | head -1 \
        | sed 's/.*value="//; s/"$//' || true
}

# secret_of prints the TOTP secret shown on the enrolment page of session $1.
secret_of() {
    gui -H "Cookie: $1" "$WEBGUI_URL/admin/enrol" | grep -o 'class="secret">[A-Z2-7 ]*' | head -1 \
        | sed 's/.*>//; s/ //g' || true
}

# totp_for sets TOTP_CODE to a code for secret $1 whose time step is newer
# than the one in the variable named $2, and stores that step there. The
# server rejects a step that is not newer than the last accepted one, so
# frequent logins use the window of one step either side and wait for the
# next step once it is used up. The previous step is only used early in a
# step, so the server's clock cannot have moved past it.
#
# With an account name in $3, a used-up window does not wait up to 30 s
# for the next step: the account's replay marker (totp.last_step in
# $TOTP_DB) and the variable are moved back two steps instead. Only the
# logins that set up a session do that; replay rejection itself is C110,
# whose code and replay sit between two totp_for calls.
totp_for() {
    local secret="$1" var="$2" user="${3:-}" last now step s
    while :; do
        last=${!var}; now=$(date +%s); step=$((now / 30))
        for s in $((step - 1)) $step $((step + 1)); do
            if (( s == step - 1 && now % 30 > 25 )); then continue; fi
            if (( s > last )); then
                eval "$var=$s"
                TOTP_CODE=$("$TOTP_BIN" "$secret" $((s * 30)))
                return
            fi
        done
        if [[ -n "$user" ]]; then
            sqlite3 -cmd '.timeout 5000' "$TOTP_DB" \
                "UPDATE totp SET last_step = $((step - 2)) WHERE username = '$user';"
            eval "$var=$((step - 2))"
            continue
        fi
        sleep $(( (step + 1) * 30 - now ))
    done
}
# TOTP_DB is the database of the running server; the ACME criteria switch it.
TOTP_DB="$TEST_DB"
ADMIN_SECRET=""; ADMIN_STEP=0

# second_factor submits code $2 on the TOTP page with pending session $1 via
# base URL $3 (default WEBGUI_URL) and prints the response headers.
second_factor() {
    local base="${3:-$WEBGUI_URL}" csrf
    csrf=$(csrf_of "$1" /admin/totp)
    curl -s --cacert "$ADMIN_CA" -D - -o "$TEST_DIR/totp_body.html" -H "Cookie: $1" -H "X-CSRF-Token: $csrf" \
        -X POST "$base/admin/totp" -d "code=$2" || true
}

# password_login prints the response headers of the password step for user
# $1 with password $2 via base URL $3 (default WEBGUI_URL).
password_login() {
    curl -s --cacert "$ADMIN_CA" -D - -o "$TEST_DIR/login_body.html" -X POST "${3:-$WEBGUI_URL}/admin/login" \
        -d "username=$1&password=$2" || true
}

# login_admin logs in as admin with password and TOTP and sets SESSION and
# CSRF for agui.
login_admin() {
    local hdrs
    SESSION=$(cookie_of "$(password_login admin adminpass123)")
    totp_for "$ADMIN_SECRET" ADMIN_STEP admin
    hdrs=$(second_factor "$SESSION" "$TOTP_CODE")
    SESSION=$(cookie_of "$hdrs")
    CSRF=$(csrf_of "$SESSION" /admin/users)
}

# enrol completes TOTP enrolment for the pending session $1; it sets
# ENROL_SECRET, ENROL_STEP, ENROL_HDRS and saves the recovery page in
# $TEST_DIR/recovery.html.
enrol() {
    local csrf
    ENROL_SECRET=$(secret_of "$1")
    csrf=$(csrf_of "$1" /admin/enrol)
    ENROL_STEP=0
    totp_for "$ENROL_SECRET" ENROL_STEP
    ENROL_HDRS=$(gui -D - -o "$TEST_DIR/recovery.html" -H "Cookie: $1" -H "X-CSRF-Token: $csrf" \
        -X POST "$WEBGUI_URL/admin/enrol" -d "code=$TOTP_CODE" || true)
}

# fingerprint_of prints the SHA-256 fingerprint of the certificate the
# server at 127.0.0.1:$1 presents for SNI $2, in the format of the log line.
fingerprint_of() {
    openssl s_client -connect "127.0.0.1:$1" -servername "$2" </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' || true
}

# ---- fresh start ------------------------------------------------------------
start_server
sleep 0.5

# Bootstrap: complete setup (admin account, then TOTP enrolment), create
# alice. The intermediate states feed C104-C108.
STDOUT=$(cat "$STDOUT_FILE")
FIRST_LOG="$TEST_DIR/first_start.txt"; cp "$STDOUT_FILE" "$FIRST_LOG"
TOKEN=$(echo "$STDOUT" | grep -o 'https://localhost:8443/setup?token=[0-9a-f]*' | head -1 | sed 's/.*token=//')
ADMIN_FP=$(grep -o "$LOGMSG"'"admin certificate" sha256=[0-9A-F:]*' "$STDOUT_FILE" | head -1 | sed 's/.*sha256=//' || true)

# C104 data: plain HTTP and TLS 1.1 against the admin port.
C104_HTTP=$(curl -s -D - --max-time 3 "http://localhost:8443/admin/login" || true)
C104_TLS11=$(openssl s_client -connect 127.0.0.1:8443 -tls1_1 </dev/null 2>&1 | grep -c 'BEGIN CERTIFICATE' || true)
C104_TLS12=$(openssl s_client -connect 127.0.0.1:8443 -tls1_2 </dev/null 2>&1 | grep -c 'BEGIN CERTIFICATE' || true)
# The page is kept for C123/C124; the setup form only exists before setup.
C104_HTTPS=$(gui -o "$TEST_DIR/setup.html" -w '%{http_code}' "$WEBGUI_URL/setup?token=$TOKEN" || true)

SETUP_HDRS=$(gui -D - -o /dev/null -X POST "$WEBGUI_URL/setup?token=$TOKEN" \
    -d "username=admin&password=adminpass123&password_confirm=adminpass123" || true)
SESSION=$(cookie_of "$SETUP_HDRS")
# Setup must not be complete before TOTP is confirmed.
C108_DAV_PENDING=$(curl -s -o /dev/null -w '%{http_code}' -u admin:adminpass123 "$WEBDAV_URL/" || true)
C108_SETUP_AGAIN=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' "$WEBGUI_URL/setup?token=$TOKEN" || true)
C108_USERS_PENDING=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' -H "Cookie: $SESSION" "$WEBGUI_URL/admin/users" || true)
enrol "$SESSION"
ADMIN_SECRET="$ENROL_SECRET"; ADMIN_STEP="$ENROL_STEP"
SESSION=$(cookie_of "$ENROL_HDRS")
CSRF=$(csrf_of "$SESSION" /admin/users)
RECOVERY_CODES=($(grep -o '<li><code>[a-z2-7-]*</code>' "$TEST_DIR/recovery.html" | sed 's/<[^>]*>//g' || true))
C108_DAV_DONE=$(curl -s -o /dev/null -w '%{http_code}' -u admin:adminpass123 -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/" || true)
C108_AGAIN=0
for page in /admin/ /admin/enrol /admin/users /admin/status; do
    if gui -L -H "Cookie: $SESSION" "$WEBGUI_URL$page" | grep -q "${RECOVERY_CODES[0]:-none}"; then C108_AGAIN=1; fi
done
C108_DB=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM recovery_codes WHERE username='admin' AND used_at IS NULL;" 2>/dev/null || echo 0)
C108_PLAIN=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM recovery_codes WHERE code_hash LIKE '%${RECOVERY_CODES[0]:-none}%';" 2>/dev/null || echo 1)

# Create alice.
agui -X POST "$WEBGUI_URL/admin/users" -d "username=alice&password=alicepass1&role=user" >/dev/null

# PUT some initial files for admin.
curl -s -X PUT -u admin:adminpass123 --data 'hello' "$WEBDAV_URL/hello.txt" >/dev/null
curl -s -X PUT -u admin:adminpass123 --data 'secret content' "$WEBDAV_URL/secret.txt" >/dev/null
curl -s -X PUT -u admin:adminpass123 --data 'auth module log' "$WEBDAV_URL/auth_log.txt" >/dev/null
curl -s -X PUT -u admin:adminpass123 --data 'log_2026_01.txt content' "$WEBDAV_URL/log_2026_01.txt" >/dev/null

# ---- C104: the admin port speaks TLS (≥ 1.2) only -----------------------------
# Go answers plaintext on a TLS port with a bare 400; no admin page is served.
C104_STATUS=$(status_line "$C104_HTTP")
C104_PAGE=$(echo "$C104_HTTP" | grep -c 'webdavgo' || true)
if [[ "$C104_STATUS" == "400" && "$C104_PAGE" == "0" && "$C104_HTTPS" == "200" \
      && "$C104_TLS12" -gt 0 && "$C104_TLS11" == "0" ]]; then
    check "C104: admin port: plain HTTP → 400 without page, TLS 1.1 refused, HTTPS (TLS 1.2+) → 200" pass
else
    check "C104: admin TLS only (http=$C104_STATUS page=$C104_PAGE https=$C104_HTTPS tls12=$C104_TLS12 tls11=$C104_TLS11)" fail
fi

# ---- C107: setup block: admin URLs, fingerprint, Token: line and setup links -
C107_LAN=$(grep -E 'https://([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[[0-9a-f:]+\]):8443/setup\?token=[0-9a-f]{64}' "$FIRST_LOG" \
    | grep -vc -e '//127\.' -e '//\[::1\]' || true)
C107_LOCAL=$(grep -c "https://localhost:8443/setup?token=$TOKEN" "$FIRST_LOG" || true)
C107_HTTP=$(grep -c 'http://[^ ]*/setup' "$FIRST_LOG" || true)
C107_FP=$(grep -cxF "       $ADMIN_FP" "$FIRST_LOG" || true)
C107_WARN=$(grep -c 'The browser warns that the certificate is self-signed\.' "$FIRST_LOG" || true)
C107_ADMIN=$(grep -cx '       https://localhost:8443/' "$FIRST_LOG" || true)
C107_TOKEN_LINE=$(grep -cxF "       Token: $TOKEN" "$FIRST_LOG" || true)
C107_TOKEN_LOGGED=$(grep "$LOG" "$FIRST_LOG" | grep -c "$TOKEN" || true)
if [[ "$C107_LAN" -gt 0 && "$C107_LOCAL" == "1" && "$C107_HTTP" == "0" && -n "$ADMIN_FP" && "$C107_FP" == "1" \
      && "$C107_WARN" == "1" && "$C107_ADMIN" == "1" && "$C107_TOKEN_LINE" == "1" && "$C107_TOKEN_LOGGED" == "0" ]]; then
    check "C107: setup block lists admin URLs ending in /, the certificate fingerprint on its own line, the Token: line and https:// setup links for $C107_LAN LAN address(es) and localhost" pass
else
    check "C107: setup block (lan_urls=$C107_LAN localhost=$C107_LOCAL http_urls=$C107_HTTP fp=$C107_FP warn=$C107_WARN admin_url=$C107_ADMIN token_line=$C107_TOKEN_LINE token_in_log=$C107_TOKEN_LOGGED)" fail
fi

# ---- C108: setup completes only with TOTP; recovery codes shown once ---------
if [[ "$C108_DAV_PENDING" == "503" && "$C108_SETUP_AGAIN" == "303 $WEBGUI_URL/admin/enrol" \
      && "$C108_USERS_PENDING" == "303 $WEBGUI_URL/admin/enrol" && "$(status_line "$ENROL_HDRS")" == "200" \
      && "${#RECOVERY_CODES[@]}" == "10" && "$C108_DAV_DONE" == "207" && "$C108_AGAIN" == "0" \
      && "$C108_DB" == "10" && "$C108_PLAIN" == "0" ]]; then
    check "C108: after the admin account WebDAV stays 503 and setup leads to TOTP enrolment; confirming shows 10 recovery codes once (stored hashed), then WebDAV works" pass
else
    check "C108: setup with TOTP (dav_pending=$C108_DAV_PENDING setup_again=[$C108_SETUP_AGAIN] users=[$C108_USERS_PENDING] enrol=$(status_line "$ENROL_HDRS") codes=${#RECOVERY_CODES[@]} dav_done=$C108_DAV_DONE shown_again=$C108_AGAIN db=$C108_DB plain=$C108_PLAIN)" fail
fi

# ---- Criterion 1: PROPFIND returns creationdate in ISO 8601 ----------------
PF1=$(curl -s -X PROPFIND -u admin:adminpass123 -H "Depth: 0" "$WEBDAV_URL/hello.txt")
if echo "$PF1" | grep -qiE 'creationdate|[0-9]{4}-[0-9]{2}-[0-9]{2}T'; then
    check "C1: PROPFIND returns creationdate (ISO 8601)" pass
else
    check "C1: PROPFIND returns creationdate (ISO 8601)" fail
fi

# ---- Criterion 2: SEARCH select only getetag --------------------------------
SEARCH2=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:getetag/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
if echo "$SEARCH2" | grep -q "getetag" && ! echo "$SEARCH2" | grep -q "getlastmodified"; then
    check "C2: SEARCH select only getetag returns only getetag" pass
else
    check "C2: SEARCH select only getetag returns only getetag" fail
fi

# ---- Criterion 3: unknown property returns 404 propstat --------------------
SEARCH3=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:getetag/><d:nonexistent/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
if echo "$SEARCH3" | grep -q "nonexistent" && echo "$SEARCH3" | grep -q "404"; then
    check "C3: Unknown property returns 404 propstat block" pass
else
    check "C3: Unknown property returns 404 propstat block" fail
fi

# ---- Criterion 4: SEARCH with <and> ----------------------------------------
sleep 1
T0=$(date -uR)
sleep 2
curl -s -X PUT -u admin:adminpass123 --data 'new content' "$WEBDAV_URL/new_small.txt" >/dev/null

SEARCH4=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data "<?xml version='1.0'?>
<d:searchrequest xmlns:d='DAV:'>
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:and>
      <d:gt><d:prop><d:getlastmodified/></d:prop><d:literal>$T0</d:literal></d:gt>
      <d:lt><d:prop><d:getcontentlength/></d:prop><d:literal>1000000</d:literal></d:lt>
    </d:and></d:where>
  </d:basicsearch>
</d:searchrequest>" "$WEBDAV_URL/")
if echo "$SEARCH4" | grep -q "new_small.txt" && ! echo "$SEARCH4" | grep -q "hello.txt"; then
    check "C4: SEARCH <and> matches files after T0 AND size<1MB" pass
else
    check "C4: SEARCH <and> (has new=$(echo "$SEARCH4"|grep -c new_small.txt) no old=$(echo "$SEARCH4"|grep -c hello.txt))" fail
fi

# ---- Criterion 5: SEARCH with <or> -----------------------------------------
SEARCH5=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data "<?xml version='1.0'?>
<d:searchrequest xmlns:d='DAV:'>
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:or>
      <d:eq><d:prop><d:displayname/></d:prop><d:literal>hello.txt</d:literal></d:eq>
      <d:eq><d:prop><d:displayname/></d:prop><d:literal>secret.txt</d:literal></d:eq>
    </d:or></d:where>
  </d:basicsearch>
</d:searchrequest>" "$WEBDAV_URL/")
HAS_HELLO=$(echo "$SEARCH5" | grep -c "hello.txt" || true)
HAS_SECRET=$(echo "$SEARCH5" | grep -c "secret.txt" || true)
HAS_OTHER=$(echo "$SEARCH5" | grep -c "auth_log.txt" || true)
if [[ "$HAS_HELLO" -gt 0 && "$HAS_SECRET" -gt 0 && "$HAS_OTHER" -eq 0 ]]; then
    check "C5: SEARCH <or> returns union of matches" pass
else
    check "C5: SEARCH <or> (hello=$HAS_HELLO secret=$HAS_SECRET other=$HAS_OTHER)" fail
fi

# ---- Criterion 6: SEARCH with <not><eq> ------------------------------------
SEARCH6=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:not><d:eq>
      <d:prop><d:displayname/></d:prop><d:literal>secret.txt</d:literal>
    </d:eq></d:not></d:where>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
NO_SECRET=$(echo "$SEARCH6" | grep -c "secret.txt" || true)
HAS_HELLO6=$(echo "$SEARCH6" | grep -c "hello.txt" || true)
if [[ "$NO_SECRET" -eq 0 && "$HAS_HELLO6" -gt 0 ]]; then
    check "C6: SEARCH <not><eq> excludes secret.txt" pass
else
    check "C6: SEARCH <not><eq> (no_secret=$NO_SECRET has_hello=$HAS_HELLO6)" fail
fi

# ---- Criterion 7: SEARCH with <like> ----------------------------------------
SEARCH7=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:like>
      <d:prop><d:displayname/></d:prop><d:literal>log_%.txt</d:literal>
    </d:like></d:where>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
HAS_LOG=$(echo "$SEARCH7" | grep -c "log_2026_01.txt" || true)
NO_HELLO=$(echo "$SEARCH7" | grep -c "hello.txt" || true)
if [[ "$HAS_LOG" -gt 0 && "$NO_HELLO" -eq 0 ]]; then
    check "C7: SEARCH <like> log_%.txt matches log file" pass
else
    check "C7: SEARCH <like> (has_log=$HAS_LOG no_hello=$NO_HELLO)" fail
fi

# ---- Criterion 8: SEARCH with <contains> ------------------------------------
SEARCH8=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:contains>
      <d:prop><d:displayname/></d:prop><d:literal>auth</d:literal>
    </d:contains></d:where>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
HAS_AUTH=$(echo "$SEARCH8" | grep -c "auth_log.txt" || true)
NO_HELLO8=$(echo "$SEARCH8" | grep -c "hello.txt" || true)
if [[ "$HAS_AUTH" -gt 0 && "$NO_HELLO8" -eq 0 ]]; then
    check "C8: SEARCH <contains> 'auth' matches auth_log.txt" pass
else
    check "C8: SEARCH <contains> (has_auth=$HAS_AUTH no_hello=$NO_HELLO8)" fail
fi

# ---- Criterion 9: SEARCH with empty <where/> returns everything -------------
SEARCH9_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X SEARCH \
    -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where/>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
SEARCH9=$(curl -s -X SEARCH -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where/>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
HAS_ALL=$(echo "$SEARCH9" | grep -c "hello.txt" || true)
if [[ "$SEARCH9_STATUS" == "207" && "$HAS_ALL" -gt 0 ]]; then
    check "C9: SEARCH empty <where/> returns all files (207)" pass
else
    check "C9: SEARCH empty <where/> (status=$SEARCH9_STATUS has_all=$HAS_ALL)" fail
fi

# ---- Criterion 10: unknown where-element returns 400 -----------------------
S10=$(curl -s -o /dev/null -w "%{http_code}" -X SEARCH \
    -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:frobnicator/></d:where>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
if [[ "$S10" == "400" ]]; then check "C10: Unknown where-element → 400" pass
else check "C10: Unknown where-element → 400 (got $S10)" fail; fi

# ---- Criterion 11: ordered comparison on string property → 400 -------------
S11=$(curl -s -o /dev/null -w "%{http_code}" -X SEARCH \
    -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?>
<d:searchrequest xmlns:d="DAV:">
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:gt>
      <d:prop><d:displayname/></d:prop><d:literal>zzz</d:literal>
    </d:gt></d:where>
  </d:basicsearch>
</d:searchrequest>' "$WEBDAV_URL/")
if [[ "$S11" == "400" ]]; then check "C11: gt on string property → 400" pass
else check "C11: gt on string property → 400 (got $S11)" fail; fi

# ---- C58: fresh start → user_version equals target_version (3) ---------------
UV58=$(sqlite3 "$TEST_DB" "PRAGMA user_version;" 2>/dev/null || echo -1)
if [[ "$UV58" == "3" ]]; then
    check "C58: fresh start → PRAGMA user_version == 3 (target)" pass
else
    check "C58: user_version after fresh start (got $UV58, want 3)" fail
fi

# ---- Criterion 12: v1→v3 migration (stop → set v1 + plant tombstones → restart → verify) --
# Simulate a DB stuck at schema v1. On restart the v2 migration must drop tombstones.
stop_server
sqlite3 "$TEST_DB" \
    "PRAGMA user_version = 1;
     CREATE TABLE IF NOT EXISTS tombstones (username TEXT, path TEXT, deleted_at TEXT,
     PRIMARY KEY(username,path));
     INSERT INTO tombstones VALUES('legacy','/legacy.txt','2026-01-01T00:00:00Z');" \
    2>/dev/null
start_server
sleep 0.5
TOMB_TABLE=$(sqlite3 "$TEST_DB" ".tables" 2>/dev/null | tr -s '[:space:]' '\n' \
    | grep -c '^tombstones$' || true)
VER12=$(sqlite3 "$TEST_DB" "PRAGMA user_version;" 2>/dev/null || echo -1)
if [[ "$TOMB_TABLE" == "0" && "$VER12" == "3" ]]; then
    check "C12: v1→v3 migration drops tombstones, user_version now 3" pass
else
    check "C12: tombstones migration (tomb=$TOMB_TABLE ver=$VER12)" fail
fi
# In-memory sessions don't survive server restarts; re-authenticate.
login_admin

# ---- C105: the self-signed admin certificate is created once ------------------
C105_CREATED_FIRST=$(grep -c "$LOGMSG"'"admin certificate created"' "$FIRST_LOG" || true)
C105_CREATED_AGAIN=$(grep -c "$LOGMSG"'"admin certificate created"' "$STDOUT_FILE" || true)
C105_LOGGED=$(grep -c "$LOGMSG\"admin certificate\" sha256=$ADMIN_FP " "$STDOUT_FILE" || true)
C105_SERVED=$(fingerprint_of 8443 localhost)
C105_KEYMODE=$(stat -f '%Lp' "$DATA_DIR/certs/admin-selfsigned.key" 2>/dev/null || stat -c '%a' "$DATA_DIR/certs/admin-selfsigned.key")
C105_ALG=$(openssl x509 -in "$ADMIN_CA" -noout -text 2>/dev/null | grep -c 'ASN1 OID: prime256v1' || true)
C105_SAN=$(openssl x509 -in "$ADMIN_CA" -noout -text 2>/dev/null | grep -c 'DNS:localhost.*IP Address:127.0.0.1' || true)
if [[ "$C105_CREATED_FIRST" == "1" && "$C105_CREATED_AGAIN" == "0" && "$C105_LOGGED" == "1" \
      && "$C105_SERVED" == "$ADMIN_FP" && "$C105_KEYMODE" == "600" && "$C105_ALG" == "1" && "$C105_SAN" == "1" ]]; then
    check "C105: admin certificate (ECDSA P-256) created once, key 0600; after restart same fingerprint served and logged" pass
else
    check "C105: admin certificate (created=$C105_CREATED_FIRST/$C105_CREATED_AGAIN logged=$C105_LOGGED served=$C105_SERVED want=$ADMIN_FP keymode=$C105_KEYMODE p256=$C105_ALG san=$C105_SAN)" fail
fi

# ---- Criterion 13: REPORT falls through to webdav handler (not 207) ---------
S13=$(curl -s -o /dev/null -w "%{http_code}" -X REPORT \
    -u admin:adminpass123 "$WEBDAV_URL/")
if [[ "$S13" != "207" ]]; then
    check "C13: REPORT not handled by us (returns $S13)" pass
else
    check "C13: REPORT should not return 207 (got $S13)" fail
fi

# ---- Criterion 14: tokens table absent after migration ----------------------
TOKENS_TABLE=$(sqlite3 "$TEST_DB" ".tables" 2>/dev/null | tr -s '[:space:]' '\n' \
    | grep -c '^tokens$' || true)
if [[ "$TOKENS_TABLE" == "0" ]]; then
    check "C14: tokens table absent from DB after migration" pass
else
    check "C14: tokens table should not exist (found=$TOKENS_TABLE)" fail
fi

# ---- Criterion 15: WebDAV PUT with tok_ password → 401 (path removed) ------
S15=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "alice:tok_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    --data 'x' "$WEBDAV_URL/x.txt")
if [[ "$S15" == "401" ]]; then check "C15: WebDAV PUT with tok_ password → 401" pass
else check "C15: tok_ WebDAV auth (got $S15)" fail; fi

# ---- Criterion 16: share API with tok_ password → 401 -----------------------
S16=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u "alice:tok_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"x@x.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S16" == "401" ]]; then check "C16: Share API POST with tok_ password → 401" pass
else check "C16: tok_ share API auth (got $S16)" fail; fi

# ---- Criterion 17: /admin/users/{name}/tokens route is gone (→ 404) ---------
S17=$(curl -s -o /dev/null -w "%{http_code}" \
    "$WEBGUI_URL/admin/users/admin/tokens" -H "Cookie: $SESSION" --cacert "$ADMIN_CA")
if [[ "$S17" == "404" ]]; then check "C17: GET /admin/users/admin/tokens → 404 (route removed)" pass
else check "C17: tokens admin route (got $S17)" fail; fi

# ---- Criterion 18: password-based auth still works --------------------------
S18=$(curl -s -o /dev/null -w "%{http_code}" -u admin:adminpass123 "$WEBDAV_URL/hello.txt")
if [[ "$S18" =~ ^(200|207)$ ]]; then check "C18: Password-based auth still works" pass
else check "C18: Password-based auth (got $S18)" fail; fi

# ---- Criterion 19: regression check (MVP + admin-ui + SEARCH + PROPFIND) ----
PF19=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u admin:adminpass123 -H "Depth: 1" "$WEBDAV_URL/")
NO_AUTH19=$(curl -s -o /dev/null -w "%{http_code}" "$WEBDAV_URL/hello.txt")
SEARCH19=$(curl -s -o /dev/null -w "%{http_code}" -X SEARCH \
    -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:"><d:basicsearch>
      <d:select><d:prop><d:getetag/></d:prop></d:select>
      <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
      <d:where/>
    </d:basicsearch></d:searchrequest>' "$WEBDAV_URL/")
ADMIN_UI19=$(agui -o /dev/null -w "%{http_code}" "$WEBGUI_URL/admin/users")
if [[ "$PF19" == "207" && "$NO_AUTH19" == "401" && \
      "$SEARCH19" == "207" && "$ADMIN_UI19" == "200" ]]; then
    check "C19: Regression — MVP, admin-ui, SEARCH, PROPFIND still pass" pass
else
    check "C19: Regression (propfind=$PF19 noauth=$NO_AUTH19 search=$SEARCH19 adminui=$ADMIN_UI19)" fail
fi

# ============================================================
# Share tests – set up alice + file structure
# (alice was created at setup and not deleted since, so just create dirs)
# ============================================================

# Create alice's directory structure via WebDAV.
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/forms" >/dev/null
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/forms/birthday" >/dev/null
curl -s -X PUT  -u alice:alicepass1 --data 'question one' "$WEBDAV_URL/forms/birthday/q1.txt" >/dev/null
T_BEFORE_SHARE=$(date -uR)
sleep 0.5

# ---- C20: POST /api/v1/shares → 201 with share_id and access_token ----------
CREATE_RESP=$(curl -s -w "\n%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"Bob@Example.com","permission":"read-write","expires_at":null}' \
    "$WEBDAV_URL/api/v1/shares")
CREATE_STATUS=$(echo "$CREATE_RESP" | tail -1)
CREATE_BODY=$(echo "$CREATE_RESP" | sed '$d')
SHARE_ID=$(echo "$CREATE_BODY" | grep -o '"share_id":"[^"]*"' | head -1 | sed 's/"share_id":"//;s/"//')
SHARE_TOKEN=$(echo "$CREATE_BODY" | grep -o '"access_token":"[^"]*"' | head -1 | sed 's/"access_token":"//;s/"//')
SHARE_URL=$(echo "$CREATE_BODY" | grep -o '"share_url":"[^"]*"' | head -1 | sed 's/"share_url":"//;s/"//')
if [[ "$CREATE_STATUS" == "201" \
      && "$SHARE_ID" == shr_* \
      && "$SHARE_TOKEN" == shr_tok_* \
      && ${#SHARE_TOKEN} -eq 72 \
      && "$SHARE_URL" == "/s/shr_"* ]]; then
    check "C20: POST /api/v1/shares → 201 with share_id, access_token, share_url" pass
else
    check "C20: POST shares (status=$CREATE_STATUS id=$SHARE_ID token_len=${#SHARE_TOKEN})" fail
fi

# ---- C21: DB row exists with canonicalised path and lowercased email --------
DB_PATH=$(sqlite3 "$TEST_DB" \
    "SELECT path FROM shares WHERE id='$SHARE_ID';" 2>/dev/null || true)
DB_EMAIL=$(sqlite3 "$TEST_DB" \
    "SELECT recipient_email FROM shares WHERE id='$SHARE_ID';" 2>/dev/null || true)
if [[ "$DB_PATH" == "/forms/birthday" && "$DB_EMAIL" == "bob@example.com" ]]; then
    check "C21: DB row has canonical path and lowercased email" pass
else
    check "C21: DB row (path='$DB_PATH' email='$DB_EMAIL')" fail
fi

# ---- C22: POST with nonexistent path → 400 ----------------------------------
S24=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/nonexistent","recipient_email":"x@x.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S24" == "400" ]]; then check "C22: POST with nonexistent path → 400" pass
else check "C22: nonexistent path (got $S24)" fail; fi

# ---- C23: POST with file path (not dir) → 400 -------------------------------
S25=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday/q1.txt","recipient_email":"x@x.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S25" == "400" ]]; then check "C23: POST with file path (not dir) → 400" pass
else check "C23: file path (got $S25)" fail; fi

# ---- C24: POST with path traversal → 400 ------------------------------------
S26=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/../etc/passwd","recipient_email":"x@x.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S26" == "400" ]]; then check "C24: POST with path traversal → 400" pass
else check "C24: path traversal (got $S26)" fail; fi

# ---- C25: POST with invalid email → 400 -------------------------------------
S27=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"not-an-email","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S27" == "400" ]]; then check "C25: POST with invalid email → 400" pass
else check "C25: invalid email (got $S27)" fail; fi

# ---- C26: POST with invalid permission → 400 --------------------------------
S28=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"x@x.com","permission":"owner"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S28" == "400" ]]; then check "C26: POST with invalid permission → 400" pass
else check "C26: invalid permission (got $S28)" fail; fi

# ---- C27: POST with past expires_at → 400 -----------------------------------
S29=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"x@x.com","permission":"read","expires_at":"2020-01-01T00:00:00Z"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S29" == "400" ]]; then check "C27: POST with past expires_at → 400" pass
else check "C27: past expires_at (got $S29)" fail; fi

# ---- C28: POST without auth → 401 -------------------------------------------
S30=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"x@x.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
if [[ "$S30" == "401" ]]; then check "C28: POST without auth → 401" pass
else check "C28: no auth (got $S30)" fail; fi

# ---- C29: GET /api/v1/shares as alice → array, no access_token --------------
LIST_RESP=$(curl -s -u alice:alicepass1 "$WEBDAV_URL/api/v1/shares")
HAS_ENTRY=$(echo "$LIST_RESP" | grep -c "share_id" || true)
NO_TOKEN=$(echo "$LIST_RESP" | grep -c "access_token" || true)
if [[ "$HAS_ENTRY" -gt 0 && "$NO_TOKEN" -eq 0 ]]; then
    check "C29: GET /api/v1/shares returns array without access_token" pass
else
    check "C29: list shares (entries=$HAS_ENTRY no_token=$NO_TOKEN)" fail
fi

# ---- C30: GET /api/v1/shares/{id} as alice → 200, no access_token -----------
GET_RESP=$(curl -s -w "\n%{http_code}" -u alice:alicepass1 "$WEBDAV_URL/api/v1/shares/$SHARE_ID")
GET_STATUS=$(echo "$GET_RESP" | tail -1)
GET_BODY=$(echo "$GET_RESP" | sed '$d')
NO_TOKEN32=$(echo "$GET_BODY" | grep -c "access_token" || true)
if [[ "$GET_STATUS" == "200" && "$NO_TOKEN32" -eq 0 ]]; then
    check "C30: GET /api/v1/shares/{id} → 200, no access_token" pass
else
    check "C30: get share (status=$GET_STATUS no_token=$NO_TOKEN32)" fail
fi

# ---- C31: GET share as admin (not owner) → 404 ------------------------------
S33=$(curl -s -o /dev/null -w "%{http_code}" -u admin:adminpass123 "$WEBDAV_URL/api/v1/shares/$SHARE_ID")
if [[ "$S33" == "404" ]]; then check "C31: GET share as non-owner admin → 404" pass
else check "C31: get share as admin (got $S33)" fail; fi

# ---- C32: DELETE share as admin (not owner) → 404, share still exists -------
S34=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    -u admin:adminpass123 "$WEBDAV_URL/api/v1/shares/$SHARE_ID")
STILL_EXISTS=$(sqlite3 "$TEST_DB" \
    "SELECT COUNT(*) FROM shares WHERE id='$SHARE_ID';" 2>/dev/null || true)
if [[ "$S34" == "404" && "$STILL_EXISTS" == "1" ]]; then
    check "C32: DELETE share as non-owner → 404, share still in DB" pass
else
    check "C32: delete as non-owner (status=$S34 still_exists=$STILL_EXISTS)" fail
fi

# ---- C33: DELETE share as alice → 204; subsequent GET → 404 -----------------
S35=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    -u alice:alicepass1 "$WEBDAV_URL/api/v1/shares/$SHARE_ID")
S35_GET=$(curl -s -o /dev/null -w "%{http_code}" -u alice:alicepass1 "$WEBDAV_URL/api/v1/shares/$SHARE_ID")
if [[ "$S35" == "204" && "$S35_GET" == "404" ]]; then
    check "C33: DELETE as owner → 204; subsequent GET → 404" pass
else
    check "C33: delete as owner (delete=$S35 get=$S35_GET)" fail
fi

# ---- Recreate share for access tests (read-write) ---------------------------
CREATE2=$(curl -s -w "\n%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"bob@example.com","permission":"read-write","expires_at":null}' \
    "$WEBDAV_URL/api/v1/shares")
CREATE2_STATUS=$(echo "$CREATE2" | tail -1)
CREATE2_BODY=$(echo "$CREATE2" | sed '$d')
SHARE_ID=$(echo "$CREATE2_BODY" | grep -o '"share_id":"[^"]*"' | head -1 | sed 's/"share_id":"//;s/"//')
SHARE_TOKEN=$(echo "$CREATE2_BODY" | grep -o '"access_token":"[^"]*"' | head -1 | sed 's/"access_token":"//;s/"//')

# ---- C34: PROPFIND /s/{id}/ → 207, href has /s/{id} prefix ------------------
PF36=$(curl -s -w "\n%{http_code}" -X PROPFIND \
    -u "bob@example.com:$SHARE_TOKEN" \
    -H "Depth: 1" "$WEBDAV_URL/s/$SHARE_ID/")
PF36_STATUS=$(echo "$PF36" | tail -1)
PF36_BODY=$(echo "$PF36" | sed '$d')
HAS_PREFIX=$(echo "$PF36_BODY" | grep -c "/s/$SHARE_ID" || true)
HAS_CREATION=$(echo "$PF36_BODY" | grep -ci "creationdate" || true)
HAS_Q1=$(echo "$PF36_BODY" | grep -c "q1.txt" || true)
if [[ "$PF36_STATUS" == "207" && "$HAS_PREFIX" -gt 0 && "$HAS_CREATION" -gt 0 && "$HAS_Q1" -gt 0 ]]; then
    check "C34: PROPFIND /s/{id}/ → 207 with share prefix hrefs and creationdate" pass
else
    check "C34: share PROPFIND (status=$PF36_STATUS prefix=$HAS_PREFIX creation=$HAS_CREATION q1=$HAS_Q1)" fail
fi

# ---- C35: PROPFIND with right token but wrong email → 401 -------------------
S37=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u "wrong@example.com:$SHARE_TOKEN" \
    -H "Depth: 0" "$WEBDAV_URL/s/$SHARE_ID/")
if [[ "$S37" == "401" ]]; then check "C35: PROPFIND with wrong email → 401" pass
else check "C35: wrong email (got $S37)" fail; fi

# ---- C36: PROPFIND with right email but tampered token → 401 ----------------
TAMPERED_TOKEN="${SHARE_TOKEN%?}X"
S38=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u "bob@example.com:$TAMPERED_TOKEN" \
    -H "Depth: 0" "$WEBDAV_URL/s/$SHARE_ID/")
if [[ "$S38" == "401" ]]; then check "C36: PROPFIND with tampered token → 401" pass
else check "C36: tampered token (got $S38)" fail; fi

# ---- C37: PROPFIND nonexistent share → 401 (no enumeration) ----------------
S39=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u "bob@example.com:$SHARE_TOKEN" \
    -H "Depth: 0" "$WEBDAV_URL/s/shr_nonexistent0000/")
if [[ "$S39" == "401" ]]; then check "C37: PROPFIND nonexistent share → 401 (no enumeration)" pass
else check "C37: nonexistent share (got $S39)" fail; fi

# ---- C38: PUT /s/{id}/q2.txt → 201; file lands at correct path ---------------
S40=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "bob@example.com:$SHARE_TOKEN" \
    --data 'second file' "$WEBDAV_URL/s/$SHARE_ID/q2.txt")
FILE_EXISTS=$(test -f "$DATA_DIR/users/alice/forms/birthday/q2.txt" && echo yes || echo no)
if [[ "$S40" =~ ^(201|204)$ && "$FILE_EXISTS" == "yes" ]]; then
    check "C38: PUT /s/{id}/q2.txt → created at correct path" pass
else
    check "C38: PUT via share (status=$S40 file=$FILE_EXISTS)" fail
fi

# ---- C39: SEARCH /s/{id}/ with getlastmodified clause → 207, hrefs prefixed --
sleep 1
T_SEARCH=$(date -uR)
sleep 1
curl -s -X PUT -u "bob@example.com:$SHARE_TOKEN" \
    --data 'updated' "$WEBDAV_URL/s/$SHARE_ID/q1.txt" >/dev/null
SEARCH41=$(curl -s -w "\n%{http_code}" -X SEARCH \
    -u "bob@example.com:$SHARE_TOKEN" \
    -H 'Content-Type: application/xml' \
    --data "<?xml version='1.0'?>
<d:searchrequest xmlns:d='DAV:'>
  <d:basicsearch>
    <d:select><d:prop><d:displayname/></d:prop></d:select>
    <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
    <d:where><d:gt><d:prop><d:getlastmodified/></d:prop><d:literal>$T_SEARCH</d:literal></d:gt></d:where>
  </d:basicsearch>
</d:searchrequest>" "$WEBDAV_URL/s/$SHARE_ID/")
SEARCH41_STATUS=$(echo "$SEARCH41" | tail -1)
SEARCH41_BODY=$(echo "$SEARCH41" | sed '$d')
HREF_PREFIX=$(echo "$SEARCH41_BODY" | grep -c "/s/$SHARE_ID" || true)
if [[ "$SEARCH41_STATUS" == "207" && "$HREF_PREFIX" -gt 0 ]]; then
    check "C39: SEARCH via share → 207 with /s/{id} href prefix" pass
else
    check "C39: SEARCH via share (status=$SEARCH41_STATUS prefix=$HREF_PREFIX)" fail
fi

# ---- C40: MOVE /s/{id}/q2.txt to /s/{id}/sub/q2.txt → success ---------------
curl -s -X MKCOL -u "bob@example.com:$SHARE_TOKEN" "$WEBDAV_URL/s/$SHARE_ID/sub" >/dev/null
S42=$(curl -s -o /dev/null -w "%{http_code}" -X MOVE \
    -u "bob@example.com:$SHARE_TOKEN" \
    -H "Destination: http://localhost:8080/s/$SHARE_ID/sub/q2.txt" \
    "$WEBDAV_URL/s/$SHARE_ID/q2.txt")
FILE_MOVED=$(test -f "$DATA_DIR/users/alice/forms/birthday/sub/q2.txt" && echo yes || echo no)
if [[ "$S42" =~ ^(201|204)$ && "$FILE_MOVED" == "yes" ]]; then
    check "C40: MOVE within share → file at new path" pass
else
    check "C40: MOVE within share (status=$S42 moved=$FILE_MOVED)" fail
fi

# ---- C41: MOVE cross-share → 403 --------------------------------------------
S43=$(curl -s -o /dev/null -w "%{http_code}" -X MOVE \
    -u "bob@example.com:$SHARE_TOKEN" \
    -H "Destination: http://localhost:8080/s/shr_0000000000000000/sub/q2.txt" \
    "$WEBDAV_URL/s/$SHARE_ID/sub/q2.txt")
if [[ "$S43" == "403" ]]; then check "C41: MOVE to different share → 403" pass
else check "C41: cross-share MOVE (got $S43)" fail; fi

# ---- C42: MOVE to destination outside /s/... → 403 -------------------------
S44=$(curl -s -o /dev/null -w "%{http_code}" -X MOVE \
    -u "bob@example.com:$SHARE_TOKEN" \
    -H "Destination: http://localhost:8080/escape.txt" \
    "$WEBDAV_URL/s/$SHARE_ID/sub/q2.txt")
if [[ "$S44" == "403" ]]; then check "C42: MOVE to path outside share → 403" pass
else check "C42: escape MOVE (got $S44)" fail; fi

# ---- C43: LOCK → 501 --------------------------------------------------------
S45=$(curl -s -o /dev/null -w "%{http_code}" -X LOCK \
    -u "bob@example.com:$SHARE_TOKEN" \
    -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?><d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope><d:locktype><d:write/></d:locktype></d:lockinfo>' \
    "$WEBDAV_URL/s/$SHARE_ID/q1.txt")
if [[ "$S45" == "501" ]]; then check "C43: LOCK → 501 Not Implemented" pass
else check "C43: LOCK (got $S45)" fail; fi

# ---- C44: Read-only share: create ----------------------------------------
CREATE_RO=$(curl -s -w "\n%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"carol@example.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
CREATE_RO_STATUS=$(echo "$CREATE_RO" | tail -1)
RO_BODY=$(echo "$CREATE_RO" | sed '$d')
RO_SHARE_ID=$(echo "$RO_BODY" | grep -o '"share_id":"[^"]*"' | head -1 | sed 's/"share_id":"//;s/"//')
RO_TOKEN=$(echo "$RO_BODY" | grep -o '"access_token":"[^"]*"' | head -1 | sed 's/"access_token":"//;s/"//')
if [[ "$CREATE_RO_STATUS" == "201" ]]; then
    check "C44: Create read-only share → 201" pass
else
    check "C44: create read-only share (got $CREATE_RO_STATUS)" fail
fi

# ---- C45: PUT on read-only share → 403 --------------------------------------
S47=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
    -u "carol@example.com:$RO_TOKEN" \
    --data 'should fail' "$WEBDAV_URL/s/$RO_SHARE_ID/nope.txt")
if [[ "$S47" == "403" ]]; then check "C45: PUT via read-only share → 403" pass
else check "C45: PUT read-only (got $S47)" fail; fi

# ---- C46: PROPFIND on read-only share → 207 ---------------------------------
S48=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u "carol@example.com:$RO_TOKEN" \
    -H "Depth: 1" "$WEBDAV_URL/s/$RO_SHARE_ID/")
if [[ "$S48" == "207" ]]; then check "C46: PROPFIND via read-only share → 207" pass
else check "C46: PROPFIND read-only (got $S48)" fail; fi

# ---- C47: Delete alice → all her shares cascade from DB ---------------------
SHARES_BEFORE=$(sqlite3 "$TEST_DB" \
    "SELECT COUNT(*) FROM shares WHERE owner_username='alice';" 2>/dev/null || true)
agui -X POST "$WEBGUI_URL/admin/users/alice/delete" >/dev/null
SHARES_AFTER=$(sqlite3 "$TEST_DB" \
    "SELECT COUNT(*) FROM shares WHERE owner_username='alice';" 2>/dev/null || true)
if [[ "$SHARES_BEFORE" -gt 0 && "$SHARES_AFTER" == "0" ]]; then
    check "C47: Delete alice → shares cascade deleted (had=$SHARES_BEFORE now=$SHARES_AFTER)" pass
else
    check "C47: cascade delete (before=$SHARES_BEFORE after=$SHARES_AFTER)" fail
fi

# ---- C48: Expiry: create short-lived share, wait, access → 401 ---------------
# Re-create alice for the expiry test.
agui -X POST "$WEBGUI_URL/admin/users" \
    -d "username=alice&password=alicepass1&role=user" >/dev/null
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/forms" >/dev/null
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/forms/birthday" >/dev/null
EXP_AT=$(date -u -v+3S '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u --date='3 seconds' '+%Y-%m-%dT%H:%M:%SZ')
EXP_RESP=$(curl -s -w "\n%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data "{\"path\":\"/forms/birthday\",\"recipient_email\":\"exp@example.com\",\"permission\":\"read\",\"expires_at\":\"$EXP_AT\"}" \
    "$WEBDAV_URL/api/v1/shares")
EXP_STATUS=$(echo "$EXP_RESP" | tail -1)
EXP_BODY=$(echo "$EXP_RESP" | sed '$d')
EXP_SHARE_ID=$(echo "$EXP_BODY" | grep -o '"share_id":"[^"]*"' | head -1 | sed 's/"share_id":"//;s/"//')
EXP_TOKEN=$(echo "$EXP_BODY" | grep -o '"access_token":"[^"]*"' | head -1 | sed 's/"access_token":"//;s/"//')
# Wait for expiry.
sleep 4
S50=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u "exp@example.com:$EXP_TOKEN" \
    -H "Depth: 0" "$WEBDAV_URL/s/$EXP_SHARE_ID/")
if [[ "$EXP_STATUS" == "201" && "$S50" == "401" ]]; then
    check "C48: Expired share token → 401" pass
else
    check "C48: expiry (create=$EXP_STATUS access_after_exp=$S50)" fail
fi

# ---- C49: GET /admin/shares → 200 (no longer stub) -------------------------
ADMIN_SHARES_STATUS=$(agui -o /dev/null -w "%{http_code}" "$WEBGUI_URL/admin/shares")
if [[ "$ADMIN_SHARES_STATUS" == "200" ]]; then
    check "C49: GET /admin/shares → 200" pass
else
    check "C49: admin shares page (got $ADMIN_SHARES_STATUS)" fail
fi

# ---- C50: POST /admin/shares/{id}/revoke → 303; access becomes 401 -----------
# Create a fresh share for alice so we can revoke it.
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/forms" >/dev/null 2>&1 || true
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/forms/birthday" >/dev/null 2>&1 || true
REVOKE_CREATE=$(curl -s -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"rev@example.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
REV_SHARE_ID=$(echo "$REVOKE_CREATE" | grep -o '"share_id":"[^"]*"' | head -1 | sed 's/"share_id":"//;s/"//')
REV_TOKEN=$(echo "$REVOKE_CREATE" | grep -o '"access_token":"[^"]*"' | head -1 | sed 's/"access_token":"//;s/"//')
S52_REVOKE=$(agui -o /dev/null -w "%{http_code}" --max-redirs 0 \
    -X POST "$WEBGUI_URL/admin/shares/$REV_SHARE_ID/revoke")
S52_ACCESS=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u "rev@example.com:$REV_TOKEN" \
    -H "Depth: 0" "$WEBDAV_URL/s/$REV_SHARE_ID/")
if [[ "$S52_REVOKE" == "303" && "$S52_ACCESS" == "401" ]]; then
    check "C50: Admin revoke → 303; subsequent access → 401" pass
else
    check "C50: revoke (revoke=$S52_REVOKE access=$S52_ACCESS)" fail
fi

# ---- C51: GET /admin/status contains "Active shares" -----------------------
STATUS_PAGE=$(agui "$WEBGUI_URL/admin/status")
if echo "$STATUS_PAGE" | grep -qi "active shares"; then
    check "C51: GET /admin/status contains 'Active shares'" pass
else
    check "C51: admin status missing 'Active shares'" fail
fi

# ---- C53-C57: share-list-fields — full 9-field coverage --------------------
# Create a fresh share to drive the field-coverage checks.
FIELD_CREATE=$(curl -s -w "\n%{http_code}" -X POST \
    -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/forms/birthday","recipient_email":"fieldtest@example.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
FIELD_STATUS=$(echo "$FIELD_CREATE" | tail -1)
FIELD_BODY=$(echo "$FIELD_CREATE" | sed '$d')
FIELD_SHARE_ID=$(echo "$FIELD_BODY" | jq -r '.share_id')

# C53: GET /api/v1/shares contains all 9 fields, correct owner_username and share_url.
LIST_RESP=$(curl -s -u alice:alicepass1 "$WEBDAV_URL/api/v1/shares")
LIST_OWNER=$(echo "$LIST_RESP" | jq -r --arg id "$FIELD_SHARE_ID" '.[] | select(.share_id == $id) | .owner_username')
LIST_URL=$(echo "$LIST_RESP" | jq -r --arg id "$FIELD_SHARE_ID" '.[] | select(.share_id == $id) | .share_url')
LIST_HAS_ALL=$(echo "$LIST_RESP" | jq -r --arg id "$FIELD_SHARE_ID" \
    '.[] | select(.share_id == $id) | has("share_id") and has("owner_username") and has("path") and has("recipient_email") and has("permission") and has("share_url") and has("created_at") and has("last_used_at") and has("expires_at")')
if [[ "$LIST_OWNER" == "alice" && "$LIST_URL" == "/s/$FIELD_SHARE_ID/" && "$LIST_HAS_ALL" == "true" ]]; then
    check "C53: GET /api/v1/shares has all 9 fields, owner_username=alice, share_url correct" pass
else
    check "C53: GET list fields (owner=$LIST_OWNER url=$LIST_URL all=$LIST_HAS_ALL)" fail
fi

# C54: GET /api/v1/shares/{id} contains all 9 fields, correct owner_username and share_url.
DETAIL_RESP=$(curl -s -u alice:alicepass1 "$WEBDAV_URL/api/v1/shares/$FIELD_SHARE_ID")
DETAIL_HAS_ALL=$(echo "$DETAIL_RESP" | jq 'has("share_id") and has("owner_username") and has("path") and has("recipient_email") and has("permission") and has("share_url") and has("created_at") and has("last_used_at") and has("expires_at")')
DETAIL_OWNER=$(echo "$DETAIL_RESP" | jq -r '.owner_username')
DETAIL_URL=$(echo "$DETAIL_RESP" | jq -r '.share_url')
if [[ "$DETAIL_HAS_ALL" == "true" && "$DETAIL_OWNER" == "alice" && "$DETAIL_URL" == "/s/$FIELD_SHARE_ID/" ]]; then
    check "C54: GET /api/v1/shares/{id} has all 9 fields, owner_username and share_url correct" pass
else
    check "C54: GET detail fields (all=$DETAIL_HAS_ALL owner=$DETAIL_OWNER url=$DETAIL_URL)" fail
fi

# C55: Neither GET list nor GET detail leaks access_token or token_hash.
LIST_TOK=$(echo "$LIST_RESP" | grep -c "access_token" || true)
LIST_HASH=$(echo "$LIST_RESP" | grep -c "token_hash" || true)
DET_TOK=$(echo "$DETAIL_RESP" | grep -c "access_token" || true)
DET_HASH=$(echo "$DETAIL_RESP" | grep -c "token_hash" || true)
if [[ "$LIST_TOK" -eq 0 && "$LIST_HASH" -eq 0 && "$DET_TOK" -eq 0 && "$DET_HASH" -eq 0 ]]; then
    check "C55: GET list and detail contain no access_token or token_hash" pass
else
    check "C55: sensitive fields (list_tok=$LIST_TOK list_hash=$LIST_HASH det_tok=$DET_TOK det_hash=$DET_HASH)" fail
fi

# C56: POST 201 response includes all 9 fields plus access_token.
POST_HAS_9=$(echo "$FIELD_BODY" | jq 'has("share_id") and has("owner_username") and has("path") and has("recipient_email") and has("permission") and has("share_url") and has("created_at") and has("last_used_at") and has("expires_at")')
POST_HAS_TOK=$(echo "$FIELD_BODY" | jq 'has("access_token")')
if [[ "$POST_HAS_9" == "true" && "$POST_HAS_TOK" == "true" && "$FIELD_STATUS" == "201" ]]; then
    check "C56: POST 201 response includes all 9 fields plus access_token" pass
else
    check "C56: POST 201 fields (9=$POST_HAS_9 tok=$POST_HAS_TOK status=$FIELD_STATUS)" fail
fi

# C57: POST and GET responses for the same share produce identical values for the 9 common fields.
POST_9=$(echo "$FIELD_BODY" | jq -c '{share_id,owner_username,path,recipient_email,permission,share_url,created_at,last_used_at,expires_at}')
DET_9=$(echo "$DETAIL_RESP"  | jq -c '{share_id,owner_username,path,recipient_email,permission,share_url,created_at,last_used_at,expires_at}')
if [[ "$POST_9" == "$DET_9" ]]; then
    check "C57: POST and GET common fields are identical" pass
else
    check "C57: POST vs GET mismatch (post=$POST_9 get=$DET_9)" fail
fi

# ============================================================
# Sync conformance (C62–C76): conditional requests, ETags, atomic PUT,
# SEARCH Date/orderby/limit, HTTP-date, 401 vs 503.
# Criteria marked "user+share" run on alice's user endpoint and through a
# read-write share; each endpoint works in its own directory.
# ============================================================

HDR_F="$TEST_DIR/sync_hdr.txt"
BODY_F="$TEST_DIR/sync_body.txt"

curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/sync" >/dev/null
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/sync/u" >/dev/null
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/sync/s" >/dev/null
SYNC_RESP=$(curl -s -X POST -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/sync/s","recipient_email":"sync@example.com","permission":"read-write"}' \
    "$WEBDAV_URL/api/v1/shares")
SYNC_ID=$(echo "$SYNC_RESP" | jq -r '.share_id')
SYNC_TOKEN=$(echo "$SYNC_RESP" | jq -r '.access_token')
SYNC_RO_RESP=$(curl -s -X POST -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/sync/s","recipient_email":"syncro@example.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
SYNC_RO_ID=$(echo "$SYNC_RO_RESP" | jq -r '.share_id')
SYNC_RO_TOKEN=$(echo "$SYNC_RO_RESP" | jq -r '.access_token')

# use_ep selects the endpoint: U = user endpoint, S = read-write share.
# SCOPE is the SEARCH scope href for the endpoint's directory.
use_ep() {
    EP="$1"
    if [[ "$EP" == "U" ]]; then
        BASE="$WEBDAV_URL/sync/u"; AUTH="alice:alicepass1"; SCOPE="/sync/u"
        FSDIR="$DATA_DIR/users/alice/sync/u"
    else
        BASE="$WEBDAV_URL/s/$SYNC_ID"; AUTH="sync@example.com:$SYNC_TOKEN"; SCOPE="/"
        FSDIR="$DATA_DIR/users/alice/sync/s"
    fi
}

# req prints the status code; headers land in $HDR_F, body in $BODY_F.
req() {
    curl -s -o "$BODY_F" -D "$HDR_F" -w '%{http_code}' -u "$AUTH" "$@" || true
}

# hdr prints the value of one response header from the last req.
hdr() {
    grep -i "^$1:" "$HDR_F" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//' || true
}

# body_of GETs a URL on the current endpoint and prints the body.
body_of() {
    curl -s -u "$AUTH" "$1" || true
}

# xml_values prints every value of one DAV property in $BODY_F, one per line,
# with &quot; decoded so ETags compare equal to the header form.
xml_values() {
    grep -o "<d:$1>[^<]*</d:$1>" "$BODY_F" | sed "s#<d:$1>##; s#</d:$1>##; s/&quot;/\"/g" || true
}

# search_xml builds a SEARCH body. $1 = scope href, $2 = select props,
# $3 = where inner XML, $4 = extra elements after <d:where> (orderby/limit).
search_xml() {
    printf '<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:"><d:basicsearch><d:select><d:prop>%s</d:prop></d:select><d:from><d:scope><d:href>%s</d:href><d:depth>infinity</d:depth></d:scope></d:from><d:where>%s</d:where>%s</d:basicsearch></d:searchrequest>' \
        "$2" "$1" "$3" "$4"
}

# http_epoch converts an HTTP-date to Unix seconds (BSD date, then GNU date).
http_epoch() {
    LC_ALL=C date -j -u -f '%a, %d %b %Y %H:%M:%S GMT' "$1" +%s 2>/dev/null \
        || LC_ALL=C date -u -d "$1" +%s 2>/dev/null || echo 0
}

# run_both runs criterion function $3 on both endpoints; each sets RESULT to
# "pass" or a short failure description.
run_both() {
    local n="$1" label="$2" fn="$3" ru rs
    $fn U; ru="$RESULT"
    $fn S; rs="$RESULT"
    if [[ "$ru" == "pass" && "$rs" == "pass" ]]; then
        check "C$n: $label (user+share)" pass
    else
        check "C$n: $label (user=[$ru] share=[$rs])" fail
    fi
}

# ---- C62: PUT returns a strong ETag; same-size rewrite without sleep changes it
c62() {
    use_ep "$1"
    local s1 e1 s2 e2
    s1=$(req -X PUT --data-binary 'aaaa' "$BASE/etag.txt"); e1=$(hdr ETag)
    s2=$(req -X PUT --data-binary 'bbbb' "$BASE/etag.txt"); e2=$(hdr ETag)
    printf -v "E1_$EP" '%s' "$e1"
    printf -v "E2_$EP" '%s' "$e2"
    if [[ "$s1" == "201" && "$s2" == "201" && "$e1" =~ ^\"[0-9a-f]+\"$ \
          && "$e2" =~ ^\"[0-9a-f]+\"$ && "$e1" != "$e2" ]]; then
        RESULT=pass
    else
        RESULT="s1=$s1 e1=$e1 s2=$s2 e2=$e2"
    fi
}
run_both 62 "PUT returns strong ETag, changes on same-second same-size rewrite" c62

# ---- C63: PUT with stale If-Match → 412, content unchanged -------------------
c63() {
    use_ep "$1"
    local e1_var="E1_$EP" s content
    s=$(req -X PUT -H "If-Match: ${!e1_var}" --data-binary 'cccc' "$BASE/etag.txt")
    content=$(body_of "$BASE/etag.txt")
    if [[ "$s" == "412" && "$content" == "bbbb" ]]; then RESULT=pass
    else RESULT="status=$s content=$content"; fi
}
run_both 63 "PUT with stale If-Match → 412, content unchanged" c63

# ---- C64: PUT with current If-Match → 2xx ------------------------------------
c64() {
    use_ep "$1"
    local e2_var="E2_$EP" s
    s=$(req -X PUT -H "If-Match: ${!e2_var}" --data-binary 'dddd' "$BASE/etag.txt")
    printf -v "E3_$EP" '%s' "$(hdr ETag)"
    if [[ "$s" =~ ^2 ]]; then RESULT=pass; else RESULT="status=$s"; fi
}
run_both 64 "PUT with current If-Match → 2xx" c64

# ---- C65: If-Match: * / If-None-Match: * semantics on PUT --------------------
c65() {
    use_ep "$1"
    local s1 g1 s2 s3
    s1=$(req -X PUT -H 'If-Match: *' --data-binary 'x' "$BASE/missing.txt")
    g1=$(req "$BASE/missing.txt")
    s2=$(req -X PUT -H 'If-None-Match: *' --data-binary 'x' "$BASE/etag.txt")
    s3=$(req -X PUT -H 'If-None-Match: *' --data-binary 'x' "$BASE/created.txt")
    if [[ "$s1" == "412" && "$g1" == "404" && "$s2" == "412" && "$s3" == "201" ]]; then
        RESULT=pass
    else
        RESULT="ifmatch*-missing=$s1 (get=$g1) inm*-existing=$s2 inm*-missing=$s3"
    fi
}
run_both 65 "If-Match:* on missing → 412; If-None-Match:* existing → 412, missing → 201" c65

# ---- C66: DELETE honours If-Match --------------------------------------------
c66() {
    use_ep "$1"
    local e1_var="E1_$EP" e3_var="E3_$EP" s1 g1 s2 g2
    s1=$(req -X DELETE -H "If-Match: ${!e1_var}" "$BASE/etag.txt")
    g1=$(req "$BASE/etag.txt")
    s2=$(req -X DELETE -H "If-Match: ${!e3_var}" "$BASE/etag.txt")
    g2=$(req "$BASE/etag.txt")
    if [[ "$s1" == "412" && "$g1" == "200" && "$s2" =~ ^2 && "$g2" == "404" ]]; then
        RESULT=pass
    else
        RESULT="stale=$s1 (get=$g1) current=$s2 (get=$g2)"
    fi
}
run_both 66 "DELETE with stale If-Match → 412 (kept), current → 2xx" c66

# ---- C67: one ETag across PUT, GET, PROPFIND and SEARCH ----------------------
c67() {
    use_ep "$1"
    local ep eg epf es
    req -X PUT --data-binary 'same etag everywhere' "$BASE/same.txt" >/dev/null; ep=$(hdr ETag)
    req "$BASE/same.txt" >/dev/null; eg=$(hdr ETag)
    req -X PROPFIND -H 'Depth: 0' "$BASE/same.txt" >/dev/null; epf=$(xml_values getetag)
    req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml "$SCOPE" '<d:getetag/>' \
        '<d:eq><d:prop><d:displayname/></d:prop><d:literal>same.txt</d:literal></d:eq>' '')" \
        "$BASE/" >/dev/null
    es=$(xml_values getetag)
    if [[ -n "$ep" && "$ep" == "$eg" && "$ep" == "$epf" && "$ep" == "$es" ]]; then RESULT=pass
    else RESULT="put=$ep get=$eg propfind=$epf search=$es"; fi
}
run_both 67 "ETag identical in PUT, GET, PROPFIND and SEARCH" c67

# ---- C68: two concurrent PUTs with the same If-Match → one 2xx, one 412 ------
# Bodies are large and rate-limited so the two uploads overlap in time; without
# the per-path lock both would pass the precondition check.
head -c 2000000 /dev/zero >"$TEST_DIR/big1.bin"
head -c 2000001 /dev/zero >"$TEST_DIR/big2.bin"
c68() {
    use_ep "$1"
    local e a b ok=0 pf=0
    req -X PUT --data-binary 'base' "$BASE/conc.txt" >/dev/null; e=$(hdr ETag)
    curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" -X PUT -H "If-Match: $e" \
        --limit-rate 4M --data-binary @"$TEST_DIR/big1.bin" "$BASE/conc.txt" >"$TEST_DIR/conc_a" &
    local pa=$!
    curl -s -o /dev/null -w '%{http_code}' -u "$AUTH" -X PUT -H "If-Match: $e" \
        --limit-rate 4M --data-binary @"$TEST_DIR/big2.bin" "$BASE/conc.txt" >"$TEST_DIR/conc_b" &
    local pb=$!
    wait "$pa" "$pb" || true
    a=$(cat "$TEST_DIR/conc_a"); b=$(cat "$TEST_DIR/conc_b")
    for s in "$a" "$b"; do
        [[ "$s" =~ ^2 ]] && ok=$((ok + 1))
        [[ "$s" == "412" ]] && pf=$((pf + 1))
    done
    if [[ "$ok" -eq 1 && "$pf" -eq 1 ]]; then RESULT=pass; else RESULT="a=$a b=$b"; fi
}
run_both 68 "Concurrent PUTs with same If-Match → exactly one 2xx and one 412" c68

# ---- C69: aborted upload keeps the old content, leaves no temp file ----------
# curl announces a body far larger than it sends and gives up after 1 s, so
# the server sees the connection drop mid-body.
c69() {
    use_ep "$1"
    local s content tmp_dav tmp_fs r1 r2
    s=$(req -X PUT --data-binary 'original content' "$BASE/abort.txt")
    curl -s -o /dev/null -u "$AUTH" -X PUT -H 'Content-Length: 100000' \
        --data-binary 'partial' --max-time 1 "$BASE/abort.txt" || true
    sleep 0.5
    content=$(body_of "$BASE/abort.txt")
    req -X PROPFIND -H 'Depth: 1' "$BASE/" >/dev/null
    tmp_dav=$(grep -c 'webdavgo-tmp' "$BODY_F" || true)
    tmp_fs=$(ls -a "$FSDIR" | grep -c 'webdavgo-tmp' || true)
    r1=$(req "$BASE/.webdavgo-tmp-x")
    r2=$(req -X PUT --data-binary 'x' "$BASE/.webdavgo-tmp-x")
    if [[ "$s" == "201" && "$content" == "original content" && "$tmp_dav" == "0" \
          && "$tmp_fs" == "0" && "$r1" == "403" && "$r2" == "403" ]]; then
        RESULT=pass
    else
        RESULT="put=$s content=$content tmp_propfind=$tmp_dav tmp_fs=$tmp_fs get_tmp=$r1 put_tmp=$r2"
    fi
}
run_both 69 "Aborted PUT keeps old content, no temp file visible, temp prefix → 403" c69

# ---- C70: PUT/MKCOL status codes; read share rejects writes ------------------
c70() {
    use_ep "$1"
    local p1 m1 m2 m3 ro_put="-" ro_mkcol="-"
    p1=$(req -X PUT --data-binary 'x' "$BASE/noparent/x.txt")
    m1=$(req -X MKCOL "$BASE/newcol")
    m2=$(req -X MKCOL "$BASE/newcol")
    m3=$(req -X MKCOL "$BASE/noparent/child")
    if [[ "$EP" == "S" ]]; then
        ro_put=$(curl -s -o /dev/null -w '%{http_code}' -u "syncro@example.com:$SYNC_RO_TOKEN" \
            -X PUT --data-binary 'x' "$WEBDAV_URL/s/$SYNC_RO_ID/ro.txt" || true)
        ro_mkcol=$(curl -s -o /dev/null -w '%{http_code}' -u "syncro@example.com:$SYNC_RO_TOKEN" \
            -X MKCOL "$WEBDAV_URL/s/$SYNC_RO_ID/rocol" || true)
    fi
    if [[ "$p1" == "409" && "$m1" == "201" && "$m2" == "405" && "$m3" == "409" ]] \
       && [[ "$EP" == "U" || ( "$ro_put" == "403" && "$ro_mkcol" == "403" ) ]]; then
        RESULT=pass
    else
        RESULT="put-noparent=$p1 mkcol=$m1 mkcol-again=$m2 mkcol-noparent=$m3 ro-put=$ro_put ro-mkcol=$ro_mkcol"
    fi
}
run_both 70 "PUT no parent → 409; MKCOL 201/405/409; read share PUT/MKCOL → 403" c70

# ---- C71: Last-Modified + If-Modified-Since → 304 ----------------------------
c71() {
    use_ep "$1"
    local lm s
    req "$BASE/same.txt" >/dev/null; lm=$(hdr Last-Modified)
    s=$(req -H "If-Modified-Since: $lm" "$BASE/same.txt")
    if [[ "$lm" == *GMT && "$s" == "304" ]]; then RESULT=pass
    else RESULT="last-modified=$lm status=$s"; fi
}
run_both 71 "GET Last-Modified, If-Modified-Since → 304" c71

# ---- C72: SEARCH orderby getlastmodified + nresults --------------------------
# mtimes are set explicitly so their order differs from the name order:
# c < a < d < b. Without orderby the result would start a, b.
c72() {
    use_ep "$1"
    local asc desc bad_n bad_p
    req -X MKCOL "$BASE/ord" >/dev/null
    for f in a b c d; do req -X PUT --data-binary "$f" "$BASE/ord/$f.txt" >/dev/null; done
    touch -t 202601010000.01 "$FSDIR/ord/c.txt"
    touch -t 202601010000.02 "$FSDIR/ord/a.txt"
    touch -t 202601010000.03 "$FSDIR/ord/d.txt"
    touch -t 202601010000.04 "$FSDIR/ord/b.txt"
    local oscope="${SCOPE%/}/ord" lim='<d:limit><d:nresults>2</d:nresults></d:limit>'
    req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml "$oscope" '<d:getlastmodified/>' '' \
        "<d:orderby><d:order><d:prop><d:getlastmodified/></d:prop><d:ascending/></d:order></d:orderby>$lim")" \
        "$BASE/" >/dev/null
    asc=$(grep -o '<d:href>[^<]*</d:href>' "$BODY_F" | sed 's#</d:href>##; s#.*/##' | tr '\n' ' ' || true)
    req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml "$oscope" '<d:getlastmodified/>' '' \
        "<d:orderby><d:order><d:prop><d:getlastmodified/></d:prop><d:descending/></d:order></d:orderby>$lim")" \
        "$BASE/" >/dev/null
    desc=$(grep -o '<d:href>[^<]*</d:href>' "$BODY_F" | sed 's#</d:href>##; s#.*/##' | tr '\n' ' ' || true)
    bad_n=$(req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml "$oscope" '<d:getetag/>' '' \
        '<d:limit><d:nresults>0</d:nresults></d:limit>')" "$BASE/")
    bad_p=$(req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml "$oscope" '<d:getetag/>' '' \
        '<d:orderby><d:order><d:prop><d:resourcetype/></d:prop></d:order></d:orderby>')" "$BASE/")
    if [[ "$asc" == "c.txt a.txt " && "$desc" == "b.txt d.txt " && "$bad_n" == "400" && "$bad_p" == "400" ]]; then
        RESULT=pass
    else
        RESULT="asc=$asc desc=$desc nresults0=$bad_n bad-prop=$bad_p"
    fi
}
run_both 72 "SEARCH orderby getlastmodified + nresults 2 → oldest/newest two in order" c72

# ---- C73: SEARCH Date header reflects the start of the search ----------------
c73() {
    use_ep "$1"
    local t0 d de
    t0=$(date -u +%s)
    req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml "$SCOPE" '<d:getetag/>' '' '')" \
        "$BASE/" >/dev/null
    d=$(hdr Date); de=$(http_epoch "$d")
    if [[ "$de" -ge "$t0" && "$de" -le $((t0 + 1)) ]]; then RESULT=pass
    else RESULT="date=$d epoch=$de sent_at=$t0"; fi
}
run_both 73 "SEARCH Date header ≤ request start + 1 s" c73

# ---- C74: getlastmodified is an HTTP-date ending in GMT -----------------------
c74() {
    use_ep "$1"
    local pf sr pf_bad sr_bad
    req -X PROPFIND -H 'Depth: 1' "$BASE/" >/dev/null
    pf=$(xml_values getlastmodified | wc -l | tr -d ' ')
    pf_bad=$(xml_values getlastmodified | grep -vc 'GMT$' || true)
    req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml "$SCOPE" '<d:getlastmodified/>' '' '')" \
        "$BASE/" >/dev/null
    sr=$(xml_values getlastmodified | wc -l | tr -d ' ')
    sr_bad=$(xml_values getlastmodified | grep -vc 'GMT$' || true)
    if [[ "$pf" -gt 0 && "$sr" -gt 0 && "$pf_bad" == "0" && "$sr_bad" == "0" ]]; then RESULT=pass
    else RESULT="propfind=$pf (non-GMT $pf_bad) search=$sr (non-GMT $sr_bad)"; fi
}
run_both 74 "getlastmodified in PROPFIND and SEARCH ends with GMT" c74

# ============================================================
# Href encoding (C144–C147), user+share. Hrefs must be percent-encoded URI
# references (RFC 4918 §8.3) that decode to the exact stored bytes and work
# unchanged as request paths. Names are written as byte escapes so no editor
# can normalize them; NFC and NFD ü get distinct prefixes because APFS treats
# the two forms as the same name.
# ============================================================
ENC_FILES=(
    'a b.txt'
    $'Stra\xc3\x9fe.txt'
    $'nfc-\xc3\xbc.txt'
    $'nfd-u\xcc\x88.txt'
    $'\xe2\x80\x9equote\xe2\x80\x9c.txt'
    '100%.txt'
    'hash#1.txt'
    'q?.txt'
    'plus+1.txt'
    'a&b.txt'
)
ENC_DIR=$'Ordner \xc3\x9f u\xcc\x88 \xc3\xbc \xe2\x80\x9e\xe2\x80\x9c %#?+&'
ENC_INNER=$'inner \xc3\xbc.txt'

# uri_seg percent-encodes one path segment the way a careful client would.
uri_seg() { jq -rn --arg s "$1" '$s|@uri'; }

# pct_decode decodes %XX escapes to raw bytes.
pct_decode() { local s="${1//\\/\\\\}"; printf '%b' "${s//%/\\x}"; }

# body_hrefs prints every <d:href> of $BODY_F, XML-unescaped, one per line.
body_hrefs() {
    grep -o '<d:href>[^<]*</d:href>' "$BODY_F" | sed 's#<d:href>##; s#</d:href>##' \
        | sed "s/&lt;/</g; s/&gt;/>/g; s/&quot;/\"/g; s/&apos;/'/g; s/&amp;/\\&/g" || true
}

# href_check verifies the hrefs of $BODY_F against the expected decoded paths
# in $1 (newline-separated); prints "pass" or a short reason.
href_check() {
    local want="$1" raw got bad
    raw=$(body_hrefs)
    # Only RFC 3986 path characters and %XX escapes may appear.
    bad=$(printf '%s\n' "$raw" | LC_ALL=C grep -vcE '^([A-Za-z0-9/._~!$&'"'"'()*+,;=:@-]|%[0-9A-F]{2})*$' || true)
    if [[ "$bad" != "0" ]]; then echo "unencoded=$bad"; return; fi
    if LC_ALL=C grep -q '&[^a-z#]' "$BODY_F" \
          || { [[ "$want" == *'a&b.txt'* ]] && ! grep -q 'a&amp;b.txt' "$BODY_F"; }; then
        echo "xml-escape"; return
    fi
    got=$(while IFS= read -r h; do pct_decode "$h"; echo; done <<<"$raw" | LC_ALL=C sort)
    want=$(printf '%s\n' "$want" | LC_ALL=C sort)
    if [[ "$got" == "$want" ]]; then echo pass; else echo "decoded-mismatch"; fi
}

# enc_setup creates the encoding fixtures under $BASE/enc via encoded URLs.
# EPATH is the decoded URL path of the endpoint's directory.
enc_setup() {
    use_ep "$1"
    if [[ "$EP" == "U" ]]; then EPATH="/sync/u"; else EPATH="/s/$SYNC_ID"; fi
    local n d
    curl -s -o /dev/null -X MKCOL -u "$AUTH" "$BASE/enc" || true
    for n in "${ENC_FILES[@]}"; do
        curl -s -g -o /dev/null -X PUT -u "$AUTH" --data-binary "$n" "$BASE/enc/$(uri_seg "$n")" || true
    done
    d=$(uri_seg "$ENC_DIR")
    curl -s -g -o /dev/null -X MKCOL -u "$AUTH" "$BASE/enc/$d" || true
    curl -s -g -o /dev/null -X PUT -u "$AUTH" --data-binary "$ENC_INNER" \
        "$BASE/enc/$d/$(uri_seg "$ENC_INNER")" || true
}

# ---- C144: PROPFIND Depth 1 hrefs are percent-encoded and decode exactly ----
c144() {
    enc_setup "$1"
    local want n s r disk=pass
    want="$EPATH/enc/"$'\n'"$EPATH/enc/$ENC_DIR/"
    for n in "${ENC_FILES[@]}"; do
        want+=$'\n'"$EPATH/enc/$n"
        [[ -f "$FSDIR/enc/$n" ]] || disk="missing-on-disk"
    done
    s=$(req -X PROPFIND -H 'Depth: 1' "$BASE/enc/")
    r=$(href_check "$want")
    if [[ "$s" == "207" && "$r" == "pass" && "$disk" == "pass" ]]; then RESULT=pass
    else RESULT="status=$s hrefs=$r disk=$disk"; fi
}
run_both 144 "PROPFIND Depth 1 hrefs percent-encoded (space, ß, NFC/NFD ü, „“, %, #, ?, +, &), decode to stored bytes" c144

# ---- C145: SEARCH hrefs the same ---------------------------------------------
c145() {
    use_ep "$1"
    if [[ "$EP" == "U" ]]; then EPATH="/sync/u"; else EPATH="/s/$SYNC_ID"; fi
    local want n s r
    want="$EPATH/enc/$ENC_DIR/$ENC_INNER"
    for n in "${ENC_FILES[@]}"; do want+=$'\n'"$EPATH/enc/$n"; done
    s=$(req -X SEARCH -H 'Content-Type: application/xml' \
        --data "$(search_xml "${SCOPE%/}/enc" '<d:getetag/>' '' '')" "$BASE/")
    r=$(href_check "$want")
    if [[ "$s" == "207" && "$r" == "pass" ]]; then RESULT=pass
    else RESULT="status=$s hrefs=$r"; fi
}
run_both 145 "SEARCH hrefs percent-encoded, decode to stored bytes" c145

# ---- C146: returned hrefs work unchanged for GET/PUT/COPY/MOVE/DELETE --------
# Every file href from PROPFIND and SEARCH is used verbatim: GET returns the
# original content, PUT overwrites, COPY and MOVE take the href (plus a
# suffix) as Destination, DELETE removes the file and the folder.
c146() {
    use_ep "$1"
    local host="${WEBDAV_URL}" hrefs h dir fails=() name
    req -X PROPFIND -H 'Depth: 1' "$BASE/enc/" >/dev/null
    hrefs=$(body_hrefs | grep -v '/$' || true)
    dir=$(body_hrefs | grep '/$' | grep -v '/enc/$' || true)
    req -X SEARCH -H 'Content-Type: application/xml' \
        --data "$(search_xml "${SCOPE%/}/enc" '<d:getetag/>' '' '')" "$BASE/" >/dev/null
    hrefs+=$'\n'$(body_hrefs | grep "$(printf '%s' "$dir" | sed 's/[.[\*^$]/\\&/g')" || true)
    while IFS= read -r h; do
        [[ -z "$h" ]] && continue
        name=$(pct_decode "${h##*/}")
        [[ "$(req -g "$host$h")" == "200" && "$(cat "$BODY_F")" == "$name" ]] || fails+=("get:$h")
        [[ "$(req -g -X PUT --data-binary "$name" "$host$h")" == "201" ]] || fails+=("put:$h")
        [[ "$(req -g -X COPY -H "Destination: $host$h.c" "$host$h")" == "201" ]] || fails+=("copy:$h")
        [[ "$(req -g -X MOVE -H "Destination: $host$h.m" "$host$h.c")" == "201" ]] || fails+=("move:$h")
        [[ "$(req -g "$host$h.m")" == "200" && "$(cat "$BODY_F")" == "$name" ]] || fails+=("get-moved:$h")
        [[ "$(req -g -X DELETE "$host$h.m")" == "204" ]] || fails+=("delete-moved:$h")
        [[ "$(req -g -X DELETE "$host$h")" == "204" && "$(req -g "$host$h")" == "404" ]] || fails+=("delete:$h")
    done <<<"$hrefs"
    [[ -n "$dir" && "$(req -g -X DELETE "$host$dir")" == "204" ]] || fails+=("delete-dir:$dir")
    [[ "$(req -X PROPFIND -H 'Depth: 1' "$BASE/enc/")" == "207" && "$(body_hrefs | wc -l | tr -d ' ')" == "1" ]] \
        || fails+=("leftovers")
    if [[ ${#fails[@]} -eq 0 && $(printf '%s\n' "$hrefs" | grep -c .) == "11" ]]; then RESULT=pass
    else RESULT="n=$(printf '%s\n' "$hrefs" | grep -c .) ${fails[*]:0:3}"; fi
}
run_both 146 "hrefs from PROPFIND/SEARCH work verbatim for GET, PUT, COPY, MOVE (Destination), DELETE" c146

# ---- C147: SEARCH scope is a URI reference (RFC 5323 §5.4, §2.2.2) ----------
# The folder href from PROPFIND works verbatim as scope; a raw "%#" → 400; a
# missing scope → 409 with search-scope-valid.
c147() {
    enc_setup "$1"
    local want dir_xml raw_xml s1 r1 s2 s3
    want="$EPATH/enc/$ENC_DIR/$ENC_INNER"
    req -X PROPFIND -H 'Depth: 1' "$BASE/enc/" >/dev/null
    dir_xml=$(grep -o '<d:href>[^<]*/</d:href>' "$BODY_F" | sed 's#<d:href>##; s#</d:href>##' \
        | grep -v '/enc/$' || true)
    s1=$(req -X SEARCH -H 'Content-Type: application/xml' \
        --data "$(search_xml "$dir_xml" '<d:getetag/>' '' '')" "$BASE/")
    r1=$(href_check "$want")
    raw_xml=$(printf '%s' "${SCOPE%/}/enc/$ENC_DIR" | sed 's/&/\&amp;/g')
    s2=$(req -X SEARCH -H 'Content-Type: application/xml' \
        --data "$(search_xml "$raw_xml" '<d:getetag/>' '' '')" "$BASE/")
    s3=$(req -X SEARCH -H 'Content-Type: application/xml' \
        --data "$(search_xml "${SCOPE%/}/enc/missing" '<d:getetag/>' '' '')" "$BASE/")
    if [[ "$s1" == "207" && "$r1" == "pass" && "$s2" == "400" && "$s3" == "409" ]] \
          && grep -q '<d:search-scope-valid><d:response>' "$BODY_F"; then
        RESULT=pass
    else
        RESULT="href=$s1/$r1 raw=$s2 missing=$s3"
    fi
}
run_both 147 "SEARCH scope: PROPFIND folder href works; invalid % → 400; missing → 409 search-scope-valid" c147

# ---- C75: revocation → 401 on every method; deleted folder → 404 -------------
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/sync/rev" >/dev/null
curl -s -X PUT -u alice:alicepass1 --data 'r' "$WEBDAV_URL/sync/rev/r.txt" >/dev/null
REV2=$(curl -s -X POST -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/sync/rev","recipient_email":"rev2@example.com","permission":"read-write"}' \
    "$WEBDAV_URL/api/v1/shares")
REV2_ID=$(echo "$REV2" | jq -r '.share_id'); REV2_TOKEN=$(echo "$REV2" | jq -r '.access_token')
AUTH="rev2@example.com:$REV2_TOKEN"
R75_PRE=$(req -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/s/$REV2_ID/")
R75_DEL=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -u alice:alicepass1 \
    "$WEBDAV_URL/api/v1/shares/$REV2_ID" || true)
R75_GET=$(req "$WEBDAV_URL/s/$REV2_ID/r.txt")
R75_PUT=$(req -X PUT --data-binary 'x' "$WEBDAV_URL/s/$REV2_ID/r.txt")
R75_PF=$(req -X PROPFIND -H 'Depth: 1' "$WEBDAV_URL/s/$REV2_ID/")
R75_SR=$(req -X SEARCH -H 'Content-Type: application/xml' --data "$(search_xml / '<d:getetag/>' '' '')" \
    "$WEBDAV_URL/s/$REV2_ID/")
curl -s -X MKCOL -u alice:alicepass1 "$WEBDAV_URL/sync/gone" >/dev/null
GONE=$(curl -s -X POST -u alice:alicepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/sync/gone","recipient_email":"gone@example.com","permission":"read"}' \
    "$WEBDAV_URL/api/v1/shares")
GONE_ID=$(echo "$GONE" | jq -r '.share_id'); GONE_TOKEN=$(echo "$GONE" | jq -r '.access_token')
curl -s -o /dev/null -X DELETE -u alice:alicepass1 "$WEBDAV_URL/sync/gone" || true
AUTH="gone@example.com:$GONE_TOKEN"
R75_GONE=$(req -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/s/$GONE_ID/")
if [[ "$R75_PRE" == "207" && "$R75_DEL" == "204" && "$R75_GET" == "401" && "$R75_PUT" == "401" \
      && "$R75_PF" == "401" && "$R75_SR" == "401" && "$R75_GONE" == "404" ]]; then
    check "C75: revoked share → 401 for GET/PUT/PROPFIND/SEARCH; deleted share folder → 404" pass
else
    check "C75: revocation (pre=$R75_PRE del=$R75_DEL get=$R75_GET put=$R75_PUT propfind=$R75_PF search=$R75_SR gone=$R75_GONE)" fail
fi

# ---- C76: DB failure during auth → 503 + Retry-After, never 401 --------------
# The DB is made unavailable for one lookup by renaming the table it reads,
# using the sqlite3 CLI while the server runs. SQLite re-checks the schema on
# every statement, so the server's next query fails with "no such table" —
# deterministic on macOS and Linux, and undone by renaming the table back.
AUTH="sync@example.com:$SYNC_TOKEN"
sqlite3 "$TEST_DB" "ALTER TABLE shares RENAME TO shares_offline;"
R76_SHARE=$(req -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/s/$SYNC_ID/"); R76_SHARE_RA=$(hdr Retry-After)
sqlite3 "$TEST_DB" "ALTER TABLE shares_offline RENAME TO shares;"
R76_SHARE_OK=$(req -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/s/$SYNC_ID/")
# A user who has never logged in, so the auth cache cannot answer and the
# lookup has to reach the (unavailable) DB.
agui -X POST "$WEBGUI_URL/admin/users" \
    -d "username=dbdown&password=dbdownpass1&role=user" >/dev/null
AUTH="dbdown:dbdownpass1"
sqlite3 "$TEST_DB" "ALTER TABLE users RENAME TO users_offline;"
R76_USER=$(req -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/"); R76_USER_RA=$(hdr Retry-After)
R76_API=$(req "$WEBDAV_URL/api/v1/shares")
sqlite3 "$TEST_DB" "ALTER TABLE users_offline RENAME TO users;"
R76_USER_OK=$(req -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
R76_LOGGED=$(grep -c "$LOG ERROR "'"share lookup failed"' "$STDOUT_FILE" || true)
if [[ "$R76_SHARE" == "503" && "$R76_SHARE_RA" == "30" && "$R76_SHARE_OK" == "207" \
      && "$R76_USER" == "503" && "$R76_USER_RA" == "30" && "$R76_API" == "503" \
      && "$R76_USER_OK" == "207" && "$R76_LOGGED" -gt 0 ]]; then
    check "C76: DB failure during share/user/API auth → 503 Retry-After: 30, logged at Error" pass
else
    check "C76: 503 path (share=$R76_SHARE ra=$R76_SHARE_RA after=$R76_SHARE_OK user=$R76_USER ra=$R76_USER_RA api=$R76_API after=$R76_USER_OK logged=$R76_LOGGED)" fail
fi

# ============================================================
# Server foundation (C77–C88): config file and flags, temp-file cleanup,
# graceful shutdown, auth cache, request log, request limits, timeouts.
# ============================================================

# log_mark prints the current length of the server log; log_since prints the
# request lines written after such a mark, in order.
log_mark() { wc -l <"$STDOUT_FILE" | tr -d ' '; }
log_since() { sleep 0.2; tail -n +$(($1 + 1)) "$STDOUT_FILE" | grep "${LOGMSG}request " || true; }

# ---- C77: data_dir from the config file is used -----------------------------
C77_DB=$(test -f "$DATA_DIR/webdavgo.db" && echo yes || echo no)
C77_USER=$(test -d "$DATA_DIR/users/alice" && echo yes || echo no)
C77_STRAY=$(test -e "$TEST_DIR/data" && echo yes || echo no)
C77_LOG=$(grep -c "${LOGMSG}config data_dir=$DATA_DIR " "$STDOUT_FILE" || true)
if [[ "$C77_DB" == "yes" && "$C77_USER" == "yes" && "$C77_STRAY" == "no" && "$C77_LOG" -gt 0 ]]; then
    check "C77: data_dir from config file holds DB and user files, nothing under ./data" pass
else
    check "C77: data_dir (db=$C77_DB user=$C77_USER stray_data=$C77_STRAY logged=$C77_LOG)" fail
fi

# ---- C82: auth cache: bcrypt, then cache; password reset invalidates ---------
agui -X POST "$WEBGUI_URL/admin/users" \
    -d "username=cachey&password=cachepass1&role=user" >/dev/null
M=$(log_mark)
A82_1=$(curl -s -o /dev/null -w '%{http_code}' -u cachey:cachepass1 -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
A82_2=$(curl -s -o /dev/null -w '%{http_code}' -u cachey:cachepass1 -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
L=$(log_since "$M")
L82_1=$(echo "$L" | sed -n 1p); L82_2=$(echo "$L" | sed -n 2p)
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users/cachey/reset" \
    -d "new_password=cachepass2"
M=$(log_mark)
A82_3=$(curl -s -o /dev/null -w '%{http_code}' -u cachey:cachepass1 -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
A82_4=$(curl -s -o /dev/null -w '%{http_code}' -u cachey:cachepass2 -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
L=$(log_since "$M")
L82_3=$(echo "$L" | sed -n 1p); L82_4=$(echo "$L" | sed -n 2p)
if [[ "$A82_1" == "207" && "$A82_2" == "207" && "$A82_3" == "401" && "$A82_4" == "207" \
      && "$L82_1" == *"user=cachey"*"auth=bcrypt"* && "$L82_2" == *"user=cachey"*"auth=cache"* \
      && "$L82_3" == *"status=401 auth=bcrypt"* && "$L82_4" == *"user=cachey"*"auth=bcrypt"* ]]; then
    check "C82: auth cache — bcrypt then cache; after reset old pw 401, new pw bcrypt" pass
else
    check "C82: auth cache (status=$A82_1/$A82_2/$A82_3/$A82_4 log1=[$L82_1] log2=[$L82_2] log3=[$L82_3] log4=[$L82_4])" fail
fi

# ---- C83: a wrong password is never answered from the cache ------------------
# cachey's correct password is cached from C82; wrong ones must still go to
# bcrypt and fail, and must not evict the cached entry.
M=$(log_mark)
A83_1=$(curl -s -o /dev/null -w '%{http_code}' -u cachey:wrongpass -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
A83_2=$(curl -s -o /dev/null -w '%{http_code}' -u cachey:wrongpass -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
A83_3=$(curl -s -o /dev/null -w '%{http_code}' -u cachey:cachepass2 -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/")
L=$(log_since "$M")
L83_1=$(echo "$L" | sed -n 1p); L83_2=$(echo "$L" | sed -n 2p); L83_3=$(echo "$L" | sed -n 3p)
if [[ "$A83_1" == "401" && "$A83_2" == "401" && "$A83_3" == "207" \
      && "$L83_1" == *"auth=bcrypt"* && "$L83_2" == *"auth=bcrypt"* && "$L83_3" == *"auth=cache"* ]]; then
    check "C83: wrong password → 401 with auth=bcrypt every time; correct one still cached" pass
else
    check "C83: wrong password (status=$A83_1/$A83_2/$A83_3 log=[$L83_1] [$L83_2] [$L83_3])" fail
fi

# ---- C84: 401 responses appear in the request log at their level -------------
# The test runs at log_level info: a 401 without credentials is a Debug line
# (counted on the Activity card instead), so it must not show up here.
M=$(log_mark)
A84_NOCREDS=$(curl -s -o /dev/null -w '%{http_code}' "$WEBDAV_URL/hello.txt")
curl -s -o /dev/null -u cachey:wrongpass "$WEBDAV_URL/api/v1/shares"
curl -s -o /dev/null -u "sync@example.com:shr_tok_wrong" -X PROPFIND -H 'Depth: 0' "$WEBDAV_URL/s/$SYNC_ID/"
L=$(log_since "$M" | grep "$LOG INFO request " || true)
# Attributes are matched one by one: client= and others sit between them.
L84_NOCREDS=$(echo "$L" | grep -F ' path=/hello.txt ' | grep -F ' status=401 ' | grep -c -F ' auth=none ' || true)
L84_BADPW=$(echo "$L" | grep -F ' path=/api/v1/shares ' | grep -F ' status=401 ' | grep -c -F ' auth=bcrypt ' || true)
L84_BADTOK=$(echo "$L" | grep -F " path=/s/$SYNC_ID/ " | grep -F ' status=401 ' | grep -c -F ' auth=token ' || true)
L84_USER=$(echo "$L" | grep -E ' path=(/hello\.txt|/api/v1/shares|/s/[^ ]*) ' | grep -c -F ' user=' || true)
if [[ "$A84_NOCREDS" == "401" && "$L84_NOCREDS" == "0" && "$L84_BADPW" == "1" \
      && "$L84_BADTOK" == "1" && "$L84_USER" == "0" ]]; then
    check "C84: 401 without creds not an Info request line (Debug); bad user password and bad share token logged at Info without user" pass
else
    check "C84: 401 logging (nocreds=$A84_NOCREDS nocreds_info_lines=$L84_NOCREDS badpw_lines=$L84_BADPW badtoken_lines=$L84_BADTOK user_fields=$L84_USER)" fail
fi

# ---- C85: SEARCH/PROPFIND body larger than max_request_body → 413 -----------
# Sizes straddle the 1 MiB default. The chunked request has no Content-Length,
# so the limit must also hold while the body is being read.
head -c 1048577 /dev/zero | tr '\0' ' ' >"$TEST_DIR/big_body.xml"
S85_SEARCH=$(curl -s -o /dev/null -w '%{http_code}' -u alice:alicepass1 -X SEARCH \
    -H 'Content-Type: application/xml' --data-binary @"$TEST_DIR/big_body.xml" "$WEBDAV_URL/" || true)
S85_PROPFIND=$(curl -s -o /dev/null -w '%{http_code}' -u "sync@example.com:$SYNC_TOKEN" -X PROPFIND \
    -H 'Depth: 0' -H 'Content-Type: application/xml' --data-binary @"$TEST_DIR/big_body.xml" \
    "$WEBDAV_URL/s/$SYNC_ID/" || true)
S85_CHUNKED=$(curl -s -o /dev/null -w '%{http_code}' -u alice:alicepass1 -X SEARCH \
    -H 'Content-Type: application/xml' -H 'Transfer-Encoding: chunked' \
    --data-binary @"$TEST_DIR/big_body.xml" "$WEBDAV_URL/" || true)
if [[ "$S85_SEARCH" == "413" && "$S85_PROPFIND" == "413" && "$S85_CHUNKED" == "413" ]]; then
    check "C85: SEARCH/PROPFIND body over max_request_body → 413 (also chunked)" pass
else
    check "C85: body limit (search=$S85_SEARCH share_propfind=$S85_PROPFIND chunked_search=$S85_CHUNKED)" fail
fi

# ---- C86 (part 1): PROPFIND Depth: infinity → 403 propfind-finite-depth ------
S86_U=$(curl -s -w '\n%{http_code}' -u alice:alicepass1 -X PROPFIND -H 'Depth: infinity' "$WEBDAV_URL/")
S86_S=$(curl -s -w '\n%{http_code}' -u "sync@example.com:$SYNC_TOKEN" -X PROPFIND "$WEBDAV_URL/s/$SYNC_ID/")
S86_U_CODE=$(echo "$S86_U" | tail -1); S86_S_CODE=$(echo "$S86_S" | tail -1)
S86_U_ERR=$(echo "$S86_U" | grep -c 'propfind-finite-depth' || true)
S86_S_ERR=$(echo "$S86_S" | grep -c 'propfind-finite-depth' || true)

# ---- C87: read_header_timeout closes a connection with incomplete headers ----
# The request line and one header are sent, the terminating blank line never
# is. read returns >128 on its own timeout and 1 on EOF (server closed).
C87_CLOSED=no
exec 3<>/dev/tcp/127.0.0.1/8080
printf 'GET /hello.txt HTTP/1.1\r\nHost: localhost\r\n' >&3
C87_T0=$(date +%s)
while :; do
    if IFS= read -r -t 8 -u 3 _line; then continue; fi
    rc=$?
    [[ "$rc" -le 128 ]] && C87_CLOSED=yes
    break
done
C87_ELAPSED=$(($(date +%s) - C87_T0))
exec 3<&-
if [[ "$C87_CLOSED" == "yes" && "$C87_ELAPSED" -ge 1 && "$C87_ELAPSED" -le 4 ]]; then
    check "C87: incomplete request header → connection closed after read_header_timeout (2 s)" pass
else
    check "C87: read_header_timeout (closed=$C87_CLOSED after ${C87_ELAPSED}s)" fail
fi

# ---- C79: unknown config key → refuse to start, naming the key ---------------
printf 'data_dir = "%s"\nmax_conections = 10\n' "$DATA_DIR" >"$TEST_DIR/bad.toml"
BAD_STDOUT="$TEST_DIR/bad_stdout.txt"
(cd "$TEST_DIR" && exec ./webdavgo -config "$TEST_DIR/bad.toml") >"$BAD_STDOUT" 2>&1 &
BAD_PID=$!
sleep 1
BAD_RUNNING=0; BAD_EXIT=0
kill -0 "$BAD_PID" 2>/dev/null && BAD_RUNNING=1 || true
if [[ "$BAD_RUNNING" -eq 0 ]]; then
    wait "$BAD_PID" 2>/dev/null || BAD_EXIT=$?
else
    kill "$BAD_PID" 2>/dev/null || true
fi
BAD_MSG=$(grep -c 'unknown key.*max_conections' "$BAD_STDOUT" || true)
if [[ "$BAD_RUNNING" -eq 0 && "$BAD_EXIT" -ne 0 && "$BAD_MSG" -gt 0 ]]; then
    check "C79: unknown config key → non-zero exit naming the key" pass
else
    check "C79: unknown key (running=$BAD_RUNNING exit=$BAD_EXIT msg=$BAD_MSG)" fail
fi

# ---- C80: leftover upload temp files are removed at startup ------------------
mkdir -p "$DATA_DIR/users/alice/sync/u"
echo stale >"$DATA_DIR/users/alice/.webdavgo-tmp-x"
echo stale >"$DATA_DIR/users/alice/sync/u/.webdavgo-tmp-y"
echo keep >"$DATA_DIR/users/alice/sync/u/not-a-tmp.txt"
stop_server
start_server
login_admin
C80_LEFT=$(find "$DATA_DIR/users" -name '.webdavgo-tmp-*' | wc -l | tr -d ' ')
C80_KEPT=$(test -f "$DATA_DIR/users/alice/sync/u/not-a-tmp.txt" && echo yes || echo no)
C80_WARN=$(grep "$LOG WARN "'"removed stale upload temp file"' "$STDOUT_FILE" \
    | grep -c -e '.webdavgo-tmp-x' -e '.webdavgo-tmp-y' || true)
rm -f "$DATA_DIR/users/alice/sync/u/not-a-tmp.txt"
if [[ "$C80_LEFT" == "0" && "$C80_KEPT" == "yes" && "$C80_WARN" == "2" ]]; then
    check "C80: stale .webdavgo-tmp-* files removed at startup, one Warn line each" pass
else
    check "C80: temp cleanup (left=$C80_LEFT kept_other=$C80_KEPT warn_lines=$C80_WARN)" fail
fi

# ---- C78: -data-dir flag overrides the config file ---------------------------
stop_server
start_server -data-dir "$TEST_DIR/flagdir"
C78_DB=$(test -f "$TEST_DIR/flagdir/webdavgo.db" && echo yes || echo no)
C78_LOG=$(grep -c "${LOGMSG}config data_dir=$TEST_DIR/flagdir " "$STDOUT_FILE" || true)
stop_server
if [[ "$C78_DB" == "yes" && "$C78_LOG" -gt 0 ]]; then
    check "C78: -data-dir flag overrides data_dir from the config file" pass
else
    check "C78: -data-dir flag (db=$C78_DB logged=$C78_LOG)" fail
fi

# ---- C81: SIGTERM mid-upload → upload completes, process exits 0 ------------
start_server
head -c 3000000 /dev/urandom >"$TEST_DIR/slow.bin"
curl -s -o /dev/null -w '%{http_code}' -u alice:alicepass1 -X PUT --limit-rate 1M \
    --data-binary @"$TEST_DIR/slow.bin" "$WEBDAV_URL/slow.bin" >"$TEST_DIR/slow_status" &
C81_CURL=$!
sleep 1
kill -TERM "$SERVER_PID"
wait "$C81_CURL" || true
C81_EXIT=0; wait "$SERVER_PID" || C81_EXIT=$?
SERVER_PID=""
C81_STATUS=$(cat "$TEST_DIR/slow_status")
C81_SAME=$(cmp -s "$TEST_DIR/slow.bin" "$DATA_DIR/users/alice/slow.bin" && echo yes || echo no)
C81_DONE=$(grep -c "$LOGMSG"'"shutdown complete"' "$STDOUT_FILE" || true)
if [[ "$C81_STATUS" == "201" && "$C81_SAME" == "yes" && "$C81_EXIT" == "0" && "$C81_DONE" -gt 0 ]]; then
    check "C81: SIGTERM during PUT → PUT 201, content complete, exit 0" pass
else
    check "C81: graceful shutdown (put=$C81_STATUS complete=$C81_SAME exit=$C81_EXIT logged=$C81_DONE)" fail
fi

# ---- C86 (part 2): allow_propfind_infinity = true → 207 ----------------------
write_config 'allow_propfind_infinity = true' 'shutdown_timeout = "1s"'
start_server
S86_ALLOW=$(curl -s -o /dev/null -w '%{http_code}' -u alice:alicepass1 -X PROPFIND \
    -H 'Depth: infinity' "$WEBDAV_URL/")
S86_ALLOW_S=$(curl -s -o /dev/null -w '%{http_code}' -u "sync@example.com:$SYNC_TOKEN" -X PROPFIND \
    "$WEBDAV_URL/s/$SYNC_ID/")
if [[ "$S86_U_CODE" == "403" && "$S86_U_ERR" -gt 0 && "$S86_S_CODE" == "403" && "$S86_S_ERR" -gt 0 \
      && "$S86_ALLOW" == "207" && "$S86_ALLOW_S" == "207" ]]; then
    check "C86: PROPFIND Depth infinity/none → 403 propfind-finite-depth; allowed by config → 207" pass
else
    check "C86: depth limit (user=$S86_U_CODE/$S86_U_ERR share=$S86_S_CODE/$S86_S_ERR allowed=$S86_ALLOW/$S86_ALLOW_S)" fail
fi

# ---- C88: shutdown timeout expires → upload cut, no temp file, exit 0 --------
curl -s -o /dev/null -w '%{http_code}' -u alice:alicepass1 -X PUT --limit-rate 500K \
    --data-binary @"$TEST_DIR/slow.bin" "$WEBDAV_URL/cut.bin" >"$TEST_DIR/cut_status" &
C88_CURL=$!
sleep 1
kill -TERM "$SERVER_PID"
wait "$C88_CURL" || true
C88_EXIT=0; wait "$SERVER_PID" || C88_EXIT=$?
SERVER_PID=""
C88_STATUS=$(cat "$TEST_DIR/cut_status")
C88_TARGET=$(test -e "$DATA_DIR/users/alice/cut.bin" && echo yes || echo no)
C88_TMP=$(find "$DATA_DIR/users" -name '.webdavgo-tmp-*' | wc -l | tr -d ' ')
C88_CUT=$(grep -c "$LOGMSG"'"shutdown timeout expired, closing connections" connections_cut=1' "$STDOUT_FILE" || true)
if [[ "$C88_STATUS" != "201" && "$C88_TARGET" == "no" && "$C88_TMP" == "0" \
      && "$C88_EXIT" == "0" && "$C88_CUT" -gt 0 ]]; then
    check "C88: shutdown timeout → upload cut and discarded, no temp file, exit 0, cut count logged" pass
else
    check "C88: forced shutdown (put=$C88_STATUS target=$C88_TARGET tmp=$C88_TMP exit=$C88_EXIT logged=$C88_CUT)" fail
fi

write_config
start_server
login_admin

# ============================================================
# Migration system tests
# ============================================================

# ---- C59: downgrade to v0 → migrations re-run, user_version restored, data preserved ----
stop_server
sqlite3 "$TEST_DB" "PRAGMA user_version = 0;" 2>/dev/null
start_server
sleep 0.5
UV59=$(sqlite3 "$TEST_DB" "PRAGMA user_version;" 2>/dev/null || echo -1)
ADMIN59=$(sqlite3 "$TEST_DB" \
    "SELECT COUNT(*) FROM users WHERE username='admin';" 2>/dev/null || echo 0)
if [[ "$UV59" == "3" && "$ADMIN59" == "1" ]]; then
    check "C59: downgrade v0→v3: user_version=3, admin user preserved" pass
else
    check "C59: migration from v0 (ver=$UV59 admin=$ADMIN59)" fail
fi
# Re-authenticate after restart.
login_admin

# ---- C60: backup file bak-v0-* created before the v0→v3 migration -----------
BAK60=$(ls "$DATA_DIR"/webdavgo.db.bak-v0-* 2>/dev/null | wc -l | tr -d ' ')
if [[ "$BAK60" -ge 1 ]]; then
    check "C60: backup file webdavgo.db.bak-v0-* exists after migration" pass
else
    check "C60: backup file not found (count=$BAK60)" fail
fi

# ---- C61: DB version newer than binary → server refuses to start ------------
stop_server
sqlite3 "$TEST_DB" "PRAGMA user_version = 4;" 2>/dev/null
FAIL_STDOUT="/tmp/webdavgo_newer_fail.txt"
(cd "$TEST_DIR" && exec ./webdavgo -config "$CONFIG_FILE") >"$FAIL_STDOUT" 2>&1 &
FAIL_PID=$!
sleep 1
STILL_RUNNING=0
kill -0 "$FAIL_PID" 2>/dev/null && STILL_RUNNING=1 || true
EXIT_CODE=0
if [[ "$STILL_RUNNING" -eq 0 ]]; then
    wait "$FAIL_PID" 2>/dev/null || EXIT_CODE=$?
else
    kill "$FAIL_PID" 2>/dev/null || true
fi
HAS_MSG=$(grep -c "newer than binary" "$FAIL_STDOUT" 2>/dev/null || true)
if [[ "$STILL_RUNNING" -eq 0 && "$EXIT_CODE" -ne 0 && "$HAS_MSG" -gt 0 ]]; then
    check "C61: DB version newer than binary → server exits non-zero" pass
else
    check "C61: newer than binary (running=$STILL_RUNNING exit=$EXIT_CODE msg=$HAS_MSG)" fail
fi
rm -f "$FAIL_STDOUT"
# Restore and restart so the C52 regression can run.
sqlite3 "$TEST_DB" "PRAGMA user_version = 3;" 2>/dev/null
start_server
sleep 0.5
login_admin

# ---- C52: Regression — all existing criteria not broken ---------------------
PF_R=$(curl -s -o /dev/null -w "%{http_code}" -X PROPFIND \
    -u admin:adminpass123 -H "Depth: 1" "$WEBDAV_URL/")
NO_AUTH_R=$(curl -s -o /dev/null -w "%{http_code}" "$WEBDAV_URL/hello.txt")
SEARCH_R=$(curl -s -o /dev/null -w "%{http_code}" -X SEARCH \
    -u admin:adminpass123 -H 'Content-Type: application/xml' \
    --data '<?xml version="1.0"?><d:searchrequest xmlns:d="DAV:"><d:basicsearch>
      <d:select><d:prop><d:getetag/></d:prop></d:select>
      <d:from><d:scope><d:href>/</d:href><d:depth>infinity</d:depth></d:scope></d:from>
      <d:where/>
    </d:basicsearch></d:searchrequest>' "$WEBDAV_URL/")
ADMIN_R=$(agui -o /dev/null -w "%{http_code}" "$WEBGUI_URL/admin/users")
if [[ "$PF_R" == "207" && "$NO_AUTH_R" == "401" && "$SEARCH_R" == "207" && "$ADMIN_R" == "200" ]]; then
    check "C52: Regression — MVP, admin-ui, SEARCH, PROPFIND still pass" pass
else
    check "C52: Regression (propfind=$PF_R noauth=$NO_AUTH_R search=$SEARCH_R admin=$ADMIN_R)" fail
fi

# ============================================================
# Admin hardening (C104–C119): TLS-only admin listener, mandatory TOTP,
# CSRF and security headers, session invalidation, brute-force overview,
# effective configuration. C104/C105/C107/C108 run during the bootstrap and
# the first restart above, C112/C113 with the brute-force limits below and
# C119 with Pebble.
# ============================================================

# ---- C109: admin without TOTP → forced enrolment; pending session is confined
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users" -d "username=admin2&password=admin2pass1&role=admin"
H109=$(password_login admin2 admin2pass1)
P109=$(cookie_of "$H109")
C109_LOC=$(location_of "$H109")
C109_USERS=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' -H "Cookie: $P109" "$WEBGUI_URL/admin/users" || true)
C109_SEC=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' -H "Cookie: $P109" "$WEBGUI_URL/admin/security" || true)
C109_TOTP=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' -H "Cookie: $P109" "$WEBGUI_URL/admin/totp" || true)
P109_CSRF=$(csrf_of "$P109" /admin/enrol)
C109_POST=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $P109" -H "X-CSRF-Token: $P109_CSRF" \
    -X POST "$WEBGUI_URL/admin/users" -d "username=sneaky&password=sneakypass1&role=admin" || true)
C109_SNEAKY=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM users WHERE username='sneaky';" 2>/dev/null || echo 1)
C109_QR=$(gui -H "Cookie: $P109" "$WEBGUI_URL/admin/enrol" | grep -c -e 'src="data:image/png;base64,' -e 'otpauth://totp/webdavgo:admin2@' || true)
enrol "$P109"
ADMIN2_SECRET="$ENROL_SECRET"; ADMIN2_STEP="$ENROL_STEP"
S2=$(cookie_of "$ENROL_HDRS")
C109_FULL=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $S2" "$WEBGUI_URL/admin/users" || true)
if [[ "$C109_LOC" == "/admin/enrol" && "$C109_USERS" == "303 $WEBGUI_URL/admin/enrol" \
      && "$C109_SEC" == "303 $WEBGUI_URL/admin/enrol" && "$C109_TOTP" == "303 $WEBGUI_URL/admin/enrol" \
      && "$C109_POST" == "303" && "$C109_SNEAKY" == "0" && "$C109_QR" == "2" && "$C109_FULL" == "200" ]]; then
    check "C109: admin without TOTP → enrolment (QR + otpauth URI); pending session redirected away from /admin/users, cannot POST; full after confirming" pass
else
    check "C109: forced enrolment (login→$C109_LOC users=[$C109_USERS] security=[$C109_SEC] totp=[$C109_TOTP] post=$C109_POST sneaky=$C109_SNEAKY qr=$C109_QR full=$C109_FULL)" fail
fi

# ---- C110: correct TOTP → full session; the same code again → rejected -------
H110=$(password_login admin adminpass123); P110=$(cookie_of "$H110"); C110_LOC=$(location_of "$H110")
C110_PENDING=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' -H "Cookie: $P110" "$WEBGUI_URL/admin/users" || true)
totp_for "$ADMIN_SECRET" ADMIN_STEP admin; CODE110="$TOTP_CODE"
H110=$(second_factor "$P110" "$CODE110"); F110=$(cookie_of "$H110")
C110_OK="$(status_line "$H110") $(location_of "$H110")"
C110_FULL=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $F110" "$WEBGUI_URL/admin/users" || true)
C110_OLD=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $P110" "$WEBGUI_URL/admin/totp" || true)
P110B=$(cookie_of "$(password_login admin adminpass123)")
H110B=$(second_factor "$P110B" "$CODE110")
C110_REPLAY="$(status_line "$H110B") $(cookie_of "$H110B")"
C110_MSG=$(grep -c 'Invalid code' "$TEST_DIR/totp_body.html" || true)
C110_LOG=$(grep -c "$LOGMSG"'"totp code replay rejected" username=admin' "$STDOUT_FILE" || true)
if [[ "$C110_LOC" == "/admin/totp" && "$C110_PENDING" == "303 $WEBGUI_URL/admin/totp" && "$C110_OK" == "303 /admin/" \
      && -n "$F110" && "$F110" != "$P110" && "$C110_FULL" == "200" && "$C110_OLD" == "303" \
      && "$C110_REPLAY" == "200 " && "$C110_MSG" == "1" && "$C110_LOG" -ge 1 ]]; then
    check "C110: password → TOTP step; valid code → new full session ID; same code in a second login → 'Invalid code', replay logged" pass
else
    check "C110: TOTP login (login→$C110_LOC pending=[$C110_PENDING] ok=[$C110_OK] full=$C110_FULL old_id=$C110_OLD replay=[$C110_REPLAY] msg=$C110_MSG log=$C110_LOG)" fail
fi

# ---- C111: a recovery code works once ---------------------------------------
REC111="${RECOVERY_CODES[0]:-none}"
H111=$(second_factor "$(cookie_of "$(password_login admin adminpass123)")" "$(echo "$REC111" | tr 'a-z' 'A-Z')")
C111_FIRST="$(status_line "$H111") $(location_of "$H111")"
H111B=$(second_factor "$(cookie_of "$(password_login admin adminpass123)")" "$REC111")
C111_SECOND="$(status_line "$H111B") $(cookie_of "$H111B")"
C111_LOG=$(grep -c "$LOGMSG"'"recovery code used" username=admin remaining=9' "$STDOUT_FILE" || true)
C111_DB=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM recovery_codes WHERE username='admin' AND used_at IS NOT NULL;" 2>/dev/null || echo 0)
if [[ "$C111_FIRST" == "303 /admin/" && "$C111_SECOND" == "200 " && "$C111_LOG" == "1" && "$C111_DB" == "1" ]]; then
    check "C111: recovery code (case-insensitive) logs in once (9 left); second use rejected" pass
else
    check "C111: recovery code (first=[$C111_FIRST] second=[$C111_SECOND] log=$C111_LOG used_in_db=$C111_DB)" fail
fi

# ---- C114: CSRF token and Origin checks on state-changing requests ----------
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users" -d "username=csrfvictim&password=csrfvictim1&role=user"
DEL114="$WEBGUI_URL/admin/users/csrfvictim/delete"
C114_NOTOKEN=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "Origin: $WEBGUI_URL" -X POST "$DEL114" || true)
C114_WRONG=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "X-CSRF-Token: 00$CSRF" -H "Origin: $WEBGUI_URL" -X POST "$DEL114" || true)
C114_ORIGIN=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "Origin: https://evil.example" -X POST "$DEL114" || true)
C114_XSITE=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "Origin: null" \
    -H "Sec-Fetch-Site: cross-site" -X POST "$DEL114" || true)
C114_REFERER=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" \
    -H "Referer: https://evil.example/page" -X POST "$DEL114" || true)
C114_LOGIN=$(gui -o /dev/null -w '%{http_code}' -H "Origin: https://evil.example" -X POST "$WEBGUI_URL/admin/login" \
    -d "username=admin&password=adminpass123" || true)
C114_STILL=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM users WHERE username='csrfvictim';" 2>/dev/null || echo 0)
# What a browser sends for an HTMX request when it withholds the origin
# (Origin: null without Referer); Sec-Fetch-Site still decides.
C114_HTMX=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "HX-Request: true" \
    -H "Origin: null" -H "Sec-Fetch-Site: same-origin" -X POST "$DEL114" || true)
C114_GONE=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM users WHERE username='csrfvictim';" 2>/dev/null || echo 1)
# A plain form carries the token as a hidden field instead of the header.
C114_FORM=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "Origin: $WEBGUI_URL" -X POST "$WEBGUI_URL/admin/users" \
    -d "username=formuser&password=formuser1&role=user&csrf_token=$CSRF" || true)
C114_FORMUSER=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM users WHERE username='formuser';" 2>/dev/null || echo 0)
if [[ "$C114_NOTOKEN$C114_WRONG$C114_ORIGIN$C114_XSITE$C114_REFERER$C114_LOGIN" == "403403403403403403" \
      && "$C114_STILL" == "1" && "$C114_HTMX" == "303" && "$C114_GONE" == "0" \
      && "$C114_FORM" == "303" && "$C114_FORMUSER" == "1" ]]; then
    check "C114: POST without/with wrong CSRF token, foreign Origin/Referer or cross-site fetch → 403; HTMX delete with X-CSRF-Token → done; form field accepted" pass
else
    check "C114: CSRF (no_token=$C114_NOTOKEN wrong=$C114_WRONG origin=$C114_ORIGIN cross_site=$C114_XSITE referer=$C114_REFERER login=$C114_LOGIN still=$C114_STILL htmx=$C114_HTMX gone=$C114_GONE form=$C114_FORM formuser=$C114_FORMUSER)" fail
fi

# ---- C115: cookie flags, security headers, no inline script or style --------
C115_COOKIE=$(password_login admin adminpass123 | grep -i '^set-cookie: webdavgo_session' | tr -d '\r' || true)
C115_HDRS=$(agui -D - -o /dev/null "$WEBGUI_URL/admin/users" | tr -d '\r' || true)
C115_LOGIN_HDRS=$(gui -D - -o /dev/null "$WEBGUI_URL/admin/login" | tr -d '\r' || true)
hval() { echo "$1" | grep -i "^$2:" | head -1 | cut -d: -f2- | sed 's/^ *//' || true; }
C115_CSP=$(hval "$C115_HDRS" content-security-policy)
C115_INLINE=0
for page in /admin/ /admin/users /admin/shares /admin/security /admin/status /admin/settings /admin/login; do
    n=$(agui "$WEBGUI_URL$page" | grep -c -e '<script>' -e '<script [^s]' -e ' style=' -e '<style' -e ' on[a-z]*=' || true)
    C115_INLINE=$((C115_INLINE + n))
done
if [[ "$C115_COOKIE" == *"Secure"* && "$C115_COOKIE" == *"HttpOnly"* && "$C115_COOKIE" == *"SameSite=Strict"* \
      && "$C115_CSP" == *"default-src 'self'"* && "$C115_CSP" == *"img-src 'self' data:"* && "$C115_CSP" != *"unsafe"* \
      && "$(hval "$C115_HDRS" x-frame-options)" == "DENY" && "$(hval "$C115_HDRS" x-content-type-options)" == "nosniff" \
      && "$(hval "$C115_HDRS" referrer-policy)" == "same-origin" && "$(hval "$C115_HDRS" cache-control)" == "no-store" \
      && "$(hval "$C115_LOGIN_HDRS" content-security-policy)" == "$C115_CSP" && "$C115_INLINE" == "0" ]]; then
    check "C115: session cookie Secure/HttpOnly/SameSite=Strict; CSP default-src 'self', X-Frame-Options, nosniff, Referrer-Policy same-origin, no-store; no inline script/style" pass
else
    check "C115: headers (cookie=[$C115_COOKIE] csp=[$C115_CSP] xfo=$(hval "$C115_HDRS" x-frame-options) nosniff=$(hval "$C115_HDRS" x-content-type-options) referrer=$(hval "$C115_HDRS" referrer-policy) cache=$(hval "$C115_HDRS" cache-control) inline=$C115_INLINE)" fail
fi

# ---- C116: password reset, TOTP reset and deletion end the user's sessions ----
users_status() { gui -o /dev/null -w '%{http_code}' -H "Cookie: $1" "$WEBGUI_URL/admin/users" || true; }
C116_BEFORE=$(users_status "$S2")
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users/admin2/reset" -d "new_password=admin2pass2"
C116_PW=$(users_status "$S2")
# totp_for has to run in this shell to remember the used step.
P116=$(cookie_of "$(password_login admin2 admin2pass2)")
totp_for "$ADMIN2_SECRET" ADMIN2_STEP admin2
S2=$(cookie_of "$(second_factor "$P116" "$TOTP_CODE")")
C116_RELOGIN=$(users_status "$S2")
C116_OWN=$(agui -o /dev/null -w '%{http_code}' -X POST "$WEBGUI_URL/admin/users/admin/totp-reset" -d "code=000000")
C116_OWN_KEPT=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM totp WHERE username='admin' AND enabled=1;" 2>/dev/null || echo 0)
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users/admin2/totp-reset"
C116_TOTP=$(users_status "$S2")
C116_TOTP_DB=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM totp WHERE username='admin2';" 2>/dev/null || echo 1)
H116=$(password_login admin2 admin2pass2); P116=$(cookie_of "$H116")
C116_REENROL=$(location_of "$H116")
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users/admin2/delete"
C116_DEL=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' -H "Cookie: $P116" "$WEBGUI_URL/admin/enrol" || true)
C116_LOG=$(grep -c -e "$LOGMSG"'"password reset" username=admin2 by=admin sessions_ended=1' \
    -e "$LOGMSG"'"totp reset" username=admin2 by=admin sessions_ended=1' \
    -e "$LOGMSG"'"user deleted" username=admin2 by=admin sessions_ended=1' "$STDOUT_FILE" || true)
if [[ "$C116_BEFORE" == "200" && "$C116_PW" == "303" && "$C116_RELOGIN" == "200" && "$C116_OWN" == "403" \
      && "$C116_OWN_KEPT" == "1" && "$C116_TOTP" == "303" && "$C116_TOTP_DB" == "0" && "$C116_REENROL" == "/admin/enrol" \
      && "$C116_DEL" == "303 $WEBGUI_URL/admin/login" && "$C116_LOG" == "3" ]]; then
    check "C116: password reset, TOTP reset and deletion each end the user's sessions; own TOTP reset without valid code → 403" pass
else
    check "C116: session invalidation (before=$C116_BEFORE after_pw=$C116_PW relogin=$C116_RELOGIN own_reset=$C116_OWN own_kept=$C116_OWN_KEPT after_totp=$C116_TOTP totp_rows=$C116_TOTP_DB reenrol=$C116_REENROL after_delete=[$C116_DEL] log=$C116_LOG)" fail
fi

# ---- C117: status page shows the effective configuration ---------------------
C117_PAGE=$(agui "$WEBGUI_URL/admin/status")
C117_N=0
for row in "<th>tls_mode</th><td><code>off</code>" "<th>config_file</th><td><code>$CONFIG_FILE</code>" \
           "<th>webgui_addr (listening)</th><td><code>:8443</code>" "<th>cert_dir</th><td><code>$DATA_DIR/certs</code>" \
           "<th>bruteforce_ip_threshold</th><td><code>100000</code>" "<th>admin certificate SHA-256</th><td><code>$ADMIN_FP</code>" \
           "<th>acme_ca</th><td><code>production</code>" "<th>domain</th><td><code>(unset)</code>"; do
    if echo "$C117_PAGE" | grep -qF "$row"; then C117_N=$((C117_N + 1)); fi
done
if [[ "$C117_N" == "8" ]]; then
    check "C117: status page lists the effective configuration (config file, listeners, tls_mode, cert_dir, limits, fingerprint)" pass
else
    check "C117: effective configuration ($C117_N of 8 rows found)" fail
fi

# ---- C118: webdavgo reset-totp clears TOTP; next login forces enrolment ------
# Since the session epoch (C134) the running service also ends the reset
# admin's sessions at their next request.
C118_NODB=0; (cd "$TEST_DIR" && ./webdavgo reset-totp -data-dir "$TEST_DIR/nonexistent" admin) >"$TEST_DIR/c118_nodb.txt" 2>&1 || C118_NODB=$?
C118_NODB_MSG=$(grep -c "$LOGMSG"'"cannot open database"' "$TEST_DIR/c118_nodb.txt" || true)
C118_NODIR=$(test -e "$TEST_DIR/nonexistent" && echo created || echo absent)
C118_NOUSER=0; (cd "$TEST_DIR" && ./webdavgo reset-totp -config "$CONFIG_FILE" nosuchuser) >/dev/null 2>&1 || C118_NOUSER=$?
C118_EXIT=0; (cd "$TEST_DIR" && ./webdavgo reset-totp -config "$CONFIG_FILE" admin) >"$TEST_DIR/c118.txt" 2>&1 || C118_EXIT=$?
C118_MSG=$(grep -c "$LOGMSG"'"totp reset" username=admin by="reset-totp command"' "$TEST_DIR/c118.txt" || true)
C118_ROWS=$(sqlite3 "$TEST_DB" "SELECT (SELECT COUNT(*) FROM totp WHERE username='admin') + (SELECT COUNT(*) FROM recovery_codes WHERE username='admin');" 2>/dev/null || echo 1)
C118_SESSION=$(users_status "$SESSION")
H118=$(password_login admin adminpass123); P118=$(cookie_of "$H118")
C118_LOC=$(location_of "$H118")
enrol "$P118"
ADMIN_SECRET="$ENROL_SECRET"; ADMIN_STEP="$ENROL_STEP"
SESSION=$(cookie_of "$ENROL_HDRS"); CSRF=$(csrf_of "$SESSION" /admin/users)
C118_AFTER=$(users_status "$SESSION")
if [[ "$C118_NODB" == "1" && "$C118_NODB_MSG" == "1" && "$C118_NODIR" == "absent" && "$C118_NOUSER" == "1" \
      && "$C118_EXIT" == "0" && "$C118_MSG" == "1" && "$C118_ROWS" == "0" && "$C118_SESSION" == "303" \
      && "$C118_LOC" == "/admin/enrol" && "$C118_AFTER" == "200" ]]; then
    check "C118: reset-totp clears TOTP and recovery codes (exit 0), ends the running session; next login → enrolment; refuses without DB or user" pass
else
    check "C118: reset-totp (nodb_exit=$C118_NODB msg=$C118_NODB_MSG dir=$C118_NODIR nouser_exit=$C118_NOUSER exit=$C118_EXIT logged=$C118_MSG rows=$C118_ROWS session=$C118_SESSION login→$C118_LOC after_enrol=$C118_AFTER)" fail
fi

# ============================================================
# Stale CSRF header after re-login (C120–C124). A boosted page keeps its
# <body hx-headers> across sign-out and sign-in in the same tab, so the
# browser sends the old session's token as header next to the fresh form
# field. curl does not run htmx; these criteria replay what it sends.
# ============================================================

# ---- C120: stale header + correct form field on the TOTP page → accepted ----
STALE_CSRF="$CSRF"
agui -o /dev/null -X POST "$WEBGUI_URL/admin/logout"
P120=$(cookie_of "$(password_login admin adminpass123)")
P120_CSRF=$(csrf_of "$P120" /admin/totp)
totp_for "$ADMIN_SECRET" ADMIN_STEP admin
H120=$(gui -D - -o /dev/null -H "Cookie: $P120" -H "X-CSRF-Token: $STALE_CSRF" -H "Origin: $WEBGUI_URL" \
    -X POST "$WEBGUI_URL/admin/totp" -d "code=$TOTP_CODE&csrf_token=$P120_CSRF" || true)
C120="$(status_line "$H120") $(location_of "$H120")"
F120=$(cookie_of "$H120")
if [[ -n "$F120" ]]; then SESSION="$F120"; CSRF=$(csrf_of "$SESSION" /admin/users); else login_admin; fi
C120_FULL=$(users_status "$SESSION")
if [[ "$C120" == "303 /admin/" && -n "$F120" && "$C120_FULL" == "200" && "$STALE_CSRF" != "$P120_CSRF" ]]; then
    check "C120: TOTP POST with the previous session's X-CSRF-Token and the current csrf_token field → accepted" pass
else
    check "C120: stale header + fresh field (totp=[$C120] full=$C120_FULL)" fail
fi

# ---- C121: stale header without form field → 403; the log names the reason --
P121=$(cookie_of "$(password_login admin adminpass123)")
P121_CSRF=$(csrf_of "$P121" /admin/totp)
post121() { gui -o /dev/null -w '%{http_code}' -H "Cookie: $P121" -H "Origin: $WEBGUI_URL" -X POST "$WEBGUI_URL/admin/totp" "$@" || true; }
L121=$(log_mark)
C121_HEADER=$(post121 -H "X-CSRF-Token: $STALE_CSRF" -d "code=000000")
C121_FORM=$(post121 -d "code=000000&csrf_token=$STALE_CSRF")
C121_NONE=$(post121 -d "code=000000")
sleep 0.2
C121_LOG=$(tail -n +$((L121 + 1)) "$STDOUT_FILE" \
    | grep "$LOGMSG"'"admin request rejected: missing or wrong CSRF token" username=admin method=POST path=/admin/totp' \
    | grep -c -e 'reason="header token wrong"' -e 'reason="form token wrong"' -e 'reason="no token"' || true)
C121_LEAK=$(grep -c -e "$STALE_CSRF" -e "$P121_CSRF" "$STDOUT_FILE" || true)
if [[ "$C121_HEADER$C121_FORM$C121_NONE" == "403403403" && "$C121_LOG" == "3" && "$C121_LEAK" == "0" ]]; then
    check "C121: TOTP POST with stale header and no field, stale field or no token → 403; Warn names header/form/no token, never the token" pass
else
    check "C121: stale token (header=$C121_HEADER form=$C121_FORM none=$C121_NONE log=$C121_LOG leak=$C121_LEAK)" fail
fi

# ---- C122: correct header, no form field (HTMX request) → accepted ----------
C122=$(gui -o /dev/null -w '%{http_code}' -H "Cookie: $SESSION" -H "X-CSRF-Token: $CSRF" -H "HX-Request: true" \
    -H "Origin: $WEBGUI_URL" -X POST "$WEBGUI_URL/admin/users" -d "username=admin3&password=admin3pass1&role=admin" || true)
C122_DB=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM users WHERE username='admin3';" 2>/dev/null || echo 0)
if [[ "$C122" == "303" && "$C122_DB" == "1" ]]; then
    check "C122: HTMX POST with correct X-CSRF-Token and no csrf_token field → accepted" pass
else
    check "C122: header only (status=$C122 created=$C122_DB)" fail
fi

# ---- C123: session-changing forms and links are not boosted -----------------
gui "$WEBGUI_URL/admin/login" >"$TEST_DIR/c123_login.html"
gui -H "Cookie: $P121" "$WEBGUI_URL/admin/totp" >"$TEST_DIR/c123_totp.html"
P123=$(cookie_of "$(password_login admin3 admin3pass1)")
gui -H "Cookie: $P123" "$WEBGUI_URL/admin/enrol" >"$TEST_DIR/c123_enrol.html"
agui "$WEBGUI_URL/admin/users" >"$TEST_DIR/c123_users.html"
C123_N=0; C123_MISSING=""
for spec in 'login|<form [^>]*action="/admin/login"[^>]*hx-boost="false"' \
            'totp|<form [^>]*action="/admin/totp"[^>]*hx-boost="false"' \
            'totp|<form [^>]*action="/admin/logout"[^>]*hx-boost="false"' \
            'enrol|<form [^>]*action="/admin/enrol"[^>]*hx-boost="false"' \
            'users|<form [^>]*action="/admin/logout"[^>]*hx-boost="false"' \
            'users|<form [^>]*action="/admin/users/admin/reset"[^>]*hx-boost="false"' \
            'users|<form [^>]*action="/admin/users/admin/totp-reset"[^>]*hx-boost="false"' \
            'recovery|<a [^>]*href="/admin/"[^>]*hx-boost="false"' \
            'setup|<form [^>]*action="/setup\?token=[0-9a-f]*"[^>]*hx-boost="false"'; do
    file="${spec%%|*}"
    if [[ "$file" == recovery || "$file" == setup ]]; then file="$TEST_DIR/$file.html"; else file="$TEST_DIR/c123_$file.html"; fi
    if grep -qE "${spec#*|}" "$file"; then C123_N=$((C123_N + 1)); else C123_MISSING="$C123_MISSING ${spec%%|*}"; fi
done
# Forms that leave the session alone stay boosted.
C123_OTHER=$(grep -cE '<form [^>]*action="/admin/users/admin3/reset"[^>]*hx-boost' "$TEST_DIR/c123_users.html" || true)
if [[ "$C123_N" == "9" && "$C123_OTHER" == "0" ]]; then
    check "C123: login, TOTP, enrolment, logout, own password/TOTP reset, recovery link and setup form carry hx-boost=\"false\"" pass
else
    check "C123: hx-boost=\"false\" ($C123_N of 9; missing:$C123_MISSING; other user's reset unboosted=$C123_OTHER)" fail
fi

# ---- C124: error display script served and referenced; CSP unchanged --------
C124_JS=$(gui -o /dev/null -w '%{http_code} %{content_type}' "$WEBGUI_URL/admin/static/errors.js" || true)
C124_EVENTS=$(gui "$WEBGUI_URL/admin/static/errors.js" | grep -c -e 'htmx:responseError' -e 'htmx:sendError' || true)
C124_REF=0; C124_TOTAL=0
for page in /admin/ /admin/users /admin/shares /admin/security /admin/status /admin/settings; do
    agui "$WEBGUI_URL$page" >"$TEST_DIR/c124_page.html"
    C124_TOTAL=$((C124_TOTAL + 1))
    if grep -q '<script src="/admin/static/errors.js"></script>' "$TEST_DIR/c124_page.html"; then C124_REF=$((C124_REF + 1)); fi
done
for f in c123_login c123_totp c123_enrol recovery setup; do
    C124_TOTAL=$((C124_TOTAL + 1))
    if grep -q '<script src="/admin/static/errors.js"></script>' "$TEST_DIR/$f.html"; then C124_REF=$((C124_REF + 1)); fi
done
CSP_WANT="default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
C124_CSP_USERS=$(hval "$(agui -D - -o /dev/null "$WEBGUI_URL/admin/users" | tr -d '\r')" content-security-policy)
C124_CSP_LOGIN=$(hval "$(gui -D - -o /dev/null "$WEBGUI_URL/admin/login" | tr -d '\r')" content-security-policy)
if [[ "$C124_JS" == "200 text/javascript"* && "$C124_EVENTS" == "2" && "$C124_REF" == "$C124_TOTAL" \
      && "$C124_CSP_USERS" == "$CSP_WANT" && "$C124_CSP_LOGIN" == "$CSP_WANT" ]]; then
    check "C124: /admin/static/errors.js served (htmx:responseError, htmx:sendError) and referenced by all $C124_TOTAL admin pages; CSP unchanged" pass
else
    check "C124: error script (js=[$C124_JS] events=$C124_EVENTS referenced=$C124_REF/$C124_TOTAL csp_users=[$C124_CSP_USERS] csp_login=[$C124_CSP_LOGIN])" fail
fi
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users/admin3/delete"

# ---- C106: the old admin default :8081 moves to :8443 once; custom values stay
# Deleting the marker makes the database look like one from before the move.
MOVED_KEY=webgui_addr_moved_to_tls_default
stop_server
sqlite3 "$TEST_DB" "UPDATE settings SET value=':8081' WHERE key='webgui_addr'; DELETE FROM settings WHERE key='$MOVED_KEY';"
start_server
C106_OLD_DB=$(sqlite3 "$TEST_DB" "SELECT value FROM settings WHERE key='webgui_addr';" 2>/dev/null || true)
C106_OLD_LOG=$(grep -c "$LOG INFO "'"admin listener moved to the new default address (TLS only)" old=:8081 new=:8443' "$STDOUT_FILE" || true)
C106_OLD_LISTEN=$(grep -c "$LOGMSG"'"webgui listener" addr=[^ ]*:8443 tls=true' "$STDOUT_FILE" || true)
stop_server
sqlite3 "$TEST_DB" "UPDATE settings SET value=':9443' WHERE key='webgui_addr'; DELETE FROM settings WHERE key='$MOVED_KEY';"
start_server
C106_CUSTOM_DB=$(sqlite3 "$TEST_DB" "SELECT value FROM settings WHERE key='webgui_addr';" 2>/dev/null || true)
C106_CUSTOM_LOG=$(grep -c 'admin listener moved' "$STDOUT_FILE" || true)
C106_CUSTOM_LISTEN=$(grep -c "$LOGMSG"'"webgui listener" addr=[^ ]*:9443 tls=true' "$STDOUT_FILE" || true)
stop_server
# Once moved, a deliberate :8081 stays.
sqlite3 "$TEST_DB" "UPDATE settings SET value=':8081' WHERE key='webgui_addr';"
start_server
C106_AGAIN_DB=$(sqlite3 "$TEST_DB" "SELECT value FROM settings WHERE key='webgui_addr';" 2>/dev/null || true)
# The settings are read before the listeners open, so this holds even if
# another process has port 8081.
C106_AGAIN_RAN=$(grep -c "$LOGMSG"'"admin certificate"' "$STDOUT_FILE" || true)
stop_server
sqlite3 "$TEST_DB" "UPDATE settings SET value=':8443' WHERE key='webgui_addr';"
start_server
login_admin
if [[ "$C106_OLD_DB" == ":8443" && "$C106_OLD_LOG" == "1" && "$C106_OLD_LISTEN" == "1" && "$C106_CUSTOM_DB" == ":9443" \
      && "$C106_CUSTOM_LOG" == "0" && "$C106_CUSTOM_LISTEN" == "1" && "$C106_AGAIN_DB" == ":8081" \
      && "$C106_AGAIN_RAN" == "1" ]]; then
    check "C106: webgui_addr :8081 (old default) → :8443 once, logged at Info; custom :9443 and a later deliberate :8081 untouched" pass
else
    check "C106: admin address move (old→$C106_OLD_DB log=$C106_OLD_LOG listen=$C106_OLD_LISTEN custom→$C106_CUSTOM_DB log=$C106_CUSTOM_LOG listen=$C106_CUSTOM_LISTEN later=$C106_AGAIN_DB ran=$C106_AGAIN_RAN)" fail
fi

# ============================================================
# Internet readiness (C89–C103): login timing, brute-force protection,
# slow request bodies, shutdown race, TLS via ACME (Pebble).
# Brute-force criteria address the server as 127.0.0.1 and [::1] explicitly:
# they are two distinct clients (IPv4 address, IPv6 /64) on macOS and Linux
# alike, unlike 127.0.0.2, which macOS does not route to lo0 by default.
# ============================================================

V4_URL="http://127.0.0.1:8080"
V6_URL="http://[::1]:8080"
GUI4_URL="https://127.0.0.1:8443"

# status_of prints the status of a PROPFIND Depth 0 with the given
# credentials; $2 is the base URL (default V4_URL).
status_of() {
    curl -s -o /dev/null -w '%{http_code}' -u "$1" -X PROPFIND -H 'Depth: 0' "${2:-$V4_URL}/" || true
}

# median prints the median of its numeric arguments.
median() { printf '%s\n' "$@" | sort -n | sed -n "$(( ($# + 1) / 2 ))p"; }

# ---- C89: unknown and known user take the same time for a wrong password -----
# Without the dummy bcrypt an unknown user is answered at once, a known one
# after a full bcrypt run; the difference is then one bcrypt duration.
T_KNOWN=(); T_UNKNOWN=()
for _ in 1 2 3 4 5; do
    T_KNOWN+=("$(curl -s -o /dev/null -w '%{time_total}' -u admin:wrongpass -X PROPFIND -H 'Depth: 0' "$V4_URL/")")
    T_UNKNOWN+=("$(curl -s -o /dev/null -w '%{time_total}' -u nosuchuser:wrongpass -X PROPFIND -H 'Depth: 0' "$V4_URL/")")
done
M_KNOWN=$(median "${T_KNOWN[@]}"); M_UNKNOWN=$(median "${T_UNKNOWN[@]}")
C89_OK=$(awk -v k="$M_KNOWN" -v u="$M_UNKNOWN" 'BEGIN { d = k - u; if (d < 0) d = -d; print (k > 0.03 && d < k / 2) ? "yes" : "no" }')
if [[ "$C89_OK" == "yes" ]]; then
    check "C89: wrong password for unknown vs known user: median ${M_UNKNOWN}s vs ${M_KNOWN}s (< half a bcrypt apart)" pass
else
    check "C89: login timing (unknown=${M_UNKNOWN}s known=${M_KNOWN}s)" fail
fi

# ---- brute-force setup -------------------------------------------------------
# Users and a share are created under the relaxed config; the server then
# restarts with small limits. In-memory limiter state starts empty on every
# restart, so each group below begins from a clean slate.
for u in bfone bftwo bfcache; do
    agui -o /dev/null -X POST "$WEBGUI_URL/admin/users" \
        -d "username=$u&password=${u}pass1&role=user"
done
curl -s -o /dev/null -X MKCOL -u bfcache:bfcachepass1 "$V4_URL/bfs"
BF_SHARE=$(curl -s -X POST -u bfcache:bfcachepass1 -H 'Content-Type: application/json' \
    --data '{"path":"/bfs","recipient_email":"bf@example.com","permission":"read"}' "$V4_URL/api/v1/shares")
BF_SHARE_ID=$(echo "$BF_SHARE" | jq -r '.share_id'); BF_SHARE_TOKEN=$(echo "$BF_SHARE" | jq -r '.access_token')

BF_CFG=('bruteforce_window = "60s"' 'bruteforce_ip_threshold = 3' 'bruteforce_lockout_base = "3s"'
    'bruteforce_lockout_max = "12s"' 'bruteforce_account_threshold = 4' 'bruteforce_account_interval = "3s"')
stop_server
write_config "${BF_CFG[@]}"
start_server

# ---- C90: IP lockout → 429 + Retry-After even for correct password; cache passes
A90_CACHE1=$(status_of bfcache:bfcachepass1)
A90_F1=$(status_of ghost1:wrongpass); A90_F2=$(status_of ghost1:wrongpass); A90_F3=$(status_of ghost1:wrongpass)
H90=$(curl -s -o /dev/null -D - -u bfone:bfonepass1 -X PROPFIND -H 'Depth: 0' "$V4_URL/" || true)
A90_LOCKED=$(echo "$H90" | head -1 | awk '{print $2}' || true)
RA90=$(echo "$H90" | grep -i '^retry-after:' | tr -d '\r' | awk '{print $2}' || true)
A90_WWWA=$(echo "$H90" | grep -ci '^www-authenticate:' || true)
A90_CACHE2=$(status_of bfcache:bfcachepass1)
A90_LOG=$(grep -c "$LOGMSG"'"brute-force lockout started" client=127.0.0.1 failures=3 duration=3s' "$STDOUT_FILE" || true)
if [[ "$A90_CACHE1" == "207" && "$A90_F1$A90_F2$A90_F3" == "401401401" && "$A90_LOCKED" == "429" \
      && "$RA90" =~ ^[1-3]$ && "$A90_WWWA" == "0" && "$A90_CACHE2" == "207" && "$A90_LOG" == "1" ]]; then
    check "C90: 3 failures → IP lockout: correct uncached password → 429 Retry-After $RA90, cached login → 207, Warn logged" pass
else
    check "C90: IP lockout (cache=$A90_CACHE1 fails=$A90_F1/$A90_F2/$A90_F3 locked=$A90_LOCKED ra=$RA90 www-auth=$A90_WWWA cache-after=$A90_CACHE2 log=$A90_LOG)" fail
fi

# ---- C91: share auth during an IP lockout: right token passes, wrong → 429 ----
A91_OK=$(status_of "bf@example.com:$BF_SHARE_TOKEN" "$V4_URL/s/$BF_SHARE_ID")
H91=$(curl -s -o /dev/null -D - -u "bf@example.com:shr_tok_wrong" -X PROPFIND -H 'Depth: 0' "$V4_URL/s/$BF_SHARE_ID/" || true)
A91_BAD=$(echo "$H91" | head -1 | awk '{print $2}' || true)
RA91=$(echo "$H91" | grep -ci '^retry-after:' || true)
if [[ "$A91_OK" == "207" && "$A91_BAD" == "429" && "$RA91" == "1" ]]; then
    check "C91: during IP lockout: correct share token → 207, wrong token → 429 with Retry-After (not 401)" pass
else
    check "C91: share during lockout (correct=$A91_OK wrong=$A91_BAD retry_after=$RA91)" fail
fi

# ---- C92: the second lockout lasts twice as long -----------------------------
sleep "$((RA90 + 1))"
A92_FREE=$(status_of bfone:bfonepass1)
status_of ghost2:wrongpass >/dev/null; status_of ghost2:wrongpass >/dev/null; status_of ghost2:wrongpass >/dev/null
# bfone is cached now, so the probe uses bftwo, whose login is not.
H92=$(curl -s -o /dev/null -D - -u bftwo:bftwopass1 -X PROPFIND -H 'Depth: 0' "$V4_URL/" || true)
A92_LOCKED=$(echo "$H92" | head -1 | awk '{print $2}' || true)
RA92=$(echo "$H92" | grep -i '^retry-after:' | tr -d '\r' | awk '{print $2}' || true)
A92_LOG=$(grep -c "$LOGMSG"'"brute-force lockout started" client=127.0.0.1 failures=3 duration=6s' "$STDOUT_FILE" || true)
if [[ "$A92_FREE" == "207" && "$A92_LOCKED" == "429" && "$RA92" =~ ^[56]$ && "$A92_LOG" == "1" ]]; then
    check "C92: after the 3 s lockout expired, 3 more failures → lockout of 6 s (Retry-After $RA92)" pass
else
    check "C92: doubling (after-expiry=$A92_FREE locked=$A92_LOCKED ra=$RA92 log=$A92_LOG)" fail
fi

# ---- C93: per-account throttle across two clients; cache still passes -------
stop_server
start_server
A93_CACHE=$(status_of bftwo:bftwopass1)
A93_F="$(status_of bftwo:wrong1)$(status_of bftwo:wrong2)$(status_of bftwo:wrong3 "$V6_URL")$(status_of bftwo:wrong4 "$V6_URL")"
H93=$(curl -s -o /dev/null -D - -u bftwo:wrong5 -X PROPFIND -H 'Depth: 0' "$V4_URL/" || true)
A93_THR=$(echo "$H93" | head -1 | awk '{print $2}' || true)
RA93=$(echo "$H93" | grep -i '^retry-after:' | tr -d '\r' | awk '{print $2}' || true)
A93_CACHE2=$(status_of bftwo:bftwopass1)
A93_OTHER=$(status_of bfone:bfonepass1)
sleep 3.2
A93_SLOT=$(status_of bftwo:wrong6 "$V6_URL")
A93_AGAIN=$(status_of bftwo:wrong7)
A93_LOG=$(grep -c "$LOGMSG"'"brute-force account throttle engaged" username=bftwo failures=4' "$STDOUT_FILE" || true)
if [[ "$A93_CACHE" == "207" && "$A93_F" == "401401401401" && "$A93_THR" == "429" && "$RA93" =~ ^[1-3]$ \
      && "$A93_CACHE2" == "207" && "$A93_OTHER" == "207" && "$A93_SLOT" == "401" && "$A93_AGAIN" == "429" \
      && "$A93_LOG" == "1" ]]; then
    check "C93: 2+2 failures from 127.0.0.1 and ::1 → account throttle 429 (Retry-After $RA93), one check per 3 s; cached login and other users pass" pass
else
    check "C93: account throttle (cache=$A93_CACHE fails=$A93_F throttled=$A93_THR ra=$RA93 cache-after=$A93_CACHE2 other-user=$A93_OTHER slot=$A93_SLOT again=$A93_AGAIN log=$A93_LOG)" fail
fi

# ---- C94: admin login lockout → 429 page ------------------------------------
stop_server
start_server
for _ in 1 2 3; do
    gui -o /dev/null -X POST "$GUI4_URL/admin/login" -d "username=admin&password=wrongpass"
done
A94=$(gui -D - -X POST "$GUI4_URL/admin/login" -d "username=admin&password=adminpass123" || true)
A94_STATUS=$(echo "$A94" | head -1 | awk '{print $2}' || true)
A94_RA=$(echo "$A94" | grep -ci '^retry-after:' || true)
A94_MSG=$(echo "$A94" | grep -c 'Too many failed login attempts. Try again in 1 minute.' || true)
A94_COOKIE=$(echo "$A94" | grep -ci 'set-cookie: webdavgo_session' || true)
if [[ "$A94_STATUS" == "429" && "$A94_RA" == "1" && "$A94_MSG" == "1" && "$A94_COOKIE" == "0" ]]; then
    check "C94: 3 failed admin logins → correct password gets 429 page 'Too many failed login attempts', no session" pass
else
    check "C94: admin lockout (status=$A94_STATUS retry_after=$A94_RA msg=$A94_MSG cookie=$A94_COOKIE)" fail
fi

# ---- C112: wrong TOTP codes count toward the IP lockout → 429 ----------------
# The full admin session is taken first: once 127.0.0.1 is locked, no login
# from it gets through, but an existing session keeps working (C113).
stop_server
start_server
login_admin
P112=$(cookie_of "$(password_login admin adminpass123 "$GUI4_URL")")
WRONG112=$("$TOTP_BIN" "$ADMIN_SECRET" 0)
# The valid code is taken first: totp_for may wait for the next time step,
# which would outlast the 3 s lockout.
totp_for "$ADMIN_SECRET" ADMIN_STEP admin
A112=""
for _ in 1 2 3; do A112+="$(status_line "$(second_factor "$P112" "$WRONG112" "$GUI4_URL")")"; done
H112=$(second_factor "$P112" "$TOTP_CODE" "$GUI4_URL")
A112_LOCKED=$(status_line "$H112")
A112_RA=$(echo "$H112" | grep -ci '^retry-after:' || true)
A112_MSG=$(grep -c 'Too many failed login attempts' "$TEST_DIR/totp_body.html" || true)
A112_COOKIE=$(cookie_of "$H112")
A112_PW=$(status_line "$(password_login admin adminpass123 "$GUI4_URL")")
A112_LOG=$(grep -c "$LOGMSG"'"brute-force lockout started" client=127.0.0.1 failures=3' "$STDOUT_FILE" || true)
# Attributes are matched one by one: client= sits between username and kind.
A112_WARN=$(grep "$LOGMSG"'"login failed: second factor" ' "$STDOUT_FILE" | grep -F ' username=admin ' \
    | grep -c -F ' kind=totp' || true)
if [[ "$A112" == "200200200" && "$A112_LOCKED" == "429" && "$A112_RA" == "1" && "$A112_MSG" == "1" \
      && -z "$A112_COOKIE" && "$A112_PW" == "429" && "$A112_LOG" == "1" && "$A112_WARN" == "3" ]]; then
    check "C112: 3 wrong TOTP codes → IP lockout: correct code and password step get 429 with Retry-After, no session" pass
else
    check "C112: TOTP lockout (wrong=$A112 correct=$A112_LOCKED retry_after=$A112_RA msg=$A112_MSG cookie=$A112_COOKIE password=$A112_PW log=$A112_LOG warn=$A112_WARN)" fail
fi

# ---- C113: Security page lists lockouts and throttles; unlock works ---------
C113_ROW='<td><code>127.0.0.1</code></td>'
C113_LISTED=$(agui "$WEBGUI_URL/admin/security" | grep -c "$C113_ROW" || true)
C113_UNLOCK=$(agui -o /dev/null -w '%{http_code}' -X POST "$WEBGUI_URL/admin/security/unlock-client" -d "client=127.0.0.1")
C113_GONE=$(agui "$WEBGUI_URL/admin/security" | grep -c "$C113_ROW" || true)
H113=$(password_login admin adminpass123 "$GUI4_URL"); P113=$(cookie_of "$H113")
C113_PW="$(status_line "$H113") $(location_of "$H113")"
# A fourth wrong code (the IP counter starts over) throttles the account,
# which has 3 failures from C112 and a threshold of 4.
C113_WRONG=$(status_line "$(second_factor "$P113" "$WRONG112" "$GUI4_URL")")
C113_ACCT=$(agui "$WEBGUI_URL/admin/security" | grep -c '<td>admin</td>' || true)
C113_CLEAR=$(agui -o /dev/null -w '%{http_code}' -X POST "$WEBGUI_URL/admin/security/clear-account" -d "username=admin")
C113_ACCT_GONE=$(agui "$WEBGUI_URL/admin/security" | grep -c '<td>admin</td>' || true)
totp_for "$ADMIN_SECRET" ADMIN_STEP admin
C113_TOTP="$(second_factor "$P113" "$TOTP_CODE" "$GUI4_URL" | head -1 | awk '{print $2}')"
C113_LOG=$(grep -c -e "$LOG INFO "'"brute-force client unlocked manually" client=127.0.0.1 by=admin' \
    -e "$LOG INFO "'"brute-force account throttle cleared manually" username=admin by=admin' "$STDOUT_FILE" || true)
if [[ "$C113_LISTED" == "1" && "$C113_UNLOCK" == "303" && "$C113_GONE" == "0" && "$C113_PW" == "303 /admin/totp" \
      && "$C113_WRONG" == "200" && "$C113_ACCT" == "1" && "$C113_CLEAR" == "303" && "$C113_ACCT_GONE" == "0" \
      && "$C113_TOTP" == "303" && "$C113_LOG" == "2" ]]; then
    check "C113: Security page lists the locked client and the throttled account; unlock/clear remove them (logged with admin) and the client logs in again" pass
else
    check "C113: security page (listed=$C113_LISTED unlock=$C113_UNLOCK gone=$C113_GONE password=[$C113_PW] wrong=$C113_WRONG account=$C113_ACCT clear=$C113_CLEAR account_gone=$C113_ACCT_GONE totp=$C113_TOTP log=$C113_LOG)" fail
fi

# ---- slow request bodies -----------------------------------------------------
stop_server
write_config 'body_read_idle_timeout = "2s"' 'body_min_rate = 1000' 'body_min_rate_grace = "2s"'
start_server
ADMIN_B64=$(printf 'admin:adminpass123' | base64)

# raw_put opens a connection, sends PUT headers for $1 with Content-Length
# $2, and feeds the body on fd 3 with the shell snippet $3 in the
# background. It prints the seconds from the end of the headers until the
# server's response arrives, then the response status code. The response is
# what proves the abort: the client's writes may keep succeeding into the
# half-closed socket for a while. SIGPIPE is ignored so that such a write
# fails instead of killing the script.
raw_put() {
    (
        trap '' PIPE
        exec 3<>/dev/tcp/127.0.0.1/8080
        printf 'PUT %s HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\nContent-Length: %s\r\n\r\n' \
            "$1" "$ADMIN_B64" "$2" >&3
        t0=$(date +%s)
        # stdout goes to /dev/null and the sender's children are killed too:
        # a leftover "sleep 20" holding the command substitution's pipe kept
        # the caller waiting 20 s after the response had arrived.
        (eval "$3") >/dev/null 2>&1 &
        sender=$!
        status_line=""
        IFS= read -r -t 15 -u 3 status_line 2>/dev/null || true
        t1=$(date +%s)
        pkill -P "$sender" 2>/dev/null || true
        kill "$sender" 2>/dev/null || true
        wait "$sender" 2>/dev/null || true
        echo "$((t1 - t0)) $(echo "$status_line" | awk '{print $2}')"
    )
}

# ---- C95: a stalled PUT body is aborted after body_read_idle_timeout ---------
curl -s -o /dev/null -u admin:adminpass123 -X PUT --data-binary 'stall original' "$V4_URL/stall.txt"
read -r C95_T C95_STATUS <<<"$(raw_put /stall.txt 100 'printf 0123456789 >&3; sleep 20')"
C95_CONTENT=$(curl -s -u admin:adminpass123 "$V4_URL/stall.txt" || true)
C95_TMP=$(find "$DATA_DIR/users/admin" -name '.webdavgo-tmp-*' | wc -l | tr -d ' ')
C95_LOG=$(grep -c "$LOGMSG"'"request body aborted: stalled" method=PUT path=/stall.txt bytes=10' "$STDOUT_FILE" || true)
if [[ "$C95_T" =~ ^[0-9]+$ && "$C95_T" -ge 1 && "$C95_T" -le 5 && "$C95_CONTENT" == "stall original" && "$C95_TMP" == "0" && "$C95_LOG" == "1" ]]; then
    check "C95: PUT body stalled > body_read_idle_timeout (2 s) → aborted after ${C95_T}s (status $C95_STATUS), old content kept, no temp file" pass
else
    check "C95: stalled body (answered_after=${C95_T}s status=$C95_STATUS content=$C95_CONTENT tmp=$C95_TMP log=$C95_LOG)" fail
fi

# ---- C96: a PUT body below body_min_rate is aborted after the grace period ---
# 100 bytes every 0.5 s = 200 B/s, under the 1000 B/s minimum, but never idle
# for long enough to hit the idle timeout.
curl -s -o /dev/null -u admin:adminpass123 -X PUT --data-binary 'rate original' "$V4_URL/rate.txt"
CHUNK=$(printf '%0100d' 0)
# The external printf (via env): a failed write of the builtin leaves its
# buffer to be flushed into the next command substitution.
read -r C96_T C96_STATUS <<<"$(raw_put /rate.txt 10000 "for _ in \$(seq 1 16); do env printf '$CHUNK' >&3 || break; sleep 0.5; done")"
C96_CONTENT=$(curl -s -u admin:adminpass123 "$V4_URL/rate.txt" || true)
C96_TMP=$(find "$DATA_DIR/users/admin" -name '.webdavgo-tmp-*' | wc -l | tr -d ' ')
C96_LOG=$(grep -c "$LOGMSG"'"request body aborted: below minimum rate" method=PUT path=/rate.txt' "$STDOUT_FILE" || true)
if [[ "$C96_T" =~ ^[0-9]+$ && "$C96_T" -ge 2 && "$C96_T" -le 4 && "$C96_CONTENT" == "rate original" && "$C96_TMP" == "0" && "$C96_LOG" == "1" ]]; then
    check "C96: PUT at 200 B/s < body_min_rate 1000 B/s → aborted after the 2 s grace (${C96_T}s, status $C96_STATUS), old content kept, no temp file" pass
else
    check "C96: min rate (answered_after=${C96_T}s status=$C96_STATUS content=$C96_CONTENT tmp=$C96_TMP log=$C96_LOG)" fail
fi

# ---- C97: race detector clean through a shutdown under load ------------------
# shutdown_timeout is short and one upload is slow, so both the graceful and
# the forced-close path run while new requests keep arriving.
stop_server
write_config 'shutdown_timeout = "1s"'
go build -race -o "$TEST_DIR/webdavgo-race" ./cmd/webdavgo
GORACE="halt_on_error=0 exitcode=66" start_binary webdavgo-race
# bcrypt is many times slower under -race; one login fills the auth cache so
# the load below is not throttled by it.
status_of alice:alicepass1 >/dev/null
curl -s -o /dev/null -u alice:alicepass1 -X PUT --limit-rate 200K \
    --data-binary @"$TEST_DIR/slow.bin" "$V4_URL/race-slow.bin" &
C97_SLOW=$!
C97_LOAD=()
for n in 1 2 3 4 5 6; do
    (
        end=$(($(date +%s) + 4))
        while [[ $(date +%s) -lt $end ]]; do
            curl -s -o /dev/null --max-time 2 -u alice:alicepass1 -X PROPFIND -H 'Depth: 1' "$V4_URL/" || true
            curl -s -o /dev/null --max-time 2 -u alice:alicepass1 -X PUT --data-binary "load $n" "$V4_URL/race-$n.txt" || true
        done
    ) &
    C97_LOAD+=($!)
done
sleep 2
kill -TERM "$SERVER_PID"
C97_EXIT=0; wait "$SERVER_PID" || C97_EXIT=$?
SERVER_PID=""
wait "$C97_SLOW" "${C97_LOAD[@]}" 2>/dev/null || true
C97_RACES=$(grep -c 'WARNING: DATA RACE' "$STDOUT_FILE" || true)
C97_REQS=$(grep -c "${LOGMSG}request " "$STDOUT_FILE" || true)
C97_FORCED=$(grep -c "$LOGMSG"'"shutdown timeout expired, closing connections"' "$STDOUT_FILE" || true)
if [[ "$C97_EXIT" == "0" && "$C97_RACES" == "0" && "$C97_REQS" -gt 10 && "$C97_FORCED" == "1" ]]; then
    check "C97: -race build: SIGTERM under load ($C97_REQS requests, forced close) → exit 0, no data race" pass
else
    check "C97: race shutdown (exit=$C97_EXIT races=$C97_RACES requests=$C97_REQS forced=$C97_FORCED)" fail
fi

# ============================================================
# Install, setup-info and review leftovers (C125–C136): install/uninstall
# with -root, require_tls, the persisted setup token, settings precedence,
# the HTTP/2 stream limit, brute-force table eviction, the session epoch,
# the own-TOTP-reset throttle and slow reads. The domain wizard criteria
# (C137–C140) need Pebble and follow the ACME criteria.
# ============================================================
go build -o "$TEST_DIR/webdavgo" ./cmd/webdavgo
mode_of() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"; }

# ---- C125: install -root writes the file layout, config and hardened unit ----
INST_ROOT="$TEST_DIR/sysroot"
C125_EXIT=0; "$TEST_DIR/webdavgo" install -root "$INST_ROOT" >"$TEST_DIR/install1.txt" 2>&1 || C125_EXIT=$?
C125_BIN=$(cmp -s "$TEST_DIR/webdavgo" "$INST_ROOT/usr/local/bin/webdavgo" && test -x "$INST_ROOT/usr/local/bin/webdavgo" && echo same || echo differs)
C125_MODES="$(mode_of "$INST_ROOT/etc/webdavgo") $(mode_of "$INST_ROOT/var/lib/webdavgo") $(mode_of "$INST_ROOT/etc/webdavgo/webdavgo.conf")"
INST_CFG="$INST_ROOT/etc/webdavgo/webdavgo.conf"
C125_CFG=$(grep -cxF -e 'data_dir = "/var/lib/webdavgo"' -e 'require_tls = true' \
    -e 'access_log = "/var/log/webdavgo/access.log"' -e 'server_log = "/var/log/webdavgo/webdavgo.log"' "$INST_CFG" || true)
# Only data_dir, require_tls and the two log files are set; tls_mode stays open for the wizard.
C125_ACTIVE=$(grep -cvE '^(#|$)' "$INST_CFG" || true)
C125_UNIT_N=0
for line in 'User=webdavgo' 'Group=webdavgo' 'NoNewPrivileges=yes' 'ProtectSystem=strict' 'ProtectHome=yes' \
    'PrivateTmp=yes' 'PrivateDevices=yes' 'ProtectKernelTunables=yes' 'ProtectKernelModules=yes' 'ProtectKernelLogs=yes' \
    'ProtectControlGroups=yes' 'RestrictNamespaces=yes' 'LockPersonality=yes' 'MemoryDenyWriteExecute=yes' \
    'SystemCallArchitectures=native' 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' 'AmbientCapabilities=CAP_NET_BIND_SERVICE' \
    'ReadWritePaths=/var/lib/webdavgo /etc/webdavgo' 'Restart=on-failure' 'ExecStart=/usr/local/bin/webdavgo -config /etc/webdavgo/webdavgo.conf' \
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK' 'WantedBy=multi-user.target'; do
    grep -qxF "$line" "$INST_ROOT/etc/systemd/system/webdavgo.service" && C125_UNIT_N=$((C125_UNIT_N + 1))
done
# The plan comes first, then nothing else: no step may run before it is listed.
C125_PLAN=$(head -1 "$TEST_DIR/install1.txt")
C125_SKIP=$(grep -c -e 'skip creating the system user webdavgo (-root)' -e 'skip systemctl and setup-info (-root)' "$TEST_DIR/install1.txt" || true)
# The generated config must parse: setup-info then fails only for the missing database.
"$TEST_DIR/webdavgo" setup-info -config "$INST_CFG" -data-dir "$TEST_DIR/inst-nodb" >"$TEST_DIR/inst-parse.txt" 2>&1 || true
C125_PARSE=$(grep -c "$LOGMSG"'"cannot open database' "$TEST_DIR/inst-parse.txt" || true)
C125_SYS=0; "$TEST_DIR/webdavgo" install >"$TEST_DIR/install-sys.txt" 2>&1 || C125_SYS=$?
C125_SYS_MSG=$(grep -c -e 'supports Linux with systemd only' -e 'must run as root' -e 'needs systemd' "$TEST_DIR/install-sys.txt" || true)
if [[ "$C125_EXIT" == "0" && "$C125_BIN" == "same" && "$C125_MODES" == "750 750 640" && "$C125_CFG" == "4" \
      && "$C125_ACTIVE" == "4" && "$C125_UNIT_N" == "22" && "$C125_PLAN" == "webdavgo install will:" && "$C125_SKIP" == "2" \
      && "$C125_PARSE" == "1" && "$C125_SYS" != "0" && "$C125_SYS_MSG" == "1" ]]; then
    check "C125: install -root: binary, /etc/webdavgo 0750, /var/lib/webdavgo 0750, config 0640 (data_dir, require_tls, access_log, server_log only), hardened unit (22 directives); plan printed first; without -root on this system → refused" pass
else
    check "C125: install layout (exit=$C125_EXIT bin=$C125_BIN modes=[$C125_MODES] cfg=$C125_CFG active=$C125_ACTIVE unit=$C125_UNIT_N/22 plan=[$C125_PLAN] skip=$C125_SKIP parse=$C125_PARSE system_exit=$C125_SYS system_msg=$C125_SYS_MSG)" fail
fi

# ---- C126: install is idempotent and updates the binary, never the config ----
echo '# operator edit' >>"$INST_CFG"
echo 'data' >"$INST_ROOT/var/lib/webdavgo/keep.db"
C126_EXIT=0; "$TEST_DIR/webdavgo" install -root "$INST_ROOT" >"$TEST_DIR/install2.txt" 2>&1 || C126_EXIT=$?
C126_KEEP=$(grep -c -e 'keep .*/usr/local/bin/webdavgo (already this binary)' -e 'keep .*/config.toml (an existing config is never overwritten)' \
    -e 'keep .*/webdavgo.service (unchanged)' "$TEST_DIR/install2.txt" || true)
go build -ldflags "-X main.version=c126" -o "$TEST_DIR/webdavgo-v2" ./cmd/webdavgo
C126_UPD=0; "$TEST_DIR/webdavgo-v2" install -root "$INST_ROOT" >"$TEST_DIR/install3.txt" 2>&1 || C126_UPD=$?
C126_COPY=$(grep -c 'copy .*webdavgo-v2 to .*/usr/local/bin/webdavgo (temporary file, then rename)' "$TEST_DIR/install3.txt" || true)
C126_NEWBIN=$(cmp -s "$TEST_DIR/webdavgo-v2" "$INST_ROOT/usr/local/bin/webdavgo" && echo yes || echo no)
C126_EDIT=$(grep -c '^# operator edit$' "$INST_CFG" || true)
C126_DATA=$(cat "$INST_ROOT/var/lib/webdavgo/keep.db" 2>/dev/null || true)
C126_TMP=$(find "$INST_ROOT" -name '.webdavgo-install-*' | wc -l | tr -d ' ')
if [[ "$C126_EXIT" == "0" && "$C126_KEEP" == "3" && "$C126_UPD" == "0" && "$C126_COPY" == "1" && "$C126_NEWBIN" == "yes" \
      && "$C126_EDIT" == "1" && "$C126_DATA" == "data" && "$C126_TMP" == "0" ]]; then
    check "C126: install again → keeps binary, config (operator edit survives), unit and data; from a newer binary → replaces only the binary" pass
else
    check "C126: install idempotency (exit=$C126_EXIT keep=$C126_KEEP update_exit=$C126_UPD copy=$C126_COPY new_bin=$C126_NEWBIN edit=$C126_EDIT data=$C126_DATA tmp=$C126_TMP)" fail
fi

# ---- C127: uninstall keeps config and data unless -purge is confirmed --------
C127_ABORT=0; printf 'not-the-hostname\n' | "$TEST_DIR/webdavgo" uninstall -root "$INST_ROOT" -purge >"$TEST_DIR/uninst0.txt" 2>&1 || C127_ABORT=$?
C127_ABORT_KEPT=$(test -f "$INST_ROOT/usr/local/bin/webdavgo" && test -f "$INST_CFG" && echo yes || echo no)
C127_EXIT=0; "$TEST_DIR/webdavgo" uninstall -root "$INST_ROOT" >"$TEST_DIR/uninst1.txt" 2>&1 || C127_EXIT=$?
C127_GONE=$(test ! -e "$INST_ROOT/usr/local/bin/webdavgo" && test ! -e "$INST_ROOT/etc/systemd/system/webdavgo.service" && echo yes || echo no)
C127_KEPT=$(test -f "$INST_CFG" && test -f "$INST_ROOT/var/lib/webdavgo/keep.db" && echo yes || echo no)
C127_SAYS=$(grep -c "^Kept: $INST_ROOT/etc/webdavgo and $INST_ROOT/var/lib/webdavgo\$" "$TEST_DIR/uninst1.txt" || true)
C127_PURGE=0; "$TEST_DIR/webdavgo" uninstall -root "$INST_ROOT" -purge -yes >"$TEST_DIR/uninst2.txt" 2>&1 || C127_PURGE=$?
C127_PURGED=$(test ! -e "$INST_ROOT/etc/webdavgo" && test ! -e "$INST_ROOT/var/lib/webdavgo" && echo yes || echo no)
if [[ "$C127_ABORT" == "1" && "$C127_ABORT_KEPT" == "yes" && "$C127_EXIT" == "0" && "$C127_GONE" == "yes" \
      && "$C127_KEPT" == "yes" && "$C127_SAYS" == "1" && "$C127_PURGE" == "0" && "$C127_PURGED" == "yes" ]]; then
    check "C127: uninstall -root removes unit and binary, keeps /etc/webdavgo and /var/lib/webdavgo; -purge needs the hostname or -yes, then removes both" pass
else
    check "C127: uninstall (purge_unconfirmed_exit=$C127_ABORT kept_then=$C127_ABORT_KEPT exit=$C127_EXIT removed=$C127_GONE kept=$C127_KEPT says=$C127_SAYS purge_exit=$C127_PURGE purged=$C127_PURGED)" fail
fi

# ---- C128: require_tls keeps plaintext WebDAV off the network ----------------
write_config 'require_tls = true'
start_server
C128_DAV=$(curl -s -o /dev/null --max-time 2 -w '%{http_code}' "$WEBDAV_URL/" || true)
C128_WARN=$(grep -c "$LOG WARN "'"webdav listener not started: require_tls is set and tls_mode is off' "$STDOUT_FILE" || true)
C128_ADMIN=$(gui -o /dev/null -w '%{http_code}' "$WEBGUI_URL/admin/login" || true)
stop_server
sqlite3 "$TEST_DB" "UPDATE settings SET value='127.0.0.1:8080' WHERE key='webdav_addr';"
start_server
C128_LOOP=$(status_of admin:adminpass123)
C128_LOOP_WARN=$(grep -c "$LOGMSG"'"webdav listener not started' "$STDOUT_FILE" || true)
stop_server
sqlite3 "$TEST_DB" "UPDATE settings SET value=':8080' WHERE key='webdav_addr';"
if [[ "$C128_DAV" == "000" && "$C128_WARN" == "1" && "$C128_ADMIN" == "200" && "$C128_LOOP" == "207" && "$C128_LOOP_WARN" == "0" ]]; then
    check "C128: require_tls with tls_mode off: no WebDAV listener on :8080 (Warn names the reason), admin UI runs; webdav_addr 127.0.0.1:8080 → served" pass
else
    check "C128: require_tls (webdav=$C128_DAV warn=$C128_WARN admin=$C128_ADMIN loopback=$C128_LOOP loopback_warn=$C128_LOOP_WARN)" fail
fi

# ---- C129: the setup token is persisted; setup-info shows the same one -------
# A fresh data directory: setup is pending there.
SI_DIR="$TEST_DIR/setupinfo"
SI_CFG="$TEST_DIR/setupinfo.toml"
printf 'data_dir = "%s"\nread_header_timeout = "2s"\n' "$SI_DIR" >"$SI_CFG"
SAVED_CONFIG="$CONFIG_FILE"; SAVED_ADMIN_CA="$ADMIN_CA"
CONFIG_FILE="$SI_CFG"; ADMIN_CA="$SI_DIR/certs/admin-selfsigned.crt"
setup_info() { (cd "$TEST_DIR" && ./webdavgo setup-info -config "$SI_CFG") 2>&1 || true; }
token_in() { grep -o 'https://localhost:8443/setup?token=[0-9a-f]*' "$1" | head -1 | sed 's/.*token=//' || true; }
start_server
SI_T1=$(token_in "$STDOUT_FILE")
setup_info >"$TEST_DIR/si1.txt"
SI_INFO1=$(token_in "$TEST_DIR/si1.txt")
SI_FP=$(grep -o "$LOGMSG"'"admin certificate" sha256=[0-9A-F:]*' "$STDOUT_FILE" | head -1 | sed 's/.*sha256=//' || true)
SI_FP_SHOWN=$(grep -cxF "       $SI_FP" "$TEST_DIR/si1.txt" || true)
SI_ADMIN_URL=$(grep -cx '       https://localhost:8443/' "$TEST_DIR/si1.txt" || true)
SI_TOKEN_LINE=$(grep -cxF "       Token: $SI_T1" "$TEST_DIR/si1.txt" || true)
stop_server
start_server
SI_T2=$(token_in "$STDOUT_FILE")
# Expire the stored token; setup-info must issue a new one that the running service accepts.
sqlite3 "$SI_DIR/webdavgo.db" "UPDATE settings SET value = substr(value, 1, 64) || ' 1000' WHERE key='setup_token';"
setup_info >"$TEST_DIR/si2.txt"
SI_T3=$(token_in "$TEST_DIR/si2.txt")
C129_NEW=$(gui -o /dev/null -w '%{http_code}' "$WEBGUI_URL/setup?token=$SI_T3" || true)
C129_OLD=$(gui -o /dev/null -w '%{http_code}' "$WEBGUI_URL/setup?token=$SI_T1" || true)
C129_LOGGED=$(grep "$LOG" "$STDOUT_FILE" "$TEST_DIR/si1.txt" "$TEST_DIR/si2.txt" | grep -c -e "$SI_T1" -e "$SI_T3" || true)
if [[ ${#SI_T1} == 64 && "$SI_INFO1" == "$SI_T1" && "$SI_T2" == "$SI_T1" && "$SI_FP_SHOWN" == "1" && "$SI_ADMIN_URL" == "1" && "$SI_TOKEN_LINE" == "1" \
      && ${#SI_T3} == 64 && "$SI_T3" != "$SI_T1" && "$C129_NEW" == "200" && "$C129_OLD" == "403" && "$C129_LOGGED" == "0" ]]; then
    check "C129: setup token survives a restart; setup-info prints the same token on its Token: line, admin URL and fingerprint; an expired token is replaced and the running service accepts the new one" pass
else
    check "C129: setup token (t1=${#SI_T1} info=$([[ "$SI_INFO1" == "$SI_T1" ]] && echo same || echo differs) restart=$([[ "$SI_T2" == "$SI_T1" ]] && echo same || echo differs) fp=$SI_FP_SHOWN admin_url=$SI_ADMIN_URL token_line=$SI_TOKEN_LINE new=${#SI_T3} new_ok=$C129_NEW old=$C129_OLD in_log=$C129_LOGGED)" fail
fi

# ---- C130: after setup the token is gone and setup-info says so -------------
gui -o /dev/null -X POST "$WEBGUI_URL/setup?token=$SI_T3" -d "username=siadmin&password=siadmin123&password_confirm=siadmin123"
C130_ROW=$(sqlite3 "$SI_DIR/webdavgo.db" "SELECT COUNT(*) FROM settings WHERE key='setup_token';" 2>/dev/null || echo 1)
C130_EXIT=0; (cd "$TEST_DIR" && ./webdavgo setup-info -config "$SI_CFG") >"$TEST_DIR/si3.txt" 2>&1 || C130_EXIT=$?
C130_DONE=$(grep -c 'Setup is complete: an admin account exists' "$TEST_DIR/si3.txt" || true)
C130_TOKEN=$(grep -c 'token=' "$TEST_DIR/si3.txt" || true)
C130_REUSE=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' "$WEBGUI_URL/setup?token=$SI_T3" || true)
stop_server
CONFIG_FILE="$SAVED_CONFIG"; ADMIN_CA="$SAVED_ADMIN_CA"
if [[ "$C130_ROW" == "0" && "$C130_EXIT" == "0" && "$C130_DONE" == "1" && "$C130_TOKEN" == "0" \
      && "$C130_REUSE" == "303 $WEBGUI_URL/admin/enrol" ]]; then
    check "C130: creating the admin deletes the stored token; setup-info then reports setup complete without a token" pass
else
    check "C130: after setup (token_rows=$C130_ROW exit=$C130_EXIT done=$C130_DONE token_shown=$C130_TOKEN reuse=[$C130_REUSE])" fail
fi

# ---- C131: precedence config file > database (wizard) > default -------------
sqlite3 "$TEST_DB" "INSERT OR REPLACE INTO settings(key,value) VALUES ('domain','db.example.com'),('acme_email','db@example.com');"
write_config 'acme_email = "file@example.com"'
start_server
login_admin
C131_STATUS=$(agui "$WEBGUI_URL/admin/status")
src() { echo "<th>$1</th><td><code>$2</code> <span class=\"muted small source\">$3</span>"; }
C131_N=0
for row in "$(src domain db.example.com 'database (Domain &amp; certificate page)')" \
           "$(src acme_email file@example.com 'config file')" "$(src tls_mode off default)" "$(src acme_ca production default)"; do
    echo "$C131_STATUS" | grep -qF "$row" && C131_N=$((C131_N + 1))
done
C131_PAGE=$(agui "$WEBGUI_URL/admin/domain")
C131_FORM=$(echo "$C131_PAGE" | grep -c 'name="domain" value="db.example.com"' || true)
C131_RO=$(echo "$C131_PAGE" | grep -c -e 'value="file@example.com" readonly disabled' -e "Set in $CONFIG_FILE." || true)
# HTTP/2 stream limit, default (C132 checks a configured one).
C132_DEFAULT=$("$H2_BIN" localhost:8443 "$ADMIN_CA" 2>&1 || true)
stop_server
# tls_mode in the file beats tls_mode = acme stored by the wizard.
sqlite3 "$TEST_DB" "INSERT OR REPLACE INTO settings(key,value) VALUES ('tls_mode','acme');"
write_config 'acme_email = "file@example.com"' 'tls_mode = "off"'
start_server
login_admin
C131_LOCK_STATUS=$(agui "$WEBGUI_URL/admin/status" | grep -cF "$(src tls_mode off 'config file')" || true)
C131_LOCK_DAV=$(status_of admin:adminpass123)
C131_LOCK_PAGE=$(agui "$WEBGUI_URL/admin/domain" | grep -c "tls_mode is set in $CONFIG_FILE" || true)
C131_LOCK_POST=$(agui -o /dev/null -w '%{http_code}' -X POST "$WEBGUI_URL/admin/domain" -d "domain=x.example.com" || true)
stop_server
sqlite3 "$TEST_DB" "DELETE FROM settings WHERE key IN ('domain','acme_email','tls_mode');"
if [[ "$C131_N" == "4" && "$C131_FORM" == "1" && "$C131_RO" == "2" && "$C131_LOCK_STATUS" == "1" && "$C131_LOCK_DAV" == "207" \
      && "$C131_LOCK_PAGE" == "1" && "$C131_LOCK_POST" == "409" ]]; then
    check "C131: domain from the database, acme_email from the file over the database, defaults marked; tls_mode in the file beats the stored acme and locks the Domain page (409)" pass
else
    check "C131: precedence (status_rows=$C131_N/4 form_domain=$C131_FORM email_readonly=$C131_RO lock_status=$C131_LOCK_STATUS lock_dav=$C131_LOCK_DAV lock_page=$C131_LOCK_PAGE lock_post=$C131_LOCK_POST)" fail
fi

# ---- C132: HTTP/2 MaxConcurrentStreams is set explicitly --------------------
write_config 'http2_max_concurrent_streams = 7'
start_server
C132_SET=$("$H2_BIN" localhost:8443 "$ADMIN_CA" 2>&1 || true)
stop_server
if [[ "$C132_DEFAULT" == "32" && "$C132_SET" == "7" ]]; then
    check "C132: HTTP/2 SETTINGS announce MAX_CONCURRENT_STREAMS 32 by default and http2_max_concurrent_streams when set (7)" pass
else
    check "C132: HTTP/2 streams (default=[$C132_DEFAULT] configured=[$C132_SET])" fail
fi

# ---- C133: a full account table never evicts a throttled account ------------
write_config 'bruteforce_max_entries = 3' 'bruteforce_account_threshold = 2' 'bruteforce_account_interval = "1h"' \
    'bruteforce_ip_threshold = 100000' 'bruteforce_window = "60s"'
start_server
C133_F="$(status_of alice:wrong1)$(status_of alice:wrong2)"
C133_OTHERS=""
for n in 1 2 3 4 5 6; do C133_OTHERS+="$(status_of "flood$n:wrong")"; done
# Uncached correct password: still throttled after six newcomers passed a table of three.
C133_ALICE=$(status_of alice:alicepass1)
C133_FULL=$(grep -c "$LOGMSG"'"brute-force table full' "$STDOUT_FILE" || true)
stop_server
if [[ "$C133_F" == "401401" && "$C133_OTHERS" == "401401401401401401" && "$C133_ALICE" == "429" && "$C133_FULL" == "0" ]]; then
    check "C133: account table of 3 full: 6 new usernames evict non-throttled entries only; the throttled account still gets 429" pass
else
    check "C133: eviction (fails=$C133_F others=$C133_OTHERS throttled=$C133_ALICE table_full_logged=$C133_FULL)" fail
fi

# ---- C134: reset-totp (separate process) ends that admin's running sessions --
write_config
start_server
login_admin
agui -o /dev/null -X POST "$WEBGUI_URL/admin/users" -d "username=epochadm&password=epochpass1&role=admin"
P134=$(cookie_of "$(password_login epochadm epochpass1)")
enrol "$P134"
S134=$(cookie_of "$ENROL_HDRS")
C134_BEFORE=$(users_status "$S134")
C134_EXIT=0; (cd "$TEST_DIR" && ./webdavgo reset-totp -config "$CONFIG_FILE" epochadm) >/dev/null 2>&1 || C134_EXIT=$?
C134_AFTER=$(gui -o /dev/null -w '%{http_code} %{redirect_url}' -H "Cookie: $S134" "$WEBGUI_URL/admin/users" || true)
C134_OTHER=$(users_status "$SESSION")
C134_EPOCH=$(sqlite3 "$TEST_DB" "SELECT value FROM settings WHERE key='session_epoch:epochadm';" 2>/dev/null || true)
C134_LOG=$(grep -c "$LOGMSG"'"admin session ended: sessions were revoked outside this process" username=epochadm sessions_ended=1' "$STDOUT_FILE" || true)
if [[ "$C134_BEFORE" == "200" && "$C134_EXIT" == "0" && "$C134_AFTER" == "303 $WEBGUI_URL/admin/login" && "$C134_OTHER" == "200" \
      && "$C134_EPOCH" == "1" && "$C134_LOG" == "1" ]]; then
    check "C134: reset-totp in a separate process bumps the session epoch in the DB; the service ends that admin's session (other admins keep theirs)" pass
else
    check "C134: session epoch (before=$C134_BEFORE exit=$C134_EXIT after=[$C134_AFTER] other=$C134_OTHER epoch=$C134_EPOCH log=$C134_LOG)" fail
fi
stop_server

# ---- C135: own TOTP reset respects the per-account throttle -----------------
write_config 'bruteforce_account_threshold = 2' 'bruteforce_account_interval = "1h"' 'bruteforce_ip_threshold = 100000'
start_server
login_admin
C135_WRONG="$(agui -o /dev/null -w '%{http_code}' -X POST "$WEBGUI_URL/admin/users/admin/totp-reset" -d "code=000000")"
C135_WRONG+="$(agui -o /dev/null -w '%{http_code}' -X POST "$WEBGUI_URL/admin/users/admin/totp-reset" -d "code=000001")"
totp_for "$ADMIN_SECRET" ADMIN_STEP admin
H135=$(agui -D - -o /dev/null -X POST "$WEBGUI_URL/admin/users/admin/totp-reset" -d "code=$TOTP_CODE" || true)
C135_VALID=$(status_line "$H135")
C135_RA=$(echo "$H135" | grep -ci '^retry-after:' || true)
C135_KEPT=$(sqlite3 "$TEST_DB" "SELECT COUNT(*) FROM totp WHERE username='admin' AND enabled=1;" 2>/dev/null || echo 0)
stop_server
if [[ "$C135_WRONG" == "403403" && "$C135_VALID" == "429" && "$C135_RA" == "1" && "$C135_KEPT" == "1" ]]; then
    check "C135: own TOTP reset: 2 wrong codes throttle the account; a valid code then gets 429 with Retry-After, TOTP kept" pass
else
    check "C135: own reset throttle (wrong=$C135_WRONG valid=$C135_VALID retry_after=$C135_RA totp_kept=$C135_KEPT)" fail
fi

# ---- C136: a client that stops reading a download is cut off ----------------
write_config 'response_write_idle_timeout = "2s"'
start_server
dd if=/dev/zero of="$TEST_DIR/big.bin" bs=1048576 count=32 2>/dev/null
curl -s -o /dev/null -u admin:adminpass123 -X PUT --data-binary @"$TEST_DIR/big.bin" "$V4_URL/big.bin"
C136_FULL=$(curl -s -u admin:adminpass123 -o "$TEST_DIR/big.dl" -w '%{size_download}' "$V4_URL/big.bin" || true)
# The server's side is what matters: once the write deadline hits, the
# handler ends and the slot is free, even while curl still drains the
# kernel buffers at 4 KB/s.
T0=$(date +%s)
curl -s -u admin:adminpass123 --limit-rate 4k --max-time 60 -o /dev/null "$V4_URL/big.bin" &
C136_CURL=$!
C136_LOG=0
for _ in $(seq 1 80); do
    C136_LOG=$(grep -c "$LOGMSG"'"response aborted: client stopped reading" method=GET path=/big.bin' "$STDOUT_FILE" || true)
    [[ "$C136_LOG" != "0" ]] && break
    sleep 0.25
done
C136_T=$(( $(date +%s) - T0 ))
kill "$C136_CURL" 2>/dev/null || true; wait "$C136_CURL" 2>/dev/null || true
# Attributes are matched one by one: client= and others sit between them.
C136_REQ=$(grep "${LOGMSG}request " "$STDOUT_FILE" | grep -F ' method=GET ' | grep -F ' path=/big.bin ' \
    | grep -F ' user=admin ' | grep -c -F ' status=200 ' || true)
curl -s -o /dev/null -u admin:adminpass123 -X DELETE "$V4_URL/big.bin"
stop_server
if [[ "$C136_FULL" == "33554432" && "$C136_LOG" == "1" && "$C136_T" -le 15 && "$C136_REQ" == "2" ]]; then
    check "C136: 32 MiB download at full speed completes; a client reading 4 KB/s is cut by response_write_idle_timeout (2 s) after ${C136_T}s, its request ends" pass
else
    check "C136: slow read (full=$C136_FULL log=$C136_LOG after=${C136_T}s finished_requests=$C136_REQ)" fail
fi

# ---- TLS via ACME (C98–C103) -------------------------------------------------
# Pebble is Let's Encrypt's ACME test server. challtestsrv answers its DNS
# queries with 127.0.0.1 for every name, and Pebble validates TLS-ALPN-01 by
# connecting to port 8080 of that address — the WebDAV listener. Validation
# is real (PEBBLE_VA_ALWAYS_VALID is not set); only the random delays and
# nonce rejections Pebble adds by default are turned off for speed.
PATH="$PATH:$(go env GOPATH)/bin"
ACME_DOMAIN="webdavgo.test"
ACME_DIR="$TEST_DIR/acme"
ACME_URL="https://$ACME_DOMAIN:8080"
PEBBLE_SRC=$(ls -d "$(go env GOMODCACHE)"/github.com/letsencrypt/pebble/v2@* 2>/dev/null | sort -V | tail -1 || true)
ACME_LABELS=(
    "C98: tls_mode=acme obtains a certificate via TLS-ALPN-01; HTTPS PROPFIND → 207, certificate for $ACME_DOMAIN"
    "C99: HSTS max-age=31536000 on HTTPS responses"
    "C100: plain HTTP to the TLS listener → no handler (no 2xx, no WWW-Authenticate)"
    "C101: admin status page shows domain and certificate not-after"
    "C102: restart loads the certificate from cert_dir, no new order"
    "C103: tls_mode=acme without domain → startup error naming the key"
    "C119: admin port serves the ACME certificate for SNI = domain, the self-signed one for localhost"
    "C137: Domain & certificate: a failed order keeps the old listener"
    "C138: Domain & certificate: trial + real order, WebDAV switches to :443 in-process"
    "C139: finish page and status page show the certificate"
    "C140: restart after the wizard: TLS on :443 from the database"
)

if ! command -v pebble >/dev/null || ! command -v pebble-challtestsrv >/dev/null || [[ -z "$PEBBLE_SRC" ]]; then
    for l in "${ACME_LABELS[@]}"; do
        check "$l (pebble not installed: go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest and .../cmd/pebble-challtestsrv@latest)" fail
    done
else
    mkdir -p "$ACME_DIR"
    cat >"$ACME_DIR/pebble.json" <<EOF
{"pebble": {
  "listenAddress": "127.0.0.1:14000",
  "managementListenAddress": "127.0.0.1:15000",
  "certificate": "$PEBBLE_SRC/test/certs/localhost/cert.pem",
  "privateKey": "$PEBBLE_SRC/test/certs/localhost/key.pem",
  "httpPort": 5002,
  "tlsPort": 8080,
  "ocspResponderURL": "",
  "externalAccountBindingRequired": false,
  "retryAfter": {"authz": 1, "order": 1},
  "keyAlgorithm": "ecdsa"
}}
EOF
    pebble-challtestsrv -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 -http01 "" -https01 "" \
        -tlsalpn01 "" -doh "" -defaultIPv4 127.0.0.1 -defaultIPv6 "" >"$ACME_DIR/challtestsrv.log" 2>&1 &
    CHALL_PID=$!
    PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=0 \
        pebble -config "$ACME_DIR/pebble.json" -dnsserver 127.0.0.1:8053 >"$ACME_DIR/pebble.log" 2>&1 &
    PEBBLE_PID=$!
    for _ in $(seq 1 40); do
        curl -s --max-time .3 --cacert "$PEBBLE_SRC/test/certs/pebble.minica.pem" \
            https://127.0.0.1:14000/dir >/dev/null 2>&1 && break
        sleep 0.25
    done
    # One file for both trust anchors: minica signs Pebble's own HTTPS
    # endpoint, the root from /roots/0 issues the server certificates.
    curl -s --cacert "$PEBBLE_SRC/test/certs/pebble.minica.pem" https://127.0.0.1:15000/roots/0 >"$ACME_DIR/root.pem" || true
    cat "$PEBBLE_SRC/test/certs/pebble.minica.pem" "$ACME_DIR/root.pem" >"$ACME_DIR/trust.pem"

    {
        echo "data_dir = \"$ACME_DIR/data\""
        echo 'log_level = "debug"'
        echo 'tls_mode = "acme"'
        echo "domain = \"$ACME_DOMAIN\""
        echo 'acme_ca = "https://127.0.0.1:14000/dir"'
        echo "acme_ca_root = \"$ACME_DIR/trust.pem\""
    } >"$CONFIG_FILE"

    # wait_cert waits up to 30 s for the certificate to be in use.
    wait_cert() {
        for _ in $(seq 1 120); do
            grep -q "$LOGMSG"'"certificate in use"' "$STDOUT_FILE" && return 0
            sleep 0.25
        done
        return 1
    }
    # https prints the status of an HTTPS PROPFIND; headers land in $HDR_F.
    https() {
        curl -s -o /dev/null -D "$HDR_F" -w '%{http_code}' --resolve "$ACME_DOMAIN:8080:127.0.0.1" \
            --cacert "$ACME_DIR/trust.pem" -u admin:adminpass123 -X PROPFIND -H 'Depth: 0' "$ACME_URL/" || true
    }

    ADMIN_CA="$ACME_DIR/data/certs/admin-selfsigned.crt"; TOTP_DB="$ACME_DIR/data/webdavgo.db"
    start_server
    ACME_TOKEN=$(grep -o 'https://localhost:8443/setup?token=[0-9a-f]*' "$STDOUT_FILE" | head -1 | sed 's/.*token=//')
    enrol "$(cookie_of "$(gui -D - -o /dev/null -X POST "$WEBGUI_URL/setup?token=$ACME_TOKEN" \
        -d "username=admin&password=adminpass123&password_confirm=adminpass123")")"
    ADMIN_SECRET="$ENROL_SECRET"; ADMIN_STEP="$ENROL_STEP"
    C98_READY=$(wait_cert && echo yes || echo no)

    # ---- C98: certificate via TLS-ALPN-01, HTTPS PROPFIND, SAN ------------
    C98_STATUS=$(https)
    C98_SAN=$(openssl s_client -connect 127.0.0.1:8080 -servername "$ACME_DOMAIN" </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null | grep -c "DNS:$ACME_DOMAIN" || true)
    C98_ALPN=$(grep -c "$LOGMSG"'"served key authentication certificate" component=certmagic challenge=tls-alpn-01' "$STDOUT_FILE" || true)
    # Every challenge CertMagic attempted must be tls-alpn-01; it also logs
    # "no solver configured" for the http-01 offer it skips.
    C98_TRIED=$(grep "$LOGMSG"'"trying to solve challenge"' "$STDOUT_FILE" | grep -c 'challenge_type=tls-alpn-01' || true)
    C98_OTHER=$(grep "$LOGMSG"'"trying to solve challenge"' "$STDOUT_FILE" | grep -vc 'challenge_type=tls-alpn-01' || true)
    C98_ISSUED=$(grep -c 'Issued certificate serial' "$ACME_DIR/pebble.log" || true)
    if [[ "$C98_READY" == "yes" && "$C98_STATUS" == "207" && "$C98_SAN" -gt 0 && "$C98_ALPN" -gt 0 \
          && "$C98_TRIED" -gt 0 && "$C98_OTHER" == "0" && "$C98_ISSUED" == "1" ]]; then
        check "${ACME_LABELS[0]}" pass
    else
        check "C98: ACME obtain (ready=$C98_READY propfind=$C98_STATUS san=$C98_SAN alpn_served=$C98_ALPN tried_alpn=$C98_TRIED tried_other=$C98_OTHER issued=$C98_ISSUED)" fail
    fi

    # ---- C99: HSTS -------------------------------------------------------
    C99_HSTS=$(hdr Strict-Transport-Security)
    if [[ "$C99_HSTS" == "max-age=31536000" ]]; then check "${ACME_LABELS[1]}" pass
    else check "C99: HSTS (got '$C99_HSTS')" fail; fi

    # ---- C100: plain HTTP is refused by the TLS listener ------------------
    # Go answers 400 to plaintext that starts like GET/HEAD/POST/PUT/OPTIONS
    # and closes the connection for anything else, such as PROPFIND.
    C100_GET=$(curl -s -D - -u admin:adminpass123 "http://127.0.0.1:8080/" || true)
    C100_PF=$(curl -s -D - -u admin:adminpass123 -X PROPFIND -H 'Depth: 0' "http://127.0.0.1:8080/" || true)
    C100_GET_STATUS=$(echo "$C100_GET" | head -1 | awk '{print $2}' || true)
    C100_PF_STATUS=$(echo "$C100_PF" | head -1 | awk '{print $2}' || true)
    C100_WWWA=$(printf '%s\n%s\n' "$C100_GET" "$C100_PF" | grep -ci '^www-authenticate:' || true)
    if [[ "$C100_GET_STATUS" == "400" && ! "$C100_PF_STATUS" =~ ^[0-9] && "$C100_WWWA" == "0" ]]; then
        check "${ACME_LABELS[2]} (GET → 400, PROPFIND → connection closed)" pass
    else
        check "C100: plain HTTP (get=$C100_GET_STATUS propfind=$C100_PF_STATUS www-auth=$C100_WWWA)" fail
    fi

    # ---- C101: admin status page ----------------------------------------
    login_admin
    C101_PAGE=$(agui "$WEBGUI_URL/admin/status" || true)
    C101_DOMAIN=$(echo "$C101_PAGE" | grep -c "<td>$ACME_DOMAIN</td>" || true)
    C101_NA=$(echo "$C101_PAGE" | grep -cE 'Not after</th><td>20[0-9]{2}-[0-9]{2}-[0-9]{2} ' || true)
    if [[ "$C101_DOMAIN" == "1" && "$C101_NA" == "1" ]]; then check "${ACME_LABELS[3]}" pass
    else check "C101: status page (domain=$C101_DOMAIN not_after=$C101_NA)" fail; fi

    # ---- C102: restart reuses the stored certificate ----------------------
    C102_ORDERS_BEFORE=$(grep -c 'Added order' "$ACME_DIR/pebble.log" || true)
    stop_server
    start_server
    C102_READY=$(wait_cert && echo yes || echo no)
    C102_STATUS=$(https)
    C102_ORDERS_AFTER=$(grep -c 'Added order' "$ACME_DIR/pebble.log" || true)
    C102_OBTAIN=$(grep -c -e "$LOGMSG"'"obtaining certificate"' -e "$LOGMSG"'"certificate obtained"' "$STDOUT_FILE" || true)
    if [[ "$C102_READY" == "yes" && "$C102_STATUS" == "207" && "$C102_ORDERS_BEFORE" == "1" \
          && "$C102_ORDERS_AFTER" == "1" && "$C102_OBTAIN" == "0" ]]; then
        check "${ACME_LABELS[4]}" pass
    else
        check "C102: restart (ready=$C102_READY propfind=$C102_STATUS orders=$C102_ORDERS_BEFORE→$C102_ORDERS_AFTER obtain_lines=$C102_OBTAIN)" fail
    fi

    # ---- C119: admin port picks the certificate by SNI ---------------------
    C119_SAN=$(openssl s_client -connect 127.0.0.1:8443 -servername "$ACME_DOMAIN" </dev/null 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null | grep -c "DNS:$ACME_DOMAIN" || true)
    C119_DOMAIN_FP=$(fingerprint_of 8443 "$ACME_DOMAIN")
    C119_WEBDAV_FP=$(fingerprint_of 8080 "$ACME_DOMAIN")
    C119_LOCAL_FP=$(fingerprint_of 8443 localhost)
    C119_IP_FP=$(openssl s_client -connect 127.0.0.1:8443 </dev/null 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//' || true)
    C119_SELF_FP=$(openssl x509 -in "$ADMIN_CA" -noout -fingerprint -sha256 | sed 's/.*=//')
    C119_CURL=$(curl -s -o /dev/null -w '%{http_code}' --resolve "$ACME_DOMAIN:8443:127.0.0.1" \
        --cacert "$ACME_DIR/trust.pem" "https://$ACME_DOMAIN:8443/admin/login" || true)
    if [[ "$C119_SAN" -gt 0 && -n "$C119_DOMAIN_FP" && "$C119_DOMAIN_FP" == "$C119_WEBDAV_FP" \
          && "$C119_LOCAL_FP" == "$C119_SELF_FP" && "$C119_IP_FP" == "$C119_SELF_FP" \
          && "$C119_DOMAIN_FP" != "$C119_SELF_FP" && "$C119_CURL" == "200" ]]; then
        check "${ACME_LABELS[6]}" pass
    else
        check "C119: admin SNI (san=$C119_SAN domain_fp=$C119_DOMAIN_FP webdav_fp=$C119_WEBDAV_FP localhost_fp=$C119_LOCAL_FP ip_fp=$C119_IP_FP self=$C119_SELF_FP curl=$C119_CURL)" fail
    fi
    stop_server

    # ---- C103: missing domain is a startup error ---------------------------
    printf 'data_dir = "%s"\ntls_mode = "acme"\n' "$ACME_DIR/nodomain" >"$TEST_DIR/nodomain.toml"
    ND_OUT="$TEST_DIR/nodomain_stdout.txt"
    (cd "$TEST_DIR" && exec ./webdavgo -config "$TEST_DIR/nodomain.toml") >"$ND_OUT" 2>&1 &
    ND_PID=$!
    sleep 1
    ND_RUNNING=0; ND_EXIT=0
    kill -0 "$ND_PID" 2>/dev/null && ND_RUNNING=1 || true
    if [[ "$ND_RUNNING" -eq 0 ]]; then wait "$ND_PID" 2>/dev/null || ND_EXIT=$?
    else kill "$ND_PID" 2>/dev/null || true; fi
    ND_MSG=$(grep -c 'domain is required when tls_mode = \\"acme\\"' "$ND_OUT" || true)
    if [[ "$ND_RUNNING" -eq 0 && "$ND_EXIT" -ne 0 && "$ND_MSG" -gt 0 ]]; then check "${ACME_LABELS[5]}" pass
    else check "C103: missing domain (running=$ND_RUNNING exit=$ND_EXIT msg=$ND_MSG)" fail; fi

    # ============================================================
    # Domain & certificate wizard (C137–C140). Pebble now validates on
    # port 443, where the wizard moves the WebDAV listener. Binding :443
    # needs no root on macOS; on Linux it needs CAP_NET_BIND_SERVICE or
    # net.ipv4.ip_unprivileged_port_start <= 443.
    # ============================================================
    kill "$PEBBLE_PID" 2>/dev/null || true; wait "$PEBBLE_PID" 2>/dev/null || true
    sed -e 's/"tlsPort": 8080/"tlsPort": 443/' "$ACME_DIR/pebble.json" >"$ACME_DIR/pebble443.json"
    PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=0 \
        pebble -config "$ACME_DIR/pebble443.json" -dnsserver 127.0.0.1:8053 >"$ACME_DIR/pebble443.log" 2>&1 &
    PEBBLE_PID=$!
    for _ in $(seq 1 40); do
        curl -s --max-time .3 --cacert "$PEBBLE_SRC/test/certs/pebble.minica.pem" \
            https://127.0.0.1:14000/dir >/dev/null 2>&1 && break
        sleep 0.25
    done
    # Pebble creates a new root at every start.
    curl -s --cacert "$PEBBLE_SRC/test/certs/pebble.minica.pem" https://127.0.0.1:15000/roots/0 >"$ACME_DIR/root443.pem" || true
    cat "$PEBBLE_SRC/test/certs/pebble.minica.pem" "$ACME_DIR/root443.pem" >"$ACME_DIR/trust443.pem"

    WIZ_DIR="$ACME_DIR/wizard"
    # wizard_config writes the wizard test config; $1 is the trial CA.
    wizard_config() {
        {
            echo "data_dir = \"$WIZ_DIR\""
            echo 'log_level = "debug"'
            echo 'read_header_timeout = "2s"'
            echo 'acme_ca = "https://127.0.0.1:14000/dir"'
            echo "acme_trial_ca = \"$1\""
            echo "acme_ca_root = \"$ACME_DIR/trust443.pem\""
        } >"$CONFIG_FILE"
    }
    # wizard_run submits domain $1 and polls the progress fragment until it
    # stops polling (at most 90 s); the last fragment is in $TEST_DIR/progress.html.
    wizard_run() {
        WIZ_POST=$(agui -o /dev/null -w '%{http_code} %{redirect_url}' -X POST "$WEBGUI_URL/admin/domain" -d "domain=$1" || true)
        for _ in $(seq 1 180); do
            agui -D "$TEST_DIR/progress.hdr" -o "$TEST_DIR/progress.html" "$WEBGUI_URL/admin/domain/progress" || true
            grep -q 'hx-trigger="every 1s"' "$TEST_DIR/progress.html" || break
            sleep 0.5
        done
    }
    https443() {
        curl -s -o /dev/null -D "$HDR_F" -w '%{http_code}' --resolve "$ACME_DOMAIN:443:127.0.0.1" \
            --cacert "$ACME_DIR/trust443.pem" -u admin:adminpass123 -X PROPFIND -H 'Depth: 0' "https://$ACME_DOMAIN/" || true
    }
    orders443() { grep -c 'Added order' "$ACME_DIR/pebble443.log" || true; }

    # ---- C137: a failed order keeps the old listener -------------------------
    wizard_config "https://127.0.0.1:1/dir"
    ADMIN_CA="$WIZ_DIR/certs/admin-selfsigned.crt"; TOTP_DB="$WIZ_DIR/webdavgo.db"
    start_server
    WIZ_TOKEN=$(grep -o 'https://localhost:8443/setup?token=[0-9a-f]*' "$STDOUT_FILE" | head -1 | sed 's/.*token=//')
    enrol "$(cookie_of "$(gui -D - -o /dev/null -X POST "$WEBGUI_URL/setup?token=$WIZ_TOKEN" \
        -d "username=admin&password=adminpass123&password_confirm=adminpass123")")"
    ADMIN_SECRET="$ENROL_SECRET"; ADMIN_STEP="$ENROL_STEP"
    SESSION=$(cookie_of "$ENROL_HDRS"); CSRF=$(csrf_of "$SESSION" /admin/users)
    C137_NEXT=$(grep -c 'href="/admin/domain" hx-boost="false">I have saved them' "$TEST_DIR/recovery.html" || true)
    C137_PAGE=$(agui -o /dev/null -w '%{http_code}' "$WEBGUI_URL/admin/domain" || true)
    curl -s -o /dev/null -u admin:adminpass123 -X PUT --data-binary 'before' "$V4_URL/wiz.txt"
    wizard_run "$ACME_DOMAIN"
    C137_MSG=$(grep -c 'class="error">Cannot talk to the certificate authority (https://127.0.0.1:1/dir)' "$TEST_DIR/progress.html" || true)
    C137_DETAILS=$(grep -c '<details><summary>Details</summary>' "$TEST_DIR/progress.html" || true)
    C137_OLD=$(status_of admin:adminpass123)
    C137_443=$(curl -s -o /dev/null --max-time 2 -w '%{http_code}' -k "https://127.0.0.1:443/" || true)
    C137_DB=$(sqlite3 "$WIZ_DIR/webdavgo.db" "SELECT COUNT(*) FROM settings WHERE key IN ('tls_mode','domain');" 2>/dev/null || echo 1)
    C137_ORDERS=$(orders443)
    if [[ "$C137_NEXT" == "1" && "$C137_PAGE" == "200" && "$WIZ_POST" == "303 $WEBGUI_URL/admin/domain" && "$C137_MSG" == "1" \
          && "$C137_DETAILS" -ge 1 && "$C137_OLD" == "207" && "$C137_443" == "000" && "$C137_DB" == "0" && "$C137_ORDERS" == "0" ]]; then
        check "C137: setup leads to Domain & certificate; an unreachable trial CA fails in plain English with details, closes :443, keeps WebDAV on :8080, stores nothing" pass
    else
        check "C137: wizard failure (next_link=$C137_NEXT page=$C137_PAGE post=[$WIZ_POST] msg=$C137_MSG details=$C137_DETAILS old=$C137_OLD port443=$C137_443 db=$C137_DB orders=$C137_ORDERS)" fail
    fi
    stop_server

    # ---- C138: trial + real order, then WebDAV moves to :443 in-process -----
    wizard_config "https://127.0.0.1:14000/dir"
    start_server
    login_admin
    dd if=/dev/zero of="$TEST_DIR/wiz16.bin" bs=1048576 count=16 2>/dev/null
    curl -s -o /dev/null -u admin:adminpass123 -X PUT --data-binary @"$TEST_DIR/wiz16.bin" "$V4_URL/wiz16.bin"
    # A download that runs across the switch must finish on the old listener.
    curl -s -u admin:adminpass123 --limit-rate 1M -o /dev/null -w '%{size_download}' "$V4_URL/wiz16.bin" >"$TEST_DIR/inflight.txt" &
    C138_DL=$!
    sleep 1
    wizard_run "$ACME_DOMAIN"
    C138_OK=$(grep -c 'class="success">Done.' "$TEST_DIR/progress.html" || true)
    C138_REDIRECT=$(grep -ci '^hx-redirect: /admin/domain/done' "$TEST_DIR/progress.hdr" || true)
    C138_STATUS=$(https443)
    C138_HSTS=$(hdr Strict-Transport-Security)
    C138_PLAIN=$(curl -s -o /dev/null --max-time 2 -w '%{http_code}' "$V4_URL/" || true)
    wait "$C138_DL" || true
    C138_INFLIGHT=$(cat "$TEST_DIR/inflight.txt")
    C138_ORDERS=$(orders443)
    C138_TRIAL=$(grep -c "$LOGMSG"'"trial certificate obtained"' "$STDOUT_FILE" || true)
    C138_DB=$(sqlite3 "$WIZ_DIR/webdavgo.db" "SELECT group_concat(key || '=' || value, ' ') FROM (SELECT * FROM settings WHERE key IN ('tls_mode','domain','webdav_addr') ORDER BY key);" 2>/dev/null || true)
    C138_CLOSED=$(grep -c "$LOGMSG"'"old webdav listener closed" addr=:8080' "$STDOUT_FILE" || true)
    if [[ "$C138_OK" == "1" && "$C138_REDIRECT" == "1" && "$C138_STATUS" == "207" && "$C138_HSTS" == "max-age=31536000; includeSubDomains" \
          && "$C138_PLAIN" == "000" && "$C138_INFLIGHT" == "16777216" && "$C138_ORDERS" == "2" && "$C138_TRIAL" == "1" \
          && "$C138_DB" == "domain=$ACME_DOMAIN tls_mode=acme webdav_addr=:443" && "$C138_CLOSED" == "1" ]]; then
        check "C138: trial order then real order (2 at Pebble); WebDAV switches to HTTPS on :443 without restart, the :8080 download in flight finishes (16 MiB), :8080 closes; settings stored" pass
    else
        check "C138: wizard success (done=$C138_OK hx_redirect=$C138_REDIRECT https=$C138_STATUS hsts=$C138_HSTS plain=$C138_PLAIN inflight=$C138_INFLIGHT orders=$C138_ORDERS trial=$C138_TRIAL db=[$C138_DB] old_closed=$C138_CLOSED)" fail
    fi

    # ---- C139: finish page and status page show the certificate -------------
    C139_DONE=$(agui "$WEBGUI_URL/admin/domain/done" || true)
    C139_URL=$(echo "$C139_DONE" | grep -c "href=\"https://$ACME_DOMAIN/\">https://$ACME_DOMAIN/</a>" || true)
    C139_QR=$(echo "$C139_DONE" | grep -c 'class="qr"' || true)
    C139_ISSUER=$(echo "$C139_DONE" | grep -c '<th>Issuer</th><td>Pebble' || true)
    C139_NEXT=$(echo "$C139_DONE" | grep -cE '<th>Next renewal</th><td>20[0-9]{2}-' || true)
    C139_STATUS=$(agui "$WEBGUI_URL/admin/status" || true)
    C139_ST_N=$(echo "$C139_STATUS" | grep -c -e '<th>Issuer</th><td>Pebble' -e '<th>Next renewal</th><td>20' -e '<th>Last error</th><td>none' || true)
    C139_SRC=$(echo "$C139_STATUS" | grep -cF "<th>domain</th><td><code>$ACME_DOMAIN</code> <span class=\"muted small source\">database (Domain &amp; certificate page)</span>" || true)
    if [[ "$C139_URL" == "1" && "$C139_QR" == "0" && "$C139_ISSUER" == "1" && "$C139_NEXT" == "1" && "$C139_ST_N" == "3" && "$C139_SRC" == "1" ]]; then
        check "C139: finish page shows https://$ACME_DOMAIN/ without a QR code, issuer and next renewal; status page shows issuer, next renewal, last error and the domain's source" pass
    else
        check "C139: finish/status (url=$C139_URL qr=$C139_QR issuer=$C139_ISSUER next=$C139_NEXT status_rows=$C139_ST_N/3 source=$C139_SRC)" fail
    fi

    # ---- C140: a restart comes up with TLS on :443 from the database --------
    stop_server
    start_server
    C140_READY=$(wait_cert && echo yes || echo no)
    C140_STATUS=$(https443)
    C140_ORDERS=$(orders443)
    C140_LISTEN=$(grep -c "$LOGMSG"'"webdav listener" addr=\[::\]:443 tls=true' "$STDOUT_FILE" || true)
    if [[ "$C140_READY" == "yes" && "$C140_STATUS" == "207" && "$C140_ORDERS" == "2" && "$C140_LISTEN" == "1" ]]; then
        check "C140: restart reads tls_mode/domain/webdav_addr from the database: TLS on :443, stored certificate, no new order" pass
    else
        check "C140: restart after wizard (ready=$C140_READY https=$C140_STATUS orders=$C140_ORDERS listener=$C140_LISTEN)" fail
    fi
    stop_server
fi

# ============================================================
# CLI commands and the database schema; unit hardening (C141–C143).
# reset-totp and setup-info never migrate: only the service does. They run
# against a copy of the test database whose user_version is set off by one.
# ============================================================
SC_DIR="$TEST_DIR/schema"
SC_CFG="$TEST_DIR/schema.toml"
mkdir -p "$SC_DIR/certs"
cp "$TEST_DB" "$SC_DIR/webdavgo.db"
[[ -f "$TEST_DB-wal" ]] && cp "$TEST_DB-wal" "$SC_DIR/webdavgo.db-wal"
cp "$DATA_DIR/certs/admin-selfsigned.crt" "$SC_DIR/certs/"
printf 'data_dir = "%s"\n' "$SC_DIR" >"$SC_CFG"
SC_TARGET=$(jq -r '.target_version' cmd/webdavgo/migrations.json)
sc_version() { sqlite3 "$SC_DIR/webdavgo.db" "PRAGMA user_version;" 2>/dev/null || echo -1; }
sc_state() {
    echo "$(sc_version) $(sqlite3 "$SC_DIR/webdavgo.db" "SELECT (SELECT COUNT(*) FROM totp) || '/' || (SELECT COUNT(*) FROM recovery_codes) || '/' || (SELECT COUNT(*) FROM settings);" 2>/dev/null) $(ls "$SC_DIR" | grep -c 'bak-' || true)"
}
# sc_run sets the schema to version $1, runs the CLI command $2.. and
# prints "exit message-count state-unchanged".
sc_run() {
    local v="$1" msg; shift
    sqlite3 "$SC_DIR/webdavgo.db" "PRAGMA user_version = $v;"
    local before after code=0
    before=$(sc_state)
    (cd "$TEST_DIR" && ./webdavgo "$@") >"$TEST_DIR/sc_out.txt" 2>&1 || code=$?
    after=$(sc_state)
    if (( v < SC_TARGET )); then
        msg="db schema version $v is older than binary target $SC_TARGET; restart the service first so it migrates the database"
    else
        msg="db schema version $v is newer than binary target $SC_TARGET; refusing to start"
    fi
    echo "$code $(grep -cF "$msg" "$TEST_DIR/sc_out.txt" || true) $([[ "$before" == "$after" ]] && echo same || echo "changed[$before→$after]")"
}

# ---- C141: reset-totp refuses a schema of another version, migrates nothing --
C141_OLD=$(sc_run $((SC_TARGET - 1)) reset-totp -config "$SC_CFG" admin)
C141_NEW=$(sc_run $((SC_TARGET + 1)) reset-totp -config "$SC_CFG" admin)
if [[ "$C141_OLD" == "1 1 same" && "$C141_NEW" == "1 1 same" ]]; then
    check "C141: reset-totp on schema v$((SC_TARGET - 1)) → 'restart the service first so it migrates', on v$((SC_TARGET + 1)) → 'newer than binary target'; exit 1, version, rows and backups untouched" pass
else
    check "C141: reset-totp schema check (older=[$C141_OLD] newer=[$C141_NEW], want [1 1 same])" fail
fi

# ---- C142: setup-info the same; at the right version it works ---------------
C142_OLD=$(sc_run $((SC_TARGET - 1)) setup-info -config "$SC_CFG")
C142_NEW=$(sc_run $((SC_TARGET + 1)) setup-info -config "$SC_CFG")
sqlite3 "$SC_DIR/webdavgo.db" "PRAGMA user_version = $SC_TARGET;"
C142_OK=0; (cd "$TEST_DIR" && ./webdavgo setup-info -config "$SC_CFG") >"$TEST_DIR/sc_ok.txt" 2>&1 || C142_OK=$?
C142_DONE=$(grep -c 'Setup is complete' "$TEST_DIR/sc_ok.txt" || true)
if [[ "$C142_OLD" == "1 1 same" && "$C142_NEW" == "1 1 same" && "$C142_OK" == "0" && "$C142_DONE" == "1" ]]; then
    check "C142: setup-info on schema v$((SC_TARGET - 1))/v$((SC_TARGET + 1)) → refused with the same messages, nothing migrated; on v$SC_TARGET → works" pass
else
    check "C142: setup-info schema check (older=[$C142_OLD] newer=[$C142_NEW] matching_exit=$C142_OK done=$C142_DONE)" fail
fi

# ---- C143: the unit carries the additional hardening ------------------------
"$TEST_DIR/webdavgo" install -root "$TEST_DIR/sysroot2" >/dev/null 2>&1 || true
C143_N=0
for line in 'UMask=0027' 'RestrictSUIDSGID=yes' 'RestrictRealtime=yes' 'ProtectClock=yes' 'ProtectHostname=yes' \
    'ProtectProc=invisible' 'SystemCallFilter=@system-service' 'SystemCallErrorNumber=EPERM'; do
    grep -qxF "$line" "$TEST_DIR/sysroot2/etc/systemd/system/webdavgo.service" && C143_N=$((C143_N + 1))
done
if [[ "$C143_N" == "8" ]]; then
    check "C143: install -root unit has UMask=0027, RestrictSUIDSGID, RestrictRealtime, ProtectClock, ProtectHostname, ProtectProc=invisible, SystemCallFilter=@system-service, SystemCallErrorNumber=EPERM" pass
else
    check "C143: unit hardening ($C143_N of 8 directives)" fail
fi

# ============================================================
# Log files (C148–C150): access_log and server_log, reopen on SIGUSR1 the
# way logrotate triggers it, and a log file that cannot be opened. A data
# directory of their own: after the domain wizard criteria the test
# database may hold webdav_addr = :443. log_level = "debug" so that the
# unauthenticated requests (401, Debug) produce request lines.
# ============================================================
LOG_DIR="$TEST_DIR/logs"
LOG_DATA="$TEST_DIR/logstore"
mkdir -p "$LOG_DIR"
# log_config writes the test config with access_log $1 and server_log $2.
log_config() {
    printf 'data_dir = "%s"\nlog_level = "debug"\naccess_log = "%s"\nserver_log = "%s"\n' \
        "$LOG_DATA" "$1" "$2" >"$CONFIG_FILE"
}
# msg_lines prints how many log lines of file $1 have the message request
# (with $2 = request) or any other message (with $2 = other).
msg_lines() {
    if [[ "$2" == request ]]; then grep -c "${LOGMSG}request " "$1" 2>/dev/null || true
    else grep "$LOG" "$1" 2>/dev/null | grep -vc "${LOGMSG}request " || true; fi
}

# ---- C148: request lines go to access_log, everything else to server_log ----
ACCESS_LOG="$LOG_DIR/access.log"
SERVER_LOG="$LOG_DIR/webdavgo.log"
log_config "$ACCESS_LOG" "$SERVER_LOG"
start_server
curl -s -o /dev/null -X PROPFIND "$WEBDAV_URL/c144-path"
sleep 0.3
C148_ACC_REQ=$(msg_lines "$ACCESS_LOG" request)
C148_ACC_OTHER=$(msg_lines "$ACCESS_LOG" other)
C148_PATH=$(grep -c 'path=/c144-path' "$ACCESS_LOG" || true)
C148_SRV_REQ=$(msg_lines "$SERVER_LOG" request)
C148_SRV_START=$(grep -c -e "${LOGMSG}startup " -e "${LOGMSG}config .*access_log=$ACCESS_LOG server_log=$SERVER_LOG" "$SERVER_LOG" || true)
# stdout and stderr (both in STDOUT_FILE) get no record: nothing is logged
# before the config is loaded, and there is no Error.
C148_STDOUT=$(grep -c "$LOG" "$STDOUT_FILE" || true)
C148_MODES="$(mode_of "$ACCESS_LOG") $(mode_of "$SERVER_LOG")"
# CLI commands log to the terminal and never open the service's files.
printf 'data_dir = "%s"\naccess_log = "%s"\nserver_log = "%s"\n' "$LOG_DATA" "$LOG_DIR/cli-access.log" "$LOG_DIR/cli-server.log" >"$TEST_DIR/cli-logs.toml"
(cd "$TEST_DIR" && ./webdavgo setup-info -config "$TEST_DIR/cli-logs.toml") >"$TEST_DIR/cli-logs.txt" 2>&1 || true
C148_CLI=$(ls "$LOG_DIR" | grep -c '^cli-' || true)
C148_CLI_OUT=$(grep -c -e 'SETUP' -e 'Setup' -e 'setup' "$TEST_DIR/cli-logs.txt" || true)
if [[ "$C148_ACC_REQ" -ge 1 && "$C148_ACC_OTHER" == "0" && "$C148_PATH" == "1" && "$C148_SRV_REQ" == "0" \
      && "$C148_SRV_START" == "2" && "$C148_STDOUT" == "0" && "$C148_MODES" == "640 640" \
      && "$C148_CLI" == "0" && "$C148_CLI_OUT" -ge 1 ]]; then
    check "C148: access_log gets only msg=request lines (Debug too), server_log startup/config and no request line, stdout/stderr no record, files 0640; setup-info leaves the configured files alone" pass
else
    check "C148: log routing (access: request=$C148_ACC_REQ other=$C148_ACC_OTHER path=$C148_PATH server: request=$C148_SRV_REQ startup+config=$C148_SRV_START stdout_records=$C148_STDOUT modes=[$C148_MODES] cli_files=$C148_CLI cli_out=$C148_CLI_OUT)" fail
fi

# ---- C149: SIGUSR1 after mv reopens both files, nothing lost ---------------
curl -s -o /dev/null -X PROPFIND "$WEBDAV_URL/c145-before"
sleep 0.2
mv "$ACCESS_LOG" "$ACCESS_LOG.1"
mv "$SERVER_LOG" "$SERVER_LOG.1"
# Between mv and the signal the server still writes to the moved files.
curl -s -o /dev/null -X PROPFIND "$WEBDAV_URL/c145-between"
kill -USR1 "$SERVER_PID"
sleep 0.3
curl -s -o /dev/null -X PROPFIND "$WEBDAV_URL/c145-after"
sleep 0.3
C149_ALIVE=$(kill -0 "$SERVER_PID" 2>/dev/null && echo yes || echo no)
C149_OLD=$(grep -c -e 'path=/c145-before' -e 'path=/c145-between' "$ACCESS_LOG.1" || true)
C149_NEW=$(grep -c 'path=/c145-after' "$ACCESS_LOG" 2>/dev/null || true)
C149_NEW_OLD=$(grep -c -e 'path=/c145-before' -e 'path=/c145-between' "$ACCESS_LOG" 2>/dev/null || true)
C149_OLD_NEW=$(grep -c 'path=/c145-after' "$ACCESS_LOG.1" || true)
C149_REOPENED=$(grep -c "$LOGMSG"'"log files reopened" ' "$SERVER_LOG" 2>/dev/null || true)
C149_SRV_OLD=$(grep -c "${LOGMSG}startup " "$SERVER_LOG.1" || true)
C149_MODE=$(mode_of "$ACCESS_LOG")
stop_server
C149_SHUTDOWN=$(grep -c "$LOGMSG"'"shutdown complete"' "$SERVER_LOG" 2>/dev/null || true)
if [[ "$C149_ALIVE" == "yes" && "$C149_OLD" == "2" && "$C149_NEW" == "1" && "$C149_NEW_OLD" == "0" && "$C149_OLD_NEW" == "0" \
      && "$C149_REOPENED" == "1" && "$C149_SRV_OLD" == "1" && "$C149_MODE" == "640" && "$C149_SHUTDOWN" == "1" ]]; then
    check "C149: mv + SIGUSR1 → server keeps running, lines up to the signal in the moved files, later ones in new 0640 files, 'log files reopened' and shutdown in the new server_log" pass
else
    check "C149: reopen (alive=$C149_ALIVE old=$C149_OLD/2 new=$C149_NEW new_has_old=$C149_NEW_OLD old_has_new=$C149_OLD_NEW reopened=$C149_REOPENED startup_in_old=$C149_SRV_OLD mode=$C149_MODE shutdown=$C149_SHUTDOWN)" fail
fi

# ---- C150: a log file that cannot be opened stops the start ---------------
# run_bounded runs the server in the foreground with stdout in $1 and
# stderr in $2 and prints its exit code; a server that starts anyway is
# killed after 5 s (no timeout(1) on macOS) and reported as "running".
run_bounded() {
    (cd "$TEST_DIR" && exec ./webdavgo -config "$CONFIG_FILE") >"$1" 2>"$2" &
    local pid=$! i
    for i in $(seq 1 20); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.25
    done
    if kill -0 "$pid" 2>/dev/null; then kill "$pid"; wait "$pid" 2>/dev/null || true; echo running; return; fi
    local code=0; wait "$pid" || code=$?; echo "$code"
}
log_config "$LOG_DIR/missing-dir/access.log" "$SERVER_LOG"
C150_EXIT=$(run_bounded "$TEST_DIR/c146-out.txt" "$TEST_DIR/c146-err.txt")
C150_ERR=$(grep -c "$LOGMSG"'"cannot open log file".*missing-dir/access.log' "$TEST_DIR/c146-err.txt" || true)
C150_OUT=$(grep -c "$LOG" "$TEST_DIR/c146-out.txt" || true)
log_config "logs/access.log" ""
C150_REL=$(run_bounded "$TEST_DIR/c146-rel-out.txt" "$TEST_DIR/c146-rel-err.txt")
C150_REL_MSG=$(cat "$TEST_DIR/c146-rel-out.txt" "$TEST_DIR/c146-rel-err.txt" | grep -c 'access_log \\"logs/access.log\\": must be an absolute path' || true)
if [[ "$C150_EXIT" != "0" && "$C150_EXIT" != "running" && "$C150_ERR" == "1" && "$C150_OUT" == "0" \
      && "$C150_REL" != "0" && "$C150_REL" != "running" && "$C150_REL_MSG" == "1" ]]; then
    check "C150: unopenable access_log → error on stderr, nothing on stdout, exit non-zero (no silent fallback); relative access_log → refused as not absolute" pass
else
    check "C150: log file errors (exit=$C150_EXIT stderr_msg=$C150_ERR stdout_records=$C150_OUT relative_exit=$C150_REL relative_msg=$C150_REL_MSG)" fail
fi

# ---- summary ----------------------------------------------------------------
for id in $REMAINING; do echo "FAIL: $id: no such criterion"; ((FAIL++)) || true; done
summary
