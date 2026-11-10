#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# JSONEachRow inserts put the query in the URL, post newline-delimited JSON,
# and can gzip that body with async_insert enabled. A bad table name or a
# SQL-escaped template is rejected at configuration time. At runtime the stub
# rejects the first batch with HTTP 400. The action must suspend and retry.
# The messages have already left the main queue during that retry, so the
# test waits until the stub has accepted every object, then shuts down.
# action.resumeInterval="1" is the configured retry delay. A suspended
# batch is retried by the core, which may post the rows one at a time, and
# the worker may commit before every injected message has been queued. The
# accepted bodies together are exactly the injected objects. Every rejected
# row is present again in those accepted bodies. The error file is created
# mode 0600 and records the ClickHouse reply without the event body.
# The stub writes its port file after bind. The EXIT trap kills it.
# This file is part of the rsyslog project, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
require_plugin omclickhouse
check_command_available python3

run_n1() {
    name="$1"
    needle="$2"
    expect_ok="$3"
    ../tools/rsyslogd -C -N1 -f "${TESTCONF_NM}.conf" -M"$RSYSLOG_MODDIR" \
        > "$RSYSLOG_DYNNAME.$name.log" 2>&1
    rc=$?
    if [ "$expect_ok" -eq 1 ]; then
        if [ "$rc" -ne 0 ]; then
            printf 'FAIL: %s config was rejected\n' "$name"
            cat "$RSYSLOG_DYNNAME.$name.log"
            error_exit 1
        fi
        content_check "End of config validation run" "$RSYSLOG_DYNNAME.$name.log"
    else
        if [ "$rc" -eq 0 ]; then
            printf 'FAIL: %s config was accepted\n' "$name"
            cat "$RSYSLOG_DYNNAME.$name.log"
            error_exit 1
        fi
        content_check "$needle" "$RSYSLOG_DYNNAME.$name.log"
    fi
}

json_module='module(load="../plugins/omclickhouse/.libs/omclickhouse")
template(name="chjson" type="string"
         string="{\"id\":\"%msg:F,58:2%\",\"message\":\"%msg%\"}")
template(name="chsql" type="string" option.stdsql="on"
         string="{\"id\":\"%msg:F,58:2%\",\"message\":\"%msg%\"}")
'

generate_conf
add_conf "$json_module"
add_conf '
action(type="omclickhouse" server="127.0.0.1" usehttps="off"
       format="jsoneachrow" table="bad name" template="chjson")
'
run_n1 bad-table "table must be" 0

generate_conf
add_conf "$json_module"
add_conf '
action(type="omclickhouse" server="127.0.0.1" usehttps="off"
       format="jsoneachrow" table="a..b" template="chjson")
'
run_n1 two-dots "table must be" 0

generate_conf
add_conf "$json_module"
add_conf '
action(type="omclickhouse" server="127.0.0.1" usehttps="off"
       format="jsoneachrow" template="chjson")
'
run_n1 missing-table "table must be" 0

generate_conf
add_conf "$json_module"
add_conf '
action(type="omclickhouse" server="127.0.0.1" usehttps="off"
       format="values" table="rsyslog.events" template="chjson")
'
run_n1 table-with-values "only valid with format jsoneachrow" 0

generate_conf
add_conf "$json_module"
add_conf '
action(type="omclickhouse" server="127.0.0.1" usehttps="off"
       format="jsoneachrow" table="rsyslog.events" template="chsql")
'
run_n1 stdsql "option.stdsql" 0

generate_conf
add_conf "$json_module"
add_conf '
action(type="omclickhouse" server="127.0.0.1" usehttps="off"
       format="nope" template="chjson")
'
run_n1 bad-format "format must be values or jsoneachrow" 0

export NUMMESSAGES=3
port_file="${RSYSLOG_DYNNAME}.ch.port"
record="${RSYSLOG_DYNNAME}.ch.jsonl"
errfile="${RSYSLOG_DYNNAME}.ch.err"
stub_pid=

cleanup_stub() {
    if [ -n "${stub_pid}" ] && kill -0 "$stub_pid" 2>/dev/null; then
        kill "$stub_pid" 2>/dev/null || true
        wait "$stub_pid" 2>/dev/null || true
    fi
}
trap cleanup_stub EXIT

python3 "${srcdir}/clickhouse_http_stub.py" \
    --port-file "$port_file" \
    --record "$record" \
    --reject-inserts 1 &
stub_pid=$!
wait_file_exists "$port_file"
port=$(cat "$port_file")

generate_conf
add_conf "$json_module"
add_conf '
:syslogtag, contains, "tag" action(type="omclickhouse"
    server="127.0.0.1"
    port="'"$port"'"
    usehttps="off"
    format="jsoneachrow"
    table="rsyslog.events"
    template="chjson"
    asyncinsert="on"
    compression="gzip"
    errorfile="'"$errfile"'"
    action.resumeInterval="1")
action(type="omfile" file="'"$RSYSLOG_OUT_LOG"'")
'

count_accepted_objects() {
    python3 - "$record" <<'PY'
import json
import os
import sys

n = 0
path = sys.argv[1]
if os.path.exists(path):
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("kind") == "insert" and rec.get("status") == 200:
                n += len([part for part in rec.get("body", "").split("\n") if part])
print(n)
PY
}

startup
injectmsg
wait_file_lines --count-function count_accepted_objects "$record" "$NUMMESSAGES" 30
shutdown_when_empty
wait_shutdown

content_check "omclickhouse: ClickHouse request failed with HTTP status 400: BAD REQUEST"

python3 - "$record" "$errfile" <<'PY' || error_exit 1
import json
import os
import stat
import sys

record, errfile = sys.argv[1], sys.argv[2]
recs = [json.loads(line) for line in open(record, encoding="utf-8") if line.strip()]
expected = [
    '{"id":"00000000","message":" msgnum:00000000:"}',
    '{"id":"00000001","message":" msgnum:00000001:"}',
    '{"id":"00000002","message":" msgnum:00000002:"}',
]
inserts = [rec for rec in recs if rec["kind"] == "insert"]
failed = [rec for rec in inserts if rec["status"] == 400]
ok = [rec for rec in inserts if rec["status"] == 200]
other = [rec for rec in inserts if rec["status"] not in (200, 400)]
if other or len(failed) != 1:
    sys.stderr.write("unexpected insert records: {0}\n".format(json.dumps(inserts)))
    sys.exit(1)


def lines_of(body):
    return [line for line in body.split("\n") if line]


def check_insert(rec):
    path = rec["path"]
    for token in (
        "query=INSERT%20INTO%20rsyslog.events%20FORMAT%20JSONEachRow",
        "async_insert=1",
        "wait_for_async_insert=1",
        "enable_http_compression=1",
    ):
        if token not in path:
            sys.stderr.write("URL missing {0}: {1}\n".format(token, path))
            sys.exit(1)
    if "application/x-ndjson" not in rec["content_type"]:
        sys.stderr.write("content type: {0}\n".format(rec["content_type"]))
        sys.exit(1)
    if rec["content_encoding"].lower() != "gzip":
        sys.stderr.write("content encoding: {0}\n".format(rec["content_encoding"]))
        sys.exit(1)


for rec in failed + ok:
    check_insert(rec)
delivered = []
for rec in ok:
    delivered.extend(lines_of(rec["body"]))
rejected = []
for rec in failed:
    rejected.extend(lines_of(rec["body"]))
if delivered != expected or not rejected or any(line not in delivered for line in rejected):
    sys.stderr.write(
        "rejected {0}\naccepted {1}\n".format(json.dumps(rejected), json.dumps(delivered))
    )
    sys.exit(1)
mode = os.stat(errfile).st_mode & 0o777
if mode != 0o600:
    sys.stderr.write("error file mode {0:o}\n".format(mode))
    sys.exit(1)
err = open(errfile, encoding="utf-8").read()
if "BAD REQUEST" not in err or "msgnum" in err:
    sys.stderr.write("error file:\n{0}\n".format(err))
    sys.exit(1)
if "rsyslog.events" not in err:
    sys.stderr.write("error file lost the target URL:\n{0}\n".format(err))
    sys.exit(1)
PY

exit_test
