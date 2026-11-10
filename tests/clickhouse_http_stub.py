#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local HTTP stand-in for omclickhouse tests.

Each POST is appended to the record file as one JSON object. A body of
exactly ``SELECT 1`` is a health check and always returns 200. Inserts
return 200 unless --reject-inserts still has remaining failures, in which
case the response is HTTP 400 with the body ``BAD REQUEST``. Gzip request
bodies are stored uncompressed. Each response closes the connection so the
single-threaded server can accept the next one. The listen port is written
only after the socket is bound.
"""

import argparse
import json
import os
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer


class Recorder(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def _send(self, status, payload):
        body = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        # One request per connection. libcurl keeps the insert connection open,
        # and this single-threaded server would otherwise never accept the
        # health check on the next connection.
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _record(self, kind, status, body):
        rec = {
            "kind": kind,
            "status": status,
            "path": self.path,
            "content_type": self.headers.get("Content-Type", ""),
            "content_encoding": self.headers.get("Content-Encoding", ""),
            "body": body,
        }
        fp = self.server.record_fp
        fp.write(json.dumps(rec, ensure_ascii=True) + "\n")
        fp.flush()
        os.fsync(fp.fileno())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length)
        encoding = (self.headers.get("Content-Encoding") or "").lower()
        if encoding == "gzip":
            try:
                raw = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
            except zlib.error as exc:
                self._record("insert", 500, "gzip decode failed: {0}".format(exc))
                self._send(500, b"gzip decode failed")
                return
        text = raw.decode("utf-8", "replace")
        if text == "SELECT 1":
            self._record("health", 200, text)
            self._send(200, b"")
            return
        if self.server.rejected < self.server.reject_inserts:
            self.server.rejected += 1
            self._record("insert", 400, text)
            self._send(400, b"BAD REQUEST")
            return
        self._record("insert", 200, text)
        self._send(200, b"")


def main():
    parser = argparse.ArgumentParser(description="omclickhouse HTTP stub")
    parser.add_argument("--interface", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--reject-inserts", type=int, default=0)
    args = parser.parse_args()

    server = HTTPServer((args.interface, args.port), Recorder)
    server.reject_inserts = args.reject_inserts
    server.rejected = 0
    server.record_fp = open(args.record, "w", encoding="utf-8")
    port = server.server_address[1]
    with open(args.port_file, "w", encoding="utf-8") as port_fp:
        port_fp.write("{0}\n".format(port))
        port_fp.flush()
        os.fsync(port_fp.fileno())
    try:
        server.serve_forever()
    finally:
        server.record_fp.close()


if __name__ == "__main__":
    main()
