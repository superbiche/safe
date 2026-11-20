#!/usr/bin/env python3
"""A registry and an advisory service for the cooldown's tests, on 127.0.0.1.

usage: fake_registry.py <dir> <port-file> <log-file>

GET /<name>      the packument <dir>/packuments/<name>.json (a scoped name is stored with %2F), 404 when absent
POST /v1/query   <dir>/osv.json when it exists, else {}
Every request is appended to the log, one line: `GET /name` or `POST /v1/query`. Nothing else is served.
"""
import http.server
import os
import sys


def main():
    root, port_file, log_file = sys.argv[1:4]

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _log(self, line):
            with open(log_file, "a") as handle:
                handle.write(line + "\n")

        def _send(self, status, body):
            data = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._log("GET " + self.path)
            name = self.path[1:]
            if "/" in name.replace("%2F", "") or ".." in name or name == "":
                return self._send(404, "{}")
            path = os.path.join(root, "packuments", name + ".json")
            if not os.path.isfile(path):
                return self._send(404, "{}")
            with open(path) as handle:
                self._send(200, handle.read())

        def do_POST(self):
            self._log("POST " + self.path)
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            if self.path != "/v1/query":
                return self._send(404, "{}")
            path = os.path.join(root, "osv.json")
            body = "{}"
            if os.path.isfile(path):
                with open(path) as handle:
                    body = handle.read()
            self._send(200, body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(port_file, "w") as handle:
        handle.write(str(server.server_address[1]))
    server.serve_forever()


main()
