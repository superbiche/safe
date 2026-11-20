#!/usr/bin/env python3
"""A registry for the cooldown's tests, on 127.0.0.1.

usage: fake_registry.py <dir> <port-file> <log-file>

GET /<name>   the packument <dir>/packuments/<name>.json, served as it is (a scoped name is stored with %2F), 404 when absent;
              <name>.status holds a status code to answer instead; <name>.redirect a location to redirect (301) to
Every request is appended to the log, one line: `GET /name`. Nothing else is served.
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
            status = os.path.join(root, "packuments", name + ".status")
            if os.path.isfile(status):
                with open(status) as handle:
                    return self._send(int(handle.read().strip()), "{}")
            redirect = os.path.join(root, "packuments", name + ".redirect")
            if os.path.isfile(redirect):
                with open(redirect) as handle:
                    self.send_response(301)
                    self.send_header("Location", handle.read().strip())
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            path = os.path.join(root, "packuments", name + ".json")
            if not os.path.isfile(path):
                return self._send(404, "{}")
            with open(path) as handle:
                self._send(200, handle.read())

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    with open(port_file, "w") as handle:
        handle.write(str(server.server_address[1]))
    server.serve_forever()


main()
