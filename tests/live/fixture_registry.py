#!/usr/bin/env python3
"""A static npm registry for the live no-script suite (ticket 1638): fixture packages whose scripts only write a marker line.

usage: fixture_registry.py <dir> <marker-file>

Builds <dir>/packages (tarballs) and <dir>/meta (packuments) from the fixtures below, then serves them on 127.0.0.1 on a free port,
printing the port on the first line of stdout. Nothing is fetched from anywhere; nothing is run.
"""
import base64, hashlib, http.server, io, json, os, socket, sys, tarfile, threading

root, marks = sys.argv[1], sys.argv[2]
MARKER_JS = ("const fs=require('fs'),e=process.env;fs.appendFileSync(%r,[e.npm_package_name,e.npm_lifecycle_event].join(' ')+'\\n');" % marks)
GYP = '{"targets":[{"target_name":"x","type":"none","actions":[{"action_name":"mark","inputs":[],"outputs":["o"],"action":["node","m.js"]}]}]}'
INSTALL = {"preinstall", "install", "postinstall"}


def package(name, version, scripts=None, extra=None, files=None, bundled=None):
    manifest = {"name": name, "version": version}
    if scripts:
        manifest["scripts"] = scripts
    if extra:
        manifest.update(extra)
    members = {"package.json": json.dumps(manifest), "m.js": MARKER_JS}
    members.update(files or {})
    for sub_name, sub_version, sub_scripts in (bundled or []):
        members["node_modules/%s/package.json" % sub_name] = json.dumps({"name": sub_name, "version": sub_version, "scripts": sub_scripts})
        members["node_modules/%s/m.js" % sub_name] = MARKER_JS
    return {"manifest": manifest, "members": members}


def has_install_script(p):
    scripts = p["manifest"].get("scripts", {})
    return bool(INSTALL & set(scripts)) or "binding.gyp" in p["members"]


S = lambda event: {event: "node m.js"}
FIXTURES = {
    "dep-install": [package("dep-install", "1.0.0", S("install"))],
    "dep-all": [package("dep-all", "1.0.0", {e: "node m.js" for e in ("preinstall", "install", "postinstall", "prepare", "prepublish")})],
    "dep-bin": [package("dep-bin", "1.0.0", S("postinstall"), {"bin": {"depbin": "cli.js"}}, {"cli.js": "#!/usr/bin/env node\n"})],
    "dep-gyp": [package("dep-gyp", "1.0.0", None, None, {"binding.gyp": GYP})],
    "dep-host": [package("dep-host", "1.0.0", S("postinstall"), {"dependencies": {"dep-bundled": "1.0.0"}, "bundleDependencies": ["dep-bundled"]}, None,
                         [("dep-bundled", "1.0.0", S("postinstall"))])],
    "dep-chain-a": [package("dep-chain-a", "1.0.0", S("postinstall"), {"dependencies": {"dep-chain-b": "1.0.0"}})],
    "dep-chain-b": [package("dep-chain-b", "1.0.0", S("postinstall"))],
    "dep-update": [package("dep-update", "1.0.0", S("install")), package("dep-update", "1.0.1", S("install"))],
    "dep-plain": [package("dep-plain", "1.0.0")],
}

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
port = sock.getsockname()[1]
sock.close()
base = "http://127.0.0.1:%d" % port
os.makedirs(root + "/packages", exist_ok=True)
os.makedirs(root + "/meta", exist_ok=True)
for name, versions in FIXTURES.items():
    doc = {"name": name, "versions": {}, "dist-tags": {"latest": versions[-1]["manifest"]["version"]}}
    for p in versions:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for member, text in sorted(p["members"].items()):
                data = text.encode()
                info = tarfile.TarInfo("package/" + member)
                info.size, info.mode = len(data), 0o755 if member == "cli.js" else 0o644
                tar.addfile(info, io.BytesIO(data))
        blob = buf.getvalue()
        fname = "%s-%s.tgz" % (name, p["manifest"]["version"])
        open(root + "/packages/" + fname, "wb").write(blob)
        version = dict(p["manifest"])
        version["dist"] = {"tarball": base + "/packages/" + fname, "integrity": "sha512-" + base64.b64encode(hashlib.sha512(blob).digest()).decode(),
                           "shasum": hashlib.sha1(blob).hexdigest()}
        if has_install_script(p):
            version["hasInstallScript"] = True
        doc["versions"][p["manifest"]["version"]] = version
    open(root + "/meta/" + name + ".json", "w").write(json.dumps(doc))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path.startswith("/packages/") and "/" not in path[len("/packages/"):]:
            file, kind = root + path, "application/octet-stream"
        elif path.count("/") == 1 and path != "/":
            file, kind = root + "/meta/" + path[1:] + ".json", "application/json"
        else:
            file = None
        if not file or not os.path.isfile(file):
            self.send_response(404); self.end_headers(); return
        data = open(file, "rb").read()
        self.send_response(200); self.send_header("Content-Type", kind); self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
print(port, flush=True)
server.serve_forever()
