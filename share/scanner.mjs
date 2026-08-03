// safe — Bun Security Scanner API adapter (version "1").
//
// Hosts implementing Bun's scanner contract (mise's embedded aube installer,
// bun >= 1.3) load this module and call scan({packages}) with the resolved
// direct+transitive registry package set after resolution and before tarball
// download. All policy lives in `safe-audit scanner-batch` — this file only
// transports the package list in and the advisory array out.
//
// Fail-closed by construction: any spawn failure, nonzero exit, timeout, or
// malformed payload THROWS, and the host's scanner contract turns that into
// a blocked install (aube: ERR_AUBE_SECURITY_SCANNER_FAILED). Never return
// [] on error — an empty array means "audited clean".

import { spawn } from "node:child_process";

// The host SIGKILLs the scanner process at 30s; killing safe-audit at 25s
// keeps the error legible (our stderr, not a silent SIGKILL). The env
// override exists for the test suite; values are clamped into (0, 25s].
const SAFE_AUDIT_TIMEOUT_MS = (() => {
  const raw = Number(process.env.SAFE_SCANNER_TIMEOUT_MS);
  return Number.isFinite(raw) && raw > 0 ? Math.min(raw, 25_000) : 25_000;
})();

function runSafeAudit(payload) {
  const bin = process.env.SAFE_AUDIT_BIN || "safe-audit";
  return new Promise((resolve, reject) => {
    const child = spawn(bin, ["scanner-batch"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    // A request-channel failure (EPIPE from a child that stopped reading)
    // means the package list may not have arrived in full — a zero exit
    // with valid output must still reject then, or a partial scan would
    // resolve as complete (PR#64 review F5).
    let stdinError = null;
    const timer = setTimeout(() => {
      settled = true;
      child.kill("SIGKILL");
      reject(new Error("safe-audit scanner-batch timed out after 25s"));
    }, SAFE_AUDIT_TIMEOUT_MS);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`safe-audit scanner-batch could not start: ${err.message}`));
    });
    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        reject(
          new Error(
            `safe-audit scanner-batch exited ${code}: ${stderr.trim() || "(no stderr)"}`,
          ),
        );
        return;
      }
      if (stdinError) {
        reject(
          new Error(
            `safe-audit scanner-batch did not receive the full package list: ${stdinError.message}`,
          ),
        );
        return;
      }
      resolve(stdout);
    });
    child.stdin.on("error", (err) => {
      stdinError = err;
    });
    child.stdin.end(payload);
  });
}

export const scanner = {
  version: "1",
  async scan({ packages }) {
    const payload = JSON.stringify({
      packages: packages.map((p) => ({ name: p.name, version: p.version })),
    });
    const out = await runSafeAudit(payload);
    let advisories;
    try {
      advisories = JSON.parse(out);
    } catch {
      throw new Error("safe-audit scanner-batch returned malformed JSON");
    }
    if (!Array.isArray(advisories)) {
      throw new Error("safe-audit scanner-batch returned a non-array payload");
    }
    return advisories;
  },
};
