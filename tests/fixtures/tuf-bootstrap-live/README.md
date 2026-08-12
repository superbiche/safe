Minimal offline TUF mirror fixture for `safe audit binary-audit verify tuf-bootstrap` live tests.

- `root.json` is a long-lived test root generated for this repo.
- `mirror/` contains only the versioned metadata and hashed target blobs that `cosign initialize` actually fetches.
- `trust/` contains the plain local targets the verifier compares after bootstrap.
- The Sigstore target payloads were captured from a working bootstrap snapshot so Cosign can parse them without network access.
