# External Dependencies

`safe` does not install its scanner dependencies automatically.

This is intentional. A security tool cannot establish trust in the binaries it
uses by downloading and running upstream installers on the user's behalf.

`safe-audit` can use these external tools when they are already available:

| Tool | Purpose | Upstream |
| --- | --- | --- |
| OSV-Scanner | Vulnerability scanning through OSV data | <https://github.com/google/osv-scanner> |
| Syft | SBOM generation | <https://github.com/anchore/syft> |
| Grype | Vulnerability scanning from SBOMs and filesystems | <https://github.com/anchore/grype> |
| Socket CLI | Package behavioral and supply-chain signal | <https://docs.socket.dev/docs/socket-cli> |
| govulncheck | Go vulnerability checks | <https://github.com/golang/vuln> |
| cargo-audit | Rust vulnerability checks | <https://github.com/rustsec/rustsec/tree/main/cargo-audit> |
| pip-audit | Python vulnerability checks | <https://github.com/pypa/pip-audit> |

Install these tools through a channel you trust. That may be an OS package
manager, a pinned release asset, a source build you reviewed, or an internal
tooling image. The right choice depends on your threat model.

After installing tools, ask `safe` to detect them:

```bash
safe doctor
safe audit setup
```

To copy an already-audited scanner set to another machine, create a local bundle:

```bash
safe audit setup --create-bundle ./scanners.tar.gz
safe audit setup remote-a --bundle ./scanners.tar.gz
```

The bundle path is a transport mechanism, not a trust mechanism. Create bundles
only from machines and binaries you have already chosen to trust.
