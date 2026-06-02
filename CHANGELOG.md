# Changelog

## 1.0.1 - 2026-06-02

- Harden `safe-audit setup` so it no longer downloads scanner binaries, runs
  upstream installer scripts, or runs language package installers.
- Make scanner setup fail closed unless required scanners already exist or an
  explicit local scanner bundle is provided.
- Treat Socket CLI as optional for scanner setup.

## 1.0.0 - 2026-06-02

- Initial public release baseline.
