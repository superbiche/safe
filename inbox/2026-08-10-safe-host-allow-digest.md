# Host-allow review digest — 2026-08-10

**Source:** `safe run host-allow review --digest` (automated)

## Summary

24 entries — 11 removable, 9 keep, 4 review-urgent, 0 unknown, 21 never used.

## Entries

| Entry | Eco | Age | Uses | Last used | Status |
|---|---|---|---|---|---|
| playwright@TO_PIN | npm | 86d | 1 | 2026-06-14T12:39:46+02:00 | keep |
| pnpm@11.1.2 | npm | 86d | 0 | never | review-urgent |
| @qwen-code/qwen-code@0.21.5 | npm | 5d | 0 | never | review-urgent |
| @openai/codex@0.144.0 | npm | 32d | 0 | never | removable |
| typescript@6.0.3 | npm | 62d | 0 | never | removable |
| @dotenvx/dotenvx@1.75.1 | npm | 38d | 0 | never | keep |
| @agentclientprotocol/codex-acp@1.1.2 | npm | 29d | 1 | 2026-07-12T21:08:32+02:00 | keep |
| opencode@1.17.18 | npm | 29d | 0 | never | keep |
| opencode-ai@1.17.18 | npm | 29d | 0 | never | keep |
| @opentelemetry/sdk-node@0.219.0 | npm | 24d | 0 | never | removable |
| @opentelemetry/exporter-trace-otlp-http@0.219.0 | npm | 24d | 0 | never | removable |
| @opentelemetry/auto-instrumentations-node@0.77.0 | npm | 24d | 0 | never | removable |
| chokidar@^4.0.1 | npm | 23d | 1 | 2026-08-01T21:37:11+02:00 | removable |
| postcss@8.5.18 | npm | 11d | 0 | never | keep |
| brace-expansion@2.1.4 | npm | 10d | 0 | never | removable |
| @nestjs/swagger@11.4.6 | npm | 10d | 0 | never | removable |
| @scalar/nestjs-api-reference@1.2.12 | npm | 10d | 0 | never | removable |
| vue-tsc@3.3.9 | npm | 10d | 0 | never | removable |
| @scalar/api-reference@1.64.0 | npm | 10d | 0 | never | review-urgent |
| @types/node@22.20.1 | npm | 10d | 0 | never | keep |
| @agentmemory/agentmemory@0.9.28 | npm | 8d | 0 | never | keep |
| @huggingface/transformers@4.2.0 | npm | 8d | 0 | never | removable |
| @colbymchenry/codegraph@1.5.0 | npm | 7d | 0 | never | review-urgent |
| graphifyy@0.9.32 | python | 7d | 0 | never | keep |

## Suggested actions

- **URGENT** `pnpm@11.1.2` now audits BLOCK — standing host trust contradicts current knowledge; review immediately.
- **URGENT** `@qwen-code/qwen-code@0.21.5` now audits BLOCK — standing host trust contradicts current knowledge; review immediately.
- **URGENT** `@scalar/api-reference@1.64.0` now audits BLOCK — standing host trust contradicts current knowledge; review immediately.
- **URGENT** `@colbymchenry/codegraph@1.5.0` now audits BLOCK — standing host trust contradicts current knowledge; review immediately.
- `@openai/codex@0.144.0` audits GO on its own — removable: `safe run host-allow remove @openai/codex`
- `typescript@6.0.3` audits GO on its own — removable: `safe run host-allow remove typescript`
- `@opentelemetry/sdk-node@0.219.0` audits GO on its own — removable: `safe run host-allow remove @opentelemetry/sdk-node`
- `@opentelemetry/exporter-trace-otlp-http@0.219.0` audits GO on its own — removable: `safe run host-allow remove @opentelemetry/exporter-trace-otlp-http`
- `@opentelemetry/auto-instrumentations-node@0.77.0` audits GO on its own — removable: `safe run host-allow remove @opentelemetry/auto-instrumentations-node`
- `chokidar@^4.0.1` audits GO on its own — removable: `safe run host-allow remove chokidar`
- `brace-expansion@2.1.4` audits GO on its own — removable: `safe run host-allow remove brace-expansion`
- `@nestjs/swagger@11.4.6` audits GO on its own — removable: `safe run host-allow remove @nestjs/swagger`
- `@scalar/nestjs-api-reference@1.2.12` audits GO on its own — removable: `safe run host-allow remove @scalar/nestjs-api-reference`
- `vue-tsc@3.3.9` audits GO on its own — removable: `safe run host-allow remove vue-tsc`
- `@huggingface/transformers@4.2.0` audits GO on its own — removable: `safe run host-allow remove @huggingface/transformers`

Removal is operator-only (TTY-gated); this digest only queues the decisions.
Statuses marked `unknown` reflect audit-infrastructure failure — retry later, never treat as stale.
