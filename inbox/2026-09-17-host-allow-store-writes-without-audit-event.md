# host-allow store writes leave no audit event (add, update, import, remove)

Date: 2026-09-17. Source: slice `tests-home-isolation` report + a live case the same day.

Only a followed replacement logs a store event (`REPLACED`, 1.64.0). `host-allow add`, `update`,
`import` and `remove` rewrite `host-allow.json` with no line in the append-only audit log. Live
case: the `@superbiche/acpx` pin moved on rainbow at 14:38 on 2026-09-17 (an operator TTY `update`
in another session) and the only trace was the file mtime. The 2026-09-16 store wipe could not be
attributed for the same reason.

Ask: one audit event per store write (`HOST_ALLOW_WRITE op=<add|update|import|remove> pkg=<…>
entries=<n>`), written after the confirmed rename, in the audit log and not in the execution log
that `host-allow review` counts.
