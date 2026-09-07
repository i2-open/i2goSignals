# End-to-end benchmark history

Appended by `goSignalsBench --history` (see [e2e-benchmark.md](e2e-benchmark.md)).
One row per run; compare like with like (same events, concurrency, mix and machine class).

| Date (UTC) | Revision | Label | Events | Conc | Mix | Ingest ev/s | Ingest p50/p99 ms | Push ev/s | Push drain s | Poll ev/s | Poll drain s | SSTP role | SSTP ev/s | SSTP drain s | Total s | OK |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-09-07 21:11 | v0.12.0-alpha.19-1-gda1c658-dirty | baseline | 5000 | 16 | alternate | 1324 | 11.5 / 23.6 | 38 | 61.7 | 106 | 19.7 | - | - | - | 65.4 | yes |
| 2026-09-07 21:18 | v0.12.0-alpha.19-1-gda1c658-dirty | shared-push-transport | 5000 | 16 | alternate | 1211 | 12.8 / 22.8 | 105 | 19.7 | 112 | 18.2 | - | - | - | 23.8 | yes |
| 2026-09-07 22:03 | v0.12.0-alpha.19-2-gf88eb08-dirty | sstp-leg-initiator | 5000 | 16 | alternate | 1084 | 13.6 / 33.5 | 94 | 13.1 | 103 | 11.6 | initiator | 106 | 11.1 | 17.7 | yes |
| 2026-09-07 22:03 | v0.12.0-alpha.19-2-gf88eb08-dirty | sstp-leg-responder | 5000 | 16 | alternate | 1234 | 11.9 / 34.0 | 94 | 13.6 | 100 | 12.6 | responder | 55 | 26.3 | 30.4 | yes |
