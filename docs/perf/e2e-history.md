# End-to-end benchmark history

Appended by `goSignalsBench --history` (see [e2e-benchmark.md](e2e-benchmark.md)).
One row per run; compare like with like (same events, concurrency, mix and machine class).

| Date (UTC) | Revision | Label | Events | Conc | Mix | Ingest ev/s | Ingest p50/p99 ms | Push ev/s | Push drain s | Poll ev/s | Poll drain s | SSTP role | SSTP ev/s | SSTP drain s | Total s | OK |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-09-07 21:11 | v0.12.0-alpha.19-1-gda1c658-dirty | baseline | 5000 | 16 | alternate | 1324 | 11.5 / 23.6 | 38 | 61.7 | 106 | 19.7 | - | - | - | 65.4 | yes |
| 2026-09-07 21:18 | v0.12.0-alpha.19-1-gda1c658-dirty | shared-push-transport | 5000 | 16 | alternate | 1211 | 12.8 / 22.8 | 105 | 19.7 | 112 | 18.2 | - | - | - | 23.8 | yes |
| 2026-09-07 22:03 | v0.12.0-alpha.19-2-gf88eb08-dirty | sstp-leg-initiator | 5000 | 16 | alternate | 1084 | 13.6 / 33.5 | 94 | 13.1 | 103 | 11.6 | initiator | 106 | 11.1 | 17.7 | yes |
| 2026-09-07 22:03 | v0.12.0-alpha.19-2-gf88eb08-dirty | sstp-leg-responder | 5000 | 16 | alternate | 1234 | 11.9 / 34.0 | 94 | 13.6 | 100 | 12.6 | responder | 55 | 26.3 | 30.4 | yes |
| 2026-09-08 21:19 | v0.12.0-alpha.19-14-g72d48de | spec102-288-before-sid-only-index | 5000 | 16 | alternate | 623 | 23.4 / 60.6 | 195 | 0.5 | 195 | 0.5 | initiator | 195 | 0.5 | 8.5 | yes |
| 2026-09-08 21:19 | v0.12.0-alpha.19-14-g72d48de | spec102-288-before-run2 | 5000 | 16 | alternate | 675 | 22.0 / 52.0 | 210 | 0.5 | 210 | 0.5 | initiator | 210 | 0.5 | 7.9 | yes |
| 2026-09-08 21:23 | v0.12.0-alpha.19-15-g77d677f-dirty | spec102-288-after-run1 | 5000 | 16 | alternate | 598 | 24.3 / 61.8 | 188 | 0.5 | 188 | 0.5 | initiator | 188 | 0.5 | 8.9 | yes |
| 2026-09-08 21:24 | v0.12.0-alpha.19-15-g77d677f-dirty | spec102-288-after-run2 | 5000 | 16 | alternate | 726 | 20.2 / 49.9 | 225 | 0.5 | 225 | 0.5 | initiator | 225 | 0.5 | 7.4 | yes |
| 2026-09-08 21:39 | v0.12.0-alpha.19-17-ge700ac2 | spec102-289-before-initiator | 5000 | 16 | sstp | 570 | 24.5 / 73.1 | - | - | - | - | initiator | 424 | 3.0 | 11.8 | yes |
| 2026-09-08 21:40 | v0.12.0-alpha.19-17-ge700ac2-dirty | spec102-289-before-initiator-run2 | 5000 | 16 | sstp | 659 | 20.8 / 67.9 | - | - | - | - | initiator | 520 | 2.0 | 9.6 | yes |
| 2026-09-08 21:40 | v0.12.0-alpha.19-17-ge700ac2-dirty | spec102-289-before-responder | 5000 | 16 | sstp | 771 | 16.8 / 68.6 | - | - | - | - | responder | 625 | 1.5 | 8.0 | yes |
| 2026-09-08 21:41 | v0.12.0-alpha.19-17-ge700ac2-dirty | spec102-289-before-responder-run2 | 5000 | 16 | sstp | 761 | 17.7 / 58.6 | - | - | - | - | responder | 659 | 1.0 | 7.6 | yes |
| 2026-09-08 21:42 | v0.12.0-alpha.19-17-ge700ac2-dirty | spec102-289-after-initiator | 5000 | 16 | sstp | 564 | 24.9 / 76.3 | - | - | - | - | initiator | 459 | 2.0 | 10.9 | yes |
| 2026-09-08 21:43 | v0.12.0-alpha.19-17-ge700ac2-dirty | spec102-289-after-initiator-run2 | 5000 | 16 | sstp | 568 | 23.5 / 94.2 | - | - | - | - | initiator | 462 | 2.0 | 10.8 | yes |
| 2026-09-08 21:43 | v0.12.0-alpha.19-17-ge700ac2-dirty | spec102-289-after-responder | 5000 | 16 | sstp | 815 | 16.6 / 52.1 | - | - | - | - | responder | 752 | 0.5 | 6.7 | yes |
| 2026-09-08 21:44 | v0.12.0-alpha.19-17-ge700ac2-dirty | spec102-289-after-responder-run2 | 5000 | 16 | sstp | 674 | 20.1 / 66.3 | - | - | - | - | responder | 631 | 0.5 | 7.9 | yes |
