# Decisions

Rulings made while building sigmaforge without a product owner to ask. Format:
`Ruling: <what> — <why> — <cost if wrong>`.

## Language semantics

- Ruling: case-insensitive matching folds ASCII letters only (`é` does not match `É`) — it is the only behaviour SQLite `LIKE`, Splunk and KQL share, and the evaluator must be exactly reproducible by the SQL backend — rules relying on Unicode case folding miss matches on non-ASCII text.
- Ruling: integer rule values match an integer field value or its exact decimal text, never `"04688"` or `4688.0` — typed SIEM columns and text logs both appear in practice; exact text keeps it predictable — zero-padded event IDs in text logs will not match.
- Ruling: `gt/gte/lt/lte` only compare real numeric values, never numeric-looking strings — otherwise SQLite's type ordering makes every string greater than every number — a log source that stores numbers as text needs a pipeline or cast.
- Ruling: keyword detections are substring matches over every field value (`*kw*`) — Sigma leaves full-text semantics to the backend; substring is the conservative superset — backends with token search (KQL `has`) are rejected rather than approximated.
- Ruling: Boolean YAML values in detections compile as the strings `true` / `false` — Sigma has no boolean matcher outside `exists`; event booleans have the same text view — rules expecting `1`/`0` will not match booleans.
- Ruling: floats in detections compile to their `repr` text — they are rare and have no portable numeric semantics — float-valued rules may need adjusting.
- Ruling: `null` matches a missing field or an explicit null, not an empty string — matches the Sigma specification — KQL cannot distinguish `""` from missing (documented divergence).
- Ruling: `them` excludes identifiers starting with `_` — Sigma specification — none known.
- Ruling: multiple `condition` entries are OR-ed — Sigma specification — none known.

## Front end

- Ruling: YAML is loaded with a conservative resolver (decimal ints/floats, true/false, null) and duplicate keys are errors — YAML 1.1 silently changes `0x1410`, `010`, `yes` and dates — rule files depending on YAML 1.1 coercions behave differently from pySigma.
- Ruling: aggregations, correlation rules, multi-document files, `expand` and `fieldref` are rejected with `UnsupportedFeatureError` — they need a larger runtime model than a single-event predicate; rejecting keeps every emitted query exact — lower compile coverage on rule sets that use them.
- Ruling: `re` patterns are not validated at parse time; each backend validates against its own engine (Python `re`, RE2 check, Lucene translation) — one engine's verdict must not fail the rule everywhere — an invalid regex surfaces at compile time per backend, not once.
- Ruling: `windash` expansion is capped at 625 variants (four dashes) — combinatorial blow-up protection — a rule with five or more word-leading dashes in one value fails.

## Pipelines

- Ruling: pipelines are YAML with a small, explicit transformation set (mapping, prefix, add_condition, set_state, change_logsource, field_allowlist, rule_failure) rather than a port of pySigma's full set — enough for the bundled targets and testable in isolation — users with complex pySigma pipelines must translate them.
- Ruling: the CLI applies each backend's default pipeline unless `--no-default-pipelines` — compiling Sysmon field names straight into ECS or Defender queries is almost always wrong — users with already-mapped rules must pass the flag.
- Ruling: the `sentinel-windows` pipeline fails rules whose logsource has no known table, and rules using fields outside the table's allowlist — a query against a guessed table or a non-existent column silently never fires — KQL compile coverage is lower (68% on the subset).
- Ruling: `ecs-windows` maps unknown Windows fields to `winlog.event_data.<Field>` — that is where Winlogbeat puts them — fields that Elastic integrations remap elsewhere will not match.

## Backends

- Ruling: the SQL target is a flat, untyped table with one column per field; regex and CIDR need two UDFs registered by `sqlite_runtime.connect()` — SQLite has neither built in, and untyped columns keep `"4688"` and `4688` distinct like the events — the SQL is not portable to other databases without equivalent functions.
- Ruling: SQL negation is `NOT coalesce(expr, 0)` — SQL three-valued logic would drop events with missing fields under `NOT` — slightly longer queries.
- Ruling: SQL keyword search requires explicit `--sql-keyword-columns` — there is no "all columns" operator in SQL and guessing would be silent — keyword rules fail for SQL by default (8 of 200 on the subset).
- Ruling: Splunk output splits top-level conjuncts into search terms and a `| where` eval clause — keeps the fast path for common rules while still expressing regex/`?`/literal-`*` exactly — mixed conjuncts are evaluated post-search (slower on large indexes).
- Ruling: EQL and KQL reject keyword detections — EQL has no full-text search and KQL `has` is token-based, not substring — 8 of 200 subset rules fail for EQL.
- Ruling: EQL regexes are translated to Lucene and refused when untranslatable (`\b`, look-around, inner anchors) — emitting PCRE into a Lucene engine fails or mismatches at search time — some regex rules do not compile for EQL.
- Ruling: string literals with NUL are refused by the SQL backend — SQLite literals cannot hold NUL — affects only synthetic inputs.

## Testing and data

- Ruling: only the SQL backend is executed; SPL/EQL/KQL are pinned by exact-output tests and golden files — no network or vendor engines in `make check` (contract) — dialect mistakes in those three are caught only by review.
- Ruling: the Hypothesis profile used by `make check` is derandomised (fixed seed), `make fuzz` runs 5,000 examples randomly — a reproducible gate plus a deeper exploratory run — the gate explores the same 300 cases each time.
- Ruling: the SigmaHQ subset (200 rules, release r2026-07-01) is committed (888 KB) with a checksum manifest, selected deterministically by evenly spaced sampling per directory — offline `make check`, no hand-picking of easy rules — the subset over-represents some directories by quota.
- Ruling: example rules and events are written for this project instead of copying SigmaHQ content into the examples — clear licensing and hand-labelled ground truth — the examples are small (9 rules, 21 events).
- Ruling: test generators were strengthened after the first mutation run killed only 4 of 13 seeded bugs — the measurement exposed weak generators; the README reports the before/after honestly — later numbers measure generators tuned with knowledge of the mutants.
