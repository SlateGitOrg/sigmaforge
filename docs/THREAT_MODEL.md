# Threat model

sigmaforge is a defensive tool: it translates detection rules into queries. It never connects
to a SIEM, never executes generated queries anywhere except an in-memory SQLite database the
user asks for (`sql-run`), and contains no offensive capability. The demo data is synthetic.

## Assets

* **Generated queries.** Their correctness is the product: a query that silently fails to match
  is a detection gap; a query that matches too much is alert fatigue.
* **The host running the compiler** (CI runner, analyst laptop).

## Trust boundaries and inputs

| input | trust | handled by |
|---|---|---|
| Sigma rule files | semi-trusted (third-party rule packs, pull requests) | `rule.py` strict loader |
| pipeline YAML | trusted configuration, but parsed defensively | `pipeline.py` |
| JSONL events (`eval`, `sql-run`) | untrusted | `cli._read_events`, `sqlite_runtime` |
| generated queries | output, pasted into a SIEM by a human or CI | backends |

## Threats and mitigations

**T1 - Code execution through YAML.** Rule and pipeline files are parsed with a `SafeLoader`
subclass: no Python object tags, only plain scalars, lists and mappings.

**T2 - Query injection through rule values.** A rule value such as `x" OR 1=1 --` must stay a
value in every dialect. Each backend escapes string literals for its own grammar (SQL `''`
doubling, SPL/EQL/KQL backslash escaping of `\` and `"`, EQL/KQL control characters),
identifiers are quoted (`"col"`, `` `field` ``, `['field']`, `'field'`), and wildcards are
re-encoded from parsed parts rather than passed through. Exact-output tests cover quotes,
backslashes and metacharacters per backend; the SQL path is additionally executed by the
differential tests with quotes and LIKE/GLOB metacharacters in the generated alphabet.
NUL characters are refused for SQL.

**T3 - Silent semantic drift (the main risk).** A query that compiles but means something else
is worse than a failure. Mitigations: one shared AST; an executable reference semantics;
differential tests on every subtree; strict YAML typing; explicit `UnsupportedFeatureError`
instead of approximations (keyword search in EQL/KQL, untranslatable regexes, unmapped
fields); a compile report that lists every failure with its reason.

**T4 - Resource exhaustion by hostile rules.** `windash` expansion is capped (625 variants per
value); `base64offset` has a fixed fan-out of 3. Regexes from rules are compiled by Python `re`
only on the evaluator/SQL path; a catastrophic-backtracking pattern can still make `eval` or
`sql-run` slow on long event values - those commands are meant for test data, not production
volumes.

**T5 - Malicious events in `sql-run`.** Events are inserted with bound parameters; table and
column names are quoted identifiers; the database is in memory and discarded.

**T6 - Supply chain.** Two runtime dependencies (PyYAML and the standard library); dev tools
are pinned in `pyproject.toml` and `uv.lock`. The SigmaHQ subset is pinned by commit and
SHA-256 manifest; `scripts/fetch_sigmahq.py` refuses mismatching downloads.

## Out of scope

* Validating that a generated query is *valid* in a live SIEM (only the SQL backend is executed).
* Detecting evasion techniques or judging whether a rule is a good detection.
* Protecting secrets: sigmaforge handles none and needs no credentials.
