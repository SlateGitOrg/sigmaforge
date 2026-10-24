# Architecture

sigmaforge is a classic three-stage compiler: a **front end** that turns Sigma YAML into a
typed expression tree, a **middle** that rewrites the tree (pipelines, simplification), and
**back ends** that print it in a query language. A fourth consumer, the **reference
evaluator**, executes the tree directly and serves as the oracle for differential testing.

## Module map

| module | role | key types / functions |
|---|---|---|
| `errors.py` | exception hierarchy with stable `category` / `feature` labels | `SigmaForgeError`, `UnsupportedFeatureError` |
| `rule.py` | strict YAML loading, rule validation | `SigmaYAMLLoader`, `SigmaRule`, `parse_rule`, `iter_rule_files` |
| `sigmastr.py` | Sigma strings with wildcards and escapes | `SigmaString`, `Wildcard`, `Shape`, `regex_escape` |
| `condition.py` | condition lexer + recursive-descent parser | `tokenize`, `parse_condition`, `format_condition` |
| `modifiers.py` | one detection item (`Field\|mod\|mod: values`) to nodes | `build_item`, `base64_offsets`, `windash_variants` |
| `ast.py` | expression tree and matchers; traversal and printing | `FieldMatch`, `KeywordMatch`, `And/Or/Not/Const`, `to_sexpr` |
| `compiler.py` | front end driver | `compile_search_identifier`, `resolve_condition`, `compile_rule` |
| `pipeline.py` | YAML processing pipelines and transformation registry | `Pipeline`, `Transformation`, `load_pipeline` |
| `optimize.py` | Boolean simplification | `simplify` |
| `evaluator.py` | reference semantics | `evaluate`, `Evaluator`, `value_text` |
| `regexdialect.py` | regex tokenizer, RE2 check, PCRE-to-Lucene translation | `tokenize`, `check_re2`, `to_lucene` |
| `backends/base.py` | precedence-aware rendering, IN-list folding | `TextRenderer`, `Backend`, `Query` |
| `backends/{splunk,eql,kql,sqlite}.py` | the four targets | `SplunkBackend`, `EqlBackend`, `KqlBackend`, `SQLiteBackend` |
| `sqlite_runtime.py` | load JSON events into SQLite, UDFs, run queries | `connect`, `load_events`, `run_query` |
| `report.py` | per-backend compile coverage with failure reasons | `build_report`, `CompileReport` |
| `cli.py` | `sigmaforge` command | `main` |

Dependencies point one way: `cli -> report -> backends -> compiler -> {modifiers, condition,
pipeline, optimize} -> ast -> sigmastr`. The only cycle is `pipeline.AddCondition` needing the
compiler's `compile_search_identifier`, imported lazily inside one method.

## The expression tree

```
Node    := FieldMatch(field, Matcher) | KeywordMatch(StrMatch | RegexMatch)
         | And(Node*) | Or(Node*) | Not(Node) | Const(bool)
Matcher := StrMatch(SigmaString, cased) | RegexMatch(pattern, flags) | CidrMatch(network)
         | NumMatch(int) | CmpMatch(op, number) | NullMatch | ExistsMatch(bool)
```

All nodes are frozen, slotted dataclasses: hashable (the simplifier deduplicates with a set),
comparable (tests assert whole trees), and safe to share between backends.

`SigmaString` stores a tuple of parts, each a literal `str` or `Wildcard.ANY` / `Wildcard.ONE`.
Parsing applies the Sigma escape rules once (`\*`, `\?`, `\\` escape; any other backslash is
literal, so `C:\Windows\` needs no doubling). Backends ask for `shape()` - `EXACT`, `CONTAINS`,
`STARTSWITH`, `ENDSWITH`, `ANYTHING` or `PATTERN` - and map it to native operators, or call
`render(escape, any_token, one_token)` with their own escaping.

## Front end

### Strict YAML (`rule.py`)

PyYAML implements YAML 1.1, where `0x1410` is the integer 5136, `010` is 8, `yes` is `True` and
`2024-01-01` is a date. Each of those would change what a detection matches. `SigmaYAMLLoader`
replaces the implicit resolvers with a conservative set (decimal ints/floats, `true/false`,
`null`) and rejects duplicate mapping keys instead of keeping the last one.

### Condition parser (`condition.py`)

A regex lexer produces `( ) | and or not them`, `1 of`, `all of` and identifiers (which may
contain `*`). The recursive-descent parser implements:

```
or_expr  := and_expr ("or" and_expr)*
and_expr := not_expr ("and" not_expr)*
not_expr := "not" not_expr | primary
primary  := "(" or_expr ")" | ("1" | "all") "of" (PATTERN | "them") | IDENT
```

Binary operators are left-associative. Errors carry the 0-based column, rendered 1-based. On
`|` the lexer stops: the remainder is an aggregation, rejected as a whole as
`UnsupportedFeatureError("aggregation")`. `format_condition` prints a fully parenthesised form;
a property test checks `parse(format(t)) == t` for random trees.

Complexity: O(n) in the condition length (single pass lexer, one token of look-ahead).

### Detection items (`modifiers.py`)

A key `Field|m1|m2` is split into the field and an ordered modifier list. Each value goes
through the modifiers left to right; a value can become several *alternatives*:

* `contains` / `startswith` / `endswith` add `Wildcard.ANY` at the ends (never duplicated);
* `windash` expands every word-leading `-` or `/` into `- / – — ―` (all combinations, capped at
  625 variants);
* `wide` / `utf16*` turn the string into bytes; `base64` encodes bytes or plain text;
* `base64offset` produces the three offset-independent encodings: for offset `i` it encodes
  `i * b" " + value` and trims the characters influenced by unknown neighbours
  (`start = (0, 2, 3)[i]`, `end = (None, -3, -2)[(len + i) % 3]`). A property test checks
  that one of the three always occurs inside the base64 of `prefix + value + suffix`.

Alternatives are OR-ed; values are OR-ed, or AND-ed under `all`. `re`, `cidr`, `exists` and
`gt/gte/lt/lte` change the matcher type and refuse incompatible companions.

### Resolving the condition (`compiler.py`)

Every search identifier compiles to a node first. The condition tree is then folded:
identifier references are looked up; `1 of p` / `all of p` turn the identifiers whose names
fully match the glob `p` (in definition order) into an `Or` / `And`; `them` means every
identifier not starting with `_`. Several conditions are OR-ed.

## Pipelines (`pipeline.py`)

A pipeline is a YAML list of transformations, each optionally gated by logsource conditions
(`rule_conditions`, joined by `all` or `any`). Transformation classes register themselves by
`type_name` through `__init_subclass__`, so adding one is a single class. Application order:
pipelines by ascending `priority`, transformations in file order. A `PipelineContext` carries
the mutable logsource, tree, backend state (`kql_table`, `eql_category`, `splunk_prefix`,
`sql_table`) and the list of applied steps (reported in `ast` and JSON output).

Field mapping rewrites `FieldMatch` leaves; a one-to-many mapping replaces the leaf with an
`Or` of copies. `field_allowlist` turns "this column does not exist in the target table" into
a compile failure instead of a query that never matches.

## Simplifier (`optimize.py`)

Bottom-up, one pass: flatten same-kind nesting, drop duplicates, fold constants, collapse
single children, remove double negation. Each rule is a Boolean identity; a property test
compares evaluator verdicts before and after on random rules and events. O(n) nodes with an
O(1) expected set lookup per child.

## Back ends

`TextRenderer.render(node, parent_precedence)` emits parentheses only when a child binds more
loosely than its parent (`OR=1 < AND=2 < NOT=3 < atom=4`). OR children that are exact matches
on the same field are folded into an IN-list where the dialect has one (`IN`, `in~`), keeping
first-seen order.

### SQLite SQL

* Case-insensitive strings: `col LIKE 'pat' ESCAPE '\'` with `%`, `_` and `\` escaped. SQLite's
  `LIKE` folds ASCII only, matching the evaluator. `LIKE` also coerces integers to text, which
  is exactly the evaluator's "text view".
* `cased`: `col GLOB 'pat'` with `*`, `?`, `[` escaped as one-character classes (`[*]`).
* Integers: `CAST(col AS TEXT) = '4688'` matches an INTEGER 4688 or the TEXT `'4688'`, not
  `'04688'`. Comparisons: `typeof(col) IN ('integer','real') AND col > n` - without the guard
  SQLite's type ordering makes every text value greater than every number.
* Regex: `col REGEXP '(?i)...'`; CIDR: `sigma_cidr_match('net', col)`. Both are Python UDFs
  registered by `sqlite_runtime.connect()`.
* **NULL-safe negation.** A missing column is NULL and Sigma says a test on a missing field is
  false. Kleene AND/OR already agree with Boolean logic when NULL is read as false (NULL AND x
  is NULL or false; NULL OR x is NULL or x), so only negation needs care: `NOT NULL` is NULL,
  but Sigma wants true. Every `Not` is emitted as `NOT coalesce(<expr>, 0)`; the inner
  expression is again "NULL means false", so the property composes through nesting.

### Splunk SPL

Output is `<search terms> [| where <eval expression>]`. Top-level conjuncts are rendered as
search terms when possible; a conjunct containing a regex, a `?` wildcard or a literal `*` is
rendered in the eval dialect instead (`match(field, "(?i)^...$")`, `cidrmatch`, `isnull`) and
moved behind `| where`. Moving only whole conjuncts keeps the Boolean structure exact. Because
SPL search gives `OR` higher precedence than `AND`, the renderer parenthesises every AND inside
an OR. Negation is `NOT field=value`, which (unlike `field!=value`) also matches events that
lack the field.

### Elastic EQL

`<category> where ...` with the category from the `ecs-windows` pipeline. Exact strings use
`:` (case-insensitive) or `==`; wildcards use `like~` / `like`; literal `*` or `?` characters,
which EQL wildcards cannot escape, fall back to a fully escaped Lucene `regex~`. Sigma regexes
go through `to_lucene`:

1. tokenize (escapes, character classes, groups, quantifiers with lazy/possessive suffix);
2. a leading `^` / trailing `$` become implicit (Lucene regexes match the whole value), and an
   unanchored side gets `.*`; a top-level alternation is wrapped in a group, and refused if it
   is also anchored;
3. translate `\d \w \s` (and negations) to classes, `\t \n \xHH` to characters, `(?:` and named
   groups to `(`, drop lazy `?`, escape Lucene-reserved `# @ & < > ~ " { }`;
4. refuse what has no equivalent: look-around, back-references, `\b`, inner anchors, possessive
   quantifiers, inline flags other than a leading `(?i)` (which selects `regex~`).

A property test generates patterns from a grammar both engines share and checks that Python's
full match of the translation equals Python's search of the original. O(n) in pattern length.

### Microsoft KQL

`Table\n| where ...` with the table from the `sentinel-windows` pipeline; no table means a
compile failure. String shapes map to `=~ contains startswith endswith` (and `_cs` / `==`);
other patterns become `matches regex "(?i)^...$"`. Sigma regexes are checked with
`check_re2` (no look-around, back-references, atomic groups, possessive quantifiers). CIDR uses
`ipv4_is_in_range` / `ipv6_is_in_range`. `null` / `exists` use `isempty` / `isnotempty`.

## Reference evaluator and differential testing

`evaluator.evaluate(node, event)` is a direct recursive interpretation; its module docstring is
the semantic specification. The differential tests (`tests/test_differential.py`) generate
rules at the YAML level and events from the rule's own values with near-miss variants (case
flips, metacharacter mutations, padding, `0`-prefixed integers, addresses of the other IP
family). They assert, per example:

1. the full SQL query selects exactly the evaluator's matches;
2. every subtree, rendered as `coalesce(<expr>, 0)` in one `SELECT`, agrees with the evaluator
   on every event;
3. the simplified and unsimplified trees agree.

`scripts/mutation_check.py` measures how sensitive this is by seeding bugs (see README).

## Complexity summary

| stage | time | notes |
|---|---|---|
| condition parse | O(c) | c = condition length |
| detection compile | O(v * w) | v values, w = windash/base64offset fan-out (bounded: 625 / 3) |
| quantifier resolution | O(q * i) | q quantifiers, i identifiers |
| pipeline application | O(t * n) | t transformations, n tree nodes |
| simplify | O(n) | |
| render | O(n + s) | s = total string length (escaping) |
| evaluate (one event) | O(n * s) | regex/wildcard matching dominates; compiled patterns are cached |
| SQL subtree check | O(n^2) text | each subtree is rendered separately; test-only |

Memory is O(n) for the tree; the compile report holds one result per rule x backend.
