# `AGENTS.md`

## 1. Scope

Artificial intelligence (AI) agents MUST follow these rules and instructions.

Agents MUST NOT report their own execution statistics or telemetry, including token usage, elapsed time, or tool-use counts.

## 2. Keywords

These keywords define normative requirements:

| Keyword | Classification | Meaning |
|---|---|---|
| `MUST` | Obligation | A requirement. |
| `MUST NOT` | Prohibition | A prohibition. |
| `SHOULD` | Encouragement | Encouraged, unless a justified exception exists. |
| `SHOULD NOT` | Discouragement | Discouraged, unless a justified exception exists. |
| `MAY` | Permission | Optional; permitted but not required. |

Only uppercase forms are normative.

Normative text MUST use these keywords consistently without weaker or less precise substitutes. Informative text SHOULD avoid them. Keywords MUST NOT be capitalized for emphasis.

## 3. Formatting

### 3.1. Code Style Authority

Agent-generated and agent-modified code MUST follow these rules. Directly modified existing code SHOULD conform where local, safe, and in scope.

Required external forms MAY differ at language, runtime, framework, protocol, wire, public application programming interface (API), database, serialization, generated-code, foreign-function, callback, or other external compatibility boundaries.

### 3.2. General Code Formatting

Code MUST satisfy these rules:

- Indentation MUST use 4 spaces and MUST NOT use tabs.
- Syntax MUST be valid.
- Trailing whitespace MUST NOT occur.
- Code text files MUST end with exactly one newline where permitted.
- Blank lines MUST be necessary and MUST NOT be consecutive.
- Formatting MUST NOT be dense, compressed, or gratuitously space-aligned.
- Delimiter and operator spacing MUST be consistent.
- Logical structure MUST remain visually apparent.
- Unclear operator precedence MUST use explicit grouping.

Nonempty comma-separated lists SHOULD have trailing commas, horizontally or vertically, where permitted. Commas MUST NOT invalidate syntax or change meaning, including creating tuples or array holes.

Statements SHOULD occupy separate lines. Complex expressions SHOULD use named intermediate values when clearer. Deep nesting SHOULD be avoided.

### 3.3. Blank Lines and Code Body Structure

Apply these rules independently inside functions, methods, branches, loops, classes, Structured Query Language (SQL) statements, and similar bodies:

- Related one-line statements and declarations MUST remain adjacent within a logical or conceptual group. Distinct groups MUST have exactly one separating blank line.
- Each block-like construct MUST form a separate group with exactly one blank line between it and adjacent groups. Block-like constructs include function and method definitions, control-flow constructs, vertically formatted calls and signatures, and multiline declarations, initializers, and assignments.
- Grouping MUST apply recursively within each block. Entries within a single parameter, argument, member, or collection list MUST NOT receive blank lines solely because the enclosing construct is multiline. Logical or conceptual subdivisions MAY have one separating blank line.
- Preconditions and guards MUST be separated from subsequent independent operations. Preparatory computations SHOULD be separated from operations consuming their results when they form distinct logical steps.
- Each `return` MUST form a separate logical section with one blank line between adjacent sections.
- Control flow includes `if`, loops, `switch`, `try`, and equivalents. Attached `else if`, `else`, `catch`, `finally`, `elif`, and `except` continuations MUST NOT have separating blank lines.
- Sections MUST NOT have blank-line padding at body boundaries. A lone `return` MUST NOT have padding.
- Block signatures MUST directly precede their first statements without blank lines.

Module-level declarations MUST be grouped by purpose, visibility, and state characteristics, with exactly one blank line between groups. Related one-line constants MUST remain adjacent without blank lines. Exported constants, exported mutable state, internal constants, and internal mutable state SHOULD form distinct groups where applicable. Within a mutable-state group, simple flags, counters, and similar state SHOULD precede complex mutable references.

Object members MUST be distinct declarations. Constructors, methods, getters, and setters MUST form separate groups under the block-like construct rule. Related one-line fields and member declarations MUST remain adjacent. A member's closing delimiter MUST NOT share the next member declaration's line. Member delimiters and commas MUST attach to the preceding member.

### 3.4. Vertical Signature and Call Formatting

Signatures, calls, constructors, type constructors, generics, type parameter lists, decorators, and similar constructs MUST be horizontal with zero arguments or parameters and, where valid, with one.

Constructs with two or more arguments or parameters MUST be vertical where permitted, one per line. Opening delimiters MUST remain on the signature or call line where supported; closing delimiters MUST occupy their own line. Alignment MUST use indentation, not manual spacing. Trailing non-comma separators SHOULD appear where supported; commas follow [General Code Formatting](#32-general-code-formatting).

SQL types, columns, and function signatures MAY remain horizontal when vertical formatting materially reduces readability. This exception applies only to this section.

### 3.5. Naming

#### 3.5.1. PascalCase

Classes, types, interfaces, protocols, traits, contracts, abstractions, typed schemas, domain objects, value objects, data transfer object types, exception types, type aliases, generics, and structured object definitions MUST use `PascalCase`.

#### 3.5.2. snake_case

Functions, methods, variables, parameters, local values, modules, packages, supported namespaces, source filenames, database columns and tables, configuration keys, and internally controlled JSON keys, commands, events, and identifiers MUST use `snake_case`.

#### 3.5.3. Constants

Constants MUST use `UPPER_SNAKE_CASE`.

#### 3.5.4. Enumerations

Enumeration members MUST use `UPPER_SNAKE_CASE`. Internally controlled serialized, persisted, displayed, and wire values MUST use lowercase, space-separated text. Machine-only values MAY use another representation when whitespace is unsuitable, but MUST remain lowercase and semantically clear.

#### 3.5.5. Boolean Names

Booleans and boolean-returning functions MUST begin with predicates such as `is_`, `has_`, `can_`, `should_`, `does_`, `was_`, or `will_`. Negated names SHOULD NOT be used; double negatives MUST NOT be used.

#### 3.5.6. Function and Method Names

Function and method names MUST begin with action-describing verbs. Noun-only names MUST NOT be used unless externally required.

#### 3.5.7. Type and Object Names

Class, type, object, contract, and abstraction names MUST be nouns or noun phrases. Generic names such as `Manager`, `Helper`, `Utility`, `Processor`, `Handler`, `Thing`, `Data`, and `Object` SHOULD NOT be used unless they identify stable domain concepts.

Names MUST NOT end in `Impl`. Interfaces MUST NOT have an `I` prefix. Abstract types MUST NOT have an `Abstract` prefix unless needed to avoid genuine ambiguity.

#### 3.5.8. Semantic Naming

Names MUST communicate domain meaning, prefer complete words, avoid unnecessary abbreviations and unexplained acronyms, use one canonical term per concept across layers, and avoid changeable implementation details.

Single-character names MUST NOT be used except for conventional mathematics, very small local indices, coordinates, and conventional generic parameters. Vague names SHOULD NOT replace precise domain names.

#### 3.5.9. Acronyms

Acronyms MUST follow surrounding naming case. Well-known acronyms MAY remain abbreviated when clearer.

#### 3.5.10. Collections

Multiple-value collections MUST normally have plural names. Container suffixes SHOULD NOT appear unless the structure has semantic importance.

#### 3.5.11. Quantities and Units

Quantity names MUST include units unless encoded by types. Variables MUST NOT change semantic units during their lifetimes. Conversions SHOULD occur at explicit boundaries.

#### 3.5.12. Private and Internal Names

Leading underscores MUST NOT solely indicate privacy. Native visibility mechanisms MUST be preferred; otherwise, privacy SHOULD use module boundaries, scope, architecture, or contracts rather than punctuation.

### 3.6. Literals and Constants

Semantically important or reused literals MUST use names rather than repeated magic values. Constant names MUST describe meaning, not literal values. Sentinels MUST have explicit semantics. Ambiguous domain-unit numbers SHOULD use named constants or typed values.

### 3.7. Imports

Imports MUST be explicit, used, and free of wildcards. Symbols MUST retain exported names without aliases for internal style compliance. Default imports MUST use documented canonical names where available. Conflicting internally controlled names MUST change.

Paths MUST be stable and direct. Import-time side effects MUST NOT occur unless explicitly required. Imports MUST be grouped by dependency origin and purpose. Related imports SHOULD be grouped by subsystem or responsibility.

Groups MUST follow this order:

1. Standard-library imports.
2. External dependencies.
3. Internal type-only imports, where supported.
4. Internal value imports.

External type-only imports MAY remain with their corresponding dependencies. Package API imports MUST be separated from worker, WebAssembly, and other asset imports. Groups MUST have exactly one separating blank line; related one-line imports within each group MUST remain adjacent. Group members MUST sort alphabetically by path, then symbol, where permitted.

### 3.8. Embedded and Generated Code

Rendered embedded, escaped, templated, interpolated, and generated code MUST conform as standalone code, including inline code, strings, shell commands, HTML, dynamic templates, generated source, SQL, executable configuration, migrations, and executable examples.

Generators MUST produce conforming output. Non-conforming output MUST be repaired in its authoritative generator or template, not through repeated manual formatting.

### 3.9. Comments

Comments MUST NOT restate obvious code and SHOULD explain only non-obvious intent, constraints, invariants, algorithms, compatibility, counterintuitive decisions, or justified workarounds.

Agents MUST NOT add, remove, or modify comments unless requested, needed for existing comment correctness, or needed to explain a non-obvious invariant introduced by the task.

### 3.10. Markdown

#### 3.10.1. Headings and Spacing

Level-one headings MUST NOT occur unless explicitly instructed. Sections MUST begin at `##`; nested sections MUST descend one heading level at a time. Headings MUST use sequential hierarchical numbers with a trailing period at every level: `## 1. Scope`, `### 1.1. Details`, and `#### 1.1.1. Cases`. Child numbering MUST restart under each parent.

Heading text SHOULD be concise noun phrases with consistent capitalization and MUST NOT have terminal punctuation after the title. Exactly one blank line SHOULD follow a heading. Blank lines MUST NOT be consecutive.

Paragraphs SHOULD cover one coherent topic with an obvious governing subject. Independent paragraphs and conceptual blocks SHOULD have one separating blank line.

Introducing sentences MUST announce their blocks through wording or a colon and MUST adjoin them without a blank line, except tables MUST have exactly one preceding blank line. Code, mathematics, and schema blocks MUST have clear introductions; diagrams SHOULD have them.

#### 3.10.2. Emphasis and Document Purpose

Bold MUST NOT occur. Italics MAY provide useful emphasis or mark terminology. Decorative punctuation, excessive emphasis, and ordinary all-caps emphasis MUST NOT occur.

Agents MUST classify each document by its primary purpose. An *informational document* explains a subject; an *organizational document* structures records, tasks, projects, or overviews.

Informational documents MUST italicize terms at their definitions and MUST define specialized concepts and prerequisite terms to the depth needed by the intended reader. Ordinary words MUST NOT receive unnecessary definitions. Later mentions MAY use normal formatting.

Organizational documents MUST maximize useful tables, lists, and other structured content, with minimal explanatory or metainformation sentences. Structure MUST NOT be redundant or obscure the content.

#### 3.10.3. Lists

Lists MUST express genuine sets, sequences, conditions, alternatives, or fields without fragmenting ordinary prose. Numbered lists MUST express significant order, precedence, sequence, or stable references. Other collections SHOULD use bullets unless numbers identify priorities.

Bullets SHOULD have parallel grammar and semantic level. Numbered items introducing nested lists MUST adjoin them without a blank line. Nested lists SHOULD express real hierarchy and SHOULD NOT exceed three levels without strong justification.

#### 3.10.4. Code and Mathematics

Inline code MUST be preferred for readable short code, identifiers, literals, commands, paths, fields, types, parameters, environment variables, configuration keys, and expressions. Code blocks MUST materially improve clarity and SHOULD contain multiline code, complete examples, configuration, queries, commands, schemas, structured data, or exact output whose line structure matters.

Fences MUST declare a suitable language when available and contain only code needed for their point. All code, including embedded and generated code and diagram source, MUST follow applicable code-style rules. Generated diagram source MUST conform.

Short, readable mathematics MUST remain inline. Blocks MAY contain long, multiline, central, or more inspectable expressions and MUST NOT provide mere emphasis.

#### 3.10.5. Tables, Quotations, Diagrams, and Footnotes

Tables MUST structure content usefully, with clear headers, comparable columns where applicable, and concise cells. Hard-to-scan tables SHOULD become lists or subsections; tables MUST NOT displace prose needed for explanation.

Quotations SHOULD preserve exact wording only when necessary; otherwise, paraphrase SHOULD be preferred. Quotations MUST preserve meaning and identify sources. Block quotes SHOULD contain only substantial quotations.

Mermaid diagrams MUST be used where useful or necessary to explain structure, relationships, or behavior. When working in Obsidian, compatible charts MUST also be used where useful or necessary. Diagrams and charts MUST have clear purposes and MUST improve understanding.

Footnotes SHOULD be sparse and MAY provide citations, history, or narrow clarification.

#### 3.10.6. Punctuation

Parentheses SHOULD contain short clarifications; nested parentheses SHOULD be avoided. Semicolons MAY improve clarity but SHOULD NOT compress sentences clearer independently. Colons SHOULD introduce related blocks, definitions, or explanations.

Complete sentences MUST have terminal punctuation. List fragments MAY omit it consistently among siblings. Identifiers and literals MUST retain defined punctuation and casing.

Prose MUST use normal capitalization; proper nouns MUST retain established capitalization.

### 3.11. SQL

Internally controlled SQL MUST have clear structural sections.

#### 3.11.1. Front Matter

Dimensional and entity-like tables SHOULD begin with applicable identity columns ordered `id`, `key`, `name`, and `label`. Other stable or primary descriptive identity fields MAY follow.

`id` MUST identify the row or canonical object. `key` SHOULD identify a stable logical identity, `name` SHOULD identify the canonical human-readable name, and `label` SHOULD identify a separate display value where applicable. Identity semantics MUST remain distinct and MUST NOT be duplicated in the business body.

#### 3.11.2. Business Body

Domain columns MUST keep related fields adjacent, follow stable domain ordering, and avoid arbitrary mixing with identity or system metadata.

#### 3.11.3. Back Matter

System-maintained lifecycle, version, audit, and historical fields MUST follow business columns, remain adjacent, and use the `system_` prefix for internal row and version lifecycle metadata. Business-valid and system-valid time MUST remain distinct. Domain timestamps MUST NOT appear in system metadata.

Persistent tables MUST include `system_created_at` and `system_updated_at` where technically applicable.

Slowly Changing Dimension Type 2 (SCD2) preserves historical row versions. Dimensional tables retaining history SHOULD use applicable SCD2 fields, including `system_first_seen_at`, `system_last_seen_at`, `system_valid_from`, `system_valid_to`, `system_version`, and `system_is_active`.

Fact tables SHOULD use only system fields needed for creation, update, audit, or technical lifecycle unless historical versioning is explicitly required.

#### 3.11.4. SQL Statements

SQL MUST use explicit joins without implicit Cartesian products. External values MUST be bound through parameters and MUST NOT be interpolated.

SQL MUST use deterministic ordering where order matters, explicit column lists for durable `INSERT` operations, and explicit material transaction boundaries. Durable application code MUST NOT use `SELECT *` without explicit justification.

Expressions and joins MUST preserve type semantics. Ambiguous references MUST use explicit aliases and qualified columns. Predicates MUST reflect query business meaning.

### 3.12. File Formatting

Text files MUST use UTF-8, LF line endings, a final newline, and four-space indentation where supported. Markdown MAY retain trailing whitespace. Makefiles MUST use tabs where required. Windows batch and command scripts MUST use CRLF line endings. Binary files MUST NOT have text formatting applied.

### 3.13. PDF Documents

PDFs MUST be generated from Markdown through Pandoc. Agents MUST NOT directly edit PDF metadata.

## 4. Relic Execution Boundaries

- Agents MUST preserve `master` as the primary branch and use `implementation/relic-full-system` for the approved implementation and CI pushes.
- Agents MUST read `docs/goal_state.json` and `docs/conformance.md` when continuing the implementation goal.
- Heavy work on the development host MUST run serially inside an enforced aggregate memory limit of at most 1 GiB, with a 768 MiB pressure threshold and swap disabled. Cargo MUST use one build job, and tests MUST use one thread. The Linux mechanism is `python3 tools/check.py`, which uses a fixed user systemd transient service with `MemoryMax=1G`, `MemoryHigh=768M`, and `MemorySwapMax=0`, verifies the actual child cgroup, and prevents overlapping guarded runs. Agents MUST NOT raise this limit without a direct user instruction.
- Implementation work MUST use at most one worker in addition to the coordinator until the user changes the memory constraint.
- If enforcement is unavailable or a workload exceeds the limit, agents MUST stop that workload, record the failure, and continue independent lightweight work. Agents MUST NOT raise the limit without a direct user instruction.
- Agents MUST NOT count ignored or unexecuted tests as passed acceptance evidence. Foundation tests MUST NOT establish full-system completion.
- Agents MUST keep native, packaging, performance, and independent-recovery evidence separate. Publication, primary-branch updates, and deployment remain outside the approved implementation-branch authority.
