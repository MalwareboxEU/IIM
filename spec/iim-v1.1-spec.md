# IIM v1.1 Specification

**Status:** Draft
**Version:** 1.1
**Released:** Target 2026-Q3 (after v1.0 stabilization)
**Editor:** Robin Dost, Malwarebox
**License:** CC BY 4.0

## 1. Introduction

The Infrastructure Intelligence Model (IIM) is a structural framework for describing adversary infrastructure. It sits between IOC feeds and MITRE ATT&CK: IOCs describe point-in-time artifacts that decay within days; ATT&CK describes behavior at the victim endpoint; IIM describes the adversary's operational infrastructure - stable across campaigns, resistant to rotation, and auditable across analysts.

This document specifies IIM v1.1. It defines the grammar, the validity rules, and the expected semantics of every concept in the model. Implementations must conform to this specification to claim IIM compatibility.

### 1.1 Scope

IIM describes **five properties of adversary infrastructure**: hosting, resolution, routing, gating, composition. It does not describe:

- What a payload does when executed on a victim host (→ MITRE ATT&CK)
- How data flows are encrypted in memory (→ ATT&CK, STIX Cyber Observable extensions)
- Which attribution group is behind an operation (→ actor profiles, out of scope for IIM)

The **scope boundary** is strict and is the central design decision of the framework. Implementations that violate the boundary do not produce valid IIM.

### 1.2 Conformance Levels

An implementation claims one of three conformance levels:

- **Level 1 - Consumer.** Loads, parses, and validates IIM chains and patterns per this spec. Does not modify or produce new ones. Typical: feed aggregators, SIEM rule engines.
- **Level 2 - Producer.** Additionally creates valid chains and patterns. Must pass validation of all outputs against the JSON Schema in §9. Typical: threat-intel platforms, analyst workbenches.
- **Level 3 - Interoperable.** Additionally round-trips IIM data through STIX 2.1 without data loss. Must preserve all `x_iim_*` custom properties on export and reconstruct them on import. Typical: mature TIPs integrating IIM natively.

### 1.3 Document Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 2. Data Model

IIM defines six concepts. The rest of the specification is expansion and rules.

| Concept | Layer | Purpose |
|---------|-------|---------|
| **Entity** | Observation | An observed artifact (url, domain, ip, file, hash, email, certificate, asn) |
| **Relation** | Observation | A directed, typed connection between two entities |
| **Role** | Interpretation | The job an entity plays within a specific chain |
| **Technique** | Interpretation | A reusable infrastructure property (catalog-defined, IIM-T###) |
| **Chain** | Composition | One complete annotated observation of a campaign |
| **Pattern** | Abstraction | A chain with entities abstracted away; the structural shape |

**Layered interpretation** is a design property: entities and relations are pure observations that can be shared across analysts who disagree about interpretation. Roles and techniques are interpretations that sit on top. Chains bind interpretation to observation. Patterns strip observation and keep only interpretation.

## 3. Entities

An entity is an observed artifact. It carries no interpretation.

### 3.1 Required Fields

An entity MUST have:

- `id` - a chain-local identifier, unique within its chain. Alphanumeric, underscore, and hyphen only. 1 to 64 characters.
- `type` - one of the allowed types (§3.2).
- `value` - the raw value of the artifact. Non-empty.

### 3.2 Allowed Types

| Type | Meaning | Example value |
|------|---------|---------------|
| `url` | A full URL | `https://phish.example/lure.pdf` |
| `domain` | A DNS name | `c2.duckdns.org` |
| `ip` | An IPv4 or IPv6 address | `185.234.72.19` |
| `file` | A file name or filesystem path | `loader.hta` |
| `hash` | A cryptographic hash value | `c8f9a2d4e6b7...` (SHA-256) |
| `email` | An email address | `lure@sender.example` |
| `certificate` | A TLS certificate (typically SHA-256 fingerprint) | `a1b2c3d4...` |
| `asn` | An Autonomous System number | `AS12345` or `12345` |

Implementations MUST NOT accept types outside this list at IIM v1.1. New types require a spec version bump.

### 3.3 Optional Fields

An entity MAY include:

- `observed_at` - RFC 3339 timestamp of first observation
- `source` - identifier of the observation source (sensor name, analyst handle, feed name)
- `evidence` - array of free-form references (sample hashes, report URLs, case numbers)

### 3.4 Semantics

Entities are **pure observations**. Two analysts MUST be able to agree that an entity exists without agreeing on what it means. No role, technique, or attribution information is carried at the entity level.

Entity `value` is case-preserving and not normalized by the spec. Implementations MAY normalize (lowercasing domains, trimming whitespace) at import time, but MUST NOT modify values stored in persisted chains.

## 4. Relations

A relation is a directed, typed connection between two entities.

### 4.1 Required Fields

A relation MUST have:

- `from` - the source entity's id, which MUST exist in the enclosing chain's `entities` array
- `to` - the target entity's id, which MUST exist in the enclosing chain's `entities` array
- `type` - one of the allowed relation types (§4.2)

### 4.2 Allowed Relation Types

| Type | Meaning |
|------|---------|
| `download` | The source artifact retrieved the target artifact |
| `redirect` | HTTP or DNS redirection from source to target |
| `drops` | The source artifact (archive, loader) produced the target as a file on disk |
| `execute` | The source artifact started execution of the target |
| `connect` | The source established a network connection to the target |
| `resolves-to` | The source (name) was resolved to the target (address) |
| `references` | The source points to the target without transferring control (e.g. dead-drop post referencing a C2 hostname) |
| `communicates-with` | Generic bidirectional communication when no directional semantics is available |

Implementations SHOULD reject non-standard relation types but MAY accept them with a warning for experimental use.

### 4.3 Optional Fields

A relation MAY include:

- `sequence_order` - a non-negative integer indicating observed ordering. When present, different relations within a chain SHOULD have distinct values. Gaps are allowed (sequence 1, 2, 5, 7 is valid).
- `observed_at` - RFC 3339 timestamp of the observed interaction
- `confidence` - one of `confirmed`, `likely`, `tentative` (§6.4)

### 4.4 Semantics

Relations describe **what one entity did to another**. They do not describe roles. A `download` relation is still pure observation: the source retrieved the target. The interpretation of *what that target is for* belongs at the chain position (§5).

Chain-position reconstruction (§5.5) uses `sequence_order` when present and falls back to declaration order in `relations` when absent.

## 5. Chains

A chain is the complete annotated observation of one campaign flow. It is the **atomic analytical unit** of IIM.

### 5.1 Required Fields

A chain MUST have:

- `iim_version` - the specification version this chain conforms to
- `chain_id` - a stable identifier for this chain. 3 to 128 characters, alphanumeric plus `.`, `_`, `-`. Starts with an alphanumeric.
- `entities` - non-empty array of entity objects (§3)
- `chain` - non-empty array of chain position objects (§5.3)
- `relations` - array (possibly empty) of relation objects (§4)

### 5.2 Optional Fields

A chain MAY include:

- `title` - human-readable chain title
- `description` - free-form prose describing the campaign
- `actor_id` - attribution identifier (e.g. MB-0001). Attribution remains optional and is not validated by IIM.
- `observed_at` - RFC 3339 timestamp when the chain was first observed as a whole
- `confidence` - chain-level confidence (§6.4)
- `needs_review` - boolean flag for chains imported from less-expressive formats (§10)
- `import_source` - string identifying the origin format when the chain was imported (e.g. `stix-2.1`)
- `attack_annotations` - optional array of ATT&CK technique references (§11)

### 5.3 Chain Positions

A chain position assigns a role and techniques to one entity within the chain.

A chain position MUST have:

- `entity_id` - reference to an entity's id; MUST exist in the chain's entities
- `role` - one of the five allowed roles (§5.4)

A chain position MAY have:

- `techniques` - array of IIM technique IDs (format `IIM-T###`). IDs MUST match the `^IIM-T[0-9]{3}$` pattern. Unknown-to-catalog IDs are permitted with a validator warning but must still match the format.
- `role_confidence` - confidence in the role assignment
- `technique_confidence` - confidence in the technique annotations
- `needs_review` - boolean flag when role or technique was derived heuristically
- `review_notes` - free text explaining what requires review

### 5.4 The Five Roles

| Role | Job |
|------|-----|
| `entry` | Initial foothold; the user-facing start of the chain |
| `redirector` | Intermediate node that routes traffic between other positions |
| `staging` | Intermediate container, loader, or transport artifact |
| `payload` | Terminal executable performing the objective |
| `c2` | Command and control endpoint |

**Roles are chain-scoped.** The same entity MAY appear in different chains with different roles. Within a single chain, each chain-position entry declares exactly one role; an entity appearing at multiple chain positions (representing multiple observations of the same artifact at different stages) receives one role per appearance. This is a rare case and SHOULD be flagged with `needs_review`.

### 5.5 Chain Order

Chain positions are ordered by their appearance in the `chain` array. Position index 0 is the first declared position.

Relations with `sequence_order` describe the observed flow through the chain. Implementations that render or traverse chains:

1. SHOULD use `sequence_order` when present
2. Otherwise SHOULD use relation declaration order
3. MUST NOT infer ordering from entity or chain-position declaration order alone

### 5.6 Chain Validity Rules

A chain is valid when:

1. All required fields are present and well-formed
2. Entity IDs are unique within the chain
3. Every `entity_id` in `chain` references an existing entity
4. Every `from` and `to` in `relations` references an existing entity
5. All technique IDs match the `IIM-T###` format
6. If `sequence_order` is used on relations, duplicate values trigger a warning but not an error

Implementations MUST report all violations. Warning-level issues (unknown technique IDs, unusual relation types, duplicate sequence numbers) MUST be surfaced but MUST NOT reject the chain.

## 6. Patterns

A pattern is a chain with entities abstracted away. It describes the structural shape of a workflow, independent of specific artifacts.

### 6.1 Required Fields

A pattern MUST have:

- `pattern_id` - stable identifier following `<PREFIX>-F-####` (e.g. `MB-F-0023`). Prefix is 2 to 6 uppercase letters identifying the publisher namespace.
- `name` - human-readable name
- `iim_version`
- `shape` - non-empty array of shape positions (§6.2)
- `relations` - array (possibly empty) of pattern relations (§6.3)

### 6.2 Shape Positions

Each shape position MUST have a `role`. A shape position MAY carry:

- `techniques` - array of technique IDs
- `optional` - boolean; when true, a matching chain MAY omit this position

### 6.3 Pattern Relations

Pattern relations use position indices rather than entity IDs. Each MUST have:

- `from_position` - integer in `[0, len(shape) - 1]`
- `to_position` - integer in `[0, len(shape) - 1]`
- `type` - one of the allowed relation types (§4.2)

### 6.4 Match Semantics

A pattern declares `match_semantics` controlling how candidate chains are compared against it:

| Value | Behavior |
|-------|----------|
| `strict` | Identical role sequence, identical technique sets per position, identical relation types, identical sequence ordering |
| `structural` | Identical role sequence and relation types; technique sets may be a superset in the candidate (default) |
| `fuzzy` | Roles roughly align; individual techniques may differ; used only for analyst hypothesis formation |

`structural` is the default and the intended mode for published feeds. Pattern match semantics MUST NOT be escalated during matching - a pattern declared as `strict` MUST NOT be loosened at match time.

### 6.5 Optional Fields

A pattern MAY include:

- `description`
- `derived_from` - array of chain IDs this pattern was abstracted from
- `actor_ids` - array of actor identifiers this pattern is known to represent
- `tags` - array of free-form labels (max 40 chars each)

### 6.6 Confidence

IIM v1.1 introduces explicit confidence modeling. Allowed values: `confirmed`, `likely`, `tentative`.

Confidence MAY be attached to:

- A chain as a whole (overall confidence in the analysis)
- A chain position's role assignment (`role_confidence`)
- A chain position's techniques (`technique_confidence`)
- A relation (`confidence`)

Confidence is an analyst judgment, not a measured probability. Implementations MUST NOT attempt to derive numeric probabilities from these values.

## 7. Feeds

A feed is a collection of patterns published together. Feeds are the operational output of IIM.

### 7.1 Required Fields

A feed MUST have:

- `feed_id` - stable identifier for the feed
- `iim_version`
- `publisher` - publisher object containing at minimum a `name`
- `patterns` - array of pattern objects

### 7.2 Publisher Object

Publisher MUST have:

- `name`

Publisher MAY have:

- `contact` - email or URL
- `url` - publisher website
- `public_key` - optional PGP public key for signature verification

### 7.3 Optional Feed Fields

- `name` - human-readable feed title
- `description`
- `tlp` - Traffic Light Protocol marking (`clear`, `green`, `amber`, `amber+strict`, `red`); default `clear`
- `created` - RFC 3339 timestamp of first publication
- `updated` - RFC 3339 timestamp of last update
- `revision` - monotonically increasing integer
- `signature` - detached signature of the patterns array if the publisher signs their feeds

### 7.4 Feed Integrity

Feed consumers MUST check `tlp` before redistribution. Signed feeds MUST have their signatures verified against the publisher's `public_key` before trust is granted.

Feed `revision` MUST be strictly greater than previously consumed revisions of the same `feed_id`.

## 8. Confidence and Evidence

IIM v1.1 introduces confidence as a first-class concept at each interpretive layer. This enables explicit separation of observation confidence from interpretation confidence, and supports workflows where STIX or IOC imports carry low initial confidence until analysts confirm.

The three confidence levels are intentionally coarse:

- `confirmed` - the analyst has first-hand evidence or multi-source corroboration
- `likely` - the annotation is well-supported but not definitively proven
- `tentative` - the annotation is a working hypothesis, often flagged for review

Evidence referenced via the `evidence` field on entities (and future extensions on chain positions) points to external artifacts supporting the observation: sample hashes, report URLs, case numbers. Evidence is free-form at v1.1; a future minor version may introduce structured evidence types.

## 9. Schema

Every IIM document - chain, pattern, or feed - MUST validate against the JSON Schema at:

    https://iim.malwarebox.eu/schema/iim-v1.1-schema.json

A local copy is maintained at `spec/iim-v1.1-schema.json` in the canonical repository. The schema is the normative structural definition; this prose spec is the normative semantic definition. In case of conflict between a schema-allowed construction and a prose rule, the prose rule governs and the schema will be corrected.

### 9.1 Extension Fields

Implementations MAY add custom fields to any object by prefixing the field name with `x_`. The schema explicitly allows `x_`-prefixed properties on every object via `patternProperties`. Fields without the `x_` prefix remain strictly validated and unknown ones are rejected.

This pattern mirrors STIX 2.1 (`x_`-prefixed extensions) and OpenAPI (`x-`-prefixed extensions) and exists for three reasons:

1. **Vendor-specific metadata.** A commercial TIP may annotate chains with `x_tip_score`, `x_tip_tags`, or similar fields that their own tooling reads but other consumers can safely ignore.
2. **Experimentation.** New concepts being trialed before being proposed for the core spec can be prototyped under `x_`-namespaces without forking.
3. **Preservation on round-trip.** The IIM→STIX exporter writes `x_iim_*` fields on STIX objects to preserve IIM semantics. The same pattern works the other way: STIX→IIM imports may carry `x_stix_*` fields preserving STIX-only concepts.

Implementations MUST NOT assume semantics for any `x_`-field defined by another party. Consumers that don't understand an extension field MUST preserve it on pass-through (for formats where that applies) but MAY ignore it for internal logic.

### 9.2 Schema Limitations

The JSON Schema enforces structural constraints but cannot express certain semantic rules:

- **Relation `sequence_order` uniqueness** - the spec recommends unique values per chain, but JSON Schema cannot enforce cross-item uniqueness within an array. Validators check this at the semantic layer.
- **Pattern relation position bounds** - `from_position` and `to_position` must index into the `shape` array, but JSON Schema cannot compare one property value against the length of another array. Validators check this.
- **Entity type-specific validation** - `value` is typed as a non-empty string regardless of `type`. Type-specific validation (URL format, IP address format, hash length) is intentionally deferred to implementations to preserve flexibility. A future minor version may add optional stricter validation.

These limitations are deliberate. Schema-level validation catches structural errors; semantic validators (like the IIM Workbench) layer additional checks on top. Implementations claiming Level 2 (Producer) conformance MUST perform both structural and semantic validation.

## 10. Import from Less-Expressive Formats

STIX 2.1 and similar formats lack three IIM concepts: chain-scoped role semantics, ordered chains, and structured infrastructure techniques. Import from such formats is therefore necessarily an **enrichment workflow**, not a mechanical conversion.

Imported chains MUST:

- Carry `import_source` identifying the origin format
- Set `confidence` to `tentative` at the chain level unless the origin format explicitly supported confidence
- Set `needs_review: true` at the chain level
- Set `needs_review: true` on every chain position whose role or techniques were derived heuristically
- Set `role_confidence: tentative` on heuristically-assigned roles

Imported chains passed through an analyst review workflow MAY be promoted to higher confidence once the analyst explicitly confirms each position.

## 11. Relationship to MITRE ATT&CK

IIM and ATT&CK are complementary, not overlapping. A single campaign can (and usually should) carry both annotations.

A chain MAY include `attack_annotations` as an array of ATT&CK technique references, each with:

- `technique_id` - matching `^T[0-9]{4}(\.[0-9]{3})?$`
- `name` - optional human-readable name
- `tactic` - optional tactic label
- `comment` - optional analyst commentary

ATT&CK annotations on a chain describe **what happens on the victim endpoint**. IIM annotations on the same chain describe **what the infrastructure is and does**. Neither is derivable from the other; neither is redundant.

The `attack_related` field on individual IIM techniques in the catalog (see `techniques/iim-techniques-v1.0.json`) points to **conceptually adjacent** ATT&CK IDs - not equivalences. Consumers MUST NOT treat these as equivalences.

## 12. Versioning

IIM follows semantic versioning at the specification level:

- **Major** (2.0) - breaking changes to the data model, role taxonomy, or relation semantics
- **Minor** (1.1, 1.2) - backward-compatible additions (new optional fields, new confidence semantics, new relation types via expansion)
- **Patch** (1.0.1) - clarifications and corrections to text or schema without semantic change

The technique catalog follows its own versioning independent of the specification version (see `techniques/README.md`).

Consumers MUST check `iim_version` on every document and MUST reject documents with a `iim_version` major exceeding their supported major. Minor version differences MUST be accepted with best-effort interpretation of new fields.

## 13. Security Considerations

### 13.1 Feed Integrity

Feeds are a trust-delegation mechanism. Consumers accepting patterns from external publishers effectively grant those publishers influence over defensive blocking. Implementations SHOULD:

- Verify detached signatures when publishers provide `public_key`
- Track `revision` monotonicity to detect rollback or replay
- Respect `tlp` markings in redistribution workflows
- Sandbox pattern evaluation to prevent denial-of-service through maliciously-crafted patterns (e.g. deeply recursive relation graphs)

### 13.2 Sensitive Content

Entity `value` fields may contain sensitive material - PII in email addresses, victim-identifying URLs, host-specific file paths. Publishers are responsible for scrubbing before publication. The spec does not define scrubbing semantics; implementations SHOULD support entity-value redaction workflows.

### 13.3 Attribution

IIM deliberately does not validate or reason about `actor_id`. Attribution is an analytical outcome outside the structural model. Implementations MUST NOT use the presence of an actor ID as evidence of attribution - it is a pointer to an external actor record, nothing more.

## 14. Non-Normative Examples

See `reference-chains/` in the canonical repository for fully annotated real-world chains. See the IIM Workbench (`tools/workbench/`) for an interactive builder and validator.

A minimal valid chain:

    {
      "iim_version": "1.1",
      "chain_id": "minimal-example",
      "entities": [
        { "id": "e1", "type": "url", "value": "https://a.example" },
        { "id": "e2", "type": "domain", "value": "b.example" }
      ],
      "chain": [
        { "entity_id": "e1", "role": "entry" },
        { "entity_id": "e2", "role": "c2" }
      ],
      "relations": [
        { "from": "e1", "to": "e2", "type": "connect", "sequence_order": 1 }
      ]
    }

A minimal valid pattern:

    {
      "pattern_id": "MB-F-0001",
      "name": "Minimal Pattern",
      "iim_version": "1.1",
      "shape": [
        { "role": "entry" },
        { "role": "c2" }
      ],
      "relations": [
        { "from_position": 0, "to_position": 1, "type": "connect" }
      ]
    }

## 15. Document Metadata

- **Prior versions:** IIM v1.0 (stable)
- **Successor:** none (v1.1 is the current draft)
- **Reference implementation:** IIM Workbench at `tools/workbench/`
- **Canonical repository:** `https://github.com/malwarebox/iim` (or your actual location)

End of specification.