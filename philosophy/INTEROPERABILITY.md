# IIM Interoperability - STIX, ATT&CK, and Friends

IIM is designed to **compose with existing frameworks**, not compete with them. This document explains how IIM chains and patterns interact with STIX, MITRE ATT&CK, the Diamond Model, and IOC feeds - with concrete code examples for each.

## Quick Reference

| Framework | Relationship | Summary |
|-----------|--------------|---------|
| **MITRE ATT&CK** | Complementary (dual annotation) | IIM = infrastructure, ATT&CK = endpoint behavior |
| **STIX 2.1** | Fully serializable (IIM → STIX), partially importable (STIX → IIM) | IIM data can be exported to STIX without loss; import is enrichment |
| **Diamond Model** | Refinement | IIM provides a structured grammar for the Infrastructure vertex |
| **Kill Chain** | Orthogonal | IIM describes structural composition within each Kill Chain phase |
| **IOC Feeds** | Supersedes | IIM patterns subsume unbounded future IOCs with the same structure |

---

## Part 1 - IIM and MITRE ATT&CK

### The Mental Model

Think of any campaign as having **two independent descriptions**:

- **ATT&CK describes what the adversary did on the victim.** Spearphishing attachment, user execution, scheduled task, credential dumping.
- **IIM describes the infrastructure the adversary built.** Geofenced delivery, RAR container, fingerprinting gate, rotating DDNS C2.

Both descriptions are true at the same time. Neither replaces the other. A complete analysis includes both.

### The Boundary (Simple Version)

```
                ┌─────────────────────────────────┐
                │    WHAT THE INFRASTRUCTURE IS   │
                │         (IIM territory)         │
                └─────────────────────────────────┘
                                │
─────── Adversary sends lure ───┼─── Victim clicks & executes ───────
                                │
                ┌─────────────────────────────────┐
                │   WHAT HAPPENS ON THE VICTIM    │
                │       (ATT&CK territory)        │
                └─────────────────────────────────┘
```

- **Before click:** Infrastructure properties (hosting, resolution, routing, gating, composition) → IIM
- **After click:** Endpoint behaviors (execution, persistence, lateral movement, exfiltration) → ATT&CK

### Dual Annotation - A Concrete Example

Take the Gamaredon chain from `STRUCTURE.md`. Here's what both annotations look like side-by-side:

**IIM annotation:**

```json
{
  "chain": [
    { "entity_id": "e1", "role": "entry",   "techniques": ["IIM-T019"] },
    { "entity_id": "e2", "role": "staging", "techniques": ["IIM-T024"] },
    { "entity_id": "e3", "role": "staging", "techniques": ["IIM-T021"] },
    { "entity_id": "e4", "role": "payload", "techniques": [] },
    { "entity_id": "e5", "role": "c2",      "techniques": ["IIM-T008", "IIM-T011", "IIM-T013"] }
  ]
}
```

**ATT&CK annotation** (as sibling data on the same chain):

```json
{
  "attack_annotations": [
    { "technique_id": "T1566.001", "name": "Phishing: Spearphishing Attachment" },
    { "technique_id": "T1204.002", "name": "User Execution: Malicious File" },
    { "technique_id": "T1059.005", "name": "Command & Scripting Interpreter: Visual Basic" },
    { "technique_id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys" },
    { "technique_id": "T1027.010", "name": "Obfuscated Files or Information: Command Obfuscation" }
  ]
}
```

Both annotations describe the same campaign. **Neither is redundant.** IIM tells you Gamaredon used rotating DDNS with a dead-drop resolver - which you can use to track their infrastructure. ATT&CK tells you Gamaredon uses VBScript execution and registry-based persistence - which you can use to detect their implants on endpoints. Different analyses, different defensive levers.

### When to Use Which

| You want to... | Use |
|----------------|-----|
| Block adversary infrastructure before it reaches users | IIM |
| Detect malicious execution on endpoints | ATT&CK |
| Build a threat actor profile with both infra and behavior | Both |
| Track adversary workflow stability over time | IIM |
| Score detection coverage of EDR against adversary behavior | ATT&CK |
| Predict next campaign's infrastructure shape | IIM patterns |
| Predict next campaign's endpoint TTPs | ATT&CK navigator |

### The `attack_related` Field

Every IIM technique has an `attack_related` field listing ATT&CK IDs that are **conceptually adjacent**. For example, `IIM-T008` (Dynamic DNS Abuse) references `T1568.002` (Dynamic Resolution: DGA/DDNS).

**Important: these are not equivalences.** They are pointers for analysts who want to cross-reference. `IIM-T008` describes a property of the infrastructure ("uses DDNS subdomains as C2"); `T1568.002` describes a malware behavior ("malware resolves dynamically"). Both can be true simultaneously, and the analysis benefits from annotating both.

Tools should render `attack_related` as "See also" links, not as equivalents.

---

## Part 2 - Exporting IIM to STIX 2.1

IIM data serializes losslessly to STIX 2.1. This section shows how.

### Object Mapping

| IIM Concept | STIX 2.1 Equivalent |
|-------------|---------------------|
| Entity (url, domain, ip, file, hash) | `indicator` or `observable` (depending on analytical intent) |
| Entity (infrastructure category) | `infrastructure` |
| Relation | `relationship` |
| Role assignment | Custom property on `infrastructure` object |
| Technique annotation | `attack-pattern` with IIM-namespaced ID, linked via `relationship` |
| Chain | `grouping` containing all the above |
| Pattern | `attack-pattern` + `infrastructure` template, linked via `grouping` |

### Minimal Export Example - A Single Role Position

Take the C2 position from the Gamaredon chain:

```json
{
  "entity_id": "e5",
  "role": "c2",
  "techniques": ["IIM-T008", "IIM-T011", "IIM-T013"]
}
```

Exports to:

```json
{
  "type": "infrastructure",
  "spec_version": "2.1",
  "id": "infrastructure--5f0c4e2a-8a1d-4f7c-b3f1-7e8f9a0b1c2d",
  "created": "2026-01-13T14:22:00.000Z",
  "modified": "2026-01-13T14:22:00.000Z",
  "name": "Gamaredon C2 · c2.duckdns.org",
  "infrastructure_types": ["command-and-control"],
  "x_iim_role": "c2",
  "x_iim_chain_id": "gamaredon-2026-01-13",
  "x_iim_techniques": ["IIM-T008", "IIM-T011", "IIM-T013"]
}
```

Plus one `indicator` for the domain itself:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "created": "2026-01-13T14:22:00.000Z",
  "modified": "2026-01-13T14:22:00.000Z",
  "pattern": "[domain-name:value = 'c2.duckdns.org']",
  "pattern_type": "stix",
  "valid_from": "2026-01-13T00:00:00.000Z",
  "indicator_types": ["malicious-activity"]
}
```

Plus a `relationship` connecting them:

```json
{
  "type": "relationship",
  "spec_version": "2.1",
  "id": "relationship--b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
  "created": "2026-01-13T14:22:00.000Z",
  "modified": "2026-01-13T14:22:00.000Z",
  "relationship_type": "indicates",
  "source_ref": "indicator--a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d",
  "target_ref": "infrastructure--5f0c4e2a-8a1d-4f7c-b3f1-7e8f9a0b1c2d"
}
```

### Full Chain Export

A complete IIM chain exports to a **STIX 2.1 Bundle** containing:

1. One `infrastructure` object per role position (5 for a 5-position chain)
2. One `indicator` object per underlying entity
3. One `relationship` of type `indicates` linking each indicator to its infrastructure
4. One `relationship` of type `communicates-with` / `derived-from` / `related-to` per IIM relation (with `x_iim_relation_type` preserving the precise IIM verb)
5. One `attack-pattern` object per unique IIM technique used in the chain (with IIM-namespaced external reference)
6. One `relationship` of type `uses` linking each infrastructure to its techniques
7. One `grouping` object wrapping the whole chain, with `context: "iim-chain"` and `x_iim_chain_id`

**The complete STIX bundle for the Gamaredon chain** is ~14 objects. Round-tripping back to IIM yields identical data - the export is lossless.

### The `x_iim_` Custom Properties

STIX 2.1 allows custom properties prefixed with `x_`. IIM uses the following:

| Custom Property | Purpose |
|-----------------|---------|
| `x_iim_version` | IIM spec version the chain/pattern conforms to |
| `x_iim_chain_id` | Chain identifier for cross-referencing |
| `x_iim_role` | Role assignment on an infrastructure object |
| `x_iim_techniques` | Array of IIM technique IDs applied at this position |
| `x_iim_sequence_order` | Sequence order on a relationship object |
| `x_iim_relation_type` | Precise IIM relation verb preserved on the relationship |
| `x_iim_match_semantics` | `strict` / `structural` / `fuzzy` on pattern groupings |
| `x_iim_confidence` | Confidence level (`confirmed` / `likely` / `tentative`) |

### The STIX Export Validator

The `tools/validator/` directory (planned v1.0) includes `iim-to-stix` which:

1. Loads an IIM chain or pattern JSON
2. Produces a valid STIX 2.1 Bundle
3. Validates the Bundle against the STIX JSON Schema
4. Emits either the Bundle or validation errors

Usage (planned):

```
iim-to-stix chain.json --output bundle.json --validate
iim-to-stix chain.json --pretty --validate
iim-to-stix feed.json --pattern --output pattern-bundle.json
```

---

## Part 3 - Importing STIX to IIM

### Why It's Partial

IIM → STIX is lossless because STIX is expressive enough to carry IIM's data (via custom properties).

STIX → IIM is **not** lossless, because STIX lacks three structural concepts IIM requires:

| IIM Concept | STIX Support |
|-------------|--------------|
| **Role semantics** | Missing. STIX has `infrastructure_types` as a flat vocabulary - no chain-scoped role assignment. |
| **Ordered chains** | Missing. STIX relationships form an unordered graph; sequence must be reconstructed from timestamps. |
| **Infrastructure techniques** | Missing. STIX maps to ATT&CK for endpoint behavior, but has no vocabulary for infrastructure properties. |

### The Enrichment Workflow

STIX → IIM import is an **enrichment workflow**, not a mechanical conversion:

1. **Extract** STIX `infrastructure`, `indicator`, `malware`, and `relationship` objects from the Bundle
2. **Reconstruct chain candidates** by traversing relationships from entry points (phishing emails, external URLs)
3. **Assign roles heuristically** based on `infrastructure_types` values, relationship directions, and position in the reconstructed sequence
4. **Flag techniques as unassigned** - the import cannot infer IIM techniques from STIX alone; analyst review required
5. **Set confidence to `tentative`** on all heuristically-derived fields; set to `confirmed` only where source data is unambiguous
6. **Emit fields with `needs_review: true`** markers for analyst completion

The output is an IIM chain **skeleton** that captures the STIX data accurately but flags the IIM-specific annotations as requiring human judgment.

### Expected Tool Behavior

The `stix-to-iim` tool (planned v1.0):

```
stix-to-iim bundle.json --output chain-skeleton.json
```

produces output like:

```json
{
  "iim_version": "1.1",
  "chain_id": "imported-from-stix-2026-01-13",
  "import_source": "stix-2.1",
  "confidence": "tentative",
  "needs_review": true,
  "entities": [ ... extracted from STIX indicators ... ],
  "chain": [
    {
      "entity_id": "e1",
      "role": "entry",
      "role_confidence": "likely",
      "techniques": [],
      "needs_review": true,
      "review_notes": "Role inferred from position. Techniques not derivable from STIX source."
    }
    // ...
  ],
  "relations": [ ... with sequence_order inferred from timestamps ... ]
}
```

An analyst then reviews, corrects, and promotes the chain to `confidence: confirmed` when ready.

---

## Part 4 - IIM and the Diamond Model

The Diamond Model of Intrusion Analysis defines four analytical vertices:

- **Adversary** - who
- **Capability** - what tools/malware
- **Infrastructure** - what hosts/networks
- **Victim** - who/what was targeted

IIM is a **structured vocabulary for the Infrastructure vertex**. Where the Diamond Model establishes Infrastructure as an analytical dimension, IIM provides the grammar to populate it.

**Mapping:**

| Diamond Model Vertex | IIM Component |
|---------------------|---------------|
| Adversary | Not in IIM (belongs to actor profiles, e.g., MB-#### actor IDs) |
| Capability | Partially overlaps with IIM Composition techniques |
| Infrastructure | Full IIM chain - entities, roles, techniques, relations |
| Victim | Not in IIM (belongs to victim telemetry, gating annotations reference target attributes) |

A Diamond Model event annotated with IIM looks like:

```
Adversary:      MB-0001 (Gamaredon)
Capability:     Pteranodon malware family
Infrastructure: IIM chain gamaredon-2026-01-13 (see reference-chains/)
Victim:         Ukrainian government entity (gov.ua)
```

The IIM chain is the detailed structure of what the "Infrastructure" label summarizes.

---

## Part 5 - IIM and the Cyber Kill Chain

The Cyber Kill Chain describes **temporal phases of intrusion**. IIM describes **structural composition within each phase**.

They are orthogonal - any Kill Chain phase can have an IIM-annotated chain describing how the infrastructure supporting that phase was composed.

| Kill Chain Phase | IIM Role Positions Typically Involved |
|------------------|---------------------------------------|
| Reconnaissance | Not usually covered by IIM |
| Weaponization | `staging` (archive construction, loader build) |
| Delivery | `entry`, `redirector`, `staging` |
| Exploitation | Typically ATT&CK territory, not IIM |
| Installation | `payload` (in IIM-composition sense) |
| Command & Control | `c2` |
| Actions on Objectives | Typically ATT&CK territory |

A Delivery-phase chain might use IIM to describe: "A URL-shortener redirect leads to a TDS that delivers a geofenced archive containing a fingerprinting loader." That's IIM structure within one Kill Chain phase.

---

## Part 6 - IIM Patterns vs. Traditional IOC Feeds

### The Core Difference

An **IOC feed** publishes point-in-time artifacts:

```
evil1.duckdns.org
evil2.duckdns.org
185.234.72.19
185.234.72.20
c8f9a2d4e6b7...
```

These decay within days. The adversary rotates; the IOCs become stale.

An **IIM pattern feed** publishes structural descriptions:

```json
{
  "pattern_id": "MB-F-0023",
  "name": "RAR-HTA Delivery to DynDNS C2",
  "shape": [ ... role positions ... ],
  "match_semantics": "structural"
}
```

This stays valid as the adversary rotates, because it describes the *workflow*, not the specific artifacts.

### Both Coexist

IOC feeds and pattern feeds are not mutually exclusive:

- **IOC feeds** give you immediate blocking power for the next 24–72 hours
- **Pattern feeds** give you sustained detection capability over months

A mature defensive posture uses both. Match new infrastructure against pattern feeds to flag it for investigation, and publish the specific IOCs discovered through pattern-matching to the IOC feed for fast-track blocking.

### Feeding Back

The IIM-to-IOC direction is deterministic: any IIM chain produces a set of IOCs (the values of the `entities`). Published as a fallback.

The IOC-to-IIM direction is **not automatic**: IOCs lack structural context. An analyst must hypothesize the pattern from a set of related IOCs, then validate the hypothesis against multiple observations. This is exactly the work IIM is designed to make explicit and reviewable.

---

## Part 7 - Practical Recipes

### Recipe 1 - Annotate a campaign with both IIM and ATT&CK

```
1. Record entities (files, domains, URLs, hashes)
2. Record relations (download, drops, connect) with sequence_order
3. Assign IIM roles to each entity position
4. Annotate IIM techniques at each role position
5. Separately annotate ATT&CK techniques on the campaign
6. Publish both annotations together; neither replaces the other
```

### Recipe 2 - Export a chain to STIX for MISP ingestion

```
1. Validate your IIM chain: `iim-validator chain.json`
2. Export to STIX: `iim-to-stix chain.json --output bundle.json --validate`
3. Upload the STIX bundle to MISP or your TIP of choice
4. MISP infrastructure objects retain x_iim_ custom properties
5. Round-tripping back to IIM (via stix-to-iim) yields the original chain
```

### Recipe 3 - Enrich a STIX bundle from a third-party feed with IIM

```
1. Import the STIX bundle: `stix-to-iim bundle.json --output skeleton.json`
2. Review the skeleton - all role assignments and techniques are marked needs_review
3. Fill in techniques based on analyst knowledge
4. Upgrade confidence from tentative to confirmed where applicable
5. Re-export to STIX: the bundle now carries IIM-enriched custom properties
6. Share the enriched bundle upstream if the original publisher accepts IIM-annotated STIX
```

### Recipe 4 - Build a pattern feed from multiple observed chains

```
1. Collect 3+ IIM chains from the same actor showing the same structure
2. Abstract entities - replace values with role positions
3. Find the common shape (identical roles, identical technique sets)
4. Codify as a pattern with match_semantics: "structural"
5. Publish to feeds/pattern-feeds/ with a stable pattern ID
6. Downstream consumers match the pattern against new infrastructure continuously
```

---

## Part 8 - Positioning Summary

IIM is **not** a replacement for any existing framework. It is the missing layer between IOCs and ATT&CK:

```
           Stable   ▲
                    │  ATT&CK (behavior)
                    │
                    │  IIM patterns  ← this is new
                    │
                    │  IIM chains    ← this is new
                    │
                    │  IOC feeds
           Ephemeral▼
```

ATT&CK is stable because it abstracts away implementation. IOCs are ephemeral because they capture point-in-time state. IIM fills the middle: stable enough to publish as a feed, specific enough to trigger collection, and explicit enough to be reviewed and improved by humans.

If you use only IOCs, you lose the adversary within days. If you use only ATT&CK, you lose the operational detail needed to actually track infrastructure. IIM gives you the structural middle - and composes with both neighbors on either side.

---

## One More Thing

Interoperability is only real if the tooling exists. The v1.0 release provides the schemas and documentation; v1.1 ships the `iim-to-stix` and `stix-to-iim` validators as reference implementations.

If you build tooling for IIM and want it referenced here, open a pull request. If you need a specific export format that isn't supported, open an issue and describe the use case.

Frameworks succeed when they are easy to compose. IIM is designed that way.
