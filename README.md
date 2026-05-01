<div align="center">

# IIM 
<img src="iim-logo.svg" alt="drawing" width="200"/>

### Infrastructure Intelligence Model

*A structural framework for modeling the operational infrastructure behind cyber campaigns.*

[**Website**](https://iim.malwarebox.eu) · [**IIM Workbench**](https://github.com/MalwareboxEU/IIM-Workbench) · [**Specification**](https://github.com/MalwareboxEU/IIM/blob/main/spec/iim-v1.1-spec.md) · [**Technique Catalog**](./techniques/iim-techniques-v1.0.json) · [**Malwarebox**](https://malwarebox.eu)

---

</div>

## What is IIM?

IIM is a structural framework that sits **between IOCs and MITRE ATT&CK** describing how adversary infrastructure is actually composed, routed, gated, and resolved. It is the missing layer that neither indicator feeds nor behavioral taxonomies address.

- **IOCs** describe what existed at a moment in time. They decay within days.
- **ATT&CK** describes what adversaries do at the endpoint level. It deliberately abstracts away implementation.
- **IIM** describes the operational infrastructure itself - structural, stable across campaigns, resistant to rotation.

IIM does not replace ATT&CK or STIX. It complements them. A campaign is annotated on both axes independently; neither annotation is redundant.

> *Indicators rotate. Actors don't. Infrastructure patterns outlive both.*

## Why It Exists

The infrastructure layer has been unmodeled for over a decade. The Diamond Model gestures at an "Infrastructure" vertex but never developed a structural vocabulary for what lives there. STIX has Infrastructure objects but treats them as metadata rather than analytical units. ATT&CK deliberately avoids the infrastructure layer to keep its behavioral focus clean.

IIM fills that gap with an explicit grammar: **roles, relations, techniques, chains, patterns**.

## Core Architecture

IIM separates observation from interpretation across four layers:

| Layer | What it describes | Example |
|-------|------------------|---------|
| **Entities** | Observable artifacts without interpretation | `{ type: "url", value: "https://..." }` |
| **Roles** | Semantic position within a chain | `entry`, `redirector`, `staging`, `payload`, `c2` |
| **Relations** | Observed interactions between entities | `redirect`, `download`, `drops`, `connect` |
| **Techniques** | Reusable infrastructure patterns | `IIM-T001` CDN Abuse, `IIM-T019` Geofenced Delivery |

On top of these, two compositional units:

- **Chains** - concrete, directed sequences of role positions describing an observed execution
- **Patterns** - structural abstractions of chains, independent of specific entities, used for federated detection

## The Five Role Types

A chain consists of one or more role positions linked by relations:

| Role | Purpose |
|------|---------|
| `entry` | Initial foothold or user-facing artifact |
| `redirector` | Traffic-steering intermediate node |
| `staging` | Intermediate container, loader, or transport |
| `payload` | Terminal executable or script performing the objective |
| `c2` | Command and control endpoint |

Roles are **chain-scoped**. An entity can hold different roles in different chains, but only one role at a given position within a single chain. This prevents role conflicts when the same infrastructure is reused across campaigns.

## The Technique Catalog (v1.0)

IIM v1.0 defines **26 infrastructure techniques** across five categories:

| Category | Count | Examples |
|----------|:-----:|----------|
| **Hosting** | 6 | CDN Abuse, Cloud Hosting, Bulletproof, Compromised Legitimate, Ephemeral Workers, Living-off-Trusted-Sites |
| **Resolution** | 7 | Fast-Flux DNS, Dynamic DNS, DGA, Disposable Domains, Domain Rotation, Shared TLS Reuse, Dead-Drop Resolver |
| **Routing** | 5 | Multi-Hop Redirect, Client-Side Redirect, Public Redirectors, TDS, Third-Party C2 |
| **Gating** | 5 | Geofenced, User-Agent, Request Fingerprinting, Time-Window, Single-Use Token |
| **Composition** | 3 | Archive Container, Nested Container, Open Directory Exposure |

Every technique describes a **property of infrastructure itself** - hosting, routing, resolution, gating, or structural composition. Endpoint behavior (execution, persistence, file formats) is deliberately excluded and covered by ATT&CK.

See [`techniques/iim-techniques-v1.0.json`](./techniques/iim-techniques-v1.0.json) for the full machine-readable catalog, and [`techniques/README.md`](./techniques/README.md) for the design principles.

## Example · Gamaredon Chain

A Gamaredon January 2026 delivery chain annotated under IIM v1.1:

```json
{
  "iim_version": "1.1",
  "chain_id": "gamaredon-2026-01-13",
  "entities": [
    { "id": "e1", "type": "url",    "value": "https://phish.example/lure.pdf" },
    { "id": "e2", "type": "file",   "value": "lure.rar" },
    { "id": "e3", "type": "file",   "value": "loader.hta" },
    { "id": "e4", "type": "file",   "value": "pteranodon.exe" },
    { "id": "e5", "type": "domain", "value": "c2.duckdns.org" }
  ],
  "chain": [
    { "entity_id": "e1", "role": "entry",      "techniques": ["IIM-T019"] },
    { "entity_id": "e2", "role": "staging",    "techniques": ["IIM-T024"] },
    { "entity_id": "e3", "role": "staging",    "techniques": ["IIM-T021"] },
    { "entity_id": "e4", "role": "payload",    "techniques": [] },
    { "entity_id": "e5", "role": "c2",         "techniques": ["IIM-T008", "IIM-T011", "IIM-T013"] }
  ],
  "relations": [
    { "from": "e1", "to": "e2", "type": "download",  "sequence_order": 1 },
    { "from": "e2", "to": "e3", "type": "drops",     "sequence_order": 2 },
    { "from": "e3", "to": "e4", "type": "execute",   "sequence_order": 3 },
    { "from": "e4", "to": "e5", "type": "connect",   "sequence_order": 4 }
  ]
}
```

The same campaign maps to ATT&CK independently:

- `T1566.001` Spearphishing Attachment
- `T1204.002` User Execution
- `T1059.005` Visual Basic
- `T1547.001` Startup Folder

Both annotations coexist on the chain. Neither is redundant. IIM describes the infrastructure the actor built; ATT&CK describes what happens on the victim.

More fully annotated reference chains are in [`reference-chains/`](./reference-chains/).
(Soon to be released)
## Positioning Relative to Existing Frameworks

IIM is designed to compose with existing standards, not compete with them.

| Framework | What It Covers | What IIM Adds |
|-----------|----------------|---------------|
| **MITRE ATT&CK** | Adversary behavior at endpoint level | Infrastructure layer below endpoint |
| **STIX 2.1** | Data exchange and transport | Structural grammar for infrastructure |
| **Diamond Model** | Event-level analysis (Adversary/Capability/Infrastructure/Victim) | Backbone for the Infrastructure vertex |
| **Kill Chain** | Temporal phases of intrusion | Structural composition within each phase |
| **IOC Feeds** | Point-in-time artifacts | Patterns that outlive specific IOCs |

ACDP scoring (the Malwarebox defensive-prioritization methodology) consumes IIM outputs directly - infrastructure patterns become inputs to actor-specific control prioritization.

## Pattern-Based Feeds

The operational output of IIM is **pattern-based feeds**, not IOC feeds.

Where an IOC feed says *"block these 47 domains that were Gamaredon C2 last week"*, an IIM pattern feed says *"this is the structural pattern of Gamaredon delivery chains, match any infrastructure that follows this structure."*

Pattern feeds are longer-lived than IOCs because they describe the adversary's workflow, not their disposable artifacts. A well-defined pattern continues to match new infrastructure for months as the adversary rotates specific domains, IPs, and hosts within the same operational logic.

See [`feeds/`](./feeds/) for reference pattern feeds.
(Soon to be released)
## Repository Structure

```
.
├── README.md                          this file
├── spec/
│   ├── iim-v1.1-spec.md              the full specification
│   ├── iim-v1.1-schema.json          JSON schema for chains, patterns, feeds
│   └── positioning.md                 relationship to ATT&CK, STIX, Diamond Model
├── techniques/
│   ├── iim-techniques-v1.0.json      26 techniques with definitions and examples
│   └── README.md                      catalog design principles and governance
├── reference-chains/
│   └── ...
├── feeds/
│   └── ...
└── tools/
    └── iim-tools/                     IIM Tools
```

## Status

IIM is currently at **v1.1 draft**. The v1.0 release covered the core model and technique catalog. v1.1 adds:

- Explicit confidence modeling at every interpretive layer
- Evidence as a first-class concept
- Temporal semantics (sequence ordering, observation timestamps)
- Pattern match semantics (strict / structural / fuzzy)
- Federation-ready feed format (publisher identity, TLP, signatures)

v1.1 is targeted for stable release once the validator CLI and reference chain library reach v1.0 themselves.

## Contributing

IIM is an open framework. Contributions are welcome in several forms:

- **Reference chains** - fully annotated real campaigns (from your own research or public reporting) as JSON files in `reference-chains/`
- **Technique proposals** - new infrastructure techniques for future catalog versions, following the scope rule in `techniques/README.md`
- **Tooling** - validators, converters, visualizers, STIX exporters
- **Critique** - challenges to role taxonomy, technique boundaries, or structural decisions

Open an issue or pull request. Technique proposals must include a justification that the proposed technique describes **infrastructure, not endpoint behavior** - the scope boundary against ATT&CK is strict by design.

## Citation

If you reference IIM in published work, please cite:

```
Dost, R. (2026). Infrastructure Intelligence Model (IIM):
A Structural Framework for Modeling Adversary Infrastructure.
Malwarebox Research. https://iim.malwarebox.eu
```

## License

The IIM specification, technique catalog, and reference chains are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Tooling in this repository is released under Apache 2.0. You may use, adapt, and redistribute both freely with attribution.

---

<div align="center">

**Malwarebox** · *In varietate concordia* 🇪🇺

[Website](https://malwarebox.eu) · [Blog](https://blog.synapticsystems.de) · [Kraken](https://kraken.malwarebox.eu) · [ACDP](https://acdp.malwarebox.eu)

</div>
