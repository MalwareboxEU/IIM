# IIM Structure - Explained

This document walks through how IIM is organized and what each piece is for. If you've never used IIM before, start here.

## The 30-Second Version

IIM describes **adversary infrastructure** the same way a grammar describes a sentence. Just as a sentence has nouns, verbs, and structure, a cyber campaign's infrastructure has:

- **Entities** - the nouns (a domain, a file, an IP)
- **Relations** - the verbs (this downloaded that, this redirected there)
- **Roles** - what job each noun plays (entry point, C2, payload)
- **Techniques** - reusable patterns the adversary applies (fast-flux DNS, geofenced delivery)
- **Chains** - a complete annotated sequence of one observed campaign
- **Patterns** - abstract shapes that match many future chains

That's the whole model. The rest is detail.

## Why Five Layers?

Infrastructure analysis has been stuck between two extremes for a decade:

- **IOC feeds** tell you that `evil.duckdns.org` resolved to `1.2.3.4` yesterday. Useful for 24 hours. Useless after that.
- **ATT&CK** tells you the adversary uses "Dynamic Resolution." Useful forever, but too abstract to trigger collection.

IIM fills the gap by separating **what was observed** (entities, relations) from **what it means** (roles, techniques, patterns). You can change the interpretation without losing the observation, and you can share the observation without forcing your interpretation on others.

## Layer 1 - Entities

An entity is something you observed. That's it. No judgment, no attribution, no meaning.

```json
{ "id": "e1", "type": "url",    "value": "https://phish.example/lure.pdf" }
{ "id": "e2", "type": "file",   "value": "lure.rar" }
{ "id": "e3", "type": "domain", "value": "c2.duckdns.org" }
{ "id": "e4", "type": "ip",     "value": "185.234.72.19" }
```

**Allowed types:** `url`, `domain`, `ip`, `file`, `hash`, `email`, `certificate`, `asn`.

**Rule:** an entity is pure observation. The `value` field is the raw artifact. Any interpretation goes on a higher layer.

**Why this matters:** two analysts can agree that `evil.duckdns.org` was observed - even if they disagree about what role it played or which actor it belongs to. Keeping observation separate from interpretation means you can share data even when you disagree about meaning.

## Layer 2 - Relations

A relation is a directed connection between two entities. It describes what one entity *did to* another.

```json
{ "from": "e1", "to": "e2", "type": "download", "sequence_order": 1 }
{ "from": "e2", "to": "e3", "type": "drops",    "sequence_order": 2 }
{ "from": "e3", "to": "e4", "type": "connect",  "sequence_order": 3 }
```

**Common relation types:**

| Type | Meaning |
|------|---------|
| `download` | One artifact fetched another |
| `redirect` | One URL sent traffic to another |
| `drops` | An archive or loader produced another file |
| `execute` | One artifact ran another |
| `connect` | A file or process contacted a host |
| `resolves-to` | A name resolved to an IP |
| `references` | A dead-drop post points to an endpoint |

**The `sequence_order` field** records the order in which you observed these steps. It's how IIM reconstructs a chain from individual observations.

**Why this matters:** relations are *still observations*, not interpretations. You observed that `lure.rar` was downloaded from `phish.example`. You didn't yet declare it was the "entry point" - that's a higher-layer judgment.

## Layer 3 - Roles

A role is the **job** an entity plays **in one specific chain**. Think of it as casting: the same actor can play different characters in different productions.

The five roles:

| Role | What It Does | Typical Example |
|------|--------------|-----------------|
| `entry` | Initial foothold; the user-facing start of the chain | Phishing URL, malicious email attachment |
| `redirector` | Routes traffic from one hop to the next | URL shortener, compromised redirect page |
| `staging` | Intermediate container, loader, or transport | RAR archive, HTA loader, downloader script |
| `payload` | Terminal executable performing the objective | Infostealer binary, ransomware executable |
| `c2` | Command-and-control endpoint | DuckDNS hostname, Telegram bot, Cobalt Strike teamserver |

**Important: roles are chain-scoped.** The same domain can be an `entry` in Monday's campaign and a `c2` in Tuesday's. Roles describe the job in *this* specific chain, not the inherent nature of the entity.

```json
{ "entity_id": "e1", "role": "entry",   "techniques": ["IIM-T019"] }
{ "entity_id": "e2", "role": "staging", "techniques": ["IIM-T024"] }
{ "entity_id": "e3", "role": "c2",      "techniques": ["IIM-T008", "IIM-T011"] }
```

**Why this matters:** role assignment is where observation becomes interpretation. It's the first place analysts can disagree. Making it explicit (rather than implicit in relations) means the disagreement is visible and discussable.

## Layer 4 - Techniques

A technique is a **reusable property of infrastructure** - something the adversary did *to build or operate their infrastructure*, which can be recognized across many campaigns.

IIM v1.0 defines 26 techniques in 5 categories:

- **Hosting** (6) - where infrastructure lives. CDN Abuse, Cloud Hosting, Bulletproof, Compromised Legitimate, Ephemeral Workers, Living-off-Trusted-Sites.
- **Resolution** (7) - how names resolve. Fast-Flux DNS, Dynamic DNS, DGA, Disposable Domains, Domain Rotation, TLS Reuse, Dead-Drop Resolver.
- **Routing** (5) - how traffic flows. Multi-Hop Redirect, Client-Side Redirect, Public Shorteners, TDS, Third-Party Apps as C2.
- **Gating** (5) - who gets what response. Geofenced, User-Agent, Request Fingerprinting, Time-Window, Single-Use Token.
- **Composition** (3) - how artifacts are packaged. Archive Container, Nested Container, Open Directory.

Techniques attach to role positions - the entity playing a role in this chain exhibits these techniques.

**The scope boundary vs. ATT&CK:** IIM techniques describe *infrastructure properties*. They never describe what a payload *does* after execution. If a technique describes endpoint behavior (process injection, registry persistence, credential dumping), it belongs in ATT&CK, not IIM. See `INTEROPERABILITY.md` for how both frameworks work together.

**Why this matters:** techniques are what survive IOC rotation. Gamaredon rotates domains every 3 hours, but has used `IIM-T008` Dynamic DNS Abuse continuously for over a decade. If you track the technique instead of the domains, you don't lose the adversary when they rotate.

## Layer 5 - Chains

A chain is a **complete annotated observation of one campaign flow**. It combines entities, relations, role assignments, and technique annotations into a single self-contained document.

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
    { "entity_id": "e1", "role": "entry",   "techniques": ["IIM-T019"] },
    { "entity_id": "e2", "role": "staging", "techniques": ["IIM-T024"] },
    { "entity_id": "e3", "role": "staging", "techniques": ["IIM-T021"] },
    { "entity_id": "e4", "role": "payload", "techniques": [] },
    { "entity_id": "e5", "role": "c2",      "techniques": ["IIM-T008", "IIM-T011", "IIM-T013"] }
  ],
  "relations": [
    { "from": "e1", "to": "e2", "type": "download", "sequence_order": 1 },
    { "from": "e2", "to": "e3", "type": "drops",    "sequence_order": 2 },
    { "from": "e3", "to": "e4", "type": "execute",  "sequence_order": 3 },
    { "from": "e4", "to": "e5", "type": "connect",  "sequence_order": 4 }
  ]
}
```

**Reading the chain:** a user clicks a geofenced URL, downloads a RAR archive, which drops an HTA loader that fingerprints the request, which executes the Pteranodon payload, which connects to a DuckDNS C2 that rotates hourly and is published via dead-drop.

**Why this matters:** one chain is one campaign observation. It's the atomic unit IIM operates on - reviewable, auditable, and reproducible.

## Layer 6 - Patterns

A pattern is a **chain with the entities abstracted away**. It describes the *shape* of a workflow without committing to specific domains, files, or IPs.

```json
{
  "pattern_id": "MB-F-0023",
  "name": "RAR-HTA Delivery to DynDNS C2",
  "iim_version": "1.1",
  "shape": [
    { "role": "entry",   "techniques": ["IIM-T019"] },
    { "role": "staging", "techniques": ["IIM-T024"] },
    { "role": "staging", "techniques": ["IIM-T021"] },
    { "role": "payload", "techniques": [] },
    { "role": "c2",      "techniques": ["IIM-T008", "IIM-T011"] }
  ],
  "relations": [
    { "from_position": 0, "to_position": 1, "type": "download" },
    { "from_position": 1, "to_position": 2, "type": "drops" },
    { "from_position": 2, "to_position": 3, "type": "execute" },
    { "from_position": 3, "to_position": 4, "type": "connect" }
  ],
  "match_semantics": "structural",
  "derived_from": ["gamaredon-2026-01-13", "gamaredon-2025-11-22"]
}
```

**The difference from a chain:** no `value` fields. No specific files or domains. Just the structural shape - "geofenced URL, RAR container, fingerprinting loader, terminal payload, dead-drop-resolved rotating DDNS C2."

**Why this matters:** patterns are **what you publish as a feed**. Where an IOC feed says "block these 47 domains from last week," a pattern feed says "match any infrastructure with this shape - forever." Patterns stay valid as the adversary rotates specific IOCs within the same operational logic.

## Match Semantics

Patterns can match chains in three ways:

| Mode | What Matches |
|------|--------------|
| `strict` | Same roles, same techniques, same relations, same order |
| `structural` | Same roles and relation shape; techniques can be a superset |
| `fuzzy` | Roles roughly align; individual techniques may differ; used for early-stage hypothesis formation |

Strict matching is rare - it's mostly useful for identifying replays of identical infrastructure. Most pattern feeds use structural matching. Fuzzy matching is analyst-assisted and not suitable for automated blocking.

## Putting It All Together

The lifecycle of an IIM analysis:

```
┌────────────────────┐
│ 1. Observe         │  You see things. URLs, files, DNS queries.
│    entities        │  No interpretation yet.
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ 2. Record          │  Link the observations. X downloaded Y. Y
│    relations       │  dropped Z. Observations remain neutral.
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ 3. Assign          │  First interpretation: X is the entry point,
│    roles           │  Y is staging, Z is payload. This is judgment.
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ 4. Annotate        │  Recognize reusable properties: geofenced,
│    techniques      │  fingerprinted, rotating DDNS. Also judgment.
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ 5. Publish         │  The complete annotated observation. One
│    chain           │  campaign, one document.
└─────────┬──────────┘
          │
┌─────────▼──────────┐
│ 6. Abstract to     │  Strip the specific entities. What remains is
│    pattern         │  the shape - usable as a feed.
└────────────────────┘
```

Each step adds interpretation on top of the previous one. You can stop at any layer and the work is still useful - a chain without patterns is still valuable research; entities without relations are still valid IOCs.

## Common Questions

**Do I have to annotate everything?**
No. A partial chain is still valid. If you only observed the delivery stages and didn't see C2, your chain ends at the payload. Mark unknowns explicitly rather than guessing.

**What if two analysts disagree on role assignment?**
That's exactly what the layering is designed for. The entities and relations are shared observations - the role disagreement is isolated to Layer 3 and doesn't contaminate the underlying data.

**Can one entity have multiple roles?**
In one chain, no - an entity plays exactly one role at one position. Across multiple chains, yes - the same domain can be `entry` in one chain and `c2` in another. Roles are chain-scoped.

**How do I know which techniques to annotate?**
If the technique describes a property of the *infrastructure*, annotate it on the relevant role position. If it describes what the payload *does* when executed, it belongs in ATT&CK, not IIM. See `techniques/README.md` for the boundary test.

**Does IIM replace STIX or ATT&CK?**
No. IIM is designed to compose with both. See `INTEROPERABILITY.md` for how.

## Repository Structure - What Lives Where

```
.
├── README.md                          overview, quick-start, design philosophy
├── STRUCTURE.md                       this file - the model explained
├── INTEROPERABILITY.md                STIX export, ATT&CK integration, other frameworks
│
├── spec/
│   ├── iim-v1.1-spec.md               full technical specification
│   ├── iim-v1.1-schema.json           JSON Schema for chains and patterns
│   └── positioning.md                  philosophical positioning vs. ATT&CK, STIX, Diamond Model
│
├── techniques/
│   ├── iim-techniques-v1.0.json        26-technique catalog (the canonical file)
│   └── README.md                       catalog governance and scope boundary
│
├── reference-chains/                   annotated real campaigns
│   ├── mb-0001-gamaredon/
│   ├── mb-0002-apt28/
│   └── ...
│
├── feeds/
│   └── pattern-feeds/                  published pattern feeds (JSON)
│
└── tools/
    └── validator/                      CLI tool for schema validation
```

Start reading at `README.md` for a high-level view, then come here for the model, then go to `techniques/README.md` for the catalog principles, then `INTEROPERABILITY.md` if you want to integrate with STIX or ATT&CK workflows.

## One More Thing

IIM is deliberately a small model. Five layers, twenty-six techniques, five roles. The whole framework fits in your head once you've read the examples.

That's the point. A framework that requires a PhD to use is a framework nobody uses. IIM is designed so an analyst with a day's familiarity can already produce valid chains - and an analyst with a week's experience can contribute new patterns to a shared feed.

If anything in this document was unclear, open an issue. Documentation gaps are bugs.
