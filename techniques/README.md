# IIM Technique Catalog

This directory contains the machine-readable catalog of IIM techniques and the design principles governing it.

## Files

| File | Purpose |
|------|---------|
| `iim-techniques-v1.0.json` | The canonical technique catalog. 26 techniques across 5 categories. |
| `README.md` | This file - design principles, scope boundary, governance. |

## What Is a Technique?

An IIM technique is a **reusable, structural property of adversary infrastructure**. Each technique describes something the infrastructure *is* or *does*, independent of what any specific payload does after it reaches a victim.

Every technique in the catalog describes one of:

1. **Hosting** - where infrastructure physically or logically lives
2. **Resolution** - how names and locators map to concrete endpoints
3. **Routing** - how traffic moves through intermediate layers
4. **Gating** - how infrastructure filters who receives what
5. **Composition** - how transported artifacts are structurally wrapped

## The Scope Boundary Against ATT&CK

IIM and MITRE ATT&CK are **complementary, not overlapping**. The boundary is enforced strictly:

| If the technique describes... | It belongs in... |
|------------------------------|------------------|
| Where infrastructure is hosted | IIM |
| How a name resolves to an IP | IIM |
| How traffic is routed | IIM |
| Who gets what response from a server | IIM |
| How a delivered archive is structured | IIM |
| What a payload does when executed | **ATT&CK** |
| How a binary persists on disk | **ATT&CK** |
| Which process injection method is used | **ATT&CK** |
| How data is encrypted or exfiltrated from a host | **ATT&CK** |
| What registry keys or files are modified | **ATT&CK** |

The **boundary test** for any proposed technique:

> *Does this describe the adversary's infrastructure and how it behaves as served, or does it describe what happens after a payload lands on the victim?*

If the answer is "after the payload lands," the technique belongs in ATT&CK, not IIM. Proposals that violate this boundary are rejected by design - not because they are invalid techniques, but because they are the wrong framework's techniques.

## Relationship to ATT&CK Sub-Techniques

Where an ATT&CK sub-technique describes behavior that IIM also has structural language for (e.g., `T1568.002` Dynamic Resolution: Domain Generation Algorithms vs. IIM-T009 DGA), both annotations coexist on the same campaign. The `attack_related` field in each technique lists conceptually adjacent ATT&CK IDs - but these are *not equivalences*. ATT&CK describes what the malware does (query many domains); IIM describes what the infrastructure *is* (a resolution substrate with algorithmically-generated candidates).

This distinction matters analytically: ATT&CK annotations age as malware rebuilds and ATT&CK versions update; IIM annotations age with the operational workflow of the adversary, which is far more stable.

## Technique Anatomy

Every technique in the catalog has the following fields:

| Field | Purpose |
|-------|---------|
| `id` | Stable identifier (IIM-T###). Never reassigned. |
| `name` | Human-readable short name. |
| `category` | One of: hosting, resolution, routing, gating, composition. |
| `short` | One-line description suitable for UI display. |
| `description` | Full technique description - what it is, how it works, why it exists. |
| `why_infrastructure` | Explicit justification that this is an infrastructure technique and not an endpoint behavior. Required. |
| `observable_indicators` | List of signals a defender or analyst can use to recognize the technique in observed infrastructure. |
| `example` | At least one real or representative example of the technique in the wild. |
| `detection_notes` | Practical guidance on detecting or characterizing the technique. |
| `attack_related` | Array of adjacent ATT&CK IDs (never asserted as equivalences). |
| `introduced_in` | Catalog version in which the technique was introduced. |

The `why_infrastructure` field is mandatory and not decorative. It enforces the scope boundary - if a reviewer cannot justify the technique as infrastructure, the proposal is reconsidered or rejected.

## Categories

### Hosting (IIM-T001 to IIM-T006)

Where and how adversary infrastructure is hosted. Describes the substrate the operation runs on - CDNs, cloud providers, bulletproof hosts, compromised legitimate sites, ephemeral serverless platforms, and trusted third-party content hosts.

### Resolution (IIM-T007 to IIM-T013)

How names or locators are resolved to concrete network endpoints. Covers the discoverability and rotation properties of infrastructure: fast-flux DNS, dynamic DNS abuse, DGAs, disposable registrations, active rotation, TLS-fingerprint reuse, and dead-drop resolvers.

### Routing (IIM-T014 to IIM-T018)

How traffic flows between victim and terminal infrastructure. Covers intermediate layers that redirect, filter, or multiplex: multi-hop redirects, client-side routing, public URL shorteners, traffic distribution systems, and third-party applications used as C2 channels.

### Gating (IIM-T019 to IIM-T023)

How access to infrastructure is restricted to intended victims. Covers filters that accept or deny requests before payload delivery: GeoIP, User-Agent, request fingerprinting, time windows, and single-use tokens.

### Composition (IIM-T024 to IIM-T026)

How artifacts served by infrastructure are structurally composed at the transport layer. Covers archive containers, nested containers, and open directory exposures. Deliberately narrow - does not extend to file-format-specific techniques (those belong in ATT&CK).

## Versioning

The catalog follows semantic versioning.

- **Major** (2.0, 3.0) - reorganization, renumbering, or scope changes
- **Minor** (1.1, 1.2) - new techniques added with new IDs, existing techniques never renumbered
- **Patch** (1.0.x) - text corrections, clarifications, example additions

Existing technique IDs are **stable across the entire catalog lifetime**. Once IIM-T019 refers to "Geofenced Delivery", it will never refer to anything else, even if the technique is later deprecated.

## Deprecation

Techniques are never removed. Deprecation adds two fields to a technique:

```json
{
  "deprecated": true,
  "deprecation_rationale": "...",
  "superseded_by": ["IIM-T0XX"]
}
```

Annotations against deprecated techniques remain valid historical data. Tools should warn when annotating new chains with deprecated techniques but never refuse to load existing annotations.

## Proposing New Techniques

New techniques are proposed via GitHub pull request against this directory. Each proposal must include:

1. **Boundary-test justification** - explicit argument that the technique describes infrastructure and not endpoint behavior
2. **At least two in-the-wild examples** - real observed cases from your research or public reporting
3. **Proposed category assignment** with rationale
4. **All required fields** populated in the JSON entry

Proposals without the boundary-test justification are returned for revision. Proposals conflicting with the scope boundary against ATT&CK are rejected by design - not out of disrespect to the proposal, but to preserve the catalog's value as a non-overlapping complement to ATT&CK.

## Tooling Expectations

Tools consuming this catalog should:

- Load the JSON by `spec_version` and `catalog_version`
- Never hard-code technique counts - always use `technique_index.total_count`
- Validate `attack_related` IDs against the current ATT&CK release when rendering
- Display `why_infrastructure` prominently in any reviewer or editor UI
- Preserve `deprecated` status when annotating - do not silently upgrade to superseding techniques

## License

The technique catalog is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). You may use, adapt, and redistribute the catalog freely with attribution. The JSON schema and tooling are Apache 2.0-licensed separately.

## Citation

If you reference the IIM technique catalog in published work, please cite:

> Dost, R. (2026). Infrastructure Intelligence Model (IIM) Technique Catalog v1.0.
> Malwarebox Research. https://iim.malwarebox.eu
