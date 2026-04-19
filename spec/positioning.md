# Positioning

Why IIM exists, and how it relates to the frameworks that came before it.

This document is non-normative - the specification lives in `iim-v1.1-spec.md`. The purpose here is to explain the design decisions and the boundary choices in plain language, so that adopters understand why IIM looks the way it does.

## The Problem

Infrastructure analysis has been stuck between two extremes for over a decade.

On one side, **IOC feeds** publish point-in-time artifacts - domains, IPs, hashes - that decay within days. The adversary rotates their infrastructure, and last week's IOCs become this week's noise. IOCs are precise but ephemeral.

On the other side, **MITRE ATT&CK** describes adversary behavior at the endpoint, abstracted above any particular implementation. ATT&CK is stable across years but deliberately silent about the infrastructure layer. You can map a campaign to T1566.001 (Spearphishing Attachment) without saying anything about whether the delivery server was geofenced, whether the C2 rotated every three hours, or whether the loader used a fingerprinting gate before serving the real payload.

Between IOCs and ATT&CK, the infrastructure layer has been under-modeled. Analysts have been writing it up in prose for a decade. Nobody has given it a grammar.

## What IIM Is

IIM is that grammar.

Five concepts cover the whole framework: entities, relations, roles, techniques, and the compositional units (chains, patterns) built from them. The concepts separate observation from interpretation deliberately:

- **Entities and relations** are pure observations. Two analysts can agree that `evil.duckdns.org` was contacted by `loader.hta` without agreeing on what that means.
- **Roles and techniques** are interpretations layered on top. This is where disagreement is allowed, visible, and discussable.
- **Chains** bind interpretation to observation. One campaign, one annotated document.
- **Patterns** strip observations away and keep only the shape. A pattern outlives specific IOCs because it describes the adversary's workflow, not their artifacts.

That's the whole framework. The rest - the 26 techniques in the v1.0 catalog, the confidence model in v1.1, the STIX export paths, the JSON Schema - is detail that supports those five concepts.

## The Scope Boundary

The central design decision of IIM is what it **does not** cover.

IIM describes infrastructure properties: hosting, resolution, routing, gating, composition. It stops at the moment a payload reaches the victim. Everything that happens on the victim host - execution, persistence, lateral movement, credential access, exfiltration - belongs to ATT&CK.

This boundary is enforced strictly in the technique catalog (see `techniques/README.md`). Proposed techniques that describe endpoint behavior are rejected not because they are invalid techniques, but because they are the wrong framework's techniques.

The boundary is not philosophical ceremony. It is the source of IIM's operational value. If IIM absorbed endpoint behavior, it would overlap with ATT&CK and force annotators to choose between them - which would make both annotations weaker. By holding the line, IIM ensures that an annotated campaign carries two independent, non-redundant descriptions: what happened on the wire, and what happened on the host.

## Relationship to MITRE ATT&CK

**Complementary.** Dual annotation is the recommended usage.

A campaign annotated under both frameworks looks like:

- **ATT&CK:** T1566.001, T1204.002, T1059.005, T1547.001 - what the malware did on the victim.
- **IIM:** `IIM-T019`, `IIM-T024`, `IIM-T021`, `IIM-T008`, `IIM-T011`, `IIM-T013` - what the infrastructure was and did.

Neither annotation replaces the other. An EDR vendor scoring their detection coverage against ATT&CK gains nothing from IIM. A CTI team tracking adversary infrastructure rotation gains nothing from ATT&CK. Both annotations serve their intended consumer, and both are present on the same campaign without conflict.

The `attack_related` field in the IIM technique catalog lists conceptually adjacent ATT&CK IDs. These are **pointers, not equivalences**. `IIM-T008` Dynamic DNS Abuse and `T1568.002` Dynamic Resolution: DGA sit near each other in concept space, but they describe different things. Tools rendering IIM techniques should surface `attack_related` as "see also," never as "equivalent to."

## Relationship to STIX 2.1

**Fully serializable in one direction. Partially importable in the other.**

IIM → STIX is lossless. Every concept in IIM maps to STIX 2.1 objects, with custom properties (`x_iim_role`, `x_iim_techniques`, `x_iim_chain_id`, etc.) preserving the IIM-specific semantics that STIX has no native vocabulary for. Round-tripping a chain through STIX and back yields identical data.

STIX → IIM is not lossless. STIX lacks three concepts IIM requires:

- **Chain-scoped role semantics.** STIX has `infrastructure_types` as a flat vocabulary. There is no notion of "this infrastructure node is the entry point in this particular chain."
- **Ordered chains.** STIX relationships form an unordered graph. Sequence must be reconstructed from timestamps, which are often missing or unreliable.
- **Infrastructure techniques.** STIX maps to ATT&CK for endpoint behavior but has no vocabulary for infrastructure properties like geofencing, fast-flux, or rotation.

Consequently, STIX → IIM import is an **enrichment workflow**, not a mechanical conversion. Imported chains carry `import_source: "stix-2.1"`, `confidence: "tentative"`, and `needs_review: true` on every heuristically-derived field. An analyst reviews and promotes the chain to higher confidence as they confirm each annotation.

The IIM Workbench (see `tools/workbench/`) implements the lossless export direction. The import direction is a v1.1 target feature.

## Relationship to the Diamond Model

**Refinement.** IIM provides a structured vocabulary for the Infrastructure vertex.

The Diamond Model establishes four analytical dimensions - Adversary, Capability, Infrastructure, Victim - and their meta-features. It provides the frame but not the grammar. Analysts populating the Infrastructure vertex have historically done so in prose.

IIM is the grammar for that vertex. A Diamond event annotated with IIM has an IIM chain attached to its Infrastructure dimension. The Diamond Model's "Infrastructure" label becomes a pointer to a structured chain document rather than a paragraph of narrative.

IIM does not extend into the other Diamond vertices. Adversary attribution (the `actor_id` field in chains) references external actor profiles; it does not model attribution itself. Victim and Capability remain in their own frameworks.

## Relationship to the Cyber Kill Chain

**Orthogonal.** The Kill Chain describes temporal phases of intrusion; IIM describes structural composition within each phase.

A Delivery-phase annotation under the Kill Chain becomes more detailed when extended with IIM: *which infrastructure pattern* delivered the payload, *how the delivery was routed*, *what gating was applied*, *what structural composition was used*. The Kill Chain says "delivery happened"; IIM says how.

Kill Chain phases and IIM chains are composable but not nested. A single IIM chain typically spans multiple Kill Chain phases (from initial access through C2 establishment). Readers who need phase-level annotation can tag individual chain positions with Kill Chain phase labels, but the spec does not require this.

## Relationship to IOC Feeds

**Supersedes at the feed layer. Coexists at the operational layer.**

A traditional IOC feed publishes:

    evil1.duckdns.org
    evil2.duckdns.org
    185.234.72.19
    c8f9a2d4e6b7...

These decay within days as the adversary rotates.

An IIM pattern feed publishes:

    {
      "pattern_id": "MB-F-0023",
      "name": "RAR-HTA Delivery to DynDNS C2",
      "shape": [ {...role positions...} ],
      "match_semantics": "structural"
    }

This remains valid as the adversary rotates, because it describes the workflow, not the artifacts.

Both forms have legitimate uses and should coexist:

- **IOC feeds** give you immediate blocking power for 24–72 hours.
- **Pattern feeds** give you sustained detection capability over months.

A mature defensive posture consumes both. New infrastructure flagged by pattern matching surfaces the specific IOCs, which then feed the IOC side for fast-track blocking. The two feeds reinforce each other; neither is sufficient alone.

## Why "Infrastructure" and Not "Capability"

Readers familiar with the Diamond Model may wonder why IIM sits on the Infrastructure vertex rather than Capability, given that techniques like "Archive Container Delivery" could be argued to describe capability.

The answer: IIM techniques describe **properties of served artifacts and operational substrate**, not properties of what the artifacts *do*. An archive container is a wrapping choice made at the infrastructure layer - the delivery pipeline wraps the payload in RAR before serving. What happens after extraction is capability. The wrapping is infrastructure.

This distinction matters because it determines where a technique goes in the catalog. The boundary test: if the property is observable from the network or from the served artifact without execution, it is infrastructure. If the property requires execution to observe, it is capability, and belongs in ATT&CK.

Composition techniques (T024 Archive Container, T025 Nested Container, T026 Open Directory) are the narrow bridge between infrastructure and capability. They describe structural properties of served artifacts - observable without execution - and nothing more. The catalog deliberately does not extend into file-format-specific techniques (which would stray into capability).

## Who IIM Is For

IIM is built for analysts doing sustained infrastructure tracking. If you:

- Run a threat-intel team that profiles actors over months
- Publish infrastructure-focused feeds to customers or partners
- Need to coordinate multi-analyst work where people disagree about interpretation
- Want your research to compose with other frameworks (ATT&CK, STIX) rather than replace them
- Are tired of IOC feeds that go stale in 48 hours

IIM is for you.

If you are an EDR vendor focused on endpoint detection, IIM is less relevant - ATT&CK and your own behavioral taxonomy will serve you better. If you are a SOC consuming commodity threat feeds, IIM is useful downstream once somebody publishes patterns you can match against; you don't need to produce IIM yourself.

## Non-Goals

IIM deliberately does not:

- **Model attribution.** The `actor_id` field is a pointer to an external actor profile. IIM does not reason about attribution.
- **Score severity or risk.** Severity is a downstream concern. The Adversary Control Defense Prioritization (ACDP) methodology, which does score risk, consumes IIM outputs as inputs.
- **Define victim telemetry.** Victim data lives in its own frameworks. IIM gating techniques reference target attributes (geography, User-Agent profile) without modeling the victim side.
- **Replace STIX for data transport.** STIX is the transport; IIM is the model. A mature workflow uses STIX 2.1 as the wire format carrying IIM-enriched chains.

These are deliberate boundaries. A framework that tries to do everything does nothing well.

## One Sentence

IIM is the missing structural layer between IOCs and ATT&CK - a grammar for the infrastructure that carries campaigns, designed to stay valid as specific artifacts rotate.

If that sentence sounds useful to your work, the specification in `iim-v1.1-spec.md` tells you how to use it precisely.