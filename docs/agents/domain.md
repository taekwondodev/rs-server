# Domain Docs

How the dev-cycle skills should consume this repo's domain documentation when exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root
- **`docs/adr/`** — read ADRs that touch the area you're about to work in.

If any of these files don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them upfront. The `/domain-modeling` skill (reached via `/grill-with-docs`, `/wayfinder`'s Grilling tickets, and `/triage`) creates them lazily when terms or decisions actually get resolved.

## File structure

Single-context repo:

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-generic-ports-dyn-trait-exception.md
│   ├── 0002-domain-error-boundary-conversion.md
│   ├── 0003-auth-token-strategy.md
│   ├── 0004-hkdf-single-secret.md
│   └── 0005-claims-data-behavior-split.md
└── crates/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a ticket, a spec, a test name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0003 (auth token strategy) — but worth reopening because…_
