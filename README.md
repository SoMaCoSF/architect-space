# Architect Space — Guardian/Sentinel working space

Companion media for **[architect.somacosf.com](https://architect.somacosf.com)** — the collaboration
space where two implementations of the same architecture meet:

> **Confidence routes. Policy authorizes. Receipts prove.**

A typed classifier (Jev) proposes. A deterministic policy boundary (LedgerGuard / PDP) authorizes.
Every act writes a hash-chained decision-receipt. A sentinel's authority is bounded — monitor,
restrict, quarantine, reroute, escalate — and never widens itself.

## Media

| File | What it shows |
|---|---|
| `media/guardian-sentinel-uuid-fit.mp4` | 36s walkthrough: typed UUID identity + capability ceilings → classifier proposal → deterministic gate → gated act + receipt |
| `media/guardian-sentinel-core-cycle.gif` | 6.3s loop of the core cycle; the gold step is the live one |
| `media/guardian-sentinel-uuid-fit-diagram.gif` | One subject ID walking route → classifier → gate → act → receipt → operator replay |

Nothing here depicts a physical system. Every visual is a rendering of identities, statistics,
and gate outcomes: a confidence bar is a rendering of a statistic the classifier reported —
never a substance, and never a permission. A UUID is an address for correlation, never a credential.

SOMACOSF

## Repo map

- `site/index.html` — the architect.somacosf.com page source (single self-contained file; deployed to Vercel project `architect-site`).
- `media/` — the motion assets: 36s explainer MP4 (+ release asset), core-cycle GIF, UUID-fit diagram GIF.
- `harness/` — the Guardian/Sentinel test harness: `guardian.py` (verified core), `cli.py` (run/verify/check), `scenarios/`, README.
- `docs/DESIGN-NOTE.md` — SOM-DOC-10109: how the SoMaCo UUID protocol fits the Guardian/Sentinel shape (identity, ceilings, PDP gate, witness receipts).

Law of the space: confidence routes, policy authorizes, receipts prove. Systems shown are informational, not physical; density is a rendering of a statistic.
