# somaco-guardian-test-harness

A deterministic policy gate for classifier output, with hash-chained receipts.

Your classifier proposes. This gate disposes. Every proposal, gate decision,
and act is written to a hash-chained ledger before the act counts as real.

Stdlib-only Python. No dependencies. No network.

```
python3 cli.py run scenarios/honest-route-freeze.json --ledger ledger.jsonl
python3 cli.py verify ledger.jsonl
python3 cli.py compare fixtures/their-ledger-convergent.jsonl
python3 cli.py thresholds their-thresholds.json
python3 cli.py check
```

## The law

- **Confidence routes. Policy authorizes. Receipts prove.**
- The classifier scores and never writes. It has no path to the actuator.
- Forbidden acts (`MOVE_FUNDS`, `WIDEN_LIMIT`, `MINT_AUTHORITY`) deny at any
  confidence. 0.99 buys the classifier nothing.
- Ceilings **intersect, never union**. An actor's claimed ceiling is capped by
  what its issuer granted. A child cannot widen its parent's authority.
- Confidence inside the gray band **[0.35, 0.75]** escalates. Low confidence is
  not a weak yes. Below the floor, the proposal denies.
- An act receipt exists only if an act happened. Escalations and denials write
  no act receipt.
- Identity is address, never credential. IDs correlate; they grant nothing.

## What this proves

- The authority boundary holds independent of the classifier: forbidden acts,
  over-ceiling values, out-of-scope acts, and self-widened ceilings all deny
  deterministically.
- The gray band routes to escalation instead of acting on a coin flip.
- The receipt chain is tamper-evident: edit one field, delete one receipt, or
  reorder the ledger, and `verify` names the first broken receipt.
- A run refuses to extend a ledger whose chain is already broken. Fail closed.

## What this does NOT prove

- **The classifier is a stub.** `guardian.py` carries a deterministic rules
  stub (`stub:deterministic-rules-v1`) behind the typed envelope so the gate
  can be exercised end to end. Live Jev / System One swaps in behind the same
  envelope; the gate does not change. Nothing here claims the stub — or any
  classifier — is accurate.
- **No production DEX claim.** The vocabulary (route freeze, provider
  quarantine) is a reference shape, not a venue integration.
- **Tamper-evidence is not tamper-proofing.** A hash chain proves a ledger was
  modified after the fact. It does not stop the modifier. Production needs
  signer identity and external anchoring matched to the threat model. That is
  future work, named as such.
- **Field convergence is not semantic proof.** `compare` maps names and
  structures; it does not authenticate an external ledger, prove that two
  gates enforced the same policy, or prove that a reported final action
  actually happened. Those claims need source receipts and verification.
- **Threshold ingestion changes nothing.** `thresholds` reports candidate
  deltas against current constants and the reference scenario grant. It never
  applies them.
- UUIDs here are correlation addresses. They are never credentials and never
  carry authority by themselves.

## Commands

### `run <scenario.json> [--ledger ledger.jsonl]`

Loads a scenario: an actor identity with granted and claimed ceilings, plus a
finished classifier proposal in the typed envelope. Intersects the ceilings,
runs the gate, prints `ALLOW` / `DENY` / `ESCALATE` with the reason, appends
the receipts (proposal, gate decision, and an act receipt only when an act
executes), and prints each new chained receipt. Repeat runs extend the same
ledger and continue the chain.

### `verify <ledger.jsonl>`

Recomputes every hash and link. Prints `PASS` with the receipt count, or
`FAIL` naming the first broken receipt — tampered, deleted, or reordered —
and why.

### `compare <their-ledger.jsonl> [--out mapped.jsonl]`

Ingests an external receipt ledger in Architect's five-field shape and maps
each record onto this harness's three receipt payloads. It prints a
field-by-field convergence table, names external fields with no home in our
schema, names harness fields with no source in the external records, and shows
the mapped schema view. With `--out`, the mapped view is also written as JSONL.

The five external fields are:

| his field | accepted source keys (canonical + reasonable aliases) | our receipt home |
|---|---|---|
| what was observed | `observed`, `observation`, `evidence` | `classifier_proposal.payload.evidence[]` |
| what Jev decided | `decided`, `decision`, `choice`, `classifier_decision` | `classifier_proposal.payload.choice` |
| confidence + distribution | `confidence`, `distribution`, or one combined `confidence+distribution` / `confidence_distribution` object | `classifier_proposal.payload.confidence` + `.distribution` |
| what policy allowed or denied | `policy`, `policy_decision`, `policy_outcome`, `verdict` | `gate_decision.payload.verdict` (+ `reason` when supplied) |
| the final action taken | `final_action`, `final_action_taken`, `action_taken`, `action` | `act_result.payload.act` + `result.status`, or no act receipt when the reported final action is `none` |

The report separates two questions that are easy to blur:

- **Five-field convergence:** are his observed / decided / confidence /
  distribution / policy / final-action components present and mapped?
- **Extended receipt gap:** which of our identity, scope, value, classifier,
  reason, and hash-chain fields have no source in his record?

Unmapped fields are never silently dropped. An extra field is named in the
report with the record line(s) where it appeared. A field-name map is not
proof that two systems mean the same thing semantically; it is the starting
point for that comparison.

Fixtures live in `fixtures/`:

- `their-ledger-convergent.jsonl` — all five fields present and mapped.
- `their-ledger-divergent.jsonl` — distribution missing throughout, with
  named no-home fields (`operator_note`, `venue_latency_ms`).

### `thresholds <their-thresholds.json>`

Diffs supplied production threshold data against the current gate constants.
It is a **report only**: ingestion never edits `guardian.py`, a scenario, a
ceiling, or any other policy constant. Policy constants move by explicit
decision, not by data intake.

Canonical input shape:

```json
{
  "source": "architect-dex-audit-2026-10",
  "gray_band": {"low": 0.40, "high": 0.70},
  "ceilings": {
    "max_value_at_risk": 500000,
    "allowed_acts": ["OBSERVE", "ESCALATE", "FREEZE_ROUTE", "QUARANTINE_PROVIDER"]
  },
  "latency_budgets_ms": {
    "classifier_p95": 80,
    "gate_p95": 5,
    "end_to_end_p95": 125
  },
  "failure_modes": {
    "total_decisions": 10000,
    "counts": {
      "gray_band_escalation": 842,
      "forbidden_act_attempt": 3,
      "over_ceiling_denial": 19,
      "tampered_or_unverifiable_receipt": 0
    }
  }
}
```

The diff names exact deltas: for example, `GRAY_LOW 0.35 -> 0.40 (+0.05)` or
`REFERENCE_MAX_VALUE_AT_RISK 250,000 -> 500,000 (+250,000; +100.0%)`. The
$250,000 figure is the shipped reference scenario grant, not a universal
production ceiling. Latency budgets currently have no harness constant; a
supplied budget is therefore reported as **would add**, not as a delta against
an invented default. Failure-mode counts are evidence for review; a count
alone does not derive a new gray band or ceiling.

### `check`

The conformance suite. Each case is named and must pass:

| case | expectation |
|---|---|
| `forbidden-act-deny` | MOVE_FUNDS at 0.99 confidence → DENY, no act receipt |
| `over-ceiling-deny` | act value above the intersected ceiling → DENY |
| `child-widen-deny` | child claims an act class the issuer never granted → DENY |
| `gray-band-escalate` | confidence in [0.35, 0.75] → ESCALATE, no act, no act receipt |
| `forged-ceiling-refused` | actor claims more than the issuer granted → intersection refuses |
| `tampered-receipt-fails` | flipping one payload field → verify FAILS at that receipt |
| `deleted-receipt-fails` | removing the middle receipt → verify FAILS |
| `honest-chain-verifies` | an honest end-to-end run → chain verifies |
| `compare-convergent-passes` | an Architect-shaped ledger with all five fields maps cleanly |
| `compare-divergent-names-gaps` | missing distribution and no-home fields are named, never dropped |
| `thresholds-diff-reports` | supplied gray-band, ceiling, latency, and failure-mode data produce exact candidate deltas, with nothing auto-applied |

Exit code 0 when all cases pass, 1 otherwise.

## Scenario format

See `scenarios/`. Read them, copy one, change the numbers.

```json
{
  "name": "honest-route-freeze",
  "description": "free text, ignored by the gate",
  "actor_id": "actor:sentinel-dex-1",
  "subject_id": "route:eth-usdc-main",
  "granted_ceiling": {
    "allowed_acts": ["OBSERVE", "ESCALATE", "FREEZE_ROUTE"],
    "max_value_at_risk": 250000,
    "scopes": ["route:eth-usdc", "route:btc-usdc"],
    "generation": 1
  },
  "claimed_ceiling": {
    "allowed_acts": ["OBSERVE", "ESCALATE", "FREEZE_ROUTE"],
    "max_value_at_risk": 250000,
    "scopes": ["route:eth-usdc"],
    "generation": 1
  },
  "decision": {
    "choice": "route_degraded",
    "confidence": 0.86,
    "distribution": {"route_degraded": 0.86, "route_ok": 0.09, "provider_suspect": 0.05},
    "proposed_act": "FREEZE_ROUTE",
    "scope": "route:eth-usdc",
    "value_at_risk": 180000,
    "evidence": ["failures_5m=17", "p95_ms=1240"],
    "classifier": "stub:deterministic-rules-v1"
  },
  "expected_verdict": "ALLOW"
}
```

`granted_ceiling` is what the issuer gave the actor. `claimed_ceiling` is what
the actor presents; omit it and the claim equals the grant. The gate intersects
claim with grant, so a claim can only narrow.

`expected_verdict` is optional. When present, `run` reports whether the actual
verdict matches — that is how `check` uses the scenario files.

## Envelope schema

The proposal your classifier must emit (`decision` in the scenario file):

| field | meaning |
|---|---|
| `choice` | the finite verdict: `route_ok`, `route_degraded`, `provider_suspect`, `anomaly_unknown`, … |
| `confidence` | 0.0–1.0. Compared against the gray band; never authorizes by itself |
| `distribution` | full probability distribution over choices |
| `proposed_act` | the act requested: `FREEZE_ROUTE`, `OBSERVE`, `UNFREEZE_ROUTE`, … |
| `scope` | what the act touches; must sit inside the ceiling's scopes |
| `value_at_risk` | value the act puts at risk; must sit under the intersected ceiling |
| `evidence` | evidence references the decision rests on — strings, hashes, metric snapshots |
| `classifier` | who decided, with version pin: `stub:deterministic-rules-v1`, `your-model:x.y` |

`decision_id`, `subject_id`, and `proposer_id` identify the proposal, its
subject, and its author. Addresses for correlation — never credentials.

## Receipt schema

One JSON object per line in the ledger. Every receipt:

| field | meaning |
|---|---|
| `seq` | position in the chain, starting at 1 |
| `kind` | `classifier_proposal`, `gate_decision`, or `act_result` |
| `payload` | the record itself (below) |
| `prev_hash` | hash of the previous receipt, or `GENESIS` |
| `hash` | SHA-256 of the canonical receipt body |

Payloads:

- **classifier_proposal** — the full decision envelope: `decision_id`,
  `subject_id`, `proposer_id`, `choice`, `confidence`, `distribution`,
  `proposed_act`, `scope`, `value_at_risk`, `evidence`, `classifier`.
- **gate_decision** — `decision_id`, `verdict` (`ALLOW`/`DENY`/`ESCALATE`),
  `act`, `reason`. The deterministic policy's answer, with its grounds.
- **act_result** — `decision_id`, `act`, `verdict`, `result`
  (`status`, `scope`). Written only when an act executes.

## Plug in a real classifier

The gate never calls your classifier. Two ways to feed it:

1. **JSON.** Have your classifier emit the envelope fields and drop them into
   a scenario file's `decision` block. Set `classifier` to your model and
   version pin. Run it.
2. **Python.** Implement one function with this shape and gate its output:

   ```python
   from guardian import DecisionEnvelope, PolicyGate

   def classify(features) -> DecisionEnvelope:
       # your model call here — must return a typed envelope
       ...
   ```

   Or skip the harness's stub entirely: `python3 guardian.py --scenario` runs
   the built-in end-to-end demo, and `python3 guardian.py` runs the original
   self-check.

What a real (non-stub) output buys you is better proposals. The boundary —
what may act, at what value, in what scope, and what got witnessed — stays
deterministic either way. That is the point.

## Files

- `guardian.py` — the core: envelope, ceilings, gate, ledger, stub classifier.
- `cli.py` — `run` / `verify` / `compare` / `thresholds` / `check`.
- `convergence.py` — the convergence kit: external receipt mapping and threshold diffing. Report-only; it cannot change policy constants.
- `scenarios/` — readable, modifiable scenario files, one per gate conformance case.
- `fixtures/` — Architect-shaped external ledgers for the compare path: one convergent, one deliberately divergent.
- `README.md` — this file.

Design note: SOM-DOC-10109 (Guardian/Sentinel decision layer).
Working space: https://architect.somacosf.com/
