#!/usr/bin/env python3
"""
somaco-guardian-test-harness — CLI.

Feed YOUR classifier's output (typed envelope JSON) into the deterministic
gate and prove what happened. Stdlib only.

Commands:
  run <scenario.json> [--ledger ledger.jsonl]   gate one proposed decision
  verify <ledger.jsonl>                          recompute the receipt chain
  check                                          conformance suite

The gate never calls your classifier. You feed it a finished proposal.
Exit codes: run 0 ok (any verdict) / 2 usage or broken input ledger;
verify 0 PASS / 1 FAIL; check 0 all pass / 1 any fail.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guardian import (  # noqa: E402
    Ceiling,
    DecisionEnvelope,
    PolicyGate,
    Receipt,
    ReceiptLedger,
    canonical,
    sha,
    tid,
)

HERE = os.path.dirname(os.path.abspath(__file__))
SCENARIO_DIR = os.path.join(HERE, "scenarios")


# ── scenario loading ────────────────────────────────────────────────────────

def ceiling_from_dict(d: dict) -> Ceiling:
    return Ceiling(
        actor_id=str(d.get("actor_id", "")),
        allowed_acts=tuple(d.get("allowed_acts", [])),
        max_value_at_risk=float(d.get("max_value_at_risk", 0)),
        scopes=tuple(d.get("scopes", [])),
        generation=int(d.get("generation", 1)),
    )


def load_scenario(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)

    actor_id = str(raw.get("actor_id", "actor:unnamed"))
    granted = ceiling_from_dict({**raw["granted_ceiling"], "actor_id": actor_id})
    claimed_raw = raw.get("claimed_ceiling") or raw["granted_ceiling"]
    claimed = ceiling_from_dict({**claimed_raw, "actor_id": actor_id})

    d = raw["decision"]
    subject_id = str(raw.get("subject_id", "subject:unnamed"))
    envelope = DecisionEnvelope(
        decision_id=str(d.get("decision_id") or tid("decision", subject_id + ":" + canonical(d))),
        subject_id=subject_id,
        proposer_id=str(d.get("proposer_id") or actor_id),
        choice=str(d["choice"]),
        confidence=float(d["confidence"]),
        distribution={str(k): float(v) for k, v in d.get("distribution", {}).items()},
        proposed_act=str(d["proposed_act"]),
        scope=str(d["scope"]),
        value_at_risk=float(d.get("value_at_risk", 0)),
        evidence=[str(e) for e in d.get("evidence", [])],
        classifier=str(d.get("classifier", "external:unspecified")),
    )
    return {
        "name": str(raw.get("name", os.path.basename(path))),
        "actor_id": actor_id,
        "granted": granted,
        "claimed": claimed,
        "envelope": envelope,
        "expected_verdict": raw.get("expected_verdict"),
    }


# ── ledger persistence (JSONL of receipt public dicts) ─────────────────────

def load_ledger(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def save_ledger(path: str, receipts: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in receipts:
            fh.write(json.dumps(r, sort_keys=True) + "\n")


def verify_chain(rows: list[dict]) -> tuple[bool, str]:
    """Recompute the chain. On failure, name the first broken receipt."""
    prev = "GENESIS"
    for i, r in enumerate(rows, start=1):
        try:
            seq, kind = int(r["seq"]), str(r["kind"])
            payload, rprev, rhash = r["payload"], str(r["prev_hash"]), str(r["hash"])
        except (KeyError, TypeError, ValueError) as exc:
            return False, f"receipt at line {i}: malformed record ({exc})"
        if seq != i:
            return False, (
                f"receipt seq {seq} (line {i}, kind={kind}): expected seq {i} — "
                "a receipt was deleted or the ledger was reordered"
            )
        if rprev != prev:
            return False, (
                f"receipt seq {seq} (line {i}, kind={kind}): prev_hash {rprev[:12]}… "
                f"does not match previous hash {prev[:12]}… — chain broken (deletion or reorder)"
            )
        body = {"seq": seq, "kind": kind, "payload": payload, "prev_hash": rprev}
        if sha(canonical(body)) != rhash:
            return False, (
                f"receipt seq {seq} (line {i}, kind={kind}): hash mismatch — "
                "the record was modified after it was written (tampered)"
            )
        prev = rhash
    return True, f"{len(rows)} receipts, chain intact"


# ── the flow: proposal → gate → (act) → receipts ────────────────────────────

def run_flow(scn: dict, ledger_path: str) -> dict:
    """Run one scenario through the gate, persisting receipts to ledger_path.

    Receipt discipline: the proposal and the gate decision are always
    witnessed. An act_result receipt is written ONLY when an act executes
    (verdict ALLOW). ESCALATE and DENY write no act receipt — no act happened.
    Fails closed if the existing ledger does not verify.
    """
    rows = load_ledger(ledger_path)
    if rows:
        ok, msg = verify_chain(rows)
        if not ok:
            raise RuntimeError(f"existing ledger {ledger_path} does not verify: {msg}. Refusing to extend a broken chain.")

    ledger = ReceiptLedger()
    for r in rows:
        ledger.receipts.append(Receipt(seq=r["seq"], kind=r["kind"], payload=r["payload"], prev_hash=r["prev_hash"], hash=r["hash"]))

    env: DecisionEnvelope = scn["envelope"]
    new: list[dict] = []
    new.append(ledger.append("classifier_proposal", env.public()).public())

    outcome = PolicyGate().decide(env, scn["claimed"], scn["granted"])
    new.append(ledger.append("gate_decision", {
        "decision_id": env.decision_id, "verdict": outcome.verdict,
        "act": outcome.act, "reason": outcome.reason,
    }).public())

    result = None
    if outcome.verdict == "ALLOW":
        if outcome.act == "FREEZE_ROUTE":
            result = {"status": "frozen", "scope": env.scope}
        elif outcome.act == "OBSERVE":
            result = {"status": "observed", "scope": env.scope}
        else:
            result = {"status": "executed", "scope": env.scope}
        new.append(ledger.append("act_result", {
            "decision_id": env.decision_id, "act": outcome.act,
            "verdict": outcome.verdict, "result": result,
        }).public())

    all_rows = [r.public() for r in ledger.receipts]
    save_ledger(ledger_path, all_rows)
    ok, _ = verify_chain(all_rows)
    return {
        "verdict": outcome.verdict, "act": outcome.act, "reason": outcome.reason,
        "result": result, "new_receipts": new, "total_receipts": len(all_rows),
        "chain_verified": ok,
    }


# ── commands ────────────────────────────────────────────────────────────────

def cmd_run(args: argparse.Namespace) -> int:
    scn = load_scenario(args.scenario)
    env = scn["envelope"]
    print(f"scenario: {scn['name']}")
    print(f"actor:    {scn['actor_id']}  subject: {env.subject_id}")
    print(f"proposal: choice={env.choice} confidence={env.confidence} act={env.proposed_act} "
          f"scope={env.scope} value_at_risk={env.value_at_risk} classifier={env.classifier}")
    try:
        out = run_flow(scn, args.ledger)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(f"VERDICT:  {out['verdict']} — {out['reason']}")
    if out["result"] is not None:
        print(f"act:      {out['act']} → {json.dumps(out['result'], sort_keys=True)}")
    else:
        print(f"act:      none (no act receipt written)")
    for r in out["new_receipts"]:
        print(f"receipt:  {json.dumps(r, sort_keys=True)}")
    print(f"ledger:   {args.ledger} ({out['total_receipts']} receipts, chain verified: {str(out['chain_verified']).lower()})")
    if scn["expected_verdict"]:
        match = "matches" if scn["expected_verdict"] == out["verdict"] else "DOES NOT MATCH"
        print(f"expected: {scn['expected_verdict']} — {match}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        rows = load_ledger(args.ledger)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL  {args.ledger} — unreadable: {exc}")
        return 1
    if not rows:
        print(f"FAIL  {args.ledger} — no receipts found")
        return 1
    ok, msg = verify_chain(rows)
    print(f"{'PASS' if ok else 'FAIL'}  {args.ledger} — {msg}")
    return 0 if ok else 1


def cmd_check(_args: argparse.Namespace) -> int:
    results: list[tuple[str, bool, str]] = []

    def record(name: str, cond: bool, detail: str = "") -> None:
        results.append((name, cond, detail))
        print(f"{'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")

    def scenario_case(name: str, filename: str, expect: str, expect_act_receipt: bool | None = None) -> None:
        scn = load_scenario(os.path.join(SCENARIO_DIR, filename))
        with tempfile.TemporaryDirectory() as td:
            ledger_path = os.path.join(td, "ledger.jsonl")
            out = run_flow(scn, ledger_path)
            kinds = [r["kind"] for r in load_ledger(ledger_path)]
        cond = out["verdict"] == expect
        detail = f"{scn['envelope'].proposed_act} → {out['verdict']} ({out['reason']})"
        if expect_act_receipt is True and "act_result" not in kinds:
            cond, detail = False, detail + "; act_result receipt missing"
        if expect_act_receipt is False and "act_result" in kinds:
            cond, detail = False, detail + "; act_result receipt written but no act should have happened"
        record(name, cond, detail)

    scenario_case("forbidden-act-deny", "forbidden-move-funds.json", "DENY", expect_act_receipt=False)
    scenario_case("over-ceiling-deny", "over-ceiling-freeze.json", "DENY", expect_act_receipt=False)
    scenario_case("child-widen-deny", "child-widen-unfreeze.json", "DENY", expect_act_receipt=False)
    scenario_case("gray-band-escalate", "gray-band-escalate.json", "ESCALATE", expect_act_receipt=False)
    scenario_case("forged-ceiling-refused", "forged-ceiling.json", "DENY", expect_act_receipt=False)

    honest = load_scenario(os.path.join(SCENARIO_DIR, "honest-route-freeze.json"))
    with tempfile.TemporaryDirectory() as td:
        ledger_path = os.path.join(td, "ledger.jsonl")
        out = run_flow(honest, ledger_path)
        record("honest-allow-writes-act", out["verdict"] == "ALLOW" and out["result"] is not None,
               f"{out['act']} → {out['verdict']}, result={json.dumps(out['result'], sort_keys=True) if out['result'] else None}")

        ok, msg = verify_chain(load_ledger(ledger_path))
        record("honest-chain-verifies", ok, msg)

        # Tamper: flip one field in the middle (gate_decision) receipt.
        rows = load_ledger(ledger_path)
        rows[1]["payload"]["verdict"] = "DENY" if rows[1]["payload"].get("verdict") != "DENY" else "ALLOW"
        tampered_path = os.path.join(td, "tampered.jsonl")
        save_ledger(tampered_path, rows)
        ok, msg = verify_chain(load_ledger(tampered_path))
        record("tampered-receipt-fails", not ok and "seq 2" in msg, msg)

        # Deletion: drop the middle receipt entirely.
        rows = load_ledger(ledger_path)
        del rows[1]
        deleted_path = os.path.join(td, "deleted.jsonl")
        save_ledger(deleted_path, rows)
        ok, msg = verify_chain(load_ledger(deleted_path))
        record("deleted-receipt-fails", not ok, msg)

    failed = [n for n, ok, _ in results if not ok]
    if failed:
        print(f"\nCONFORMANCE FAILED: {len(failed)} case(s): {', '.join(failed)}")
        return 1
    print(f"\nCONFORMANCE GREEN: {len(results)} cases — the gate denies what it must, escalates the gray band, and the chain catches tampering.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian-test-harness", description=__doc__.splitlines()[2])
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="gate one scenario file")
    p_run.add_argument("scenario")
    p_run.add_argument("--ledger", default="ledger.jsonl", help="ledger file to extend (default: ./ledger.jsonl)")
    p_run.set_defaults(fn=cmd_run)

    p_verify = sub.add_parser("verify", help="recompute a ledger's hash chain")
    p_verify.add_argument("ledger")
    p_verify.set_defaults(fn=cmd_verify)

    p_check = sub.add_parser("check", help="run the conformance suite")
    p_check.set_defaults(fn=cmd_check)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
