#!/usr/bin/env python3
"""
Guardian/Sentinel decision-layer harness.

Stdlib only. The classifier is a deterministic stub behind a typed interface;
live Jev/System One can be swapped behind the same envelope later.

Doctrine implemented:
- classifier scores, never writes
- deterministic acts are never overruled by confidence
- gray band routes to escalation
- capability ceilings intersect, never union
- UUID-shaped identities are address/correlation only, never credentials
- every proposal / gate decision / act writes a hash-chained receipt
"""

from __future__ import annotations

import hashlib
import json
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://somacosf.com/guardian-sentinel-harness")
GRAY_LOW = 0.35
GRAY_HIGH = 0.75

FORBIDDEN_ACTS = {"MOVE_FUNDS", "WIDEN_LIMIT", "MINT_AUTHORITY"}


def tid(kind: str, name: str) -> str:
    """Typed correlation identity. Address only; never a credential."""
    return f"{kind}:{uuid.uuid5(NS, f'{kind}:{name}')}"


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Ceiling:
    actor_id: str
    allowed_acts: Tuple[str, ...]
    max_value_at_risk: float
    scopes: Tuple[str, ...]
    generation: int = 1

    def intersect(self, other: "Ceiling") -> "Ceiling":
        """Ceilings intersect, never union; lineage only attenuates."""
        return Ceiling(
            actor_id=self.actor_id,
            allowed_acts=tuple(sorted(set(self.allowed_acts) & set(other.allowed_acts))),
            max_value_at_risk=min(self.max_value_at_risk, other.max_value_at_risk),
            scopes=tuple(sorted(set(self.scopes) & set(other.scopes))),
            generation=max(self.generation, other.generation),
        )

    def permits(self, act: str, scope: str, value: float) -> Tuple[bool, str]:
        if act in FORBIDDEN_ACTS:
            return False, f"{act} is forbidden to classifier/sentinel authority"
        if act not in self.allowed_acts:
            return False, f"{act} outside ceiling for {self.actor_id}"
        if scope not in self.scopes:
            return False, f"scope {scope} outside ceiling for {self.actor_id}"
        if value > self.max_value_at_risk:
            return False, f"value {value} exceeds ceiling {self.max_value_at_risk}"
        return True, "within ceiling"


@dataclass
class DecisionEnvelope:
    decision_id: str
    subject_id: str
    proposer_id: str
    choice: str
    confidence: float
    distribution: Dict[str, float]
    proposed_act: str
    scope: str
    value_at_risk: float
    evidence: List[str] = field(default_factory=list)
    classifier: str = "stub:deterministic-rules-v1"

    def public(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "subject_id": self.subject_id,
            "proposer_id": self.proposer_id,
            "choice": self.choice,
            "confidence": round(self.confidence, 4),
            "distribution": {k: round(v, 4) for k, v in sorted(self.distribution.items())},
            "proposed_act": self.proposed_act,
            "scope": self.scope,
            "value_at_risk": self.value_at_risk,
            "evidence": list(self.evidence),
            "classifier": self.classifier,
        }


class StubClassifier:
    """Deterministic stub behind the typed classifier interface.

    Live Jev/System One is the named future swap behind this same envelope.
    """

    def classify(self, *, subject_id: str, proposer_id: str, features: Mapping[str, Any]) -> DecisionEnvelope:
        failures = float(features.get("failures_5m", 0))
        p95_ms = float(features.get("p95_ms", 0))
        anomaly = float(features.get("anomaly_score", 0.0))
        value = float(features.get("value_at_risk", 0.0))
        scope = str(features.get("scope", "route:unknown"))

        if anomaly >= 0.90:
            choice, conf = "anomaly_unknown", 0.55
            dist = {"anomaly_unknown": 0.55, "route_degraded": 0.30, "route_ok": 0.15}
            act = "ESCALATE"
        elif failures >= 12 or p95_ms >= 900:
            choice, conf = "route_degraded", 0.86
            dist = {"route_degraded": 0.86, "route_ok": 0.09, "provider_suspect": 0.05}
            act = "FREEZE_ROUTE"
        elif failures >= 4 or p95_ms >= 450:
            choice, conf = "route_degraded", 0.58
            dist = {"route_degraded": 0.58, "route_ok": 0.34, "provider_suspect": 0.08}
            act = "FREEZE_ROUTE"
        else:
            choice, conf = "route_ok", 0.93
            dist = {"route_ok": 0.93, "route_degraded": 0.05, "provider_suspect": 0.02}
            act = "OBSERVE"

        evidence = [
            f"failures_5m={features.get('failures_5m', 0)}",
            f"p95_ms={features.get('p95_ms', 0)}",
            f"anomaly_score={features.get('anomaly_score', 0.0)}",
        ]
        return DecisionEnvelope(
            decision_id=tid("decision", f"{subject_id}:{canonical(dict(features))}"),
            subject_id=subject_id,
            proposer_id=proposer_id,
            choice=choice,
            confidence=conf,
            distribution=dist,
            proposed_act=act,
            scope=scope,
            value_at_risk=value,
            evidence=evidence,
        )


@dataclass
class Receipt:
    seq: int
    kind: str
    payload: Dict[str, Any]
    prev_hash: str
    hash: str

    def public(self) -> Dict[str, Any]:
        return {"seq": self.seq, "kind": self.kind, "payload": self.payload, "prev_hash": self.prev_hash, "hash": self.hash}


class ReceiptLedger:
    def __init__(self) -> None:
        self.receipts: List[Receipt] = []

    def append(self, kind: str, payload: Dict[str, Any]) -> Receipt:
        prev = self.receipts[-1].hash if self.receipts else "GENESIS"
        seq = len(self.receipts) + 1
        body = {"seq": seq, "kind": kind, "payload": payload, "prev_hash": prev}
        h = sha(canonical(body))
        receipt = Receipt(seq=seq, kind=kind, payload=payload, prev_hash=prev, hash=h)
        self.receipts.append(receipt)
        return receipt

    def verify(self) -> bool:
        prev = "GENESIS"
        for i, r in enumerate(self.receipts, start=1):
            if r.seq != i or r.prev_hash != prev:
                return False
            body = {"seq": r.seq, "kind": r.kind, "payload": r.payload, "prev_hash": r.prev_hash}
            if sha(canonical(body)) != r.hash:
                return False
            prev = r.hash
        return True


@dataclass
class GateOutcome:
    verdict: str  # ALLOW | DENY | ESCALATE
    act: str
    reason: str
    effective_ceiling: Ceiling


class PolicyGate:
    def decide(self, decision: DecisionEnvelope, actor_ceiling: Ceiling, parent_ceiling: Ceiling) -> GateOutcome:
        effective = actor_ceiling.intersect(parent_ceiling)
        act = decision.proposed_act

        if act in FORBIDDEN_ACTS:
            return GateOutcome("DENY", act, "forbidden act: deterministic authorization owns this path", effective)
        if decision.confidence < GRAY_LOW:
            return GateOutcome("DENY", act, f"confidence {decision.confidence:.2f} below floor {GRAY_LOW}", effective)
        if GRAY_LOW <= decision.confidence <= GRAY_HIGH:
            return GateOutcome("ESCALATE", act, f"gray band [{GRAY_LOW}, {GRAY_HIGH}] routes to escalation", effective)

        ok, why = effective.permits(act, decision.scope, decision.value_at_risk)
        if not ok:
            return GateOutcome("DENY", act, why, effective)
        return GateOutcome("ALLOW", act, f"above gray band and {why}", effective)


class Actuator:
    """Deterministic actuator. The classifier never calls this directly."""

    def __init__(self, ledger: ReceiptLedger) -> None:
        self.ledger = ledger
        self.frozen_routes: set[str] = set()

    def execute(self, decision: DecisionEnvelope, outcome: GateOutcome) -> Dict[str, Any]:
        act = outcome.act
        if outcome.verdict == "ALLOW" and act == "FREEZE_ROUTE":
            self.frozen_routes.add(decision.scope)
            result = {"status": "frozen", "scope": decision.scope}
        elif outcome.verdict == "ESCALATE":
            result = {"status": "escalated", "scope": decision.scope}
        elif outcome.verdict == "ALLOW" and act == "OBSERVE":
            result = {"status": "observed", "scope": decision.scope}
        else:
            result = {"status": "no_act", "scope": decision.scope, "verdict": outcome.verdict}
        self.ledger.append("act_result", {"decision_id": decision.decision_id, "act": act, "verdict": outcome.verdict, "result": result})
        return result


def run_scenario() -> Dict[str, Any]:
    ledger = ReceiptLedger()
    classifier = StubClassifier()
    gate = PolicyGate()
    actuator = Actuator(ledger)

    sentinel_id = tid("actor", "sentinel-dex-1")
    route_id = tid("route", "eth-usdc-main")
    parent = Ceiling(sentinel_id, ("OBSERVE", "ESCALATE", "FREEZE_ROUTE"), 1_000_000, ("route:eth-usdc", "route:btc-usdc"))
    child = Ceiling(sentinel_id, ("OBSERVE", "ESCALATE", "FREEZE_ROUTE", "MOVE_FUNDS"), 250_000, ("route:eth-usdc",))

    features = {"failures_5m": 17, "p95_ms": 1240, "anomaly_score": 0.22, "value_at_risk": 180_000, "scope": "route:eth-usdc"}
    decision = classifier.classify(subject_id=route_id, proposer_id=sentinel_id, features=features)
    ledger.append("classifier_proposal", decision.public())

    outcome = gate.decide(decision, child, parent)
    ledger.append("gate_decision", {"decision_id": decision.decision_id, "verdict": outcome.verdict, "act": outcome.act, "reason": outcome.reason})

    result = actuator.execute(decision, outcome)
    return {"decision": decision.public(), "gate": {"verdict": outcome.verdict, "act": outcome.act, "reason": outcome.reason}, "result": result, "ledger": [r.public() for r in ledger.receipts], "chain_verified": ledger.verify()}


def self_check() -> int:
    failures: List[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        print(f"{'PASS' if cond else 'FAIL'}  {name}{(' — ' + detail) if detail else ''}")
        if not cond:
            failures.append(name)

    scenario = run_scenario()
    check("scenario classifies route_degraded", scenario["decision"]["choice"] == "route_degraded")
    check("gate allows freeze within intersected ceiling", scenario["gate"]["verdict"] == "ALLOW", scenario["gate"]["reason"])
    check("actuator froze route", scenario["result"]["status"] == "frozen")
    check("receipt chain verifies", scenario["chain_verified"] is True, f"{len(scenario['ledger'])} receipts")

    # Gray band escalates; confidence never authorizes by itself.
    ledger = ReceiptLedger()
    gate = PolicyGate()
    actor = tid("actor", "sentinel-gray")
    ceiling = Ceiling(actor, ("OBSERVE", "ESCALATE", "FREEZE_ROUTE"), 100_000, ("route:eth-usdc",))
    gray = DecisionEnvelope(tid("decision", "gray"), tid("route", "eth-usdc-main"), actor, "route_degraded", 0.55, {"route_degraded": 0.55, "route_ok": 0.45}, "FREEZE_ROUTE", "route:eth-usdc", 10_000, ["synthetic gray-band case"])
    out = gate.decide(gray, ceiling, ceiling)
    check("gray band escalates", out.verdict == "ESCALATE", out.reason)

    # Forbidden deterministic acts deny even at very high confidence.
    greedy = DecisionEnvelope(tid("decision", "greedy"), tid("route", "eth-usdc-main"), actor, "route_ok", 0.99, {"route_ok": 0.99}, "MOVE_FUNDS", "route:eth-usdc", 10_000, ["synthetic forbidden-act case"])
    out = gate.decide(greedy, ceiling, ceiling)
    check("MOVE_FUNDS denied despite 0.99 confidence", out.verdict == "DENY", out.reason)

    # Ceiling intersection narrows: child cannot widen value/scope.
    parent = Ceiling(actor, ("OBSERVE", "ESCALATE", "FREEZE_ROUTE"), 50_000, ("route:eth-usdc",))
    child = Ceiling(actor, ("OBSERVE", "ESCALATE", "FREEZE_ROUTE", "UNFREEZE_ROUTE"), 500_000, ("route:eth-usdc", "route:sol-usdc"))
    eff = child.intersect(parent)
    ok, why = eff.permits("FREEZE_ROUTE", "route:eth-usdc", 75_000)
    check("intersected ceiling denies over-value freeze", not ok, why)
    ok, why = eff.permits("UNFREEZE_ROUTE", "route:eth-usdc", 10_000)
    check("child cannot widen act class", not ok, why)

    if failures:
        print(f"\nSELF-CHECK FAILED: {len(failures)} failure(s)")
        return 1
    print("\nSELF-CHECK GREEN: classifier proposes, deterministic gate disposes, receipts verify.")
    return 0


if __name__ == "__main__":
    if "--scenario" in sys.argv:
        print(json.dumps(run_scenario(), indent=2, sort_keys=True))
        raise SystemExit(0)
    raise SystemExit(self_check())
