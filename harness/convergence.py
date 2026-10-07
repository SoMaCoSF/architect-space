#!/usr/bin/env python3
"""Convergence kit for external Guardian/Sentinel receipt records.

This module ingests Architect-shaped records; it does not run the gate and it
never changes policy constants. Its job is narrower and more useful for a
model comparison:

* map every supplied field onto the harness receipt schema, or name it as
  having no home;
* name every harness receipt field for which the external record supplies no
  source;
* diff supplied production thresholds against current reference constants;
* report candidate changes without applying them.

Stdlib only.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from guardian import FORBIDDEN_ACTS, GRAY_HIGH, GRAY_LOW

# The shipped scenario grants use this value repeatedly. It is a reference
# ceiling for comparison, not a universal production limit.
REFERENCE_MAX_VALUE_AT_RISK = 250_000.0
REFERENCE_ALLOWED_ACTS = ("OBSERVE", "ESCALATE", "FREEZE_ROUTE")


def _norm_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")


def _json_line(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _is_present(value: Any) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def _as_float(value: Any) -> Optional[float]:
    try:
        if isinstance(value, bool):
            return None
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _first_value(record: Mapping[str, Any], aliases: Iterable[str]) -> Tuple[Optional[str], Any]:
    alias_set = {_norm_key(a) for a in aliases}
    for key, value in record.items():
        if _norm_key(key) in alias_set:
            return str(key), value
    return None, None


def _sub_value(value: Mapping[str, Any], aliases: Iterable[str]) -> Tuple[Optional[str], Any]:
    return _first_value(value, aliases)


# ── external receipt mapping ────────────────────────────────────────────────

CORE_FIELDS: Tuple[Dict[str, Any], ...] = (
    {
        "canonical": "observed",
        "label": "what was observed",
        "aliases": (
            "observed", "observation", "observations", "evidence", "evidence_refs",
            "what_was_observed", "observed_data", "observation_data",
        ),
        "target": "classifier_proposal.payload.evidence[]",
    },
    {
        "canonical": "decided",
        "label": "what Jev/classifier decided",
        "aliases": (
            "decided", "decision", "jev_decided", "what_jev_decided",
            "classifier_decision", "classification", "choice",
        ),
        "target": "classifier_proposal.payload.choice",
    },
    {
        "canonical": "confidence",
        "label": "confidence",
        "aliases": ("confidence", "confidence_score", "model_confidence"),
        "target": "classifier_proposal.payload.confidence",
    },
    {
        "canonical": "distribution",
        "label": "distribution",
        "aliases": (
            "distribution", "probability_distribution", "probabilities",
            "choice_distribution", "distribution_over_choices",
        ),
        "target": "classifier_proposal.payload.distribution",
    },
    {
        "canonical": "policy",
        "label": "what policy allowed or denied",
        "aliases": (
            "policy", "policy_decision", "policy_outcome", "policy_result",
            "policy_allowed_denied", "policy_allowed_or_denied",
            "what_policy_allowed_or_denied", "allowed_or_denied", "allowed_denied",
            "gate_decision", "gate_verdict", "verdict",
        ),
        "target": "gate_decision.payload.verdict (+ reason when supplied)",
    },
    {
        "canonical": "final_action",
        "label": "the final action taken",
        "aliases": (
            "final_action", "final_action_taken", "final action taken",
            "action_taken", "action", "act", "final_act",
        ),
        "target": "act_result.payload.act + result.status (or no act)",
    },
)

COMBINED_CONFIDENCE_ALIASES = (
    "confidence_distribution", "confidence_and_distribution",
    "confidence_plus_distribution", "confidence_score_distribution",
)

# Harness fields that Architect's five-field record does not ordinarily carry.
# If an external record happens to use one of these names, it is mapped rather
# than reported as an unexplained extra.
OUR_ONLY_FIELDS: Tuple[Dict[str, Any], ...] = (
    {
        "canonical": "decision_id",
        "label": "decision identity",
        "aliases": ("decision_id", "receipt_decision_id"),
        "target": "classifier_proposal.payload.decision_id",
        "target_path": ("classifier_proposal", "decision_id"),
    },
    {
        "canonical": "subject_id",
        "label": "subject identity",
        "aliases": ("subject_id", "subject", "route_id", "provider_id"),
        "target": "classifier_proposal.payload.subject_id",
        "target_path": ("classifier_proposal", "subject_id"),
    },
    {
        "canonical": "proposer_id",
        "label": "proposer identity",
        "aliases": ("proposer_id", "actor_id", "sentinel_id"),
        "target": "classifier_proposal.payload.proposer_id",
        "target_path": ("classifier_proposal", "proposer_id"),
    },
    {
        "canonical": "proposed_act",
        "label": "proposed act (distinct from final act)",
        "aliases": ("proposed_act", "requested_act"),
        "target": "classifier_proposal.payload.proposed_act",
        "target_path": ("classifier_proposal", "proposed_act"),
    },
    {
        "canonical": "scope",
        "label": "act scope",
        "aliases": ("scope",),
        "target": "classifier_proposal.payload.scope",
        "target_path": ("classifier_proposal", "scope"),
    },
    {
        "canonical": "value_at_risk",
        "label": "value at risk",
        "aliases": ("value_at_risk", "value", "value_at_risk_usd"),
        "target": "classifier_proposal.payload.value_at_risk",
        "target_path": ("classifier_proposal", "value_at_risk"),
    },
    {
        "canonical": "classifier",
        "label": "classifier/model identity",
        "aliases": ("classifier", "classifier_id", "model", "model_version"),
        "target": "classifier_proposal.payload.classifier",
        "target_path": ("classifier_proposal", "classifier"),
    },
    {
        "canonical": "reason",
        "label": "gate reason",
        "aliases": ("reason", "policy_reason", "gate_reason"),
        "target": "gate_decision.payload.reason",
        "target_path": ("gate_decision", "reason"),
    },
    {
        "canonical": "seq",
        "label": "receipt sequence",
        "aliases": ("seq", "sequence"),
        "target": "receipt.seq",
        "target_path": ("chain", "seq"),
    },
    {
        "canonical": "kind",
        "label": "receipt kind",
        "aliases": ("kind", "receipt_kind"),
        "target": "receipt.kind",
        "target_path": ("chain", "kind"),
    },
    {
        "canonical": "prev_hash",
        "label": "previous receipt hash",
        "aliases": ("prev_hash", "previous_hash"),
        "target": "receipt.prev_hash",
        "target_path": ("chain", "prev_hash"),
    },
    {
        "canonical": "hash",
        "label": "receipt hash",
        "aliases": ("hash", "receipt_hash"),
        "target": "receipt.hash",
        "target_path": ("chain", "hash"),
    },
)


def load_external_ledger(path: str) -> List[Dict[str, Any]]:
    """Load a JSONL external ledger (or a JSON array of record objects)."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    stripped = text.strip()
    if not stripped:
        raise ValueError(f"{path}: no records found")
    if stripped.startswith("["):
        data = json.loads(stripped)
        if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
            raise ValueError(f"{path}: top-level JSON array must contain record objects")
        return data

    records: List[Dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: line {line_no} is not valid JSON ({exc})") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}: line {line_no} is not a JSON object")
        records.append(row)
    if not records:
        raise ValueError(f"{path}: no records found")
    return records


def _normalize_evidence(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item if isinstance(item, str) else _json_line(item) for item in value]
    if isinstance(value, str):
        return [value]
    return [_json_line(value)]


def _normalize_distribution(value: Any) -> Dict[str, float]:
    if isinstance(value, Mapping):
        out: Dict[str, float] = {}
        for key, raw in value.items():
            num = _as_float(raw)
            if num is not None:
                out[str(key)] = num
        return out
    if isinstance(value, list):
        out = {}
        for item in value:
            if isinstance(item, Mapping):
                key = item.get("choice", item.get("label", item.get("name")))
                num = _as_float(item.get("probability", item.get("confidence", item.get("value"))))
                if key is not None and num is not None:
                    out[str(key)] = num
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                num = _as_float(item[1])
                if num is not None:
                    out[str(item[0])] = num
        return out
    return {}


def _normalize_decided(value: Any) -> Optional[str]:
    if isinstance(value, Mapping):
        _key, nested = _sub_value(value, ("choice", "decided", "decision", "classification"))
        return str(nested) if _is_present(nested) else None
    return str(value) if _is_present(value) else None


def _normalize_policy(value: Any) -> Tuple[Optional[str], Optional[str], List[str]]:
    """Return (verdict, reason, nested-unmapped-paths)."""
    if isinstance(value, Mapping):
        _k, verdict_raw = _sub_value(
            value, ("verdict", "outcome", "decision", "policy_decision", "result", "status")
        )
        _k, reason_raw = _sub_value(value, ("reason", "rationale", "explanation"))
        _k, allowed_raw = _sub_value(value, ("allowed", "allow", "permitted"))
        _k, denied_raw = _sub_value(value, ("denied", "deny", "rejected"))
        known = {
            _norm_key(k)
            for k in value.keys()
            if _norm_key(k)
            in {
                "verdict", "outcome", "decision", "policy_decision", "result", "status",
                "reason", "rationale", "explanation", "allowed", "allow", "permitted",
                "denied", "deny", "rejected",
            }
        }
        unmapped = [str(k) for k in value.keys() if _norm_key(k) not in known]
        if isinstance(allowed_raw, bool):
            verdict = "ALLOW" if allowed_raw else "DENY"
        elif isinstance(denied_raw, bool):
            verdict = "DENY" if denied_raw else "ALLOW"
        else:
            verdict = _normalize_verdict(verdict_raw)
        reason = str(reason_raw) if _is_present(reason_raw) else None
        return verdict, reason, unmapped
    return _normalize_verdict(value), None, []


def _normalize_verdict(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return "ALLOW" if value else "DENY"
    if not _is_present(value):
        return None
    text = str(value).strip().upper()
    if any(token in text for token in ("ESCALAT", "HUMAN", "REVIEW")):
        return "ESCALATE"
    if any(token in text for token in ("DENY", "DENIED", "REJECT", "BLOCK", "FORBID")):
        return "DENY"
    if any(token in text for token in ("ALLOW", "ALLOWED", "APPROV", "PERMIT")):
        return "ALLOW"
    if text in {"NONE", "NO_ACT", "NO ACTION", "OBSERVE_ONLY"}:
        return "DENY"
    return text


def _normalize_final_action(value: Any) -> Tuple[Optional[str], Optional[str], List[str]]:
    """Return (act, reported status, nested-unmapped-paths)."""
    if isinstance(value, Mapping):
        _k, act_raw = _sub_value(value, ("act", "action", "name", "final_action", "action_taken"))
        _k, status_raw = _sub_value(value, ("status", "result", "outcome", "state"))
        known = {
            _norm_key(k)
            for k in value.keys()
            if _norm_key(k) in {"act", "action", "name", "final_action", "action_taken", "status", "result", "outcome", "state"}
        }
        unmapped = [str(k) for k in value.keys() if _norm_key(k) not in known]
        act = str(act_raw) if _is_present(act_raw) else None
        status = str(status_raw) if _is_present(status_raw) else None
        if act and act.strip().upper() in {"NONE", "NO_ACT", "NO ACTION", "NULL"}:
            return None, status or "none_reported", unmapped
        return act, status, unmapped
    if not _is_present(value):
        return None, None, []
    act = str(value)
    if act.strip().upper() in {"NONE", "NO_ACT", "NO ACTION", "NULL"}:
        return None, "none_reported", []
    return act, None, []


def map_external_record(record: Mapping[str, Any], line: int) -> Dict[str, Any]:
    consumed: set[str] = set()
    source_fields: Dict[str, List[str]] = {}
    nested_unmapped: List[str] = []

    def use(canonical: str, key: Optional[str]) -> None:
        if key is not None:
            consumed.add(_norm_key(key))
            source_fields.setdefault(canonical, []).append(str(key))

    mapped: Dict[str, Any] = {
        "classifier_proposal": {
            "decision_id": None,
            "subject_id": None,
            "proposer_id": None,
            "choice": None,
            "confidence": None,
            "distribution": {},
            "proposed_act": None,
            "scope": None,
            "value_at_risk": None,
            "evidence": [],
            "classifier": None,
        },
        "gate_decision": {
            "decision_id": None,
            "verdict": None,
            "act": None,
            "reason": None,
        },
        "act_result": None,
        "chain": {"seq": None, "kind": None, "prev_hash": None, "hash": None},
    }
    proposal = mapped["classifier_proposal"]
    gate = mapped["gate_decision"]

    # Observed.
    key, value = _first_value(record, CORE_FIELDS[0]["aliases"])
    use("observed", key)
    if key is not None:
        proposal["evidence"] = _normalize_evidence(value)

    # Decided.
    key, value = _first_value(record, CORE_FIELDS[1]["aliases"])
    use("decided", key)
    if key is not None:
        proposal["choice"] = _normalize_decided(value)

    # Confidence + distribution, including the combined five-field form.
    combined_key, combined_value = _first_value(record, COMBINED_CONFIDENCE_ALIASES)
    if combined_key is not None:
        use("confidence", combined_key)
        use("distribution", combined_key)
        if isinstance(combined_value, Mapping):
            _k, conf_raw = _sub_value(combined_value, ("confidence", "confidence_score", "score", "value"))
            _k, dist_raw = _sub_value(
                combined_value,
                ("distribution", "probability_distribution", "probabilities", "choices"),
            )
            known = {
                _norm_key(k)
                for k in combined_value.keys()
                if _norm_key(k)
                in {
                    "confidence", "confidence_score", "score", "value", "distribution",
                    "probability_distribution", "probabilities", "choices",
                }
            }
            nested_unmapped.extend(
                f"{combined_key}.{k}" for k in combined_value.keys() if _norm_key(k) not in known
            )
            proposal["confidence"] = _as_float(conf_raw)
            proposal["distribution"] = _normalize_distribution(dist_raw)
        elif isinstance(combined_value, (list, tuple)) and len(combined_value) >= 2:
            proposal["confidence"] = _as_float(combined_value[0])
            proposal["distribution"] = _normalize_distribution(combined_value[1])
    else:
        key, value = _first_value(record, CORE_FIELDS[2]["aliases"])
        use("confidence", key)
        if key is not None:
            if isinstance(value, Mapping):
                _k, conf_raw = _sub_value(value, ("confidence", "confidence_score", "score", "value"))
                _k, dist_raw = _sub_value(
                    value, ("distribution", "probability_distribution", "probabilities", "choices")
                )
                proposal["confidence"] = _as_float(conf_raw if conf_raw is not None else value.get("confidence"))
                if dist_raw is not None:
                    use("distribution", key)
                    proposal["distribution"] = _normalize_distribution(dist_raw)
            else:
                proposal["confidence"] = _as_float(value)
        key, value = _first_value(record, CORE_FIELDS[3]["aliases"])
        use("distribution", key)
        if key is not None:
            proposal["distribution"] = _normalize_distribution(value)

    # Policy.
    key, value = _first_value(record, CORE_FIELDS[4]["aliases"])
    use("policy", key)
    policy_reason = None
    if key is not None:
        verdict, policy_reason, extras = _normalize_policy(value)
        gate["verdict"] = verdict
        gate["reason"] = policy_reason
        if policy_reason is not None:
            source_fields.setdefault("reason", []).append(f"{key}.reason")
        nested_unmapped.extend(f"{key}.{extra}" for extra in extras)

    # Final action.
    final_key, final_value = _first_value(record, CORE_FIELDS[5]["aliases"])
    use("final_action", final_key)
    final_act, final_status = None, None
    if final_key is not None:
        final_act, final_status, extras = _normalize_final_action(final_value)
        nested_unmapped.extend(f"{final_key}.{extra}" for extra in extras)

    # Our-only fields, if the external record happens to carry them.
    for spec in OUR_ONLY_FIELDS:
        key, value = _first_value(record, spec["aliases"])
        if key is None or _norm_key(key) in consumed:
            continue
        # Do not steal a key already semantically used by a core field.
        use(spec["canonical"], key)
        section, field = spec["target_path"]
        if section == "classifier_proposal":
            proposal[field] = value
        elif section == "gate_decision":
            gate[field] = value
        elif section == "chain":
            mapped["chain"][field] = value

    if gate["decision_id"] is None:
        gate["decision_id"] = proposal["decision_id"]
    gate["act"] = proposal["proposed_act"] or final_act
    if final_act is not None:
        mapped["act_result"] = {
            "decision_id": proposal["decision_id"],
            "act": final_act,
            "verdict": gate["verdict"],
            "result": {"status": final_status or "reported"},
        }

    unmapped: Dict[str, Any] = {}
    for key, value in record.items():
        if _norm_key(key) not in consumed:
            unmapped[str(key)] = value
    for path in nested_unmapped:
        unmapped[path] = "<nested field>"

    mapped_core: Dict[str, bool] = {
        "observed": bool(proposal["evidence"]),
        "decided": proposal["choice"] is not None,
        "confidence": proposal["confidence"] is not None,
        "distribution": bool(proposal["distribution"]),
        "policy": gate["verdict"] is not None,
        "final_action": final_key is not None and (final_act is not None or final_status is not None),
    }
    # An explicit "none" final-action report counts as mapped: it maps to the
    # absence of an act_result receipt, not to a missing field.
    present_core: Dict[str, bool] = {
        spec["canonical"]: any(_norm_key(src) in {_norm_key(k) for k in record.keys()} for src in source_fields.get(spec["canonical"], []))
        for spec in CORE_FIELDS
    }

    return {
        "line": line,
        "mapped": mapped,
        "source_fields": source_fields,
        "present_core": present_core,
        "mapped_core": mapped_core,
        "unmapped_fields": unmapped,
    }


def compare_records(records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    mapped_records = [map_external_record(record, i) for i, record in enumerate(records, start=1)]
    total = len(records)

    def build_rows(specs: Sequence[Mapping[str, Any]], core: bool) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for spec in specs:
            canonical = str(spec["canonical"])
            source_keys: Counter[str] = Counter()
            present_lines: List[int] = []
            mapped_lines: List[int] = []
            for item in mapped_records:
                for src in item["source_fields"].get(canonical, []):
                    source_keys[src] += 1
                if core:
                    if item["present_core"].get(canonical):
                        present_lines.append(item["line"])
                    if item["mapped_core"].get(canonical):
                        mapped_lines.append(item["line"])
                else:
                    if canonical in item["source_fields"]:
                        present_lines.append(item["line"])
                        mapped_lines.append(item["line"])
            rows.append(
                {
                    "canonical": canonical,
                    "label": spec["label"],
                    "source_fields": sorted(source_keys),
                    "present_lines": present_lines,
                    "mapped_lines": mapped_lines,
                    "missing_lines": [n for n in range(1, total + 1) if n not in present_lines],
                    "unmapped_lines": [
                        item["line"]
                        for item in mapped_records
                        if item["line"] in present_lines and item["line"] not in mapped_lines
                    ],
                    "target": spec["target"],
                }
            )
        return rows

    core_rows = build_rows(CORE_FIELDS, core=True)
    our_rows = build_rows(OUR_ONLY_FIELDS, core=False)

    unmapped_fields: Dict[str, List[int]] = {}
    for item in mapped_records:
        for field in item["unmapped_fields"]:
            unmapped_fields.setdefault(field, []).append(item["line"])

    five_field_convergent = all(
        len(row["mapped_lines"]) == total for row in core_rows
    ) and not unmapped_fields

    return {
        "record_count": total,
        "mapped_records": mapped_records,
        "core_rows": core_rows,
        "our_rows": our_rows,
        "unmapped_fields": unmapped_fields,
        "five_field_convergent": five_field_convergent,
    }


def compare_ledger(path: str) -> Dict[str, Any]:
    result = compare_records(load_external_ledger(path))
    result["path"] = path
    return result


def _status(row: Mapping[str, Any], total: int) -> str:
    present = len(row["present_lines"])
    mapped = len(row["mapped_lines"])
    if present == 0:
        return "missing"
    if mapped == present:
        return "present+mapped"
    if mapped == 0:
        return "present-unmapped"
    return "partially mapped"


def format_compare_report(result: Mapping[str, Any]) -> str:
    total = int(result["record_count"])
    lines: List[str] = []
    lines.append(f"external ledger: {result.get('path', '<records>')} ({total} record(s))")
    lines.append(
        "mapping basis: his five fields -> our classifier_proposal / gate_decision / act_result payloads; "
        "unknown fields are named, never silently dropped"
    )
    lines.append("")
    lines.append("FIELD CONVERGENCE TABLE")
    lines.append("canonical field | his source field(s) | his status | our receipt home | our status | coverage")

    def append_row(row: Mapping[str, Any]) -> None:
        source = ", ".join(row["source_fields"]) if row["source_fields"] else "—"
        his_status = _status(row, total)
        our_status = "mapped" if row["mapped_lines"] else "no source"
        coverage = f"{len(row['mapped_lines'])}/{total} mapped; {len(row['present_lines'])}/{total} present"
        lines.append(
            f"{row['canonical']} | {source} | {his_status} | {row['target']} | {our_status} | {coverage}"
        )

    for row in result["core_rows"]:
        append_row(row)
    for row in result["our_rows"]:
        append_row(row)

    lines.append("")
    if result["five_field_convergent"]:
        lines.append(
            f"FIVE-FIELD CONVERGENCE: CONVERGENT — all five fields present and mapped in {total}/{total} records; no unmapped fields"
        )
    else:
        missing_names = [
            row["canonical"] for row in result["core_rows"] if len(row["mapped_lines"]) != total
        ]
        extra = f"; unmapped fields present" if result["unmapped_fields"] else ""
        lines.append(
            "FIVE-FIELD CONVERGENCE: DIVERGENT — incomplete or unmapped fields: "
            + (", ".join(missing_names) if missing_names else "none")
            + extra
        )

    lines.append("")
    lines.append("HIS FIELDS WITH NO HOME IN OUR SCHEMA")
    if result["unmapped_fields"]:
        for field, record_lines in sorted(result["unmapped_fields"].items()):
            lines.append(f"- {field} (record line(s): {', '.join(map(str, record_lines))}) — no current target; named, not dropped")
    else:
        lines.append("- none")

    lines.append("")
    lines.append("OUR FIELDS WITH NO SOURCE IN HIS RECORDS")
    missing_ours = [row for row in result["our_rows"] if not row["mapped_lines"]]
    partial_ours = [row for row in result["our_rows"] if 0 < len(row["mapped_lines"]) < total]
    if missing_ours:
        for row in missing_ours:
            lines.append(f"- {row['canonical']} -> {row['target']} (no source in any record)")
    else:
        lines.append("- none globally absent")
    if partial_ours:
        for row in partial_ours:
            lines.append(
                f"- {row['canonical']} -> {row['target']} (partial source: {len(row['mapped_lines'])}/{total} records)"
            )

    lines.append("")
    lines.append("PER-RECORD GAPS")
    any_gap = False
    for item in result["mapped_records"]:
        gaps = [
            row["canonical"]
            for row in result["core_rows"]
            if item["line"] in row["missing_lines"] or item["line"] in row["unmapped_lines"]
        ]
        if gaps:
            any_gap = True
            lines.append(f"- line {item['line']}: {', '.join(gaps)}")
    if not any_gap:
        lines.append("- none in the five shared fields")

    lines.append("")
    lines.append("MAPPED SCHEMA VIEW")
    for item in result["mapped_records"]:
        lines.append(f"line {item['line']}: {_json_line(item['mapped'])}")
    return "\n".join(lines)


# ── threshold diff ──────────────────────────────────────────────────────────

def _nested(data: Mapping[str, Any], keys: Iterable[str]) -> Any:
    wanted = {_norm_key(k) for k in keys}
    for key, value in data.items():
        if _norm_key(key) in wanted:
            return value
    return None


def _merge_threshold_root(data: Mapping[str, Any]) -> Dict[str, Any]:
    root: Dict[str, Any] = dict(data)
    nested = _nested(data, ("thresholds", "escalation_thresholds", "architect_thresholds"))
    if isinstance(nested, Mapping):
        merged = dict(nested)
        merged.update({k: v for k, v in root.items() if _norm_key(k) not in {"thresholds", "escalation_thresholds", "architect_thresholds"}})
        return merged
    return root


def _gray_band(data: Mapping[str, Any]) -> Tuple[Optional[float], Optional[float]]:
    raw = _nested(data, ("gray_band", "gray_band_bounds", "escalation_band", "escalation_thresholds"))
    # escalation_thresholds may itself be the root after merging; avoid loops.
    if isinstance(raw, Mapping) and ("low" in raw or "high" in raw or "min" in raw or "max" in raw):
        low = _as_float(_nested(raw, ("low", "min", "lower", "floor")))
        high = _as_float(_nested(raw, ("high", "max", "upper", "ceiling")))
        return low, high
    if isinstance(raw, (list, tuple)) and len(raw) >= 2:
        return _as_float(raw[0]), _as_float(raw[1])
    low = _as_float(_nested(data, ("gray_band_low", "gray_low", "escalation_floor")))
    high = _as_float(_nested(data, ("gray_band_high", "gray_high", "escalation_ceiling")))
    return low, high


def _ceiling_data(data: Mapping[str, Any]) -> Tuple[Optional[float], Optional[List[str]]]:
    raw = _nested(data, ("ceilings", "ceiling", "policy_ceilings", "ceiling_policy"))
    max_value: Optional[float] = None
    acts: Optional[List[str]] = None
    if isinstance(raw, Mapping):
        max_value = _as_float(_nested(raw, ("max_value_at_risk", "max_value", "value_ceiling", "ceiling")))
        acts_raw = _nested(raw, ("allowed_acts", "acts", "act_classes"))
        if isinstance(acts_raw, list):
            acts = [str(x) for x in acts_raw]
    direct = _as_float(_nested(data, ("max_value_at_risk", "ceiling_max_value_at_risk")))
    if direct is not None:
        max_value = direct
    acts_raw = _nested(data, ("allowed_acts", "ceiling_allowed_acts"))
    if isinstance(acts_raw, list):
        acts = [str(x) for x in acts_raw]
    return max_value, acts


def _latency_budgets(data: Mapping[str, Any]) -> Dict[str, float]:
    raw = _nested(
        data,
        ("latency_budgets_ms", "latency_budgets", "latency_ms", "latency", "latency_budget_ms"),
    )
    budgets: Dict[str, float] = {}
    if isinstance(raw, Mapping):
        for key, value in raw.items():
            if isinstance(value, Mapping):
                for subkey, subvalue in value.items():
                    num = _as_float(subvalue)
                    if num is not None:
                        budgets[f"{key}_{subkey}"] = num
            else:
                num = _as_float(value)
                if num is not None:
                    budgets[str(key)] = num
    elif isinstance(raw, (int, float)):
        budgets["end_to_end"] = float(raw)
    # Tolerate flat p95_ms-style fields at the root.
    for key, value in data.items():
        nk = _norm_key(key)
        if nk in {"p50_ms", "p95_ms", "p99_ms", "latency_p95_ms", "end_to_end_p95_ms"}:
            num = _as_float(value)
            if num is not None:
                budgets.setdefault(str(key), num)
    return budgets


def _latency_constant_name(raw_key: str) -> str:
    nk = _norm_key(raw_key)
    nk = nk.replace("_milliseconds", "").replace("_ms", "")
    if "classifier" in nk or "jev" in nk or "model" in nk:
        prefix = "CLASSIFIER"
    elif "gate" in nk or "policy" in nk or "ledgerguard" in nk:
        prefix = "GATE"
    elif "receipt" in nk or "ledger" in nk:
        prefix = "RECEIPT"
    elif "end_to_end" in nk or "total" in nk or nk in {"latency", "budget"}:
        prefix = "END_TO_END"
    else:
        prefix = nk.upper()
    percentile = ""
    for token in ("p50", "p90", "p95", "p99"):
        if token in nk:
            percentile = f"_{token.upper()}"
            break
    if prefix == nk.upper():
        return f"{prefix}_LATENCY_BUDGET_MS"
    return f"{prefix}{percentile}_LATENCY_BUDGET_MS"


def _failure_modes(data: Mapping[str, Any]) -> Tuple[Optional[float], Dict[str, float]]:
    raw = _nested(data, ("failure_modes", "failure_mode_counts", "failure_modes_counts", "failures"))
    total: Optional[float] = None
    counts: Dict[str, float] = {}
    if isinstance(raw, Mapping):
        total = _as_float(
            _nested(raw, ("total_decisions", "total", "denominator", "decisions", "total_count"))
        )
        counts_raw = _nested(raw, ("counts", "modes", "by_mode", "failure_counts"))
        source = counts_raw if isinstance(counts_raw, Mapping) else raw
        if isinstance(source, Mapping):
            for key, value in source.items():
                if _norm_key(key) in {"total_decisions", "total", "denominator", "decisions", "total_count", "counts", "modes", "by_mode", "failure_counts"}:
                    continue
                num = _as_float(value)
                if num is not None:
                    counts[str(key)] = num
        if isinstance(counts_raw, list):
            for item in counts_raw:
                if isinstance(item, Mapping):
                    name = item.get("mode", item.get("name", item.get("failure_mode")))
                    num = _as_float(item.get("count", item.get("value", item.get("n"))))
                    if name is not None and num is not None:
                        counts[str(name)] = num
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, Mapping):
                name = item.get("mode", item.get("name", item.get("failure_mode")))
                num = _as_float(item.get("count", item.get("value", item.get("n"))))
                if name is not None and num is not None:
                    counts[str(name)] = num
    direct_total = _as_float(_nested(data, ("total_decisions", "decision_total")))
    if direct_total is not None:
        total = direct_total
    return total, counts


def thresholds_report(data: Mapping[str, Any]) -> Dict[str, Any]:
    root = _merge_threshold_root(data)
    source = root.get("source", root.get("name", "<unspecified>"))
    lines: List[str] = []
    changes: List[str] = []

    lines.append(f"threshold source: {source}")
    lines.append("mode: REPORT ONLY — ingestion never applies policy constants")
    lines.append(
        f"current gate constants: GRAY_LOW={GRAY_LOW:.2f}, GRAY_HIGH={GRAY_HIGH:.2f}, "
        f"width={GRAY_HIGH - GRAY_LOW:.2f}; forbidden acts={', '.join(sorted(FORBIDDEN_ACTS))}"
    )
    lines.append(
        f"reference scenario ceiling: max_value_at_risk={REFERENCE_MAX_VALUE_AT_RISK:,.0f}; "
        f"allowed acts={', '.join(REFERENCE_ALLOWED_ACTS)}"
    )
    lines.append("")

    low, high = _gray_band(root)
    if low is not None or high is not None:
        lines.append("GRAY BAND DIFF")
        if low is not None:
            delta = low - GRAY_LOW
            lines.append(
                f"- GRAY_LOW: current {GRAY_LOW:.2f} -> supplied {low:.2f} (Δ {delta:+.2f})"
                + (" — CHANGE CANDIDATE" if delta != 0 else " — no change")
            )
            if delta != 0:
                changes.append(f"GRAY_LOW {GRAY_LOW:.2f} -> {low:.2f} ({delta:+.2f})")
        if high is not None:
            delta = high - GRAY_HIGH
            lines.append(
                f"- GRAY_HIGH: current {GRAY_HIGH:.2f} -> supplied {high:.2f} (Δ {delta:+.2f})"
                + (" — CHANGE CANDIDATE" if delta != 0 else " — no change")
            )
            if delta != 0:
                changes.append(f"GRAY_HIGH {GRAY_HIGH:.2f} -> {high:.2f} ({delta:+.2f})")
        if low is not None and high is not None:
            width = high - low
            current_width = GRAY_HIGH - GRAY_LOW
            lines.append(
                f"- gray-band width: current {current_width:.2f} -> supplied {width:.2f} (Δ {width - current_width:+.2f})"
            )
            if not (0 <= low < high <= 1):
                lines.append("- WARNING: supplied gray band is outside [0,1] or low >= high; treat as invalid until corrected")
        lines.append("")

    max_value, supplied_acts = _ceiling_data(root)
    if max_value is not None or supplied_acts is not None:
        lines.append("CEILING DIFF (against the shipped reference scenario grant)")
        if max_value is not None:
            delta = max_value - REFERENCE_MAX_VALUE_AT_RISK
            pct = (delta / REFERENCE_MAX_VALUE_AT_RISK * 100) if REFERENCE_MAX_VALUE_AT_RISK else 0.0
            lines.append(
                f"- REFERENCE_MAX_VALUE_AT_RISK: current {REFERENCE_MAX_VALUE_AT_RISK:,.0f} -> supplied {max_value:,.0f} "
                f"(Δ {delta:+,.0f}; {pct:+.1f}%)"
                + (" — CHANGE CANDIDATE" if delta != 0 else " — no change")
            )
            if delta != 0:
                changes.append(
                    f"REFERENCE_MAX_VALUE_AT_RISK {REFERENCE_MAX_VALUE_AT_RISK:,.0f} -> {max_value:,.0f} ({delta:+,.0f}; {pct:+.1f}%)"
                )
        if supplied_acts is not None:
            current = set(REFERENCE_ALLOWED_ACTS)
            supplied = set(supplied_acts)
            added = sorted(supplied - current)
            removed = sorted(current - supplied)
            forbidden = sorted(supplied & FORBIDDEN_ACTS)
            if added:
                lines.append(
                    f"- supplied act classes not in the reference grant: {', '.join(added)} — not effective unless an issuer grants them; intersection cannot widen authority"
                )
            if removed:
                lines.append(
                    f"- reference act classes absent from supplied ceiling: {', '.join(removed)} — adopting this would narrow the reference grant"
                )
            if forbidden:
                lines.append(
                    f"- supplied act classes that remain forbidden regardless of any ceiling: {', '.join(forbidden)}"
                )
            if not added and not removed:
                lines.append("- allowed act classes: identical to the reference grant")
        lines.append("")

    budgets = _latency_budgets(root)
    if budgets:
        lines.append("LATENCY BUDGET DIFF")
        lines.append("- current harness state: no latency-budget constants are defined in guardian.py")
        for raw_key in sorted(budgets):
            const_name = _latency_constant_name(raw_key)
            lines.append(
                f"- {const_name}: current <not set> -> supplied {budgets[raw_key]:,.0f} ms — WOULD ADD a constant; no delta against an existing default exists"
            )
            changes.append(f"ADD {const_name} = {budgets[raw_key]:,.0f} ms (currently not set)")
        lines.append("")

    total, counts = _failure_modes(root)
    if counts or total is not None:
        lines.append("FAILURE-MODE EVIDENCE (counts inform review; they do not derive constants)")
        if total is not None:
            lines.append(f"- total decisions supplied: {total:,.0f}")
        for mode in sorted(counts):
            count = counts[mode]
            share = f" ({count / total:.2%} of supplied total)" if total else ""
            lines.append(f"- {mode}: {count:,.0f}{share}")
            nk = _norm_key(mode)
            if "forbidden" in nk or "move_funds" in nk:
                lines.append("  policy effect: none proposed — forbidden acts remain deterministic DENY at any confidence")
            elif "gray" in nk or "escalat" in nk:
                lines.append("  policy effect: evidence for gray-band review only; a count alone does not move GRAY_LOW or GRAY_HIGH")
            elif "ceiling" in nk or "over_value" in nk:
                lines.append("  policy effect: evidence for ceiling review only; a count alone does not move a ceiling")
            elif "tamper" in nk or "receipt" in nk:
                lines.append("  policy effect: receipt-integrity evidence; no threshold constant follows from the count alone")
            else:
                lines.append("  policy effect: no current constant maps to this mode; named here rather than dropped")
        lines.append("")

    lines.append("CANDIDATE CHANGES (not applied)")
    if changes:
        for change in changes:
            lines.append(f"- {change}")
    else:
        lines.append("- none")
    lines.append("No file, gate constant, ceiling, or scenario was modified by this report.")

    return {"lines": lines, "changes": changes, "text": "\n".join(lines)}


def load_thresholds(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: threshold input must be a JSON object")
    return data


def format_thresholds_report(data: Mapping[str, Any]) -> str:
    return str(thresholds_report(data)["text"])
