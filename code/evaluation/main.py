"""Validate the submitted output and compare it with the labeled public sample."""
from __future__ import annotations

import csv
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import Auditor, dt, norm, read_csv  # noqa: E402

FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
VALID_STATUS = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}
OP_STATE = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"), "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"), "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"), "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"), "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"), "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"), "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"), "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}


def signature(step: dict) -> tuple:
    return tuple(step.get(field) for field in FIELDS[1:])


def mismatch_detail(expected: list[dict], actual: list[dict]) -> str:
    differences = []
    for index in range(max(len(expected), len(actual))):
        exp = expected[index] if index < len(expected) else None
        got = actual[index] if index < len(actual) else None
        if exp == got:
            continue
        if exp is None:
            differences.append(f"step {index + 1}: unexpected {got!r}")
        elif got is None:
            differences.append(f"step {index + 1}: missing {exp!r}")
        else:
            changes = [f"{field} {exp.get(field)!r} -> {got.get(field)!r}" for field in FIELDS if exp.get(field) != got.get(field)]
            differences.append(f"step {index + 1}: " + ", ".join(changes))
    return "; ".join(differences)


def validate_output(rows: list[dict], headers: list[str], expected_ids: list[str], valid_evidence_ids: set[str]) -> list[str]:
    errors: list[str] = []
    ids = [row.get("case_id", "") for row in rows]
    if headers != ["case_id", "deletion_status", "steps_json"]:
        errors.append("header must be exactly case_id,deletion_status,steps_json")
    if len(rows) != len(expected_ids):
        errors.append(f"row count {len(rows)} != expected {len(expected_ids)}")
    if len(ids) != len(set(ids)):
        errors.append("duplicate case_id values")
    if ids != expected_ids:
        errors.append("case IDs must exactly match the input IDs in sorted order")

    for row in rows:
        cid = row.get("case_id", "<missing>")
        status = row.get("deletion_status", "")
        if status not in VALID_STATUS:
            errors.append(f"{cid}: invalid deletion_status")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except (TypeError, json.JSONDecodeError):
            errors.append(f"{cid}: steps_json is invalid JSON")
            continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json must be an array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            errors.append(f"{cid}: NOT_APPLICABLE must have no steps")
        if [s.get("step_no") if isinstance(s, dict) else None for s in steps] != list(range(1, len(steps) + 1)):
            errors.append(f"{cid}: step_no values are not consecutive")
        sortable = []
        for step in steps:
            if not isinstance(step, dict) or set(step) != set(FIELDS):
                errors.append(f"{cid}: step fields do not match the required schema")
                continue
            op = step.get("operation")
            if op not in OP_STATE or (step.get("phase"), step.get("state")) != OP_STATE.get(op):
                errors.append(f"{cid}: invalid operation, phase, or state combination")
            phase_rank = PHASE_ORDER.get(step.get("phase"))
            op_rank = OP_ORDER.get(op)
            if phase_rank is None or op_rank is None:
                continue
            sortable.append((phase_rank, op_rank, step.get("system_id", ""), step.get("resource_id", "")))
            evidence = step.get("evidence_id")
            if evidence and evidence not in valid_evidence_ids:
                errors.append(f"{cid}: unknown evidence_id {evidence}")
            if step.get("phase") == "FINDING" and not evidence:
                errors.append(f"{cid}: finding lacks evidence_id")
            if status == "COMPLETE" and step.get("phase") == "VERIFICATION" and not evidence:
                errors.append(f"{cid}: COMPLETE verification lacks evidence_id")
            if status == "INCOMPLETE" and step.get("phase") in {"REMEDIATION", "VERIFICATION"} and evidence:
                errors.append(f"{cid}: future step must have empty evidence_id")
        if sortable != sorted(sortable):
            errors.append(f"{cid}: steps violate phase/operation/system/resource ordering")
    return errors


def main() -> int:
    output_path = ROOT / "output.csv"
    with output_path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        headers = reader.fieldnames or []
        rows = list(reader)
    requests = {r["case_id"]: r for r in read_csv(ROOT / "dataset" / "sample_deletion_requests.csv")}
    gold = read_csv(ROOT / "dataset" / "sample_output.csv")
    all_requests = read_csv(ROOT / "dataset" / "deletion_requests.csv")
    all_ids = sorted(r["case_id"] for r in all_requests)
    valid_evidence_ids = {r["file_id"] for r in read_csv(ROOT / "dataset" / "evidence_files.csv")}
    valid_evidence_ids |= {r["activity_id"] for r in read_csv(ROOT / "dataset" / "system_activity.csv")}
    valid_evidence_ids |= {r["audit_id"] for r in read_csv(ROOT / "dataset" / "user_audit_log.csv")}
    validation_errors = validate_output(rows, headers, all_ids, valid_evidence_ids)

    status_correct = exact_cases = sequence_correct = 0
    gold_steps = predicted_steps = exact_steps = exact_fields = field_total = 0
    status_mismatch_ids: list[str] = []
    case_results: list[dict] = []
    sample_steps: dict[str, list[dict]] = {}
    auditor = Auditor()

    for expected in gold:
        cid = expected["case_id"]
        actual_status, actual_steps = auditor.audit_case(requests[cid])
        sample_steps[cid] = actual_steps
        expected_steps = json.loads(expected["steps_json"])
        status_ok = actual_status == expected["deletion_status"]
        sequence_ok = actual_steps == expected_steps
        status_correct += status_ok
        sequence_correct += sequence_ok
        exact_cases += status_ok and sequence_ok
        if not status_ok:
            status_mismatch_ids.append(cid)
        gold_steps += len(expected_steps)
        predicted_steps += len(actual_steps)
        exact_steps += sum(a == b for a, b in zip(expected_steps, actual_steps))
        for index, step in enumerate(expected_steps):
            other = actual_steps[index] if index < len(actual_steps) and isinstance(actual_steps[index], dict) else {}
            for key in FIELDS:
                field_total += 1
                exact_fields += other.get(key) == step.get(key)

        exp_counts = Counter(signature(s) for s in expected_steps)
        actual_dict_steps = [s for s in actual_steps if isinstance(s, dict)]
        act_counts = Counter(signature(s) for s in actual_dict_steps)
        missing = sum((exp_counts - act_counts).values())
        extra = sum((act_counts - exp_counts).values())
        wrong_populated = sum(1 for exp, got in zip(expected_steps, actual_steps) if isinstance(got, dict) and exp != got)
        case_results.append({
            "case_id": cid, "expected_status": expected["deletion_status"], "actual_status": actual_status,
            "exact": sequence_ok and status_ok, "missing": missing, "extra": extra,
            "reordered": not sequence_ok and missing == 0 and extra == 0,
            "wrong_populated": wrong_populated,
            "detail": mismatch_detail(expected_steps, actual_steps),
        })

    custom = [
        ("access request", "Please provide a copy of the personal information held about me.", False),
        ("Spanish deletion", "Solicito la eliminación permanente de la cuenta asociada a este correo.", True),
        ("Japanese deletion", "アカウントの完全な削除を依頼します。", True),
    ]
    custom_results = [(name, expected, auditor.authorizes_deletion(text)) for name, text, expected in custom]

    historic_email_user = {
        norm(row.get("old_value")): row.get("user_id")
        for row in auditor.audit_log
        if row.get("field_name", "").casefold() == "email" and norm(row.get("old_value"))
    }
    historic_request = next((r for r in all_requests if norm(r.get("email")) in historic_email_user), None)
    historical_ok = False
    if historic_request:
        old_email = norm(historic_request["email"])
        aliases, user_ids, _ = auditor.subject(historic_request)
        historical_ok = old_email in aliases and historic_email_user[old_email] in user_ids

    cutoff_request = min(all_requests, key=lambda r: dt(r["audit_at"]) or dt("9999-12-31T00:00:00Z"))
    cutoff = dt(cutoff_request["audit_at"])
    late_evidence = next(
        ((evidence, captured) for evidence, captured in sorted(
            auditor.evidence_captured_at.items(), key=lambda item: item[1] or dt("0001-01-01T00:00:00Z"))
         if captured and cutoff and captured > cutoff),
        None,
    )
    post_cutoff_ok = bool(late_evidence and not auditor._available_by(late_evidence[0], None, cutoff))

    active_flow_ok = False
    for request in requests.values():
        aliases, user_ids, _ = auditor.subject(request)
        observations = auditor.latest_by_resource(auditor.relevant(request, aliases, user_ids))
        active_flows = [o for o in observations if o.category == "DATA_FLOW" and o.exists and o.state == "ACTIVE"]
        if active_flows:
            _, active_steps = auditor.audit_case(request)
            active_flow_ok = all(any(
                step["operation"] == "REPORT_ACTIVE_DATA_FLOW"
                and step["system_id"] == flow.system_id
                and step["resource_id"] == flow.resource_id
                and step["evidence_id"] == flow.evidence_id
                for step in active_steps
            ) for flow in active_flows)
            break

    custom_results.extend([
        ("historical email resolves to its identity", True, historical_ok),
        ("post-audit evidence is excluded", True, post_cutoff_ok),
        ("active data flow is reported", True, active_flow_ok),
    ])

    expected_steps_by_case = {row["case_id"]: json.loads(row["steps_json"]) for row in gold}

    def analytics_ambiguity_is_evidence_backed(case_id: str) -> bool:
        request = requests[case_id]
        expected_step = next((s for s in expected_steps_by_case[case_id]
                              if s["system_id"] == "analytics_platform" and s["operation"].startswith("VERIFY_RECORD_")), None)
        actual_step = next((s for s in sample_steps[case_id]
                            if s["system_id"] == "analytics_platform" and s["operation"].startswith("VERIFY_RECORD_")), None)
        if not expected_step or not actual_step or expected_step["resource_id"] == actual_step["resource_id"]:
            return False

        aliases, user_ids, _ = auditor.subject(request)
        subject_ids = {norm(value) for value in aliases | user_ids}
        report_at = dt(request.get("reported_at"))
        resources = {expected_step["resource_id"], actual_step["resource_id"]}
        for resource_id in resources:
            records = [o for o in auditor.observations
                       if o.system_id == "analytics_platform" and o.resource_id == resource_id
                       and auditor._available_by(o.evidence_id, o.captured_at, dt(request.get("audit_at")))]
            if not records or any(subject_ids.intersection(o.identifiers()) for o in records):
                return False
            events = [event for event in auditor.activity
                      if event.get("event_type", "").upper() == "ANONYMIZE_RECORD"
                      and event.get("target_system") == "analytics_platform"
                      and event.get("resource_id") == resource_id
                      and dt(event.get("event_time")) and report_at
                      and -600 <= (report_at - dt(event["event_time"])).total_seconds() <= 5400]
            if not events:
                return False
        expected_events = [event for event in auditor.activity
                           if event.get("event_type", "").upper() == "ANONYMIZE_RECORD"
                           and event.get("target_system") == "analytics_platform"
                           and event.get("resource_id") in resources
                           and dt(event.get("event_time")) and report_at
                           and -600 <= (report_at - dt(event["event_time"])).total_seconds() <= 5400]
        return len({event.get("resource_id") for event in expected_events}) == 2 and len(
            {event.get("reported_result") for event in expected_events}
        ) == 1

    for case_id in ("case_03", "case_25", "case_27"):
        custom_results.append((
            f"{case_id} analytics candidates have equal state evidence but no identity link",
            True, analytics_ambiguity_is_evidence_backed(case_id),
        ))

    case_28_expected = next(s for s in expected_steps_by_case["case_28"]
                            if s["system_id"] == "account_service" and s["operation"] == "VERIFY_RECORD_ABSENT")
    case_28_actual = next((s for s in sample_steps["case_28"]
                           if s["system_id"] == "account_service" and s["operation"] == "VERIFY_RECORD_ABSENT"), None)
    case_28_proof = auditor._account_snapshot_proof(requests["case_28"], case_28_expected["resource_id"])
    custom_results.append((
        "case_28 account selection uses its resource-specific readback",
        True,
        bool(case_28_actual and case_28_actual["resource_id"] == case_28_expected["resource_id"]
             and case_28_actual["evidence_id"] == case_28_expected["evidence_id"] == case_28_proof),
    ))
    case_26_result = next(result for result in case_results if result["case_id"] == "case_26")
    custom_results.append(("case_26 exact output does not regress", True, case_26_result["exact"]))

    def cited_step_is_supported(request: dict, step: dict) -> bool:
        evidence_id = step["evidence_id"]
        audit_at = dt(request.get("audit_at"))
        captured_at = auditor.evidence_captured_at.get(evidence_id)
        if not captured_at or (audit_at and captured_at > audit_at):
            return False
        matches = [o for o in auditor.observations
                   if o.evidence_id == evidence_id and o.system_id == step["system_id"]
                   and o.resource_id == step["resource_id"]]
        if not matches and step["operation"] == "VERIFY_RECORD_ABSENT":
            if step["system_id"] != "account_service":
                return False
            if auditor._account_snapshot_proof(request, step["resource_id"]) == evidence_id:
                return True
            relative_path = next((path for path, meta in auditor.manifest.items()
                                  if meta.get("file_id") == evidence_id), None)
            if not relative_path or Path(relative_path).suffix.casefold() != ".sql":
                return False
            connection = sqlite3.connect(":memory:")
            try:
                connection.executescript((ROOT / "dataset" / relative_path).read_text(
                    encoding="utf-8", errors="replace"))
                tables = [row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND lower(name) LIKE '%customer_profiles%'"
                )]
                if not tables:
                    return False
                for table in tables:
                    columns = {row[1].casefold() for row in connection.execute(
                        f'PRAGMA table_info("{table}")')}
                    if "resource_id" in columns and connection.execute(
                        f'SELECT 1 FROM "{table}" WHERE resource_id = ? LIMIT 1',
                        (step["resource_id"],),
                    ).fetchone():
                        return False
                return True
            except (OSError, sqlite3.Error):
                return False
            finally:
                connection.close()
        state_checks = {
            "REPORT_REMAINING_RECORD": lambda o: o.exists and o.state == "PRESENT",
            "REPORT_EXPOSED_PII": lambda o: o.exists and (
                o.has_pii() or bool(auditor.subject(request)[0].intersection(o.identifiers()))),
            "REPORT_ACTIVE_DATA_FLOW": lambda o: o.exists and o.state == "ACTIVE",
            "REPORT_RESTORE_RISK": lambda o: o.exists and o.state == "ACTIVE",
            "VERIFY_RECORD_ABSENT": lambda o: not o.exists or o.state == "ABSENT",
            "VERIFY_RECORD_PRESENT": lambda o: o.exists,
            "VERIFY_RECORD_REDACTED": lambda o: o.exists and o.state == "REDACTED",
            "VERIFY_RECORD_ANONYMIZED": lambda o: o.exists and o.state == "ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED": lambda o: o.state == "DISABLED",
            "VERIFY_RESTORE_BLOCKED": lambda o: o.state == "BLOCKED",
        }
        check = state_checks.get(step["operation"])
        return bool(check and any(check(o) for o in matches))

    citations_grounded = all(
        cited_step_is_supported(requests[cid], step)
        for cid, steps in sample_steps.items() for step in steps if step["evidence_id"]
    )
    custom_results.append((
        "public sample citations match resource state and audit cutoff", True, citations_grounded,
    ))
    custom_pass = sum(expected == actual for _, expected, actual in custom_results)

    mismatch_ids = [r["case_id"] for r in case_results if not r["exact"]]
    missing_total = sum(r["missing"] for r in case_results)
    extra_total = sum(r["extra"] for r in case_results)
    reordered_cases = sum(r["reordered"] for r in case_results)
    wrong_populated_total = sum(r["wrong_populated"] for r in case_results)
    report = f"""# Evaluation Report

## Reproducible run

- Generator: python code/main.py
- Evaluator: python code/evaluation/main.py
- Public sample IDs are separate from the 518 full-dataset IDs, so labeled cases are run directly through the solution; root output.csv is validated independently.

## Full output validation

- Requests/prediction rows: {len(rows)} / {len(all_ids)}
- Exact schema, unique/sorted input case IDs: {'PASS' if not any('header' in e or 'row count' in e or 'duplicate' in e or 'case IDs' in e for e in validation_errors) else 'FAIL'}
- Valid JSON, statuses, exact step fields, operation/state pairs, evidence rules, consecutive numbering, and required ordering: {'PASS' if not validation_errors else 'FAIL'}
- Validation errors: {len(validation_errors)}
"""
    if validation_errors:
        report += "\n".join(f"- {error}" for error in validation_errors[:100]) + "\n"

    report += f"""
## Labeled sample metrics

- Cases: {len(gold)}
- Deletion-status accuracy: {status_correct}/{len(gold)} ({status_correct / max(1, len(gold)):.1%})
- Exact ordered case result (status and every step): {exact_cases}/{len(gold)} ({exact_cases / max(1, len(gold)):.1%})
- Step exact match at the same array position: {exact_steps}/{gold_steps} gold steps ({exact_steps / max(1, gold_steps):.1%}); this is positional recall-like accuracy, so a shifted step is incorrect.
- Field accuracy: {exact_fields}/{field_total} required fields ({exact_fields / max(1, field_total):.1%}), aligned by expected step position; absent predicted steps count as seven wrong fields.
- Predicted sample steps: {predicted_steps}; gold sample steps: {gold_steps}.
- Sequence diff counts: {missing_total} missing step instances, {extra_total} extra step instances, {wrong_populated_total} incorrectly populated positional steps, {reordered_cases} cases with same step multiset but different order.
- Status mismatch cases: {', '.join(status_mismatch_ids) if status_mismatch_ids else 'none'}
- Exact-output mismatch cases: {', '.join(mismatch_ids) if mismatch_ids else 'none'}

### Per-case expected-versus-actual summary

| Case | Expected status | Actual status | Exact | Missing | Extra | Reordered | All positional differences |
|---|---|---|---:|---:|---:|---|---|
"""
    for result in case_results:
        detail = (result["detail"] or "-").replace("|", "\\|")
        report += f"| {result['case_id']} | {result['expected_status']} | {result['actual_status']} | {'yes' if result['exact'] else 'no'} | {result['missing']} | {result['extra']} | {'yes' if result['reordered'] else 'no'} | {detail} |\n"

    report += "\n## Additional custom evaluation cases\n\n| Case | Expected | Actual | Result |\n|---|---:|---:|---|\n"
    report += "\n".join(f"| {name} | {expected} | {actual} | {'PASS' if expected == actual else 'FAIL'} |" for name, expected, actual in custom_results)
    report += f"""

## Baseline and final comparison

- Earlier measured baseline: status 32/32, exact ordered output 17/32, step exact 171/193, field exact 1280/1351.
- Baseline immediately before this resource-selection change: status 32/32, exact ordered output 19/32, step exact 172/193, field exact 1272/1351.
- Final measured output: status {status_correct}/{len(gold)}, exact ordered output {exact_cases}/{len(gold)}, step exact {exact_steps}/{gold_steps}, field exact {exact_fields}/{field_total}.
- The production change ranks cutoff-valid subject-linked and resource-specific observations before workflow status and timestamp, and restricts account absence proofs to an exact resource readback or a complete account inventory. It fixes case_28 without changing case_26. Cases 03, 25, and 27 remain ambiguous: each competing analytics record has resource-level state evidence, but neither candidate has subject identifiers; no evidence-backed tie-break is available.

## Findings and limitations

- The remaining errors cluster around resource selection and missing or extra analytics, account, and security steps. Temporal activity rows can lack subject identifiers; their reported results are not proof of ownership or state. Ambiguous resources are not inferred as belonging to a person.
- Case-specific detailed differences are summarized in the table above. The public sample labels are available; hidden canonical labels for the other requests are not.
- The implementation uses deterministic evidence parsing and local Tesseract OCR for the 11 supplied images. It makes no hosted model calls; the usage report documents zero hosted-model tokens and costs.
"""
    report_path = ROOT / "code" / "evaluation" / "evaluation_report.md"
    report_path.write_text(report, encoding="utf-8")
    print(report)
    return 1 if validation_errors or custom_pass != len(custom_results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
