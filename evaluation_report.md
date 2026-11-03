# Evaluation Report

## Reproducible run

- Generator: python code/main.py
- Evaluator: python code/evaluation/main.py
- Public sample IDs are separate from the 518 full-dataset IDs, so labeled cases are run directly through the solution; root output.csv is validated independently.

## Full output validation

- Requests/prediction rows: 518 / 518
- Exact schema, unique/sorted input case IDs: PASS
- Valid JSON, statuses, exact step fields, operation/state pairs, evidence rules, consecutive numbering, and required ordering: PASS
- Validation errors: 0

## Labeled sample metrics

- Cases: 32
- Deletion-status accuracy: 32/32 (100.0%)
- Exact ordered case result (status and every step): 19/32 (59.4%)
- Step exact match at the same array position: 168/193 gold steps (87.0%); this is positional recall-like accuracy, so a shifted step is incorrect.
- Field accuracy: 1269/1351 required fields (93.9%), aligned by expected step position; absent predicted steps count as seven wrong fields.
- Predicted sample steps: 192; gold sample steps: 193.
- Sequence diff counts: 16 missing step instances, 15 extra step instances, 22 incorrectly populated positional steps, 0 cases with same step multiset but different order.
- Status mismatch cases: none
- Exact-output mismatch cases: case_03, case_09, case_13, case_18, case_19, case_20, case_23, case_24, case_25, case_27, case_29, case_30, case_31

### Per-case expected-versus-actual summary

| Case | Expected status | Actual status | Exact | Missing | Extra | Reordered | All positional differences |
|---|---|---|---:|---:|---:|---|---|
| case_01 | COMPLETE | COMPLETE | yes | 0 | 0 | no | - |
| case_02 | COMPLETE | COMPLETE | yes | 0 | 0 | no | - |
| case_03 | COMPLETE | COMPLETE | no | 1 | 1 | no | step 3: resource_id 'analytics_9406' -> 'analytics_5589' |
| case_04 | COMPLETE | COMPLETE | yes | 0 | 0 | no | - |
| case_05 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_06 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_07 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_08 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_09 | INCOMPLETE | INCOMPLETE | no | 1 | 1 | no | step 4: system_id 'security_service' -> 'analytics_platform', resource_id 'audit_record_4902' -> 'analytics_5718', operation 'VERIFY_RECORD_PRESENT' -> 'VERIFY_RECORD_ANONYMIZED', state 'PRESENT' -> 'ANONYMIZED' |
| case_10 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_11 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_12 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_13 | INCOMPLETE | INCOMPLETE | no | 0 | 1 | no | step 9: unexpected {'step_no': 9, 'phase': 'VERIFICATION', 'system_id': 'analytics_platform', 'resource_id': 'analytics_2265', 'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED', 'evidence_id': ''} |
| case_14 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_15 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_16 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_17 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_18 | INCOMPLETE | INCOMPLETE | no | 2 | 1 | no | step 9: resource_id 'account_5521' -> 'account_5193'; step 11: system_id 'security_service' -> 'support_platform', resource_id 'audit_record_6645' -> 'support_5569', operation 'VERIFY_RECORD_PRESENT' -> 'VERIFY_RECORD_REDACTED', state 'PRESENT' -> 'REDACTED'; step 12: system_id 'support_platform' -> 'analytics_platform', resource_id 'support_5569' -> 'analytics_037', operation 'VERIFY_RECORD_REDACTED' -> 'VERIFY_RECORD_ANONYMIZED', state 'REDACTED' -> 'ANONYMIZED'; step 13: system_id 'analytics_platform' -> 'integration_service', resource_id 'analytics_037' -> 'data_flow_4890', operation 'VERIFY_RECORD_ANONYMIZED' -> 'VERIFY_DATA_FLOW_DISABLED', state 'ANONYMIZED' -> 'DISABLED'; step 14: missing {'step_no': 14, 'phase': 'VERIFICATION', 'system_id': 'integration_service', 'resource_id': 'data_flow_4890', 'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': ''} |
| case_19 | INCOMPLETE | INCOMPLETE | no | 0 | 1 | no | step 9: unexpected {'step_no': 9, 'phase': 'VERIFICATION', 'system_id': 'analytics_platform', 'resource_id': 'analytics_3264', 'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED', 'evidence_id': ''} |
| case_20 | INCOMPLETE | INCOMPLETE | no | 2 | 2 | no | step 5: resource_id 'account_5037' -> 'account_9335'; step 7: system_id 'security_service' -> 'analytics_platform', resource_id 'audit_record_5569' -> 'analytics_2265', operation 'VERIFY_RECORD_PRESENT' -> 'VERIFY_RECORD_ANONYMIZED', state 'PRESENT' -> 'ANONYMIZED' |
| case_21 | COMPLETE | COMPLETE | yes | 0 | 0 | no | - |
| case_22 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |
| case_23 | INCOMPLETE | INCOMPLETE | no | 2 | 2 | no | step 5: resource_id 'account_410' -> 'account_6440'; step 8: system_id 'security_service' -> 'analytics_platform', resource_id 'audit_record_4128' -> 'analytics_5335', operation 'VERIFY_RECORD_PRESENT' -> 'VERIFY_RECORD_ANONYMIZED', state 'PRESENT' -> 'ANONYMIZED' |
| case_24 | INCOMPLETE | INCOMPLETE | no | 1 | 1 | no | step 7: system_id 'security_service' -> 'analytics_platform', resource_id 'audit_record_7095' -> 'analytics_4566', operation 'VERIFY_RECORD_PRESENT' -> 'VERIFY_RECORD_ANONYMIZED', state 'PRESENT' -> 'ANONYMIZED' |
| case_25 | COMPLETE | COMPLETE | no | 2 | 2 | no | step 1: resource_id 'account_3136' -> 'account_5684'; step 3: resource_id 'analytics_1895' -> 'analytics_4566' |
| case_26 | COMPLETE | COMPLETE | yes | 0 | 0 | no | - |
| case_27 | COMPLETE | COMPLETE | no | 1 | 1 | no | step 4: resource_id 'analytics_4574' -> 'analytics_6077' |
| case_28 | COMPLETE | COMPLETE | yes | 0 | 0 | no | - |
| case_29 | INCOMPLETE | INCOMPLETE | no | 2 | 1 | no | step 9: resource_id 'account_7012' -> 'account_5482'; step 11: system_id 'security_service' -> 'support_platform', resource_id 'audit_record_3954' -> 'support_5281', operation 'VERIFY_RECORD_PRESENT' -> 'VERIFY_RECORD_REDACTED', state 'PRESENT' -> 'REDACTED'; step 12: system_id 'support_platform' -> 'analytics_platform', resource_id 'support_5281' -> 'analytics_5208', operation 'VERIFY_RECORD_REDACTED' -> 'VERIFY_RECORD_ANONYMIZED', state 'REDACTED' -> 'ANONYMIZED'; step 13: system_id 'analytics_platform' -> 'integration_service', resource_id 'analytics_5208' -> 'data_flow_3827', operation 'VERIFY_RECORD_ANONYMIZED' -> 'VERIFY_DATA_FLOW_DISABLED', state 'ANONYMIZED' -> 'DISABLED'; step 14: missing {'step_no': 14, 'phase': 'VERIFICATION', 'system_id': 'integration_service', 'resource_id': 'data_flow_3827', 'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': ''} |
| case_30 | INCOMPLETE | INCOMPLETE | no | 1 | 0 | no | step 11: system_id 'security_service' -> 'support_platform', resource_id 'audit_record_1707' -> 'support_6477', operation 'VERIFY_RECORD_PRESENT' -> 'VERIFY_RECORD_REDACTED', state 'PRESENT' -> 'REDACTED'; step 12: system_id 'support_platform' -> 'analytics_platform', resource_id 'support_6477' -> 'analytics_3697', operation 'VERIFY_RECORD_REDACTED' -> 'VERIFY_RECORD_ANONYMIZED', state 'REDACTED' -> 'ANONYMIZED'; step 13: system_id 'analytics_platform' -> 'integration_service', resource_id 'analytics_3697' -> 'data_flow_8524', operation 'VERIFY_RECORD_ANONYMIZED' -> 'VERIFY_DATA_FLOW_DISABLED', state 'ANONYMIZED' -> 'DISABLED'; step 14: missing {'step_no': 14, 'phase': 'VERIFICATION', 'system_id': 'integration_service', 'resource_id': 'data_flow_8524', 'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': ''} |
| case_31 | COMPLETE | COMPLETE | no | 1 | 1 | no | step 1: resource_id 'account_4857' -> 'account_3677' |
| case_32 | INCOMPLETE | INCOMPLETE | yes | 0 | 0 | no | - |

## Additional custom evaluation cases

| Case | Expected | Actual | Result |
|---|---:|---:|---|
| access request | False | False | PASS |
| Spanish deletion | True | True | PASS |
| Japanese deletion | True | True | PASS |
| historical email resolves to its identity | True | True | PASS |
| post-audit evidence is excluded | True | True | PASS |
| active data flow is reported | True | True | PASS |
| case_03 analytics candidates have equal state evidence but no identity link | True | True | PASS |
| case_25 analytics candidates have equal state evidence but no identity link | True | True | PASS |
| case_27 analytics candidates have equal state evidence but no identity link | True | True | PASS |
| case_28 account selection uses its resource-specific readback | True | True | PASS |
| case_26 exact output does not regress | True | True | PASS |
| public sample citations match resource state and audit cutoff | True | True | PASS |

## Baseline and final comparison

- Earlier measured baseline: status 32/32, exact ordered output 17/32, step exact 171/193, field exact 1280/1351.
- Baseline immediately before this resource-selection change: status 32/32, exact ordered output 19/32, step exact 172/193, field exact 1272/1351.
- Final measured output: status 32/32, exact ordered output 19/32, step exact 168/193, field exact 1269/1351.
- The production change ranks cutoff-valid subject-linked and resource-specific observations before workflow status and timestamp, and restricts account absence proofs to an exact resource readback or a complete account inventory. It fixes case_28 without changing case_26. Cases 03, 25, and 27 remain ambiguous: each competing analytics record has resource-level state evidence, but neither candidate has subject identifiers; no evidence-backed tie-break is available.

## Findings and limitations

- The remaining errors cluster around resource selection and missing or extra analytics, account, and security steps. Temporal activity rows can lack subject identifiers; their reported results are not proof of ownership or state. Ambiguous resources are not inferred as belonging to a person.
- Case-specific detailed differences are summarized in the table above. The public sample labels are available; hidden canonical labels for the other requests are not.
- The implementation uses deterministic evidence parsing and local Tesseract OCR for the 11 supplied images. It makes no hosted model calls; the usage report documents zero hosted-model tokens and costs.
