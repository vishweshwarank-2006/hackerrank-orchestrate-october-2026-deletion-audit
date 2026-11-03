# Ghost Data Still Exists — Deletion Audit Agent

## Overview

The Ghost Data Still Exists project implements a deletion-audit agent that evaluates whether customer deletion requests have actually been completed across multiple systems.

Rather than trusting the status reported by an existing deletion workflow, the solution analyzes identity records, historical audit events, system activity, deletion policies, and supporting evidence to determine the deletion state at the specified audit cutoff.

The agent generates an `output.csv` containing one result per deletion request, including the deletion status and an ordered JSON array of findings, remediation actions, and verification checks.

## Objectives

- Resolve current and historical user identifiers.
- Determine resource states at `audit_at`.
- Identify personal data that remains across relevant systems.
- Detect active synchronization, import, and restore paths that could recreate deleted data.
- Apply deletion, redaction, anonymization, and retention policies.
- Generate ordered remediation and verification steps.
- Produce structured output for automated evaluation.

## Project Structure

```text
.
├── code/
│   ├── main.py
│   └── evaluation/
│       └── main.py
├── dataset/
│   ├── deletion_requests.csv
│   ├── sample_deletion_requests.csv
│   ├── sample_output.csv
│   ├── user_identities.csv
│   ├── user_audit_log.csv
│   ├── system_activity.csv
│   ├── deletion_rules.csv
│   ├── evidence_files.csv
│   └── evidence/
├── evaluation/
│   ├── evaluation_report.md
│   └── usage_report.md
├── output.csv
├── code.zip
└── README.md
```

The archive may contain additional supporting files depending on the final packaging configuration.

## Approach

The solution uses a Python-based processing pipeline to interpret the supplied records and evidence, reconstruct deletion state, and generate structured audit results.

### 1. Input Processing

The agent reads deletion requests, identity records, historical audit logs, system activity, deletion rules, and the evidence manifest.

### 2. Identity Resolution

Current and historical identity information is used to associate relevant records and activities with each deletion request. This helps identify data that may remain under previous identifiers.

### 3. Evidence Analysis

The solution examines available structured records and supported evidence formats to assess resource states and operational activity. Reported workflow statuses and operation results are treated as claims rather than conclusive proof.

### 4. Policy Evaluation

Each relevant resource is evaluated against its applicable deletion rule. Depending on the policy, the required treatment may include:

- Deleting the record.
- Redacting identifying fields while preserving an allowed record.
- Anonymizing a record so it can no longer be linked to the individual.
- Preserving records that must be retained.
- Disabling active data flows or blocking restore paths that could recreate deleted data.

Where policy permits an account tombstone, the stable internal `user_id` may remain while direct identifiers such as name, email, phone number, and email hash are removed as required.

### 5. Status Determination

Each request receives one of the required statuses:

- `COMPLETE` — the available evidence supports that the required deletion and retention conditions have been satisfied.
- `INCOMPLETE` — records, identifiers, or active processes still require remediation, or the required conditions have not been established.
- `NOT_APPLICABLE` — the person did not request deletion, so no deletion or deletion verification is authorized.

### 6. Step Generation

For incomplete requests, the agent generates findings, proposed remediation actions, and subsequent verification checks.

For complete requests, it generates verification steps supporting the current state. Not-applicable requests receive an empty JSON array.

Steps follow the challenge's required phase, operation, system, and resource ordering.

## Output Format

The generated `output.csv` uses the required columns:

```csv
case_id,deletion_status,steps_json
```

Each row contains:

- `case_id`: the deletion request identifier.
- `deletion_status`: `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- `steps_json`: an ordered JSON array of structured audit steps.

Each step contains exactly the following fields:

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_01"
}
```

Step numbers begin at 1 and increase consecutively. The expected output contains 518 data rows sorted by `case_id`.

## Implementation Notes

- The implementation is written in Python.
- Evidence parsing and deletion-state reconstruction use deterministic processing rules.
- Local OCR is used for supported image evidence where required.
- The final processing pipeline does not rely on hosted LLM API calls.
- Output generation follows the challenge's required schema and ordering constraints.

## Running the Solution

Run commands from the repository root in a Python environment with the required dependencies installed.

Generate the output:

```bash
python code/main.py
```

Run the evaluator:

```bash
python code/evaluation/main.py
```

If the scripts require a different working directory or additional arguments, follow the instructions provided in the implementation.

## Evaluation

The evaluation process measures the generated output against the available reference cases and reports status, step, field, and sequence accuracy.

The submission's `evaluation/evaluation_report.md` must include:

- Case-level status accuracy.
- Step-level and field-level accuracy.
- Sequence accuracy.
- At least three additional evaluation cases created by the team.
- Failures identified and improvements made.

The `evaluation/usage_report.md` must summarize the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request costs.

Because the final processing pipeline does not use hosted LLM API calls, hosted-model token usage and API costs should be reported as zero or not applicable, as appropriate. Local processing costs should not be represented as hosted-model token costs.

All reported metrics and usage figures should reflect the actual final run.

## Limitations

The quality of the results depends on the completeness and interpretation of the supplied evidence, identity history, system activity, and deletion policies.

Passing structural validation does not guarantee that every result matches the hidden canonical answers. Evaluation metrics should be reported accurately, and unresolved failure cases should be documented rather than presented as successful.

## Submission Checklist

- [ ] `output.csv` contains exactly 518 data rows.
- [ ] Rows are sorted by `case_id`.
- [ ] All deletion statuses use the permitted values.
- [ ] Every `steps_json` value is valid JSON.
- [ ] Step objects contain exactly the required fields.
- [ ] Step numbers are consecutive and step ordering follows the specification.
- [ ] Evidence references and policy decisions have been validated.
- [ ] `evaluation/evaluation_report.md` contains the required metrics, custom cases, failures, and improvements.
- [ ] `evaluation/usage_report.md` documents the final run and token-usage and cost accounting.
- [ ] `code.zip` contains the runnable solution and required evaluation files.
- [ ] The development or usage transcript is prepared as a separate submission item.

## Conclusion

The project aims to move deletion auditing beyond workflow status labels by reconstructing the state of relevant records and data flows, applying policy-specific requirements, and generating an auditable sequence of findings, remediation actions, and verification checks.
