# Shared Data Format (proposal)

This is the format the two agents pass between each other. It is a proposal for the team to confirm.

```
synthetic_dataset.json ──► validation.py ──► recon agent ──► recon_summary.json ──► classifier.py ──► classification_output.json
```

## 1. Finding record

Defined in `expected_results.md`. Six keys, all required: `id`, `page`, `section`, `sent`, `response`, `observation`.

## 2. Recon summary (recon agent → classifier)

```json
{
  "summary": {
    "target": "stanford.ex.test",
    "pages": ["stanford.ex.test/login", "..."],
    "observations": ["..."]
  },
  "items": [
    {
      "id": "C-1",
      "page": "stanford.ex.test/login",
      "section": "password",
      "sent": "'",
      "response": 500,
      "observation": "You have an error in your SQL syntax; check the manual...",
      "recon_note": "Single quote in password field returned a 500 with a database error message."
    }
  ]
}
```

Rules:
- Each item keeps all six finding-record fields **unchanged**. The classifier quotes evidence from `observation` and `sent`, so these fields must not be rewritten or summarized.
- The recon agent may add `recon_note` (its own short summary) and the top-level `summary` object. The classifier never uses these as evidence.
- Only records that passed `validation.py` go into `items`. The classifier validates them again anyway.

## 3. Classification output (classifier → next milestone)

One result per item:

| Field | Type | Meaning |
|---|---|---|
| `record_id` | str | `id` of the source record |
| `source` | object | `page`, `section`, `response` copied from the record so you can trace it |
| `category` | `sql_injection` \| `reflected_xss` \| `informational` \| `insufficient_information` | What the finding looks like |
| `cwe` | str \| null | Set by code from the category (`CWE-89`, `CWE-79`), never by the model |
| `status` | `suspected` \| `not_a_vulnerability` \| `insufficient_information` | There is no `confirmed`. Only the later validation stage can confirm a finding. |
| `confidence` | `low` \| `medium` \| `high` | How sure the classifier is |
| `confidence_reason` | str | Why |
| `evidence_quotes` | list[str] | Exact substrings of the record's `observation` or `sent`. Checked by code. |
| `severity` | `low` \| `medium` \| `high` \| `insufficient_information` | Word label only. No CVSS or other numeric score. |
| `severity_reason` | str | Explanation of the severity label |
| `uncertainty_notes` | str | What is unknown, or what would be needed to confirm |
| `instruction_like_text_detected` | bool | True if the record contains text written as instructions to an AI |
| `guardrail_notes` | list[str] | Anything the code-level checks removed or downgraded |

Records the classifier rejects go in a separate `rejected` list with the reason.
