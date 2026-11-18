"""Classification agent.

Reads the recon summary (see SCHEMA.md), labels each finding as a suspected
vulnerability type, and writes structured results that cite their evidence.

Two backends:
  --mode rules   deterministic pattern rules, no API key needed (baseline)
  --mode llm     Claude via the Anthropic API (see llm_backend.py)

Both backends go through the same code-level guardrails in apply_guardrails(),
so the output rules hold regardless of what the model says.

Usage:
  python classifier.py --input recon_summary_example.json --mode rules
  python classifier.py --input recon_summary_example.json --mode llm --output out.json
"""

import argparse
import contextlib
import json
import re
import sys
from pathlib import Path

from validation import validate

EVIDENCE_FIELDS = ("observation", "sent")

CATEGORIES = ("sql_injection", "reflected_xss", "informational", "insufficient_information")
STATUSES = ("suspected", "not_a_vulnerability", "insufficient_information")
CONFIDENCES = ("low", "medium", "high")
SEVERITIES = ("low", "medium", "high", "insufficient_information")
VULN_CATEGORIES = ("sql_injection", "reflected_xss")

# CWE is set by code from the category, never by the model.
CWE_BY_CATEGORY = {"sql_injection": "CWE-89", "reflected_xss": "CWE-79"}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
NUMERIC_SCORE_RE = re.compile(
    r"\bCVSS(?:v?\d(?:\.\d)?)?\s*(?:score\s*)?(?:of\s*|:\s*|=\s*)?\d{1,2}(?:\.\d)?"
    r"|\b\d{1,2}(?:\.\d)?\s*/\s*10\b",
    re.IGNORECASE,
)
INSTRUCTION_RE = re.compile(
    r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,20}"
    r"\b(instructions?|commands?|prompts?|rules)\b"
    r"|\bsystem prompt\b"
    r"|\byou are now\b"
    r"|\b(export|reveal|print|send|leak)\b.{0,30}\b(api keys?|secrets?|passwords?|credentials?|tokens?)\b",
    re.IGNORECASE,
)
SQL_ERROR_RE = re.compile(
    r"SQL syntax|SQLSTATE|ORA-\d{5}|unclosed quotation mark|SQLite\w*Error|pg_query|mysql_\w+\(",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

def load_recon_items(path):
    """Read the recon summary and return (valid_items, rejected)."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise ValueError("recon summary must be an object with an 'items' list (see SCHEMA.md)")
    # validation.py prints per-record lines; keep stdout clean for results.
    with contextlib.redirect_stdout(sys.stderr):
        valid, rejected = validate(data["items"])
    return valid, rejected


# ---------------------------------------------------------------------------
# Rules backend (no API key; also the baseline to compare the LLM against)
# ---------------------------------------------------------------------------

def classify_rules(item):
    obs = item["observation"]
    sent = item.get("sent") or ""

    injected = INSTRUCTION_RE.search(obs)
    if injected:
        return {
            "category": "insufficient_information",
            "status": "insufficient_information",
            "confidence": "low",
            "confidence_reason": "The observation is page text written as an instruction to an AI. "
                                 "It is not the result of a test input, so it shows no specific flaw.",
            "evidence_quotes": [injected.group(0)],
            "severity": "insufficient_information",
            "severity_reason": "No test input or server behaviour to assess.",
            "uncertainty_notes": "User-posted text on this page contains a prompt-injection attempt. "
                                 "A human should check where this text comes from.",
            "instruction_like_text_detected": True,
        }

    sql_error = SQL_ERROR_RE.search(obs)
    if sent and sql_error:
        return {
            "category": "sql_injection",
            "status": "suspected",
            "confidence": "medium",
            "confidence_reason": "The test input produced a database error message, which suggests the "
                                 "input reaches a SQL query unescaped. An error alone does not prove "
                                 "the injection is exploitable.",
            "evidence_quotes": [sent, sql_error.group(0)],
            "severity": "high",
            "severity_reason": "If exploitable, SQL injection can expose or change database contents. "
                               "This is potential impact; it has not been validated.",
            "uncertainty_notes": "Needs a controlled re-test in the sandbox to confirm exploitability.",
            "instruction_like_text_detected": False,
        }

    if sent and any(ch in sent for ch in "<>\"'") and sent in obs:
        return {
            "category": "reflected_xss",
            "status": "suspected",
            "confidence": "high",
            "confidence_reason": "The test payload appears unchanged in the returned page, so a browser "
                                 "would run it as markup or script.",
            "evidence_quotes": [sent],
            "severity": "medium",
            "severity_reason": "Reflected XSS needs a victim to open a crafted link; impact depends on "
                               "what the page can access.",
            "uncertainty_notes": "Not checked whether a Content-Security-Policy would block execution.",
            "instruction_like_text_detected": False,
        }

    if not sent:
        return {
            "category": "informational",
            "status": "not_a_vulnerability",
            "confidence": "medium",
            "confidence_reason": "No test input was sent and no error or reflected input was observed.",
            "evidence_quotes": [obs],
            "severity": "low",
            "severity_reason": "Information disclosure only; no version or exploitable behaviour shown.",
            "uncertainty_notes": "None.",
            "instruction_like_text_detected": False,
        }

    return {
        "category": "insufficient_information",
        "status": "insufficient_information",
        "confidence": "low",
        "confidence_reason": "A test input was sent but the observation matches no known pattern.",
        "evidence_quotes": [],
        "severity": "insufficient_information",
        "severity_reason": "Not enough evidence to assess.",
        "uncertainty_notes": "Needs human review.",
        "instruction_like_text_detected": False,
    }


# ---------------------------------------------------------------------------
# Guardrails (applied to every backend's output)
# ---------------------------------------------------------------------------

def _record_text(item):
    return " ".join(str(item.get(f) or "") for f in EVIDENCE_FIELDS)


def _downgrade(result, note):
    result["category"] = "insufficient_information"
    result["status"] = "insufficient_information"
    result["confidence"] = "low"
    result["severity"] = "insufficient_information"
    result["guardrail_notes"].append(note)


def apply_guardrails(item, raw):
    """Enforce the output rules in code. Returns a new result dict."""
    result = {
        "record_id": item["id"],
        "source": {k: item.get(k) for k in ("page", "section", "response")},
        **{k: raw.get(k) for k in (
            "category", "status", "confidence", "confidence_reason", "evidence_quotes",
            "severity", "severity_reason", "uncertainty_notes", "instruction_like_text_detected",
        )},
        "guardrail_notes": list(raw.get("guardrail_notes", [])),
    }
    record_text = _record_text(item)

    # 1. Labels must come from the fixed lists. Anything else (including "confirmed") is downgraded.
    for field, allowed in (("category", CATEGORIES), ("status", STATUSES),
                           ("confidence", CONFIDENCES), ("severity", SEVERITIES)):
        if result[field] not in allowed:
            _downgrade(result, f"{field} value {result[field]!r} is not allowed")

    # 2. Evidence quotes must be exact substrings of the record.
    quotes = result["evidence_quotes"] or []
    kept = [q for q in quotes if isinstance(q, str) and q and any(
        q in str(item.get(f) or "") for f in EVIDENCE_FIELDS)]
    for q in quotes:
        if q not in kept:
            result["guardrail_notes"].append(f"removed quote not found in record: {q!r}")
    result["evidence_quotes"] = kept
    if result["category"] in VULN_CATEGORIES and not kept:
        _downgrade(result, "vulnerability label had no supporting quote from the record")

    # 3. No CVE IDs unless the record itself contains them; no numeric severity scores.
    for field in ("confidence_reason", "severity_reason", "uncertainty_notes"):
        text = result[field] or ""
        for cve in set(CVE_RE.findall(text)):
            if cve.lower() not in record_text.lower():
                text = text.replace(cve, "[removed: unsupported CVE id]")
                result["guardrail_notes"].append(f"removed unsupported CVE id from {field}")
        if NUMERIC_SCORE_RE.search(text):
            text = NUMERIC_SCORE_RE.sub("[removed: numeric score]", text)
            result["guardrail_notes"].append(f"removed numeric severity score from {field}")
        result[field] = text

    # 4. Severity must be explained.
    if result["severity"] != "insufficient_information" and not (result["severity_reason"] or "").strip():
        result["severity"] = "insufficient_information"
        result["guardrail_notes"].append("severity had no explanation")

    # 5. Instruction-like text: code check OR model flag.
    if INSTRUCTION_RE.search(record_text):
        result["instruction_like_text_detected"] = True
    result["instruction_like_text_detected"] = bool(result["instruction_like_text_detected"])

    result["cwe"] = CWE_BY_CATEGORY.get(result["category"])
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def classify_all(items, mode="rules", client=None):
    if mode == "llm":
        from llm_backend import classify_llm  # imported here so rules mode needs no packages
    results = []
    for item in items:
        if mode == "llm":
            raw, error = classify_llm(item, client=client)
            if error:
                raw = {
                    "category": "insufficient_information", "status": "insufficient_information",
                    "confidence": "low", "confidence_reason": "Classifier did not return a result.",
                    "evidence_quotes": [], "severity": "insufficient_information",
                    "severity_reason": "Not assessed.", "uncertainty_notes": "Needs human review.",
                    "instruction_like_text_detected": False, "guardrail_notes": [error],
                }
        else:
            raw = classify_rules(item)
        results.append(apply_guardrails(item, raw))
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True, help="recon summary JSON (see SCHEMA.md)")
    parser.add_argument("--mode", choices=("rules", "llm"), default="rules")
    parser.add_argument("--output", help="write results here instead of stdout")
    args = parser.parse_args(argv)

    try:
        items, rejected = load_recon_items(args.input)
    except (OSError, json.JSONDecodeError, ValueError) as e:
        print(f"ERROR: could not read recon summary: {e}", file=sys.stderr)
        return 1

    results = classify_all(items, mode=args.mode)
    out = {"classifier_mode": args.mode, "results": results, "rejected": rejected}
    if args.mode == "llm":
        from llm_backend import MODEL
        out["model"] = MODEL

    text = json.dumps(out, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n")
        print(f"{len(results)} classified, {len(rejected)} rejected -> {args.output}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
