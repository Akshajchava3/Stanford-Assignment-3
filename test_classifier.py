"""Offline tests for the classification agent (no API key needed).

Run: python -m unittest test_classifier -v
"""

import json
import unittest
from pathlib import Path

from classifier import apply_guardrails, classify_all, load_recon_items

HERE = Path(__file__).parent
EXAMPLE = HERE / "recon_summary_example.json"


def by_id(results):
    return {r["record_id"]: r for r in results}


class RulesMatchExpectedResults(unittest.TestCase):
    """Rules backend against the answer key in expected_results.md."""

    @classmethod
    def setUpClass(cls):
        items, cls.rejected = load_recon_items(EXAMPLE)
        cls.results = by_id(classify_all(items, mode="rules"))

    def test_c1_suspected_sql_injection(self):
        r = self.results["C-1"]
        self.assertEqual((r["category"], r["status"], r["cwe"]), ("sql_injection", "suspected", "CWE-89"))

    def test_c2_suspected_reflected_xss(self):
        r = self.results["C-2"]
        self.assertEqual((r["category"], r["status"], r["cwe"]), ("reflected_xss", "suspected", "CWE-79"))

    def test_c3_informational(self):
        r = self.results["C-3"]
        self.assertEqual((r["category"], r["status"]), ("informational", "not_a_vulnerability"))

    def test_c5_stays_uncertain_and_flags_injection(self):
        r = self.results["C-5"]
        self.assertEqual(r["status"], "insufficient_information")
        self.assertTrue(r["instruction_like_text_detected"])

    def test_nothing_is_ever_confirmed(self):
        self.assertTrue(all(r["status"] != "confirmed" for r in self.results.values()))

    def test_every_quote_traces_to_the_record(self):
        records = {i["id"]: i for i in json.loads(EXAMPLE.read_text())["items"]}
        for rid, r in self.results.items():
            text = (records[rid]["observation"] or "") + (records[rid]["sent"] or "")
            for q in r["evidence_quotes"]:
                self.assertIn(q, text, f"{rid} quote not in record")


class Guardrails(unittest.TestCase):
    ITEM = {"id": "T-1", "page": "x.test/a", "section": "q", "sent": "'", "response": 500,
            "observation": "You have an error in your SQL syntax"}

    def raw(self, **over):
        base = {"category": "sql_injection", "status": "suspected", "confidence": "high",
                "confidence_reason": "db error", "evidence_quotes": ["SQL syntax"],
                "severity": "high", "severity_reason": "data exposure",
                "uncertainty_notes": "", "instruction_like_text_detected": False}
        base.update(over)
        return base

    def test_confirmed_status_is_downgraded(self):
        r = apply_guardrails(self.ITEM, self.raw(status="confirmed"))
        self.assertEqual(r["status"], "insufficient_information")

    def test_made_up_quote_is_removed_and_label_downgraded(self):
        r = apply_guardrails(self.ITEM, self.raw(evidence_quotes=["UNION SELECT password FROM users"]))
        self.assertEqual(r["evidence_quotes"], [])
        self.assertEqual(r["category"], "insufficient_information")

    def test_invented_cve_is_removed(self):
        r = apply_guardrails(self.ITEM, self.raw(severity_reason="Matches CVE-2021-44228."))
        self.assertNotIn("CVE-2021-44228", r["severity_reason"])
        self.assertTrue(r["guardrail_notes"])

    def test_numeric_score_is_removed(self):
        r = apply_guardrails(self.ITEM, self.raw(severity_reason="CVSS 9.8, critical"))
        self.assertNotIn("9.8", r["severity_reason"])

    def test_unexplained_severity_is_cleared(self):
        r = apply_guardrails(self.ITEM, self.raw(severity_reason=""))
        self.assertEqual(r["severity"], "insufficient_information")


class MalformedInput(unittest.TestCase):
    def test_c4_rejected_before_classification(self):
        c4 = next(r for r in json.loads((HERE / "synthetic_dataset.json").read_text()) if r["id"] == "C-4")
        tmp = HERE / "_tmp_recon.json"
        try:
            tmp.write_text(json.dumps({"items": [c4]}))
            items, rejected = load_recon_items(tmp)
        finally:
            tmp.unlink(missing_ok=True)
        self.assertEqual(items, [])
        self.assertEqual(rejected[0]["id"], "C-4")


if __name__ == "__main__":
    unittest.main()
