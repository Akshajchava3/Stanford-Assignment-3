# Stanford-Assignment-3
## All Files
### synthetic_dataset.json
This is the actual dataset containing 5 cases: a suspected SQL injection finding, a suspected XSS finding, a benign observation, an incomplete record, and a record containing instruction-like text.
### expected_results.md
This acts as an answer key for the classification agent, which it can compare its results against after reading the dataset.
### validation.py
A final check function that can make sure that no garbage is passed to the agent.
### SCHEMA.md
The shared data format between the recon agent and the classification agent (proposal).
### classifier.py / llm_backend.py
The classification agent. Reads the recon summary, labels each finding (SQL injection, reflected XSS, informational, insufficient information), and writes results that quote their evidence. `--mode rules` runs with no API key; `--mode llm` uses Claude. Both go through the same code-level checks: no "confirmed" status, quotes must match the record, no CVE IDs or numeric scores, and instruction-like text is flagged rather than followed.
### recon_summary_example.json
Placeholder recon output in the SCHEMA.md format, to be replaced by the recon agent's real output.
### examples/
Example classifier output.

## Running the classifier

Offline (no API key):
```
python classifier.py --input recon_summary_example.json --mode rules
python -m unittest test_classifier -v
```

With Claude (needs `pip install -r requirements.txt` and `ANTHROPIC_API_KEY` set):
```
python classifier.py --input recon_summary_example.json --mode llm --output examples/classification_output_llm.json
```
