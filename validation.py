import json
from pathlib import Path

expected_keys = ['id', 'page', 'section', 'sent', 'response', 'observation']

type_dict = {
    'id': str,
    'sent': (str, type(None)),
    'page': str,
    'section': (str, type(None)),
    'response': int,
    'observation': str
}

def validate(findings):
    valid = []
    rejected = []
    for case in findings:
        
        if not isinstance(case, dict):
            print(f"UNKNOWN malformed: record is {type(case).__name__}, not an object")
            rejected.append({
                "id": "UNKNOWN",
                "missing": [],
                "type_issues": [f"record is {type(case).__name__}, not an object"],
            })
            continue
        
        missing = []

        for key in expected_keys:
            if key not in case: 
                missing.append(key)

        type_issue = []

        for key in expected_keys:
            if key not in missing:
                if not isinstance(case[key], type_dict[key]):
                    actual = type(case[key]).__name__
                    type_issue.append(f"{key}: got {actual}")

        for key in ['id', 'page', 'observation']:
            if key not in missing and isinstance(case[key], str) and case[key].strip() == "":
                type_issue.append(f"{key}: empty string")

        if 'response' not in missing and isinstance(case['response'], bool):
            type_issue.append("response: got bool")

        if missing:
            print(f"{case.get('id', 'UNKNOWN')} missing: {missing}")

        if type_issue:
            print(f"{case.get('id', 'UNKNOWN')} TypeErrors: {type_issue}")

        if not missing and not type_issue:
            print(f"{case.get('id')}: All keys present and no TypeErrors")
            valid.append(case)
        else:
            rejected.append({
                "id": case.get('id', 'UNKNOWN'),
                "missing": missing,
                "type_issues": type_issue,
            })     
    return valid, rejected

if __name__ == "__main__":
    DATA_PATH = Path(__file__).parent / "synthetic_dataset.json"

    try:
        json.loads(DATA_PATH.read_text())
    except json.JSONDecodeError as e:
        print(f"Malformed JSON file: {e}")
        raise SystemExit(1)

    with open(DATA_PATH) as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        print(f"Malformed dataset: expected a list of records, got {type(findings).__name__}")
        raise SystemExit(1)

    valid, rejected = validate(findings)
    print(f"\n{len(valid)} valid, {len(rejected)} rejected")
    for r in rejected:
        print(r)