"""Validate schemas and fixtures; also assert known-bad documents are rejected."""
import json, sys
from jsonschema import Draft202012Validator, FormatChecker

def load(p):
    with open(p) as f:
        return json.load(f)

ok = True
pairs = [
    ("packages/schemas/policy-bundle.schema.json", "tests/fixtures/bundle-example.json"),
    ("packages/schemas/event-envelope.schema.json", "tests/fixtures/event-example.json"),
]
for schema_path, doc_path in pairs:
    schema = load(schema_path)
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(load(doc_path)))
    for e in errors:
        ok = False
        print(f"{doc_path}: {e.message}")

bad = load("tests/fixtures/bundle-example.json")
bad["policies"][0]["rules"][0]["when"]["all"][0]["field"] = "clasification"
if not list(Draft202012Validator(load(pairs[0][0])).iter_errors(bad)):
    ok = False
    print("schema accepted a misspelt field root")

print("schemas OK" if ok else "schemas FAILED")
sys.exit(0 if ok else 1)
