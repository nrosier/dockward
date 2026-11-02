---
name: sarif-validate
description: Validate SARIF 2.1.0 output from the converter against the official SARIF 2.1.0 JSON schema (fetch or use a schema file the project provides; if neither exists, say so and stop rather than guess). Use after changing the Trivy to SARIF converter.
---

# sarif-validate

Checks that converter output conforms to SARIF 2.1.0 (CLAUDE.md rule 3).

**Note:** The project has no Cargo or Docker files yet, and the converter may not exist. Until `backend/` and the converter exist, this skill is expected to fail with "file not found". That is not a failure of the skill.

## Steps

1. Find a project-provided schema first:
   `find /Users/nrosier/Development/harborgate -iname 'sarif*schema*.json' -not -path '*/node_modules/*' -not -path '*/target/*'`
2. If none is found, fetch the official schema into a new empty temp directory:
   `SCHEMA_DIR=$(mktemp -d) && curl -fsSL -o "$SCHEMA_DIR/sarif-schema-2.1.0.json" https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`
   If the fetch fails and step 1 found nothing, STOP and report: "no SARIF 2.1.0 schema available (no project file, fetch failed)". Do not guess a schema.
3. Produce converter output. Use the converter's test fixture or its documented command. Record the exact output path as `SARIF_FILE`. If the path is unknown, STOP and report it.
4. Validate with a JSON Schema validator, for example:
   `check-jsonschema --schemafile "$SCHEMA_DIR/sarif-schema-2.1.0.json" "$SARIF_FILE"`
5. Confirm the file is valid JSON and has `"version": "2.1.0"`:
   `python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("version"))' "$SARIF_FILE"`

## Pass / fail

- PASS: step 4 exits 0 with zero schema errors, and step 5 prints `2.1.0`.
- FAIL: any schema error, a wrong or missing `version`, or invalid JSON.
- STOP (neither a schema nor a fetch is available, or no output path): report it and do not mark validation as passed.

## Report

- Schema source used (project file path, or the fetch URL and its SHA-256).
- `SARIF_FILE` path validated.
- Validator command and exit code.
- Every schema error, verbatim, with its JSON path.
