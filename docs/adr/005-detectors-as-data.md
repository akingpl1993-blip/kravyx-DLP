# ADR-005: Detectors are signed data, with embedded test vectors
Status: accepted (2026-10-04)

A detector is pattern + validator + proximity keywords + confidence rules + test values +
test vectors, in a versioned pack. Built-in and tenant custom detectors share the format.
A pack failing its self-test cannot be published. Confidence (low/medium/high) is the main
false-positive control: known test values (e.g. 4111 1111 1111 1111) are downgraded to Low,
and policies count Medium+ by default. Distinct values are counted, not repetitions.

## Addendum (2026-10-05): credential-shaped test vectors are base64-encoded

GitHub push protection rejected the first push because synthetic AWS keys in the pack's
test vectors look real. Allow-listing them would make every fork, mirror and customer
scanner raise the same alerts. Instead, test values and vectors may be written as
`b64:<base64>`, decoded only in memory by the loader and self-test; all credential-category
vectors use this form. Rust test sources assemble such strings from parts (`concat!`).
`tests/secrets/scan.py --history` fails CI if any commit contains a credential-shaped
literal. Self-test failure messages print the encoded form, never the decoded value.
