# ADR-005: Detectors are signed data, with embedded test vectors
Status: accepted (2026-10-04)

A detector is pattern + validator + proximity keywords + confidence rules + test values +
test vectors, in a versioned pack. Built-in and tenant custom detectors share the format.
A pack failing its self-test cannot be published. Confidence (low/medium/high) is the main
false-positive control: known test values (e.g. 4111 1111 1111 1111) are downgraded to Low,
and policies count Medium+ by default. Distinct values are counted, not repetitions.
