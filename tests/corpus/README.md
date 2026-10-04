# Synthetic DLP test corpus

Every value in this directory is **synthetic**: generated to satisfy the relevant
checksum (Luhn, mod-97, Verhoeff) with no relation to real people or accounts, or
taken from vendors' published documentation examples. Never add real personal data.

- `positive/` — content that must trigger specific detectors.
- `negative/` — realistic business content that must produce no Medium/High findings.
