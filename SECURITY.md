# Security policy

- Report vulnerabilities privately to the security owners; do not open public issues.
- No real personal, payment or health data in the repository, tests, fixtures or logs. Test data is synthetic (checksum-valid generated values or vendor documentation examples).
- Raw matched values must never leave `inspect-core` results: only counts, confidence and masked samples. CI enforces this for the simulator path.
- Every tenant-owned table must carry `tenant_id` with forced RLS; `tests/isolation` fails the build otherwise.
- The runtime database role is never the schema owner and never `BYPASSRLS`.
