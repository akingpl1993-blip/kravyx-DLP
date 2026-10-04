# ADR-004: Policy evaluation semantics
Status: accepted (2026-10-04)

1. In-scope policies: enabled, schedule-active, channel match, user/group scope.
2. Each matching enforce-mode rule contributes one enforcement action (max one per rule).
3. Exception rules (Allow only) at priority P carve out matches with priority < P, including
   their side effects. Ties do not carve out (restrictive wins on equal priority).
4. Most restrictive remaining action wins:
   allow < audit < warn < justify < request_approval < encrypt < quarantine < block.
5. Side effects are unioned, except `create_incident`: one event yields one incident, using
   the deciding rule's parameters.
6. Monitor-mode policies are reported, never enforced.
7. Missing facts make a leaf false; therefore `not(...)` over a missing fact is true
   (e.g. an unknown GenAI app is treated as unsanctioned). This is deliberate fail-closed.

Deviation from the architecture doc: "Notify" is modelled as side effects
(`notify_user`, `notify_admin`), not an enforcement level, because notifying never
changes whether data moves.
