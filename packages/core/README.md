# @tamtunnel/agentarb-core

Zero-dependency, no-I/O core for AgentArb: evidence bundle format v1,
RFC 8785 (JCS) canonicalization, Ed25519 `did:key` JWS, evidence trust
tiers, a minimal JSONLogic rules engine, versioned/signed/content-
addressed rule sets, verdicts with revocation, and the adjudication
engine.

Key design points:

- **Canonicalization is pinned RFC 8785**, vendored here because
  `@tamtunnel/si-wallet-core` keeps its canonicalizer private. Non-JSON
  values throw instead of being coerced.
- **JWS payloads must be canonical**: verification recomputes the
  canonical form and requires byte equality with the encoded segment.
- **Evidence signatures are fail-closed**: a bad signature rejects the
  whole bundle; evidence is never silently downgraded.
- **Money is integer minor units only**, with BigInt rational splits
  and an explicit remainder policy. Refunds never exceed the claim.
- **The engine can say "I don't know"**: no matching rule escalates
  instead of guessing.

Build: `npm run build -w @tamtunnel/agentarb-core`
Test: `node --test "packages/core/test/*.test.ts"` (from the repo root,
after building).
