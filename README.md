# AgentArb — small-claims court for agent commerce

## The problem

AI agents are starting to buy and sell from each other: one agent hires
another to do a task, pays for data, or books a service. When the deal
goes wrong — nothing arrived, it arrived late, half of it was wrong —
there is no small-claims court. Human courts don't scale to a $10
dispute, chargebacks don't exist for agent-to-agent payments, and "the
agent said so" is not evidence.

So today, agent commerce either trusts blindly or doesn't happen at
all. Both are bad.

## The solution, in plain terms

AgentArb is a neutral arbiter that any two agents (or their operators)
can use to settle a dispute:

1. **Both sides submit signed evidence.** The claimant files a bundle:
   what was agreed, what was paid, what went wrong, and evidence —
   delivery scans, messages, inspection reports. Every item is signed
   with the submitter's cryptographic identity, so nobody can forge
   someone else's proof.
2. **Not all evidence is equal.** Evidence signed by the *other* party
   (an admission against interest) counts most. Evidence from an
   independent third party counts next. Your own signed word counts
   less. Unsigned claims count least. Each kind of dispute requires a
   minimum level of proof before the rules will even look at it.
3. **Deterministic rules decide.** Three built-in rule sets cover the
   common cases: non-delivery, late delivery, wrong or partial
   delivery. The rules are data, not code — they can't run anything,
   they can only look at the evidence. Every verdict says exactly
   which rules fired, so anyone can re-check it.
4. **When the rules can't decide, a human does.** If the evidence is
   too weak or contradictory, the engine says "I don't know" and
   escalates instead of guessing. A human reviewer issues a verdict in
   the same signed format.
5. **Money moves only on verdicts.** Holds are frozen per claim and
   released or refunded when a verdict says so. Nothing moves on a
   claim alone, and a refund can never exceed the amount claimed.
6. **Everything is checkable offline.** Bundles, verdicts, and rule
   sets are signed; anyone with the files can verify them without
   asking the server. Verdicts cite the exact rule-set version and
   hash that decided them.

AgentArb holds no real money in v1. The escrow is a ledger model —
records of holds, releases, and refunds — that real payment adapters
(Stripe, on-chain) will settle against later. The verdict format is
already final, so adapters slot in without changing it.

## Quick start

Requires Node 22+.

```sh
npm install
npm run build

# 1. Start the arbiter server (local only, port 3000)
npm run build -w @tamtunnel/agentarb-server
node packages/server/dist/index.js

# 2. In another terminal, generate a demo dispute
node packages/cli/dist/index.js demo --scenario non-delivery --out /tmp/demo

# 3. Submit it, adjudicate it, and check the verdict — no server trust needed
node packages/cli/dist/index.js submit --server http://127.0.0.1:3000 --in /tmp/demo/bundle.json
# note the case_id, then:
node packages/cli/dist/index.js adjudicate --server http://127.0.0.1:3000 --case <case-id>
node packages/cli/dist/index.js verify --in /tmp/demo/bundle.json   # offline, no server
```

Try the other scenarios too: `late-delivery` (refunds a pre-agreed
penalty when an oracle-signed delivery scan is past the deadline) and
`wrong-partial-delivery` (refunds the missing amount on credible
inspection evidence). The read-only case viewer lives at
http://127.0.0.1:3000/.

Run the tests:

```sh
npm test        # build all packages, then the full suite (node:test)
npm run typecheck
```

## Architecture

npm-workspaces monorepo, TypeScript throughout:

| Package | What it is |
| --- | --- |
| `@tamtunnel/agentarb-core` | Zero-dependency, no I/O: bundle format, JCS canonicalization, Ed25519 did:key JWS, trust tiers, JSONLogic rules engine, verdicts, revocation. |
| `@tamtunnel/agentarb-server` | Arbiter service: Fastify API, SQLite case store, verdict-gated escrow ledger, human escalation, read-only HTML viewer. |
| `@tamtunnel/agentarb-cli` | `agentarb` binary: keygen, bundle sign/verify, submit, adjudicate, demo. Offline verification is first-class. |

### The bundle (format v1)

A versioned JSON envelope: header, parties as `did:key`, transaction
reference (currency + integer minor-unit amount — never floats), claims,
and evidence items. Evidence carries inline content, a SHA-256 hash, a
URI, or a combination. The envelope separates payload from signatures;
each signature is a compact Ed25519 JWS over the canonical (RFC 8785
JCS) payload, so multi-party signing works and any tampering is
detectable. Verification is fail-closed: a bad evidence signature
rejects the whole bundle — evidence is never silently downgraded.

### Trust tiers

| Tier | Meaning |
| --- | --- |
| 3 — counterparty-signed | Signed by a party to the dispute who did not submit the item. |
| 2 — third-party-oracle-signed | Signed by someone who is not a party. |
| 1 — self-signed | Signed by the submitter. |
| 0 — unsigned | No signature claim. |

Minimum tiers: non-delivery admits tier ≥ 1; late-delivery and
wrong/partial-delivery admit tier ≥ 2 (timestamps and condition claims
need independence). Items below the minimum are excluded from
evaluation and recorded in the trace.

### Rules engine

A vendored minimal JSONLogic evaluator (data, never `eval`). Rule sets
are versioned, content-addressed (SHA-256 of the canonical rules), and
signed; every verdict cites the exact rule-set id, version, and hash.
Rules evaluate in order; the first match decides; no match escalates.
The three built-in sets ship signed in
`packages/core/src/builtin-rulesets.generated.ts` (generated by
`scripts/sign-rulesets.mjs` from `builtin-definitions.ts`).

### Verdicts

Versioned, signed, content-addressed: a verdict's id is the SHA-256 of
its canonical payload, so the same bundle + same rules + same decision
time yields a byte-identical verdict (Ed25519 signatures are
deterministic). `method` is `rules` or `human`. Invariants enforced on
every verdict: refund is an integer ≥ 0, never exceeds the claimed
amount, and `escalate` always carries refund 0.

### Escrow

Ledger adapter, not custody. Holds are scoped per claim. Applying a
verdict moves only the delta versus what was already applied for that
claim, so re-adjudication is safe. Reject releases the claim's hold;
escalate moves nothing. A second adapter accepts AgentCred task
mandates as holds: the mandate is verified with the audited
`@tamtunnel/si-wallet-core` `verifyMandate`, its major-unit limit must
cover the hold, and verification consumes the mandate (single-use by
design — re-submission fails as a replay).

### Key rotation and revocation

The arbiter's key lives in the server data dir. Rotating it retires the
old key; verdicts signed by retired keys still verify against the
trusted set (active + retired), unknown keys never do. A verdict can be
revoked with a signed revocation entry; consumers must check the
revocation list — a revoked verdict still verifies cryptographically
but is void.

## FAQs

**Is this real money?**
No, not in v1. Holds are ledger records. The verdict format is final so
payment adapters can settle against it later without changing
anything.

**Why `did:key` identities?**
The public key *is* the identity — no registry lookup, no certificate
chain. Verification needs only the DID string, which is also why key
rotation stays simple: trust is a set of DIDs.

**Why JSONLogic for rules?**
Rules must be auditable data, not code. JSONLogic can't touch the
filesystem, the network, or anything but the evidence object it is
given. There is no sandbox to escape because there is no execution.

**What if the rules get it wrong?**
Two backstops: the engine escalates whenever it can't decide, and a
verdict can be revoked. A revoked verdict does not auto-reverse escrow
in v1 — reversing a settled ledger entry is a human process, and v1
says so instead of pretending otherwise.

**Does the server have authentication?**
No. v1 binds `127.0.0.1` by default and is a local demo/test service.
Put it behind authentication before exposing it to any network you
don't trust. The same applies to the arbiter private key in the data
dir — protect the directory; a future version should use a KMS/HSM.

**What does AgentArb deliberately not do?**
Real-money custody or payment rails; multi-arbiter consensus,
reputation, or a marketplace; zero-knowledge proofs or encrypted
evidence; claim types beyond the three built-ins; multi-node or
Postgres operation; ML risk scoring; a dashboard SPA (the viewer is
server-rendered HTML on purpose).

## Repository best practices

- `npm test` — build everything, run the whole suite. Green before
  reporting anything complete.
- `npm run typecheck` — strict TypeScript, no emit.
- Build output lives in `dist/` only. Never commit compiled `.js` /
  `.d.ts` next to `.ts` sources — test imports resolve stale files
  first and the suite will silently test old code.
- No personal identifiers anywhere in the repo: examples use clearly
  fake data only.
- Pushes go through the review gate plus the adversarial judge gate
  before shipping (see project history). The demo site and explainer
  video come after the gates, not before.
- License: Apache-2.0 (see LICENSE).
