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

## Demo

See a real sample arbitration — a $100 non-delivery dispute, walked through
from signed evidence bundle to signed verdict to escrow refund — at
<https://tamtunnel.github.io/agentarb/>, with a short captioned explainer
video at <https://tamtunnel.github.io/agentarb/#video>.

## Quick start

Requires Node 24+.

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
URI, or a combination. A SHA-256 carried alongside inline content must
be the digest of those content bytes (verified — a signed item cannot
claim content X with the hash of Y); a SHA-256 carried with a URI and
no inline content is an unverified claim about remote bytes, because v1
has no fetcher. The envelope separates payload from signatures;
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
`scripts/sign-rulesets.mjs` from `builtin-definitions.ts`). Re-signing
requires the built-in signing key; with a new keypair you must also
update `BUILTIN_SIGNER_DID` in the generated file.

### Verdicts

Versioned, signed, content-addressed: a verdict's id is the SHA-256 of
its canonical payload, so the same bundle + same rules + same decision
time yields a byte-identical verdict (Ed25519 signatures are
deterministic). `method` is `rules` or `human`. Invariants enforced on
every verdict: refund is an integer ≥ 0, never exceeds the claimed
amount, and `escalate` always carries refund 0. Verification enforces
that the id is the content address of the signed payload — the
signature does not cover the id, so without this check a revoked
verdict could be re-labeled post-signing and presented to an offline
consumer as live. Signing refuses to mint a verdict whose id is not
its content address, for the same reason. The CLI's `verdict verify`
accepts `--revocations <file>` to check a revocation list; without it,
VALID means cryptographically valid only — revocation is a separate
list and must be checked explicitly.

### Escrow

Ledger adapter, not custody. Holds are scoped per claim. Applying a
verdict moves only the delta versus what was already applied for that
claim, so re-adjudication is safe. Reject releases the claim's hold;
escalate moves nothing. A release that zeroes a hold marks it
`released`. Two figures are tracked per claim: `applied` (the latest
verdict's refund level) and `cumulative` (cash actually moved, never
decreased, never reset by a reject) — so refund → reject → refund can
never pay a claim twice. A hold created after a refund verdict was
already applied funds the outstanding shortfall immediately (and a
later re-application of the same verdict does the same), so new holds
never strand funds. A downward revision after a full refund cannot
claw back cash already refunded — the ledger records the lower applied
level, but the over-refunded cash stays refunded; clawback is a human
process in v1, like revocation.

A second adapter accepts AgentCred task mandates as holds: the mandate
is verified with the audited `@tamtunnel/si-wallet-core`
`verifyMandate`, its major-unit limit must cover the hold, and
verification consumes the mandate (single-use by design — re-submission
fails as a replay). The adapter adds checks upstream added in
`@tamtunnel/si-wallet-core@0.1.1`: the mandate and grant JWS kids must
equal the identities they claim (`kid == iss` for both, grant `sub ==`
mandate `iss`). Before 0.1.1, upstream `verifyMandate` never bound kid to
issuer, so without these checks an attacker holding only their own key
could mint a victim-issued chain that verifies. The adapter checks are
kept as defense in depth; AgentArb's `^0.1.0` range picks up 0.1.1
automatically once it is on npm. The mandate must be minted for audience `agentarb`,
its `claims.currency` must equal the hold currency, its scope must
include `agentarb:hold`, and the major→minor conversion floors, never
rounds up. Any agent may back a hold (guarantor model — the mandate
proves spending authority, not party membership); party matching is
deliberately not enforced.

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

### Known limitations (v1)

- **Identical claims fail closed.** Two claims with identical type,
  amount, and evidence produce byte-identical verdicts, and verdict ids
  are the global primary key — so adjudicating both returns a clean
  400 with a full rollback, and the case stays open for `/escalate`.
  The v1.1 fix is verdicts citing `claim_index`; until then, identical
  claims must go to a human.
- **Human verdicts accept any non-party key.** Consistent with v1's
  no-auth posture: the human-verdict endpoint rejects party
  self-dealing but does not restrict which non-party key may rule.
  A trusted-human list is a v2 addition, not a silent v1 default.
- **Revocation voids; it does not reverse.** Revoking a verdict does
  not move escrow (see the FAQ above), and a revoked verdict still
  verifies cryptographically — consumers must check the revocation
  list, e.g. via the CLI's `--revocations` flag.

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
