// packages/server/src/app.ts
//
// Arbiter service: Fastify API + SQLite case store + verdict-gated escrow
// + human escalation + read-only HTML viewer.
//
// Security posture for v1 (stated plainly in the README too):
//   - Binds 127.0.0.1 by default; put it behind auth before exposing it.
//   - No authentication on the API itself in v1 — it is a local demo and
//     test service. Anyone who can reach it can submit cases and rotate
//     keys. Do not expose it to untrusted networks.
//   - Arbiter private keys live in the data dir (SQLite). Protect the dir
//     (0600 files, backed-up separately); v2 should use a KMS/HSM.
//   - The server verifies every signature it is handed; it never trusts
//     a claimed tier, amount, or signer without checking the JWS.

import Fastify, { type FastifyInstance, type FastifyReply } from "fastify";
import { randomUUID } from "node:crypto";
import {
  adjudicateClaimWithEvidence,
  BUNDLE_SCHEMA,
  builtinRulesetFor,
  CanonicalizationError,
  generateKeypair,
  isDidKey,
  isHttpUrl,
  isIsoDate,
  isMinorUnits,
  signRevocation,
  signVerdict,
  TIER_NAMES,
  validateBundlePayload,
  validateVerdict,
  VERDICT_SCHEMA,
  verdictIdFor,
  verifyBundle,
  verifyEvidenceItem,
  verifyVerdict,
  verdictSignPayload,
  type Bundle,
  type Ed25519Jwk,
  type EvidenceItem,
  type Verdict,
  type VerifiedEvidence,
} from "@tamtunnel/agentarb-core";
import { Store, type CaseStatus } from "./store.js";
import {
  applyUnfundedRefund,
  applyVerdictToEscrow,
  checkMandateForHold,
} from "./escrow.js";
import {
  renderCaseDetail,
  renderCaseList,
  type CaseSummary,
} from "./viewer.js";

export interface ServerOptions {
  store: Store;
  /** When true, POST /adjudicate accepts a `now` override (tests). */
  allowNowOverride?: boolean;
}

function bad(reply: FastifyReply, code: number, error: string, details?: unknown) {
  return reply.status(code).send({ error, ...(details !== undefined ? { details } : {}) });
}

/** Map a store failure to a safe client-facing message: SQLite internals
 * (e.g. "UNIQUE constraint failed: verdicts.id" on identical claims)
 * must never leak through a 400 body. */
function sanitizedStoreError(e: unknown): string {
  const msg = (e as Error).message ?? "store operation failed";
  if (/UNIQUE constraint failed/.test(msg)) {
    return "duplicate verdict id — identical claims cannot be adjudicated separately; use /escalate for a human decision";
  }
  if (/NOT NULL constraint failed|no such table|no such column/.test(msg)) {
    return "store operation failed";
  }
  return msg;
}

export function createApp(opts: ServerOptions): FastifyInstance {
  const { store } = opts;
  // Fastify 5 strips unknown body fields by default (removeAdditional),
  // which would silently accept — and, before the handler, erase — junk
  // fields on the evidence endpoint instead of rejecting them. Disable
  // stripping so additionalProperties:false in the route schemas is
  // actually enforced as a 400.
  const app = Fastify({
    logger: false,
    ajv: { customOptions: { removeAdditional: false } },
  });

  // ------------------------------------------------------- arbiter keys
  const nowIso = () => new Date().toISOString();
  function ensureArbiterKey(): { did: string; privateJwk: Ed25519Jwk } {
    const active = store.getActiveArbiterKey();
    if (active) {
      return {
        did: active.did,
        privateJwk: JSON.parse(active.private_jwk_json) as Ed25519Jwk,
      };
    }
    const kp = generateKeypair();
    store.addArbiterKey(kp.did, JSON.stringify(kp.privateJwk), nowIso());
    return { did: kp.did, privateJwk: kp.privateJwk };
  }
  // ------------------------------------------------------------- helpers
  function caseOr404(id: string) {
    const row = store.getCase(id);
    if (!row) return null;
    const bundle = JSON.parse(row.bundle_json) as Bundle;
    const evidence = store.getEvidence(id).map((r) => ({
      ...JSON.parse(r.evidence_json),
      tier: r.tier,
      tierName: TIER_NAMES[r.tier as 0 | 1 | 2 | 3],
    }));
    const verdicts = store.getVerdicts(id).map((r) => {
      const verdict = JSON.parse(r.verdict_json) as Verdict;
      const revoked = store.getRevocation(r.id);
      return {
        ...verdict,
        revoked: revoked ? JSON.parse(revoked.revocation_json) : null,
      };
    });
    const holds = store.getHolds(id).map((h) => ({
      ...h,
      events: store.getHoldEvents(h.id),
    }));
    return {
      id: row.id,
      status: row.status,
      bundle,
      bundle_hash: row.bundle_hash,
      evidence,
      verdicts,
      holds,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  // ---------------------------------------------------------------- routes
  app.get("/health", async () => ({ ok: true }));

  app.post(
    "/v1/cases",
    { schema: { body: { type: "object", required: ["bundle"], properties: { bundle: BUNDLE_SCHEMA } } } },
    async (request, reply) => {
      const { bundle } = request.body as { bundle: unknown };
      const structural = validateBundlePayload(
        (bundle as { signatures?: unknown }).signatures !== undefined
          ? stripSignatures(bundle as Bundle)
          : bundle,
      );
      if (structural.length > 0) {
        return bad(reply, 400, "bundle payload invalid", structural);
      }
      const verified = verifyBundle(bundle);
      if (!verified.ok) {
        return bad(reply, 400, "bundle verification failed", verified.errors);
      }
      const b = bundle as Bundle;
      if (store.findCaseByBundleId(b.id)) {
        return bad(reply, 409, `a case already exists for bundle ${b.id}`);
      }
      const caseId = "case_" + randomUUID();
      const now = nowIso();
      // Case + evidence are one unit: a failure partway must not leave a
      // case missing evidence.
      store.transaction(() => {
        store.createCase(caseId, b, verified.hash as string, now);
        for (const ev of verified.evidence) {
          store.addEvidence(caseId, ev.item.id, ev.item, ev.tier, now);
        }
      });
      return reply.status(201).send({
        case_id: caseId,
        bundle_hash: verified.hash,
        status: "open",
        evidence: verified.evidence.map((e) => ({
          id: e.item.id,
          tier: e.tier,
          tierName: e.tierName,
        })),
      });
    },
  );

  app.get("/v1/cases", async () => {
    const cases = store.listCases().map((row) => {
      const bundle = JSON.parse(row.bundle_json) as Bundle;
      return {
        id: row.id,
        status: row.status,
        bundle_id: bundle.id,
        claimant: bundle.claimant,
        respondent: bundle.respondent,
        created_at: row.created_at,
      };
    });
    return { cases };
  });

  app.get("/v1/cases/:id", async (request, reply) => {
    const detail = caseOr404((request.params as { id: string }).id);
    if (!detail) return bad(reply, 404, "case not found");
    return detail;
  });

  app.post(
    "/v1/cases/:id/evidence",
    {
      schema: {
        body: {
          type: "object",
          required: ["evidence"],
          additionalProperties: false,
          properties: {
            evidence: {
              type: "object",
              required: ["id", "kind", "submitted_by"],
              additionalProperties: false,
              properties: {
                id: { type: "string", minLength: 1 },
                kind: { type: "string" },
                content: { type: ["string", "null"] },
                sha256: { type: ["string", "null"] },
                uri: { type: ["string", "null"] },
                delivered_at: { type: ["string", "null"] },
                signer: { type: ["string", "null"] },
                jws: { type: ["string", "null"] },
                submitted_by: { type: "string" },
              },
            },
          },
        },
      },
    },
    async (request, reply) => {
      const id = (request.params as { id: string }).id;
      const row = store.getCase(id);
      if (!row) return bad(reply, 404, "case not found");
      if (row.status === "resolved") {
        return bad(reply, 409, "case is resolved; evidence can no longer be added");
      }
      const { evidence } = request.body as { evidence: EvidenceItem };
      const bundle = JSON.parse(row.bundle_json) as Bundle;
      const kinds = ["delivery-proof", "communication", "oracle-attestation", "payment-proof", "condition-proof", "other"];
      if (!kinds.includes(evidence.kind)) {
        return bad(reply, 400, `evidence.kind must be one of ${kinds.join(", ")}`);
      }
      if (evidence.sha256 != null && !/^[0-9a-f]{64}$/.test(evidence.sha256)) {
        return bad(reply, 400, "evidence.sha256 must be a 64-hex-character digest");
      }
      if (evidence.uri != null && !isHttpUrl(evidence.uri)) {
        return bad(reply, 400, "evidence.uri must be an http(s) URL");
      }
      // Parity with the bundle path (validateBundlePayload): a garbage
      // delivered_at must be rejected here too, not coerced to a null
      // epoch by the engine.
      if (evidence.delivered_at != null && !isIsoDate(evidence.delivered_at)) {
        return bad(reply, 400, "evidence.delivered_at must be an ISO-8601 timestamp or null");
      }
      // Reuse the bundle validator for the single item by checking the
      // item's shape fields directly.
      if (!evidence.content && !evidence.sha256 && !evidence.uri) {
        return bad(reply, 400, "evidence must carry at least one of content, sha256, uri");
      }
      if ((evidence.signer == null) !== (evidence.jws == null)) {
        return bad(reply, 400, "evidence must carry both signer and jws, or neither");
      }
      if (!isDidKey(evidence.submitted_by)) {
        return bad(reply, 400, "submitted_by must be an Ed25519 did:key");
      }
      const v = verifyEvidenceItem(evidence, bundle.claimant, bundle.respondent);
      if (!v.ok) {
        return bad(reply, 400, "evidence verification failed", v.errors);
      }
      const existing = store.getEvidence(id);
      if (existing.some((r) => r.evidence_id === evidence.id)) {
        return bad(reply, 409, `evidence ${evidence.id} already exists on this case`);
      }
      // Defense in depth behind the schema's additionalProperties:false:
      // a hostile deeply-nested body must be a 400, never a 500 from a
      // canonicalization throw inside the store.
      try {
        store.addEvidence(id, evidence.id, evidence, v.tier as number, nowIso());
      } catch (e) {
        if (e instanceof CanonicalizationError || e instanceof RangeError) {
          return bad(reply, 400, "evidence cannot be canonicalized", (e as Error).message);
        }
        throw e;
      }
      return reply.status(201).send({
        id: evidence.id,
        tier: v.tier,
        tierName: v.tierName,
      });
    },
  );

  app.post(
    "/v1/cases/:id/adjudicate",
    {
      schema: {
        body: {
          type: "object",
          properties: { now: { type: "string" } },
        },
      },
    },
    async (request, reply) => {
      const id = (request.params as { id: string }).id;
      const row = store.getCase(id);
      if (!row) return bad(reply, 404, "case not found");
      if (row.status === "resolved") {
        return bad(reply, 409, "case is resolved; it cannot be re-adjudicated");
      }
      const body = (request.body ?? {}) as { now?: string };
      let now = new Date();
      if (body.now !== undefined) {
        if (!opts.allowNowOverride) {
          return bad(reply, 400, "now override is disabled on this server");
        }
        const parsed = new Date(body.now);
        if (Number.isNaN(parsed.getTime())) {
          return bad(reply, 400, "now must be an ISO-8601 timestamp");
        }
        now = parsed;
      }
      const bundle = JSON.parse(row.bundle_json) as Bundle;
      // Guard: the stored envelope must still verify as the claimant
      // signed it. Evidence added after submission is NOT part of that
      // envelope, so each stored item is re-verified individually below
      // (fresh tiers under current logic) instead of re-checking the
      // envelope against the rebuilt payload — which would fail every
      // re-adjudication following an evidence addition.
      const origVerified = verifyBundle(bundle);
      if (!origVerified.ok) {
        return bad(reply, 400, "stored bundle no longer verifies", origVerified.errors);
      }
      const verifiedEvidence: VerifiedEvidence[] = [];
      for (const r of store.getEvidence(id)) {
        const item = JSON.parse(r.evidence_json) as EvidenceItem;
        const v = verifyEvidenceItem(item, bundle.claimant, bundle.respondent);
        if (!v.ok) {
          return bad(reply, 400, "stored evidence no longer verifies", v.errors);
        }
        verifiedEvidence.push({
          item,
          tier: v.tier as 0 | 1 | 2 | 3,
          tierName: v.tierName as string,
        });
      }
      const fullBundle: Bundle = {
        ...bundle,
        evidence: verifiedEvidence.map((e) => e.item),
      };
      const arbiter = ensureArbiterKey();
      const nowIsoStr = nowIso();
      const verdicts: Verdict[] = [];
      const escrowEffects: unknown[] = [];
      let anyEscalate = false;
      try {
        // The whole loop is one transaction: a failure on any claim
        // rolls back every verdict, escrow effect, and status change, so
        // a retry cannot create duplicate verdicts or double-move escrow.
        store.transaction(() => {
          for (let i = 0; i < bundle.claims.length; i++) {
            const claim = bundle.claims[i];
            const ruleset = builtinRulesetFor(claim.type);
            const { verdict } = adjudicateClaimWithEvidence(
              fullBundle,
              i,
              ruleset,
              id,
              arbiter.did,
              verifiedEvidence,
              row.bundle_hash,
              now,
            );
            const signed = signVerdict(verdict, arbiter.privateJwk);
            store.saveVerdict(
              signed.id,
              id,
              i,
              signed,
              signed.method,
              signed.outcome,
              signed.refund_minor,
              nowIsoStr,
            );
            const effects = applyVerdictToEscrow(
              store,
              id,
              i,
              signed.id,
              signed.outcome,
              signed.refund_minor,
              nowIsoStr,
              claim.amount_minor,
            );
            escrowEffects.push(...effects);
            if (signed.outcome === "escalate") anyEscalate = true;
            verdicts.push(signed);
          }
          const status: CaseStatus = anyEscalate ? "escalated" : "adjudicated";
          store.setCaseStatus(id, status, nowIsoStr);
        });
      } catch (e) {
        return bad(reply, 400, "adjudication failed", sanitizedStoreError(e));
      }
      const status: CaseStatus = anyEscalate ? "escalated" : "adjudicated";
      return { case_id: id, status, verdicts, escrow: escrowEffects };
    },
  );

  app.get("/v1/cases/:id/verdicts", async (request, reply) => {
    const id = (request.params as { id: string }).id;
    const row = store.getCase(id);
    if (!row) return bad(reply, 404, "case not found");
    const verdicts = store.getVerdicts(id).map((r) => {
      const verdict = JSON.parse(r.verdict_json) as Verdict;
      const revoked = store.getRevocation(r.id);
      return {
        ...verdict,
        revoked: revoked ? JSON.parse(revoked.revocation_json) : null,
      };
    });
    return { case_id: id, verdicts };
  });

  app.post(
    "/v1/cases/:id/escalate",
    {
      schema: {
        body: {
          type: "object",
          properties: { reason: { type: "string" } },
        },
      },
    },
    async (request, reply) => {
      const id = (request.params as { id: string }).id;
      const row = store.getCase(id);
      if (!row) return bad(reply, 404, "case not found");
      if (row.status === "resolved") {
        return bad(reply, 409, "case is resolved");
      }
      store.setCaseStatus(id, "escalated", nowIso());
      return { case_id: id, status: "escalated" };
    },
  );

  app.post(
    "/v1/cases/:id/human-verdict",
    {
      schema: {
        body: {
          type: "object",
          required: ["verdict", "claim_index"],
          properties: {
            verdict: VERDICT_SCHEMA,
            claim_index: { type: "integer", minimum: 0 },
          },
        },
      },
    },
    async (request, reply) => {
      const id = (request.params as { id: string }).id;
      const row = store.getCase(id);
      if (!row) return bad(reply, 404, "case not found");
      if (row.status !== "escalated") {
        return bad(reply, 409, "human verdicts require an escalated case (escalate it first)");
      }
      const { verdict, claim_index } = request.body as {
        verdict: Verdict;
        claim_index: number;
      };
      const bundle = JSON.parse(row.bundle_json) as Bundle;
      const structural = validateVerdict(verdict);
      if (structural.length > 0) {
        return bad(reply, 400, "verdict invalid", structural);
      }
      if (verdict.method !== "human") {
        return bad(reply, 400, "human-verdict endpoint requires method 'human'");
      }
      if (verdict.case_id !== id || verdict.bundle_id !== bundle.id) {
        return bad(reply, 400, "verdict does not belong to this case/bundle");
      }
      const claim = bundle.claims[claim_index];
      if (!claim) {
        return bad(reply, 400, `claim index ${claim_index} out of range`);
      }
      if (verdict.claim_amount_minor !== claim.amount_minor) {
        return bad(reply, 400, "verdict claim_amount_minor does not match the claim");
      }
      if (verdict.currency !== bundle.transaction.currency) {
        return bad(reply, 400, "verdict currency does not match the transaction");
      }
      if (verdict.outcome === "escalate") {
        return bad(reply, 400, "human verdicts cannot escalate — the human is the escalation target");
      }
      // The verdict must cite THIS case's bundle, by content address, and
      // must not be self-dealing: the claimant or respondent cannot sign
      // their own "human verdict" awarding themselves a refund. The id
      // check also stops non-content ids colliding across cases (verdict
      // id is a global primary key — a collision would 500 on save).
      if (verdict.bundle_hash !== row.bundle_hash) {
        return bad(reply, 400, "verdict bundle_hash does not match the stored bundle");
      }
      if (verdict.id !== verdictIdFor(verdictSignPayload(verdict))) {
        return bad(reply, 400, "verdict id is not the content address of its payload");
      }
      if (verdict.arbiter === bundle.claimant || verdict.arbiter === bundle.respondent) {
        return bad(reply, 400, "human verdict arbiter must not be a party to the case");
      }
      const v = verifyVerdict(verdict);
      if (!v.ok) {
        return bad(reply, 400, "verdict verification failed", v.errors);
      }
      // Verdict + escrow + status are one unit (same atomicity argument
      // as adjudication). Wrapped like adjudication: any store failure
      // is a clean 400, never a 500 leaking internals.
      let effects;
      try {
        effects = store.transaction(() => {
          store.saveVerdict(
            verdict.id,
            id,
            claim_index,
            verdict,
            verdict.method,
            verdict.outcome,
            verdict.refund_minor,
            nowIso(),
          );
          const fx = applyVerdictToEscrow(
            store,
            id,
            claim_index,
            verdict.id,
            verdict.outcome,
            verdict.refund_minor,
            nowIso(),
            claim.amount_minor,
          );
          store.setCaseStatus(id, "resolved", nowIso());
          return fx;
        });
      } catch (e) {
        return bad(reply, 400, "human verdict failed", sanitizedStoreError(e));
      }
      return { case_id: id, status: "resolved", verdict, escrow: effects };
    },
  );

  app.post(
    "/v1/verdicts/:id/revoke",
    {
      schema: {
        body: {
          type: "object",
          required: ["reason"],
          properties: { reason: { type: "string", minLength: 1 } },
        },
      },
    },
    async (request, reply) => {
      const verdictId = (request.params as { id: string }).id;
      const row = store.getVerdict(verdictId);
      if (!row) return bad(reply, 404, "verdict not found");
      if (store.getRevocation(verdictId)) {
        return bad(reply, 409, "verdict is already revoked");
      }
      const { reason } = request.body as { reason: string };
      const arbiter = ensureArbiterKey();
      const entry = signRevocation(
        {
          verdict_id: verdictId,
          reason,
          revoked_at: nowIso(),
          arbiter: arbiter.did,
        },
        arbiter.privateJwk,
      );
      store.saveRevocation(verdictId, entry, nowIso());
      return entry;
    },
  );

  app.post(
    "/v1/holds",
    {
      schema: {
        body: {
          type: "object",
          required: ["case_id", "amount_minor", "currency"],
          properties: {
            case_id: { type: "string" },
            claim_index: { type: "integer", minimum: 0 },
            amount_minor: { type: "integer", minimum: 0 },
            currency: { type: "string", pattern: "^[A-Z]{3}$" },
            mandate_jws: { type: "string" },
          },
        },
      },
    },
    async (request, reply) => {
      const { case_id, claim_index, amount_minor, currency, mandate_jws } =
        request.body as {
          case_id: string;
          claim_index?: number;
          amount_minor: number;
          currency: string;
          mandate_jws?: string;
        };
      const row = store.getCase(case_id);
      if (!row) return bad(reply, 404, "case not found");
      if (row.status === "resolved") {
        return bad(reply, 409, "case is resolved; holds can no longer be added");
      }
      const bundle = JSON.parse(row.bundle_json) as Bundle;
      const idx = claim_index ?? 0;
      if (!bundle.claims[idx]) {
        return bad(reply, 400, `claim index ${idx} out of range`);
      }
      if (currency !== bundle.transaction.currency) {
        return bad(reply, 400, "hold currency does not match the transaction");
      }
      if (!isMinorUnits(amount_minor)) {
        return bad(reply, 400, "amount_minor must be a non-negative safe integer");
      }
      if (amount_minor > bundle.claims[idx].amount_minor) {
        return bad(reply, 400, "hold amount_minor must not exceed the claim amount");
      }
      let mandateAgent: string | null = null;
      if (mandate_jws) {
        const check = checkMandateForHold(mandate_jws, amount_minor, currency);
        if (!check.ok) {
          return bad(reply, 400, "mandate verification failed", check.reason);
        }
        mandateAgent = check.agent ?? null;
      }
      const holdId = "hold_" + randomUUID();
      const now = nowIso();
      const refundEffects = store.transaction(() => {
        store.createHold(holdId, case_id, idx, amount_minor, currency, mandate_jws ?? null, mandateAgent, now);
        store.addHoldEvent(holdId, "hold", amount_minor, null, now);
        // A refund verdict applied before any hold existed leaves cash
        // outstanding (applied > cumulative); fund it from this hold now
        // instead of stranding the hold "held" forever.
        return applyUnfundedRefund(store, case_id, idx, holdId, now);
      });
      return reply.status(201).send({
        hold_id: holdId,
        case_id,
        claim_index: idx,
        amount_minor,
        currency,
        remaining_minor: amount_minor - refundEffects.reduce((s, e) => s + e.amount_minor, 0),
        status: refundEffects.length > 0 && refundEffects[0].remaining_minor === 0 ? "refunded" : "held",
        mandate_agent: mandateAgent,
        escrow: refundEffects,
      });
    },
  );

  app.get("/v1/holds/:id", async (request, reply) => {
    const hold = store.getHold((request.params as { id: string }).id);
    if (!hold) return bad(reply, 404, "hold not found");
    return { ...hold, events: store.getHoldEvents(hold.id) };
  });

  app.get("/v1/keys", async () => {
    const keys = store.getArbiterKeys();
    return {
      active: keys.find((k) => k.status === "active")?.did ?? null,
      retired: keys.filter((k) => k.status === "retired").map((k) => k.did),
    };
  });

  app.post("/v1/keys/rotate", async () => {
    const now = nowIso();
    const previous = store.getActiveArbiterKey();
    if (previous) store.retireArbiterKey(previous.did, now);
    const kp = generateKeypair();
    store.addArbiterKey(kp.did, JSON.stringify(kp.privateJwk), now);
    return {
      active: kp.did,
      retired: store
        .getArbiterKeys()
        .filter((k) => k.status === "retired")
        .map((k) => k.did),
    };
  });

  // ------------------------------------------------------------ viewer
  app.get("/", async (_request, reply) => {
    const cases: CaseSummary[] = store.listCases().map((row) => {
      const bundle = JSON.parse(row.bundle_json) as Bundle;
      return {
        id: row.id,
        status: row.status,
        bundle_id: bundle.id,
        claimant: bundle.claimant,
        respondent: bundle.respondent,
        created_at: row.created_at,
      };
    });
    return reply.type("text/html").send(renderCaseList(cases));
  });

  app.get("/cases/:id", async (request, reply) => {
    const detail = caseOr404((request.params as { id: string }).id);
    if (!detail) return bad(reply, 404, "case not found");
    const evidence = detail.evidence.map((e) => ({
      id: String(e.id),
      kind: String(e.kind),
      tier: Number(e.tier),
      tierName: String(e.tierName),
    }));
    const verdicts = detail.verdicts.map((v) => ({
      id: String(v.id),
      method: String(v.method),
      outcome: String(v.outcome),
      refund_minor: Number(v.refund_minor),
      revoked: v.revoked !== null,
      reasoning: (v.reasoning as Array<{ rule: string; matched: boolean; reason: string }>),
    }));
    const holds = detail.holds.map((h) => ({
      id: String(h.id),
      claim_index: Number(h.claim_index),
      amount_minor: Number(h.amount_minor),
      remaining_minor: Number(h.remaining_minor),
      status: String(h.status),
      mandate_agent: h.mandate_agent ? String(h.mandate_agent) : null,
    }));
    return reply.type("text/html").send(
      renderCaseDetail({
        id: detail.id,
        status: detail.status,
        bundle: detail.bundle as unknown as Record<string, unknown>,
        bundle_hash: detail.bundle_hash,
        evidence,
        verdicts,
        holds,
      }),
    );
  });

  return app;
}

function stripSignatures(bundle: Bundle): Omit<Bundle, "signatures"> {
  const { signatures: _signatures, ...payload } = bundle;
  return payload;
}
