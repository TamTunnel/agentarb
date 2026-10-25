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
  adjudicateClaim,
  BUNDLE_SCHEMA,
  builtinRulesetFor,
  generateKeypair,
  isDidKey,
  isMinorUnits,
  signRevocation,
  signVerdict,
  TIER_NAMES,
  validateBundlePayload,
  validateVerdict,
  VERDICT_SCHEMA,
  verifyBundle,
  verifyEvidenceItem,
  verifyVerdict,
  type Bundle,
  type Ed25519Jwk,
  type EvidenceItem,
  type Verdict,
} from "@tamtunnel/agentarb-core";
import { Store, type CaseStatus } from "./store.js";
import { applyVerdictToEscrow, checkMandateForHold } from "./escrow.js";
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

export function createApp(opts: ServerOptions): FastifyInstance {
  const { store } = opts;
  const app = Fastify({ logger: false });

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
  function trustedArbiterDids(): string[] {
    return store.getArbiterKeys().map((k) => k.did);
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
      store.createCase(caseId, b, verified.hash as string, now);
      for (const ev of verified.evidence) {
        store.addEvidence(caseId, ev.item.id, ev.item, ev.tier, now);
      }
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
          properties: {
            evidence: {
              type: "object",
              required: ["id", "kind", "submitted_by"],
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
      store.addEvidence(id, evidence.id, evidence, v.tier as number, nowIso());
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
      // Rebuild the bundle with its stored (verified) evidence so the
      // engine sees exactly what the case holds, including later additions.
      const storedEvidence = store.getEvidence(id).map((r) => JSON.parse(r.evidence_json));
      const fullBundle: Bundle = { ...bundle, evidence: storedEvidence };
      const arbiter = ensureArbiterKey();
      const nowIsoStr = nowIso();
      const verdicts: Verdict[] = [];
      const escrowEffects: unknown[] = [];
      let anyEscalate = false;
      try {
        for (let i = 0; i < bundle.claims.length; i++) {
          const claim = bundle.claims[i];
          const ruleset = builtinRulesetFor(claim.type);
          const { verdict } = adjudicateClaim(
            fullBundle,
            i,
            ruleset,
            id,
            arbiter.did,
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
          );
          escrowEffects.push(...effects);
          if (signed.outcome === "escalate") anyEscalate = true;
          verdicts.push(signed);
        }
      } catch (e) {
        return bad(reply, 400, "adjudication failed", (e as Error).message);
      }
      const status: CaseStatus = anyEscalate ? "escalated" : "adjudicated";
      store.setCaseStatus(id, status, nowIsoStr);
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
      const v = verifyVerdict(verdict);
      if (!v.ok) {
        return bad(reply, 400, "verdict verification failed", v.errors);
      }
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
      const effects = applyVerdictToEscrow(
        store,
        id,
        claim_index,
        verdict.id,
        verdict.outcome,
        verdict.refund_minor,
        nowIso(),
      );
      store.setCaseStatus(id, "resolved", nowIso());
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
      let mandateAgent: string | null = null;
      if (mandate_jws) {
        const check = checkMandateForHold(mandate_jws, amount_minor);
        if (!check.ok) {
          return bad(reply, 400, "mandate verification failed", check.reason);
        }
        mandateAgent = check.agent ?? null;
      }
      const holdId = "hold_" + randomUUID();
      const now = nowIso();
      store.createHold(holdId, case_id, idx, amount_minor, currency, mandate_jws ?? null, mandateAgent, now);
      store.addHoldEvent(holdId, "hold", amount_minor, null, now);
      return reply.status(201).send({
        hold_id: holdId,
        case_id,
        claim_index: idx,
        amount_minor,
        currency,
        remaining_minor: amount_minor,
        status: "held",
        mandate_agent: mandateAgent,
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
