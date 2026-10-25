// packages/core/src/verdict.ts
//
// Verdict format v1 + signing + revocation.
//
// A verdict is a versioned JSON envelope citing everything that decided
// it: the bundle hash, the exact rule-set id/version/hash, a reasoning
// trace naming which rules fired, and a `method` flag (`rules` vs
// `human`). Verdicts are signed by the deciding key (the arbiter key for
// rules verdicts, the human reviewer's did:key for human verdicts) over
// the canonical payload.
//
// Verdict ids are content addresses: id = "v_" + SHA-256 of the canonical
// verdict payload (minus id and signature). Same bundle + same rules +
// same decision time therefore yields a byte-identical verdict — the
// determinism property the engine is tested on. (Ed25519 signatures are
// deterministic, so the signature matches too.)
//
// Invariants enforced on every verdict, signed or not:
//   - refund_minor is an integer >= 0 and never exceeds the claim amount.
//   - outcome "escalate" always carries refund 0 (nothing moves while a
//     human has not ruled).
//   - rules verdicts cite a rule set; human verdicts must not.
//
// Revocation: a verdict can be revoked by the arbiter (or a trusted key)
// with a signed revocation entry. Verifiers check the revocation list
// separately — a revoked verdict still verifies cryptographically, but
// must be treated as void by any consumer.

import { canonicalize, canonicalHashSync } from "./jcs.js";
import { isDidKey } from "./did.js";
import { signJws, verifyJws, type Ed25519Jwk } from "./jws.js";
import { isMinorUnits } from "./money.js";

export type VerdictOutcome =
  | "refund_full"
  | "refund_partial"
  | "reject"
  | "escalate";

export type VerdictMethod = "rules" | "human";

export interface ReasoningStep {
  rule: string;
  matched: boolean;
  reason: string;
}

export interface VerdictCore {
  format: "agentarb-verdict";
  version: 1;
  case_id: string;
  bundle_id: string;
  bundle_hash: string;
  ruleset_id?: string;
  ruleset_version?: number;
  ruleset_hash?: string;
  method: VerdictMethod;
  outcome: VerdictOutcome;
  refund_minor: number;
  currency: string;
  claim_amount_minor: number;
  reasoning: ReasoningStep[];
  decided_at: string;
  arbiter: string;
}

export interface Verdict extends VerdictCore {
  id: string;
  signature?: string | null;
}

/** The exact object a verdict JWS signs (verdict minus id/signature). */
export function verdictSignPayload(
  verdict: VerdictCore,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    format: verdict.format,
    version: verdict.version,
    case_id: verdict.case_id,
    bundle_id: verdict.bundle_id,
    bundle_hash: verdict.bundle_hash,
    method: verdict.method,
    outcome: verdict.outcome,
    refund_minor: verdict.refund_minor,
    currency: verdict.currency,
    claim_amount_minor: verdict.claim_amount_minor,
    reasoning: verdict.reasoning,
    decided_at: verdict.decided_at,
    arbiter: verdict.arbiter,
  };
  if (verdict.ruleset_id !== undefined) out.ruleset_id = verdict.ruleset_id;
  if (verdict.ruleset_version !== undefined) {
    out.ruleset_version = verdict.ruleset_version;
  }
  if (verdict.ruleset_hash !== undefined) {
    out.ruleset_hash = verdict.ruleset_hash;
  }
  return out;
}

/** Content-addressed verdict id for a verdict payload. */
export function verdictIdFor(payload: Record<string, unknown>): string {
  return "v_" + canonicalHashSync(payload);
}

export function signVerdict(
  verdict: Verdict,
  privateJwk: Ed25519Jwk,
): Verdict {
  const payload = verdictSignPayload(verdict);
  const jws = signJws(payload, privateJwk);
  const verified = verifyJws(jws);
  if (!verified.ok || verified.issuerDid !== verdict.arbiter) {
    throw new Error("verdict signer key does not match verdict.arbiter");
  }
  return { ...verdict, signature: jws };
}

/** Structural validation of a verdict (no crypto). Returns error strings. */
export function validateVerdict(v: unknown): string[] {
  const errors: string[] = [];
  if (v === null || typeof v !== "object" || Array.isArray(v)) {
    return ["verdict must be an object"];
  }
  const d = v as Record<string, unknown>;
  if (d.format !== "agentarb-verdict") errors.push("format must be 'agentarb-verdict'");
  if (d.version !== 1) errors.push("version must be 1");
  if (typeof d.id !== "string" || d.id.length === 0) errors.push("id must be a non-empty string");
  if (typeof d.case_id !== "string" || d.case_id.length === 0) errors.push("case_id must be a non-empty string");
  if (typeof d.bundle_id !== "string" || d.bundle_id.length === 0) errors.push("bundle_id must be a non-empty string");
  if (typeof d.bundle_hash !== "string" || !/^[0-9a-f]{64}$/.test(d.bundle_hash)) {
    errors.push("bundle_hash must be a 64-hex-character digest");
  }
  if (d.method !== "rules" && d.method !== "human") errors.push("method must be 'rules' or 'human'");
  const outcomes = ["refund_full", "refund_partial", "reject", "escalate"];
  if (!outcomes.includes(d.outcome as string)) {
    errors.push(`outcome must be one of ${outcomes.join(", ")}`);
  }
  if (!isMinorUnits(d.refund_minor)) errors.push("refund_minor must be a non-negative safe integer");
  if (!isMinorUnits(d.claim_amount_minor)) errors.push("claim_amount_minor must be a non-negative safe integer");
  if (
    typeof d.refund_minor === "number" &&
    typeof d.claim_amount_minor === "number" &&
    (d.refund_minor as number) > (d.claim_amount_minor as number)
  ) {
    errors.push("refund_minor must not exceed claim_amount_minor");
  }
  if (d.outcome === "escalate" && d.refund_minor !== 0) {
    errors.push("escalate verdicts must carry refund_minor 0");
  }
  if (typeof d.currency !== "string" || !/^[A-Z]{3}$/.test(d.currency)) {
    errors.push("currency must be a 3-letter uppercase code");
  }
  if (!Array.isArray(d.reasoning) || d.reasoning.length === 0) {
    errors.push("reasoning must be a non-empty array");
  } else {
    d.reasoning.forEach((r: unknown, i: number) => {
      if (r === null || typeof r !== "object" || Array.isArray(r)) {
        errors.push(`reasoning[${i}] must be an object`);
        return;
      }
      const step = r as Record<string, unknown>;
      if (typeof step.rule !== "string" || step.rule.length === 0) errors.push(`reasoning[${i}].rule must be a non-empty string`);
      if (typeof step.matched !== "boolean") errors.push(`reasoning[${i}].matched must be a boolean`);
      if (typeof step.reason !== "string" || step.reason.length === 0) errors.push(`reasoning[${i}].reason must be a non-empty string`);
    });
  }
  if (typeof d.decided_at !== "string" || Number.isNaN(Date.parse(d.decided_at))) {
    errors.push("decided_at must be an ISO-8601 timestamp");
  }
  if (!isDidKey(d.arbiter)) errors.push("arbiter must be an Ed25519 did:key");
  if (d.method === "rules") {
    if (typeof d.ruleset_id !== "string" || d.ruleset_id.length === 0) errors.push("rules verdicts must cite ruleset_id");
    if (!Number.isSafeInteger(d.ruleset_version) || (d.ruleset_version as number) < 1) errors.push("rules verdicts must cite ruleset_version >= 1");
    if (typeof d.ruleset_hash !== "string" || !/^[0-9a-f]{64}$/.test(d.ruleset_hash)) {
      errors.push("rules verdicts must cite a 64-hex ruleset_hash");
    }
  }
  if (d.method === "human" && (d.ruleset_id !== undefined || d.ruleset_hash !== undefined)) {
    errors.push("human verdicts must not cite a rule set");
  }
  if (d.signature !== undefined && d.signature !== null && typeof d.signature !== "string") {
    errors.push("signature must be a string");
  }
  return errors;
}

export interface VerdictVerification {
  ok: boolean;
  errors: string[];
}

/**
 * Full verdict verification: structure, signature (when present), and
 * signer match. When trustedArbiters is given, the arbiter DID must be a
 * member (this is how key rotation stays safe: retired arbiter keys remain
 * trusted for old verdicts, unknown keys never are). A verdict without a
 * signature verifies structurally only when allowUnsigned is set.
 */
export function verifyVerdict(
  verdict: unknown,
  opts: { trustedArbiters?: string[]; allowUnsigned?: boolean } = {},
): VerdictVerification {
  const errors = validateVerdict(verdict);
  if (errors.length > 0) return { ok: false, errors };
  const v = verdict as Verdict;
  if (opts.trustedArbiters && !opts.trustedArbiters.includes(v.arbiter)) {
    errors.push(`arbiter ${v.arbiter} is not in the trusted set`);
  }
  if (v.signature == null) {
    if (!opts.allowUnsigned) errors.push("verdict is unsigned");
    return { ok: errors.length === 0, errors };
  }
  const verified = verifyJws(v.signature, v.arbiter);
  if (!verified.ok) {
    errors.push(`signature invalid (${verified.reason})`);
    return { ok: false, errors };
  }
  if (canonicalize(verified.payload) !== canonicalize(verdictSignPayload(v))) {
    errors.push("signature does not cover this verdict");
  }
  return { ok: errors.length === 0, errors };
}

// ---------------------------------------------------------------- revocation

export interface RevocationEntry {
  verdict_id: string;
  reason: string;
  revoked_at: string;
  arbiter: string;
  signature: string;
}

export function revocationSignPayload(
  entry: Omit<RevocationEntry, "signature">,
): Record<string, unknown> {
  return {
    verdict_id: entry.verdict_id,
    reason: entry.reason,
    revoked_at: entry.revoked_at,
    arbiter: entry.arbiter,
  };
}

export function signRevocation(
  entry: Omit<RevocationEntry, "signature">,
  privateJwk: Ed25519Jwk,
): RevocationEntry {
  const jws = signJws(revocationSignPayload(entry), privateJwk);
  const verified = verifyJws(jws);
  if (!verified.ok || verified.issuerDid !== entry.arbiter) {
    throw new Error("revocation signer key does not match revocation.arbiter");
  }
  return { ...entry, signature: jws };
}

export function verifyRevocation(
  entry: RevocationEntry,
  trustedArbiters?: string[],
): { ok: boolean; errors: string[] } {
  const errors: string[] = [];
  if (typeof entry.verdict_id !== "string" || entry.verdict_id.length === 0) {
    errors.push("verdict_id must be a non-empty string");
  }
  if (typeof entry.reason !== "string" || entry.reason.length === 0) {
    errors.push("reason must be a non-empty string");
  }
  if (typeof entry.revoked_at !== "string" || Number.isNaN(Date.parse(entry.revoked_at))) {
    errors.push("revoked_at must be an ISO-8601 timestamp");
  }
  if (!isDidKey(entry.arbiter)) errors.push("arbiter must be an Ed25519 did:key");
  if (trustedArbiters && !trustedArbiters.includes(entry.arbiter)) {
    errors.push(`arbiter ${entry.arbiter} is not in the trusted set`);
  }
  if (errors.length > 0) return { ok: false, errors };
  const verified = verifyJws(entry.signature, entry.arbiter);
  if (!verified.ok) {
    errors.push(`signature invalid (${verified.reason})`);
    return { ok: false, errors };
  }
  if (
    canonicalize(verified.payload) !==
    canonicalize(revocationSignPayload(entry))
  ) {
    errors.push("signature does not cover this revocation");
  }
  return { ok: errors.length === 0, errors };
}

export function isRevoked(
  revocations: RevocationEntry[],
  verdictId: string,
): RevocationEntry | null {
  return revocations.find((r) => r.verdict_id === verdictId) ?? null;
}
