// packages/core/src/bundle.ts
//
// Evidence bundle format v1.
//
// A bundle is a versioned JSON envelope: header, parties as did:key,
// transaction reference, claims with integer minor-unit amounts (NEVER
// floats), evidence items typed with content-or-SHA256-hash+URI, and
// Ed25519 JWS signatures over the canonical (JCS) payload.
//
// Signing model: the envelope separates `payload` from `signatures`.
// Each signature is a compact JWS whose payload is the canonical JSON of
// the payload object. Multi-party signing is supported (claimant and
// respondent can both sign). Verification is fail-closed: an invalid
// signature, a signer field that disagrees with the JWS kid, or a signed
// evidence item with a bad signature rejects the whole bundle — evidence
// is never silently downgraded.
//
// Evidence trust tiers (highest first):
//   3 counterparty-signed — submitted by one party and signed by the
//     other party (an admission against interest). A party-signed item
//     submitted by a third party is NOT tier 3 — the admission structure
//     requires the other party to be the submitter.
//   2 third-party-oracle-signed — signed by someone who is not a party.
//   1 self-signed — signed by the submitter themselves.
//   0 unsigned — no signature claim at all.
// Only verified evidence reaches the rules engine, and each claim type has
// a minimum tier (see MIN_TIER_FOR_CLAIM_TYPE). Items below the minimum
// are excluded from evaluation and recorded in the trace.

import { canonicalize, canonicalHashSync, CanonicalizationError } from "./jcs.js";
import { isDidKey } from "./did.js";
import { signJws, verifyJws, type Ed25519Jwk } from "./jws.js";
import { isMinorUnits } from "./money.js";

export type ClaimType =
  | "non-delivery"
  | "late-delivery"
  | "wrong-partial-delivery";

export const CLAIM_TYPES: ClaimType[] = [
  "non-delivery",
  "late-delivery",
  "wrong-partial-delivery",
];

/** Minimum evidence tier that may be admitted for each claim type. */
export const MIN_TIER_FOR_CLAIM_TYPE: Record<ClaimType, number> = {
  "non-delivery": 1,
  "late-delivery": 2,
  "wrong-partial-delivery": 2,
};

export type EvidenceTier = 0 | 1 | 2 | 3;

export const TIER_NAMES: Record<EvidenceTier, string> = {
  0: "unsigned",
  1: "self-signed",
  2: "third-party-oracle-signed",
  3: "counterparty-signed",
};

export interface TransactionRef {
  ref: string;
  currency: string;
  amount_minor: number;
  description?: string;
  agreed_delivery_at?: string | null;
}

export interface Claim {
  type: ClaimType;
  amount_minor: number;
  details: Record<string, unknown>;
}

export type EvidenceKind =
  | "delivery-proof"
  | "communication"
  | "oracle-attestation"
  | "payment-proof"
  | "condition-proof"
  | "other";

export interface EvidenceItem {
  id: string;
  kind: EvidenceKind;
  content?: string | null;
  sha256?: string | null;
  uri?: string | null;
  /** ISO-8601 timestamp the evidence asserts (e.g. delivery time). */
  delivered_at?: string | null;
  /** did:key claiming to have signed this item; must match the JWS kid. */
  signer?: string | null;
  /** Compact JWS over the canonical evidence payload (minus jws/signer). */
  jws?: string | null;
  /** did:key of the party who attached this item to the bundle. */
  submitted_by: string;
}

export interface BundlePayload {
  format: "agentarb-bundle";
  version: 1;
  id: string;
  created_at: string;
  claimant: string;
  respondent: string;
  transaction: TransactionRef;
  claims: Claim[];
  evidence: EvidenceItem[];
}

export interface BundleSignature {
  signer: string;
  jws: string;
}

export interface Bundle extends BundlePayload {
  signatures: BundleSignature[];
}

/** The exact object an evidence JWS signs (item minus jws/signer). */
export function evidenceSignPayload(
  item: EvidenceItem,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: item.id,
    kind: item.kind,
    submitted_by: item.submitted_by,
  };
  if (item.content != null) out.content = item.content;
  if (item.sha256 != null) out.sha256 = item.sha256;
  if (item.uri != null) out.uri = item.uri;
  if (item.delivered_at != null) out.delivered_at = item.delivered_at;
  return out;
}

export function bundlePayload(bundle: Bundle): BundlePayload {
  const {
    format,
    version,
    id,
    created_at,
    claimant,
    respondent,
    transaction,
    claims,
    evidence,
  } = bundle;
  return {
    format,
    version,
    id,
    created_at,
    claimant,
    respondent,
    transaction,
    claims,
    evidence,
  };
}

/** Content address of a bundle: SHA-256 of its canonical payload. */
export function bundleHash(bundle: Bundle): string {
  return canonicalHashSync(bundlePayload(bundle));
}

/** Append a signature by the given key to a bundle payload. */
export function signBundle(
  payload: BundlePayload,
  privateJwk: Ed25519Jwk,
): Bundle {
  const jws = signJws(payload as unknown as Record<string, unknown>, privateJwk);
  const verified = verifyJws(jws);
  const signer = verified.issuerDid as string;
  return { ...payload, signatures: [{ signer, jws }] };
}

/** Append an additional signature to an already-signed bundle. */
export function addBundleSignature(
  bundle: Bundle,
  privateJwk: Ed25519Jwk,
): Bundle {
  const jws = signJws(
    bundlePayload(bundle) as unknown as Record<string, unknown>,
    privateJwk,
  );
  const verified = verifyJws(jws);
  const signer = verified.issuerDid as string;
  if (bundle.signatures.some((s) => s.signer === signer)) {
    throw new Error(`bundle already signed by ${signer}`);
  }
  return { ...bundle, signatures: [...bundle.signatures, { signer, jws }] };
}

// ---------------------------------------------------------------- validation

function isIsoDate(s: unknown): s is string {
  return (
    typeof s === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/.test(s) &&
    !Number.isNaN(Date.parse(s))
  );
}

function isSha256Hex(s: unknown): s is string {
  return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
}

export function isHttpUrl(s: unknown): s is string {
  if (typeof s !== "string") return false;
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Structural validation of a bundle payload. Returns a list of error
 * strings; empty means valid. This is pure and dependency-free; the server
 * additionally enforces the same shape with JSON Schema (ajv).
 */
export function validateBundlePayload(
  payload: unknown,
): string[] {
  const errors: string[] = [];
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    return ["bundle payload must be an object"];
  }
  const p = payload as Record<string, unknown>;
  if (p.format !== "agentarb-bundle") errors.push("format must be 'agentarb-bundle'");
  if (p.version !== 1) errors.push("version must be 1");
  if (typeof p.id !== "string" || p.id.length === 0) errors.push("id must be a non-empty string");
  if (!isIsoDate(p.created_at)) errors.push("created_at must be an ISO-8601 timestamp");
  if (!isDidKey(p.claimant)) errors.push("claimant must be an Ed25519 did:key");
  if (!isDidKey(p.respondent)) errors.push("respondent must be an Ed25519 did:key");
  if (p.claimant === p.respondent) errors.push("claimant and respondent must differ");

  const tx = p.transaction as Record<string, unknown> | undefined;
  if (tx === null || typeof tx !== "object" || Array.isArray(tx)) {
    errors.push("transaction must be an object");
  } else {
    if (typeof tx.ref !== "string" || tx.ref.length === 0) errors.push("transaction.ref must be a non-empty string");
    if (typeof tx.currency !== "string" || !/^[A-Z]{3}$/.test(tx.currency)) {
      errors.push("transaction.currency must be a 3-letter uppercase code");
    }
    if (!isMinorUnits(tx.amount_minor)) errors.push("transaction.amount_minor must be a non-negative safe integer");
    if (tx.description !== undefined && typeof tx.description !== "string") {
      errors.push("transaction.description must be a string");
    }
    if (tx.agreed_delivery_at !== undefined && tx.agreed_delivery_at !== null && !isIsoDate(tx.agreed_delivery_at)) {
      errors.push("transaction.agreed_delivery_at must be an ISO-8601 timestamp or null");
    }
  }

  if (!Array.isArray(p.claims) || p.claims.length === 0) {
    errors.push("claims must be a non-empty array");
  } else {
    const txAmount = (tx as Record<string, unknown> | undefined)?.amount_minor;
    p.claims.forEach((c: unknown, i: number) => {
      const prefix = `claims[${i}]`;
      if (c === null || typeof c !== "object" || Array.isArray(c)) {
        errors.push(`${prefix} must be an object`);
        return;
      }
      const claim = c as Record<string, unknown>;
      if (!CLAIM_TYPES.includes(claim.type as ClaimType)) {
        errors.push(`${prefix}.type must be one of ${CLAIM_TYPES.join(", ")}`);
      }
      if (!isMinorUnits(claim.amount_minor)) {
        errors.push(`${prefix}.amount_minor must be a non-negative safe integer`);
      } else if (typeof txAmount === "number" && (claim.amount_minor as number) > txAmount) {
        errors.push(`${prefix}.amount_minor must not exceed transaction.amount_minor`);
      }
      if (claim.details === null || typeof claim.details !== "object" || Array.isArray(claim.details)) {
        errors.push(`${prefix}.details must be an object`);
      } else {
        const d = claim.details as Record<string, unknown>;
        if (claim.type === "late-delivery") {
          if (!isMinorUnits(d.penalty_minor)) {
            errors.push(`${prefix}.details.penalty_minor must be a non-negative safe integer`);
          } else if (
            typeof claim.amount_minor === "number" &&
            (d.penalty_minor as number) > (claim.amount_minor as number)
          ) {
            errors.push(`${prefix}.details.penalty_minor must not exceed claims[${i}].amount_minor`);
          }
        }
        if (claim.type === "wrong-partial-delivery") {
          const hasMissing = isMinorUnits(d.missing_minor);
          const frac = d.delivered_fraction as Record<string, unknown> | undefined;
          const hasFraction =
            frac !== null &&
            typeof frac === "object" &&
            !Array.isArray(frac) &&
            Number.isSafeInteger(frac.numerator) &&
            (frac.numerator as number) >= 0 &&
            Number.isSafeInteger(frac.denominator) &&
            (frac.denominator as number) > 0 &&
            (frac.numerator as number) <= (frac.denominator as number);
          if (!hasMissing && !hasFraction) {
            errors.push(`${prefix}.details must carry missing_minor or a valid delivered_fraction {numerator, denominator}`);
          }
          if (
            hasMissing &&
            typeof claim.amount_minor === "number" &&
            (d.missing_minor as number) > (claim.amount_minor as number)
          ) {
            errors.push(`${prefix}.details.missing_minor must not exceed claims[${i}].amount_minor`);
          }
        }
      }
    });
    // Cap the SUM of claims at the transaction amount, not just each claim
    // individually: two claims on contradictory theories of the same loss
    // (e.g. non-delivery refund_full plus wrong-partial refund_partial)
    // must never pay out more than the transaction itself.
    if (typeof txAmount === "number") {
      let sum = 0;
      let allAmountsValid = true;
      for (const c of p.claims as unknown[]) {
        if (
          c !== null &&
          typeof c === "object" &&
          !Array.isArray(c) &&
          isMinorUnits((c as Record<string, unknown>).amount_minor)
        ) {
          sum += (c as Record<string, unknown>).amount_minor as number;
        } else {
          allAmountsValid = false;
        }
      }
      if (allAmountsValid && sum > txAmount) {
        errors.push(
          `sum of claim amounts (${sum}) must not exceed transaction.amount_minor (${txAmount})`,
        );
      }
    }
  }

  if (!Array.isArray(p.evidence)) {
    errors.push("evidence must be an array");
  } else {
    const seen = new Set<string>();
    p.evidence.forEach((e: unknown, i: number) => {
      const prefix = `evidence[${i}]`;
      if (e === null || typeof e !== "object" || Array.isArray(e)) {
        errors.push(`${prefix} must be an object`);
        return;
      }
      const item = e as Record<string, unknown>;
      if (typeof item.id !== "string" || item.id.length === 0) {
        errors.push(`${prefix}.id must be a non-empty string`);
      } else if (seen.has(item.id)) {
        errors.push(`${prefix}.id duplicates an earlier evidence id`);
      } else {
        seen.add(item.id);
      }
      const kinds = ["delivery-proof", "communication", "oracle-attestation", "payment-proof", "condition-proof", "other"];
      if (!kinds.includes(item.kind as string)) {
        errors.push(`${prefix}.kind must be one of ${kinds.join(", ")}`);
      }
      if (item.content == null && item.sha256 == null && item.uri == null) {
        errors.push(`${prefix} must carry at least one of content, sha256, uri`);
      }
      if (item.content !== undefined && item.content !== null && typeof item.content !== "string") {
        errors.push(`${prefix}.content must be a string`);
      }
      if (item.sha256 !== undefined && item.sha256 !== null && !isSha256Hex(item.sha256)) {
        errors.push(`${prefix}.sha256 must be a 64-hex-character digest`);
      }
      if (item.uri !== undefined && item.uri !== null && !isHttpUrl(item.uri)) {
        errors.push(`${prefix}.uri must be an http(s) URL`);
      }
      if (item.delivered_at !== undefined && item.delivered_at !== null && !isIsoDate(item.delivered_at)) {
        errors.push(`${prefix}.delivered_at must be an ISO-8601 timestamp or null`);
      }
      if (item.signer !== undefined && item.signer !== null && !isDidKey(item.signer)) {
        errors.push(`${prefix}.signer must be an Ed25519 did:key`);
      }
      if (item.jws !== undefined && item.jws !== null && typeof item.jws !== "string") {
        errors.push(`${prefix}.jws must be a string`);
      }
      if ((item.signer == null) !== (item.jws == null)) {
        errors.push(`${prefix} must carry both signer and jws, or neither`);
      }
      if (!isDidKey(item.submitted_by)) {
        errors.push(`${prefix}.submitted_by must be an Ed25519 did:key`);
      }
    });
  }
  return errors;
}

// ---------------------------------------------------------------- verification

export interface EvidenceVerification {
  ok: boolean;
  errors: string[];
  tier: EvidenceTier | null;
  tierName: string | null;
}

/**
 * Verify a single evidence item: signature validity, signer agreement,
 * and tier computation. Used by verifyBundle and by the server's
 * add-evidence endpoint so both paths agree exactly.
 */
export function verifyEvidenceItem(
  item: EvidenceItem,
  claimant: string,
  respondent: string,
): EvidenceVerification {
  if (item.jws == null) {
    return { ok: true, errors: [], tier: 0, tierName: TIER_NAMES[0] };
  }
  if (item.signer == null) {
    return {
      ok: false,
      errors: [`evidence ${item.id}: jws present without a signer`],
      tier: null,
      tierName: null,
    };
  }
  const v = verifyJws(item.jws, item.signer);
  if (!v.ok) {
    return {
      ok: false,
      errors: [`evidence ${item.id}: signature invalid (${v.reason})`],
      tier: null,
      tierName: null,
    };
  }
  let covers: boolean;
  try {
    covers = canonicalize(v.payload) === canonicalize(evidenceSignPayload(item));
  } catch (e) {
    if (e instanceof CanonicalizationError || e instanceof RangeError) {
      return {
        ok: false,
        errors: [`evidence ${item.id}: item cannot be canonicalized (${(e as Error).message})`],
        tier: null,
        tierName: null,
      };
    }
    throw e;
  }
  if (!covers) {
    return {
      ok: false,
      errors: [`evidence ${item.id}: signature does not cover this item`],
      tier: null,
      tierName: null,
    };
  }  const signer = item.signer;
  let tier: EvidenceTier;
  if (signer === item.submitted_by) {
    tier = 1;
  } else if (
    (item.submitted_by === claimant && signer === respondent) ||
    (item.submitted_by === respondent && signer === claimant)
  ) {
    // Tier 3 requires the admission structure: one party submits, the
    // other party signed. A party-signed item submitted by a third party
    // is tier 2 — independently signed, but not an admission.
    tier = 3;
  } else {
    tier = 2;
  }
  return { ok: true, errors: [], tier, tierName: TIER_NAMES[tier] };
}

export interface VerifiedEvidence {
  item: EvidenceItem;
  tier: EvidenceTier;
  tierName: string;
}

export interface BundleVerification {
  ok: boolean;
  errors: string[];
  hash: string | null;
  signers: string[];
  evidence: VerifiedEvidence[];
}

/**
 * Full bundle verification: structure, envelope signatures (each JWS must
 * sign exactly this payload, and the claimant must have signed when
 * requireClaimantSignature is set), and per-item evidence signatures.
 * An evidence item with a bad signature fails the whole bundle — it is
 * never silently downgraded to unsigned.
 */
export function verifyBundle(
  bundle: unknown,
  opts: { requireClaimantSignature?: boolean } = {},
): BundleVerification {
  const requireClaimantSignature = opts.requireClaimantSignature !== false;
  const errors: string[] = [];
  if (bundle === null || typeof bundle !== "object" || Array.isArray(bundle)) {
    return { ok: false, errors: ["bundle must be an object"], hash: null, signers: [], evidence: [] };
  }
  const b = bundle as Bundle;
  errors.push(...validateBundlePayload(bundlePayload(b)));
  if (!Array.isArray(b.signatures) || b.signatures.length === 0) {
    errors.push("signatures must be a non-empty array");
  }
  const payload = bundlePayload(b);
  let expectedCanonical: string;
  try {
    expectedCanonical = canonicalize(payload);
  } catch (e) {
    if (e instanceof CanonicalizationError || e instanceof RangeError) {
      return {
        ok: false,
        errors: [`bundle payload cannot be canonicalized (${(e as Error).message})`],
        hash: null,
        signers: [],
        evidence: [],
      };
    }
    throw e;
  }
  const signers: string[] = [];
  if (Array.isArray(b.signatures)) {
    for (let i = 0; i < b.signatures.length; i++) {
      const sig = b.signatures[i] as BundleSignature;
      if (!sig || typeof sig.jws !== "string" || !isDidKey(sig.signer)) {
        errors.push(`signatures[${i}] must carry a did:key signer and a JWS string`);
        continue;
      }
      const v = verifyJws(sig.jws, sig.signer);
      if (!v.ok) {
        errors.push(`signatures[${i}] (${sig.signer}): ${v.reason}`);
        continue;
      }
      let covers: boolean;
      try {
        covers = canonicalize(v.payload) === expectedCanonical;
      } catch (e) {
        if (e instanceof CanonicalizationError || e instanceof RangeError) {
          errors.push(`signatures[${i}] cannot be canonicalized (${(e as Error).message})`);
          continue;
        }
        throw e;
      }
      if (!covers) {
        errors.push(`signatures[${i}] does not sign this bundle payload`);
        continue;
      }
      signers.push(sig.signer);
    }
  }
  if (
    requireClaimantSignature &&
    typeof b.claimant === "string" &&
    !signers.includes(b.claimant)
  ) {
    errors.push("claimant has not signed the bundle");
  }

  const evidence: VerifiedEvidence[] = [];
  if (Array.isArray(b.evidence)) {
    for (const item of b.evidence) {
      const v = verifyEvidenceItem(item, b.claimant, b.respondent);
      if (!v.ok) {
        errors.push(...v.errors);
        continue;
      }
      evidence.push({
        item,
        tier: v.tier as EvidenceTier,
        tierName: v.tierName as string,
      });
    }
  }
  if (errors.length > 0) {
    return { ok: false, errors, hash: null, signers, evidence: [] };
  }
  return { ok: true, errors: [], hash: bundleHash(b), signers, evidence };
}

/**
 * Split verified evidence for one claim type into admitted (>= min tier)
 * and excluded items, with reasons. Only admitted evidence reaches the
 * rules engine.
 */
export function filterEvidenceForClaim(
  verified: VerifiedEvidence[],
  claimType: ClaimType,
): {
  admitted: VerifiedEvidence[];
  excluded: Array<{ id: string; tier: EvidenceTier; reason: string }>;
} {
  const min = MIN_TIER_FOR_CLAIM_TYPE[claimType];
  const admitted: VerifiedEvidence[] = [];
  const excluded: Array<{ id: string; tier: EvidenceTier; reason: string }> = [];
  for (const v of verified) {
    if (v.tier >= min) {
      admitted.push(v);
    } else {
      excluded.push({
        id: v.item.id,
        tier: v.tier,
        reason: `tier ${v.tier} (${v.tierName}) below minimum ${min} for ${claimType}`,
      });
    }
  }
  return { admitted, excluded };
}
