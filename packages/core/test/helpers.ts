// packages/core/test/helpers.ts
//
// Shared fixtures for core tests. Deterministic keypairs from seeds so
// test output is reproducible.

import {
  keypairFromSeed,
  signJws,
  evidenceSignPayload,
  signBundle,
  addBundleSignature,
  type Bundle,
  type BundlePayload,
  type Claim,
  type EvidenceItem,
  type Keypair,
} from "../dist/index.js";

export function party(seedByte: number): Keypair {
  return keypairFromSeed(Buffer.alloc(32, seedByte));
}

export function basePayload(overrides: Partial<BundlePayload> = {}): BundlePayload {
  const claimant = party(1).did;
  const respondent = party(2).did;
  return {
    format: "agentarb-bundle",
    version: 1,
    id: "bundle-1",
    created_at: "2026-10-20T00:00:00Z",
    claimant,
    respondent,
    transaction: {
      ref: "tx-100",
      currency: "USD",
      amount_minor: 10000,
      description: "Example agent task",
      agreed_delivery_at: "2026-10-01T00:00:00Z",
    },
    claims: [
      {
        type: "non-delivery",
        amount_minor: 10000,
        details: {},
      } as Claim,
    ],
    evidence: [],
    ...overrides,
  };
}

export function signedBundle(
  payload: BundlePayload,
  signers: Keypair[] = [party(1)],
): Bundle {
  let bundle = signBundle(payload, signers[0].privateJwk);
  for (const kp of signers.slice(1)) {
    bundle = addBundleSignature(bundle, kp.privateJwk);
  }
  return bundle;
}

/** Evidence item signed by `signer`, submitted by `submitter`. */
export function signedEvidence(
  item: Omit<EvidenceItem, "signer" | "jws">,
  signer: Keypair,
): EvidenceItem {
  const bare = { ...item, signer: null, jws: null } as EvidenceItem;
  const jws = signJws(evidenceSignPayload(bare), signer.privateJwk);
  return { ...item, signer: signer.did, jws };
}
