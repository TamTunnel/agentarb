// packages/core/src/jws.ts
//
// Stateless Ed25519 compact JWS, following the exact profile audited in
// @tamtunnel/si-wallet-core: header {"alg":"EdDSA","typ":"JWT","kid"},
// kid "<did:key>#key-1", strict canonical base64url segments, signature over
// ASCII "header.payload". Difference from si-wallet-core: no keystore —
// keypairs are caller-supplied JWKs, and payloads MUST be canonical (JCS)
// JSON: verification recomputes the canonical form and requires byte
// equality with the encoded payload segment, so a signer cannot smuggle in
// a non-canonical encoding that verifies but hashes differently.

import crypto from "node:crypto";
import { canonicalize } from "./jcs.js";
import {
  didFromRawPublicKey,
  isDidKey,
  rawPublicKeyFromDid,
} from "./did.js";

export class JwsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JwsError";
  }
}

export interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  d?: string;
}

export interface Keypair {
  did: string;
  privateJwk: Ed25519Jwk;
  publicJwk: Ed25519Jwk;
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function base64urlEncode(v: string | Buffer): string {
  return (Buffer.isBuffer(v) ? v : Buffer.from(v, "utf8")).toString(
    "base64url",
  );
}

/** Strict base64url: decode, re-encode canonically, require exact match. */
export function base64urlDecodeStrict(s: string): Buffer {
  if (typeof s !== "string" || s.length === 0 || /[^A-Za-z0-9_-]/.test(s)) {
    throw new JwsError("not canonical base64url");
  }
  const buf = Buffer.from(s, "base64url");
  if (buf.toString("base64url") !== s) {
    throw new JwsError("not canonical base64url");
  }
  return buf;
}

/** Fresh random Ed25519 keypair with its did:key. */
export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Ed25519Jwk;
  const privateJwk = privateKey.export({
    format: "jwk",
  }) as unknown as Ed25519Jwk;
  const did = didFromRawPublicKey(
    Buffer.from(publicJwk.x, "base64url"),
  );
  return { did, privateJwk, publicJwk };
}

/** Deterministic keypair from a 32-byte seed (tests, fixtures). */
export function keypairFromSeed(seed32: Buffer): Keypair {
  if (!Buffer.isBuffer(seed32) || seed32.length !== 32) {
    throw new JwsError("seed must be 32 bytes");
  }
  // Ed25519 private key as PKCS#8 DER: prefix + raw seed.
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    seed32,
  ]);
  const privateKey = crypto.createPrivateKey({
    key: der,
    format: "der",
    type: "pkcs8",
  });
  const publicKey = crypto.createPublicKey(privateKey);
  const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Ed25519Jwk;
  const privateJwk = privateKey.export({
    format: "jwk",
  }) as unknown as Ed25519Jwk;
  const did = didFromRawPublicKey(Buffer.from(publicJwk.x, "base64url"));
  return { did, privateJwk, publicJwk };
}

export function didFromPrivateJwk(jwk: Ed25519Jwk): string {
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d) {
    throw new JwsError("not an Ed25519 private JWK");
  }
  const privateKey = crypto.createPrivateKey({ key: jwk as unknown as crypto.JsonWebKey, format: "jwk" });
  const publicKey = crypto.createPublicKey(privateKey);
  const publicJwk = publicKey.export({ format: "jwk" }) as unknown as Ed25519Jwk;
  return didFromRawPublicKey(Buffer.from(publicJwk.x, "base64url"));
}

export function privateKeyObjectFromJwk(jwk: Ed25519Jwk): crypto.KeyObject {
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d) {
    throw new JwsError("not an Ed25519 private JWK");
  }
  return crypto.createPrivateKey({ key: jwk as unknown as crypto.JsonWebKey, format: "jwk" });
}

export function publicKeyObjectFromDid(did: string): crypto.KeyObject {
  const raw = rawPublicKeyFromDid(did);
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

/**
 * Sign a JSON payload. The payload is encoded as canonical (JCS) JSON, so
 * verifiers can enforce byte equality. Returns the compact JWS.
 */
export function signJws(
  payload: Record<string, unknown>,
  privateJwk: Ed25519Jwk,
): string {
  const did = didFromPrivateJwk(privateJwk);
  const h = base64urlEncode(
    JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: did + "#key-1" }),
  );
  const p = base64urlEncode(canonicalize(payload));
  const sig = crypto.sign(
    null,
    Buffer.from(h + "." + p),
    privateKeyObjectFromJwk(privateJwk),
  );
  return `${h}.${p}.${base64urlEncode(sig)}`;
}

export interface VerifiedJws {
  ok: boolean;
  reason?: string;
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
  issuerDid?: string;
}

/**
 * Verify a compact JWS. Checks: 3 parts, strict base64url, alg EdDSA,
 * kid resolves to an Ed25519 did:key, signature valid, and the payload
 * segment is exactly the canonical form of the decoded payload.
 * When expectedDid is given, the kid DID must equal it. Never throws —
 * failures are returned as { ok: false, reason }.
 */
export function verifyJws(
  jws: string,
  expectedDid?: string,
): VerifiedJws {
  try {
    const parts = (jws || "").split(".");
    if (parts.length !== 3) {
      return { ok: false, reason: "malformed JWS (want 3 parts)" };
    }
    const [h, p, s] = parts;
    let header: Record<string, unknown>;
    let payload: Record<string, unknown>;
    try {
      header = JSON.parse(base64urlDecodeStrict(h).toString("utf8"));
      payload = JSON.parse(base64urlDecodeStrict(p).toString("utf8"));
    } catch {
      return {
        ok: false,
        reason: "JWS header/payload is not valid base64url JSON",
      };
    }
    if (header === null || typeof header !== "object" || Array.isArray(header)) {
      return { ok: false, reason: "JWS header is not an object" };
    }
    if (
      payload === null ||
      typeof payload !== "object" ||
      Array.isArray(payload)
    ) {
      return { ok: false, reason: "JWS payload is not an object" };
    }
    if (header.alg !== "EdDSA") {
      return { ok: false, reason: `unsupported alg ${header.alg}` };
    }
    const kidDid = String(header.kid || "").split("#")[0];
    if (!isDidKey(kidDid)) {
      return { ok: false, reason: "kid does not resolve to an Ed25519 did:key" };
    }
    if (expectedDid && kidDid !== expectedDid) {
      return { ok: false, reason: "kid does not match expected issuer DID" };
    }
    // Canonical-payload enforcement: the encoded segment must be exactly
    // the canonical form of the decoded payload.
    let canonicalSegment: string;
    try {
      canonicalSegment = base64urlEncode(canonicalize(payload));
    } catch {
      return { ok: false, reason: "payload is not canonicalizable JSON" };
    }
    if (canonicalSegment !== p) {
      return { ok: false, reason: "payload segment is not canonical JSON" };
    }
    let pub: crypto.KeyObject;
    try {
      pub = publicKeyObjectFromDid(kidDid);
    } catch (e) {
      return {
        ok: false,
        reason: "cannot resolve issuer did:key: " + (e as Error).message,
      };
    }
    const sigOk = crypto.verify(
      null,
      Buffer.from(h + "." + p),
      pub,
      base64urlDecodeStrict(s),
    );
    if (!sigOk) return { ok: false, reason: "signature invalid" };
    return { ok: true, header, payload, issuerDid: kidDid };
  } catch (e) {
    return { ok: false, reason: "verification error: " + (e as Error).message };
  }
}
