// packages/core/src/did.ts
//
// Ed25519 did:key handling. The encoding is the multicodec form audited in
// @tamtunnel/si-wallet-core (0xed 0x01 prefix + 32-byte raw public key,
// base58btc, "did:key:z" prefix). This module is stateless: it never touches
// a keystore — keypairs are passed in as JWKs by the caller.

const B58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export class DidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DidError";
  }
}

export function base58Encode(buf: Buffer): string {
  let n = 0n;
  for (const b of buf) n = (n << 8n) + BigInt(b);
  let s = "";
  while (n > 0n) {
    s = B58_ALPHABET[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of buf) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s || "1";
}

export function base58Decode(str: string): Buffer {
  let n = 0n;
  for (const c of str) {
    const i = B58_ALPHABET.indexOf(c);
    if (i < 0) throw new DidError("invalid base58 character");
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  for (const c of str) {
    if (c !== "1") break;
    zeros++;
  }
  return Buffer.concat([Buffer.alloc(zeros), Buffer.from(bytes)]);
}

const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);

/** did:key for a 32-byte raw Ed25519 public key. */
export function didFromRawPublicKey(raw32: Buffer): string {
  if (!Buffer.isBuffer(raw32) || raw32.length !== 32) {
    throw new DidError("Ed25519 public key must be 32 bytes");
  }
  return (
    "did:key:z" +
    base58Encode(Buffer.concat([ED25519_MULTICODEC_PREFIX, raw32]))
  );
}

/** Raw 32-byte Ed25519 public key for a did:key. Throws on malformed input. */
export function rawPublicKeyFromDid(did: string): Buffer {
  const m = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did || "");
  if (!m) throw new DidError(`malformed did:key: ${did}`);
  const raw = base58Decode(m[1]);
  if (
    raw.length !== 34 ||
    raw[0] !== ED25519_MULTICODEC_PREFIX[0] ||
    raw[1] !== ED25519_MULTICODEC_PREFIX[1]
  ) {
    throw new DidError("did:key is not an Ed25519 key");
  }
  return raw.subarray(2);
}

/** True when the string parses as an Ed25519 did:key. Never throws. */
export function isDidKey(did: unknown): did is string {
  if (typeof did !== "string") return false;
  try {
    rawPublicKeyFromDid(did);
    return true;
  } catch {
    return false;
  }
}
