import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  base58Decode,
  base58Encode,
  didFromRawPublicKey,
  generateKeypair,
  isDidKey,
  keypairFromSeed,
  rawPublicKeyFromDid,
  signJws,
  verifyJws,
} from "../dist/index.js";

test("did: base58 round-trips including leading zeros", () => {
  const buf = Buffer.from([0, 0, 1, 2, 3, 255]);
  assert.deepEqual(base58Decode(base58Encode(buf)), buf);
});

test("did: key round-trip and malformed rejection", () => {
  const kp = generateKeypair();
  assert.ok(isDidKey(kp.did));
  assert.deepEqual(
    didFromRawPublicKey(rawPublicKeyFromDid(kp.did)),
    kp.did,
  );
  assert.ok(!isDidKey("did:key:znotbase58!!"));
  assert.ok(!isDidKey("did:example:123"));
  assert.ok(!isDidKey(42));
});

test("did: seeded keypairs are deterministic", () => {
  const a = keypairFromSeed(Buffer.alloc(32, 9));
  const b = keypairFromSeed(Buffer.alloc(32, 9));
  const c = keypairFromSeed(Buffer.alloc(32, 10));
  assert.equal(a.did, b.did);
  assert.notEqual(a.did, c.did);
});

test("jws: sign and verify round-trip", () => {
  const kp = generateKeypair();
  const jws = signJws({ hello: "world", n: 1 }, kp.privateJwk);
  const v = verifyJws(jws, kp.did);
  assert.equal(v.ok, true);
  assert.equal(v.issuerDid, kp.did);
  assert.deepEqual(v.payload, { hello: "world", n: 1 });
});

test("jws: tampered payload fails", () => {
  const kp = generateKeypair();
  const jws = signJws({ a: 1 }, kp.privateJwk);
  const [h, p, s] = jws.split(".");
  const tampered = [h, Buffer.from('{"a":2}').toString("base64url"), s].join(".");
  assert.equal(verifyJws(tampered).ok, false);
});

test("jws: non-canonical payload segment fails even with a valid signature", () => {
  // Forge by hand: sign the non-canonical bytes '{"a": 1}' (with a space)
  // with a valid key. The signature is cryptographically valid, but the
  // payload segment is not the canonical form, so verification must fail.
  const kp = generateKeypair();
  const h = Buffer.from(
    JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: kp.did + "#key-1" }),
  ).toString("base64url");
  const p = Buffer.from('{"a": 1}', "utf8").toString("base64url");
  const sig = crypto
    .sign(null, Buffer.from(h + "." + p), crypto.createPrivateKey({ key: kp.privateJwk, format: "jwk" }))
    .toString("base64url");
  const v = verifyJws(`${h}.${p}.${sig}`);
  assert.equal(v.ok, false);
  assert.match(v.reason || "", /not canonical/);
});

test("jws: wrong expected DID fails", () => {
  const kp = generateKeypair();
  const other = generateKeypair();
  const jws = signJws({ a: 1 }, kp.privateJwk);
  assert.equal(verifyJws(jws, other.did).ok, false);
  assert.equal(verifyJws(jws, kp.did).ok, true);
});

test("jws: malformed inputs fail, never throw", () => {
  assert.equal(verifyJws("").ok, false);
  assert.equal(verifyJws("a.b").ok, false);
  assert.equal(verifyJws("a.b.c.d").ok, false);
  assert.equal(verifyJws("!!!.@@@.###").ok, false);
});

test("jws: non-EdDSA alg rejected", () => {
  const kp = generateKeypair();
  const jws = signJws({ a: 1 }, kp.privateJwk);
  const [h, p, s] = jws.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8"));
  header.alg = "ES256";
  const forged = [
    Buffer.from(JSON.stringify(header)).toString("base64url"),
    p,
    s,
  ].join(".");
  const v = verifyJws(forged);
  assert.equal(v.ok, false);
  assert.match(v.reason || "", /unsupported alg/);
});
