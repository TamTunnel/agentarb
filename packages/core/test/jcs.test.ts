import test from "node:test";
import assert from "node:assert/strict";
import { canonicalize, canonicalHashSync } from "../dist/index.js";

test("jcs: sorts keys recursively", () => {
  assert.equal(
    canonicalize({ b: 1, a: { d: 2, c: 3 } }),
    '{"a":{"c":3,"d":2},"b":1}',
  );
});

test("jcs: array order preserved", () => {
  assert.equal(canonicalize({ a: [3, 2, 1] }), '{"a":[3,2,1]}');
});

test("jcs: number serialization follows ECMAScript rules", () => {
  assert.equal(canonicalize({ n: 1e30 }), '{"n":1e+30}');
  assert.equal(canonicalize({ n: 0.004 }), '{"n":0.004}');
  assert.equal(canonicalize({ n: -0 }), '{"n":0}');
  assert.equal(canonicalize({ n: 333333333.33333329 }), '{"n":333333333.3333333}');
});

test("jcs: string escaping matches RFC 8785", () => {
  // Quote, backslash, and control chars escaped; DEL and non-ASCII raw.
  assert.equal(
    canonicalize({ s: 'a"b\\c\n\t\x01\x7fé' }),
    '{"s":"a\\"b\\\\c\\n\\t\\u0001\x7fé"}',
  );
});

test("jcs: unicode keys sort by UTF-16 code units", () => {
  assert.equal(
    canonicalize({ b: 1, a: 2, é: 3, e: 4 }),
    '{"a":2,"b":1,"e":4,"é":3}',
  );
});

test("jcs: rejects non-JSON values instead of coercing", () => {
  assert.throws(() => canonicalize({ n: Infinity }), /non-finite/);
  assert.throws(() => canonicalize({ n: NaN }), /non-finite/);
  assert.throws(() => canonicalize({ f: () => 1 }), /cannot canonicalize/);
  assert.throws(() => canonicalize({ u: undefined }), /cannot canonicalize/);
  assert.throws(() => canonicalize({ b: 10n }), /cannot canonicalize/);
});

test("jcs: hash is deterministic and content-sensitive", () => {
  const a = canonicalHashSync({ b: 1, a: 2 });
  const b = canonicalHashSync({ a: 2, b: 1 });
  const c = canonicalHashSync({ a: 2, b: 3 });
  assert.equal(a, b);
  assert.notEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test("jcs: nesting beyond the depth limit throws CanonicalizationError", () => {
  let deep: Record<string, unknown> = {};
  let cursor = deep;
  for (let i = 0; i < 2000; i++) {
    const next: Record<string, unknown> = {};
    cursor.nested = next;
    cursor = next;
  }
  assert.throws(() => canonicalize(deep), /maximum depth/);
  // Just under the limit still works.
  let shallow: Record<string, unknown> = {};
  cursor = shallow;
  for (let i = 0; i < 50; i++) {
    const next: Record<string, unknown> = {};
    cursor.nested = next;
    cursor = next;
  }
  assert.equal(typeof canonicalize(shallow), "string");
});
