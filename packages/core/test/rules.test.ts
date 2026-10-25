import test from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../dist/index.js";

test("rules: var with dotted paths and defaults", () => {
  assert.equal(evaluate({ var: "a.b" }, { a: { b: 42 } }), 42);
  assert.equal(evaluate({ var: "a.missing" }, { a: {} }), null);
  assert.equal(evaluate({ var: ["a.missing", 7] }, { a: {} }), 7);
  assert.equal(evaluate({ var: "arr.1" }, { arr: [10, 20] }), 20);
});

test("rules: comparisons and boolean combinators", () => {
  assert.equal(evaluate({ "==": [1, 1] }, {}), true);
  assert.equal(evaluate({ "==": [1, "1"] }, {}), true); // JSONLogic loose ==
  assert.equal(evaluate({ "===": [1, "1"] }, {}), false);
  assert.equal(evaluate({ and: [true, 5] }, {}), 5);
  assert.equal(evaluate({ and: [true, 0] }, {}), 0);
  assert.equal(evaluate({ or: [0, "x"] }, {}), "x");
  assert.equal(evaluate({ "!": [0] }, {}), true);
  assert.equal(evaluate({ "!!": [""] }, {}), false);
});

test("rules: if with else", () => {
  assert.equal(evaluate({ if: [false, 1, true, 2, 3] }, {}), 2);
  assert.equal(evaluate({ if: [false, 1, false, 2, 3] }, {}), 3);
  assert.equal(evaluate({ if: [false, 1] }, {}), null);
});

test("rules: in, missing", () => {
  assert.equal(evaluate({ in: ["ell", "hello"] }, {}), true);
  assert.equal(evaluate({ in: [2, [1, 2, 3]] }, {}), true);
  assert.deepEqual(evaluate({ missing: ["a", "b"] }, { a: 1 }), ["b"]);
});

test("rules: filter, map, all, some, none", () => {
  const data = { items: [{ t: 1 }, { t: 3 }, { t: 5 }] };
  assert.deepEqual(
    evaluate({ filter: [{ var: "items" }, { ">": [{ var: "t" }, 2] }] }, data),
    [{ t: 3 }, { t: 5 }],
  );
  assert.deepEqual(
    evaluate({ map: [{ var: "items" }, { var: "t" }] }, data),
    [1, 3, 5],
  );
  assert.equal(
    evaluate({ all: [{ var: "items" }, { ">": [{ var: "t" }, 0] }] }, data),
    true,
  );
  assert.equal(
    evaluate({ some: [{ var: "items" }, { "==": [{ var: "t" }, 3] }] }, data),
    true,
  );
  assert.equal(
    evaluate({ none: [{ var: "items" }, { "==": [{ var: "t" }, 9] }] }, data),
    true,
  );
  assert.equal(evaluate({ all: [[], { var: "x" }] }, {}), true);
  assert.equal(evaluate({ some: [[], { var: "x" }] }, {}), false);
});

test("rules: arithmetic and fail-closed errors", () => {
  assert.equal(evaluate({ "+": [1, 2, 3] }, {}), 6);
  assert.equal(evaluate({ "-": [10, 4] }, {}), 6);
  assert.equal(evaluate({ "*": [3, 4] }, {}), 12);
  assert.equal(evaluate({ "/": [10, 4] }, {}), 2.5);
  assert.throws(() => evaluate({ "/": [1, 0] }, {}), /division by zero/);
  assert.throws(() => evaluate({ "%": [1, 0] }, {}), /division by zero/);
  assert.throws(() => evaluate({ unknown_op: [1] }, {}), /unknown operation/);
  assert.throws(() => evaluate({ a: 1, b: 2 }, {}), /exactly one operation/);
});

test("rules: rule objects are data — no code execution surface", () => {
  // A rule mentioning process/global must not resolve to anything real.
  assert.equal(evaluate({ var: "process.env" }, {}), null);
  assert.equal(
    evaluate({ "==": [{ var: "constructor" }, "x"] }, {}),
    false,
  );
});

test("rules: nesting beyond the depth limit throws RuleError", () => {
  let deep: Record<string, unknown> = { var: "x" };
  for (let i = 0; i < 2000; i++) {
    deep = { and: [deep] };
  }
  assert.throws(() => evaluate(deep, { x: true }), /maximum nesting depth/);
});
