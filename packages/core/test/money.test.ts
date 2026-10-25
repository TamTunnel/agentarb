import test from "node:test";
import assert from "node:assert/strict";
import {
  isMinorUnits,
  rationalSplit,
  refundForDeliveredFraction,
} from "../dist/index.js";

test("money: minor-unit validation", () => {
  assert.equal(isMinorUnits(0), true);
  assert.equal(isMinorUnits(100), true);
  assert.equal(isMinorUnits(10.5), false);
  assert.equal(isMinorUnits(-1), false);
  assert.equal(isMinorUnits(Number.MAX_SAFE_INTEGER + 1), false);
  assert.equal(isMinorUnits("100"), false);
});

test("money: rational split floors with explicit remainder", () => {
  const { share, remainder } = rationalSplit(10000, 3, 4);
  assert.equal(share, 7500);
  assert.equal(remainder, 2500);
  assert.equal(share + remainder, 10000);
});

test("money: odd splits never lose a unit", () => {
  const { share, remainder } = rationalSplit(100, 1, 3);
  assert.equal(share, 33);
  assert.equal(remainder, 67);
  assert.equal(share + remainder, 100);
});

test("money: refund for delivered fraction", () => {
  assert.equal(refundForDeliveredFraction(10000, 3, 4), 2500);
  assert.equal(refundForDeliveredFraction(10000, 1, 1), 0);
  assert.equal(refundForDeliveredFraction(10000, 0, 4), 10000);
});

test("money: invalid splits throw", () => {
  assert.throws(() => rationalSplit(100, 1, 0), /denominator/);
  assert.throws(() => rationalSplit(100, 5, 4), /numerator/);
  assert.throws(() => rationalSplit(100.5, 1, 2), /minor/);
  assert.throws(() => rationalSplit(-5, 1, 2), /minor/);
});
