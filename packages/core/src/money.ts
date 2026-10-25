// packages/core/src/money.ts
//
// Integer-only money math. Amounts are ALWAYS integer minor units
// (cents, satoshis, wei-fractions — never floats). Any computation that
// could produce a fraction uses BigInt rationals with an explicit remainder
// policy, so verdicts are deterministic and auditable.

export class MoneyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MoneyError";
  }
}

/** True for a safe non-negative integer (a valid minor-unit amount). */
export function isMinorUnits(n: unknown): n is number {
  return (
    typeof n === "number" &&
    Number.isSafeInteger(n) &&
    n >= 0
  );
}

export function assertMinorUnits(n: unknown, field: string): number {
  if (!isMinorUnits(n)) {
    throw new MoneyError(`${field} must be a non-negative safe integer (minor units), got ${String(n)}`);
  }
  return n;
}

/**
 * Rational split: share = floor(total * numerator / denominator).
 * Returns { share, remainder } where share + remainder = total.
 * Remainder stays with the payer by default — callers must say where it
 * goes. Throws on denominator 0, numerator > denominator, or unsafe input.
 */
export function rationalSplit(
  totalMinor: number,
  numerator: number,
  denominator: number,
): { share: number; remainder: number } {
  assertMinorUnits(totalMinor, "totalMinor");
  if (!Number.isSafeInteger(numerator) || numerator < 0) {
    throw new MoneyError("numerator must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(denominator) || denominator <= 0) {
    throw new MoneyError("denominator must be a positive safe integer");
  }
  if (numerator > denominator) {
    throw new MoneyError("numerator must not exceed denominator");
  }
  const total = BigInt(totalMinor);
  const share = (total * BigInt(numerator)) / BigInt(denominator);
  const shareNum = Number(share);
  if (!Number.isSafeInteger(shareNum)) {
    throw new MoneyError("split result is not a safe integer");
  }
  return { share: shareNum, remainder: totalMinor - shareNum };
}

/**
 * Refund for a delivered fraction: the buyer keeps the delivered share,
 * the refund is the rest. fraction = { numerator, denominator } of the
 * transaction that WAS delivered. Returns the refund amount.
 */
export function refundForDeliveredFraction(
  totalMinor: number,
  numerator: number,
  denominator: number,
): number {
  const { remainder } = rationalSplit(totalMinor, numerator, denominator);
  return remainder;
}
