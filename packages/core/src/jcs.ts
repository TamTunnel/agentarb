// packages/core/src/jcs.ts
//
// Pinned RFC 8785 (JSON Canonicalization Scheme) implementation.

import { createHash } from "node:crypto";
//
// Why vendored here instead of imported: @tamtunnel/si-wallet-core keeps its
// canonicalizer private (not exported as a standalone API), and core is
// zero-dependency by design. This implementation follows RFC 8785 exactly for
// JSON inputs:
//
//  - Objects: keys sorted by UTF-16 code units (JS default string sort),
//    no whitespace.
//  - Numbers: ECMAScript Number::toString — which is what JSON.stringify
//    already produces, including 1e30 -> "1e+30" and -0 -> "0".
//  - Strings: JSON.stringify escaping matches RFC 8785 §3.2.3 (escapes `"`,
//    `\`, and U+0000–U+001F with the short forms where defined; every other
//    character, including DEL and non-ASCII, passes through raw).
//
// Fail-closed: non-JSON values (undefined, functions, symbols, bigints,
// non-finite numbers) throw instead of being silently coerced, because a
// canonical form that silently drops data would break signature verification.

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

function canonicalizeValue(value: unknown): string {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "string" || t === "boolean") return JSON.stringify(value);
  if (t === "number") {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new CanonicalizationError("non-finite number cannot be canonicalized");
    }
    return JSON.stringify(n);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalizeValue(v)).join(",") + "]";
  }
  if (t === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ":" + canonicalizeValue(obj[k]));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new CanonicalizationError(`cannot canonicalize value of type ${t}`);
}

/** Canonical JSON string for a JSON value (RFC 8785). */
export function canonicalize(value: unknown): string {
  return canonicalizeValue(value);
}

/** SHA-256 hex digest of the canonical form — the content address. */
export function canonicalHashSync(value: unknown): string {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}
