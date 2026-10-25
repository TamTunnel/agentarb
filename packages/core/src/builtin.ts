// packages/core/src/builtin.ts
//
// Loading for the built-in rule sets. The sets ship in
// builtin-rulesets.generated.ts (produced by scripts/sign-rulesets.mjs
// from builtin-definitions.ts). Loading verifies every set against the
// embedded built-in signer DID — a tampered built-in must never silently
// load.

import {
  BUILTIN_RULESETS,
  BUILTIN_SIGNER_DID,
} from "./builtin-rulesets.generated.js";
import {
  verifyRuleset,
  type SignedRuleset,
} from "./rulesets.js";
import type { ClaimType } from "./bundle.js";

/** The built-in signer DID embedded in the generated file. */
export function builtinSignerDid(): string {
  return BUILTIN_SIGNER_DID;
}

/**
 * Load and verify the built-in rule sets. Throws if any set fails
 * verification against the embedded built-in signer DID.
 */
export function loadBuiltinRulesets(): SignedRuleset[] {
  const out: SignedRuleset[] = [];
  for (const rs of BUILTIN_RULESETS) {
    const v = verifyRuleset(rs, { trustedSigners: [BUILTIN_SIGNER_DID] });
    if (!v.ok) {
      throw new Error(
        `built-in rule set ${rs.id} failed verification: ${v.errors.join("; ")}`,
      );
    }
    out.push(rs);
  }
  return out;
}

/** Find the built-in rule set for a claim type (verified on load). */
export function builtinRulesetFor(claimType: ClaimType): SignedRuleset {
  const sets = loadBuiltinRulesets();
  const found = sets.find((s) => s.claim_type === claimType);
  if (!found) throw new Error(`no built-in rule set for ${claimType}`);
  return found;
}
