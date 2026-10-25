// packages/core/src/schemas.ts
//
// JSON Schema (draft 2020-12 subset, ajv-compatible) for the wire formats.
// Core itself validates with hand-written pure functions (it is
// zero-dependency); the server uses these schemas for schema-first HTTP
// validation via Fastify's built-in ajv. The two validators must agree —
// the server test suite checks representative payloads against both.

export const BUNDLE_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "agentarb-bundle",
  type: "object",
  additionalProperties: false,
  required: [
    "format",
    "version",
    "id",
    "created_at",
    "claimant",
    "respondent",
    "transaction",
    "claims",
    "evidence",
    "signatures",
  ],
  properties: {
    format: { const: "agentarb-bundle" },
    version: { const: 1 },
    id: { type: "string", minLength: 1 },
    created_at: { type: "string", format: "date-time" },
    claimant: { type: "string", minLength: 1 },
    respondent: { type: "string", minLength: 1 },
    transaction: {
      type: "object",
      additionalProperties: false,
      required: ["ref", "currency", "amount_minor"],
      properties: {
        ref: { type: "string", minLength: 1 },
        currency: { type: "string", pattern: "^[A-Z]{3}$" },
        amount_minor: { type: "integer", minimum: 0 },
        description: { type: "string" },
        agreed_delivery_at: { type: ["string", "null"], format: "date-time" },
      },
    },
    claims: {
      type: "array",
      minItems: 1,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["type", "amount_minor", "details"],
        properties: {
          type: {
            type: "string",
            enum: ["non-delivery", "late-delivery", "wrong-partial-delivery"],
          },
          amount_minor: { type: "integer", minimum: 0 },
          details: { type: "object" },
        },
      },
    },
    evidence: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["id", "kind", "submitted_by"],
        properties: {
          id: { type: "string", minLength: 1 },
          kind: {
            type: "string",
            enum: [
              "delivery-proof",
              "communication",
              "oracle-attestation",
              "payment-proof",
              "condition-proof",
              "other",
            ],
          },
          content: { type: ["string", "null"] },
          sha256: { type: ["string", "null"], pattern: "^[0-9a-f]{64}$" },
          uri: { type: ["string", "null"] },
          delivered_at: { type: ["string", "null"], format: "date-time" },
          signer: { type: ["string", "null"] },
          jws: { type: ["string", "null"] },
          submitted_by: { type: "string", minLength: 1 },
        },
      },
    },
    signatures: {
      type: "array",
      minItems: 1,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["signer", "jws"],
        properties: {
          signer: { type: "string", minLength: 1 },
          jws: { type: "string", minLength: 1 },
        },
      },
    },
  },
} as const;

export const VERDICT_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "agentarb-verdict",
  type: "object",
  additionalProperties: false,
  required: [
    "format",
    "version",
    "id",
    "case_id",
    "bundle_id",
    "bundle_hash",
    "method",
    "outcome",
    "refund_minor",
    "currency",
    "claim_amount_minor",
    "reasoning",
    "decided_at",
    "arbiter",
  ],
  properties: {
    format: { const: "agentarb-verdict" },
    version: { const: 1 },
    id: { type: "string", minLength: 1 },
    case_id: { type: "string", minLength: 1 },
    bundle_id: { type: "string", minLength: 1 },
    bundle_hash: { type: "string", pattern: "^[0-9a-f]{64}$" },
    ruleset_id: { type: "string", minLength: 1 },
    ruleset_version: { type: "integer", minimum: 1 },
    ruleset_hash: { type: "string", pattern: "^[0-9a-f]{64}$" },
    method: { type: "string", enum: ["rules", "human"] },
    outcome: {
      type: "string",
      enum: ["refund_full", "refund_partial", "reject", "escalate"],
    },
    refund_minor: { type: "integer", minimum: 0 },
    currency: { type: "string", pattern: "^[A-Z]{3}$" },
    claim_amount_minor: { type: "integer", minimum: 0 },
    reasoning: {
      type: "array",
      minItems: 1,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["rule", "matched", "reason"],
        properties: {
          rule: { type: "string", minLength: 1 },
          matched: { type: "boolean" },
          reason: { type: "string", minLength: 1 },
        },
      },
    },
    decided_at: { type: "string", format: "date-time" },
    arbiter: { type: "string", minLength: 1 },
    signature: { type: ["string", "null"] },
  },
} as const;

export const RULESET_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "agentarb-ruleset",
  type: "object",
  additionalProperties: false,
  required: [
    "format",
    "id",
    "version",
    "claim_type",
    "description",
    "min_evidence_tier",
    "rules",
    "hash",
    "signer",
    "signature",
  ],
  properties: {
    format: { const: "agentarb-ruleset" },
    id: { type: "string", minLength: 1 },
    version: { type: "integer", minimum: 1 },
    claim_type: {
      type: "string",
      enum: ["non-delivery", "late-delivery", "wrong-partial-delivery"],
    },
    description: { type: "string", minLength: 1 },
    min_evidence_tier: { type: "integer", enum: [0, 1, 2, 3] },
    rules: {
      type: "array",
      minItems: 1,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "when", "outcome", "reason"],
        properties: {
          name: { type: "string", minLength: 1 },
          when: true,
          outcome: {
            type: "string",
            enum: ["refund_full", "refund_partial", "reject", "escalate"],
          },
          reason: { type: "string", minLength: 1 },
        },
      },
    },
    hash: { type: "string", pattern: "^[0-9a-f]{64}$" },
    signer: { type: "string", minLength: 1 },
    signature: { type: "string", minLength: 1 },
  },
} as const;
