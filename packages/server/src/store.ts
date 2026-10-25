// packages/server/src/store.ts
//
// SQLite case store (better-sqlite3, synchronous). One database file per
// server data dir. All JSON blobs are stored as canonical JSON strings so
// rows are comparable and diffable.
//
// State machine for cases:
//   open -> adjudicated | escalated -> resolved
//   - evidence may be added while open, escalated, or adjudicated
//     (re-adjudication applies escrow deltas, see escrow.ts)
//   - adjudicated: verdicts issued; escalated: a verdict (or an operator)
//     asked for human review; resolved: a human verdict closed the case
//   - resolved is terminal
// Revocation voids a verdict for consumers but does not auto-reverse
// escrow in v1 (documented limitation).

import Database from "better-sqlite3";
import fs from "node:fs";
import { canonicalize } from "@tamtunnel/agentarb-core";

export type CaseStatus = "open" | "adjudicated" | "escalated" | "resolved";

export interface CaseRow {
  id: string;
  bundle_json: string;
  bundle_hash: string;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
}

export interface EvidenceRow {
  case_id: string;
  evidence_id: string;
  evidence_json: string;
  tier: number;
  added_at: string;
}

export interface VerdictRow {
  id: string;
  case_id: string;
  claim_index: number;
  verdict_json: string;
  method: string;
  outcome: string;
  refund_minor: number;
  created_at: string;
}

export interface HoldRow {
  id: string;
  case_id: string;
  claim_index: number;
  amount_minor: number;
  currency: string;
  remaining_minor: number;
  status: string;
  mandate_jws: string | null;
  mandate_agent: string | null;
  created_at: string;
  updated_at: string;
}

export interface HoldEventRow {
  id: number;
  hold_id: string;
  kind: string;
  amount_minor: number;
  verdict_id: string | null;
  created_at: string;
}

export interface RevocationRow {
  verdict_id: string;
  revocation_json: string;
  created_at: string;
}

export interface ArbiterKeyRow {
  did: string;
  private_jwk_json: string;
  status: "active" | "retired";
  created_at: string;
  retired_at: string | null;
}

export class Store {
  private db: Database.Database;

  constructor(path: string) {
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        bundle_json TEXT NOT NULL,
        bundle_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS case_evidence (
        case_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        evidence_json TEXT NOT NULL,
        tier INTEGER NOT NULL,
        added_at TEXT NOT NULL,
        PRIMARY KEY (case_id, evidence_id)
      );
      CREATE TABLE IF NOT EXISTS verdicts (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        claim_index INTEGER NOT NULL,
        verdict_json TEXT NOT NULL,
        method TEXT NOT NULL,
        outcome TEXT NOT NULL,
        refund_minor INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS holds (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        claim_index INTEGER NOT NULL DEFAULT 0,
        amount_minor INTEGER NOT NULL,
        currency TEXT NOT NULL,
        remaining_minor INTEGER NOT NULL,
        status TEXT NOT NULL,
        mandate_jws TEXT,
        mandate_agent TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS hold_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hold_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        amount_minor INTEGER NOT NULL,
        verdict_id TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS revocations (
        verdict_id TEXT PRIMARY KEY,
        revocation_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS arbiter_keys (
        did TEXT PRIMARY KEY,
        private_jwk_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        retired_at TEXT
      );
      CREATE TABLE IF NOT EXISTS claim_escrow (
        case_id TEXT NOT NULL,
        claim_index INTEGER NOT NULL,
        applied_refund_minor INTEGER NOT NULL,
        cumulative_refund_minor INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (case_id, claim_index)
      );
    `);
    // Migration for databases created before cumulative_refund_minor
    // existed: the column tracks cash actually refunded per claim and is
    // never reset by a reject (see escrow.ts) — without it, a
    // refund → reject → refund sequence could pay a claim twice.
    const cols = this.db.pragma("table_info(claim_escrow)") as Array<{
      name: string;
    }>;
    if (!cols.some((c) => c.name === "cumulative_refund_minor")) {
      this.db.exec(
        "ALTER TABLE claim_escrow ADD COLUMN cumulative_refund_minor INTEGER NOT NULL DEFAULT 0",
      );
    }
    // The database holds arbiter private keys: tighten file modes so a
    // local user cannot read them. Sidecars are created by the schema
    // writes above; missing files (e.g. :memory:) are skipped.
    if (path !== ":memory:") {
      for (const f of [path, `${path}-wal`, `${path}-shm`]) {
        try {
          fs.chmodSync(f, 0o600);
        } catch {
          // File does not exist yet — nothing to tighten.
        }
      }
    }
  }

  close(): void {
    this.db.close();
  }

  /**
   * Run fn inside a single SQLite transaction. Any throw rolls every
   * write in fn back — this is what makes adjudication atomic: a
   * mid-loop failure cannot strand partial verdicts or moved escrow.
   */
  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  // ------------------------------------------------------------- cases

  createCase(id: string, bundle: unknown, bundleHash: string, now: string): void {
    this.db
      .prepare(
        "INSERT INTO cases (id, bundle_json, bundle_hash, status, created_at, updated_at) VALUES (?, ?, ?, 'open', ?, ?)",
      )
      .run(id, canonicalize(bundle), bundleHash, now, now);
  }

  getCase(id: string): CaseRow | undefined {
    return this.db.prepare("SELECT * FROM cases WHERE id = ?").get(id) as
      | CaseRow
      | undefined;
  }

  findCaseByBundleId(bundleId: string): CaseRow | undefined {
    const rows = this.db.prepare("SELECT * FROM cases").all() as CaseRow[];
    for (const row of rows) {
      const bundle = JSON.parse(row.bundle_json) as { id?: string };
      if (bundle.id === bundleId) return row;
    }
    return undefined;
  }

  listCases(): CaseRow[] {
    return this.db
      .prepare("SELECT * FROM cases ORDER BY created_at DESC")
      .all() as CaseRow[];
  }

  setCaseStatus(id: string, status: CaseStatus, now: string): void {
    this.db
      .prepare("UPDATE cases SET status = ?, updated_at = ? WHERE id = ?")
      .run(status, now, id);
  }

  // ---------------------------------------------------------- evidence

  addEvidence(
    caseId: string,
    evidenceId: string,
    evidence: unknown,
    tier: number,
    now: string,
  ): void {
    this.db
      .prepare(
        "INSERT INTO case_evidence (case_id, evidence_id, evidence_json, tier, added_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(caseId, evidenceId, canonicalize(evidence), tier, now);
  }

  getEvidence(caseId: string): EvidenceRow[] {
    return this.db
      .prepare(
        "SELECT * FROM case_evidence WHERE case_id = ? ORDER BY added_at ASC",
      )
      .all(caseId) as EvidenceRow[];
  }

  // ---------------------------------------------------------- verdicts

  saveVerdict(
    id: string,
    caseId: string,
    claimIndex: number,
    verdict: unknown,
    method: string,
    outcome: string,
    refundMinor: number,
    now: string,
  ): void {
    this.db
      .prepare(
        "INSERT INTO verdicts (id, case_id, claim_index, verdict_json, method, outcome, refund_minor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(id, caseId, claimIndex, canonicalize(verdict), method, outcome, refundMinor, now);
  }

  getVerdicts(caseId: string): VerdictRow[] {
    return this.db
      .prepare(
        "SELECT * FROM verdicts WHERE case_id = ? ORDER BY created_at ASC",
      )
      .all(caseId) as VerdictRow[];
  }

  getVerdict(id: string): VerdictRow | undefined {
    return this.db.prepare("SELECT * FROM verdicts WHERE id = ?").get(id) as
      | VerdictRow
      | undefined;
  }

  // ------------------------------------------------------------- holds

  createHold(
    id: string,
    caseId: string,
    claimIndex: number,
    amountMinor: number,
    currency: string,
    mandateJws: string | null,
    mandateAgent: string | null,
    now: string,
  ): void {
    this.db
      .prepare(
        "INSERT INTO holds (id, case_id, claim_index, amount_minor, currency, remaining_minor, status, mandate_jws, mandate_agent, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'held', ?, ?, ?, ?)",
      )
      .run(id, caseId, claimIndex, amountMinor, currency, amountMinor, mandateJws, mandateAgent, now, now);
  }

  getHolds(caseId: string): HoldRow[] {
    return this.db
      .prepare("SELECT * FROM holds WHERE case_id = ? ORDER BY created_at ASC")
      .all(caseId) as HoldRow[];
  }

  getHold(id: string): HoldRow | undefined {
    return this.db.prepare("SELECT * FROM holds WHERE id = ?").get(id) as
      | HoldRow
      | undefined;
  }

  addHoldEvent(
    holdId: string,
    kind: string,
    amountMinor: number,
    verdictId: string | null,
    now: string,
  ): void {
    this.db
      .prepare(
        "INSERT INTO hold_events (hold_id, kind, amount_minor, verdict_id, created_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(holdId, kind, amountMinor, verdictId, now);
  }

  getHoldEvents(holdId: string): HoldEventRow[] {
    return this.db
      .prepare(
        "SELECT * FROM hold_events WHERE hold_id = ? ORDER BY id ASC",
      )
      .all(holdId) as HoldEventRow[];
  }

  updateHold(holdId: string, remainingMinor: number, status: string, now: string): void {
    this.db
      .prepare(
        "UPDATE holds SET remaining_minor = ?, status = ?, updated_at = ? WHERE id = ?",
      )
      .run(remainingMinor, status, now, holdId);
  }

  // ------------------------------------------------------- claim escrow

  getAppliedRefund(caseId: string, claimIndex: number): number {
    const row = this.db
      .prepare(
        "SELECT applied_refund_minor FROM claim_escrow WHERE case_id = ? AND claim_index = ?",
      )
      .get(caseId, claimIndex) as { applied_refund_minor: number } | undefined;
    return row ? row.applied_refund_minor : 0;
  }

  setAppliedRefund(caseId: string, claimIndex: number, amount: number): void {
    this.db
      .prepare(
        "INSERT INTO claim_escrow (case_id, claim_index, applied_refund_minor) VALUES (?, ?, ?) ON CONFLICT(case_id, claim_index) DO UPDATE SET applied_refund_minor = ?",
      )
      .run(caseId, claimIndex, amount, amount);
  }

  /**
   * Cash actually refunded for this claim across ALL verdicts, including
   * across rejects. Never decreases, never reset by a reject — it is the
   * cap that stops refund → reject → refund from paying a claim twice.
   */
  getCumulativeRefund(caseId: string, claimIndex: number): number {
    const row = this.db
      .prepare(
        "SELECT cumulative_refund_minor FROM claim_escrow WHERE case_id = ? AND claim_index = ?",
      )
      .get(caseId, claimIndex) as
      | { cumulative_refund_minor: number }
      | undefined;
    return row ? row.cumulative_refund_minor : 0;
  }

  addCumulativeRefund(caseId: string, claimIndex: number, amount: number): void {
    if (amount === 0) return;
    this.db
      .prepare(
        "INSERT INTO claim_escrow (case_id, claim_index, applied_refund_minor, cumulative_refund_minor) VALUES (?, ?, 0, ?) ON CONFLICT(case_id, claim_index) DO UPDATE SET cumulative_refund_minor = cumulative_refund_minor + excluded.cumulative_refund_minor",
      )
      .run(caseId, claimIndex, amount);
  }

  // -------------------------------------------------------- revocations

  saveRevocation(verdictId: string, revocation: unknown, now: string): void {
    this.db
      .prepare(
        "INSERT INTO revocations (verdict_id, revocation_json, created_at) VALUES (?, ?, ?)",
      )
      .run(verdictId, canonicalize(revocation), now);
  }

  getRevocation(verdictId: string): RevocationRow | undefined {
    return this.db
      .prepare("SELECT * FROM revocations WHERE verdict_id = ?")
      .get(verdictId) as RevocationRow | undefined;
  }

  // ------------------------------------------------------- arbiter keys

  getArbiterKeys(): ArbiterKeyRow[] {
    return this.db
      .prepare("SELECT * FROM arbiter_keys ORDER BY created_at ASC")
      .all() as ArbiterKeyRow[];
  }

  getActiveArbiterKey(): ArbiterKeyRow | undefined {
    return this.db
      .prepare("SELECT * FROM arbiter_keys WHERE status = 'active' LIMIT 1")
      .get() as ArbiterKeyRow | undefined;
  }

  addArbiterKey(did: string, privateJwkJson: string, now: string): void {
    this.db
      .prepare(
        "INSERT INTO arbiter_keys (did, private_jwk_json, status, created_at, retired_at) VALUES (?, ?, 'active', ?, NULL)",
      )
      .run(did, privateJwkJson, now);
  }

  retireArbiterKey(did: string, now: string): void {
    this.db
      .prepare(
        "UPDATE arbiter_keys SET status = 'retired', retired_at = ? WHERE did = ?",
      )
      .run(now, did);
  }
}
