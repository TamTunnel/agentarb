// packages/server/src/viewer.ts
//
// Minimal read-only case viewer: server-rendered HTML, no JavaScript, no
// SPA. Every interpolated value is escaped — case data comes from
// untrusted submitters, and the viewer must never become an XSS sink.

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const PAGE_HEAD = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentArb cases</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;line-height:1.5}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}
code{word-break:break-all}.badge{display:inline-block;padding:.1rem .4rem;border-radius:4px;background:#eee}
.badge.refund_full,.badge.refund_partial{background:#d4edda}
.badge.reject{background:#f8d7da}.badge.escalate{background:#fff3cd}
pre{white-space:pre-wrap;word-break:break-word;background:#f6f6f6;padding:1rem}
</style></head><body>`;

export interface CaseSummary {
  id: string;
  status: string;
  bundle_id: string;
  claimant: string;
  respondent: string;
  created_at: string;
}

export function renderCaseList(cases: CaseSummary[]): string {
  const rows = cases
    .map(
      (c) =>
        `<tr><td><a href="/cases/${escapeHtml(c.id)}">${escapeHtml(c.id)}</a></td>` +
        `<td><span class="badge">${escapeHtml(c.status)}</span></td>` +
        `<td>${escapeHtml(c.bundle_id)}</td>` +
        `<td><code>${escapeHtml(c.claimant)}</code></td>` +
        `<td><code>${escapeHtml(c.respondent)}</code></td>` +
        `<td>${escapeHtml(c.created_at)}</td></tr>`,
    )
    .join("\n");
  return (
    PAGE_HEAD +
    `<h1>AgentArb cases</h1>` +
    `<p>Read-only viewer. Cases are submitted via the API; see the README for the quick start.</p>` +
    `<table><tr><th>Case</th><th>Status</th><th>Bundle</th><th>Claimant</th><th>Respondent</th><th>Created</th></tr>` +
    rows +
    `</table></body></html>`
  );
}

export interface CaseDetailData {
  id: string;
  status: string;
  bundle: Record<string, unknown>;
  bundle_hash: string;
  evidence: Array<{ id: string; kind: string; tier: number; tierName: string }>;
  verdicts: Array<{
    id: string;
    method: string;
    outcome: string;
    refund_minor: number;
    revoked: boolean;
    reasoning: Array<{ rule: string; matched: boolean; reason: string }>;
  }>;
  holds: Array<{
    id: string;
    claim_index: number;
    amount_minor: number;
    remaining_minor: number;
    status: string;
    mandate_agent: string | null;
  }>;
}

export function renderCaseDetail(d: CaseDetailData): string {
  const tx = d.bundle.transaction as Record<string, unknown>;
  const claims = d.bundle.claims as Array<Record<string, unknown>>;
  const evidenceRows = d.evidence
    .map(
      (e) =>
        `<tr><td>${escapeHtml(e.id)}</td><td>${escapeHtml(e.kind)}</td>` +
        `<td>${e.tier} (${escapeHtml(e.tierName)})</td></tr>`,
    )
    .join("\n");
  const verdictRows = d.verdicts
    .map((v) => {
      const reasoning = v.reasoning
        .map(
          (r) =>
            `<li>${escapeHtml(r.rule)}: ${r.matched ? "matched" : "no"} — ${escapeHtml(r.reason)}</li>`,
        )
        .join("\n");
      return (
        `<h3>Verdict <code>${escapeHtml(v.id)}</code> ` +
        `<span class="badge ${escapeHtml(v.outcome)}">${escapeHtml(v.outcome)}</span>` +
        (v.revoked ? ` <span class="badge">REVOKED</span>` : "") +
        `</h3><p>Method: ${escapeHtml(v.method)}; refund: ${v.refund_minor} minor units.</p>` +
        `<ul>${reasoning}</ul>`
      );
    })
    .join("\n");
  const holdRows = d.holds
    .map(
      (h) =>
        `<tr><td><code>${escapeHtml(h.id)}</code></td><td>${h.claim_index}</td>` +
        `<td>${h.amount_minor}</td><td>${h.remaining_minor}</td>` +
        `<td>${escapeHtml(h.status)}</td>` +
        `<td>${h.mandate_agent ? escapeHtml(h.mandate_agent) : "—"}</td></tr>`,
    )
    .join("\n");
  const claimRows = claims
    .map(
      (c, i) =>
        `<tr><td>${i}</td><td>${escapeHtml(String(c.type))}</td><td>${String(c.amount_minor)}</td></tr>`,
    )
    .join("\n");
  return (
    PAGE_HEAD +
    `<h1>Case <code>${escapeHtml(d.id)}</code> <span class="badge">${escapeHtml(d.status)}</span></h1>` +
    `<p>Bundle <code>${escapeHtml(String(d.bundle.id))}</code><br>` +
    `Hash <code>${escapeHtml(d.bundle_hash)}</code><br>` +
    `Claimant <code>${escapeHtml(String(d.bundle.claimant))}</code><br>` +
    `Respondent <code>${escapeHtml(String(d.bundle.respondent))}</code><br>` +
    `Transaction ${escapeHtml(String(tx.ref))}: ${String(tx.amount_minor)} ${escapeHtml(String(tx.currency))}</p>` +
    `<h2>Claims</h2><table><tr><th>#</th><th>Type</th><th>Amount (minor)</th></tr>${claimRows}</table>` +
    `<h2>Evidence</h2><table><tr><th>ID</th><th>Kind</th><th>Trust tier</th></tr>${evidenceRows}</table>` +
    `<h2>Verdicts</h2>${verdictRows || "<p>None yet.</p>"}` +
    `<h2>Holds</h2><table><tr><th>ID</th><th>Claim</th><th>Amount</th><th>Remaining</th><th>Status</th><th>Mandate agent</th></tr>${holdRows}</table>` +
    `<p><a href="/">← All cases</a></p></body></html>`
  );
}
