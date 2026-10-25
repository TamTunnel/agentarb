# @tamtunnel/agentarb-server

Arbiter service: Fastify API, SQLite case store (better-sqlite3),
verdict-gated escrow ledger, AgentCred mandate-as-hold adapter, human
escalation, arbiter key rotation, verdict revocation, and a read-only
server-rendered HTML case viewer (no JavaScript, all output escaped).

Run:

```sh
npm run build -w @tamtunnel/agentarb-server
node packages/server/dist/index.js
```

Environment:

| Variable | Default | Meaning |
| --- | --- | --- |
| `AGENTARB_DATA_DIR` | `./agentarb-data` | Data directory (SQLite lives here unless `AGENTARB_DB` is set). |
| `AGENTARB_DB` | `<dataDir>/agentarb.db` | SQLite path (`:memory:` for ephemeral runs). |
| `AGENTARB_HOST` | `127.0.0.1` | Bind host — local only by default. |
| `AGENTARB_PORT` | `3000` | Bind port. |
| `AGENTARB_ALLOW_NOW_OVERRIDE` | unset | When `=1`, adjudication accepts a `now` override (tests). |

API: `POST /v1/cases`, `GET /v1/cases`, `GET /v1/cases/:id`,
`POST /v1/cases/:id/evidence`, `POST /v1/cases/:id/adjudicate`,
`GET /v1/cases/:id/verdicts`, `POST /v1/cases/:id/escalate`,
`POST /v1/cases/:id/human-verdict`, `POST /v1/verdicts/:id/revoke`,
`POST /v1/holds`, `GET /v1/holds/:id`, `GET /v1/keys`,
`POST /v1/keys/rotate`, plus `GET /` and `GET /cases/:id` (viewer).

Security posture for v1: no API authentication — put it behind auth
before exposing it. The server owns its AgentCred replay ledger
(`SI_WALLET_DIR` defaults to the data dir), so mandate-backed holds are
single-use. Arbiter private keys live in the data dir; protect it.
