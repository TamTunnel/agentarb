# @tamtunnel/agentarb-cli

`agentarb` binary: keygen, bundle sign/verify, submit, adjudicate,
case fetch, demo generation. Offline verification of bundles and
verdicts is first-class — no server needed to check a signature, a
trust tier, or a verdict.

```sh
npm run build -w @tamtunnel/agentarb-cli
node packages/cli/dist/index.js help
```

Key files are JSON as printed by `agentarb keygen`
(`{ did, privateJwk, publicJwk }`) or a bare Ed25519 private JWK.
Files written by `keygen` and `demo` get mode 0600. Treat them like
passwords.
