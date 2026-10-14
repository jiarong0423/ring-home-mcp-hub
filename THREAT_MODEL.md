# Threat model (summary)

Trust boundary: **MCP client → API Gateway → Lambda (MCP server) → DynamoDB/KMS → owner's Mac worker → local console (simulated devices)**.

| Threat | Mitigation |
|---|---|
| Someone other than the owner issues commands | Cognito MFA + PKCE, single admin-created owner, Ring account pinned to the owner (SHA-256, constant-time compare), MCP resource-server scopes |
| Reuse of an approval or Ring token | Single-use bootstrap/renewal latches, 1-hour Ring token replay marker, failure budget (3 definite rejections → 1 h lock) |
| Replay or duplication of a command | Idempotent command ids, single-slot mailbox, 30-second TTL, claim-token hash, Mac journal (apply at most once), proof nonces |
| A fake or impersonated Mac | Operator-approved Ed25519 key enrollment; every fetch/receipt carries a signed proof over owner, operation, audience, token hash, payload hash and nonce (≤ 15 s) |
| "Accepted" reported as "executed" | `executed=true` only after a receipt matching the claim, envelope hash, Mac key and exact device/action |
| Cloud compromise opening the door | Door unlock, camera disarm and value actions are not in the cloud allowlist; the Mac worker and the local console enforce the same allowlist; local unlock needs a one-use confirmation |
| A refused command running later | Cloud-origin commands are never queued locally (applied immediately or refused) |
| Silent infrastructure change | Gateway admission file pins API id, stage, domain and function, and rejects a request whose deployment id differs from the pinned one; a redeploy requires re-admission |
| Local attacker in the browser | Loopback-only server, Host/Origin checks, separate operator code with rate limit for every cloud or Ring action, no secrets sent to the page |

Known residual risks: reduced-assurance Mac mode (no local anti-rollback/Wi-Fi trust re-check), operator-built approval files, sandbox-only Ring identity.
