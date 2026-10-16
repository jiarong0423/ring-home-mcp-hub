# Security

## Reporting
Please open a GitHub issue without exploit details, or contact the maintainer through the repository profile.

## Secrets and identifiers
- No credentials, tokens, keys or account ids are committed; the code ships with placeholders.
- Ring Developer Playground tokens are imported from the local clipboard into server memory (console) or pasted on the admin phone; they stay in hub memory only, never reach the browser and are not written to disk. For live view the hub forwards the phone's WebRTC offer and keeps the token.
- The hub's relay signing key (Ed25519) is a 0600 file in `~/.home-mcp-console/`; only its public key goes into the relay stack. The Ring webhook HMAC key is a NoEcho stack parameter, passed to the relay Lambda as an environment variable (readable by account principals allowed to read the function configuration); it is never logged. Phones enabled for remote approval keep a non-extractable WebCrypto key in their browser.

## Network exposure
- The local console binds to `127.0.0.1` and checks Host/Origin headers; it is not reachable from other machines.
- Family relay: a public Lambda function URL. Hub calls must carry an Ed25519 signature from the pinned hub key; phone calls must carry a P-256 signature from an activated phone; the hub verifies each decision again before anything opens. Ring webhook calls (`POST /ring/webhook`) must carry a valid `X-Signature` HMAC-SHA256 of the raw body; without a configured key the route answers 503. Bodies are capped at 8 KB (16 KB for `/ring/webhook`) and every row expires.
- The hub calls Amazon SNS, CloudWatch and Bedrock through the AWS CLI with a dedicated least-privilege profile; it never handles access keys.

## Dependencies
- Local console: Node.js standard library only (no npm dependencies). Optional features call system tools by absolute path: `/usr/bin/osascript` (pairing dialog), `/usr/bin/say` (voice notice), the AWS CLI (email, heartbeat, Bedrock) and a local Python with `opencv-python-headless` and `numpy` (face hint).
- The relay Lambda uses the AWS SDK bundled in the Node.js 22 runtime.

## Earlier phase (cloud MCP chain)
Not part of the current demo; see [docs/EARLIER_PHASE_CLOUD_MCP.md](docs/EARLIER_PHASE_CLOUD_MCP.md).
- Deployment values (API base, Cognito domain, client id) are read from environment variables.
- For the Mac worker CLI, a Ring Playground token is passed once through the `RING_PLAYGROUND_TOKEN` environment variable or a hidden prompt.
- Cognito access tokens (5-minute lifetime) stay in local server memory; authorization codes and PKCE verifiers are single use.
- The Mac Ed25519 signing key is encrypted at rest. The passphrase comes from a hidden terminal prompt (or, for scripted CLI use, `RING_MAC_KEY_PASSPHRASE` / piped stdin); it is never accepted on the command line or from the browser.
- The Mac worker only makes outbound HTTPS requests to the configured API Gateway and Cognito domain; it opens no inbound port.
- The AWS endpoints are public by design and require a Cognito access token with the MCP scopes; Mac endpoints additionally require an Ed25519 request proof from the enrolled key.
- The Mac worker uses the Node.js standard library only; the cloud MCP Lambda uses AWS SDK v3 (see `cloud/aws/ring-private/package-lock.json`).
