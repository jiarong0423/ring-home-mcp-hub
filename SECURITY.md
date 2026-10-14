# Security

## Reporting
Please open a GitHub issue without exploit details, or contact the maintainer through the repository profile.

## Secrets and identifiers
- No credentials, tokens, keys or account ids are committed. Deployment values (API base, Cognito domain, client id) are read from environment variables; the code ships with placeholders.
- Ring Developer Playground tokens are imported from the local clipboard into server memory (console) or passed once through the `RING_PLAYGROUND_TOKEN` environment variable / hidden prompt (Mac worker CLI). They never reach the browser and are not written to disk.
- Cognito access tokens (5-minute lifetime) stay in local server memory; authorization codes and PKCE verifiers are single use.
- The Mac Ed25519 signing key is encrypted at rest. The passphrase comes from a hidden terminal prompt (or, for scripted CLI use, `RING_MAC_KEY_PASSPHRASE` / piped stdin); it is never accepted on the command line or from the browser.

## Network exposure
- The local console binds to `127.0.0.1` and checks Host/Origin headers; it is not reachable from other machines.
- The Mac worker only makes outbound HTTPS requests to the configured API Gateway and Cognito domain; it opens no inbound port.
- The AWS endpoints are public by design and require a Cognito access token with the MCP scopes; Mac endpoints additionally require an Ed25519 request proof from the enrolled key.

## Dependencies
- Local console and Mac worker: Node.js standard library only.
- Lambda: AWS SDK v3 (see `cloud/aws/ring-private/package-lock.json`).
