# Secrets

No secret value is stored in this repository.

| Secret / sensitive value | Where it lives | Notes |
| --- | --- | --- |
| Provider secret | AWS Secrets Manager (`ProviderSecretVersionId` pins the exact version) | Encrypted with the stack's KMS key |
| HMAC digest secret | AWS Secrets Manager (`DigestSecretVersionId` pins the exact version) | Keys the record digests (owner subject, Ring account) |
| Ring account id | Never stored in clear; sealed with a KMS data key (identity envelope) and referenced by digest | The owner approval pins only its SHA-256 |
| Ring Developer Playground token | Not stored; used once for `GET /v1/users/me`; a 1-hour replay marker stores only its SHA-256 | Local console keeps it in memory only |
| Cognito tokens | Validated on every request (issuer, client, audience, scopes, 5-minute lifetime) | PKCE verifier and authorization code are single use |
| Mac Ed25519 private key | Only on the owner's Mac, encrypted at rest | The cloud stores the enrolled public key |

Rotation: publish a new secret version and update the pinned version parameter; revoke by disabling the owner/Mac state parameters and the stack's public ingress.
