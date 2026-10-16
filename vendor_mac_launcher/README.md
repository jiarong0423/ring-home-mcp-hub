# Mac worker

Earlier phase (cloud MCP chain, not part of the demo video): the owner's Mac is the only place a cloud command is executed. It fetches a command from the cloud MCP mailbox with an Ed25519-signed request proof, checks it (schema, 30-second expiry, owner, allowlist, claim token), applies it **once** (local journal), and posts a signed receipt. The cloud reports `executed=true` only after that receipt is accepted.

Execution mode is **software-direct (reduced assurance)** — see `BLOCKERS.md` for what the full formal runtime would add.

## Commands (`node mac-worker.mjs <command>`)

| Command | What it does |
|---|---|
| `keygen --owner-ref <ref> --association-revision <n>` | Creates the encrypted Ed25519 key (hidden passphrase prompt) and prints the public key for the enrollment approval |
| `login-url` | Prints a Cognito authorize URL (PKCE S256); the verifier stays in a 0600 file |
| `bootstrap --callback-url <url>` | Owner verification/renewal: sends a Ring Playground token (env `RING_PLAYGROUND_TOKEN` or hidden prompt) to `POST /owner/bootstrap` |
| `enroll --callback-url <url>` | Enrolls this Mac's key (`POST /mac/enroll`) |
| `demo-switch --callback-url <url> --enabled <true|false>` | One login: MCP `software_test_switch.set` → worker → MCP result |
| `run --callback-url <url>` | Fetch / verify / execute / receipt loop for queued commands |
| `ring-demo` | Read-only Ring Playground check (`/v1/users/me`, `/v1/devices`), de-identified output |
| `status` | Local identity, pending login, journal; no network |

`home_device.command` (the seven simulated devices) is executed through the local console's Cloud MCP panel, which owns the simulator and its pairing gates (`demoDevice` in `src/launcher.mjs`).

## Configuration
`RING_HUB_API_BASE`, `RING_HUB_COGNITO_DOMAIN`, `RING_HUB_CLIENT_ID` (see the root README), and `RING_MAC_STATE_DIR` (default `~/.ring-mac-worker`, 0700). Tokens, authorization codes and the passphrase are never written to disk or printed.

## Tests
`node --test tests/*.test.mjs` — 40 tests, fully local. An in-process TLS fake cloud verifies bearer + Ed25519 proof with the real verifier, nonce replay, single claim, receipts, and the `home_device` flow. Requires `openssl` for the test certificate.
