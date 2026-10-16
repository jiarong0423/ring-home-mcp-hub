# Earlier phase: cloud MCP chain

This is the earlier phase of the project: a cloud MCP chain on API Gateway, Lambda, Cognito, DynamoDB, KMS and Secrets Manager. It is still deployed, but it is not part of the demo video; the current project is described in the [README](../README.md).

## Cloud MCP chain (earlier phase): how a command flows

![Earlier phase: cloud MCP chain](architecture.png)

1. **Owner verification (Ring).** The owner signs in with Amazon Cognito (MFA). A Ring Developer Playground token is sent once to `POST /owner/bootstrap`; the Lambda calls Ring `GET /v1/users/me` and compares the SHA-256 of the Ring account id with the pinned owner account (constant-time). A single-use latch and a token replay marker prevent reuse. The association is valid for at most 24 hours.
2. **Mac enrollment.** The owner's Mac has an Ed25519 key. An operator-approved enrollment (`POST /mac/enroll`) binds that key to the owner.
3. **Command.** An MCP client calls `home_device.command {deviceId, action}` on our MCP server (`POST /mcp`, Streamable HTTP). Only the allowlist below is accepted. The command is stored in a single-slot DynamoDB mailbox and lives for 30 seconds.
4. **Execution.** The Mac fetches the command with an Ed25519-signed request proof, checks it, and applies it **once** to a **paired** simulated device in the local console. A device that is not paired, a gateway set offline, or a device fault means *not applied* — cloud commands are never queued for later.
5. **Receipt.** The Mac posts a signed receipt bound to the command id, envelope hash, device and action. Only then does `home_device.result {commandId}` return `status: SUCCEEDED, executed: true`.

### Cloud allowlist (MCP `home_device.command`)

| Device | Actions accepted from the cloud |
|---|---|
| living_light | on, off |
| air_conditioner | on, off |
| dehumidifier | on, off |
| robot_vacuum | start, pause, dock |
| camera | arm |
| front_door | lock |
| alarm_clock | — (local console only) |

**Never accepted from the cloud:** door unlock, camera disarm, any action that takes a value (temperature, humidity, alarm time). The allowlist is checked at three points — the cloud contract, the Mac worker and the local console simulator.

## Run it

### B. Ring Developer Playground, read-only (legacy console mode, your own Ring developer account)

```bash
npm run start:ring-playground
```

1. Log in with the printed **demo passcode**.
2. In *Ring official device discovery*, enter the printed **operator code**.
3. In the Ring Developer Playground, generate a token and copy it.
4. Click **Import token from local clipboard** — the token goes straight into server memory; the page never sees it.
5. Enter the operator code again and click **Query Ring devices manually**. You get a de-identified device count; nothing is paired or operated.

Playground tokens expire after about 30 minutes; generate a fresh one if you see HTTP 401.

### C. Full cloud chain (requires your own AWS stack)

See [Deploy your own AWS stack](#deploy-your-own-aws-stack-outline) below first.

```bash
export RING_HUB_API_BASE=https://<api-id>.execute-api.<region>.amazonaws.com/<stage>
export RING_HUB_COGNITO_DOMAIN=https://<domain-prefix>.auth.<region>.amazoncognito.com
export RING_HUB_CLIENT_ID=<public PKCE app client id>
export RING_MAC_STATE_DIR="$HOME/.ring-mac-worker"

# one-time owner ceremony (each step needs its own Cognito login URL)
node vendor_mac_launcher/mac-worker.mjs keygen --owner-ref owner/<you> --association-revision 1
#   -> prints keyId, publicKeySpki and an approvalSkeleton. Add "expiresAt" (epoch ms, at most 24 h ahead),
#      save it as mac-enrollment-approval-v1.json in the Lambda layer and set MacEnrollmentApprovalSha256 to its sha256.
#      The owner approval (owner-bootstrap-approval-v1.json: Cognito sub + SHA-256 of your Ring account id) is pinned the same way
#      via OwnerBootstrapApprovalSha256. `node vendor_mac_launcher/mac-worker.mjs ring-demo` prints that Ring account hash.
node vendor_mac_launcher/mac-worker.mjs login-url        # open the printed URL, sign in, copy the callback URL
RING_PLAYGROUND_TOKEN="<fresh Playground token>" node vendor_mac_launcher/mac-worker.mjs bootstrap --callback-url "<callback URL>"
node vendor_mac_launcher/mac-worker.mjs enroll --callback-url "<callback URL>"

# console with the Cloud MCP panel (asks for the Mac key passphrase, hidden)
npm run start:cloud-panel
```

In the console: pair a device → operator code → **Cognito login** → sign in → paste the callback URL (or read it from the clipboard) → choose e.g. *Living room light — Light on* → **Send to device via cloud**. The steps stream in; the run ends with `Done: result.status=SUCCEEDED, executed=true`. One login is reused by later actions until its token expires (about 5 minutes); press **Cognito login** again after that.

Mac worker tests: `npm run test:mac-worker` (40 tests: keygen, PKCE, signed fetch/receipt, home_device flow against a fake cloud).

## Deploy your own AWS stack (outline)

1. Deploy `cloud/aws/ring-private/bootstrap-template.yaml` (artifact bucket, CloudFormation execution role, runtime role) and create the KMS alias it expects.
2. Build the Lambda artifact (every source file and dependency is SHA-256 pinned) and upload the zip to the artifact bucket:
   ```bash
   (cd cloud/aws/ring-private && npm ci --omit=dev)
   mkdir -p output/isolation/current_runs/build
   cp cloud/aws/ring-private/artifact-pins.json output/isolation/current_runs/build/pins.json
   node scripts/build_ring_private_artifact.mjs --root "$PWD" --out "$PWD/output/isolation/current_runs/build/artifact" --pins "$PWD/output/isolation/current_runs/build/pins.json"
   (cd output/isolation/current_runs/build/artifact && zip -qrX ../lambda.zip .)
   ```
   The builder refuses any file whose hash differs from the pins; regenerate `artifact-pins.json` (and the `FIXED` list in the builder) if you change the code.
3. Deploy `cloud/aws/ring-private/template.yaml` with public ingress disabled, store the secret values and pin their version ids.
4. Enable ingress, build the gateway admission file for the live API id / stage / deployment, publish the layer, and set the approval hashes and state parameters.
5. Create the single Cognito owner user (MFA), then run the owner ceremony from [section C](#c-full-cloud-chain-requires-your-own-aws-stack).

Everything account-specific (account id, region, API id, Cognito ids, Ring account pin, Mac key) is a parameter — nothing is hard-coded.

## Security model (earlier phase)

- **Owner only:** Cognito MFA + PKCE, plus a Ring account pinned to the owner; single owner, admin-created users only.
- **Short-lived by design:** 5-minute access tokens, 30-second commands, owner association and Mac enrollment approvals of at most 24 hours.
- **Single use:** idempotent command ids, one command in flight per owner, single-use approval latches, Ring token replay markers, proof nonces.
- **Evidence, not acceptance:** `executed=true` requires a receipt that matches the claim token, envelope hash, enrolled Mac key and the exact device/action.
- **Console and Mac worker:** the console asks for the operator code once per cloud login (rate-limited) and never sends tokens, codes or the Mac key passphrase to the browser. The Mac worker only makes outbound requests — it opens no inbound port.

See [SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](../THREAT_MODEL.md).

## Where the earlier phase is in code

| What | File |
|---|---|
| Ring `GET /v1/users/me` (owner verification, Lambda) | `cloud/aws/ring-private/ring-token-client.mjs`, used by `cloud-owner-bootstrap.mjs` |
| MCP tools `home_device.command` / `home_device.result` | `cloud/aws/ring-private/b02-layer-runtime.mjs`, contract in `src/formal-runtime/mac-command-contract.mjs` |
| Command queue, claim, receipt (DynamoDB) | `cloud/aws/ring-private/mac-command-service.mjs`, `mac-command-store.mjs` |
| Mac worker (fetch / verify / apply / receipt) | `vendor_mac_launcher/` (`mac-worker.mjs`, `vendor/mac-command-worker.mjs`, `vendor/home-device-port.mjs`) |
| Infrastructure | `cloud/aws/ring-private/template.yaml`, `bootstrap-template.yaml` |

## AWS services in the earlier phase

| Service | Role in the project |
|---|---|
| Amazon API Gateway (REST, regional, TLS 1.2+ security policy, throttled) | Endpoints of the earlier phase: `/mcp`, `/auth/*`, `/owner/bootstrap`, `/mac/enroll`, `/mac/commands/fetch`, `/mac/commands/receipt`, `/.well-known/oauth-protected-resource`. Legacy account-link routes on API Gateway (`/ring/token`, `/ring/link`, `/ring/complete`, `/ring/webhook`) are deployed but not part of the demonstrated flow; the Ring webhook receiver in [A5](../README.md#a5-approve-from-anywhere-aws-family-relay-optional) is a different route, on the family relay's function URL. |
| AWS Lambda (Node.js 24, arm64, AWS SAM) + layer | Earlier phase: our cloud MCP server and the owner / Mac endpoints; the layer holds pinned approval files |
| Amazon Cognito | Owner sign-in: managed login, MFA required, PKCE public client, 5-minute access tokens, MCP resource-server scopes |
| Amazon DynamoDB | Identity links and latches, single-slot command mailbox, receipts, Mac enrollments, proof nonces, anti-rollback witness |
| AWS KMS | Table and secret encryption; Ring account ids are envelope-sealed before storage |
| AWS Secrets Manager | Provider and HMAC digest secrets, pinned to exact versions |
| AWS CloudFormation, Amazon S3, IAM | Gated change-set deployments, pinned build artifacts, least-privilege deployer and runtime roles |
| Amazon CloudWatch Logs | Log group for the earlier-phase Lambda function |

The MCP server also pins its API Gateway id, stage, domain and function in an admission file and checks every request against it; when a request carries a different deployment id it is rejected, so a redeploy requires an explicit re-admission.

## Limitations (earlier phase)

- Six of the seven simulated home devices accept allowlisted cloud actions (see the allowlist above).
- The Mac worker runs in **software-direct, reduced-assurance mode** (no local Wi-Fi trust or anti-rollback re-check on the Mac).
- Approvals are short-lived and renewed by an operator ceremony; there is no automatic renewal yet.
- Some legacy modules from earlier iterations (e.g. `telegram-*`, account-link routes) remain in the code but are not part of the demonstrated flow.
