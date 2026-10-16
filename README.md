# Ring Home MCP Hub

**An MCP home hub for AI agents. It acts only for a Ring-verified owner — and reports `executed=true` only after the owner's Mac returns a verified receipt.**

Built for the *Build, Ship, Shape: Amazon Developer Hackathon 2026* — **Ring track**, plus the **AWS Builder** mini challenge.

- Demo video (under 3 minutes): https://youtu.be/_DTcUaVQPgE
- License: MIT

![Architecture](docs/architecture.png)

---

## Why

AI agents are starting to run real homes. Two questions decide whether that is safe:

1. **Who is the agent allowed to obey?** → Only the owner whose Ring account was verified, signed in with MFA.
2. **Can it prove what it actually did?** → An API saying "accepted" proves nothing. Here a command counts as executed only when the owner's enrolled Mac returns a receipt for that exact command, device and action.

## What is real and what is simulated

| Part | Status |
|---|---|
| Ring Developer Playground API (`/v1/users/me`, `/v1/devices`) | **Real calls**, Playground **sandbox** account and token |
| AWS chain: API Gateway, Lambda (our MCP server), Cognito (MFA + PKCE), DynamoDB, KMS, Secrets Manager | **Real deployment** (CloudFormation) |
| Owner's Mac worker (Ed25519-signed fetch and receipt) | **Real**, running in *software-direct / reduced-assurance* mode |
| Seven home devices and the ESP32-C3 "gateway" in the local console | **Software simulations** — no physical devices are controlled |
| Physical Ring device | Not used (the rules do not require one) |

## How a command flows

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

## Where Ring and AWS are called in code

| What | File |
|---|---|
| Ring `GET /v1/users/me` (owner verification, Lambda) | `cloud/aws/ring-private/ring-token-client.mjs`, used by `cloud-owner-bootstrap.mjs` |
| Ring `GET /v1/devices` (read-only discovery, local console) | `src/ring_official_client.mjs` |
| Ring event history probe (read-only) | `src/ring_official_history_client.mjs` |
| MCP tools `home_device.command` / `home_device.result` | `cloud/aws/ring-private/b02-layer-runtime.mjs`, contract in `src/formal-runtime/mac-command-contract.mjs` |
| Command queue, claim, receipt (DynamoDB) | `cloud/aws/ring-private/mac-command-service.mjs`, `mac-command-store.mjs` |
| Mac worker (fetch / verify / apply / receipt) | `vendor_mac_launcher/` (`mac-worker.mjs`, `vendor/mac-command-worker.mjs`, `vendor/home-device-port.mjs`) |
| Infrastructure | `cloud/aws/ring-private/template.yaml`, `bootstrap-template.yaml` |

## AWS integration (AWS Builder)

| Service | Role in the project |
|---|---|
| Amazon API Gateway (REST, regional, TLS 1.2+ security policy, throttled) | Endpoints used in the demo: `/mcp`, `/auth/*`, `/owner/bootstrap`, `/mac/enroll`, `/mac/commands/fetch`, `/mac/commands/receipt`, `/.well-known/oauth-protected-resource`. Legacy account-link routes (`/ring/token`, `/ring/link`, `/ring/complete`, `/ring/webhook`) are deployed but not part of the demonstrated flow. |
| AWS Lambda (Node.js 24, arm64) + layer | Our MCP server and the owner / Mac endpoints; the layer holds pinned approval files |
| Amazon Cognito | Owner sign-in: managed login, MFA required, PKCE public client, 5-minute access tokens, MCP resource-server scopes |
| Amazon DynamoDB | Identity links and latches, single-slot command mailbox, receipts, Mac enrollments, proof nonces, anti-rollback witness |
| AWS KMS | Table and secret encryption; Ring account ids are envelope-sealed before storage |
| AWS Secrets Manager | Provider and HMAC digest secrets, pinned to exact versions |
| AWS CloudFormation, Amazon S3, IAM | Gated change-set deployments, pinned build artifacts, least-privilege deployer and runtime roles |

The MCP server also pins its API Gateway id, stage, domain and function in an admission file and checks every request against it; when a request carries a different deployment id it is rejected, so a redeploy requires an explicit re-admission.

---

## Run it locally

Requirements: **macOS** (clipboard import uses `/usr/bin/pbpaste`) and **Node.js ≥ 20.11**. No `npm install` is needed for the local console.

```bash
git clone https://github.com/jiarong0423/ring-home-mcp-hub.git
cd ring-home-mcp-hub
```

The local server listens on **127.0.0.1 only** (default port 8765). Nothing on the internet can connect to it.

### A. Simulator only (no accounts needed)

```bash
npm start
```

Open http://127.0.0.1:8765, log in with the one-time passcode printed in the terminal, pair a device (6-digit simulated code) and control it. All seven devices are simulated; every action is audited.

### A2. Use the console from your phone (pair once)

With the server from A running, the terminal prints `ADMIN phone pairing code: dddd dddd` (10 minutes, single use).

1. Make the phone reach the Mac's loopback port: `adb reverse tcp:8765 tcp:8765` (USB or wireless adb).
2. On the phone open `http://127.0.0.1:8765/`, choose **Pair this phone**, enter the code and a name.
3. Type `y` in the Mac terminal. The phone opens the console; from then on it opens directly and stays signed in. It stays trusted until you remove it.
4. Family: in the console's **Family phones** panel press **Add a family phone** and repeat steps 1–3 on their phone. Family phones run everyday devices; unlock, disarm and settings stay with admins. **Remove** revokes a phone immediately.

Pairings are stored as hashes in `~/.home-mcp-console/phones.json` (override with `HOME_MCP_PHONE_STORE`).

### A3. Home guardian for an older relative (low-frequency heartbeats, alerts, daily routine)

The console's **Home guardian** panel (first on the dashboard) watches the Ring camera and the home gateway with low-frequency heartbeats (camera every 5 minutes, gateway every 60 seconds) and runs a daily routine (lights, dehumidifier, AC, alarm) instead of someone pressing buttons remotely. Every run ends as ✓ confirmed (receipt), ✗ not done, or ? cannot confirm; a run missed while the gateway was down is **not** made up automatically — a family member taps **Do it now**. Alerts appear only when something changes (late → offline → back online).

Demo a whole day in minutes (the clock only affects the guardian; codes and sessions keep real time):

```bash
HOME_MCP_CLOCK_SPEED=60 HOME_MCP_CLOCK_START=06:58 npm start
```

Ring camera status is real (`GET /v1/devices/{id}/status`) while a Playground token is loaded (`RING_ACCESS_TOKEN=... npm start`, about 30 minutes); without a token the camera is simulated.

**Email alerts (optional, Amazon SNS):** deploy `cloud/aws/notify/notify-template.json` (one SNS topic + email subscription, a CloudWatch alarm that fires when the hub stops sending its heartbeat, and a least-privilege IAM user). Create that user's access key yourself, store it with `aws configure --profile home-mcp-notify`, then start with `HOME_MCP_NOTIFY_SNS_TOPIC_ARN=... HOME_MCP_NOTIFY_AWS_PROFILE=home-mcp-notify`. The hub calls the AWS CLI and never handles the key.

### A4. Opening the door: the AI asks, the admin phone approves (SIMULATED)

The Ring Partner API has no lock control, so the front door is simulated and labelled SIMULATED everywhere. Opening it never
happens directly. An AI agent over local MCP (`device_front_door` `unlock`), a family phone or the console can only **ask**.
The answer is `pending_approval`. The paired **admin phone** then shows a banner for 60 s with **Approve / Deny** and a Ring door
snapshot. Approving needs that phone's own long-lived credential (kept in the phone's browser), not just a session token, so an
agent holding a session cannot approve itself. One request at a time; single use; expiry, denial and gateway failure are all
recorded on the guardian timeline (email for "someone is asking" and "it was opened", never with the image).

- Snapshot: with a Playground token loaded, the hub calls Ring's Image Snapshots API (`POST /v1/devices/{id}/media/image/download`,
  `latest_in_range`, 303 to a short-lived URL; the Ring token is never sent to that URL). It is kept in memory for the life of the
  request and shown to the admin phone only. Without a token, a stand-in image labelled SIMULATED is shown with the reason.
- Cloud, schedules and batches still cannot unlock.
- Optional **face hint** (OpenCV YuNet + SFace, on the Mac): the admin phone may enrol a person (e.g. the carer) only with a
  separate "this person agreed" tick. The hub keeps an AES-256-GCM encrypted 128-number feature, never the photo; delete one
  person or everyone at any time. On a real Ring snapshot the banner then says "looks like <name>" or "not enrolled". It is a
  hint only and never opens the door. Turn it on with `HOME_MCP_FACE_PYTHON` (a Python with `opencv-python-headless`) and
  `HOME_MCP_FACE_MODELS` (folder with `face_detection_yunet_2023mar.onnx` and `face_recognition_sface_2021dec.onnx` from
  opencv_zoo); without them it says "off" and approval works the same.

### B. Ring Developer Playground, read-only (your own Ring developer account)

```bash
npm run start:ring-playground
```

1. Log in with the printed **demo passcode**.
2. In *Ring official device discovery*, enter the printed **operator code**.
3. In the Ring Developer Playground, generate a token and copy it.
4. Click **Import token from local clipboard** — the token goes straight into server memory; the page never sees it.
5. Enter the operator code again and click **Query Ring devices manually**. You get a de-identified device count; nothing is paired or operated.

Playground tokens expire after about 30 minutes; generate a fresh one if you see HTTP 401.

### C. Full cloud chain (requires your own AWS stack — see below)

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

### Tests

```bash
npm test                  # local console + simulator + Ring client (offline fakes) + cloud panel against a fake cloud
npm run test:mac-worker   # Mac worker: keygen, PKCE, signed fetch/receipt, home_device flow against a fake cloud
```

Cloud tests live in `cloud/aws/ring-private/tests` (run `npm ci` there first; some tests need `RING_TRANSPORT_TEST_ROOT=/private/tmp/<dir>`).

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
5. Create the single Cognito owner user (MFA), then run the owner ceremony from section C.

Everything account-specific (account id, region, API id, Cognito ids, Ring account pin, Mac key) is a parameter — nothing is hard-coded.

## Security model

- **Owner only:** Cognito MFA + PKCE, plus a Ring account pinned to the owner; single owner, admin-created users only.
- **Short-lived by design:** 5-minute access tokens, 30-second commands, owner association and Mac enrollment approvals of at most 24 hours.
- **Single use:** idempotent command ids, one command in flight per owner, single-use approval latches, Ring token replay markers, proof nonces.
- **Evidence, not acceptance:** `executed=true` requires a receipt that matches the claim token, envelope hash, enrolled Mac key and the exact device/action.
- **Door safety:** no unlock or disarm from the cloud; local unlock needs a one-use confirmation.
- **Local isolation:** the console binds to 127.0.0.1, requires a separate operator code for every Ring action and once per cloud login (rate-limited), and never sends tokens, codes or the Mac key passphrase to the browser. The Mac worker only makes outbound requests — it opens no inbound port.

See `SECURITY.md` and `THREAT_MODEL.md`.

## Limitations (honest scope)

- The Ring side uses the **Ring Developer Playground sandbox**; production Ring account linking was not available to our account.
- The seven home devices are **software simulations**; six accept allowlisted cloud actions.
- The Mac worker runs in **software-direct, reduced-assurance mode** (no local Wi-Fi trust or anti-rollback re-check on the Mac).
- Approvals are short-lived and renewed by an operator ceremony; there is no automatic renewal yet.
- Some legacy modules from earlier iterations (e.g. `telegram-*`, account-link routes) remain in the code but are not part of the demonstrated flow.

## Product feedback for Ring

Submitted on Devpost; highlights: Playground tokens last ~30 minutes and an expired token returns a bare HTTP 401; the sandbox offers read-only discovery but no controllable simulated device; account linking was unavailable for a non-US developer account.

## Built during the hackathon

Started on 2026-09-29, inside the submission window.

## License

MIT — see [LICENSE](LICENSE).
