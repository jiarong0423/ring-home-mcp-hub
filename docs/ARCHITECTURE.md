# Architecture

Five views of Home MCP Guardian, kept in sync with the code (file names in the boxes are real). GitHub renders these Mermaid diagrams directly. A one-page overview drawn for the README is [`system-overview.png`](system-overview.png) (source: [`diagrams/system-overview.html`](diagrams/system-overview.html)).

1. [System](#1-system) — what runs where
2. [Door approval](#2-door-approval) — the AI asks, a phone decides, Ring live view on the banner
3. [Remote approval](#3-remote-approval-family-relay) — approving from outside the home through the AWS family relay
4. [Guardian](#4-guardian) — how "something quietly stopped" is detected
5. [Ring webhooks and Chime](#5-ring-webhooks-and-chime) — Ring events for a hub behind NAT, and announcements on a Ring Chime

The earlier phase of the project (a cloud MCP chain with Cognito, API Gateway and a Mac worker that returns signed receipts) is shown in [`architecture.png`](architecture.png) and described in the README.

## 1. System

```mermaid
flowchart TB
  subgraph PEOPLE["People and agents"]
    AP["Admin phone (browser)"]
    FP["Family phone (browser)"]
    AG["AI agent (any MCP client)"]
  end
  subgraph MAC["Mac at home, 127.0.0.1 only"]
    HUB["Home hub: src/server.mjs<br/>local MCP /mcp, pairing with a macOS dialog,<br/>door requests, guardian, voice notice,<br/>face hint (OpenCV), daily care note"]
    SIM["SIMULATED: 7 devices,<br/>home gateway, door lock"]
  end
  RING["Ring API, Playground token in hub memory<br/>devices, capabilities, status, Event History,<br/>Image Snapshots, Live Video (WHEP), Chime playback"]
  subgraph NOTIFY["AWS stack home-mcp-notify"]
    SNS["Amazon SNS email"]
    CW["CloudWatch alarm<br/>home-mcp-hub-silent"]
    BR["Amazon Bedrock<br/>Claude Sonnet 4.5"]
  end
  subgraph RELAY["AWS stack home-mcp-family-relay"]
    FURL["Lambda function URL<br/>/relay/* and /ring/webhook"]
    DDB["DynamoDB table (TTL)"]
  end
  AP -- "approve / deny, Ring live view" --> HUB
  FP -- "ask to open the door" --> HUB
  AG -- "MCP tools/call: unlock is only a request" --> HUB
  HUB -- "commands, receipts, heartbeats" --> SIM
  HUB -- "Bearer token" --> RING
  HUB -- "alerts" --> SNS
  HUB -- "HubHeartbeat every 5 min" --> CW
  CW -- "ALARM / OK" --> SNS
  HUB -- "converse (day's facts only)" --> BR
  HUB -- "Ed25519-signed messages,<br/>Ring events pulled every 10 s" --> FURL
  FP -. "away from home: P-256-signed answer" .-> FURL
  RING -. "partner webhooks, X-Signature HMAC<br/>(needs partner credentials)" .-> FURL
  FURL --> DDB
  classDef people fill:#ffffff,stroke:#4a6073,color:#0f1720
  classDef hub fill:#e3f7ef,stroke:#1f9e78,stroke-width:2px,color:#0f1720
  classDef sim fill:#eef1f4,stroke:#8a9aa8,stroke-dasharray:4 3,color:#0f1720
  classDef ring fill:#e3f2fc,stroke:#1a8fd6,stroke-width:2px,color:#0f1720
  classDef aws fill:#fff1dc,stroke:#e68a00,color:#0f1720
  class AP,FP,AG people
  class HUB hub
  class SIM sim
  class RING ring
  class SNS,CW,BR,FURL,DDB aws
  style MAC fill:#f3fbf8,stroke:#1f9e78
  style NOTIFY fill:#fffaf2,stroke:#e68a00
  style RELAY fill:#fffaf2,stroke:#e68a00
  style PEOPLE fill:#f7f9fb,stroke:#a9b8c6
```

## 2. Door approval

The approving phone is the admin phone, or a phone the admin enabled for remote approval (section 3).

```mermaid
sequenceDiagram
  participant A as AI agent, Ring doorbell or family phone
  box rgba(31,158,120,0.12) Mac at home
    participant H as Hub (server.mjs)
    participant D as door_requests.mjs
    participant L as Door lock (SIMULATED)
  end
  box rgba(26,143,214,0.12) Ring
    participant R as Ring API
  end
  participant P as Admin phone
  A->>H: device_front_door unlock (MCP) or door request
  H->>D: request (one at a time, 60 s)
  H-->>A: pending_approval
  H->>R: POST /v1/devices/{id}/media/image/download
  R-->>H: 303 to a short-lived image URL (kept in memory)
  H-)P: banner with Ring snapshot and face hint
  opt Ring live view
    P->>H: POST /api/door/live with the browser's SDP offer
    H->>R: POST /v1/devices/{id}/media/streaming/whep/sessions with the token
    R-->>H: SDP answer
    H-->>P: SDP answer (the token never leaves the hub)
  end
  P->>H: POST /api/door/decide with this phone's credential
  H->>H: credential checked and rotated (a reused one revokes the phone)
  H->>D: decide approve
  D->>L: simulated unlock
  L-->>D: receipt (or failed when the gateway is down)
  H->>R: DELETE the WHEP session
  H-)A: approved, timeline, email and voice notice
```

## 3. Remote approval (family relay)

The cloud only passes messages. The hub signs everything it sends with its Ed25519 key (public key pinned in the stack); each phone signs with its own non-extractable WebCrypto P-256 key; the hub verifies the phone's signature with the key it stored itself before anything opens.

```mermaid
sequenceDiagram
  participant AP as Admin phone
  box rgba(31,158,120,0.12) Mac at home
    participant H as Hub (remote_relay.mjs)
  end
  box rgba(230,138,0,0.12) AWS
    participant F as Relay (Lambda function URL)
    participant T as DynamoDB (TTL)
  end
  participant FP as Enabled phone (/family page)
  AP->>H: Enable remote approval
  H->>F: op code (hash of a one-time code, signed by the hub)
  F->>T: store, expires in 10 min
  H-->>AP: one-time link to the family page
  FP->>FP: create a P-256 key in the browser (IndexedDB)
  FP->>F: op register with the code and public key (signed by the phone)
  H->>F: op poll
  F-->>H: registration
  H->>F: op activate (hub stores the phone's public key)
  Note over H,FP: later, a door request at home
  H->>F: op request (text only: who asks, seconds left)
  FP->>F: op pending
  FP->>F: op decide approve (signed by the phone)
  H->>F: op poll
  F-->>H: signed decision
  H->>H: verify with the stored phone key, then decide
  H->>F: op result
```

## 4. Guardian

```mermaid
stateDiagram-v2
  state "Home gateway: heartbeat every 60 s" as GW {
    online --> late: no heartbeat for 3 min
    late --> offline: 5 min, email
    late --> online: heartbeat
    offline --> online: heartbeat, recovered email
  }
  state "Ring camera: device status every 5 min" as CAM {
    cam_online --> cam_late: 1 failed check
    cam_late --> cam_offline: 2 failed checks, email
    cam_offline --> cam_online: status ok, recovered email
  }
  state "Daily routine step" as RUN {
    pending --> confirmed: receipt
    pending --> not_executed: gateway offline or refused
    pending --> unknown: no receipt
    pending --> not_monitored: first seen over 60 min late
    not_executed --> confirmed: family taps Do it now
    unknown --> confirmed: retry
  }
  state "Hub itself" as HUBS {
    beating --> silent: no HubHeartbeat metric (CloudWatch alarm)
    silent --> beating: metric resumes, OK email
  }
  classDef good fill:#e3f7ef,stroke:#1f9e78,color:#0f1720
  classDef warn fill:#fff6d6,stroke:#c9a227,color:#0f1720
  classDef bad fill:#fde6e3,stroke:#d0493a,color:#0f1720
  class online, cam_online, confirmed, beating good
  class late, cam_late, unknown, not_monitored, pending warn
  class offline, cam_offline, not_executed, silent bad
```

## 5. Ring webhooks and Chime

A hub at home sits behind NAT, so Ring's partner webhooks go to the relay's public `POST /ring/webhook`, and the hub pulls them over its signed channel. Real Ring deliveries need partner credentials with account linking, which our developer account does not have; this path was tested against the live relay with signed events shaped like Ring's documented examples (0.7–2.5 s from delivery to the hub). The Playground has no Chime: finding devices and their capabilities ran on the real Ring API, and playback is tested against the documented responses.

```mermaid
sequenceDiagram
  box rgba(26,143,214,0.12) Ring
    participant R as Ring (partner webhooks)
  end
  box rgba(230,138,0,0.12) AWS
    participant F as Relay (Lambda function URL)
    participant T as DynamoDB (TTL 24 h)
  end
  box rgba(31,158,120,0.12) Mac at home
    participant H as Hub (remote_relay.mjs, server.mjs)
  end
  box rgba(26,143,214,0.12) Ring
    participant C as Ring API (Chime)
  end
  R->>F: POST /ring/webhook with X-Signature sha256=HMAC of the raw body
  F->>F: check the HMAC (constant time), drop a repeated meta.request_id
  F->>T: keep only type, sub-type, device id and time
  F-->>R: 200 (503 on storage trouble so Ring retries, 4xx for bad input)
  loop every 10 s with HOME_MCP_RING_WEBHOOKS=on
    H->>F: op ringEvents after n (Ed25519-signed)
    F-->>H: up to 20 newer events (the first pull only records the position)
  end
  alt button_press or a person, under 2 minutes old
    H->>H: door request, as in section 2
  else device_offline or device_online
    H->>H: guardian camera state changes at once, one email each way
  end
  opt HOME_MCP_CHIME=on, a Ring token loaded and a Chime found by its capabilities
    H->>C: GET /v1/devices/{id}/status (skip when offline or snoozed)
    H->>C: GET /v1/devices/{id}/configurations (first enabled audio slot)
    H->>C: POST /v1/devices/{id}/media/audio/playback with its audio_ref
    C-->>H: status completed (the Mac voice speaks as well)
  end
```

The same mailbox is published on its own as an MIT project, [ring-webhook-mailbox](https://github.com/jiarong0423/ring-webhook-mailbox) (CloudFormation template, client, tests).
