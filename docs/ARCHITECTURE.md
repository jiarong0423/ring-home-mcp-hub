# Architecture

Four views of Home MCP Guardian, kept in sync with the code (file names in the boxes are real). GitHub renders these Mermaid diagrams directly.

1. [System](#1-system) — what runs where
2. [Door approval](#2-door-approval) — the AI asks, a phone decides, Ring live view on the banner
3. [Remote approval](#3-remote-approval-family-relay) — approving from outside the home through the AWS family relay
4. [Guardian](#4-guardian) — how "something quietly stopped" is detected

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
  RING["Ring API, Playground token in hub memory<br/>devices, status, Event History,<br/>Image Snapshots, Live Video (WHEP)"]
  subgraph NOTIFY["AWS stack home-mcp-notify"]
    SNS["Amazon SNS email"]
    CW["CloudWatch alarm<br/>home-mcp-hub-silent"]
    BR["Amazon Bedrock<br/>Claude Sonnet 4.5"]
  end
  subgraph RELAY["AWS stack home-mcp-family-relay"]
    FURL["Lambda function URL"]
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
  HUB -- "Ed25519-signed messages" --> FURL
  FP -. "away from home: P-256-signed answer" .-> FURL
  FURL --> DDB
```

## 2. Door approval

The approving phone is the admin phone, or a phone the admin enabled for remote approval (section 3).

```mermaid
sequenceDiagram
  participant A as AI agent, Ring doorbell or family phone
  participant H as Hub (server.mjs)
  participant D as door_requests.mjs
  participant R as Ring API
  participant P as Admin phone
  participant L as Door lock (SIMULATED)
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
  participant H as Hub (remote_relay.mjs)
  participant F as Relay (Lambda function URL)
  participant T as DynamoDB (TTL)
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
```
