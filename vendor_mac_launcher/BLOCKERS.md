# Reduced-assurance mode (what the Mac worker does and does not check)

The Mac worker runs in **software-direct** mode. It was used end to end against the real AWS deployment in the demo (owner bootstrap/renewal, Mac enrollment, `home_device.command` with `executed=true`).

## Checked on the Mac
- Command schema, 30-second expiry, owner and association revision equal to the enrolled identity.
- Allowlist (`homeDeviceAllowed`) and exact envelope arguments.
- Claim token format; local journal so a command is applied at most once.
- Every fetch and receipt is signed with the enrolled Ed25519 key (request proof with nonce, ≤ 15 s).
- Mac clock must not be behind the command's issue time (refused before any side effect).
- `home_device.command` is applied only through the local console (owner session, pairing, immediate apply, never queued).

## Not checked on the Mac (relies on the cloud's checks)
- A full local formal runtime with grant issue/consume, local anti-rollback witness, household Wi-Fi trust and a Mac-local copy of the owner association.

Every run prints `mode: "software-direct"` so this mode cannot be mistaken for the full path. Closing these gaps needs a Mac-local authorization server and owner-approved local association state; that is future work.
