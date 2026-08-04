# Security Model

This document describes the security boundaries of the AgentEnvelope SDK.

## What the SDK is

The SDK is a **stateless cryptographic toolkit** released under Apache 2.0. It provides:

- Deterministic key derivation (HKDF-SHA256)
- Signature creation and verification (secp256k1 + keccak256)
- Canonical JSON serialisation
- Structured message types (delegates, requests, envelopes, receipts)

The SDK runs offline, requires no account, and has no network dependencies. It is the
**sovereign cryptographic substrate** — you can build your own authority layer on top, or use AgentEnvelope's hosted governance at [agentenvelope.io](https://agentenvelope.io) as the optional managed layer.

## What the SDK is not

The SDK is **not** an authority layer, a governance engine, or a policy enforcer. It is
cryptographic primitives. If you need governance, you either build it yourself or use the
hosted product.

| Responsibility | Where it lives |
|----------------|----------------|
| Issuing delegates | The vault owner, via the browser console |
| Choosing bot policy | The delegate issuer (`any-signed-bot` vs `address-set`) |
| Enforcing `maxUses` | The verifier (caller in sovereign mode, hosted API in governed mode) |
| Enforcing `maxMints` | The hosted API |
| Nonce replay prevention | The hosted API |
| Revoking capabilities | The governance layer (time windows, API key rotation, record status) |

## Architectural boundaries

### Delegates require a vault-signed issuer

A `MintDelegate` is only valid if it carries a signature from a real domain issuer. The domain issuer address is derived from the vault root, which only the vault owner holds. Without a legitimate delegate, a bot signature has no standing — there is nothing to mint against.

### `any-signed-bot` is a policy choice, not a vulnerability

When a delegate issuer chooses `any-signed-bot`, they are explicitly allowing open bot enrollment. Any bot that can produce a valid signature may mint within the delegate's bounds. This is intentional. If the issuer wants to restrict minting to specific bots, they use `address-set` policy with `allowedBotAddresses`.

### `maxUses` enforcement requires state

The SDK is stateless. It cannot track how many times a capability has been used because that requires persistent storage. Usage enforcement is the responsibility of the verifier:

- In **sovereign mode**, the caller is their own verifier and must track usage themselves.
- In **portal-governed mode**, the hosted API enforces `maxUses`, `maxMints`, and nonce replay.

Using the SDK offline without a verifier will always permit unrestricted signing. This is the documented behaviour of sovereign mode — you are your own authority, and you are responsible for enforcement.

If you want turnkey enforcement, use the hosted governance layer. If you want full control, build your own verifier. The SDK supports both paths.

### The SDK honours the issuer's policy

The SDK does not second-guess the delegate issuer. If the issuer granted a capability, the SDK will derive and sign according to that grant. Policy decisions are made at issuance time in the vault, not at signing time in the SDK.

## Threat model summary

| Threat | Mitigation |
|--------|------------|
| Rogue bot mints without authorisation | Impossible without a vault-signed delegate |
| Attacker exhausts `maxUses` | Verifier enforcement (hosted API or caller) |
| Attacker replays a nonce | Hosted API nonce tracking |
| Stolen capability used after expiry | Time window decay checked at verification |
| Compromised bot key | `address-set` policy limits blast radius; revoke delegate or rotate API key |

## Responsible disclosure

If you believe you have found a security issue outside this model, please contact security@agentenvelope.io. We respond within 48 hours.
