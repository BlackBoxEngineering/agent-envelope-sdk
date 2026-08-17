# AgentEnvelope Authority Model

This document is informative. The normative protocol rules live in
[agent-envelope-v1.md](./agent-envelope-v1.md).

AgentEnvelope is an authority layer for anything that performs an action.

The model is:

```text
vault -> domain -> action envelope -> capability -> public record -> verification
```

## Layers

| Layer | Role |
| --- | --- |
| Vault | Holds the customer root. The root never leaves custody. |
| Domain | Scopes authority to a class of work. |
| Action envelope | Defines the exact operation, resources, time window, decay, and limits. |
| Capability | Private signing material for that exact action envelope. |
| Public record | Seedless verifier metadata. |
| Verification | Checks that a signed payload matches the public authority boundary. |

## The Category

AgentEnvelope defines derived authority for action-performing systems.

Instead of asking:

```text
What token was issued to this runtime?
```

it asks:

```text
Was this exact action derived from the correct authority boundary?
```

## Sovereign And Hosted Modes

Sovereign mode runs locally with no account, no API key, no network, and no hosted dependency.

Hosted governance adds public records, mint receipts, verification events, audit trails, API-keyed
metering, and future team controls. Hosted governance does not create agent authority; it verifies,
records, meters, and audits it.

## Non-Negotiable Invariants

Offline verification must always work without AgentEnvelope.

Hosted Lambda functions must never derive or hold customer roots, passphrases, domain seeds, action
seeds, mint material, or private capabilities.

Neither invariant should be weakened by future product or protocol work.
