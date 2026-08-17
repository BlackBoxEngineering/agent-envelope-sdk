# AgentEnvelope Glossary

## Action Envelope

The complete immutable permission input for one deterministic action key: agent id, domain
reference, operation, resources, action index, time window, decay policy, and limits.

## Action Seed

Private 32-byte signing material derived for one action envelope. It is represented in exported
capabilities as `actionSeedHex`. It must not be published or stored by hosted services.

## Agent Address

The EVM-style address derived from an action seed. It is the public identity a verifier recovers
from an action signature.

## Attestation

A hosted verifier signature over its own receipt. Attestation is additive and not required for
offline verification.

## Capability

Private action authority handed to a worker or bot. A capability contains the action seed or enough
private material to derive it locally.

## Domain

A stable authority branch scoped to a class of work, such as communication, lookup, operations, or
a custom purpose.

## Domain Projection

The public, seedless summary of a domain: canonical domain info, domain hash, domain address, and
domain fingerprint.

## Derived Authority

Authority produced deterministically from customer-held secret material and canonical permission
inputs, rather than issued as a bearer credential by a central service.

## Hosted Governance

The optional AgentEnvelope service layer for public records, mint receipts, verification events,
audit trails, billing, API-keyed metering, and policy controls.

## Mint Delegate

A domain-signed permit that lets a bot request bounded action capabilities without touching the
vault root or domain seed.

## Mint Material

Private 32-byte material derived from the identity root and domain hash. It lets a delegated bot
derive the action seed after a valid mint request.

## Mint Request

A bot-signed request for an action capability within the bounds of a MintDelegate.

## Public Action Record

Verifier-safe metadata binding an agent address to a domain projection and exact action envelope.

## Sovereign Verification

Offline verification of a payload signature against a public action record. It requires no account,
API key, network, hosted verifier, or AgentEnvelope service availability.

## Vault

The custody boundary holding the identity root. In browser-held mode, the root is encrypted locally
and the passphrase never leaves the browser.
