# AgentEnvelope v1: Derived Authority Specification

Status: Draft 2026-08-17  
Author: Matthew McPhillips  
Canonical namespace: `agentenvelope`  
Canonical publication: `agent-envelope-sdk` repository
Reference implementations: `agent-envelope-sdk` for open SDK primitives; `agent-envelope` and
`agent-envelope-web` for hosted governance and browser-held custody flows

## Abstract

AgentEnvelope v1 defines a deterministic authority protocol for systems that perform actions:
AI agents, bots, workflow steps, microservices, devices, orders, instructions, access grants, and
distributed systems.

AgentEnvelope authority is derived from customer-held custody material, not issued by a hosted
service. A verifier can check an action signature against a public action record without receiving
the vault root, passphrase, domain seed, action seed, mint material, or any private signing
material.

## Status Of This Document

This document is normative for AgentEnvelope v1 unless a section is explicitly marked
informative. The key words `MUST`, `MUST NOT`, `REQUIRED`, `SHOULD`, `SHOULD NOT`, and `MAY` are to
be interpreted as described in RFC 2119 and RFC 8174.

## Design Goals

AgentEnvelope v1 has these goals:

- derive authority rather than issue bearer credentials;
- keep roots, seeds, and private action material inside customer custody boundaries;
- bind action authority to a complete canonical action envelope;
- allow stateless signature verification from public records;
- keep hosted governance additive, never required for offline verification;
- preserve isolation between domains, actions, and mint-delegated capabilities.

## Cryptographic Primitives

Implementations MUST use:

| Purpose | Primitive |
| --- | --- |
| Key derivation | HKDF-SHA256 |
| Derivation salt | `agentenvelope-v1` |
| Message hash | keccak-256 over UTF-8 bytes |
| Signatures | secp256k1 |
| Content hash | SHA-256 |
| Address format | `0x` + last 20 bytes of keccak-256 of the uncompressed secp256k1 public key without the leading format byte |

All byte strings used as private seeds in v1 MUST be 32 bytes.

v1 `keccak-256` is the Keccak-256 function used by Ethereum address and signature ecosystems
(original Keccak padding), not the FIPS 202 SHA3-256 variant. Implementations MUST NOT substitute
SHA3-256 where v1 specifies keccak-256.

If a 32-byte seed is not a valid secp256k1 scalar, implementations MUST transform it to a valid
scalar using the v1 `seedToKey` retry behavior: HKDF-SHA256 with the same salt and info string
`key`, retrying no more than 8 times. Implementations SHOULD expose this through the SDK function
rather than by duplicating low-level logic.

## Canonical JSON

All derivation, content hash, and signing inputs MUST use canonical JSON:

- object keys sorted lexicographically;
- recursive object canonicalization;
- array order preserved;
- normal JSON encoding for primitives;
- no added whitespace.

To avoid cross-runtime numeric ambiguity, v1 derivation, content hash, and signing inputs MUST NOT
contain floating-point JSON numbers. Numeric values in those inputs MUST be integers represented in
canonical decimal form, without exponent notation, leading plus signs, insignificant fractional
components, or negative zero. Where a value cannot be represented safely and interoperably as an
integer, it SHOULD be represented as a string.

v1 canonical JSON is not the JSON Canonicalization Scheme (RFC 8785). v1 interoperability is
defined by this section and the published v1 test vectors.

Example:

```json
{"z":1,"a":{"y":2,"x":3}}
```

canonicalizes to:

```json
{"a":{"x":3,"y":2},"z":1}
```

Unknown fields in normative v1 objects MUST be rejected by strict schema validators when they would
alter derivation or verification meaning.

## Signing Prefixes

Every signature domain MUST use the following exact UTF-8 prefix before canonical JSON:

| Object | Prefix |
| --- | --- |
| Action payload | `\x19AgentEnvelope Signed Message:\n` |
| MintDelegate body | `\x19AgentEnvelope Mint Delegate:\n` |
| MintRequest body | `\x19AgentEnvelope Mint Request:\n` |
| Attestation receipt | `\x19AgentEnvelope Attestation:\n` |

The signed hash is:

```text
keccak256(utf8(prefix + canonicalJSON(body)))
```

The signature format MUST be `0x` + 32-byte `r` + 32-byte `s` + 1-byte recovery id encoded as
`27` or `28`.

## Identifier Rules

The following fields MUST be normalized by trimming and lowercasing before canonicalization:

- `DomainInfo.namespace`
- `DomainInfo.domainId`
- `DomainInfo.kind`
- `ActionEnvelope.agentId`
- `ActionEnvelope.operation`
- `ActionEnvelope.resources[]`

Identifiers except resources MUST match:

```text
^[a-z0-9][a-z0-9._:-]{0,127}$
```

Resources MUST be normalized, deduplicated, and sorted before inclusion in an `ActionEnvelope`.

## Authority Tree

AgentEnvelope v1 defines this authority path:

```text
identityRoot -> domainSeed -> actionEnvelope -> actionSeed -> agentAddress
```

The public projection is:

```text
domain public summary + action envelope + action envelope hash + agent address
```

The public projection MUST NOT include `identityRoot`, passphrases, `domainSeed`, `actionSeed`,
`actionSeedHex`, `mintMaterial`, or private keys.

## DomainInfo

`DomainInfo` is the immutable canonical input for deriving a domain seed.

```ts
interface DomainInfo {
  type: 'agentenvelope.domainInfo'
  version: 1
  namespace: string
  domainId: string
  kind: string
}
```

The domain seed MUST be derived as:

```text
HKDF-SHA256(
  ikm = identityRoot,
  salt = "agentenvelope-v1",
  info = canonicalJSON({ purpose: "domain", domainInfo }),
  length = 32
)
```

The domain hash MUST be:

```text
SHA-256(canonicalJSON(domainInfo))
```

encoded as `0x`-prefixed lowercase hex.

The domain address MUST be the v1 secp256k1 address of `domainSeed`.

The domain fingerprint MUST be:

```text
"ae-domain-" + first16Hex(SHA-256(canonicalJSON({ domainAddress, domainHash })))
```

## Domain Projection

A domain projection has this shape:

```ts
interface DomainProjection {
  domainInfo: DomainInfo
  canonicalDomainInfo: string
  domainHash: string
  domainAddress: string
  domainFingerprint: string
  createdAt: string
}
```

`createdAt` is metadata. It MUST NOT enter key derivation.

## ActionEnvelope

`ActionEnvelope` is the complete immutable permission input for one deterministic action key.

```ts
type DecayMode = 'NONE' | 'TIME' | 'ACTION' | 'BOTH'
type UsageEnforcement = 'external'

interface ActionEnvelope {
  type: 'agentenvelope.actionEnvelope'
  version: 1
  agentId: string
  domain: { domainId: string; domainHash: string }
  actionIndex: number
  operation: string
  resources: string[]
  timeWindow: { notBefore: number | null; notAfter: number | null }
  decayPolicy: { mode: DecayMode }
  limits: { maxUses: number | null; enforcement: UsageEnforcement }
}
```

Validation rules:

- `domain.domainHash` MUST match the selected domain projection.
- `domain.domainId` MUST match the selected domain projection.
- `actionIndex` MUST be a non-negative integer.
- `operation` MUST be one normalized operation identifier.
- `resources` MUST contain at least one resource.
- `TIME` and `BOTH` decay MUST include at least one finite time boundary.
- `ACTION` and `BOTH` decay MUST include a positive integer `maxUses`.
- `maxUses: null` is valid only for `NONE` or `TIME`.
- If both `notBefore` and `notAfter` are present, `notAfter` MUST be greater than `notBefore`.
- v1 public action envelopes MUST use `limits.enforcement: "external"`.

The action envelope hash MUST be:

```text
SHA-256(canonicalJSON(actionEnvelope))
```

encoded as `0x`-prefixed lowercase hex.

The action seed MUST be derived as:

```text
HKDF-SHA256(
  ikm = domainSeed,
  salt = "agentenvelope-v1",
  info = canonicalJSON({ purpose: "action", actionEnvelope }),
  length = 32
)
```

The agent address MUST be the v1 secp256k1 address of `actionSeed`.

## AgentActionCapability

An `AgentActionCapability` is private signing authority.

```ts
interface AgentActionCapability {
  type: 'agentenvelope.agentCapability'
  version: 1
  custodyMode: 'sovereign-browser' | 'remote-mint-delegate'
  generatedAt: string
  warning: string
  domain?: DomainProjection
  actionEnvelope?: ActionEnvelope
  canonicalActionEnvelope?: string
  actionEnvelopeHash?: string
  delegateId?: string
  requestId?: string
  agentAddress: string
  actionSeedHex: string
}
```

`actionSeedHex` is private signing material. It MUST NOT be stored in hosted workspace sync, public
records, verifier records, audit events, hosted receipts, or logs.

## PublicActionRecord

A `PublicActionRecord` is verifier-safe metadata for one action capability.

```ts
type CustodyMode = 'sovereign-browser' | 'external-custody' | 'remote-mint-delegate'

interface PublicActionRecord {
  type: 'agentenvelope.publicActionRecord'
  version: 1
  recordId: string
  ownerUserId: string
  custodyMode: CustodyMode
  verifierProfile: 'domain-action-envelope'
  status: 'active'
  createdAt: string
  agentId: string
  agentAddress: string
  domain: DomainProjection
  actionEnvelope: ActionEnvelope
  canonicalActionEnvelope: string
  actionEnvelopeHash: string
  legitimacyRef?: LegitimacyRef
  expiry: string | null
}
```

`ownerUserId`, `recordId`, `createdAt`, `legitimacyRef`, and `expiry` are metadata. They MUST NOT
enter key derivation.

Public records MUST NOT contain private signing material.

## Action Signing

Workers sign payloads with the 32-byte action seed:

```text
hash = keccak256(utf8("\x19AgentEnvelope Signed Message:\n" + canonicalJSON(payload)))
signature = secp256k1.sign(hash, actionPrivateKey)
```

The payload MAY be any JSON-serializable value. Verifiers MUST canonicalize the payload before
recovering the address.

## Verification

A verifier that holds a public action record, payload, and signature MUST check:

1. the record type and version are valid;
2. the record is active;
3. the requested `actionIndex` matches `record.actionEnvelope.actionIndex`;
4. `canonicalActionEnvelope` equals `canonicalJSON(record.actionEnvelope)`;
5. `actionEnvelopeHash` equals `SHA-256(canonicalActionEnvelope)`;
6. any supplied `expectedActionEnvelopeHash` matches the record;
7. time decay has not made the action invalid;
8. the signature is well formed;
9. the recovered signer address equals `record.agentAddress`.

These checks are stateless except time. They do not prove that a `maxUses` slot is unspent.

Usage consumption MUST be enforced by a verifier-controlled or hosted ledger when the application
requires replay or use-count protection.

## Mint Delegation

Mint delegation lets a bot request bounded action capabilities without receiving the vault root or
domain seed.

### Mint Material

The domain owner derives private mint material as:

```text
HKDF-SHA256(
  ikm = identityRoot,
  salt = "agentenvelope-v1",
  info = canonicalJSON({ purpose: "mint-material", domainHash }),
  length = 32
)
```

`mintMaterial` is private signing-equivalent material. It MUST be delivered out of band only to the
bot or service that needs the delegated authority.

### MintDelegate

`MintDelegate` is signed by the domain issuer.

```ts
type BotPolicy = 'any-signed-bot' | 'address-set'

interface MintDelegate {
  type: 'agentenvelope.mintDelegate'
  version: 1
  delegateId: string
  legitimacyRef?: LegitimacyRef
  issuerAddress: string
  avatarAddress?: string
  domainHash: string
  allowedOperations: string[]
  allowedResources: string[]
  botPolicy: BotPolicy
  allowedBotAddresses?: string[]
  actionIndexPolicy: { min: number; max: number }
  maxMints: number
  maxUsesPerAction: number
  timeWindow: { notBefore: number | null; notAfter: number | null }
  nonce: string
  issuedAt: string
  issuerSignature: string
}
```

The delegate id MUST be:

```text
"ae-delegate-" + first16Hex(SHA-256(canonicalJSON({ issuerAddress, domainHash, nonce })))
```

`issuerSignature` MUST sign the delegate body without `issuerSignature` using the MintDelegate
signing prefix.

When `legitimacyRef` is present it is part of the signed delegate body: it enters `delegateHash`
and therefore the remote-mint derivation input. `legitimacyRef.legitimacyId` MUST be a string;
`stateVersion`, when present, MUST be a positive integer; `stateHash`, when present, MUST be
`0x`-prefixed 32-byte lowercase hex.

When `botPolicy` is `address-set`, `allowedBotAddresses` MUST be present and non-empty.

### MintRequest

`MintRequest` is signed by the bot.

```ts
interface MintRequest {
  type: 'agentenvelope.mintRequest'
  version: 1
  requestId: string
  delegateId: string
  delegateHash: string
  botAddress: string
  agentId: string
  operation: string
  resources: string[]
  actionIndex: number
  maxUses: number
  timeWindow: { notBefore: number | null; notAfter: number | null }
  nonce: string
  requestedAt: string
  legitimacyId?: string
  botSignature: string
}
```

The request id MUST be:

```text
"ae-request-" + first16Hex(SHA-256(canonicalJSON({ botAddress, delegateId, nonce })))
```

`delegateHash` MUST be:

```text
SHA-256(canonicalJSON(delegate body without issuerSignature))
```

`botSignature` MUST sign the request body without `botSignature` using the MintRequest signing
prefix.

When `MintDelegate.legitimacyRef.required` is true, hosted governance MUST require
`MintRequest.legitimacyId` to equal `MintDelegate.legitimacyRef.legitimacyId`, and the value is part
of the bot-signed request body.

### Mint Request Verification

A mint verifier MUST:

1. recover and validate the delegate issuer signature;
2. verify the recovered issuer address equals `delegate.issuerAddress`;
3. verify the delegate is active under its time window;
4. recover and validate the bot request signature;
5. verify the recovered bot address equals `request.botAddress`;
6. enforce `address-set` bot policy when selected;
7. verify `request.delegateHash` matches the delegate body;
8. verify `request.operation` is allowed by the delegate;
9. verify every requested resource is allowed by exact match, prefix wildcard such as `thread:*`, or `*`;
10. verify `request.actionIndex` is inside the delegate index range;
11. verify `request.maxUses` does not exceed `delegate.maxUsesPerAction`;
12. verify the request time window fits inside the delegate time window;
13. enforce nonce replay and `maxMints` with state when running hosted governance.

### Remote Mint Action Seed

After a valid delegate and request, a bot MAY derive its remote-mint action seed as:

```text
HKDF-SHA256(
  ikm = mintMaterial,
  salt = "agentenvelope-v1",
  info = canonicalJSON({
    purpose: "remote-mint",
    delegateHash,
    mintRequest: requestBodyWithoutBotSignature
  }),
  length = 32
)
```

The resulting action seed signs action payloads using the normal action signing prefix.

## Legitimacy References

Legitimacy is additive governance state: it records whether an authority remains admissible under
current policy, evidence, and time. It MUST NOT alter derived seeds, agent addresses, canonical
action envelopes, or the v1 authority tree. A signature MAY be valid while legitimacy is denied.

A legitimacy reference has this shape:

```ts
interface LegitimacyRef {
  legitimacyId: string
  required?: boolean
  policyId?: string
  stateVersion?: number
  stateHash?: string
}
```

On a `MintDelegate`, `legitimacyRef` is signed content. On a `PublicActionRecord`, it is metadata.

An SDK-side legitimacy state check treats a state as currently legitimate only when all of the
following hold:

- `type` is `agentenvelope.legitimacyState`;
- `version` is `1`;
- `status` is `legitimate`;
- `expiresAt`, when present, is later than the evaluation time.

The full legitimacy model, including evidence statements, events, profiles, and deterministic
evaluation, is described in the AgentEnvelope Internet-Draft series
(`draft-mcphillips-agentenvelope-derived-authority`).

## Receipt Attestation

Hosted AgentEnvelope verifiers MAY sign their own verification or mint receipts. Attestation is
additive and MUST NOT be required for sovereign offline verification.

A receipt attestation has this shape:

```ts
interface ReceiptAttestation {
  attesterAddress: string
  alg: 'secp256k1-keccak256'
  signature: string
}
```

The attestation signature MUST cover the receipt body excluding the `attestation` field using the
Attestation signing prefix.

Verifiers SHOULD pin the expected attester address out of band. The current published hosted
attester address is:

```text
0x2332d1b716a49a520d9a2de6baebeb5bdafdf994
```

## Hosted API Boundary

The hosted AgentEnvelope API MAY store encrypted workspace state, safe metadata, public action
records, stored delegates, verification events, audit events, billing records, API key hashes,
mint ledgers, legitimacy state, and legitimacy events.

The hosted API MUST NOT receive, derive, persist, log, or return:

- vault passphrases;
- plaintext identity roots;
- domain seeds;
- action seeds;
- `actionSeedHex`;
- mint material;
- private keys.

Hosted API keys meter and protect the hosted governance service. They MUST NOT be treated as agent
authority. Agent authority is proven by signatures, public records, delegates, and out-of-band key
material.

## Versioning

All normative v1 objects MUST include:

```json
{"version":1}
```

and a type string beginning with `agentenvelope.`.

Any future incompatible change to derivation salts, signing prefixes, canonical JSON behavior,
signature format, address derivation, or normative object semantics MUST use a new version.

## Security Considerations

Implementations MUST treat `identityRoot`, `domainSeed`, `actionSeed`, `actionSeedHex`,
`mintMaterial`, bot seeds, and private keys as secret signing material.

Implementations SHOULD zero temporary seed buffers after use where the runtime permits.

Implementations MUST NOT log private signing material.

Offline verification proves that a signature matches a public action record and time window. It
does not prove that a max-use slot is unspent. Systems that require replay prevention MUST maintain
state.

The `any-signed-bot` policy is intentionally open. Issuers that require bot restriction MUST use
`address-set`.

Attestation certifies only the hosted verifier statement about facts it computed. It does not add
custody, and it MUST NOT become a requirement for sovereign verification.

## IANA Considerations

This document has no IANA actions.

## Provenance

The non-normative provenance record is maintained in [provenance.md](./provenance.md).

## Conformance

A v1 implementation SHOULD reproduce the deterministic vectors in
[vectors/v1-core.json](./vectors/v1-core.json).

At minimum, a conforming implementation MUST reproduce:

- canonical JSON strings;
- content hashes;
- domain address and fingerprint;
- action envelope hash;
- action address;
- action signatures and recovered addresses;
- mint delegate and mint request signature verification;
- remote mint action address derivation.
