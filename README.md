# agent-envelope-sdk

**Sovereign cryptographic primitives for delegated action authority. Apache 2.0.**

---

## What this is

Stateless cryptographic toolkit — deterministic key derivation, signature creation, signature
verification, structured message types. Runs offline. No account. No network.

AgentEnvelope is not limited to AI agents. In the SDK, an "agent" is a bounded
action identity: a named actor, operation, resource set, decay policy, and
verifiable address. That actor can be a chatbot, backend worker, workflow step,
service, device command, access grant, order, instruction, or any other system
trusted to act.

This is the **substrate**, not the product. Two paths:

- **Build your own authority layer** — derive keys, sign actions, verify signatures, enforce
  policy in your own infrastructure. Apache 2.0. You own it.

- **Use AgentEnvelope hosted governance** — optional managed layer at
  [agentenvelope.io](https://agentenvelope.io). Adds vault management, delegate issuance,
  public records, mint receipts, delegate revocation, maxMints and nonce-replay checks,
  legitimacy checks, usage ledgers, audit trails.

Neither path requires the other.

Importing from `agent-envelope-sdk` loads only sovereign/offline primitives. Hosted APIs are
opt-in through `agent-envelope-sdk/client`; API keys meter governance services and are never
agent signing authority.

## The cryptographic model

Authority is **derived**, not issued. A single root secret deterministically produces an
unbounded hierarchy of domain keys, action identities, and scoped action capabilities. Same
inputs, same outputs. A child cannot recover its parent. Siblings cannot be inferred from
each other.

Capabilities are scoped to operation, resource set, and time window. Workers sign payloads.
Verifiers check signatures against public records — no shared secrets, no central issuer,
no network.

Verification always works offline. Hosted attestation (`verifyReceipt`) is additive — it
certifies AgentEnvelope's signed statement about a verdict. It never gates the offline path.
Offline verification proves provenance and integrity; it does not prove nonce freshness,
delegate revocation state, live legitimacy state, or whether a max-use slot has already been
consumed.

## Specification

The canonical AgentEnvelope v1 specification is published in [spec/](spec/README.md).

- [AgentEnvelope v1: Derived Authority Specification](spec/agent-envelope-v1.md)
- [Deterministic v1 conformance vectors](spec/vectors/v1-core.json)
- [Provenance record](spec/provenance.md)

## Install

```bash
npm install agent-envelope-sdk
```

Requires Node.js 18 or later.

## SDK Usage

The root module is for worker, verifier, and bot-side code that does not hold the vault root.
Root-holding orchestrators and console-style apps use `agent-envelope-sdk/avatar` for domain and
action capability derivation.

### Worker side — sign a payload

```js
import { signAction, hexToBytes } from 'agent-envelope-sdk';

const capability = JSON.parse(process.env.AGENTENVELOPE_CAPABILITY_JSON);
const actionSeed = hexToBytes(capability.actionSeedHex);

const payload = {
  action: 'send-message',
  threadId: 'customer-123',
  bodyHash: '0xabc',
};

const signature = signAction(actionSeed, payload);
console.log({ payload, signature, agentAddress: capability.agentAddress });
```

### Verifier side — verify a signature locally

```js
import { verifyAction, recoverActionAddress } from 'agent-envelope-sdk';

const record = JSON.parse(fs.readFileSync('public-record.json', 'utf8'));
const payload = { action: 'send-message', threadId: 'customer-123', bodyHash: '0xabc' };
const signature = '0x...';

// Option A — verify directly against the known agent address.
const result = verifyAction({ message: payload, signature, expectedAddress: record.agentAddress });
console.log(result); // { valid: true, recoveredAddress: '0x...' }

// Option B — recover the signer address and compare yourself.
const recovered = recoverActionAddress(payload, signature);
console.log(recovered === record.agentAddress); // true
```

### Verifier side — verify via the hosted API

```js
import { AgentEnvelopeClient } from 'agent-envelope-sdk/client';

const client = new AgentEnvelopeClient({ apiKey: '<your-api-key>' });

const report = await client.verifyAction({
  agentId: record.agentId,
  actionIndex: record.actionEnvelope.actionIndex,
  payload,
  signature,
  expectedActionEnvelopeHash: record.actionEnvelopeHash,
});
console.log(report.valid, report.checks);
```

### Bot side - mint a capability via the hosted API

```js
import { buildMintRequest, hexToBytes, mintActionCapability } from 'agent-envelope-sdk';
import { AgentEnvelopeClient } from 'agent-envelope-sdk/client';

const client = new AgentEnvelopeClient({ apiKey: process.env.AE_API_KEY });
const botSeed = hexToBytes(process.env.AE_BOT_KEY);
const delegate = await client.getStoredDelegate(process.env.AE_DELEGATE_ID);

const request = buildMintRequest(botSeed, delegate, {
  agentId: process.env.AE_BOT_ID,
  operation: 'send-message',
  resources: ['thread:customer-123'],
  actionIndex: 0,
  maxUses: 1,
  timeWindow: {
    notBefore: Date.now(),
    notAfter: Date.now() + 60 * 60 * 1000,
  },
  nonce: crypto.randomUUID(),
  requestedAt: new Date().toISOString(),
  ...(delegate.legitimacyRef?.legitimacyId
    ? { legitimacyId: delegate.legitimacyRef.legitimacyId }
    : {}),
});

const receipt = await client.mint({ delegate, request });

const capability = mintActionCapability(
  hexToBytes(process.env.AE_MINT_MATERIAL),
  delegate,
  request,
);
```

`legitimacyId` is optional signed context in the SDK. This keeps sovereign/offline use fully
decentralised: local builders and verifiers do not need AgentEnvelope hosted governance. When a
hosted delegate contains `legitimacyRef.required === true`, the hosted mint route requires the bot
to sign the matching `legitimacyId` into the `MintRequest`; missing or wrong-scope legitimacy is
rejected before a capability is authorised.

`any-signed-bot` is intentionally broad: any bot that can sign the mint request may mint within the
delegate's bounds. Use it only when possession of the delegate is the intended authority boundary.
For named workers or regulated deployments, issue delegates with `botPolicy: 'address-set'` and
`allowedBotAddresses`.

### Verify a hosted attestation

When the hosted verifier is provisioned with an attestation key, verify reports and mint receipts
carry an `attestation`. Pin the published attester address out-of-band and confirm it — a receipt
with no `attestation` is still a complete, independently verifiable result.

```js
import { verifyReceipt } from 'agent-envelope-sdk';

const result = verifyReceipt(report, PUBLISHED_ATTESTER_ADDRESS);
console.log(result.valid, result.attesterAddress);
```

## Key Properties

| Property | Description |
|----------|-------------|
| Stateless verification | Verifies signatures against public records without seed disclosure |
| Scoped capabilities | Each capability is bound to a specific operation, resource set, and time window |
| Mathematical decay | Time expiry is enforced from the public record |
| Usage limits | `maxUses` is signed into the record; consumption counters require caller or governed state |
| No hosted seed custody | Signing material never leaves the worker |

---

## License

[Apache-2.0](LICENSE) — see [NOTICE](NOTICE) for attribution.
