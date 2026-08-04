# agent-envelope-sdk

**Sovereign cryptographic primitives for agent authority. Apache 2.0.**

---

## What this is

Stateless cryptographic toolkit — deterministic key derivation, signature creation, signature
verification, structured message types. Runs offline. No account. No network.

This is the **substrate**, not the product. Two paths:

- **Build your own authority layer** — derive keys, sign actions, verify signatures, enforce
  policy in your own infrastructure. Apache 2.0. You own it.

- **Use AgentEnvelope hosted governance** — optional managed layer at
  [agentenvelope.io](https://agentenvelope.io). Adds vault management, delegate issuance,
  public records, mint receipts, usage enforcement, audit trails.

Neither path requires the other.

## The cryptographic model

Authority is **derived**, not issued. A single root secret deterministically produces an
unbounded hierarchy of domain keys, agent identities, and scoped action capabilities. Same
inputs, same outputs. A child cannot recover its parent. Siblings cannot be inferred from
each other.

Capabilities are scoped to operation, resource set, and time window. Workers sign payloads.
Verifiers check signatures against public records — no shared secrets, no central issuer,
no network.

Verification always works offline. Hosted attestation (`verifyReceipt`) is additive — it
certifies AgentEnvelope's signed statement about a verdict. It never gates the offline path.

## Install

```bash
npm install agent-envelope-sdk
```

Requires Node.js 18 or later.

## SDK Usage

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

### Mint a capability via the hosted API

```js
const receipt = await client.mint({ delegate, request });
```

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
| Usage limits | Max-use counts are published in the public record |
| No hosted seed custody | Signing material never leaves the worker |

---

## License

[Apache-2.0](LICENSE) — see [NOTICE](NOTICE) for attribution.
