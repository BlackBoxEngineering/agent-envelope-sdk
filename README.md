# AgentEnvelope v1

**Cryptographic capabilities for agents. No central issuer. No shared secrets.**

---

## The Problem

Every agent-auth system in use today requires a central issuer. OAuth issues tokens. SPIFFE issues certificates. API keys are issued by hand. When an agent needs authority, something has to grant it.

Issued authority has structural weaknesses: tokens can be stolen and replayed, revocation requires infrastructure, hierarchies require nested issuance ceremonies, and scaling to millions of agents means scaling the issuer.

## The Model

AgentEnvelope derives cryptographic capabilities from a customer-held root — nothing is issued by a
central service. Each capability is scoped to a specific operation, resource set, and time window.
Workers sign payloads using their capability. Verifiers check signatures against public records — no
shared secrets, no central issuer.

Verification always works offline, with no network and no AgentEnvelope key. Hosted attestation
(`verifyReceipt`) is additive: it certifies AgentEnvelope's own signed statement about a verdict it
computed. It never gates the offline path.

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
