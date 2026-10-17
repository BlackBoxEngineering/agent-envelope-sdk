# Richard Whitney Fault Investigation: SDK and Portal Verification

Reviewed: 17 October 2026.

**Remediation update:** the mint-budget rejection / delegated-registration bypass is fixed in the local backend code and covered by regression tests. It has not been deployed. Other findings remain unchanged. The investigation evidence below describes the pre-fix revisions unless explicitly marked otherwise; see the remediation record at the bottom.

This revision supersedes the earlier demo-led assessment. The executable SDK, portal implementation, and hosted backend are the source of truth for product findings. Cold-chain behaviour is recorded separately and is not used to establish a defect in the SDK or portal.

## Scope and evidence standard

The review traced the relevant call paths and ran local reproductions against these checkouts:

| Component | Checkout revision | Relevant implementation |
| --- | --- | --- |
| SDK, version 1.4.6 | `be613a85926080e641306014c97f64a25b838cad` | `agent-envelope-sdk/src/index.js`, `src/avatar.js` |
| Web portal | `9a594f66e978386ffd239deac2b69482f2edca8d` | `agent-envelope-web/app`, `lib/sovereign`, `components/home` |
| Hosted backend used by the portal | `9282e835e1aa0efa263555747832297791c18a3f` | `agent-envelope/amplify/functions` |

The portal's installed SDK is version 1.4.6. Its `src/index.js` was byte-for-byte identical to the SDK checkout during this review.

The portal permit playground imports its verifier from `agent-envelope-sdk`, at `app/records/playground/RecordsPlaygroundClient.tsx:10`. An older implementation in `lib/sovereign/permits.ts` differs from the SDK, but no application import of that helper was found. Its defects must not be reported as active playground defects.

Evidence levels used here:

- **Executed locally:** actual product functions were called with synthetic keys or published test vectors.
- **Handler reproduction:** actual backend handlers ran with an in-memory database substitute. No AWS state was read or written.
- **Source trace:** implementation and callers were inspected, without claiming a deployed end-to-end test.
- **Unconfirmed:** the available evidence cannot establish cause or live impact.

No deployed portal, API Gateway configuration, live database, mail delivery, or production legitimacy state was tested. Handler reproductions use optional legitimacy in audit mode. A required legitimacy policy can independently deny a request; these tests establish what happens when that separate policy permits processing. The action verdicts in the reproductions come from the real verification core, not a live invocation of the complete hosted verification route.

## Product findings at a glance

| Point | SDK / portal / backend conclusion | Classification |
| --- | --- | --- |
| 1. External enforcement | External action-use accounting remains deliberate. The separately confirmed mint-budget registration bypass has been fixed locally with atomic admission and strict registration binding. | Design boundary unchanged; backend defect fixed locally, deployment pending |
| 2. Expiry | Finite delegate bounds can be omitted in requests. Registration also permits a decay mode that disables finite dates, and backend validation accepts an unbounded BOTH envelope that the SDK rejects. | Confirmed SDK/backend defects and validation divergence |
| 3. Replay / hosted head | Valid signatures can verify repeatedly. The hosted head records evidence; it does not consume a capability. A public envelope alone is not a signing credential. | Confirmed enforcement boundary |
| 4. Numeric duration | Resource policy is string membership. Neither generic action verifier interprets payload parameters or enforces refrigeration semantics. | Application responsibility; claims must identify it |
| 5. Bot binding | SDK and backend correctly enforce address-set. Portal issuance hard-codes any-signed-bot and cannot configure that restriction. | Confirmed portal feature gap |
| 6. Blast radius | Action-key isolation holds, but a runtime's aggregate authority depends on all secrets and delegates it holds. The demo's 500-mint settings are not portal defaults. | Deployment-dependent risk; prior framing corrected |
| 7. Public claims | Homepage proof ignores its expired window; portal capability tooltips also imply automatic spending without identifying the external counter. | Confirmed presentation / guarantee mismatch |
| 8. Email delay | Portal uses Amplify authentication and email recovery. Source cannot locate the reported delivery delay. | Unconfirmed operational report |

## 1. External enforcement and mint/use accounting

**Fix status:** the mint-admission defect described below is fixed locally. `admitMintRequest()` now commits nonce admission and the guarded mint-count increment in one transaction. Registration requires `admissionStatus: 'admitted'`, matching request ID, and the hash of the complete signed request body. The external action-use accounting boundary is not changed. Details and rollout limitations are recorded at the bottom.

### Existing setup

The SDK Action Envelope builder always emits `limits.enforcement: 'external'`. The portal builder does the same. The SDK validates the declared limit, but neither its offline record verifier nor the backend action-verification core keeps a spent-use counter.

Relevant code:

- [SDK envelope builder](src/avatar.js): `buildActionEnvelope()`, line 114.
- [SDK record verifier](src/index.js): `verifyRecord()`, line 522.
- [Portal envelope builder](../agent-envelope-web/lib/sovereign/domains.ts): line 172.
- [Hosted action handler](../agent-envelope/amplify/functions/verifySovereignAction/handler.ts): line 10.
- [Hosted mint handler](../agent-envelope/amplify/functions/verifyMintRequest/handler.ts): nonce reservation at line 74, mint-count increment at line 91.
- [Database operations](../agent-envelope/amplify/functions/shared/db.ts): `checkAndWriteMintNonce()` at line 468 and `incrementDelegateMintCount()` at line 533.
- [Delegated registration](../agent-envelope/amplify/functions/registerDelegatedSovereignAgent/handler.ts): mint-ledger check at line 68.

Hosted minting does maintain state: it conditionally inserts a nonce row, then separately increments the delegate's mint count with a maximum guard. These are separate writes. The verification handler's `incrementUsage(..., 'verifications')` updates an account/month service meter, not a capability-use limit.

Bot-driven minting is already part of the SDK and hosted API. It does not require an architectural addition merely to avoid manually issuing commands.

### Richard's claim

The declared one-use limit depends on something outside the cryptography, and the product should identify who counts uses rather than imply that the capability consumes itself.

### Evidence and assessment

**Confirmed design boundary:** a correctly signed payload under a one-use capability returned valid on two consecutive calls to both the SDK verifier and backend verification core. This is expected for stateless verification. External enforcement is part of the product contract, not a testing-only flag.

The distinction is between committing to a declared limit and enforcing its consumption. A trusted gateway is a legitimate place to enforce it; that trust dependency should be explicit.

**Additional confirmed backend defect:** after the delegate's mint budget is exhausted, the mint handler reserves a new nonce and then returns 409 when the count increment fails. Delegated registration checks for the nonce row and matching delegate/request identifiers but does not require proof that the count/admission step succeeded.

The actual handlers produced this result with a delegate allowing three mints:

| Request | Mint status | Registration status | Stored mint count | Verification core before expiry |
| --- | --- | --- | --- | --- |
| 1 | 200 | 201 | 1 | Valid |
| 2 | 200 | 201 | 2 | Valid |
| 3 | 200 | 201 | 3 | Valid |
| 4 | 409 | 201 | 3 | Valid |

This requires a valid delegate, correctly signed in-scope requests, the necessary worker material, and satisfaction of other admission checks. It is not an unauthenticated ability to forge authority. It does show that rejecting mint request 4 is insufficient to stop its later registration.

The earlier report understated this by treating hosted mint counts as a complete enforcement result. The counter itself rejects excess increments; the subsequent registration path does not distinguish reserved from admitted requests.

### Suggested way forward

1. Make nonce reservation, mint-budget admission, and a durable completed/admitted mint record atomic, or use an explicit state machine whose completed state is required by registration.
2. Bind that admission record to the complete signed request, preferably by a canonical request hash. A nonce/request identifier alone is not the full admitted policy.
3. Add a regression test that exhausts the budget, receives 409, then attempts delegated registration and expects denial.
4. Keep service metering, mint budgets, and action-use consumption distinct in APIs and UI.
5. For action consumption, maintain an atomic budget keyed to the capability or trusted envelope identity. Use a separate signed command identifier for idempotency. A fresh command ID must not reset a capability's total `maxUses`.
6. Treat the local demo's intentional reuse as a demo concern. Fixing its loop would not fix the product accounting issue above.

## 2. Expiry and delegate containment

### Existing setup

The SDK and portal support four decay modes. The actual SDK, hosted verifier, and portal availability code agree on these semantics:

| Mode | Checks finite time bounds during verification? | Built-in action-use counter? |
| --- | --- | --- |
| NONE | No | No |
| ACTION | No | No; external consumption required |
| TIME | Yes | No |
| BOTH | Yes | No; external consumption required |

A finite date does not enforce expiry when the mode is ACTION or NONE.

The manual capability form defaults to BOTH with finite dates. The delegate form defaults to an expiry roughly seven days ahead. This contradicts a blanket claim that portal-issued authority never expires.

Relevant code:

- [SDK time checks](src/index.js): `_validateActionEnvelope()` at line 66 and `_checkDecay()` at line 87.
- [SDK mint checks](src/index.js): `verifyMintRequest()` at line 414, especially lines 449-453.
- [Backend mint checks](../agent-envelope/amplify/functions/shared/mint.ts): request containment at lines 152-159.
- [Backend record validation and decay](../agent-envelope/amplify/functions/shared/sovereign.ts): `assertActionEnvelope()` and `checkActionEnvelopeDecay()`.
- [Registration consistency checks](../agent-envelope/amplify/functions/registerDelegatedSovereignAgent/handler.ts): `recordMintConsistencyError()`, line 140.
- [Portal availability](../agent-envelope-web/lib/sovereign/availability.ts): `actionEnvelopeAvailability()`, line 15.
- [Portal capability defaults](../agent-envelope-web/app/agents/AgentsManualKey.tsx): default decay mode at line 62.

### Richard's claim

A finite delegate can produce an action whose validity is unbounded, so expiry of mint authority does not ensure expiry of the resulting action.

### Evidence and assessment

There are three distinct product findings.

**A. Null request bounds bypass delegate containment.** The SDK, the installed SDK used by the portal playground, and the backend all accepted a correctly signed request with null bounds beneath a finite delegate. They also accepted a finite start plus a null end. A non-null end later than the delegate end was correctly rejected.

The code only compares a boundary when both sides are non-null. It does not require an omitted request boundary to inherit or respect a finite delegate boundary.

**B. Delegated registration does not bind an expiry-enforcing decay mode.** A bounded mint request can be registered as an ACTION envelope with the same numeric dates. Registration compares the dates and `maxUses` but does not constrain the decay mode. The SDK and backend then correctly follow ACTION semantics and skip those dates.

The defect is in the admission/registration contract: preserving date values while allowing a mode that disables them defeats a claim that the delegated request's finite window will govern later use.

**C. Backend envelope validation is weaker than SDK validation.** The backend accepted and registered BOTH with two null time bounds. Its verification core returned valid. The SDK rejected that record because BOTH requires at least one finite boundary.

Local handler results, resetting the budget between these independent cases:

| Request window / registered mode | Mint | Registration | SDK after expiry | Backend core after expiry |
| --- | --- | --- | --- | --- |
| Null bounds / ACTION | 200 | 201 | Valid | Valid |
| Finite bounds / ACTION | 200 | 201 | Valid | Valid |
| Finite bounds / BOTH | 200 | 201 | Expired | Expired |
| Null bounds / BOTH | 200 | 201 | Invalid shape | Valid |

“After expiry” means a test clock later than the finite delegate end and, where present, the action end. The required-legitimacy path was not used in these handler cases.

**Positive control:** a correctly formed expired BOTH record was rejected by the SDK and backend, and the portal availability function labelled it expired. Ordinary finite expiry works when the correct mode and valid bounds are present.

### Suggested way forward

1. Reject missing request bounds wherever the delegate specifies a finite corresponding boundary. Apply the same rule in the SDK, installed portal dependency, and backend implementation.
2. Validate request time types, ordering, and containment consistently.
3. Define and enforce the signed relationship between request policy and Action Envelope decay mode. A finite admitted action window must not be disabled during registration.
4. Share or align the backend and SDK envelope validators; reject BOTH/TIME without the required time boundary.
5. Add cross-component tests for null bounds, one missing bound, explicit out-of-range bounds, decay-mode downgrade, malformed BOTH, and normal expiry.
6. Explain in the portal that ACTION mode does not enforce the displayed dates. Retain BOTH as the ordinary default.
7. Treat delegate expiry, action expiry, and live legitimacy as separate checks. A finite delegate does not automatically revoke every previously minted record.

## 3. Replay and the hosted head

### Existing setup

The backend verification route loads a public record, evaluates legitimacy, computes the action report, writes verification/witness evidence, and returns the report. It does not reserve or spend the action capability.

The SDK verifies the supplied signature against the address in the record, checks envelope integrity and index, and evaluates time decay. The application must supply a trusted record/address or equivalent authority provenance.

Relevant code:

- [SDK verification](src/index.js): line 522.
- [Hosted verification route](../agent-envelope/amplify/functions/verifySovereignAction/handler.ts): lines 14, 20, 35, 42, 79, and 89.
- [Hosted verdict calculation](../agent-envelope/amplify/functions/shared/sovereign.ts): line 214.

### Richard's claim

A captured action could be replayed at a dangerous time without forging a signature; a hosted record/head might or might not prevent that.

### Evidence and assessment

The replay boundary is confirmed by the repeated-verification reproduction in point 1. A witness append records a verification; it does not make a second verification fail as already spent. Required legitimacy may deny the action based on current policy, but it is not a substitute for use consumption.

The original wording needs a qualification: **the public Action Envelope alone is not the private capability.** Possession of public JSON does not let someone sign a new command. Relevant capture scenarios are:

- a captured payload and its valid signature can be replayed unchanged unless freshness/consumption checks stop it;
- a stolen private action seed can sign more payloads, subject to trusted scope and consumption enforcement;
- a public envelope without a signature or private key is insufficient.

A five-minute action window reduces the time available for replay. It does not guarantee that only one execution occurs during those five minutes.

### Suggested way forward

1. State explicitly that hosted verification is not an action-use reservation.
2. Provide or document an execution adapter that checks trusted scope, current admission requirements, capability budget, and signed command idempotency before the side effect.
3. Persist consumption state across processes/restarts where the application's guarantee requires it.
4. Define retry behaviour for pending, completed, failed, and uncertain execution. Do not promise exactly-once physical effects merely from a successful database write.
5. Test duplicate and concurrent submissions separately from expiry and signature tampering.
6. Keep witness/head evidence as an accountability function; do not present it as an execution lock.

## 4. Resource strings and numeric parameters

### Existing setup

The SDK and backend mint verifiers perform resource membership checks. Their implementations support exact strings, `<first-colon-prefix>:*`, and `*`. They do not implement arbitrary numeric comparisons or general wildcard expressions.

The portal Action Envelope builder lowercases and normalizes resources. Consequently, textual variants should not be discussed without identifying the construction path: portal-built `duration:1H` is normalized, while directly signed mint-request strings are compared as supplied.

At action verification, the generic SDK/backend checks do not interpret payload fields such as duration, value, unit, operation, or resource identifiers.

Relevant code:

- [SDK mint resource checks](src/index.js): lines 442-445.
- [Backend mint resource checks](../agent-envelope/amplify/functions/shared/mint.ts): scope checks following delegate-hash verification.
- [Portal normalization](../agent-envelope-web/lib/sovereign/domains.ts): `normalizeResources()`.
- [SDK action verifier](src/index.js): line 522.
- [Backend action verifier](../agent-envelope/amplify/functions/shared/sovereign.ts): line 214.

### Richard's claim

A resource such as duration:1h is a string label. Safety depends on a downstream component interpreting the command and enforcing its relationship to that label.

### Evidence and assessment

Confirmed as an application responsibility. A local reproduction created authority for a one-hour defrost at store 184, signed a payload containing a different operation, store 999, and value 8 with that action key, and received valid from both generic action-verification functions.

This did not forge a signature or alter a trusted envelope. It demonstrates that a valid signer can sign arbitrary payload bytes and that the generic verifier does not decide whether those bytes describe an authorised physical operation.

A runtime must not treat `valid: true` from these functions as a complete domain-specific execution approval. An SDK abstraction can reasonably leave this mapping to clients, but the mapping is necessary for the claimed scope boundary.

The cold-chain simulator has a separate numeric/unit-to-resource check. That is evidence about the demo adapter only, not a built-in SDK or portal feature.

### Suggested way forward

1. Document the action-verifier return value precisely: signature/record/time checks, with application semantics still required.
2. Provide explicit adapter examples or an optional schema/policy hook for mapping payloads to signed authority.
3. Enforce operation, resource identity, required resource completeness, units, and numeric values before execution.
4. If exact labels remain the model, document canonicalization and reject ambiguous representations.
5. Treat typed comparisons such as a maximum duration as a separate protocol feature, not as something already enforced by the current string array.

## 5. Bot identity binding

### Existing setup

The SDK and backend implement `address-set` and compare the recovered bot address against `allowedBotAddresses`.

The current portal delegate-issuance flow instead hard-codes `botPolicy: 'any-signed-bot'`. Its local delegate types restrict the policy to that value, and its builder does not serialize an allowed-address set. This is not just the cold-chain handoff configuration.

Relevant code:

- [SDK bot restriction](src/index.js): lines 436-439.
- [Backend bot restriction](../agent-envelope/amplify/functions/shared/mint.ts): line 132.
- [Portal issue flow](../agent-envelope-web/app/agents/AgentsClient.tsx): line 177.
- [Portal delegate types and builder](../agent-envelope-web/lib/sovereign/domains.ts): lines 86, 264, and 283.
- [Active playground import](../agent-envelope-web/app/records/playground/RecordsPlaygroundClient.tsx): line 10.
- [Unused alternate helper](../agent-envelope-web/lib/sovereign/permits.ts): line 93.

### Richard's claim

Any signed bot is a broader authorisation class than a specifically named/key-bound worker.

### Evidence and assessment

**Positive control:** a request signed with an unlisted bot key was rejected by the SDK, the portal's installed SDK, and the backend with “bot address not in allowed set.”

**Portal gap:** users cannot select that working policy in the current issue flow. The earlier advice to simply select address-set in the portal was incomplete; the UI and builder need support.

The unused alternate permit helper accepted the same unlisted bot. Since the active playground imports the SDK instead, this is code drift and a maintenance hazard, not a demonstrated active playground bypass.

An agent ID is signed metadata. It is not interchangeable with an enforced key/address allow-list. Also, bot binding governs who may submit a mint request; it does not make an exported action seed non-transferable.

### Suggested way forward

1. Add policy selection and allowed-address entry to the portal's delegate issue form, types, and signed builder.
2. Use the SDK implementation or parity tests to keep the portal and backend checks aligned.
3. Remove or align the unused helper before it can become an accidental alternate verifier.
4. Display friendly worker names alongside enforced addresses.
5. Retain any-signed-bot for deployments that deliberately want it; label its authority boundary accurately.
6. Test issuance, JSON handoff, and mint acceptance/rejection together.

## 6. Aggregate blast radius

### Existing setup

SDK action derivation includes the domain and canonical Action Envelope. Remote mint derivation includes the delegate hash and signed request body. These provide distinct derived keys.

The SDK's `deriveMintMaterial()` and portal's vault helper derive domain-scoped mint material. The same domain material can support multiple delegates; the derived child action keys are still distinct.

The actual portal delegate form defaults are:

- operation: send-message;
- resources: *;
- max mints: 10;
- max uses per action: 1;
- action indexes: 0-99;
- expiry: approximately seven days;
- required legitimacy creation enabled;
- bot policy: any-signed-bot, set in the issue handler.

The cold-chain instructions' 500 mints and 0-1000 index range are demo settings, not these portal defaults.

Relevant code:

- [SDK local action derivation](src/avatar.js): line 154.
- [SDK mint material and remote action derivation](src/index.js): lines 469 and 484.
- [Portal mint material](../agent-envelope-web/lib/sovereign/vault.ts): line 260.
- [Portal defaults](../agent-envelope-web/app/agents/AgentsDelegateSection.tsx): lines 53-62.

### Richard's claim

A central automation holding many stores' authorities can expose all of them at once, despite each final capability having a narrow scope.

### Evidence and assessment

The code supports isolation between derived child keys; possessing one action seed does not provide the parent derivation material. Existing interoperability/derivation tests passed.

That does not determine which secrets a real runtime holds. The 700-store scenario remains a deployment hypothesis, not a verified compromise or a product-wide store count.

The earlier report's delegate blast-radius table also needs a qualification: mint budgets are governed state, not mathematical restrictions on a holder of mint material. `mintActionCapability()` derives a key without contacting the hosted service or enforcing a counter. Accepted authority depends on verified delegates, trusted records, and a correct admission path. Point 1 shows a flaw in one such path.

| Compromise | Supported conclusion |
| --- | --- |
| One action seed | Cannot derive parent or sibling keys; its accepted actions still depend on the trusted envelope, semantic checks, time mode, and consumption policy |
| Worker holding delegate, bot key, mint material, and hosted access | Can attempt minting within available authority; accepted mint counts rely on correct governance enforcement |
| Runtime holding multiple workers' secrets | Exposes the aggregate authority available to that runtime |
| Domain or root secret | Exposes the corresponding derivation scope |

### Suggested way forward

1. Describe blast radius by the compromised material, not solely by final capability scope.
2. Fix the hosted mint-admission defect before claiming maxMints as an end-to-end registration bound.
3. Review the portal's wildcard resource default and broad bot default in the intended onboarding context.
4. Use narrower delegates and separated secret custody where customers require isolation.
5. Do not claim a 700-store weakness was demonstrated, or prescribe a particular topology without the customer's deployment model.

## 7. Product descriptions and portal feedback

### Existing setup

The homepage says its browser verifier demonstrates one refund, one time window, and one use, with proof before execution. The component actually calls `verifyAction()` and compares fixed envelope/payload hashes.

The signed example's expiry is **15 August 2026 at 17:00 UTC**. Evaluating the actual component constants and proof expression on the review date returned true; expiry is not part of that expression.

Within the authenticated portal, the capability result tooltip says ACTION expires after maxUses and BOTH uses whichever limit comes first. It does not identify who maintains or enforces the action-use counter.

Relevant code:

- [Homepage claims](../agent-envelope-web/app/page.tsx): lines 147-176.
- [Homepage proof component](../agent-envelope-web/components/home/HeroVerifier.tsx): constants at lines 23-45, calculation at line 63, heading at line 95.
- [Portal capability tooltips](../agent-envelope-web/app/agents/AgentsCapabilityResult.tsx): lines 53-54.
- [Portal ordinary availability checks](../agent-envelope-web/lib/sovereign/availability.ts): line 15.

### Richard's claim

Public summaries imply stronger guarantees than the structures and explicit fields support.

### Evidence and assessment

Confirmed for the examples above, with an important qualification: the homepage still verifies a mathematically valid historical signature. It is the presentation as currently bounded/pre-execution authority that exceeds those checks.

This does **not** mean the ordinary SDK time verifier or portal availability implementation ignores expiry. The expired BOTH control was correctly rejected/labelled expired by those components.

Similarly, the reported historic “independent reproduction” wording is not independently established by this code review. The pasted exchange records Richard's criticism; it does not supply the earlier page version or external experiment evidence.

The public claim should follow the functions actually used:

| Check | SDK offline | Hosted backend | Client/executor |
| --- | --- | --- | --- |
| Payload signature against trusted action address | Yes | Yes | Supplies trusted authority context |
| Envelope integrity and local validation | SDK checks it | Registration checks it, with the divergences in point 2 | Must preserve trust in the record |
| Finite time decay | TIME/BOTH | TIME/BOTH | Must not disable required timing through policy choice |
| Mint operation/resource membership | Mint-request verifier | Mint and registration paths | Supplies intended scope |
| Bot address allow-list | Yes | Yes | Portal issuance currently lacks configuration support |
| Current legitimacy | No live state | Evaluated by route policy | Must require it when needed |
| Mint budget / nonce | No state | Conditional writes; registration flaw in point 1 | Must rely on completed admission |
| Payload domain semantics | No generic mapping | No generic mapping | Required before side effects |
| Action-use consumption | No | Not in verify route | Required where maxUses/replay guarantees are claimed |
| Physical completion | No | Can verify a signed outcome statement | Must perform/observe the effect |

### Suggested way forward

1. Label the homepage check as historical signature/integrity verification, or implement and display full current record/time verification.
2. Do not merely move the displayed dates: the envelope hash and any relevant binding must remain internally consistent.
3. Explain external consumption beside the portal's maximum-use and ACTION/BOTH descriptions.
4. Describe domain-specific scope validation as a required integration check.
5. Distinguish live legitimacy, mint admission, action consumption, and outcome evidence in public wording.
6. Preserve accurate claims about offline signature verification and child-key isolation.

## 8. Password-reset email

### Existing setup

The portal renders Amplify's Authenticator. Its auth configuration enables email recovery and configures a sender. The reviewed application code does not implement a custom password-reset mail queue or a deliberate hour-long send delay.

Relevant code:

- [Authentication page](../agent-envelope-web/components/auth/AuthPage.tsx): Authenticator at line 73.
- [Authentication configuration](../agent-envelope-web/amplify/auth/resource.ts): email sender and EMAIL_ONLY recovery.

### Richard's claim

The reset email arrived almost an hour after he requested it.

### Evidence and assessment

The report establishes delayed receipt, not the cause. Neither the application source nor the conversation establishes that AgentEnvelope's sending path was healthy or that Richard's mailbox caused the delay.

The earlier statement “probably his email” is a hypothesis. “No confirmed application defect” is the supported classification.

### Suggested way forward

Keep this as an unconfirmed operational report. If investigating it, compare the request time, provider send/delivery events, and received-message headers. No code fix is justified by the available evidence alone.

## Cold-chain findings retained as context only

The previous review found that the local simulator uses fixed, reusable ACTION capabilities with null time bounds, that its adapter maps numeric defrost values into resource strings, and that hosted publication runs asynchronously after the simulated result. Its hosted integration constructs five-minute BOTH envelopes.

These observations explain what Richard saw. They do not establish SDK expiry defaults, portal bot-policy support, or deployed backend enforcement. They should be tracked separately from the product fixes above.

## Validation and limits

Fresh checks in this review:

| Check | Result |
| --- | --- |
| SDK existing tests | 18 passed |
| Backend existing tests | 117 passed |
| Portal sovereign tests | 57 passed |
| Portal availability/routes/templates tests | 9 passed |
| Portal/SDK interoperability tests | 7 passed, including subtests |
| SDK vs portal-installed SDK core source | Identical |
| Focused null-bound, replay, semantic-scope, bot-policy and expiry probes | Results recorded above |
| Actual mint/registration handlers with in-memory database | Reproduced admission and expiry issues |
| Actual homepage constants/proof expression | Valid=true with expired displayed window |

At the initial investigation, passing existing tests did not establish coverage of these newly reproduced cases. The focused probes above characterize the pre-fix behaviour.

The initial investigation changed only this document. The subsequent authorized fix changes backend mint admission, registration checks, regression tests, and documentation. No deployed services, live data, credentials, SDK implementation, or portal implementation were modified. Post-fix validation is recorded below.

## Product work priority

1. **Implemented locally; deployment pending:** completed-mint admission and registration binding, including the over-budget registration case.
2. Fix nullable-window containment, prevent expiry-mode downgrade, and align backend/SDK envelope validation.
3. Add cross-component regression coverage and roll out consistent SDK/backend behaviour.
4. Add address-set issuance to the portal.
5. Correct homepage and authenticated-portal guarantee wording.
6. Define the action-consumption and semantic-adapter contract for clients that need execution guarantees.
7. Handle demo refinements independently; keep email cause unconfirmed pending delivery evidence.

## Reproduction appendix

The commands below run from `C:/BlackBox/agent-envelope-web` using the locally installed tsx loader. They use public SDK vectors or synthetic authority and do not load an .env file. Each runs in a separate Node process, so the test clock and mocked functions do not persist.

### A. SDK, active portal SDK, backend and unused helper comparison

Copy into PowerShell:

```powershell
@'
import fs from 'node:fs';
import assert from 'node:assert/strict';
import * as sdk from '../agent-envelope-sdk/src/index.js';
import * as installed from 'agent-envelope-sdk';
import * as avatar from '../agent-envelope-sdk/src/avatar.js';
const unwrap = m => m.default ?? m;
const mint = unwrap(await import('../agent-envelope/amplify/functions/shared/mint.ts'));
const backend = unwrap(await import('../agent-envelope/amplify/functions/shared/sovereign.ts'));
const availability = unwrap(await import('./lib/sovereign/availability.ts'));
const dormant = unwrap(await import('./lib/sovereign/permits.ts'));
const vector=JSON.parse(fs.readFileSync('../agent-envelope-sdk/spec/vectors/v1-core.json','utf8'));
const now=Date.parse('2026-10-17T12:00:00Z');
Date.now=()=>now;
const d=vector.mintDelegation.delegate;
const input={...vector.mintDelegation.request,timeWindow:{notBefore:now-1000,notAfter:now+60000}};
const make=(patch={},seed=vector.seeds.botSeedHex,delegate=d)=>sdk.buildMintRequest(sdk.hexToBytes(seed),delegate,{...input,...patch});
const summary=r=>({valid:r.valid,...r.reason?{reason:r.reason}:{}});
for(const [label,patch] of [
 ['bounded',{}],
 ['null_bounds',{timeWindow:{notBefore:null,notAfter:null}}],
 ['omitted_end',{timeWindow:{notBefore:now-1000,notAfter:null}}],
 ['past_delegate_end',{timeWindow:{notBefore:now,notAfter:d.timeWindow.notAfter+1}}],
]) {
 const r=make(patch);
 console.log(JSON.stringify({case:label,sdk:summary(sdk.verifyMintRequest(r,d)),portalInstalledSdk:summary(installed.verifyMintRequest(r,d)),backend:summary(mint.verifyMintRequest(r,d))}));
}
const wrongBot=make({},'77'.repeat(32));
console.log(JSON.stringify({case:'unlisted_bot',sdk:summary(sdk.verifyMintRequest(wrongBot,d)),portalInstalledSdk:summary(installed.verifyMintRequest(wrongBot,d)),backend:summary(mint.verifyMintRequest(wrongBot,d)),unusedPortalHelper:summary(dormant.verifyMintRequest(wrongBot,d))}));
const domain=avatar.projectDomainKey(sdk.hexToBytes(vector.seeds.identityRootHex),avatar.createDomainInfo({namespace:'audit',domainId:'review',kind:'test'}));
function action(mode='BOTH',window={notBefore:now-1000,notAfter:now+60000}){
 const env=avatar.buildActionEnvelope(domain,{agentId:'audit-worker',actionIndex:0,operation:'run_scheduled_defrost',resources:['duration:1h','store:184'],notBefore:window.notBefore,notAfter:window.notAfter,decayMode:mode,maxUses:1});
 const cap=avatar.deriveAgentActionCapability(sdk.hexToBytes(vector.seeds.identityRootHex),domain,env);
 const record=avatar.createPublicActionRecord(cap,{ownerUserId:'review-owner'});
 return {record,cap};
}
function check(record,cap,payload){
 const signature=sdk.signAction(sdk.hexToBytes(cap.actionSeedHex),payload);
 const req={actionIndex:0,payload,signature,expectedActionEnvelopeHash:record.actionEnvelopeHash};
 backend.assertPublicRecord(record);
 return {sdk:summary(sdk.verifyRecord(record,req)),backend:summary(backend.createVerificationReport(record,req))};
}
const a=action();
const payload={operation:'run_scheduled_defrost',resources:['duration:1h','store:184'],value:1,unit:'hours'};
console.log(JSON.stringify({case:'same_single_use_twice',first:check(a.record,a.cap,payload),second:check(a.record,a.cap,payload)}));
console.log(JSON.stringify({case:'valid_signer_wrong_payload_scope',...check(a.record,a.cap,{...payload,operation:'different_operation',resources:['store:999'],value:8})}));
for(const mode of ['BOTH','ACTION']){
 const a=action(mode,{notBefore:now-2000,notAfter:now-1000});
 console.log(JSON.stringify({case:'expired_'+mode,...check(a.record,a.cap,payload),portalAvailability:availability.actionEnvelopeAvailability(a.record.actionEnvelope,now)}));
}
console.log(JSON.stringify({sdkSourceMatchesPortalInstalled:fs.readFileSync('../agent-envelope-sdk/src/index.js','utf8')===fs.readFileSync('./node_modules/agent-envelope-sdk/src/index.js','utf8')}));
'@ | node --import tsx --input-type=module
```

Expected key observations: null request bounds accepted by all three active mint verifiers; unlisted bot rejected by all three; repeated action verification succeeds; signed payload semantic mismatch succeeds at the generic verifier; BOTH expires while ACTION ignores dates.

### B. Real backend handlers with in-memory database (historical pre-fix reproduction)

**Historical only:** this harness targets the pre-fix backend revision listed above and mocks separate writes, not transactions. Do not use it to validate the patched checkout. The maintained post-fix regression is `agent-envelope/tests/register-delegated.test.js`, run with `npm test -- tests/register-delegated.test.js` from the backend repository.

This substitutes only database transport and disables fetch. Its simulated database honours the nonce uniqueness and mint-count guards used in these scenarios. It does not model DynamoDB concurrency, IAM, API Gateway, production legitimacy, or witness integrations. The public-record registration and mint handlers themselves are imported from the backend checkout.

```powershell
@'
import fs from 'node:fs';
import * as sdk from '../agent-envelope-sdk/src/index.js';
const unwrap=m=>m.default??m;
const {db}=unwrap(await import('../agent-envelope/amplify/functions/shared/db.ts'));
const {handler:mintHandler}=unwrap(await import('../agent-envelope/amplify/functions/verifyMintRequest/handler.ts'));
const {handler:registerHandler}=unwrap(await import('../agent-envelope/amplify/functions/registerDelegatedSovereignAgent/handler.ts'));
const {createVerificationReport}=unwrap(await import('../agent-envelope/amplify/functions/shared/sovereign.ts'));
const v=JSON.parse(fs.readFileSync('../agent-envelope-sdk/spec/vectors/v1-core.json','utf8'));
const initialNow=Date.parse('2026-10-17T12:00:00Z');
let clockNow=initialNow;
Date.now=()=>clockNow;
process.env.AGENT_TABLE_NAME='in-memory-audit-only';
process.env.LEGITIMACY_ENFORCEMENT_MODE='audit';
delete process.env.ATTESTATION_SIGNING_KEY;
const rows=new Map();
const d=v.mintDelegation.delegate;
const ownerUserId='in-memory-review';
rows.set('DELEGATE_STORE#'+d.delegateId,{delegateId:d.delegateId,ownerUserId,delegate:d});
rows.set('CUSTOMER#'+ownerUserId,{status:'active',plan:'platinum'});
db.send=async command=>{
 const i=command.input;
 if(command.constructor.name==='GetCommand')return {Item:rows.get(i.Key.pk)};
 if(command.constructor.name==='PutCommand'){
   if(i.ConditionExpression==='attribute_not_exists(pk)'&&rows.has(i.Item.pk)){
     const error=new Error('already exists');error.name='ConditionalCheckFailedException';throw error;
   }
   rows.set(i.Item.pk,i.Item);return {};
 }
 if(command.constructor.name==='UpdateCommand'){
   if(i.Key.pk.startsWith('MINT_DELEGATE#')){
     const count=rows.get(i.Key.pk)?.mintCount??0;
     if(count>=i.ExpressionAttributeValues[':max']){
       const error=new Error('mint count exceeded');error.name='ConditionalCheckFailedException';throw error;
     }
     rows.set(i.Key.pk,{mintCount:count+1});
   }
   return {};
 }
 throw new Error('Unexpected database command, no external call allowed: '+command.constructor.name);
};
globalThis.fetch=async()=>{throw new Error('Network disabled for audit');};
async function runCase(name,timeWindow,mode){
 const request=sdk.buildMintRequest(sdk.hexToBytes(v.seeds.botSeedHex),d,{...v.mintDelegation.request,timeWindow,nonce:'audit-'+name});
 const mintResponse=await mintHandler({body:JSON.stringify({delegate:d,request})});
 const cap=sdk.mintActionCapability(sdk.hexToBytes(v.mintDelegation.mintMaterialHex),d,request);
 const envelope={...structuredClone(v.action.envelope),agentId:request.agentId,actionIndex:request.actionIndex,operation:request.operation,resources:request.resources,timeWindow,decayPolicy:{mode},limits:{maxUses:request.maxUses,enforcement:'external'}};
 const canonical=sdk.canonicalJSON(envelope);
 const record={type:'agentenvelope.publicActionRecord',version:1,recordId:'ae-audit-'+name,ownerUserId,custodyMode:'remote-mint-delegate',verifierProfile:'domain-action-envelope',status:'active',createdAt:new Date(initialNow).toISOString(),agentId:request.agentId,agentAddress:cap.agentAddress,domain:v.domain,actionEnvelope:envelope,canonicalActionEnvelope:canonical,actionEnvelopeHash:sdk.contentHash(canonical),expiry:timeWindow.notAfter===null?null:new Date(timeWindow.notAfter).toISOString()};
 const registered=await registerHandler({body:JSON.stringify({record,request,delegateId:d.delegateId})});
 const payload={operation:request.operation,resources:request.resources};
 const signature=sdk.signAction(sdk.hexToBytes(cap.actionSeedHex),payload);
 const beforeExpiry=createVerificationReport(record,{actionIndex:request.actionIndex,payload,signature,expectedActionEnvelopeHash:record.actionEnvelopeHash});
 clockNow=d.timeWindow.notAfter+1000;
 const report=createVerificationReport(record,{actionIndex:request.actionIndex,payload,signature,expectedActionEnvelopeHash:record.actionEnvelopeHash});
 console.log(JSON.stringify({case:name,mintStatus:mintResponse.statusCode,registrationStatus:registered.statusCode,beforeExpiryValid:beforeExpiry.valid,...registered.statusCode!==201?{registrationBody:JSON.parse(registered.body)}:{},sdkAfterExpiry:sdk.verifyRecord(record,{actionIndex:request.actionIndex,payload,signature,expectedActionEnvelopeHash:record.actionEnvelopeHash}).valid,afterDelegateAndActionExpiry:{valid:report.valid,reason:report.reason??null},mintCount:rows.get('MINT_DELEGATE#'+d.delegateId)?.mintCount,maxMints:d.maxMints,conditions:'In-memory database; optional legitimacy in audit mode; verification core invoked directly'}));
 clockNow=initialNow;
}

for(const [name,timeWindow,mode] of [
 ['unbounded-action',{notBefore:null,notAfter:null},'ACTION'],
 ['finite-window-action-mode',{notBefore:initialNow-1000,notAfter:initialNow+60000},'ACTION'],
 ['finite-window-both-mode',{notBefore:initialNow-1000,notAfter:initialNow+60000},'BOTH'],
 ['unbounded-both-mode',{notBefore:null,notAfter:null},'BOTH'],
]) {
 rows.delete('MINT_DELEGATE#'+d.delegateId);
 await runCase(name,timeWindow,mode);
}
rows.delete('MINT_DELEGATE#'+d.delegateId);
for(let i=1;i<=4;i++)await runCase('mint-budget-'+i,{notBefore:initialNow-1000,notAfter:initialNow+60000},'BOTH');
'@ | node --import tsx --input-type=module
```

Historical pre-fix observations: the fourth request under maxMints=3 returns mintStatus=409, registrationStatus=201 and beforeExpiryValid=true; finite ACTION registration ignores its dates; unbounded BOTH is accepted by the backend but rejected by the SDK.

## Faults ranked by seriousness

Ranked by potential impact, not confirmed production exploitability. Confirmed defects are distinguished from integration requirements and architectural boundaries. The evidence establishes local code behaviour; deployed-service behaviour was not tested.

1. **Mint-budget rejection bypass — confirmed defect, now fixed locally (point 1; deployment pending).** Previously, a rejected mint left a nonce record that registration accepted. Atomic budget admission and an admitted status/request hash now close this path. Existing registered records are not retroactively reviewed or revoked. See the remediation record below.

2. **Intended expiry can be bypassed — confirmed defects (point 2).** Requests can omit finite delegate bounds, and registration can accept a decay mode that disables the dates. Backend validation also accepts an unbounded BOTH envelope that the SDK rejects. Enforce boundary containment, bind the expiry-enforcing mode to admitted policy, and align validators. Correctly formed TIME/BOTH capabilities do enforce expiry.

3. **A valid signature does not establish that the command is within scope — integration requirement (point 4).** Generic verification accepts signed payloads without interpreting their operation, target, or duration. This is serious if an executor treats `valid: true` as complete authorization. Require domain-specific payload-to-authority checks before execution.

4. **Replay and maximum uses are not enforced by verification — architectural boundary (points 1 and 3).** The same signed command can verify repeatedly. An execution layer must enforce consumption and idempotency; hosted verification alone does not provide this. Public envelope JSON alone is not sufficient to sign or replay an authorized command.

5. **Portal cannot configure restricted bot identities — confirmed feature gap (point 5).** SDK/backend address restrictions work, but portal issuance hard-codes `any-signed-bot`. Add policy selection and an allowed-address list to the portal form, types, and signed builder.

6. **Portal wording overstates demonstrated guarantees — confirmed presentation issue (point 7).** The homepage proof ignores expiry, and use-limit descriptions do not explain the required external counter. Align the displayed claims with the checks performed and make integration responsibilities explicit.

**Not established as product faults:** the claimed large-scale blast radius depends on actual secret custody (point 6); the email-delay cause remains unknown (point 8). Demo settings do not establish portal defaults or a product-wide vulnerability.

## Remediation record: mint-budget registration bypass

Status: **fixed and tested locally; not deployed**. Scope: only the mint-budget/admission issue and its request binding, not the remaining expiry, use-consumption, semantics, bot-policy, or presentation findings.

### Cause and implementation

The old mint path wrote a replay nonce before charging the budget. Its 409 failure left that row behind; registration treated the row as proof of successful minting.

The backend now:

1. Uses `admitMintRequest()` in [shared/db.ts](../agent-envelope/amplify/functions/shared/db.ts) to submit one `TransactWriteCommand`: conditional nonce insertion and maxMints-guarded count increment commit together or neither commits. The two standalone write helpers were removed. This uses [DynamoDB transaction atomicity](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html).
2. Stores `admissionStatus: 'admitted'` and `requestHash` with the existing request metadata. [shared/mint.ts](../agent-envelope/amplify/functions/shared/mint.ts) computes the hash from the canonical complete bot-signed request body, excluding the signature itself. This binds scope, dates, limits, identity, and other signed fields rather than relying on identifiers alone.
3. Makes [the mint handler](../agent-envelope/amplify/functions/verifyMintRequest/handler.ts) call that single admission operation. Duplicate nonce and exhausted-budget failures retain their 409 responses.
4. Makes [delegated registration](../agent-envelope/amplify/functions/registerDelegatedSovereignAgent/handler.ts) read the ledger consistently and require admitted status, matching delegate/request identifiers, and the exact request hash. Missing, legacy, pending, or mismatched admission cannot authorize registration.

Admission means the budget was charged successfully; it does not promise that the HTTP response was delivered or that later audit/receipt processing succeeded. Response-loss/idempotent receipt recovery is not added by this fix.

### Regression results

The tracked regression in [register-delegated.test.js](../agent-envelope/tests/register-delegated.test.js) runs the actual handlers, signature/policy checks, and database helper with an in-memory transactional transport. Its fixtures use required delegate legitimacy in enforce mode.

| Case | Post-fix result |
| --- | --- |
| Three requests under maxMints=3 | Mint 200 and registration 201 for each; count reaches 3 |
| Fourth request | Mint 409, registration 403; no nonce admission or public record; count stays 3 |
| Duplicate nonce | Mint 409; no additional budget consumed; original admission unchanged |
| Two requests competing for the last slot | One admitted, one rejected; exactly one nonce and one budget increment in the test model |
| Database failure before transaction commit | No admission or count record; registration denied |
| Legacy/pending row, absent/wrong hash, or absent request ID | Registration 403; no public record written |
| Re-signed altered resource scope with the same nonce/request ID | Registration 403 because the complete request-body hash differs |

Validation after the fix:

- `npm test` in the backend: **126 tests passed across 14 files**.
- `npx tsc --noEmit -p amplify/tsconfig.json`: **passed**.
- Database-helper tests assert a single transaction containing both conditional writes; handler tests check complete request hashing and error responses.
- The existing local database/mint-handler test files remain covered by the repository's ignore rules; the end-to-end admission regression is in the already tracked registration test file.
- No live AWS/DynamoDB or deployed portal test was performed. The concurrent-request test exercises the in-memory model; production atomicity relies on DynamoDB's transaction implementation, not a simulated load test.

### Compatibility and rollout

- Old nonce rows lack trustworthy admission evidence. They are intentionally rejected for new registrations, even if some came from legitimate successful mints. Do not automatically backfill approval from nonce existence or the aggregate counter.
- Unpublished legacy requests need a fresh signed request/nonce and available budget, or an explicitly authorized reconciliation/reissue process. This fix does not reset counters or migrate production records.
- Existing registered public records are not changed or revoked. Any retrospective review is separate work.
- Deploy both handlers together in a coordinated release, or deploy stricter registration first and accept temporary registration denials while the old mint writer remains active. Updating only mint leaves historical orphan rows usable by old registration.
- Before rollout, verify the deployed role/table permissions support the transaction and run the budget-exhaustion regression against a non-production deployment.
- SDK, portal, API payload shapes, and successful response formats do not need changes for this fix. Backend architecture/data-model documentation has been updated.
