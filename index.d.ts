// AgentEnvelope SDK — worker/bot-side types only.

export type DecayMode = 'NONE' | 'TIME' | 'ACTION' | 'BOTH';

export interface TimeWindow {
    notBefore: number | null;
    notAfter: number | null;
}

export interface ActionIndexPolicy {
    min: number;
    max: number;
}

export type LegitimacyStatus = 'legitimate' | 'suspended' | 'invalid' | 'closed' | 'compromised';
export type LegitimacyScopeKind = 'domain' | 'delegate' | 'record' | 'agent';

export interface LegitimacyRef {
    legitimacyId: string;
    stateVersion?: number;
    stateHash?: string;
    policyId?: string;
    required?: boolean;
}

export interface LegitimacyState {
    type: 'agentenvelope.legitimacyState';
    version: 1;
    legitimacyId: string;
    ownerUserId: string;
    status: LegitimacyStatus;
    stateVersion: number;
    stateHash: string;
    reasonCode?: string;
    scope: { kind: LegitimacyScopeKind; id: string; domainHash?: string };
    policyRef: { policyId: string; policyVersion: number; policyHash: string };
    assumptions: Array<{ assumptionId: string; assumptionVersion: number; assumptionHash: string; label?: string }>;
    evidence: Array<{ kind: string; uri?: string; sha256?: string; label?: string; metadata?: Record<string, unknown> }>;
    createdAt: string;
    updatedAt: string;
    expiresAt?: string | null;
    closedAt?: string | null;
    compromisedAt?: string | null;
}

export interface LegitimacyEvent {
    type: 'agentenvelope.legitimacyEvent';
    version: 1;
    eventId: string;
    eventType: 'jurisdiction.change' | 'evidence.invalidation' | 'objective.closure' | 'endpoint.compromised' | 'policy.custom';
    legitimacyId: string;
    occurredAt: string;
    effectiveAt: string;
    scope: LegitimacyState['scope'];
    patch: Record<string, unknown>;
    evidence: LegitimacyState['evidence'];
    producer: { authorityId: string; keyId: string };
    signature: { alg: 'secp256k1-keccak256'; signerAddress: string; value: string };
}

// Opaque record received from the console or API — workers verify against it, never construct it.
export interface PublicActionRecord {
    type: 'agentenvelope.publicActionRecord';
    version: 1;
    recordId: string;
    agentId: string;
    agentAddress: string;
    status: string;
    domain: { domainId: string; domainHash: string };
    actionEnvelope: { actionIndex: number; [key: string]: unknown };
    actionEnvelopeHash: string;
    legitimacyRef?: LegitimacyRef;
    expiry: string | null;
    [key: string]: unknown;
}

export interface MintDelegate {
    type: 'agentenvelope.mintDelegate';
    version: 1;
    delegateId: string;
    legitimacyRef?: LegitimacyRef;
    issuerAddress: string;
    avatarAddress?: string;
    domainHash: string;
    allowedOperations: string[];
    allowedResources: string[];
    botPolicy: 'any-signed-bot' | 'address-set';
    allowedBotAddresses?: string[];
    actionIndexPolicy: ActionIndexPolicy;
    maxMints: number;
    maxUsesPerAction: number;
    timeWindow: TimeWindow;
    nonce: string;
    issuedAt: string;
    issuerSignature: string;
}

export interface MintDelegateInput {
    avatarAddress?: string;
    domainHash: string;
    legitimacyRef?: LegitimacyRef;
    allowedOperations: string[];
    allowedResources: string[];
    botPolicy: 'any-signed-bot' | 'address-set';
    allowedBotAddresses?: string[];
    actionIndexPolicy: ActionIndexPolicy;
    maxMints: number;
    maxUsesPerAction: number;
    timeWindow: TimeWindow;
    nonce: string;
    issuedAt: string;
}

export interface MintRequestInput {
    agentId: string;
    operation: string;
    resources: string[];
    actionIndex: number;
    maxUses: number;
    timeWindow: TimeWindow;
    nonce: string;
    requestedAt: string;
    legitimacyId?: string;
}

export interface MintRequest {
    type: 'agentenvelope.mintRequest';
    version: 1;
    requestId: string;
    delegateId: string;
    delegateHash: string;
    botAddress: string;
    agentId: string;
    operation: string;
    resources: string[];
    actionIndex: number;
    maxUses: number;
    timeWindow: TimeWindow;
    nonce: string;
    requestedAt: string;
    legitimacyId?: string;
    botSignature: string;
}

export interface VerifyActionResult {
    valid: boolean;
    reason?: string;
    recoveredAddress?: string;
}

export interface MintVerifyResult {
    valid: boolean;
    reason?: string;
}

export interface VerifyRecordResult {
    type: 'agentenvelope.verificationReport';
    version: 1;
    valid: boolean;
    reason?: string;
    checkedAt: string;
    recordId?: string;
    agentId?: string;
    actionEnvelopeHash?: string;
    expectedActionEnvelopeHash?: string;
    checks?: {
        recordActive: boolean;
        actionRegistered: boolean;
        canonicalActionEnvelopeMatches: boolean;
        actionEnvelopeHashConsistent: boolean;
        domainCanonicalMatches: boolean;
        domainHashConsistent: boolean;
        domainHashMatches: boolean;
        domainIdMatches: boolean;
        actionEnvelopeShapeValid: boolean;
        signatureWellFormed: boolean;
        signatureValid: boolean;
        addressMatchesRecord: boolean;
        actionEnvelopeHashMatches: boolean;
        decayed: boolean;
    };
    addresses?: { agentAddress: string; recoveredActionAddress?: string };
    domain?: { domainId: string; domainHash: string };
    actionIndex?: number;
}

export function canonicalJSON(value: unknown): string;
export function contentHash(value: unknown): string;
export function hexToBytes(value: string): Uint8Array;
export function signAction(actionSeed: Uint8Array, message: unknown): string;
export function verifyAction(input: { message: unknown; signature: string; expectedAddress: string }): VerifyActionResult;
export function recoverActionAddress(message: unknown, signature: string): string;
export function verifyRecord(record: PublicActionRecord, input: { payload: unknown; signature: string; actionIndex: number; expectedActionEnvelopeHash?: string }): VerifyRecordResult;
export function buildMintDelegate(domainSeed: Uint8Array, input: MintDelegateInput): MintDelegate;
export function verifyMintDelegate(delegate: MintDelegate, expectedIssuerAddress: string): MintVerifyResult;
export function buildMintRequest(botSeed: Uint8Array, delegate: MintDelegate, input: MintRequestInput): MintRequest;
export function verifyMintRequest(request: MintRequest, delegate: MintDelegate): MintVerifyResult;
export function isAuthorityLegitimate(state: LegitimacyState): MintVerifyResult;

// Remote-mint capability derived locally by the bot after the hosted verifier accepts its request.
export interface RemoteMintCapability {
    type: 'agentenvelope.agentCapability';
    version: 1;
    custodyMode: 'remote-mint-delegate';
    generatedAt: string;
    warning: string;
    delegateId: string;
    requestId: string;
    agentAddress: string;
    /** Private signing material. Never log or sync this value. */
    actionSeedHex: string;
}

export function seedAddress(seed: Uint8Array): string;
export function deriveMintMaterial(identityRoot: Uint8Array, domain: { domainHash: string }): Uint8Array;
export function mintActionCapability(mintMaterial: Uint8Array, delegate: MintDelegate, request: MintRequest): RemoteMintCapability;

// A signed statement from AgentEnvelope's hosted verifier about a fact it computed.
// It certifies "this record / mint request was checked and found in scope at time T" —
// never that anything is "legitimate", and it never holds a user seed.
export interface ReceiptAttestation {
    attesterAddress: string;
    alg: 'secp256k1-keccak256';
    signature: string;
}

export interface VerifyReceiptResult {
    valid: boolean;
    reason?: string;
    /** Address recovered from the receipt signature (present on success and on mismatch). */
    attesterAddress?: string;
    recoveredAddress?: string;
}

/** Signs a hosted-verifier receipt body with an attester seed. The `attestation` field,
 *  if present on the input, is stripped before signing. Used by the hosted backend. */
export function signReceipt(attesterSeed: Uint8Array, receiptBody: Record<string, unknown>): ReceiptAttestation;

/** Verifies an attested receipt. Always pass the published attester address as
 *  `expectedAttesterAddress` — without it, only self-consistency is checked. */
export function verifyReceipt(receipt: Record<string, unknown> & { attestation?: ReceiptAttestation }, expectedAttesterAddress?: string): VerifyReceiptResult;
