/**
 * Optional hosted governance client.
 *
 * The core SDK verifies and signs locally with no network dependency. This
 * client talks to AgentEnvelope hosted APIs for operated services such as
 * public records, verifier receipts, mint governance, usage ledgers, and
 * legitimacy state. The API key meters service access; it is not agent signing
 * authority.
 */
export interface AgentEnvelopeClientConfig {
    apiKey: string;
}

export interface VerifyActionApiInput {
    agentId: string;
    actionIndex: number;
    payload: unknown;
    signature: string;
    expectedActionEnvelopeHash?: string;
}

export interface MintApiInput {
    delegate: unknown;
    request: unknown;
}

export type LegitimacyStatus = 'legitimate' | 'suspended' | 'invalid' | 'closed' | 'compromised';

export interface LegitimacyCreateInput {
    legitimacyId?: string;
    ownerUserId?: string;
    status?: LegitimacyStatus;
    reasonCode?: string;
    scope: { kind: 'domain' | 'delegate' | 'record' | 'agent'; id: string; domainHash?: string };
    policyRef: { policyId: string; policyVersion: number; policyHash: string };
    assumptions?: unknown[];
    evidence?: unknown[];
    expiresAt?: string | null;
}

export interface LegitimacyPatchInput {
    legitimacyId: string;
    event: unknown;
}

/** Error wrapper for non-2xx hosted API responses. */
export declare class AgentEnvelopeApiError extends Error {
    status: number;
    code?: string;
    body?: unknown;
    legitimacy?: unknown;
}

export declare class AgentEnvelopeClient {
    /** apiKey meters hosted governance access; it is not agent signing authority. */
    constructor(config: AgentEnvelopeClientConfig);

    /** Hosted verification for a payload/signature against a public record. */
    verifyAction(input: VerifyActionApiInput): Promise<unknown>;

    /** Fetches a published public agent/action record by agent id. */
    getAgent(agentId: string): Promise<unknown>;

    /** Fetches a stored mint delegate by delegate id. */
    getStoredDelegate(delegateId: string): Promise<unknown>;

    /** Submits a signed delegate and signed mint request to hosted governance. */
    mint(input: MintApiInput): Promise<unknown>;

    /** Creates or replaces a legitimacy state used by governed flows. */
    setLegitimacyState(input: LegitimacyCreateInput): Promise<unknown>;

    /** Applies a legitimacy event/patch to an existing legitimacy state. */
    patchLegitimacyState(input: LegitimacyPatchInput): Promise<unknown>;

    /** Fetches the latest legitimacy state by id. */
    getLegitimacyState(legitimacyId: string): Promise<unknown>;
}
