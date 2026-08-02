import type { DecayMode } from './index.d.ts';

export interface DomainInfoInput {
    namespace: string;
    domainId: string;
    kind: string;
}

export interface DomainInfo {
    type: 'agentenvelope.domainInfo';
    version: 1;
    namespace: string;
    domainId: string;
    kind: string;
}

export interface DomainKeySummary {
    domainInfo: DomainInfo;
    canonicalDomainInfo: string;
    domainHash: string;
    domainAddress: string;
    domainFingerprint: string;
    createdAt: string;
}

export interface ActionEnvelopeInput {
    agentId: string;
    actionIndex: number;
    operation: string;
    resources: string[] | string;
    notBefore: number | null;
    notAfter: number | null;
    decayMode: DecayMode;
    maxUses: number | null;
}

export interface ActionEnvelope {
    type: 'agentenvelope.actionEnvelope';
    version: 1;
    agentId: string;
    domain: { domainId: string; domainHash: string };
    actionIndex: number;
    operation: string;
    resources: string[];
    timeWindow: { notBefore: number | null; notAfter: number | null };
    decayPolicy: { mode: DecayMode };
    limits: { maxUses: number | null; enforcement: 'external' };
}

export interface AgentActionCapability {
    type: 'agentenvelope.agentCapability';
    version: 1;
    custodyMode: 'sovereign-browser';
    generatedAt: string;
    warning: string;
    domain: DomainKeySummary;
    actionEnvelope: ActionEnvelope;
    canonicalActionEnvelope: string;
    actionEnvelopeHash: string;
    agentAddress: string;
    /** Private signing material — treat as a private key. Zero after use. */
    actionSeedHex: string;
}

export interface PublicActionRecordOptions {
    ownerUserId: string;
    createdAt?: Date;
}

export interface SovereignPublicActionRecord {
    type: 'agentenvelope.publicActionRecord';
    version: 1;
    recordId: string;
    ownerUserId: string;
    custodyMode: 'sovereign-browser';
    verifierProfile: 'domain-action-envelope';
    status: 'active';
    createdAt: string;
    agentId: string;
    agentAddress: string;
    domain: DomainKeySummary;
    actionEnvelope: ActionEnvelope;
    canonicalActionEnvelope: string;
    actionEnvelopeHash: string;
    expiry: string | null;
}

/**
 * Validate and normalise a DomainInfo descriptor.
 */
export function createDomainInfo(input: DomainInfoInput): DomainInfo;

/**
 * Derive the public domain projection from an identity root and a DomainInfo.
 * The domain seed is zeroed after use.
 *
 * @param identityRoot  32-byte vault root — keep secret, zero after use.
 */
export function projectDomainKey(identityRoot: Uint8Array, domainInfo: DomainInfo, now?: Date): DomainKeySummary;

/**
 * Build and validate an ActionEnvelope from a domain summary and input fields.
 */
export function buildActionEnvelope(domain: DomainKeySummary, input: ActionEnvelopeInput): ActionEnvelope;

/**
 * Derive a private AgentActionCapability from an identity root, domain summary, and action envelope.
 * Both the domain seed and action seed are zeroed after use.
 *
 * CUSTODY WARNING: the returned object contains actionSeedHex — private signing material.
 * Give it only to the specific worker that needs this exact authority. Never log or sync it.
 *
 * @param identityRoot  32-byte vault root — keep secret, zero after use.
 */
export function deriveAgentActionCapability(
    identityRoot: Uint8Array,
    domain: DomainKeySummary,
    envelope: ActionEnvelope,
    now?: Date,
): AgentActionCapability;

/**
 * Build a metadata-only public action record from a capability.
 * Contains no actionSeedHex — safe to store, publish, and hand to verifiers.
 */
export function createPublicActionRecord(
    capability: AgentActionCapability,
    options: PublicActionRecordOptions,
): SovereignPublicActionRecord;

/**
 * Serialize an AgentActionCapability to a pretty-printed JSON string.
 * The result contains actionSeedHex — treat it as a private key.
 */
export function serializeAgentActionCapability(capability: AgentActionCapability): string;

/**
 * Serialize a public action record to a pretty-printed JSON string.
 * Safe to store, publish, and hand to verifiers.
 */
export function serializePublicActionRecord(record: SovereignPublicActionRecord): string;
