import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalJSON, contentHash } from './index.js';

const encoder = new TextEncoder();
const SALT = encoder.encode('agentenvelope-v1');
const SECP256K1_N = secp256k1.CURVE.n;
const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{0,127}$/;

// ─── Internal helpers ────────────────────────────────────────────────────────

function _utf8(s) {
    return encoder.encode(s);
}

function _sha256hex(bytes) {
    return `0x${bytesToHex(sha256(bytes))}`;
}

function _seedToKey(seed) {
    let key = seed;
    for (let i = 0; i <= 8; i++) {
        if (BigInt(`0x${bytesToHex(key)}`) > 0n && BigInt(`0x${bytesToHex(key)}`) < SECP256K1_N) return key;
        key = hkdf(sha256, key, SALT, _utf8('key'), 32);
    }
    throw new Error('could not derive valid secp256k1 key');
}

function _seedAddress(seed) {
    const pub = secp256k1.getPublicKey(_seedToKey(seed), false);
    return `0x${bytesToHex(keccak_256(pub.slice(1)).slice(-20))}`;
}

function _hkdf(ikm, info) {
    return hkdf(sha256, ikm, SALT, info, 32);
}

function _normalizeIdentifier(value, label) {
    const normalized = value.trim().toLowerCase();
    if (!IDENTIFIER.test(normalized)) throw new Error(`${label} must be a stable lowercase identifier`);
    return normalized;
}

function _normalizeResources(value) {
    const entries = (Array.isArray(value) ? value : value.split(','))
        .map((r) => r.trim().toLowerCase())
        .filter(Boolean);
    return [...new Set(entries)].sort();
}

function _deriveDomainSeed(identityRoot, domainInfo) {
    if (!(identityRoot instanceof Uint8Array) || identityRoot.length !== 32)
        throw new Error('identityRoot must be a 32-byte Uint8Array');
    return _hkdf(identityRoot, _utf8(canonicalJSON({ purpose: 'domain', domainInfo })));
}

function _actionEnvelopeExpiry(envelope) {
    const notAfter = envelope.timeWindow?.notAfter;
    return typeof notAfter === 'number' && Number.isFinite(notAfter) ? new Date(notAfter).toISOString() : null;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Validate and normalise a DomainInfo descriptor.
 * The returned object is the canonical derivation input — never mutate it.
 */
export function createDomainInfo({ namespace, domainId, kind }) {
    return {
        type: 'agentenvelope.domainInfo',
        version: 1,
        namespace: _normalizeIdentifier(namespace, 'Namespace'),
        domainId: _normalizeIdentifier(domainId, 'Domain id'),
        kind: _normalizeIdentifier(kind, 'Domain kind'),
    };
}

/**
 * Derive the public domain projection from an identity root and a DomainInfo.
 * The domain seed is zeroed after use. Returns a DomainKeySummary.
 *
 * @param {Uint8Array} identityRoot  32-byte vault root — keep secret, zero after use.
 * @param {object}     domainInfo    Output of createDomainInfo().
 * @param {Date}       [now]
 * @returns {object}   DomainKeySummary — safe to store and publish.
 */
export function projectDomainKey(identityRoot, domainInfo, now = new Date()) {
    const canonicalDomainInfo = canonicalJSON(domainInfo);
    const domainHash = _sha256hex(_utf8(canonicalDomainInfo));
    const domainSeed = _deriveDomainSeed(identityRoot, domainInfo);
    try {
        const domainAddress = _seedAddress(domainSeed);
        const domainFingerprint = `ae-domain-${bytesToHex(sha256(_utf8(canonicalJSON({ domainAddress, domainHash })))).slice(0, 16)}`;
        return {
            domainInfo,
            canonicalDomainInfo,
            domainHash,
            domainAddress,
            domainFingerprint,
            createdAt: now.toISOString(),
        };
    } finally {
        domainSeed.fill(0);
    }
}

/**
 * Build and validate an ActionEnvelope from a domain summary and input fields.
 *
 * @param {object} domain  DomainKeySummary from projectDomainKey().
 * @param {object} input   { agentId, actionIndex, operation, resources, notBefore, notAfter, decayMode, maxUses }
 * @returns {object}  ActionEnvelope — safe to store and publish.
 */
export function buildActionEnvelope(domain, input) {
    const agentId = _normalizeIdentifier(input.agentId, 'Agent id');
    const operation = _normalizeIdentifier(input.operation, 'Operation');
    const resources = _normalizeResources(input.resources);
    const { actionIndex, decayMode: mode, maxUses, notBefore, notAfter } = input;

    if (!Number.isInteger(actionIndex) || actionIndex < 0)
        throw new Error('Action index must be a non-negative integer');
    if (resources.length === 0)
        throw new Error('At least one resource is required');
    if ((mode === 'TIME' || mode === 'BOTH') && !Number.isFinite(notBefore) && !Number.isFinite(notAfter))
        throw new Error('Time decay requires a start or end time');
    if (notBefore !== null && notAfter !== null && notAfter <= notBefore)
        throw new Error('End time must be after start time');
    if ((mode === 'ACTION' || mode === 'BOTH') && (!Number.isInteger(maxUses) || maxUses === null || maxUses < 1))
        throw new Error('Action decay requires a positive maximum use count');
    if ((mode === 'NONE' || mode === 'TIME') && maxUses !== null && (!Number.isInteger(maxUses) || maxUses < 1))
        throw new Error('Maximum uses must be a positive integer or null');

    return {
        type: 'agentenvelope.actionEnvelope',
        version: 1,
        agentId,
        domain: { domainId: domain.domainInfo.domainId, domainHash: domain.domainHash },
        actionIndex,
        operation,
        resources,
        timeWindow: { notBefore: notBefore ?? null, notAfter: notAfter ?? null },
        decayPolicy: { mode },
        limits: { maxUses: maxUses ?? null, enforcement: 'external' },
    };
}

/**
 * Derive a private AgentActionCapability from an identity root, domain summary, and action envelope.
 * Both the domain seed and action seed are zeroed after use.
 *
 * CUSTODY WARNING: the returned object contains actionSeedHex — private signing material.
 * Give it only to the specific worker that needs this exact authority. Never log or sync it.
 *
 * @param {Uint8Array} identityRoot  32-byte vault root — keep secret, zero after use.
 * @param {object}     domain        DomainKeySummary from projectDomainKey().
 * @param {object}     envelope      ActionEnvelope from buildActionEnvelope().
 * @param {Date}       [now]
 * @returns {object}   AgentActionCapability — contains actionSeedHex, treat as a private key.
 */
export function deriveAgentActionCapability(identityRoot, domain, envelope, now = new Date()) {
    if (envelope.domain.domainId !== domain.domainInfo.domainId || envelope.domain.domainHash !== domain.domainHash)
        throw new Error('Action envelope does not match the selected domain');

    const domainSeed = _deriveDomainSeed(identityRoot, domain.domainInfo);
    try {
        if (_seedAddress(domainSeed) !== domain.domainAddress)
            throw new Error('Selected domain does not belong to this vault');

        const canonicalActionEnvelope = canonicalJSON(envelope);
        const actionEnvelopeHash = _sha256hex(_utf8(canonicalActionEnvelope));
        const actionSeed = _hkdf(domainSeed, _utf8(canonicalJSON({ purpose: 'action', actionEnvelope: envelope })));
        try {
            return {
                type: 'agentenvelope.agentCapability',
                version: 1,
                custodyMode: 'sovereign-browser',
                generatedAt: now.toISOString(),
                warning: 'Contains a private action seed. Give it only to the worker that needs this exact authority.',
                domain,
                actionEnvelope: envelope,
                canonicalActionEnvelope,
                actionEnvelopeHash,
                agentAddress: _seedAddress(actionSeed),
                actionSeedHex: bytesToHex(actionSeed),
            };
        } finally {
            actionSeed.fill(0);
        }
    } finally {
        domainSeed.fill(0);
    }
}

/**
 * Build a metadata-only public action record from a capability.
 * Contains no actionSeedHex — safe to store, publish, and hand to verifiers.
 *
 * @param {object} capability  AgentActionCapability from deriveAgentActionCapability().
 * @param {object} options     { ownerUserId: string, createdAt?: Date }
 * @returns {object}  SovereignPublicActionRecord
 */
export function createPublicActionRecord(capability, { ownerUserId, createdAt } = {}) {
    if (!ownerUserId || typeof ownerUserId !== 'string') throw new Error('ownerUserId is required');
    const ts = (createdAt ?? new Date()).toISOString();
    const recordId = `ae-action-${contentHash({
        ownerUserId,
        agentAddress: capability.agentAddress,
        actionEnvelopeHash: capability.actionEnvelopeHash,
    }).slice(2, 22)}`;
    return {
        type: 'agentenvelope.publicActionRecord',
        version: 1,
        recordId,
        ownerUserId,
        custodyMode: capability.custodyMode,
        verifierProfile: 'domain-action-envelope',
        status: 'active',
        createdAt: ts,
        agentId: capability.actionEnvelope.agentId,
        agentAddress: capability.agentAddress,
        domain: capability.domain,
        actionEnvelope: capability.actionEnvelope,
        canonicalActionEnvelope: capability.canonicalActionEnvelope,
        actionEnvelopeHash: capability.actionEnvelopeHash,
        expiry: _actionEnvelopeExpiry(capability.actionEnvelope),
    };
}

/**
 * Serialize an AgentActionCapability to a pretty-printed JSON string.
 * The result contains actionSeedHex — treat it as a private key.
 */
export function serializeAgentActionCapability(capability) {
    return `${JSON.stringify(capability, null, 2)}\n`;
}

/**
 * Serialize a public action record to a pretty-printed JSON string.
 * Safe to store, publish, and hand to verifiers.
 */
export function serializePublicActionRecord(record) {
    return `${JSON.stringify(record, null, 2)}\n`;
}
