import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex } from '@noble/hashes/utils';
import { DECAY_MODES } from './constants.js';

const encoder = new TextEncoder();
const SECP256K1_N = secp256k1.CURVE.n;

// Internal byte prefixes — not named constants, not exported.
const _a = encoder.encode('\x19AgentEnvelope Signed Message:\n');
const _b = encoder.encode('\x19AgentEnvelope Mint Delegate:\n');
const _c = encoder.encode('\x19AgentEnvelope Mint Request:\n');
const _d = encoder.encode('\x19AgentEnvelope Attestation:\n');
const _s = encoder.encode('agentenvelope-v1');

function _prefix(pre, msg) {
    const b = new Uint8Array(pre.length + msg.length);
    b.set(pre);
    b.set(msg, pre.length);
    return b;
}

function _msgHash(message) {
    return keccak_256(_prefix(_a, encoder.encode(canonicalJSON(message))));
}

function _seedToKey(seed) {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('seed must be a 32-byte Uint8Array');
    let key = seed;
    for (let i = 0; i <= 8; i++) {
        if (BigInt(`0x${bytesToHex(key)}`) > 0n && BigInt(`0x${bytesToHex(key)}`) < SECP256K1_N) return key;
        key = hkdf(sha256, key, _s, encoder.encode('key'), 32);
    }
    throw new Error('could not derive valid key');
}

function _seedAddr(seed) {
    const pub = secp256k1.getPublicKey(_seedToKey(seed), false);
    return `0x${bytesToHex(keccak_256(pub.slice(1)).slice(-20))}`;
}

export function canonicalJSON(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return JSON.stringify(value);
    return `{${Object.keys(value)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${canonicalJSON(value[k])}`)
        .join(',')}}`;
}

export function contentHash(value) {
    const input = typeof value === 'string' ? value : canonicalJSON(value);
    return `0x${bytesToHex(sha256(encoder.encode(input)))}`;
}

export function hexToBytes(value) {
    const hex = value.startsWith('0x') ? value.slice(2) : value;
    if (!/^[a-fA-F0-9]*$/.test(hex) || hex.length % 2 !== 0) throw new Error('hex value must contain an even number of hex characters');
    return Uint8Array.from({ length: hex.length / 2 }, (_, i) => Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}

export function seedAddress(seed) {
    return _seedAddr(seed);
}

export function signAction(actionSeed, message) {
    const sig = secp256k1.sign(_msgHash(message), _seedToKey(actionSeed));
    return `0x${sig.r.toString(16).padStart(64, '0')}${sig.s.toString(16).padStart(64, '0')}${(sig.recovery + 27).toString(16).padStart(2, '0')}`;
}

export function recoverActionAddress(message, signature) {
    const hex = signature.startsWith('0x') ? signature.slice(2) : signature;
    if (!/^[a-fA-F0-9]{130}$/.test(hex)) throw new Error('signature must be 65 bytes');
    const recovery = Number.parseInt(hex.slice(128, 130), 16) - 27;
    if (recovery !== 0 && recovery !== 1) throw new Error('signature recovery byte must be 27 or 28');
    const sig = secp256k1.Signature.fromCompact(hex.slice(0, 128)).addRecoveryBit(recovery);
    const pub = sig.recoverPublicKey(_msgHash(message)).toRawBytes(false);
    return `0x${bytesToHex(keccak_256(pub.slice(1)).slice(-20))}`;
}

export function verifyAction({ message, signature, expectedAddress }) {
    try {
        const recovered = recoverActionAddress(message, signature);
        if (recovered.toLowerCase() !== expectedAddress.toLowerCase()) return { valid: false, reason: 'address mismatch', recoveredAddress: recovered };
        return { valid: true, recoveredAddress: recovered };
    } catch (err) {
        return { valid: false, reason: err instanceof Error ? err.message : 'verification failed' };
    }
}

// --- Attestations -----------------------------------------------------------
// A receipt attestation is AgentEnvelope's own signed statement about a fact the
// hosted verifier computed. Verifiers should pin the published attester address
// out-of-band; the address inside a receipt is a convenience, not a root of trust.
function _receiptHash(receiptBody) {
    return keccak_256(_prefix(_d, encoder.encode(canonicalJSON(receiptBody))));
}

export function signReceipt(attesterSeed, receiptBody) {
    const { attestation: _drop, ...body } = receiptBody ?? {};
    const sig = secp256k1.sign(_receiptHash(body), _seedToKey(attesterSeed));
    const signature = `0x${sig.r.toString(16).padStart(64, '0')}${sig.s.toString(16).padStart(64, '0')}${(sig.recovery + 27).toString(16).padStart(2, '0')}`;
    return { attesterAddress: _seedAddr(attesterSeed), alg: 'secp256k1-keccak256', signature };
}

export function verifyReceipt(receipt, expectedAttesterAddress) {
    try {
        if (!receipt || typeof receipt !== 'object') return { valid: false, reason: 'receipt must be an object' };
        const { attestation, ...body } = receipt;
        if (!attestation || typeof attestation !== 'object') return { valid: false, reason: 'receipt is not attested' };
        const { attesterAddress, signature } = attestation;
        if (!/^0x[a-fA-F0-9]{40}$/.test(attesterAddress ?? '')) return { valid: false, reason: 'attesterAddress is invalid' };
        const hex = typeof signature === 'string' && signature.startsWith('0x') ? signature.slice(2) : signature;
        if (typeof hex !== 'string' || !/^[a-fA-F0-9]{130}$/.test(hex)) return { valid: false, reason: 'signature must be 65 bytes' };
        const recovery = Number.parseInt(hex.slice(128, 130), 16) - 27;
        if (recovery !== 0 && recovery !== 1) return { valid: false, reason: 'signature recovery byte must be 27 or 28' };
        const sig = secp256k1.Signature.fromCompact(hex.slice(0, 128)).addRecoveryBit(recovery);
        const pub = sig.recoverPublicKey(_receiptHash(body)).toRawBytes(false);
        const recoveredAddress = `0x${bytesToHex(keccak_256(pub.slice(1)).slice(-20))}`;
        if (recoveredAddress.toLowerCase() !== attesterAddress.toLowerCase()) return { valid: false, reason: 'attester address mismatch', recoveredAddress };
        if (expectedAttesterAddress && recoveredAddress.toLowerCase() !== expectedAttesterAddress.toLowerCase()) return { valid: false, reason: 'unexpected attester', recoveredAddress };
        return { valid: true, attesterAddress: recoveredAddress, recoveredAddress };
    } catch (err) {
        return { valid: false, reason: err instanceof Error ? err.message : 'verification failed' };
    }
}

export function buildMintDelegate(domainSeed, input) {
    if (!(domainSeed instanceof Uint8Array) || domainSeed.length !== 32) throw new Error('domainSeed must be a 32-byte Uint8Array');
    const issuerAddress = _seedAddr(domainSeed);
    const { avatarAddress, domainHash, allowedOperations, allowedResources, botPolicy, allowedBotAddresses, actionIndexPolicy, maxMints, maxUsesPerAction, timeWindow, nonce, issuedAt } = input;
    if (avatarAddress !== undefined && !/^0x[a-fA-F0-9]{40}$/.test(avatarAddress)) throw new Error('avatarAddress must be a 0x-prefixed 20-byte hex address');
    if (botPolicy === 'address-set') {
        if (!Array.isArray(allowedBotAddresses) || allowedBotAddresses.length === 0) throw new Error('address-set policy requires at least one allowedBotAddresses entry');
        for (const addr of allowedBotAddresses) {
            if (!/^0x[a-fA-F0-9]{40}$/.test(addr)) throw new Error(`allowedBotAddresses entry is not a valid address: ${addr}`);
        }
    }
    const delegateId = `ae-delegate-${contentHash({ issuerAddress, domainHash, nonce }).slice(2, 18)}`;
    const delegateBody = { type: 'agentenvelope.mintDelegate', version: 1, delegateId, issuerAddress, ...(avatarAddress !== undefined ? { avatarAddress } : {}), domainHash, allowedOperations, allowedResources, botPolicy, ...(botPolicy === 'address-set' ? { allowedBotAddresses } : {}), actionIndexPolicy, maxMints, maxUsesPerAction, timeWindow, nonce, issuedAt };
    try {
        const hash = keccak_256(_prefix(_b, encoder.encode(canonicalJSON(delegateBody))));
        const sig = secp256k1.sign(hash, _seedToKey(domainSeed));
        const issuerSignature = `0x${sig.r.toString(16).padStart(64, '0')}${sig.s.toString(16).padStart(64, '0')}${(sig.recovery + 27).toString(16).padStart(2, '0')}`;
        return { ...delegateBody, issuerSignature };
    } finally {
        domainSeed.fill(0);
    }
}

export function verifyMintDelegate(delegate, expectedIssuerAddress) {
    try {
        const { issuerSignature, ...delegateBody } = delegate;
        if (delegateBody.type !== 'agentenvelope.mintDelegate') return { valid: false, reason: 'type is invalid' };
        if (delegateBody.version !== 1) return { valid: false, reason: 'version is invalid' };
        if (!/^0x[a-fA-F0-9]{40}$/.test(delegateBody.issuerAddress ?? '')) return { valid: false, reason: 'issuerAddress is invalid' };
        if (delegateBody.avatarAddress !== undefined && !/^0x[a-fA-F0-9]{40}$/.test(delegateBody.avatarAddress)) return { valid: false, reason: 'avatarAddress is invalid' };
        if (!/^0x[a-fA-F0-9]{64}$/.test(delegateBody.domainHash ?? '')) return { valid: false, reason: 'domainHash is invalid' };
        if (!Array.isArray(delegateBody.allowedOperations) || delegateBody.allowedOperations.length === 0) return { valid: false, reason: 'allowedOperations is invalid' };
        if (!Array.isArray(delegateBody.allowedResources) || delegateBody.allowedResources.length === 0) return { valid: false, reason: 'allowedResources is invalid' };
        if (!['any-signed-bot', 'address-set'].includes(delegateBody.botPolicy)) return { valid: false, reason: 'botPolicy is invalid' };
        if (!delegateBody.actionIndexPolicy || !Number.isInteger(delegateBody.actionIndexPolicy.min) || delegateBody.actionIndexPolicy.min < 0 || !Number.isInteger(delegateBody.actionIndexPolicy.max) || delegateBody.actionIndexPolicy.max < delegateBody.actionIndexPolicy.min) return { valid: false, reason: 'actionIndexPolicy is invalid' };
        if (!Number.isInteger(delegateBody.maxMints) || delegateBody.maxMints < 1) return { valid: false, reason: 'maxMints is invalid' };
        if (!Number.isInteger(delegateBody.maxUsesPerAction) || delegateBody.maxUsesPerAction < 1) return { valid: false, reason: 'maxUsesPerAction is invalid' };
        if (!/^0x[a-fA-F0-9]{64}$/.test(delegateBody.nonce ?? '')) return { valid: false, reason: 'nonce is invalid' };
        if (typeof delegateBody.issuedAt !== 'string') return { valid: false, reason: 'issuedAt is invalid' };
        if (!/^0x[a-fA-F0-9]{130}$/.test(issuerSignature ?? '')) return { valid: false, reason: 'issuerSignature is invalid' };
        const hash = keccak_256(_prefix(_b, encoder.encode(canonicalJSON(delegateBody))));
        const sHex = issuerSignature.slice(2);
        const rec = Number.parseInt(sHex.slice(128, 130), 16) - 27;
        const sig = secp256k1.Signature.fromCompact(sHex.slice(0, 128)).addRecoveryBit(rec);
        const pub = sig.recoverPublicKey(hash).toRawBytes(false);
        const recovered = `0x${bytesToHex(keccak_256(pub.slice(1)).slice(-20))}`;
        if (recovered.toLowerCase() !== expectedIssuerAddress.toLowerCase()) return { valid: false, reason: 'issuer address mismatch' };
        return { valid: true };
    } catch (err) {
        return { valid: false, reason: err instanceof Error ? err.message : 'verification failed' };
    }
}

export function buildMintRequest(botSeed, delegate, input) {
    if (!(botSeed instanceof Uint8Array) || botSeed.length !== 32) throw new Error('botSeed must be a 32-byte Uint8Array');
    const botAddress = _seedAddr(botSeed);
    const { agentId, operation, resources, actionIndex, maxUses, timeWindow, nonce, requestedAt } = input;
    const requestId = `ae-request-${contentHash({ botAddress, delegateId: delegate.delegateId, nonce }).slice(2, 18)}`;
    const { issuerSignature, ...delegateBody } = delegate;
    const delegateHash = contentHash(canonicalJSON(delegateBody));
    const requestBody = { type: 'agentenvelope.mintRequest', version: 1, requestId, delegateId: delegate.delegateId, delegateHash, botAddress, agentId, operation, resources, actionIndex, maxUses, timeWindow, nonce, requestedAt };
    try {
        const hash = keccak_256(_prefix(_c, encoder.encode(canonicalJSON(requestBody))));
        const sig = secp256k1.sign(hash, _seedToKey(botSeed));
        const botSignature = `0x${sig.r.toString(16).padStart(64, '0')}${sig.s.toString(16).padStart(64, '0')}${(sig.recovery + 27).toString(16).padStart(2, '0')}`;
        return { ...requestBody, botSignature };
    } finally {
        botSeed.fill(0);
    }
}

export function verifyMintRequest(request, delegate) {
    try {
        const { issuerSignature, ...delegateBody } = delegate;
        const dHash = keccak_256(_prefix(_b, encoder.encode(canonicalJSON(delegateBody))));
        const dHex = issuerSignature.slice(2);
        const dRec = Number.parseInt(dHex.slice(128, 130), 16) - 27;
        const dSig = secp256k1.Signature.fromCompact(dHex.slice(0, 128)).addRecoveryBit(dRec);
        const dPub = dSig.recoverPublicKey(dHash).toRawBytes(false);
        const recoveredIssuer = `0x${bytesToHex(keccak_256(dPub.slice(1)).slice(-20))}`;
        if (recoveredIssuer.toLowerCase() !== delegate.issuerAddress.toLowerCase()) return { valid: false, reason: 'delegate issuer signature invalid' };
        if (!/^0x[a-fA-F0-9]{40}$/.test(delegate.issuerAddress)) return { valid: false, reason: 'issuerAddress is invalid' };
        const now = Date.now();
        if (delegate.timeWindow.notBefore !== null && now < delegate.timeWindow.notBefore) return { valid: false, reason: 'delegate not yet active' };
        if (delegate.timeWindow.notAfter !== null && now > delegate.timeWindow.notAfter) return { valid: false, reason: 'delegate expired' };
        const { botSignature, ...requestBody } = request;
        const rHash = keccak_256(_prefix(_c, encoder.encode(canonicalJSON(requestBody))));
        const rHex = botSignature.slice(2);
        const rRec = Number.parseInt(rHex.slice(128, 130), 16) - 27;
        const rSig = secp256k1.Signature.fromCompact(rHex.slice(0, 128)).addRecoveryBit(rRec);
        const rPub = rSig.recoverPublicKey(rHash).toRawBytes(false);
        const recoveredBot = `0x${bytesToHex(keccak_256(rPub.slice(1)).slice(-20))}`;
        if (recoveredBot.toLowerCase() !== request.botAddress.toLowerCase()) return { valid: false, reason: 'bot signature invalid' };
        if (delegate.botPolicy === 'address-set') {
            if (!Array.isArray(delegate.allowedBotAddresses) || delegate.allowedBotAddresses.length === 0) return { valid: false, reason: 'address-set policy requires allowedBotAddresses' };
            if (!delegate.allowedBotAddresses.some((a) => a.toLowerCase() === recoveredBot.toLowerCase())) return { valid: false, reason: 'bot address not in allowed set' };
        }
        if (request.delegateHash.toLowerCase() !== contentHash(canonicalJSON(delegateBody)).toLowerCase()) return { valid: false, reason: 'delegateHash mismatch' };
        if (!delegate.allowedOperations.includes(request.operation)) return { valid: false, reason: 'operation not allowed' };
        for (const resource of request.resources) {
            const pfx = resource.split(':')[0];
            if (!delegate.allowedResources.some((r) => r === resource || r === `${pfx}:*` || r === '*')) return { valid: false, reason: `resource not allowed: ${resource}` };
        }
        if (request.actionIndex < delegate.actionIndexPolicy.min || request.actionIndex > delegate.actionIndexPolicy.max) return { valid: false, reason: 'actionIndex out of policy range' };
        if (request.maxUses > delegate.maxUsesPerAction) return { valid: false, reason: 'maxUses exceeds delegate limit' };
        const { notBefore: dNB, notAfter: dNA } = delegate.timeWindow;
        const { notBefore: rNB, notAfter: rNA } = request.timeWindow;
        if (dNB !== null && rNB !== null && rNB < dNB) return { valid: false, reason: 'request timeWindow starts before delegate' };
        if (dNA !== null && rNA !== null && rNA > dNA) return { valid: false, reason: 'request timeWindow ends after delegate' };
        if (dNA !== null && rNB !== null && rNB > dNA) return { valid: false, reason: 'request timeWindow outside delegate' };
        return { valid: true };
    } catch (err) {
        return { valid: false, reason: err instanceof Error ? err.message : 'verification failed' };
    }
}

export function deriveMintMaterial(identityRoot, domain) {
    if (!(identityRoot instanceof Uint8Array) || identityRoot.length !== 32) throw new Error('identityRoot must be a 32-byte Uint8Array');
    return hkdf(sha256, identityRoot, _s, encoder.encode(canonicalJSON({ purpose: 'mint-material', domainHash: domain.domainHash })), 32);
}

export function mintActionCapability(mintMaterial, delegate, request) {
    if (!(mintMaterial instanceof Uint8Array) || mintMaterial.length !== 32) throw new Error('mintMaterial must be a 32-byte Uint8Array');
    const { issuerSignature, ...delegateBody } = delegate;
    const { botSignature, ...requestBody } = request;
    const delegateHash = contentHash(canonicalJSON(delegateBody));
    const actionSeed = hkdf(sha256, mintMaterial, _s, encoder.encode(canonicalJSON({ purpose: 'remote-mint', delegateHash, mintRequest: requestBody })), 32);
    try {
        return {
            type: 'agentenvelope.agentCapability',
            version: 1,
            custodyMode: 'remote-mint-delegate',
            generatedAt: new Date().toISOString(),
            warning: 'Contains a private action seed. Give it only to the worker that needs this exact authority.',
            delegateId: delegate.delegateId,
            requestId: request.requestId,
            agentAddress: _seedAddr(actionSeed),
            actionSeedHex: bytesToHex(actionSeed),
        };
    } finally {
        actionSeed.fill(0);
        mintMaterial.fill(0);
    }
}

export function verifyRecord(record, { payload, signature, actionIndex, expectedActionEnvelopeHash } = {}) {
    try {
        if (record?.type !== 'agentenvelope.publicActionRecord') throw new Error('public action record type is invalid');
        if (record.version !== 1) throw new Error('public action record version is invalid');
        if (!record.agentAddress || !/^0x[a-fA-F0-9]{40}$/.test(record.agentAddress)) throw new Error('agent address is invalid');
        if (!record.actionEnvelope || typeof record.actionEnvelope !== 'object') throw new Error('action envelope is required');
        const recordActive = record.status === 'active';
        const actionIndexMatches = record.actionEnvelope.actionIndex === actionIndex;
        const decay = _checkDecay(record.actionEnvelope);
        const decayed = !decay.valid;
        const actionEnvelopeHashMatches = !expectedActionEnvelopeHash || expectedActionEnvelopeHash.toLowerCase() === record.actionEnvelopeHash.toLowerCase();
        const sigResult = actionIndexMatches
            ? (() => {
                  try {
                      const recovered = recoverActionAddress(payload, signature);
                      return recovered.toLowerCase() === record.agentAddress.toLowerCase() ? { valid: true, recoveredAddress: recovered } : { valid: false, reason: 'address mismatch', recoveredAddress: recovered };
                  } catch (err) {
                      return { valid: false, reason: err instanceof Error ? err.message : 'verification failed' };
                  }
              })()
            : { valid: false, reason: 'action index not registered' };
        const signatureWellFormed = sigResult.reason !== 'signature must be 65 bytes' && sigResult.reason !== 'signature recovery byte must be 27 or 28';
        const valid = recordActive && actionIndexMatches && sigResult.valid && actionEnvelopeHashMatches && !decayed;
        const reason = valid ? undefined : !recordActive ? 'record inactive' : !actionIndexMatches ? 'action index not registered' : decayed ? decay.reason : !actionEnvelopeHashMatches ? 'action envelope hash mismatch' : (sigResult.reason ?? 'verification failed');
        return {
            type: 'agentenvelope.verificationReport',
            version: 1,
            valid,
            ...(reason ? { reason } : {}),
            checkedAt: new Date().toISOString(),
            recordId: record.recordId,
            agentId: record.agentId,
            actionEnvelopeHash: record.actionEnvelopeHash,
            ...(expectedActionEnvelopeHash ? { expectedActionEnvelopeHash } : {}),
            checks: { recordActive, actionRegistered: actionIndexMatches, signatureWellFormed, signatureValid: sigResult.valid, addressMatchesRecord: sigResult.valid, actionEnvelopeHashMatches, decayed },
            addresses: { agentAddress: record.agentAddress, ...(sigResult.recoveredAddress ? { recoveredActionAddress: sigResult.recoveredAddress } : {}) },
            domain: {
                domainId: record.domain?.domainInfo?.domainId ?? record.domain?.domainId,
                domainHash: record.domain.domainHash,
            },
            actionIndex,
        };
    } catch (err) {
        return { type: 'agentenvelope.verificationReport', version: 1, valid: false, reason: err instanceof Error ? err.message : 'verification failed', checkedAt: new Date().toISOString() };
    }
}

function _checkDecay(envelope) {
    const mode = envelope.decayPolicy?.mode;
    if (mode === 'NONE' || mode === 'ACTION') return { valid: true };
    const now = Date.now();
    const { notBefore, notAfter } = envelope.timeWindow ?? {};
    if (notBefore != null && now < notBefore) return { valid: false, reason: 'not yet valid' };
    if (notAfter != null && now > notAfter) return { valid: false, reason: 'expired' };
    return { valid: true };
}