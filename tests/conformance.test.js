import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

import * as packageSdk from 'agent-envelope-sdk';
import * as rootSdk from '../src/index.js';
import {
    buildMintDelegate,
    buildMintRequest,
    canonicalJSON,
    contentHash,
    deriveMintMaterial,
    hexToBytes,
    mintActionCapability,
    recoverActionAddress,
    seedAddress,
    signAction,
    signReceipt,
    verifyAction,
    verifyMintDelegate,
    verifyMintRequest,
    verifyReceipt,
    verifyRecord,
} from '../src/index.js';

const execFileAsync = promisify(execFile);
const vector = JSON.parse(await readFile(new URL('../spec/vectors/v1-core.json', import.meta.url), 'utf8'));
const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const FIXED_NOW = Date.parse('2026-08-17T12:00:00.000Z');
const ROOT_SOURCE = await readFile(new URL('../src/index.js', import.meta.url), 'utf8');
const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
const encoder = new TextEncoder();

function withFixedNow(fn) {
    const originalNow = Date.now;
    Date.now = () => FIXED_NOW;
    try {
        return fn();
    } finally {
        Date.now = originalNow;
    }
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

function publicActionRecord() {
    return {
        type: 'agentenvelope.publicActionRecord',
        version: 1,
        recordId: 'ae-action-v1-vector',
        status: 'active',
        agentId: vector.action.envelope.agentId,
        agentAddress: vector.action.agentAddress,
        domain: clone(vector.domain),
        actionEnvelope: clone(vector.action.envelope),
        canonicalActionEnvelope: vector.action.canonicalActionEnvelope,
        actionEnvelopeHash: vector.action.actionEnvelopeHash,
        expiry: '2026-12-31T23:59:59.000Z',
    };
}

function refreshRecordEnvelope(record) {
    record.canonicalActionEnvelope = canonicalJSON(record.actionEnvelope);
    record.actionEnvelopeHash = contentHash(record.canonicalActionEnvelope);
    return record;
}

function expectRecordInvalid(record, expectedReason) {
    const report = withFixedNow(() =>
        verifyRecord(record, {
            payload: vector.action.payload,
            signature: vector.action.signature,
            actionIndex: record.actionEnvelope?.actionIndex ?? vector.action.envelope.actionIndex,
        }),
    );
    assert.equal(report.valid, false);
    if (expectedReason) assert.equal(report.reason, expectedReason);
    return report;
}

function flipHexBit(hex) {
    const prefix = hex.startsWith('0x') ? '0x' : '';
    const body = hex.slice(prefix.length);
    const first = body[0] === '0' ? '1' : '0';
    return `${prefix}${first}${body.slice(1)}`;
}

function assertLowerHex(value, bytes) {
    assert.match(value, new RegExp(`^0x[a-f0-9]{${bytes * 2}}$`));
}

function deriveDomainSeed() {
    return hkdf(sha256, hexToBytes(vector.seeds.identityRootHex), encoder.encode('agentenvelope-v1'), encoder.encode(canonicalJSON({ purpose: 'domain', domainInfo: vector.domain.domainInfo })), 32);
}

test('canonicalJSON is deterministic for key order, whitespace, and nesting', () => {
    const expected = '{"a":{"x":3,"y":2},"z":1}';
    assert.equal(canonicalJSON({ z: 1, a: { y: 2, x: 3 } }), expected);
    assert.equal(canonicalJSON({ a: { x: 3, y: 2 }, z: 1 }), expected);
    assert.equal(canonicalJSON(JSON.parse('{ "z" : 1, "a" : { "y" : 2, "x" : 3 } }')), expected);
    assert.equal(canonicalJSON({ b: [{ z: 2, a: 1 }, ['x', { c: 3 }]], a: true }), '{"a":true,"b":[{"a":1,"z":2},["x",{"c":3}]]}');
    assert.equal(canonicalJSON({ n: 1 }), '{"n":1}');
    assert.equal(canonicalJSON({ n: '1' }), '{"n":"1"}');
    assert.throws(() => canonicalJSON({ n: 1.5 }), /canonical JSON numbers must be safe integers/);
    assert.throws(() => canonicalJSON({ n: -0 }), /canonical JSON numbers must be safe integers/);
    assert.throws(() => canonicalJSON({ n: 1e21 }), /canonical JSON numbers must be safe integers/);
});

test('v1 core vector canonicalization, hashes, addresses, and signatures match', () => {
    assert.equal(canonicalJSON(vector.domain.domainInfo), vector.domain.canonicalDomainInfo);
    assert.equal(contentHash(vector.domain.canonicalDomainInfo), vector.domain.domainHash);
    assertLowerHex(vector.domain.domainHash, 32);

    assert.equal(canonicalJSON(vector.action.envelope), vector.action.canonicalActionEnvelope);
    assert.equal(contentHash(vector.action.canonicalActionEnvelope), vector.action.actionEnvelopeHash);
    assertLowerHex(vector.action.actionEnvelopeHash, 32);
    assert.ok(canonicalJSON({ code: '00123' }).includes('"00123"'));

    const actionSeed = hexToBytes(vector.action.actionSeedHex);
    assert.equal(seedAddress(actionSeed), vector.action.agentAddress);
    assert.equal(seedAddress(hexToBytes(vector.action.actionSeedHex)), vector.action.agentAddress);
    assert.equal(signAction(actionSeed, vector.action.payload), vector.action.signature);
    assert.equal(recoverActionAddress(vector.action.payload, vector.action.signature), vector.action.recoveredAddress);
    assert.deepEqual(verifyAction({ message: vector.action.payload, signature: vector.action.signature, expectedAddress: vector.action.agentAddress }), {
        valid: true,
        recoveredAddress: vector.action.recoveredAddress,
    });
});

test('action signatures fail closed when signature or payload changes', () => {
    assert.equal(verifyAction({ message: vector.action.payload, signature: flipHexBit(vector.action.signature), expectedAddress: vector.action.agentAddress }).valid, false);
    assert.equal(verifyAction({ message: { ...vector.action.payload, threadId: 'customer-999' }, signature: vector.action.signature, expectedAddress: vector.action.agentAddress }).valid, false);
    assert.throws(() => recoverActionAddress(vector.action.payload, vector.action.signature.slice(0, -2)), /signature must be 65 bytes/);
});

test('verifyRecord accepts the v1 public record vector offline', () => {
    const report = withFixedNow(() =>
        verifyRecord(publicActionRecord(), {
            payload: vector.action.payload,
            signature: vector.action.signature,
            actionIndex: vector.action.envelope.actionIndex,
            expectedActionEnvelopeHash: vector.action.actionEnvelopeHash,
        }),
    );

    assert.equal(report.valid, true);
    assert.equal(report.checks.canonicalActionEnvelopeMatches, true);
    assert.equal(report.checks.actionEnvelopeHashConsistent, true);
    assert.equal(report.checks.domainCanonicalMatches, true);
    assert.equal(report.checks.domainHashConsistent, true);
    assert.equal(report.checks.domainHashMatches, true);
    assert.equal(report.checks.domainIdMatches, true);
    assert.equal(report.checks.actionEnvelopeShapeValid, true);
    assert.equal(report.checks.signatureValid, true);
    assert.equal(report.addresses.recoveredActionAddress, vector.action.agentAddress);
});

test('verifyRecord fails closed on canonical envelope and hash tampering', () => {
    const changedEnvelope = publicActionRecord();
    changedEnvelope.actionEnvelope.resources = ['channel:support', 'thread:customer-999'];

    const changedEnvelopeReport = withFixedNow(() =>
        verifyRecord(changedEnvelope, {
            payload: vector.action.payload,
            signature: vector.action.signature,
            actionIndex: vector.action.envelope.actionIndex,
        }),
    );

    assert.equal(changedEnvelopeReport.valid, false);
    assert.equal(changedEnvelopeReport.reason, 'canonical action envelope mismatch');
    assert.equal(changedEnvelopeReport.checks.canonicalActionEnvelopeMatches, false);

    const changedHash = publicActionRecord();
    changedHash.actionEnvelopeHash = `0x${'0'.repeat(64)}`;

    const changedHashReport = withFixedNow(() =>
        verifyRecord(changedHash, {
            payload: vector.action.payload,
            signature: vector.action.signature,
            actionIndex: vector.action.envelope.actionIndex,
        }),
    );

    assert.equal(changedHashReport.valid, false);
    assert.equal(changedHashReport.reason, 'action envelope hash inconsistent');
    assert.equal(changedHashReport.checks.actionEnvelopeHashConsistent, false);
});

test('verifyRecord enforces domain binding, time windows, limits, and required fields', () => {
    const domainHashMismatch = refreshRecordEnvelope(publicActionRecord());
    domainHashMismatch.actionEnvelope.domain.domainHash = `0x${'1'.repeat(64)}`;
    refreshRecordEnvelope(domainHashMismatch);
    expectRecordInvalid(domainHashMismatch, 'domain hash mismatch');

    const domainIdMismatch = publicActionRecord();
    domainIdMismatch.actionEnvelope.domain.domainId = 'other-domain';
    refreshRecordEnvelope(domainIdMismatch);
    expectRecordInvalid(domainIdMismatch, 'domain id mismatch');

    const namespaceMismatch = publicActionRecord();
    namespaceMismatch.domain.domainInfo.namespace = 'other-namespace';
    expectRecordInvalid(namespaceMismatch, 'domain canonical info mismatch');

    const future = publicActionRecord();
    future.actionEnvelope.timeWindow.notBefore = FIXED_NOW + 1000;
    future.actionEnvelope.timeWindow.notAfter = FIXED_NOW + 2000;
    refreshRecordEnvelope(future);
    expectRecordInvalid(future, 'not yet valid');

    const expired = publicActionRecord();
    expired.actionEnvelope.timeWindow.notBefore = FIXED_NOW - 2000;
    expired.actionEnvelope.timeWindow.notAfter = FIXED_NOW - 1000;
    refreshRecordEnvelope(expired);
    expectRecordInvalid(expired, 'expired');

    const swapped = publicActionRecord();
    swapped.actionEnvelope.timeWindow.notBefore = FIXED_NOW + 2000;
    swapped.actionEnvelope.timeWindow.notAfter = FIXED_NOW + 1000;
    refreshRecordEnvelope(swapped);
    expectRecordInvalid(swapped, 'timeWindow is invalid');

    const zeroMaxUses = publicActionRecord();
    zeroMaxUses.actionEnvelope.limits.maxUses = 0;
    refreshRecordEnvelope(zeroMaxUses);
    expectRecordInvalid(zeroMaxUses, 'maxUses is invalid');

    const stringTime = publicActionRecord();
    stringTime.actionEnvelope.timeWindow.notBefore = String(FIXED_NOW - 1000);
    refreshRecordEnvelope(stringTime);
    expectRecordInvalid(stringTime, 'timeWindow notBefore is invalid');

    const missingCanonical = publicActionRecord();
    delete missingCanonical.canonicalActionEnvelope;
    expectRecordInvalid(missingCanonical, 'canonical action envelope mismatch');

    const missingHash = publicActionRecord();
    delete missingHash.actionEnvelopeHash;
    expectRecordInvalid(missingHash, 'action envelope hash is invalid');

    const uppercaseHash = publicActionRecord();
    uppercaseHash.actionEnvelopeHash = uppercaseHash.actionEnvelopeHash.toUpperCase().replace('X', 'x');
    expectRecordInvalid(uppercaseHash, 'action envelope hash is invalid');

    const uppercaseDomainHash = publicActionRecord();
    uppercaseDomainHash.domain.domainHash = uppercaseDomainHash.domain.domainHash.toUpperCase().replace('X', 'x');
    uppercaseDomainHash.actionEnvelope.domain.domainHash = uppercaseDomainHash.domain.domainHash;
    refreshRecordEnvelope(uppercaseDomainHash);
    expectRecordInvalid(uppercaseDomainHash, 'domain hash inconsistent');

    const uppercaseAddress = publicActionRecord();
    uppercaseAddress.agentAddress = uppercaseAddress.agentAddress.toUpperCase().replace('X', 'x');
    expectRecordInvalid(uppercaseAddress, 'agent address is invalid');

    const missingSignature = withFixedNow(() =>
        verifyRecord(publicActionRecord(), {
            payload: vector.action.payload,
            actionIndex: vector.action.envelope.actionIndex,
        }),
    );
    assert.equal(missingSignature.valid, false);

    const topLevelExtra = publicActionRecord();
    topLevelExtra.extra = 'ignored outside derivation surface';
    assert.equal(
        withFixedNow(() =>
            verifyRecord(topLevelExtra, {
                payload: vector.action.payload,
                signature: vector.action.signature,
                actionIndex: vector.action.envelope.actionIndex,
            }),
        ).valid,
        true,
    );

    const envelopeExtra = publicActionRecord();
    envelopeExtra.actionEnvelope.extra = 'covered by canonical envelope';
    expectRecordInvalid(envelopeExtra, 'canonical action envelope mismatch');
});

test('verifyRecord rejects non-integer canonical JSON values fail-closed', () => {
    const floatTime = publicActionRecord();
    floatTime.actionEnvelope.timeWindow.notBefore = FIXED_NOW - 0.5;
    expectRecordInvalid(floatTime, 'canonical JSON numbers must be safe integers');
});

test('v1 remote mint delegation vector matches exported SDK behavior', () => {
    const mint = vector.mintDelegation;
    const mintMaterial = deriveMintMaterial(hexToBytes(vector.seeds.identityRootHex), vector.domain);
    assert.equal(Buffer.from(mintMaterial).toString('hex'), mint.mintMaterialHex);

    const domainSeed = deriveDomainSeed();
    const rebuiltDelegate = buildMintDelegate(domainSeed, {
        domainHash: mint.delegate.domainHash,
        allowedOperations: mint.delegate.allowedOperations,
        allowedResources: mint.delegate.allowedResources,
        botPolicy: mint.delegate.botPolicy,
        allowedBotAddresses: mint.delegate.allowedBotAddresses,
        actionIndexPolicy: mint.delegate.actionIndexPolicy,
        maxMints: mint.delegate.maxMints,
        maxUsesPerAction: mint.delegate.maxUsesPerAction,
        timeWindow: mint.delegate.timeWindow,
        nonce: mint.delegate.nonce,
        issuedAt: mint.delegate.issuedAt,
    });
    assert.deepEqual(rebuiltDelegate, mint.delegate);
    assert.deepEqual([...domainSeed], Array(32).fill(0));

    assert.deepEqual(verifyMintDelegate(mint.delegate, mint.delegate.issuerAddress), { valid: true });

    const request = buildMintRequest(hexToBytes(vector.seeds.botSeedHex), mint.delegate, {
        agentId: mint.request.agentId,
        operation: mint.request.operation,
        resources: mint.request.resources,
        actionIndex: mint.request.actionIndex,
        maxUses: mint.request.maxUses,
        timeWindow: mint.request.timeWindow,
        nonce: mint.request.nonce,
        requestedAt: mint.request.requestedAt,
    });

    assert.deepEqual(request, mint.request);
    assert.deepEqual(withFixedNow(() => verifyMintRequest(mint.request, mint.delegate)), { valid: true });

    const capability = mintActionCapability(mintMaterial, mint.delegate, mint.request);
    assert.equal(capability.agentAddress, mint.remoteCapability.agentAddress);
    assert.equal(capability.actionSeedHex, mint.remoteCapability.actionSeedHex);
    assert.equal(signAction(hexToBytes(capability.actionSeedHex), mint.remotePayload), mint.remoteSignature);
    assert.equal(recoverActionAddress(mint.remotePayload, mint.remoteSignature), mint.remoteRecoveredAddress);
});

test('remote mint path fails closed on delegate, request, and remote signature mutation', () => {
    const mint = vector.mintDelegation;

    const tamperedDelegate = clone(mint.delegate);
    tamperedDelegate.allowedOperations = ['delete-message'];
    assert.equal(verifyMintRequest(mint.request, tamperedDelegate).valid, false);

    const nonceTamperedRequest = clone(mint.request);
    nonceTamperedRequest.nonce = `0x${'3'.repeat(64)}`;
    assert.equal(withFixedNow(() => verifyMintRequest(nonceTamperedRequest, mint.delegate)).valid, false);

    const operationRequest = buildMintRequest(hexToBytes(vector.seeds.botSeedHex), mint.delegate, {
        agentId: mint.request.agentId,
        operation: 'delete-message',
        resources: mint.request.resources,
        actionIndex: mint.request.actionIndex,
        maxUses: mint.request.maxUses,
        timeWindow: mint.request.timeWindow,
        nonce: `0x${'4'.repeat(64)}`,
        requestedAt: mint.request.requestedAt,
    });
    assert.equal(withFixedNow(() => verifyMintRequest(operationRequest, mint.delegate)).reason, 'operation not allowed');

    const resourceRequest = buildMintRequest(hexToBytes(vector.seeds.botSeedHex), mint.delegate, {
        agentId: mint.request.agentId,
        operation: mint.request.operation,
        resources: ['admin:root'],
        actionIndex: mint.request.actionIndex,
        maxUses: mint.request.maxUses,
        timeWindow: mint.request.timeWindow,
        nonce: `0x${'5'.repeat(64)}`,
        requestedAt: mint.request.requestedAt,
    });
    assert.equal(withFixedNow(() => verifyMintRequest(resourceRequest, mint.delegate)).reason, 'resource not allowed: admin:root');

    const indexRequest = buildMintRequest(hexToBytes(vector.seeds.botSeedHex), mint.delegate, {
        agentId: mint.request.agentId,
        operation: mint.request.operation,
        resources: mint.request.resources,
        actionIndex: 99,
        maxUses: mint.request.maxUses,
        timeWindow: mint.request.timeWindow,
        nonce: `0x${'6'.repeat(64)}`,
        requestedAt: mint.request.requestedAt,
    });
    assert.equal(withFixedNow(() => verifyMintRequest(indexRequest, mint.delegate)).reason, 'actionIndex out of policy range');

    const maxUsesRequest = buildMintRequest(hexToBytes(vector.seeds.botSeedHex), mint.delegate, {
        agentId: mint.request.agentId,
        operation: mint.request.operation,
        resources: mint.request.resources,
        actionIndex: mint.request.actionIndex,
        maxUses: 2,
        timeWindow: mint.request.timeWindow,
        nonce: `0x${'7'.repeat(64)}`,
        requestedAt: mint.request.requestedAt,
    });
    assert.equal(withFixedNow(() => verifyMintRequest(maxUsesRequest, mint.delegate)).reason, 'maxUses exceeds delegate limit');

    assert.equal(verifyAction({ message: mint.remotePayload, signature: flipHexBit(mint.remoteSignature), expectedAddress: mint.remoteCapability.agentAddress }).valid, false);
    assert.equal(verifyAction({ message: { ...mint.remotePayload, threadId: 'customer-999' }, signature: mint.remoteSignature, expectedAddress: mint.remoteCapability.agentAddress }).valid, false);
});

test('legitimacyRef is signed into delegates and enforced by mint requests', () => {
    const mint = vector.mintDelegation;
    const legitimacyRef = {
        legitimacyId: 'ae-legit-test',
        required: true,
        policyId: 'manufacturing-location-precondition',
        stateVersion: 1,
        stateHash: vector.action.actionEnvelopeHash,
    };
    const delegate = buildMintDelegate(deriveDomainSeed(), {
        domainHash: mint.delegate.domainHash,
        legitimacyRef,
        allowedOperations: mint.delegate.allowedOperations,
        allowedResources: mint.delegate.allowedResources,
        botPolicy: mint.delegate.botPolicy,
        allowedBotAddresses: mint.delegate.allowedBotAddresses,
        actionIndexPolicy: mint.delegate.actionIndexPolicy,
        maxMints: mint.delegate.maxMints,
        maxUsesPerAction: mint.delegate.maxUsesPerAction,
        timeWindow: mint.delegate.timeWindow,
        nonce: `0x${'8'.repeat(64)}`,
        issuedAt: mint.delegate.issuedAt,
    });
    assert.deepEqual(verifyMintDelegate(delegate, delegate.issuerAddress), { valid: true });

    const tamperedDelegate = clone(delegate);
    tamperedDelegate.legitimacyRef.stateVersion = 2;
    assert.equal(verifyMintDelegate(tamperedDelegate, delegate.issuerAddress).reason, 'issuer address mismatch');

    const request = buildMintRequest(hexToBytes(vector.seeds.botSeedHex), delegate, {
        agentId: mint.request.agentId,
        operation: mint.request.operation,
        resources: mint.request.resources,
        actionIndex: mint.request.actionIndex,
        maxUses: mint.request.maxUses,
        timeWindow: mint.request.timeWindow,
        nonce: `0x${'9'.repeat(64)}`,
        requestedAt: mint.request.requestedAt,
        legitimacyId: legitimacyRef.legitimacyId,
    });
    assert.deepEqual(withFixedNow(() => verifyMintRequest(request, delegate)), { valid: true });

    const missingLegitimacyRequest = clone(request);
    delete missingLegitimacyRequest.legitimacyId;
    assert.equal(withFixedNow(() => verifyMintRequest(missingLegitimacyRequest, delegate)).reason, 'bot signature invalid');

    const wrongLegitimacyRequest = buildMintRequest(hexToBytes(vector.seeds.botSeedHex), delegate, {
        agentId: mint.request.agentId,
        operation: mint.request.operation,
        resources: mint.request.resources,
        actionIndex: mint.request.actionIndex,
        maxUses: mint.request.maxUses,
        timeWindow: mint.request.timeWindow,
        nonce: `0x${'a'.repeat(64)}`,
        requestedAt: mint.request.requestedAt,
        legitimacyId: 'ae-legit-other',
    });
    assert.equal(withFixedNow(() => verifyMintRequest(wrongLegitimacyRequest, delegate)).reason, 'legitimacyId mismatch');
});

test('receipt attestations verify locally and fail closed on tamper', () => {
    const receiptBody = {
        type: 'agentenvelope.governanceReceipt',
        version: 1,
        recordId: 'ae-action-v1-vector',
        signatureValid: true,
        actionEnvelopeHash: vector.action.actionEnvelopeHash,
    };
    const attesterSeed = hexToBytes(vector.seeds.botSeedHex);
    const attestation = signReceipt(attesterSeed, receiptBody);
    assertLowerHex(attestation.attesterAddress, 20);
    assert.match(attestation.signature, /^0x[a-f0-9]{130}$/);

    const receipt = { ...receiptBody, attestation };
    assert.equal(verifyReceipt(receipt, attestation.attesterAddress).valid, true);
    assert.equal(verifyReceipt({ ...receipt, signatureValid: false }, attestation.attesterAddress).reason, 'attester address mismatch');
    assert.equal(verifyReceipt(receipt, vector.action.agentAddress).reason, 'unexpected attester');
    assert.equal(verifyReceipt({ ...receipt, attestation: { ...attestation, signature: flipHexBit(attestation.signature) } }, attestation.attesterAddress).valid, false);
});

test('root export stays sovereign-only', () => {
    assert.equal('AgentEnvelopeClient' in rootSdk, false);
    assert.equal('AgentEnvelopeClient' in packageSdk, false);
    assert.equal(ROOT_SOURCE.includes('execute-api'), false);
    assert.equal(ROOT_SOURCE.includes('agentenvelope.io'), false);
    assert.equal(ROOT_SOURCE.includes('fetch('), false);
});

test('npm pack dry-run includes vectors and tests without hosted client in root export', async () => {
    const command = process.platform === 'win32' ? (process.env.ComSpec ?? 'cmd.exe') : 'npm';
    const args = process.platform === 'win32' ? ['/d', '/s', '/c', 'npm pack --dry-run --json'] : ['pack', '--dry-run', '--json'];
    const { stdout } = await execFileAsync(command, args, { cwd: PACKAGE_ROOT });
    const [pack] = JSON.parse(stdout);
    const files = new Set(pack.files.map((file) => file.path));
    assert.equal(pack.name, 'agent-envelope-sdk');
    assert.equal(pack.version, packageJson.version);
    assert.equal(files.has('spec/vectors/v1-core.json'), true);
    assert.equal(files.has('tests/conformance.test.js'), true);
    assert.equal(files.has('tests/client.test.js'), true);
    assert.equal(files.has('src/client.js'), true);
    assert.equal(files.has('src/index.js'), true);
});
