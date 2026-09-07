/**
 * Optional hosted governance client.
 *
 * The core SDK verifies and signs locally with no network dependency. This
 * client talks to agentenvelope.io hosted APIs for operated services such as
 * public records, verifier receipts, mint governance, usage ledgers, and
 * legitimacy state. The API key meters service access; it is not agent signing
 * authority.
 */

const _BASE = 'https://jemdjwteae.execute-api.us-east-1.amazonaws.com/v1';

/**
 * Error wrapper for non-2xx hosted API responses.
 * Keeps the HTTP status, service error code/body, and any legitimacy decision
 * returned by governance.
 */
export class AgentEnvelopeApiError extends Error {
    /**
     * @param {number} status  HTTP status code.
     * @param {object} body    Parsed response body, when available.
     */
    constructor(status, body) {
        super(body?.message || body?.error || `AgentEnvelope API error ${status}`);
        this.name = 'AgentEnvelopeApiError';
        this.status = status;
        this.code = body?.code;
        this.body = body;
        this.legitimacy = body?.legitimacy;
    }
}

export class AgentEnvelopeClient {
    /**
     * Create a hosted governance API client.
     * apiKey identifies and meters service access; it is not a signing key and
     * cannot create agent authority by itself.
     *
     * @param {object} config         Client configuration.
     * @param {string} config.apiKey  Hosted API key.
     */
    constructor({ apiKey }) {
        this._key = apiKey;
    }

    // Shared JSON headers for hosted API calls.
    _headers() {
        return { 'Content-Type': 'application/json', 'X-Api-Key': this._key };
    }

    /**
     * Ask hosted governance to verify a payload/signature against a public record.
     * Returns a governed verification report and may include an attestation.
     *
     * @param {object} input                              Verification input.
     * @param {string} input.agentId                      Agent id to verify against.
     * @param {number} input.actionIndex                  Expected action index.
     * @param {unknown} input.payload                     JSON-compatible signed payload.
     * @param {string} input.signature                    0x-prefixed 65-byte signature.
     * @param {string} [input.expectedActionEnvelopeHash] Optional pinned envelope hash.
     * @returns {Promise<object>}                         Hosted verification report.
     */
    async verifyAction({ agentId, actionIndex, payload, signature, expectedActionEnvelopeHash }) {
        const report = await this._json('/sovereign/verify', {
            method: 'POST',
            body: JSON.stringify({ agentId, actionIndex, payload, signature, expectedActionEnvelopeHash }),
        });
        if (report && report.type === 'agentenvelope.sovereignVerificationReport') report.type = 'agentenvelope.verificationReport';
        return report;
    }

    /**
     * Fetch a published public agent/action record by agent id.
     *
     * @param {string} agentId  Agent id to fetch.
     * @returns {Promise<object>} Public agent/action record.
     */
    async getAgent(agentId) {
        if (typeof agentId !== 'string' || !/^[a-zA-Z0-9_:-]{1,128}$/.test(agentId)) throw new Error('agentId is invalid');
        return this._json('/sovereign/agents/' + encodeURIComponent(agentId), { method: 'GET' });
    }

    /**
     * Fetch a stored mint delegate by delegate id.
     *
     * @param {string} delegateId  Delegate id to fetch.
     * @returns {Promise<object>}  Stored signed mint delegate.
     */
    async getStoredDelegate(delegateId) {
        if (typeof delegateId !== 'string' || !/^[a-zA-Z0-9_:-]{1,128}$/.test(delegateId)) throw new Error('delegateId is invalid');
        return this._json('/sovereign/delegates/' + encodeURIComponent(delegateId), { method: 'GET' });
    }

    /**
     * Submit a signed delegate and signed mint request to hosted governance.
     * The service performs stateful checks such as replay, maxMints, and policy.
     *
     * @param {object} input          Mint input.
     * @param {object} input.delegate Signed mint delegate.
     * @param {object} input.request  Signed mint request.
     * @returns {Promise<object>}     Hosted mint result.
     */
    async mint({ delegate, request }) {
        return this._json('/sovereign/mint', {
            method: 'POST',
            body: JSON.stringify({ delegate, request }),
        });
    }

    /**
     * Create or replace a legitimacy state used by governed mint/verification.
     *
     * @param {object} input      Legitimacy state input.
     * @returns {Promise<object>} Created or replaced legitimacy state.
     */
    async setLegitimacyState(input) {
        return this._json('/sovereign/legitimacy', {
            method: 'POST',
            body: JSON.stringify(input),
        });
    }

    /**
     * Apply a legitimacy event/patch to an existing legitimacy state.
     *
     * @param {object} input      Legitimacy patch input.
     * @returns {Promise<object>} Updated legitimacy state/result.
     */
    async patchLegitimacyState(input) {
        return this._json('/sovereign/legitimacy', {
            method: 'PATCH',
            body: JSON.stringify(input),
        });
    }

    /**
     * Fetch the latest legitimacy state by id.
     *
     * @param {string} legitimacyId  Legitimacy state id.
     * @returns {Promise<object>}    Latest legitimacy state.
     */
    async getLegitimacyState(legitimacyId) {
        if (typeof legitimacyId !== 'string' || !legitimacyId.trim()) throw new Error('legitimacyId is required');
        return this._json('/sovereign/legitimacy?legitimacyId=' + encodeURIComponent(legitimacyId.trim()), {
            method: 'GET',
        });
    }

    // Internal fetch helper that normalizes JSON responses and throws
    // AgentEnvelopeApiError for hosted API failures.
    async _json(path, init) {
        const res = await fetch(_BASE + path, {
            ...init,
            headers: this._headers(),
        });
        const body = await res.json().catch(() => null);
        if (!res.ok) throw new AgentEnvelopeApiError(res.status, body);
        return body;
    }
}
