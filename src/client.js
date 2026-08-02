const _BASE = 'https://jemdjwteae.execute-api.us-east-1.amazonaws.com/v1';

export class AgentEnvelopeClient {
    constructor({ apiKey }) {
        this._key = apiKey;
    }

    _headers() {
        return { 'Content-Type': 'application/json', 'X-Api-Key': this._key };
    }

    async verifyAction({ agentId, actionIndex, payload, signature, expectedActionEnvelopeHash }) {
        const res = await fetch(_BASE + '/sovereign/verify', {
            method: 'POST',
            headers: this._headers(),
            body: JSON.stringify({ agentId, actionIndex, payload, signature, expectedActionEnvelopeHash }),
        });
        const report = await res.json();
        // Hosted API tags reports 'sovereignVerificationReport'; normalize to the canonical SDK type.
        if (report && report.type === 'agentenvelope.sovereignVerificationReport') report.type = 'agentenvelope.verificationReport';
        return report;
    }

    async getAgent(agentId) {
        if (typeof agentId !== 'string' || !/^[a-zA-Z0-9_:-]{1,128}$/.test(agentId)) throw new Error('agentId is invalid');
        const res = await fetch('https://jemdjwteae.execute-api.us-east-1.amazonaws.com/v1/sovereign/agents/lookup', {
            method: 'POST',
            headers: this._headers(),
            body: JSON.stringify({ agentId }),
        });
        return res.json();
    }

    async mint({ delegate, request }) {
        const res = await fetch(_BASE + '/sovereign/mint', {
            method: 'POST',
            headers: this._headers(),
            body: JSON.stringify({ delegate, request }),
        });
        return res.json();
    }
}