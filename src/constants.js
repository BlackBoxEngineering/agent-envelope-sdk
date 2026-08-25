/**
 * Decay modes for an action envelope.
 *
 * NONE   - No decay.
 * TIME   - Decays only when outside the time window.
 * ACTION - Decays only when maxUses is reached. Requires external use counting.
 * BOTH   - Decays when outside the time window or when maxUses is reached.
 *
 * The SDK can verify signatures, envelopes, and time windows locally. ACTION
 * decay is different: maxUses is a signed boundary, but the current use count
 * must be enforced by an external state holder such as a ledger, verifier API,
 * or AgentEnvelope Web governance at https://agentenvelope.io.
 */

export const DECAY_MODES = Object.freeze({
    NONE: 'NONE',
    TIME: 'TIME',
    ACTION: 'ACTION',
    BOTH: 'BOTH',
});
