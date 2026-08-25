// AgentEnvelope SDK — constants type declarations

/**
 * Decay modes for an action envelope.
 *
 * The SDK can verify signatures, envelopes, and time windows locally. ACTION
 * decay is different: maxUses is a signed boundary, but the current use count
 * must be enforced by an external state holder such as a ledger, verifier API,
 * or AgentEnvelope Web governance at https://agentenvelope.io.
 */

export declare const DECAY_MODES: Readonly<{
    NONE: 'NONE';
    TIME: 'TIME';
    ACTION: 'ACTION';
    BOTH: 'BOTH';
}>;
