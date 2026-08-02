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

export declare class AgentEnvelopeClient {
    constructor(config: AgentEnvelopeClientConfig);
    verifyAction(input: VerifyActionApiInput): Promise<unknown>;
    getAgent(agentId: string): Promise<unknown>;
    mint(input: MintApiInput): Promise<unknown>;
}