import * as Cord from '@cord.network/sdk';

type ContentPrimitives = string | number | boolean | undefined;
export interface IContents {
    [key: string]:
        | ContentPrimitives
        | IContents
        | Array<ContentPrimitives | IContents>;
}

export interface VCProofType {
    type: string;
}

export interface ED25519Proof extends VCProofType {
    created: string;
    proofPurpose: string;
    verificationMethod: string | Cord.DidUri;
    proofValue: string;
    challenge: string | undefined;
}

export interface CordProof2024 extends VCProofType, Cord.IStatementEntry {
    identifier: string; //Cord.StatementUri
    genesisHash: string;
}

export interface CordProof2025 extends VCProofType, Cord.IStatementEntryAccountType {
    identifier: string; //Cord.StatementUri
    genesisHash: string;
}

export interface CordSDRProof2024 extends VCProofType {
    defaultDigest: string;
    hashes: Array<Cord.HexString>;
    nonceMap: Record<string, string>;
    genesisHash: string;
}

export type VCProof = CordSDRProof2024 | ED25519Proof | CordProof2024 | CordProof2025;

/* TODO: make it more clear, and better - followup PRs */
export interface VerifiableCredential {
    '@context': Array<string>;
    type: Array<string>;
    issuer: Cord.DidUri;
    //id: string
    credentialHash: Cord.HexString;
    credentialSubject: IContents;
    credentialSchema: Cord.ISchema | undefined;
    proof: Array<VCProof> | VCProof;
    [key: string]: any;
}

/* TODO: make it more clear, and better - followup PRs */
/* CORD only allows array of VC(s) */
export interface VerifiablePresentation {
    '@context': Array<string>;
    type: Array<string>;
    proof: VCProof;
    holder: Cord.DidUri;
    VerifiableCredential: VerifiableCredential[];
    [key: string]: any;
}

export interface SignResponseData {
    /**
     * Result of the signing.
     */
    signature: Uint8Array
    /**
     * The did key uri used for signing.
     */
    keyUri: string
    /**
     * The did key type used for signing.
     */
    keyType: Cord.DidVerificationKey['type']
  }
  

/**
 * A callback function to sign data.
 */
export type SignCallback = (signData: any) => Promise<SignResponseData>;
