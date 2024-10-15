import * as Cord from '@cord.network/sdk';
import { RegistryUri, SchemaUri } from '@cord.network/sdk';

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
    // TODO: Disable keyUri for account based op.
    verificationMethod?: string | Cord.DidUri;
    proofValue: string;
    challenge: string | undefined;
}

export interface CordProof2024 extends VCProofType, Cord.IStatementEntry {
    identifier: string; //Cord.StatementUri
    genesisHash: string;
}

export interface CordProof2024B extends VCProofType, Cord.IRegistryEntry {
    registryUri: RegistryUri;
    schemaUri?: SchemaUri;
    identifier: string; //Cord.RegistryEntry.uri
    genesisHash: string;
}

export interface CordSDRProof2024 extends VCProofType {
    defaultDigest: string;
    hashes: Array<Cord.HexString>;
    nonceMap: Record<string, string>;
    genesisHash: string;
}

export type VCProof = CordSDRProof2024 | ED25519Proof | CordProof2024 | CordProof2024B;

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

/**
 * A callback function to sign data.
 */
// TODO: Recheck below
export type SignCallback = (signData: any) => Promise<Cord.SignResponseData>;
export type SignCallbackB = (signData: any) => Promise<{
    signature: Uint8Array; // Keep the signature
    keyType: string;        // Keep the key type (e.g., ed25519, sr25519, etc.)
}>;