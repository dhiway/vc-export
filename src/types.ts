import * as Cord from '@cord.network/sdk';

type ContentPrimitives = string | number | boolean | undefined
export interface IContents {
  [key: string]:
    | ContentPrimitives
    | IContents
    | Array<ContentPrimitives | IContents>
}

export interface VCProofType {
  type: string
}

export interface ED25519Proof extends VCProofType {
    created: string
    proofPurpose: string
    verificationMethod: string | Cord.DidUri
    proofValue: string
    challenge: string | undefined
}

export interface CordProof2024 extends VCProofType, Cord.IStatementEntry {
      identifier: string //Cord.StatementUri
}

export interface CordSDRProof2024 extends VCProofType {
    defaultDigest: string
    hashes: Array<Cord.HexString>
    nonceMap: Record<string, string>
}

export type VCProof = CordSDRProof2024 | ED25519Proof | CordProof2024

/* TODO: make it more clear, and better - followup PRs */
export interface VerifiableCredential {
  '@context': Array<string>
  type: Array<string>
  issuer: Cord.DidUri
  //id: string
  credentialHash: Cord.HexString
  credentialSubject: IContents
  credentialSchema: Cord.ISchema | undefined
  proof: Array<VCProof> | VCProof
  [key: string]: any
}

/* TODO: make it more clear, and better - followup PRs */
export interface VerifiablePresentation {
  '@context': Array<string>
  type: Array<string>
  proof: Array<VCProof> | VCProof
  holder: Cord.DidUri
  VerifiableCredential: VerifiableCredential[] | VerifiableCredential
  [key: string]: any
}
