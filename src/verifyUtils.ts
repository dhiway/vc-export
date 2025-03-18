import { base58Decode } from '@polkadot/util-crypto';

import * as Cord from '@cord.network/sdk';

import {
    IStatementDetails,
    Option,
    AccountId32,
    StatementUri,
    IStatementStatus,
    HexString,
    DidUri,
    SpaceUri,
    SchemaUri
} from '@cord.network/types';

import {
    VerifiableCredential,
    VerifiablePresentation,
    IContents,
    VCProof,
    ED25519Proof,
    CordSDRProof2024,
    CordProof2024,
    CordProof2025,
} from './types';

import * as Did from '@cord.network/did'

import { decodeStatementDetailsfromChain } from '@cord.network/statement';

import {uriToIdentifier, uriToStatementIdAndDigest, identifierToUri} from '@cord.network/identifier';

import { SDKErrors } from '@cord.network/utils';

import { makeStatementsJsonLD, calculateVCHash } from './utils';

export async function getDetailsfromChain(
    identifier: string
  ): Promise<IStatementDetails | null> {
    const api = Cord.ConfigService.get('api')
    const statementId = uriToIdentifier(identifier)
  
    const statementEntry = await api.query.statement.statements(statementId)
    const decodedDetails = decodeStatementDetailsfromChain(
      statementEntry,
      identifier
    )
    if (decodedDetails === null) {
      throw new SDKErrors.StatementError(
        `There is no statement with the provided ID "${statementId}" present on the chain.`
      )
    }
  
    return decodedDetails
}

export async function fetchStatementDetailsfromChain(
    stmtUri: StatementUri
  ): Promise<IStatementStatus | null> {
    const api = Cord.ConfigService.get('api')
    const { identifier, digest } = uriToStatementIdAndDigest(stmtUri)
  
    const statementDetails = await getDetailsfromChain(identifier)
    if (statementDetails === null) {
      throw new SDKErrors.StatementError(
        `There is no statement with the provided ID "${identifier}" present on the chain.`
      )
    }
  
    const schemaUri =
      statementDetails.schemaUri !== undefined
        ? identifierToUri(statementDetails.schemaUri)
        : undefined
  
    const spaceUri = identifierToUri(statementDetails.spaceUri)
  
    const elementStatusDetails = await api.query.statement.entries(
      identifier,
      digest
    )
  
    if (elementStatusDetails === null) {
      throw new SDKErrors.StatementError(
        `There is no entry with the provided ID "${identifier}" and digest "${digest}" present on the chain.`
      )
    }
  
    const elementChainCreator = (
      elementStatusDetails as Option<AccountId32>
    ).unwrap()
    const elementCreator = Did.fromChain(elementChainCreator)
  
    const elementStatus = await api.query.statement.revocationList(
      identifier,
      digest
    )
  
    let revoked = false
    if (!elementStatus.isEmpty) {
      const encodedStatus = elementStatus.unwrap()
      revoked = encodedStatus.revoked.valueOf()
    }
  
    const statementStatus: IStatementStatus = {
      uri: statementDetails.uri,
      digest,
      spaceUri,
      creatorUri: elementCreator,
      schemaUri,
      revoked,
    }
  
    return statementStatus
  }

  export async function fetchStatementDetailsfromChain2025(
    stmtUri: StatementUri
  ): Promise<Cord.IStatementStatusAccountType | null> {
    const api = Cord.ConfigService.get('api')
    const { identifier, digest } = uriToStatementIdAndDigest(stmtUri)
  
    const statementDetails = await getDetailsfromChain(identifier)
    if (statementDetails === null) {
      throw new SDKErrors.StatementError(
        `There is no statement with the provided ID "${identifier}" present on the chain.`
      )
    }
  
    const schemaUri =
      statementDetails.schemaUri !== undefined
        ? identifierToUri(statementDetails.schemaUri)
        : undefined
  
    const spaceUri = identifierToUri(statementDetails.spaceUri)
  
    const elementStatusDetails = await api.query.statement.entries(
      identifier,
      digest
    )
  
    if (elementStatusDetails === null) {
      throw new SDKErrors.StatementError(
        `There is no entry with the provided ID "${identifier}" and digest "${digest}" present on the chain.`
      )
    }
  
    const elementChainCreator = (
      elementStatusDetails as Option<AccountId32>
    ).unwrap()
    const elementCreator = Did.fromChain(elementChainCreator)
  
    const elementStatus = await api.query.statement.revocationList(
      identifier,
      digest
    )
  
    let revoked = false
    if (!elementStatus.isEmpty) {
      const encodedStatus = elementStatus.unwrap()
      revoked = encodedStatus.revoked.valueOf()
    }
  
    const statementStatus: Cord.IStatementStatusAccountType = {
      uri: statementDetails.uri,
      digest,
      spaceUri,
      creatorAddress: elementCreator,
      schemaUri,
      revoked,
    }
  
    return statementStatus
  }

export async function verifyAgainstProperties(
    stmtUri: StatementUri,
    digest: HexString,
    creator?: DidUri,
    spaceuri?: SpaceUri,
    schemaUri?: SchemaUri
  ): Promise<{ isValid: boolean; message: string }> {
    try {
      const statementStatus = await fetchStatementDetailsfromChain(stmtUri)
  
      if (!statementStatus) {
        return {
          isValid: false,
          message: `Statement details for "${digest}" not found.`,
        }
      }
  
      if (digest !== statementStatus.digest) {
        return {
          isValid: false,
          message: 'Digest does not match with Statement Digest.',
        }
      }
  
      if (statementStatus?.revoked) {
        return {
          isValid: false,
          message: `Statement "${stmtUri}" Revoked.`,
        }
      }
  
      if (creator) {
        if (creator !== statementStatus.creatorUri) {
          return {
            isValid: false,
            message: 'Statement and Digest creator does not match.',
          }
        }
      }
  
      if (spaceuri) {
        if (spaceuri !== statementStatus.spaceUri) {
          return {
            isValid: false,
            message: 'Statement and Digest space details does not match.',
          }
        }
      }
  
      if (schemaUri) {
        if (schemaUri !== statementStatus.schemaUri) {
          return {
            isValid: false,
            message: 'Statement and Digest schema details does not match.',
          }
        }
      }
  
      return {
        isValid: true,
        message:
          'Digest properties provided are valid and matches the statement details.',
      }
    } catch (error) {
      if (error instanceof Error) {
        return {
          isValid: false,
          message: `Error verifying properties: ${error}`,
        }
      }
      return {
        isValid: false,
        message: 'An unknown error occurred while verifying the properties.',
      }
    }
  }

  export async function verifyAgainstProperties2025(
    stmtUri: StatementUri,
    digest: HexString,
    creator?: string,
    spaceuri?: SpaceUri,
    schemaUri?: SchemaUri
  ): Promise<{ isValid: boolean; message: string }> {
    try {
      const statementStatus = await fetchStatementDetailsfromChain2025(stmtUri)
  
      if (!statementStatus) {
        return {
          isValid: false,
          message: `Statement details for "${digest}" not found.`,
        }
      }
  
      if (digest !== statementStatus.digest) {
        return {
          isValid: false,
          message: 'Digest does not match with Statement Digest.',
        }
      }
  
      if (statementStatus?.revoked) {
        return {
          isValid: false,
          message: `Statement "${stmtUri}" Revoked.`,
        }
      }
  
      if (creator) {
        if (creator !== statementStatus.creatorAddress) {
          return {
            isValid: false,
            message: 'Statement and Digest creator does not match.',
          }
        }
      }
  
      if (spaceuri) {
        if (spaceuri !== statementStatus.spaceUri) {
          return {
            isValid: false,
            message: 'Statement and Digest space details does not match.',
          }
        }
      }
  
      if (schemaUri) {
        if (schemaUri !== statementStatus.schemaUri) {
          return {
            isValid: false,
            message: 'Statement and Digest schema details does not match.',
          }
        }
      }
  
      return {
        isValid: true,
        message:
          'Digest properties provided are valid and matches the statement details.',
      }
    } catch (error) {
      if (error instanceof Error) {
        return {
          isValid: false,
          message: `Error verifying properties: ${error}`,
        }
      }
      return {
        isValid: false,
        message: 'An unknown error occurred while verifying the properties.',
      }
    }
  }

export function verifyDisclosedAttributes(
    content: IContents,
    schemaId: string | undefined,
    nonceMap: Record<string, string>,
    hashes: string[],
    attributes?: string[],
): void {
    // apply defaults
    // use canonicalisation algorithm to make hashable statement strings
    if (!schemaId) throw 'schemaId is needed for SDR verification';

    const statements = makeStatementsJsonLD(content, schemaId);
    let filteredStatements = statements;
    if (attributes && attributes.length) {
        filteredStatements = Cord.Utils.DataUtils.filterStatements(
            statements,
            attributes,
        );
    }

    // iterate over statements to produce salted hashes
    const hashed = Cord.Utils.Crypto.hashStatements(filteredStatements, {
        nonces: nonceMap,
    });
    // check resulting hashes
    const digestsInProof = Object.keys(nonceMap);
    const { verified, errors } = hashed.reduce<{
        verified: boolean;
        errors: Error[];
    }>(
        (status, { saltedHash, statement, digest, nonce }) => {
            // check if the statement digest was contained in the proof and mapped it to a nonce
            if (!digestsInProof.includes(digest) || !nonce) {
                status.errors.push(
                    new Cord.Utils.SDKErrors.NoProofForStatementError(
                        statement,
                    ),
                );
                return { ...status, verified: false };
            }
            // check if the hash is whitelisted in the proof
            if (!hashes.includes(saltedHash)) {
                status.errors.push(
                    new Cord.Utils.SDKErrors.InvalidProofForStatementError(
                        statement,
                    ),
                );
                return { ...status, verified: false };
            }
            return status;
        },
        { verified: true, errors: [] },
    );
    if (verified !== true) {
        throw new Cord.Utils.SDKErrors.ContentUnverifiableError(
            'One or more statements in the content could not be verified',
            { cause: errors },
        );
    }
}

export async function verifyProofElement(
    proof: VCProof,
    credHash: string | Cord.HexString | undefined,
    vc: VerifiableCredential | undefined,
) {
    if (proof.type === 'CordProof2024') {
        /* verify the proof */
        let obj = proof as unknown as CordProof2024;

        if (obj.digest !== credHash) {
            throw 'credential Digest mismatch';
        }
        if (
            obj.elementUri !== `${obj.identifier}:${credHash.replace('0x', '')}`
        ) {
            throw 'elementUri mismatch';
        }
        
        /* SDK Method Name: Cord.Statament.verifyAgainstProperties */
        const verificationResult = await verifyAgainstProperties(
            obj.elementUri,
            obj.digest,
            obj.creatorUri,
            obj.spaceUri,
            obj.schemaUri,
        );

        if (!verificationResult.isValid) {
            throw 'Failed to verify CordProof2024';
        }
        /* all good, no throw */
    }
    if (proof.type === 'CordProof2025') {
      /* verify the proof */
      let obj = proof as unknown as CordProof2025;

      if (obj.digest !== credHash) {
          throw 'credential Digest mismatch';
      }
      if (
          obj.elementUri !== `${obj.identifier}:${credHash.replace('0x', '')}`
      ) {
          throw 'elementUri mismatch';
      }
      
      /* SDK Method Name: Cord.Statament.verifyAgainstProperties */
      const verificationResult = await verifyAgainstProperties2025(
          obj.elementUri,
          obj.digest,
          obj.creatorAddress,
          obj.spaceUri,
          obj.schemaUri,
      );

      if (!verificationResult.isValid) {
          throw 'Failed to verify CordProof2025';
      }
      /* all good, no throw */
  }
  if (proof.type === 'Ed25519Signature2020') {
        let obj = proof as unknown as ED25519Proof;
        let signature: any = obj.proofValue;
        /* this 'z' is from digitalbazaar/ed25519signature2020 project */
        /* TODO: use the above package to verify the proof */
        if (signature && signature[0] !== 'z') {
            throw 'proofValue not formated properly. Please refer to the standard';
        }
        let str = signature.substr(1, signature.length);
        /* lets convert it to uint8array, and send to verification */
        let message = obj.challenge ?? credHash;
        if (!message)
            throw 'the challenge/digest passed for verification is invalid';
        await Cord.Did.verifyDidSignature({
            message,
            signature: base58Decode(str),
            keyUri: obj.verificationMethod as unknown as Cord.DidResourceUri,
        });
        /* all is good, no throw */
    }
    if (proof.type === 'CordSDRProof2024') {
        let obj = proof as unknown as CordSDRProof2024;

        /* make sure from whats is present in content, we get back the same content nonces */
        let subject = vc?.credentialSubject
            ? { ...vc.credentialSubject }
            : { id: 'dummy', '@context': 'dummy' };
        delete subject.id;
        delete subject['@context'];

        verifyDisclosedAttributes(
            subject,
            vc?.credentialSchema?.$id,
            obj.nonceMap,
            obj.hashes,
            Object.keys(subject),
        );
    }
}

export async function verifyVC(vc: VerifiableCredential): Promise<void> {
    /* proof check */
    const proofs: any = vc.proof;
    if (!proofs.length) {
        let hashes =
            proofs.type === 'CordSDRProof2024' ? proofs.hashes : undefined;
        let credHash = calculateVCHash(vc, hashes);
        await verifyProofElement(vc.proof as VCProof, credHash, vc);
        return;
    }

    let credHash = calculateVCHash(vc, undefined);

    /*
    /* digest may change depending on if its SDR based VC or simple VC */
    for (let i = 0; i < proofs.length; i++) {
        let obj = proofs[i];
        if (!obj) continue;
        if (obj.type === 'CordSDRProof2024') {
            credHash = calculateVCHash(vc, obj.hashes);
        }
    }
    /* assumption is one is getting the vc with proof here */
    // let identifier = vc.id;

    for (let i = 0; i < proofs.length; i++) {
        let obj = proofs[i];
        if (!obj) continue;
        await verifyProofElement(obj, credHash, vc);
    }
    return;
}

export async function verifyVP(vp: VerifiablePresentation) {
    /* proof check */
    await verifyProofElement(vp.proof as VCProof, undefined, undefined);

    let vcs = vp.VerifiableCredential;
    for (let i = 0; i < vcs.length; i++) {
        let vc = vcs[i];
        await verifyVC(vc);
    }
}
