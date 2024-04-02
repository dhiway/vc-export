import { base58Encode } from '@polkadot/util-crypto';
import dayjs from 'moment';

import * as Cord from '@cord.network/sdk';

import { verifyDataStructure } from '@cord.network/statement';

import {
    uriToIdentifier,
    buildStatementUri,
} from '@cord.network/identifier'

import * as Did from '@cord.network/did'

import {
    HexString,
    DidUri,
    SpaceUri,
    SchemaUri,
    StatementUri,
    IStatementEntry,
    H256,
    Bytes,
    AccountId,
    blake2AsHex,
} from '@cord.network/types';

import {
    VerifiableCredential,
    VerifiablePresentation,
    IContents,
    ED25519Proof,
    CordSDRProof2024,
    CordProof2024,
    SignCallback,
} from './types';

import { hashContents, calculateVCHash } from './utils';

export function getUriForStatement(
    digest: HexString,
    spaceUri: SpaceUri,
    creatorUri: DidUri,
  ): StatementUri {
    const api = Cord.ConfigService.get('api')

    const scaleEncodedSchema = api.createType<H256>('H256', digest).toU8a()
    const scaleEncodedSpace = api
      .createType<Bytes>('Bytes', uriToIdentifier(spaceUri))
      .toU8a()
    const scaleEncodedCreator = api
      .createType<AccountId>('AccountId', Did.toChain(creatorUri))
      .toU8a()
    const IdDigest = blake2AsHex(
      Uint8Array.from([
        ...scaleEncodedSchema,
        ...scaleEncodedSpace,
        ...scaleEncodedCreator,
      ])
    )
    const statementUri = buildStatementUri(IdDigest, digest)
  
    return statementUri
}

export function buildCordProof(
    digest: HexString,
    spaceUri: SpaceUri,
    creatorUri: DidUri,
    schemaUri?: SchemaUri
  ): IStatementEntry {
    const stmtUri = getUriForStatement(digest, spaceUri, creatorUri)
  
    const statement: IStatementEntry = {
        elementUri: stmtUri,
        digest,
        creatorUri,
        spaceUri,
        schemaUri: schemaUri || undefined,
    }

    verifyDataStructure(statement)
    return statement
}

/* TODO: not sure why, the sign() of the key is giving the same output if treated as a function,
   but when compared with output of locally created sign, they are different */
export async function addProof(
    vc: VerifiableCredential,
    callbackFn: SignCallback,
    issuerDid: Cord.DidDocument,
    options: any,
) {
    const now = dayjs();
    let credHash: Cord.HexString = calculateVCHash(vc, undefined);

    /* TODO: Bring selective disclosure here */
    let proof2: CordSDRProof2024 | undefined = undefined;
    if (options.needSDR) {
        let contents = { ...vc.credentialSubject };
        delete contents.id;

        let hashes = hashContents(contents, options.schemaUri);

        /* proof 2 - ConentNonces for selective disclosure */
        /* This will enable the selective disclosure. This may not be compatible with the normal VC */
        /* This also would change the 'credentialSubject' */
        proof2 = {
            type: 'CordSDRProof2024',
            defaultDigest: credHash,
            hashes: hashes.hashes,
            nonceMap: hashes.nonceMap,
        };
        let vocabulary = `${options.schemaUri}#`;
        vc.credentialSubject['@context'] = { vocab: vocabulary };
        credHash = calculateVCHash(vc, hashes.hashes);
    }
    vc.credentialHash = credHash;

    /* proof 0 - Ed25519 */
    /* validates ownership by checking the signature against the DID */

    let cbData = await callbackFn(vc.credentialHash);

    let proof0: ED25519Proof = {
        type: 'Ed25519Signature2020',
        created: now.toDate().toString(),
        proofPurpose: cbData.keyType,
        verificationMethod: cbData.keyUri,
        proofValue: 'z' + base58Encode(cbData.signature),
        challenge: undefined,
    };

    /* proof 1 - CordProof */
    /* contains check for revoke */
    let proof1: CordProof2024 | undefined = undefined;
    if (options.needStatementProof) {

        // SDK Method Name: Cord.statement.buildFromProperties //
        const statementEntry = buildCordProof(
            vc.credentialHash,
            options.spaceUri!,
            issuerDid.uri,
            options.schemaUri ?? undefined,
        );
        let elem = statementEntry.elementUri.split(':');
        proof1 = {
            type: 'CordProof2024',
            elementUri: statementEntry.elementUri,
            spaceUri: statementEntry.spaceUri,
            schemaUri: statementEntry.schemaUri,
            creatorUri: issuerDid.uri,
            digest: vc.credentialHash,
            identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
        };

        vc.id = proof1.identifier;
    }

    vc['proof'] = [proof0];
    if (proof1) vc.proof.push(proof1);
    if (proof2) vc.proof.push(proof2);

    return vc;
}

export function buildVcFromContent(
    schema: Cord.ISchema,
    contents: IContents,
    issuer: Cord.DidDocument,
    holder: Cord.DidUri,
    options: any,
) {
    Cord.Schema.verifyObjectAgainstSchema(contents, schema);

    const { evidenceIds, validFrom, validUntil, templates, labels } = options;

    const now = new Date();
    const issuanceDate = now.toISOString();
    const validFromString = validFrom
        ? validFrom.toISOString()
        : now.toISOString();
    const validUntilString = validUntil
        ? validUntil.toISOString()
        : new Date(new Date().setFullYear(now.getFullYear() + 1)).toISOString();

    const credentialSubject = {
        ...contents,
        id: holder,
    };
    let vc: any = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://cord.network/2023/cred/v1',
        ],
        type: ['VerifiableCredential'],
        issuer: issuer.uri,
        issuanceDate: issuanceDate,
        credentialSubject,
        validFrom: validFromString,
        validUntil: validUntilString,
        metadata: {
            evidence: evidenceIds,
            template: templates,
            label: labels,
        },
        credentialSchema: schema,
    };
    vc.credentialHash = calculateVCHash(vc, undefined);

    return vc as VerifiableCredential;
}

export function updateVcFromContent(
    contents: IContents,
    vc: VerifiableCredential,
    validUntil: string | undefined,
) {
    Cord.Schema.verifyObjectAgainstSchema(
        contents,
        vc.credentialSchema as Cord.ISchema,
    );

    const now = new Date();
    const validFromString = now.toISOString();
    const validUntilString = validUntil ? validUntil : vc.validUntil;

    const credentialSubject = {
        ...contents,
        id: vc.credentialSubject.id,
    };

    let updatedVc: any = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://cord.network/2023/cred/v1',
        ],
        type: ['VerifiableCredential'],
        issuer: vc.issuer,
        issuanceDate: validFromString,
        credentialSubject,
        validFrom: validFromString,
        validUntil: validUntilString,
        metadata: vc.metadata,
        credentialSchema: vc.credentialSchema,
    };

    updatedVc.credentialHash = calculateVCHash(updatedVc, undefined);

    return updatedVc as VerifiableCredential;
}

export async function makePresentation(
    vcs: VerifiableCredential[],
    holder: Cord.DidDocument,
    callbackFn: SignCallback,
    challenge: string,
    options: any,
) {
    const now = dayjs();
    let copiedVcs = vcs;
    if (options?.needSDR) {
        copiedVcs = [];

        for (let i = 0; i < vcs.length; i++) {
            let vc = vcs[i];

            if (options.selectedFields) {
                let subject = vc.credentialSubject;
                let newSubject = {
                    id: subject.id,
                    ['@context']: subject['@context'],
                };

                Object.keys(subject).forEach((key) => {
                    if (options.selectedFields.includes(key)) {
                        newSubject[key] = subject[key];
                    }
                });
                let copyOfVC = {
                    ...vc,
                    credentialSubject: newSubject,
                };
                copiedVcs.push(copyOfVC);
            } else {
                copiedVcs.push(vc);
            }
        }
    }

    let cbData = await callbackFn(challenge);

    let proof0: ED25519Proof = {
        challenge: challenge,
        type: 'Ed25519Signature2020',
        created: now.toDate().toString(),
        proofPurpose: cbData.keyType,
        verificationMethod: cbData.keyUri,
        proofValue: 'z' + base58Encode(cbData.signature),
    };
    let vp: VerifiablePresentation = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://cord.network/2023/cred/v1',
        ],
        type: ['VerifiablePresentation'],
        holder: holder.uri,
        VerifiableCredential: copiedVcs,
        metadata: {},
        proof: proof0,
    };

    return vp;
}
