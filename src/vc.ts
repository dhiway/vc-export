import { base58Encode } from '@polkadot/util-crypto';
import dayjs from 'moment';
import * as Cord from '@cord.network/sdk';
// import { verifyDataStructure } from '@cord.network/statement';
// import { uriToIdentifier, buildStatementUri } from '@cord.network/identifier';
// import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020';
// import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020';
// import { sign, purposes } from 'jsonld-signatures';

import {
    ApiPromise,
} from '@cord.network/types';

import {
    VerifiableCredential,
    VerifiablePresentation,
    IContents,
    ED25519Proof,
    CordSDRProof2025,
    CordProof2025,
    SignCallback,
} from './types';

import { hashContents, calculateVCHash, /* calculateNewVCHash */} from './utils';
import { v4 as uuidv4 } from 'uuid';

// export function getUriForStatement(
//     digest: HexString,
//     spaceUri: SpaceUri,
//     creatorUri: string,
// ): StatementUri {
//     const api = Cord.ConfigService.get('api');

//     const scaleEncodedSchema = api.createType<H256>('H256', digest).toU8a();
//     const scaleEncodedSpace = api
//         .createType<Bytes>('Bytes', uriToIdentifier(spaceUri))
//         .toU8a();
//     const scaleEncodedCreator = api
//         .createType<AccountId>('AccountId', creatorUri)
//         .toU8a();
//     const IdDigest = blake2AsHex(
//         Uint8Array.from([
//             ...scaleEncodedSchema,
//             ...scaleEncodedSpace,
//             ...scaleEncodedCreator,
//         ]),
//     );
//     const statementUri = buildStatementUri(IdDigest, digest);

//     return statementUri;
// }

// export function buildCordProof(
//     digest: HexString,
//     spaceUri: SpaceUri,
//     creatorUri: string,
//     schemaUri?: SchemaUri,
// ): Cord.IStatementEntryAccountType {
//     const stmtUri = getUriForStatement(digest, spaceUri, creatorUri);

//     const statement: Cord.IStatementEntryAccountType = {
//         elementUri: stmtUri,
//         digest,
//         creatorAddress: creatorUri,
//         spaceUri,
//         schemaUri: schemaUri || undefined,
//     };

//     verifyDataStructure(statement);
//     return statement;
// }

// export function updateBuildCordProof(
//     stmtUri: StatementUri,
//     digest: HexString,
//     spaceUri: SpaceUri,
//     creatorUri: string,
//     schemaUri?: SchemaUri,
// ): Cord.IStatementEntryAccountType {
//     const statementUri = Cord.Identifier.updateStatementUri(stmtUri, digest);

//     const statement = {
//         elementUri: statementUri,
//         digest,
//         creatorAddress: creatorUri,
//         spaceUri,
//     };
//     verifyDataStructure(statement);
//     return statement;
// }                                                         




/* TODO: not sure why, the sign() of the key is giving the same output if treated as a function,
   but when compared with output of locally created sign, they are different */
export async function addProof(
    vc: VerifiableCredential,
    callbackFn: SignCallback,
    /* TODO: Should below be the profile-id or the ss58 Account address */
    registryId: string,
    issuerAddress: string,
    /* TODO: Should we take in ProfileId too */
    network: ApiPromise,
    options: any,
    proofId: string = uuidv4(),
) {
    const now = dayjs();
    let credHash: Cord.HexString = calculateVCHash(vc, undefined);
    let genesisHash: string = await Cord.getGenesisHash(network);

    /* TODO: Bring selective disclosure here */
    let proof2: CordSDRProof2025 | undefined = undefined;
    if (options.needSDR) {
        let contents = { ...vc.credentialSubject };
        delete contents.id;

        let hashes = hashContents(contents, undefined);

        /* proof 2 - ConentNonces for selective disclosure */
        /* This will enable the selective disclosure. This may not be compatible with the normal VC */
        /* This also would change the 'credentialSubject' */
        proof2 = {
            type: 'CordSDRProof2025',
            defaultDigest: credHash,
            hashes: hashes.hashes,
            nonceMap: hashes.nonceMap,
            genesisHash: genesisHash,
        };
        /* Setting context to default as in makeVP */
        // let vocabulary = `${options.schemaUri}#`;
        // vc.credentialSubject['@context'] = { vocab: vocabulary };
        vc.credentialSubject['@context'] = 'https://cord.network/2023/cred/v1';
        credHash = calculateVCHash(vc, hashes.hashes);
    }
    vc.credentialHash = credHash;

    /* proof 0 - Ed25519 */
    /* validates ownership by checking the signature against the DID */

    /* TODO: Check if callback is actually required now. 
     * We even removed it from SDK.
     */
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
    let proof1: CordProof2025 | undefined = undefined;
    if (options.needEntryProof) {
        /* TODO: I think since we dont have dependency of api, we can directly use from SDK's methods */
        /* SDK Method Name: Cord.Entry.buildFromProperties */
        // Technically return below and proof.
        Cord.Entry.createEntriesProperties(
            registryId,
            vc.credentialHash,
            null, // TODO: Check requirement of blob here
        );

        proof1 = {
            type: 'CordProof2025',
            /* TODO: We wont be having the elementUri at this moment before its creation, 
             * think of the steps to be taken for filling up 'elementUri' and 'identifier'.
             */
            // elementUri: statementEntry.elementUri,
            // spaceUri: statementEntry.spaceUri,
            // schemaUri: statementEntry.schemaUri,
            registryId: registryId,
            issuerAddress: issuerAddress,
            tx_hash: vc.credentialHash,
            /* Check how we can add identifier here, change would be needed in types.ts too */
            // identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
            genesisHash: genesisHash,
            // /* TODO: Fix removal of blob later */
            // blob: null,
        };

        vc.id = proofId;
    }

    vc['proof'] = [proof0];
    if (proof1) vc.proof.push(proof1);
    if (proof2) vc.proof.push(proof2);

    return vc;
}

export async function updateAddProof(
    registryId: string,
    registryEntryId: string,
    vc: VerifiableCredential,
    callbackFn: SignCallback,
    issuerAddress: string,
    network: ApiPromise,
    options: any,
) {
    const now = dayjs();
    let credHash: Cord.HexString = calculateVCHash(vc, undefined);
    let genesisHash: string = await Cord.getGenesisHash(network);

    /* TODO: Bring selective disclosure here */
    let proof2: CordSDRProof2025 | undefined = undefined;
    if (options.needSDR) {
        let contents = { ...vc.credentialSubject };
        delete contents.id;

        let hashes = hashContents(contents, undefined);

        /* proof 2 - ConentNonces for selective disclosure */
        /* This will enable the selective disclosure. This may not be compatible with the normal VC */
        /* This also would change the 'credentialSubject' */
        proof2 = {
            type: 'CordSDRProof2025',
            defaultDigest: credHash,
            hashes: hashes.hashes,
            nonceMap: hashes.nonceMap,
            genesisHash: genesisHash,
        };
        /* Setting context to default as in makeVP */
        // let vocabulary = `${options.schemaUri}#`;
        // vc.credentialSubject['@context'] = { vocab: vocabulary };
        vc.credentialSubject['@context'] = 'https://cord.network/2023/cred/v1';
        credHash = calculateVCHash(vc, hashes.hashes);
    }
    vc.credentialHash = credHash;

    /* proof 0 - Ed25519 */
    /* validates ownership by checking the signature against the DID */

    /* TODO: Check if callback is actually required now. 
     * We even removed it from SDK.
     */
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
    let proof1: CordProof2025 | undefined = undefined;
    if (options.needEntryProof) {
        Cord.Entry.updateEntriesProperties(
            registryId,
            registryEntryId,
            vc.credentialHash,
            null, // TODO: Check requirement of blob here
        );

        proof1 = {
            type: 'CordProof2025',
            /* TODO: We wont be having the elementUri at this moment before its creation, 
             * think of the steps to be taken for filling up 'elementUri' and 'identifier'.
             */
            // elementUri: statementEntry.elementUri,
            // spaceUri: statementEntry.spaceUri,
            // schemaUri: statementEntry.schemaUri,
            // creatorAddress: issuerDid.replace('did:web:','').replace('.myn.social',''),
            registryId: registryId, 
            issuerAddress: issuerAddress,
            tx_hash: vc.credentialHash,
            /* Check how we can add identifier here, change would be needed in types.ts too */
            // identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
            genesisHash: genesisHash,
            // /* TODO: Fix removal of blob later */
            // blob: null,
        };

        /* TODO: Is there a requirement of updating the vc.id on update method? */
        // vc.id = proof1.identifier;
        vc.id = vc.id;
    }

    vc['proof'] = [proof0];
    if (proof1) vc.proof.push(proof1);
    if (proof2) vc.proof.push(proof2);

    return vc;
}

export function buildVcFromContent(
    schema: object,
    contents: IContents,
    issuer: string,
    holder: string,
    options?: any | null,
) {
    /* TODO: Is below needed, we dont have support to verifyObjectAgainstSchema now.
     * If required we might need a separate method/svc for this.
     */
    // Cord.Schema.verifyObjectAgainstSchema(contents, schema);

    const { evidenceIds, validFrom, validUntil, templates, labels, metadata, vcType } = options ?? {};

    const now = new Date();
    const issuanceDate = now.toISOString();
    const validFromString = validFrom
        ? validFrom.toISOString()
        : now.toISOString();
    const validUntilString = validUntil
        ? validUntil.toISOString()
        : new Date(new Date().setFullYear(now.getFullYear() + 1)).toISOString();
    const expirationDate = validUntil
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
        issuer: issuer,
        issuanceDate: issuanceDate,
        expirationDate:expirationDate,
        credentialSubject,
        validFrom: validFromString,
        validUntil: validUntilString,
        metadata: {
            evidence: evidenceIds,
            template: templates,
            label: labels,
	    ...metadata,
        },
        credentialSchema: schema,
    };
    if (vcType) {
       vc.type.push(vcType);
    }
    vc.credentialHash = calculateVCHash(vc, undefined);

    return vc as VerifiableCredential;
}

export async function buildEd25519VcFromContent(
    schema: any,
    contents: any,
    issuer: string,
    holder: string,
    options: any,
) {
    // Cord.Schema.verifyObjectAgainstSchema(contents, schema);

    const { validUntil } = options;

    const now = new Date();
    const issuanceDate = now.toISOString();
    const expirationDate = validUntil
        ? validUntil.toISOString()
        : new Date(new Date().setFullYear(now.getFullYear() + 1)).toISOString();

    const credentialSubject = {
        ...contents,
    };
    if (holder) {
        credentialSubject.id = holder;
    }

    let vc: any = {
        ...schema,
        // '@context': [
        //     'https://www.w3.org/2018/credentials/v1',
        //     'https://cord.network/2023/cred/v1',
        // ],
        // type: ['VerifiableCredential'],
        holder: { id: holder },
        credentialSubject,
        // credentialSchema: {
        //     '@id': 'https://www.w3.org/2018/credentials#credentialSchema',
        //     '@type': '@id',
        //   },
        issuanceDate: issuanceDate,
        expirationDate: expirationDate,
        issuer,
        // credentialSchema: schema,
    };
    vc.credentialHash = calculateVCHash(vc, undefined);

    return vc as VerifiableCredential;
}

/* TODO: Fix later, commenting out */
// export async function statementEntryToAnchorHash(
//     vc: VerifiableCredential,
//     issuerDid: string,
//     options: any,
//     statement?: any,
// ) {
//     const credHash = calculateNewVCHash(vc, undefined);

//     let statementEntry;

//     if (options.call === 'update') {
//         statementEntry = updateBuildCordProof(
//             statement,
//             credHash,
//             options.spaceUri,
//             issuerDid,
//             options.schemaUri ?? undefined,
//         );
//     } else {
//         statementEntry = buildCordProof(
//             credHash,
//             options.spaceUri,
//             issuerDid,
//             undefined,
//         );
//     }
//     return statementEntry;
// }


/* TODO: Fix later, commenting out */
// export async function addEd5519Proof(
//     vc: any,
//     callbackFn: SignCallback,
//     issuerDid: string,
//     network: ApiPromise,
//     options: any,
// ) {
//     if (options.type) {
//         delete vc.credentialHash;
//         // Add statement as id in VC
//         const vcId = options.statement.split(':').slice(0, 3).join(':');
//         vc.id = vcId;

//         const signedVC = await signCredential(vc, options.did);
//         return signedVC;
//     } else {
//         const now = dayjs();
//         let credHash: Cord.HexString = calculateVCHash(vc, undefined);
//         let genesisHash: string = await Cord.getGenesisHash(network);

//         /* TODO: Bring selective disclosure here */
//         let proof2: CordSDRProof2024 | undefined = undefined;
//         if (options.needSDR) {
//             let contents = { ...vc.credentialSubject };
//             delete contents.id;

//             let hashes = hashContents(contents, options.schemaUri);

//             /* proof 2 - ConentNonces for selective disclosure */
//             /* This will enable the selective disclosure. This may not be compatible with the normal VC */
//             /* This also would change the 'credentialSubject' */
//             proof2 = {
//                 type: 'CordSDRProof2024',
//                 defaultDigest: credHash,
//                 hashes: hashes.hashes,
//                 nonceMap: hashes.nonceMap,
//                 genesisHash: genesisHash,
//             };
//             let vocabulary = `${options.schemaUri}#`;
//             vc.credentialSubject['@context'] = { vocab: vocabulary };
//             credHash = calculateVCHash(vc, hashes.hashes);
//         }
//         vc.credentialHash = credHash;

//         /* proof 0 - Ed25519 */
//         /* validates ownership by checking the signature against the DID */

//         let cbData = await callbackFn(vc.credentialHash);

//         let proof0: ED25519Proof = {
//             type: 'Ed25519Signature2020',
//             created: now.toDate().toString(),
//             proofPurpose: cbData.keyType,
//             verificationMethod: cbData.keyUri,
//             proofValue: 'z' + base58Encode(cbData.signature),
//             challenge: undefined,
//         };

//         /* proof 1 - CordProof */
//         /* contains check for revoke */
//         let proof1: CordProof2025 | undefined = undefined;
//         if (options.needStatementProof) {
//             // SDK Method Name: Cord.statement.buildFromProperties //
//             const statementEntry = buildCordProof(
//                 vc.credentialHash,
//                 options.spaceUri!,
//                 issuerDid,
//                 options.schemaUri ?? undefined,
//             );
//             let elem = statementEntry.elementUri.split(':');
//             proof1 = {
//                 type: 'CordProof2025',
//                 elementUri: statementEntry.elementUri,
//                 spaceUri: statementEntry.spaceUri,
//                 schemaUri: statementEntry.schemaUri,
//                 creatorAddress: issuerDid.replace('did:web:','').replace('.myn.social',''),
//                 digest: vc.credentialHash,
//                 identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
//                 genesisHash: genesisHash,
//             };

//             vc.id = proof1.identifier;
//         }

//         vc['proof'] = [proof0];
//         if (proof1) vc.proof.push(proof1);
//         if (proof2) vc.proof.push(proof2);

//         return vc;
//     }
// }

/* TODO: Fix later, commenting out */
// export async function updateEd25519Proof(
//     oldStmt: StatementUri,
//     vc: any,
//     callbackFn: SignCallback,
//     issuerDid: string,
//     network: ApiPromise,
//     options: any,
// ) {
//     if (options.type) {
//         delete vc.credentialHash;
//         // Add statement as id in VC
//         const vcId = oldStmt.split(':').slice(0, 3).join(':');
//         vc.id = vcId;

//         const signedVC = await signCredential(vc, options.did);
//         return signedVC;
//     } else {
//         const now = dayjs();
//         let credHash: Cord.HexString = calculateVCHash(vc, undefined);
//         let genesisHash: string = await Cord.getGenesisHash(network);

//         /* TODO: Bring selective disclosure here */
//         let proof2: CordSDRProof2024 | undefined = undefined;
//         if (options.needSDR) {
//             let contents = { ...vc.credentialSubject };
//             delete contents.id;

//             let hashes = hashContents(contents, options.schemaUri);

//             /* proof 2 - ConentNonces for selective disclosure */
//             /* This will enable the selective disclosure. This may not be compatible with the normal VC */
//             /* This also would change the 'credentialSubject' */
//             proof2 = {
//                 type: 'CordSDRProof2024',
//                 defaultDigest: credHash,
//                 hashes: hashes.hashes,
//                 nonceMap: hashes.nonceMap,
//                 genesisHash: genesisHash,
//             };
//             let vocabulary = `${options.schemaUri}#`;
//             vc.credentialSubject['@context'] = { vocab: vocabulary };
//             credHash = calculateVCHash(vc, hashes.hashes);
//         }
//         vc.credentialHash = credHash;

//         /* proof 0 - Ed25519 */
//         /* validates ownership by checking the signature against the DID */

//         let cbData = await callbackFn(vc.credentialHash);

//         let proof0: ED25519Proof = {
//             type: 'Ed25519Signature2020',
//             created: now.toDate().toString(),
//             proofPurpose: cbData.keyType,
//             verificationMethod: cbData.keyUri,
//             proofValue: 'z' + base58Encode(cbData.signature),
//             challenge: undefined,
//         };

//         /* proof 1 - CordProof */
//         /* contains check for revoke */
//         let proof1: CordProof2025 | undefined = undefined;
//         if (options.needStatementProof) {
//             // SDK Method Name: Cord.statement.buildFromUpdateProperties //
//             const statementEntry = updateBuildCordProof(
//                 oldStmt,
//                 vc.credentialHash,
//                 options.spaceUri!,
//                 issuerDid,
//                 options.schemaUri ?? undefined,
//             );
//             let elem = statementEntry.elementUri.split(':');
//             proof1 = {
//                 type: 'CordProof2025',
//                 elementUri: statementEntry.elementUri,
//                 spaceUri: statementEntry.spaceUri,
//                 schemaUri: statementEntry.schemaUri,
//                 creatorAddress: issuerDid.replace('did:web:','').replace('.myn.social',''),
//                 digest: vc.credentialHash,
//                 identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
//                 genesisHash: genesisHash,
//             };

//             vc.id = proof1.identifier;
//         }

//         vc['proof'] = [proof0];
//         if (proof1) vc.proof.push(proof1);
//         if (proof2) vc.proof.push(proof2);

//         return vc;
//     }
// }

/*
export async function signCredential(vc: VerifiableCredential, did: any) {
    try {
        let signedDoc;

        const keyPair = await Ed25519VerificationKey2020.generate({
            controller: did,
        });

        const suite = new Ed25519Signature2020({ key: keyPair });

        try {
            signedDoc = await sign(vc, {
                suite,
                purpose: new purposes.AssertionProofPurpose(),
                documentLoader: async (url: any) => {
                    console.log(`Resolving URL: ${url}`);
                    if (url.startsWith('https://')) {
                        const response = await fetch(url);
                        const json = await response.json();
                        return {
                            contextUrl: null,
                            document: json,
                            documentUrl: url,
                        };
                    }
                    return {};
                },
            });
        } catch (error) {
            console.error('Signing Error:', error);
        }

        return signedDoc;
    } catch (error) {
        console.error('err: ', error);
        throw new Error('Error generating signed doc');
    }
}
*/

export async function updateEd25519VcFromContent(
    contents: IContents,
    vc: VerifiableCredential,
    validUntil: string | undefined,
) {
    // Cord.Schema.verifyObjectAgainstSchema(
    //     contents,
    //     vc.credentialSchema as Cord.ISchema,
    // );

    const now = new Date();
    const validFromString = now.toISOString();
    const validUntilString = validUntil ? validUntil : vc.expirationDate;

    const credentialSubject = {
        ...contents,
        // id: vc.credentialSubject.id,
    };

    const { '@context': context, type } = vc;

    let updatedVc: any = {
        '@context': context,
        type,
        // '@context': [
        //     'https://www.w3.org/2018/credentials/v1',
        //     'https://cord.network/2023/cred/v1',
        // ],
        // type: ['VerifiableCredential'],
        holder: { id: vc.holder.id },
        issuer: vc.issuer,
        issuanceDate: validFromString,
        expirationDate: validUntilString,
        credentialSubject,
        // validFrom: validFromString,
        // credentialSchema: vc.credentialSchema,
    };

    updatedVc.credentialHash = calculateVCHash(updatedVc, undefined);

    return updatedVc as VerifiableCredential;
}

export async function updateVcFromContent(
    contents: IContents,
    vc: VerifiableCredential,
    validUntil: string | undefined,
    options?: any
) {
    /* TODO: Is below needed, we dont have support to verifyObjectAgainstSchema now.
     * If required we might need a separate method/svc for this.
     */
    // Cord.Schema.verifyObjectAgainstSchema(contents, schema);

    const { metadata } = options ?? {};
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
        expirationDate: validUntilString,
        credentialSubject,
        validFrom: validFromString,
        validUntil: validUntilString,
        metadata: { ...vc.metadata, ...metadata },
        credentialSchema: vc.credentialSchema,
    };

    updatedVc.credentialHash = calculateVCHash(updatedVc, undefined);

    return updatedVc as VerifiableCredential;
}

export async function makePresentation(
    vcs: VerifiableCredential[],
    holder: string,
    callbackFn: SignCallback,
    challenge: string,
    network: ApiPromise,
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
                let newSubject: { [key: string]: any } = {
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
        holder: holder,
        VerifiableCredential: copiedVcs,
        metadata: {},
        proof: proof0,
    };

    return vp;
}

/* TODO: This function can be used in addProof and updateAddProof to get the digest */
export async function constructCordProof2025(
    registryId: string,
    digest: Cord.HexString,
    /* TODO: Should below be the profile-id or the ss58 Account address */
    issuerAddress: string,
    network: ApiPromise,
    options?: any,
) {
    const genesisHash: string = await Cord.getGenesisHash(network);
        Cord.Entry.createEntriesProperties(
            registryId,
            digest,
            null, // TODO: Check requirement of blob here
        );
    
    let proof: CordProof2025 = {
        type: 'CordProof2025',
        registryId: registryId,
        issuerAddress: issuerAddress,
        tx_hash: digest,
        /* Check how we can add identifier here, change would be needed in types.ts too */
        // identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
        genesisHash: genesisHash,
        // blob: null,
    };

    return proof;
}
