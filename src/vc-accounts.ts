import { base58Encode } from '@polkadot/util-crypto';
import dayjs from 'moment';

import * as Cord from '@cord.network/sdk';

// import { verifyDataStructure } from '@cord.network/statement';

import { uriToIdentifier, buildStatementUri } from '@cord.network/identifier';

import * as Did from '@cord.network/did';

import {
    HexString,
    DidUri,
    SpaceUri,
    //SchemaUri,
    StatementUri,
    //IStatementEntry,
    H256,
    Bytes,
    AccountId,
    blake2AsHex,
    ApiPromise,
    RegistryUri,
    EntryUri,
    ENTRY_IDENT,
    ENTRY_PREFIX,
    EntryDigest,
    //IRegistryEntry,
    RegistryAuthorizationUri,
} from '@cord.network/types';

import {
  hashToUri,
} from '@cord.network/identifier';

import {
    VerifiableCredential,
    VerifiablePresentation,
    IContents,
    ED25519Proof,
    CordSDRProof2024,
    //CordProof2024,
    CordProof2024B,
    SignCallback,
    SignCallbackB,
} from './types';

import { hashContents, calculateVCHash } from './utils';

export function getUriForStatement(
    digest: HexString,
    spaceUri: SpaceUri,
    creatorUri: DidUri,
): StatementUri {
    const api = Cord.ConfigService.get('api');

    const scaleEncodedSchema = api.createType<H256>('H256', digest).toU8a();
    const scaleEncodedSpace = api
        .createType<Bytes>('Bytes', uriToIdentifier(spaceUri))
        .toU8a();
    const scaleEncodedCreator = api
        .createType<AccountId>('AccountId', Did.toChain(creatorUri))
        .toU8a();
    const IdDigest = blake2AsHex(
        Uint8Array.from([
            ...scaleEncodedSchema,
            ...scaleEncodedSpace,
            ...scaleEncodedCreator,
        ]),
    );
    const statementUri = buildStatementUri(IdDigest, digest);

    return statementUri;
}

export async function getUriForRegistryEntry(
  entryDigest: EntryDigest,
  registryUri: RegistryUri,
  creatorAddress: string
): Promise<EntryUri> {
  const api = Cord.ConfigService.get('api')
  const scaleEncodedRegistryDigest = api
    .createType<H256>('H256', entryDigest)
    .toU8a()
  const scaleEncodedRegistryId = api
    .createType<Bytes>('Bytes', uriToIdentifier(registryUri))
    .toU8a()
  const scaleEncodedCreator = api
    .createType<AccountId>('AccountId', creatorAddress)
    .toU8a()
  const digest = blake2AsHex(
    Uint8Array.from([
      ...scaleEncodedRegistryDigest,
      ...scaleEncodedRegistryId,
      ...scaleEncodedCreator
    ])
  );

  const entryUri = hashToUri(digest, ENTRY_IDENT, ENTRY_PREFIX) as EntryUri;
  return entryUri;
}

export interface IRegistryEntry {
  uri: EntryUri
  creatorUri: DidUri
  digest: HexString
  blob: string | null
  authorizationUri: RegistryAuthorizationUri
}

// TODO: Attempt use CORDs SDK method instead of below.
// export async function buildCordProof(
//     digest: HexString,
//     registryUri: RegistryUri,
//     creatorUri: DidUri,
//     blob: string | null = null,
//     authorizationUri: RegistryAuthorizationUri,
//     // TODO: schmeaUri is not required at `entry` level but only at `registry` level.
//     //schemaUri?: SchemaUri,
// ): Promise<IRegistryEntry> {
//     const entryUri = await getUriForRegistryEntry(digest, registryUri, uriToIdentifier(creatorUri));

//     const registryEntry: IRegistryEntry = {
//         uri: entryUri,
//         creatorUri,
//         digest,
//         blob, 
//         authorizationUri,
//     };

//     // TODO: Disable for now, Write this method in CORD.JS
//     // verifyDataStructure(statement);
//     return registryEntry;
// }

// export function updateBuildCordProof(
//     stmtUri: StatementUri,
//     digest: HexString,
//     spaceUri: SpaceUri,
//     creatorUri: DidUri,
//     schemaUri?: SchemaUri,
// ): IStatementEntry {
//     const statementUri = Cord.Identifier.updateStatementUri(stmtUri, digest);

//     const statement = {
//         elementUri: statementUri,
//         digest,
//         creatorUri,
//         spaceUri,
//     };
//     verifyDataStructure(statement);
//     return statement;
// }

/* TODO: not sure why, the sign() of the key is giving the same output if treated as a function,
   but when compared with output of locally created sign, they are different */
export async function addProof(
    vc: VerifiableCredential,
    callbackFn: SignCallbackB,
    issuerDidUri: Cord.DidUri,
    network: ApiPromise,
    options: any,
) {
    const now = dayjs();
    let credHash: Cord.HexString = calculateVCHash(vc, undefined);
    let genesisHash: string = await Cord.getGenesisHash(network);
    
    /* TODO: Bring selective disclosure here */
    let proof2: CordSDRProof2024 | undefined = undefined;
    if (options.needSDR) {
        let contents = { ...vc.credentialSubject };
        delete contents.id;

        let hashes;
        if (options.schemaUri) {
            hashes = hashContents(contents, options.schemaUri);
        } else {
            hashes = hashContents(contents, null);
        }

        /* proof 2 - ConentNonces for selective disclosure */
        /* This will enable the selective disclosure. This may not be compatible with the normal VC */
        /* This also would change the 'credentialSubject' */
        proof2 = {
            type: 'CordSDRProof2024',
            defaultDigest: credHash,
            hashes: hashes.hashes,
            nonceMap: hashes.nonceMap,
            genesisHash: genesisHash,
        };
        // TODO: Handle schemaUri as option.
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
        //verificationMethod: cbData.keyUri,
        proofValue: 'z' + base58Encode(cbData.signature),
        challenge: undefined,
    };

    /* proof 1 - CordProof */
    /* contains check for revoke */
    let proof1: CordProof2024B | undefined = undefined;
    if (options.needStatementProof) {
        // TODO: Make this for Registry-Entries
        // TODO: Add registryUri in IRegistryEntry interface
        // SDK Method Name: Cord.statement.buildFromProperties //
        const registryEntry = await Cord.Entries.CreateEntriesProperties(
            issuerDidUri.slice(10),
            vc.credentialHash,
            options.blob,
            options.registryUri,
            options.authorizationUri
        );
        let elem = registryEntry.uri.split(':');
        proof1 = {
            type: 'CordProof2024B',
            uri: registryEntry.uri,
            registryUri: options.registryUri,
            blob: registryEntry.blob,
            authorizationUri: registryEntry.authorizationUri,

            // TODO: Keep Schema ID null for now
            schemaUri: undefined,

            creatorUri: issuerDidUri,
            digest: vc.credentialHash,
            identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
            genesisHash: genesisHash
        };

        vc.id = proof1.identifier;
    }

    vc['proof'] = [proof0];
    if (proof1) vc.proof.push(proof1);
    if (proof2) vc.proof.push(proof2);

    return vc;
}

// export async function updateAddProof(
//     oldStmt: StatementUri,
//     vc: VerifiableCredential,
//     callbackFn: SignCallback,
//     issuerDid: Cord.DidDocument,
//     network: ApiPromise,
//     options: any,
// ) {
//     const now = dayjs();
//     let credHash: Cord.HexString = calculateVCHash(vc, undefined);
//     let genesisHash: string = await Cord.getGenesisHash(network);

//     /* TODO: Bring selective disclosure here */
//     let proof2: CordSDRProof2024 | undefined = undefined;
//     if (options.needSDR) {
//         let contents = { ...vc.credentialSubject };
//         delete contents.id;

//         let hashes = hashContents(contents, options.schemaUri);

//         /* proof 2 - ConentNonces for selective disclosure */
//         /* This will enable the selective disclosure. This may not be compatible with the normal VC */
//         /* This also would change the 'credentialSubject' */
//         proof2 = {
//             type: 'CordSDRProof2024',
//             defaultDigest: credHash,
//             hashes: hashes.hashes,
//             nonceMap: hashes.nonceMap,
//             genesisHash: genesisHash,
//         };
//         let vocabulary = `${options.schemaUri}#`;
//         vc.credentialSubject['@context'] = { vocab: vocabulary };
//         credHash = calculateVCHash(vc, hashes.hashes);
//     }
//     vc.credentialHash = credHash;

//     /* proof 0 - Ed25519 */
//     /* validates ownership by checking the signature against the DID */

//     let cbData = await callbackFn(vc.credentialHash);

//     let proof0: ED25519Proof = {
//         type: 'Ed25519Signature2020',
//         created: now.toDate().toString(),
//         proofPurpose: cbData.keyType,
//         verificationMethod: cbData.keyUri,
//         proofValue: 'z' + base58Encode(cbData.signature),
//         challenge: undefined,
//     };

//     /* proof 1 - CordProof */
//     /* contains check for revoke */
//     let proof1: CordProof2024 | undefined = undefined;
//     if (options.needStatementProof) {
//         // SDK Method Name: Cord.statement.buildFromUpdateProperties //
//         const statementEntry = updateBuildCordProof(
//             oldStmt,
//             vc.credentialHash,
//             options.spaceUri!,
//             issuerDid.uri,
//             options.schemaUri ?? undefined,
//         );
//         let elem = statementEntry.elementUri.split(':');
//         proof1 = {
//             type: 'CordProof2024',
//             elementUri: statementEntry.elementUri,
//             spaceUri: statementEntry.spaceUri,
//             schemaUri: statementEntry.schemaUri,
//             creatorUri: issuerDid.uri,
//             digest: vc.credentialHash,
//             identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
//             genesisHash: genesisHash,
//         };

//         vc.id = proof1.identifier;
//     }

//     vc['proof'] = [proof0];
//     if (proof1) vc.proof.push(proof1);
//     if (proof2) vc.proof.push(proof2);

//     return vc;
// }

export function buildVcFromContent(
    schema: Cord.ISchema | null = null,
    contents: IContents,
    issuer: Cord.DidUri,
    holder: Cord.DidUri,
    options: any,
) {
    if (schema) {
        Cord.Schema.verifyObjectAgainstSchema(contents, schema);
    }
    const { evidenceIds, validFrom, validUntil, templates, labels } = options;

    console.log("evidenceIds", evidenceIds);

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
        issuer: issuer,
        issuanceDate: issuanceDate,
        credentialSubject,
        validFrom: validFromString,
        validUntil: validUntilString,
        metadata: {
            evidence: evidenceIds,
            template: templates,
            label: labels,
        },
        credentialSchema: schema || null,
    };
    vc.credentialHash = calculateVCHash(vc, undefined);

    return vc as VerifiableCredential;
}

// export function updateVcFromContent(
//     contents: IContents,
//     vc: VerifiableCredential,
//     validUntil: string | undefined,
// ) {
//     Cord.Schema.verifyObjectAgainstSchema(
//         contents,
//         vc.credentialSchema as Cord.ISchema,
//     );

//     const now = new Date();
//     const validFromString = now.toISOString();
//     const validUntilString = validUntil ? validUntil : vc.validUntil;

//     const credentialSubject = {
//         ...contents,
//         id: vc.credentialSubject.id,
//     };

//     let updatedVc: any = {
//         '@context': [
//             'https://www.w3.org/2018/credentials/v1',
//             'https://cord.network/2023/cred/v1',
//         ],
//         type: ['VerifiableCredential'],
//         issuer: vc.issuer,
//         issuanceDate: validFromString,
//         credentialSubject,
//         validFrom: validFromString,
//         validUntil: validUntilString,
//         metadata: vc.metadata,
//         credentialSchema: vc.credentialSchema,
//     };

//     updatedVc.credentialHash = calculateVCHash(updatedVc, undefined);

//     return updatedVc as VerifiableCredential;
// }

export async function makePresentation(
    vcs: VerifiableCredential[],
    holderUri: Cord.DidUri,
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
        // TODO: Disable keyUri for account based now.
        // verificationMethod: cbData.keyUri,
        proofValue: 'z' + base58Encode(cbData.signature),
    };
    let vp: VerifiablePresentation = {
        '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://cord.network/2023/cred/v1',
        ],
        type: ['VerifiablePresentation'],
        holder: holderUri,
        VerifiableCredential: copiedVcs,
        metadata: {},
        proof: proof0,
    };

    return vp;
}
