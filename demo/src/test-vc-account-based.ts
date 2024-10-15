import * as Cord from '@cord.network/sdk';
import { createDid } from './generateDid';
import { randomUUID } from 'crypto';
import 'dotenv/config';

import fs from 'fs';
import crypto from 'crypto';

import {
    createAccount
} from './createAccount';

import {
    //addProof,
    //buildVcFromContent,
    makePresentation,
    updateAddProof,
    updateVcFromContent,
} from '../../src/vc';

import {
    addProof,
    buildVcFromContent,
    //makePresentation,
    //updateAddProof,
    //updateVcFromContent,
} from '../../src/vc-accounts';


import { 
    BN
} from 'bn.js';

import type {
  DidUri,
} from '@cord.network/types';

import { verifyVP, verifyVC, verifyProofElement } from '../../src/verifyUtils';

import { getCordProofForDigest } from '../../src/docs';

function getChallenge(): string {
    return Cord.Utils.UUID.generate();
}

async function main() {
    const { NETWORK_ADDRESS, ANCHOR_URI, DID_NAME } = process.env;
    const networkAddress = NETWORK_ADDRESS;
    const anchorUri = ANCHOR_URI;
    const didName = DID_NAME;
    Cord.ConfigService.set({ submitTxResolveOn: Cord.Chain.IS_IN_BLOCK });
    await Cord.connect(networkAddress as string);

    const api = Cord.ConfigService.get('api');

    // Step 1: Setup Membership
    // Setup transaction author account - CORD Account.
    console.log(`\n❄️  New Network Member`)
    const authorityissuerIdentity = Cord.Utils.Crypto.makeKeypairFromUri(
        process.env.ANCHOR_URI ? process.env.ANCHOR_URI : '0x47738cb5518e81ddec01e95bd41cf98a0631667c3d9cac4af3586d270e25d738//1',
        'sr25519'
    )

    // Setup network member account for `Issuer`.
    const { account: issuerIdentity } = await createAccount()
    console.log(`🏦  Issuer Member (${issuerIdentity.type}): ${issuerIdentity.address}`)

    const issuerUri = `did:cord:3${issuerIdentity.address}` as DidUri;

    let issuerTopUpTx = await api.tx.balances.transferAllowDeath(issuerIdentity.address, new BN('1000000000000000'));
    await Cord.Chain.signAndSubmitTx(issuerTopUpTx, authorityissuerIdentity);

    // Setup network member account for `Holder`.
    const { account: holderIdentity } = await createAccount()
    console.log(`🏦  Holder Member (${holderIdentity.type}): ${holderIdentity.address}`)

    const holderUri = `did:cord:3${holderIdentity.address}` as DidUri;

    let holderTopUpTx = await api.tx.balances.transferAllowDeath(holderIdentity.address, new BN('1000000000000000'));
    await Cord.Chain.signAndSubmitTx(holderTopUpTx, authorityissuerIdentity);

    // Create a Registry.  
    const blob = {"data": "test"};
    const stringified_blob = JSON.stringify(blob);
    const registryDigest = await Cord.Registries.getDigestFromRawData(stringified_blob);

    const registryDetails = await Cord.Registries.registryCreateProperties(
        issuerIdentity.address,
        registryDigest,     //digest
        null,              //schemaId
        blob,              //blob
    );

    console.log(`\n❄️  Registry Create Details `, registryDetails);

    const registry = await Cord.Registries.dispatchCreateRegistryToChain(
        registryDetails,
        issuerIdentity,
    );
    
    console.log('\n✅ Registry created!');

    /* TODO: 
     * Create Schema and generate its ID.
    */

    let newCredContent = await buildVcFromContent(
        null,
        {
            name: 'Alice',
            age: 29,
            id: '123456789987654321',
            country: 'India',
            address: {
                street: 'a',
                pin: 54032,
                location: {
                    state: 'karnataka',
                },
            },
        },
        issuerUri,
        holderUri,
        {
            registryUri: registry.uri,
            schemaUri: null,
        },
    );

    let vc = await addProof(
        newCredContent,
        async (data) => ({
            signature: await issuerIdentity.sign(data),
            keyType: issuerIdentity.type
        }),
        issuerUri,
        api,
        {
            registryUri: registry.uri,
            authorizationUri: registry.authorizationUri,
            schemaUri: null,
            needSDR: true,
            needStatementProof: true,
        },
    );
    console.dir(vc, {
        depth: null,
        colors: true,
    });

    
    // Create a Registry Entry.
    const entryBlob = {"test": "data"};
    const stringifiedEntryBlob = JSON.stringify(entryBlob);
    const entryDigest = await Cord.Registries.getDigestFromRawData(stringifiedEntryBlob);

    // Create a Registry Entry Properties.
    const registryEntryDetails = await Cord.Entries.CreateEntriesProperties(
        issuerIdentity.address,
        entryDigest,                  //digest
        entryBlob,                    //blob
        registry.uri,                 //registryUri
        registry.authorizationUri     //registryAuthUri
    );

    console.log(`\n❄️  Registry Entry Create Details `, registryEntryDetails);

    // Dispatch the Registry Entry to the chain.
    const registryEntry = await Cord.Entries.dispatchCreateEntryToChain(
        registryEntryDetails,
        issuerIdentity,
    )

    console.log('\n✅ Registry Entry created!', registryEntry);

    await verifyVC(vc);

    // let vp = await makePresentation(
    //     [vc],
    //     holderUri,
    //     async (data) => ({
    //         signature: await holderIdentity.sign(data),
    //         keyType: holderIdentity.type,
    //     }),
    //     getChallenge(),
    //     api,
    //     {
    //         needSDR: true,
    //         selectedFields: ['age', 'address'],
    //     },
    // );
    // console.dir(vp, { colors: true, depth: null });
    // /* VP verification would 'throw' an error in case of error */
    // await verifyVP(vp);

    // /* sample for document hash anchor on CORD */
    // const content: any = fs.readFileSync('./package.json');
    // const hashFn = crypto.createHash('sha256');
    // hashFn.update(content);
    // let digest = `0x${hashFn.digest('hex')}`;

    // const docProof = await getCordProofForDigest(digest, issuerDid, api, {
    //     spaceUri: space.uri,
    // });
    // const statement1 = await Cord.Statement.dispatchRegisterToChain(
    //     docProof,
    //     issuerDid.uri,
    //     issuerIdentity,
    //     space.authorization,
    //     async ({ data }) => ({
    //         signature: issuerKeys.authentication.sign(data),
    //         keyType: issuerKeys.authentication.type,
    //     }),
    // );

    // console.dir(docProof, { colors: true, depth: null });
    // console.log(`✅ Statement element registered - ${statement1}`);

    // await verifyProofElement(docProof, digest, undefined);

    // // Step:5 Update Verifiable credential
    // console.log(`\n* Statement updation`);

    // // validUntil can be a field of choice , have set it to a month for this example
    // const oneMonthFromNow = new Date();
    // oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);
    // const validUntil = oneMonthFromNow.toISOString();

    // let updatedCredContent = await updateVcFromContent(
    //     {
    //         name: 'Bob',
    //         age: 30,
    //         id: '362734238278237',
    //         country: 'India',
    //         address: {
    //             street: 'a',
    //             pin: 54032,
    //             location: {
    //                 state: 'karnataka',
    //             },
    //         },
    //     },
    //     vc,
    //     validUntil,
    // );

    // let updatedVc = await updateAddProof(
    //     vc.proof[1].elementUri,
    //     updatedCredContent,
    //     async (data) => ({
    //         signature: await issuerKeys.assertionMethod.sign(data),
    //         keyType: issuerKeys.assertionMethod.type,
    //         keyUri: `${issuerDid.uri}${
    //             issuerDid.assertionMethod![0].id
    //         }` as Cord.DidResourceUri,
    //     }),
    //     issuerDid,
    //     api,
    //     {
    //         spaceUri: space.uri,
    //         schemaUri,
    //         needSDR: true,
    //         needStatementProof: true,
    //     },
    // );

    // console.dir(updatedVc, {
    //     depth: null,
    //     colors: true,
    // });

    // const updatedStatement = await Cord.Statement.dispatchUpdateToChain(
    //     updatedVc.proof[1],
    //     issuerDid.uri,
    //     issuerIdentity,
    //     space.authorization,
    //     async ({ data }) => ({
    //         signature: issuerKeys.authentication.sign(data),
    //         keyType: issuerKeys.authentication.type,
    //     }),
    // );

    // console.log(`✅ UpdatedStatement element registered - ${updatedStatement}`);

    // await verifyVC(updatedVc);
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally(Cord.disconnect);

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    Cord.disconnect();
    process.exit(0);
});
