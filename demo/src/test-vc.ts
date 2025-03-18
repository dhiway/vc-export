import * as Cord from '@cord.network/sdk';
import 'dotenv/config';

import fs from 'fs';
import crypto from 'crypto';
import BN from 'bn.js';

import { createAccount } from './createAccount';

import {
    addProof,
    buildVcFromContent,
    makePresentation,
    updateAddProof,
    updateVcFromContent,
} from '../../src/vc';

import { verifyVP, verifyVC, verifyProofElement } from '../../src/verifyUtils';

import { getCordProofForDigest } from '../../src/docs';

function getChallenge(): string {
    return Cord.Utils.UUID.generate();
}

async function main() {
    const { NETWORK_ADDRESS, ANCHOR_URI, DID_NAME } = process.env;
    //const networkAddress = NETWORK_ADDRESS ?? 'ws://localhost:9944';
    //const anchorUri = ANCHOR_URI ?? '//Alice';
    const networkAddress = 'ws://localhost:9944';
    const anchorUri =  '//Alice';
    const didName = DID_NAME;
    Cord.ConfigService.set({ submitTxResolveOn: Cord.Chain.IS_IN_BLOCK });
    await Cord.connect(networkAddress as string);

    const api = Cord.ConfigService.get('api');

    // Step 1: Setup Membership
    // Setup transaction author account - CORD Account.

    console.log(`\n❄️  New Network Member`);
    const authorIdentity = Cord.Utils.Crypto.makeKeypairFromUri(
        anchorUri as string,
        'sr25519',
    );

    // Create Holder DID
    const { account: holderAccount, mnemonic: holderMnemonic } =
        await createAccount();

    // Create issuer DID
    const { account: issuerAccount, mnemonic: issuerMnemonic } =
        await createAccount();
   
      // Transfer funds for author identity.
    let author_id_tx = await api.tx.balances.transferAllowDeath(issuerAccount.address, new BN('1000000000000000'));
    await Cord.Chain.signAndSubmitTx(author_id_tx, authorIdentity);

    author_id_tx = await api.tx.balances.transferAllowDeath(holderAccount.address, new BN('1000000000000000'));
    await Cord.Chain.signAndSubmitTx(author_id_tx, authorIdentity);

        /* We need to get 'DID' as a variable while issuing */
    const issuerAccountDid = `did:web:${issuerAccount.address}.myn.social`;
    const holderDid = `did:web:${holderAccount.address}.myn.social`;

    console.log('✅ Identities created!');

    console.log(`\n❄️  Chain Space Creation `);
    const spaceProperties = await Cord.ChainSpace.buildFromProperties(
        issuerAccount.address,
        `Testing_VC_v1.${Cord.Utils.UUID.generate()}`
    );

    console.log(`\n❄️  Chain Space Properties `);
    const space = await Cord.ChainSpace.dispatchToChain(
        spaceProperties,
        issuerAccount,
    );

    console.log(`\n❄️  Chain Space Approval `);
    //await Cord.ChainSpace.sudoApproveChainSpace(authorIdentity, space.uri, 100);
    //console.log(`✅  Chain Space Approved`);

    /* schema */
    let newSchemaContent = require('./schema.json');
    let newSchemaName =
        newSchemaContent.title + ':' + Cord.Utils.UUID.generate();
    newSchemaContent.title = newSchemaName;

    let schemaProperties = Cord.Schema.buildFromProperties(
        newSchemaContent,
        issuerAccount.address,
    );
    const schemaUri = await Cord.Schema.dispatchToChain(
        schemaProperties.schema,
        issuerAccount
    );
    console.log(`✅ Schema - ${schemaUri} - added!`);

    // Step 4: Delegate creates a new Verifiable Document
    console.log(`\n❄️  Statement Creation `);

    let newCredContent = await buildVcFromContent(
        schemaProperties.schema,
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
        issuerAccountDid,
        holderDid,
        {
            spaceUri: space.uri,
            schemaUri: schemaUri,
        },
    );

    let vc = await addProof(
        newCredContent,
        async (data) => ({
            signature: issuerAccount.sign(data),
            keyType: issuerAccount.type,
            keyUri: `${issuerAccountDid}`,
        }),
        issuerAccount.address,
        issuerAccountDid,
        api,
        {
            spaceUri: space.uri,
            schemaUri,
            needSDR: true,
            needStatementProof: true,
        },
    );
    console.dir(vc, {
        depth: null,
        colors: true,
    });

    const proof = vc.proof ? vc.proof[1]: {};
    const statement = await Cord.Statement.dispatchRegisterToChain(
        proof as unknown as Cord.IStatementEntry,
        issuerAccount,
        space.authorization,
    );

    console.log(`✅ Statement element registered - ${statement}`);
/*
    await verifyVC(vc);

    const holderKeys = Cord.Utils.Keys.generateKeypairs(
        holderMnemonic,
        'sr25519',
    );

    let vp = await makePresentation(
        [vc],
        holderDid,
        async (data) => ({
            signature: holderKeys.assertionMethod.sign(data),
            keyType: holderKeys.assertionMethod.type,
            keyUri: `${holderDid.uri}${
                holderDid.assertionMethod![0].id
            }` as Cord.DidResourceUri,
        }),
        getChallenge(),
        api,
        {
            needSDR: true,
            selectedFields: ['age', 'address'],
        },
    );
    console.dir(vp, { colors: true, depth: null });
    */
    /* VP verification would 'throw' an error in case of error */
    //await verifyVP(vp);

    /* sample for document hash anchor on CORD */
    const content: any = fs.readFileSync('./package.json');
    const hashFn = crypto.createHash('sha256');
    hashFn.update(content);
    let digest: Cord.HexString = `0x${hashFn.digest('hex')}`;

    const docProof = await getCordProofForDigest(digest, issuerAccount.address, api, {
        spaceUri: space.uri,
    });
    const statement1 = await Cord.Statement.dispatchRegisterToChain(
        docProof as unknown as Cord.IStatementEntry,
        issuerAccount,
        space.authorization,
    );

    console.dir(docProof, { colors: true, depth: null });
    console.log(`✅ Statement element registered - ${statement1}`);

    //await verifyProofElement(docProof, digest, undefined);

    // Step:5 Update Verifiable credential
    console.log(`\n* Statement updation`);

    // validUntil can be a field of choice , have set it to a month for this example
    const oneMonthFromNow = new Date();
    oneMonthFromNow.setMonth(oneMonthFromNow.getMonth() + 1);
    const validUntil = oneMonthFromNow.toISOString();

    let updatedCredContent = await updateVcFromContent(
        {
            name: 'Bob',
            age: 30,
            id: '362734238278237',
            country: 'India',
            address: {
                street: 'a',
                pin: 54032,
                location: {
                    state: 'karnataka',
                },
            },
        },
        vc,
        validUntil,
    );

    let updatedVc = await updateAddProof(
        vc.proof[1].elementUri,
        updatedCredContent,
        async (data) => ({
            signature: await issuerAccount.sign(data),
            keyType: issuerAccount.type,
            keyUri: issuerAccountDid,
        }),
        issuerAccountDid,
        api,
        {
            spaceUri: space.uri,
            schemaUri,
            needSDR: true,
            needStatementProof: true,
        },
    );

    console.dir(updatedVc, {
        depth: null,
        colors: true,
    });

    const updatedStatement = await Cord.Statement.dispatchUpdateToChain(
        updatedVc.proof[1] as unknown as Cord.IStatementEntry,
        issuerAccount,
        space.authorization,
    );

    console.log(`✅ UpdatedStatement element registered - ${updatedStatement}`);

    await verifyVC(updatedVc);
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally(Cord.disconnect);

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    Cord.disconnect();
    process.exit(0);
});
