import * as Cord from '@cord.network/sdk';
import { createDid } from './generateDid';
import { randomUUID } from 'crypto';
import 'dotenv/config';

import fs from 'fs';
import crypto from 'crypto';

import { addProof, buildVcFromContent, makePresentation } from '../../src/vc';

import { verifyVP, verifyVC, verifyProofElement } from '../../src/verifyUtils';

import { getCordProofForDigest } from '../../src/docs';

import {
    requestJudgement,
    setIdentity,
    setRegistrar,
    provideJudgement,
} from './utils/createRegistrar';

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

    // Step 1: Setup Membership
    // Setup transaction author account - CORD Account.

    console.log(`\n❄️  New Network Member`);
    const authorIdentity = Cord.Utils.Crypto.makeKeypairFromUri(
        anchorUri as string,
        'sr25519',
    );

    // Create Holder DID
    const { mnemonic: holderMnemonic, document: holderDid } =
        await createDid(authorIdentity);

    // Create issuer DID
    const { mnemonic: issuerMnemonic, document: issuerDid } =
        await createDid(authorIdentity);
    const issuerKeys = Cord.Utils.Keys.generateKeypairs(
        issuerMnemonic,
        'ed25519',
    );
    console.log(
        `🏛   Issuer (${issuerDid?.assertionMethod![0].type}): ${issuerDid.uri}`,
    );
    const conformingDidDocument = Cord.Did.exportToDidDocument(
        issuerDid,
        'application/json',
    );
    console.log('✅ Identities created!');

    console.log(`\n❄️  Chain Space Creation `);
    const spaceProperties = await Cord.ChainSpace.buildFromProperties(
        issuerDid.uri,
    );

    console.log(`\n❄️  Chain Space Properties `);
    const space = await Cord.ChainSpace.dispatchToChain(
        spaceProperties,
        issuerDid.uri,
        authorIdentity,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.log(`\n❄️  Chain Space Approval `);
    await Cord.ChainSpace.sudoApproveChainSpace(authorIdentity, space.uri, 100);
    console.log(`✅  Chain Space Approved`);

    /* schema */
    let newSchemaContent = require('./schema.json');
    let newSchemaName =
        newSchemaContent.title + ':' + Cord.Utils.UUID.generate();
    newSchemaContent.title = newSchemaName;

    let schemaProperties = Cord.Schema.buildFromProperties(
        newSchemaContent,
        space.uri,
        issuerDid.uri,
    );
    const schemaUri = await Cord.Schema.dispatchToChain(
        schemaProperties.schema,
        issuerDid.uri,
        authorIdentity,
        space.authorization,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
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
        issuerDid,
        holderDid.uri,
        {
            spaceUri: space.uri,
            schemaUri: schemaUri,
        },
    );

    let vc = await addProof(
        newCredContent,
        async (data) => ({
            signature: await issuerKeys.assertionMethod.sign(data),
            keyType: issuerKeys.assertionMethod.type,
            keyUri: `${issuerDid.uri}${
                issuerDid.assertionMethod![0].id
            }` as Cord.DidResourceUri,
        }),
        issuerDid,
        { spaceUri: space.uri, schemaUri, needSDR: true },
    );
    console.dir(vc, {
        depth: null,
        colors: true,
    });

    const statement = await Cord.Statement.dispatchRegisterToChain(
        vc.proof[1],
        issuerDid.uri,
        authorIdentity,
        space.authorization,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.log(`✅ Statement element registered - ${statement}`);

    await verifyVC(vc);

    const holderKeys = Cord.Utils.Keys.generateKeypairs(
        holderMnemonic,
        'ed25519',
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
        {
            needSDR: true,
            selectedFields: ['age', 'address'],
        },
    );
    console.dir(vp, { colors: true, depth: null });
    /* VP verification would 'throw' an error in case of error */
    await verifyVP(vp);

    /* sample for document hash anchor on CORD */
    const content: any = fs.readFileSync('./package.json');
    const hashFn = crypto.createHash('sha256');
    hashFn.update(content);
    let digest = `0x${hashFn.digest('hex')}`;

    const docProof = await getCordProofForDigest(digest, issuerDid, {
        spaceUri: space.uri,
    });
    const statement1 = await Cord.Statement.dispatchRegisterToChain(
        docProof,
        issuerDid.uri,
        authorIdentity,
        space.authorization,
        async ({ data }) => ({
            signature: issuerKeys.authentication.sign(data),
            keyType: issuerKeys.authentication.type,
        }),
    );

    console.dir(docProof, { colors: true, depth: null });
    console.log(`✅ Statement element registered - ${statement1}`);

    await verifyProofElement(docProof, digest, undefined);
}

main()
    .then(() => console.log('\nBye! 👋 👋 👋 '))
    .finally(Cord.disconnect);

process.on('SIGINT', async () => {
    console.log('\nBye! 👋 👋 👋 \n');
    Cord.disconnect();
    process.exit(0);
});
