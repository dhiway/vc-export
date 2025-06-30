import * as Cord from '@cord.network/sdk';
import 'dotenv/config';

import fs from 'fs';
import crypto from 'crypto';

import { blake2AsHex } from '@cord.network/sdk';

import { Keyring } from '@polkadot/keyring';
import { createAccount } from '../../src/utils';

import {
    addProof,
    buildVcFromContent,
    constructCordProof2025,
    makePresentation,
    updateAddProof,
    updateVcFromContent,
} from '../../src/vc';

import { verifyVP, verifyVC, verifyProofElement } from '../../src/verifyUtils';

const TIMEOUT = 10_000; // 10s timeout for event listeners

function getChallenge(): string {
    return Cord.Utils.UUID.generate();
}

/**
 * Waits for a specific chain event and extracts a field from its data.
 * @param api - CORD API instance.
 * @param eventCheck - Function to check if an event matches.
 * @param fieldIndex - Index of the field to extract from event data.
 * @returns Promise resolving to the extracted field value.
 */
async function waitForEvent(api, eventCheck, fieldIndex) {
  return new Promise((resolve, reject) => {
    let unsubscribe;
    api.query.system.events((events) => {
      events.forEach(({ phase, event }) => {
        if (phase.isApplyExtrinsic && eventCheck(event)) {
          console.log("event found:", event.toHuman());
          const fieldValue = event.data[fieldIndex].toHuman();
          resolve(fieldValue);
          if (unsubscribe) unsubscribe();
        }
      });
    }).then((unsub) => {
      unsubscribe = unsub;
    });

    setTimeout(() => {
      if (unsubscribe) unsubscribe();
      reject(new Error('Timeout: Event not found'));
    }, TIMEOUT);
  });
}

async function main() {
  const networkAddress = /*process.env.NETWORK_ADDRESS || */ 'ws://127.0.0.1:9944';
  const stashUri = process.env.STASH_URI || '//Alice';
  const TRANSFER_AMOUNT = 100 * 10 ** 12; // 30 WAY for transactions

  try {
    console.log(`\n🏦 Connecting to CORD at ${networkAddress}...`);
    Cord.ConfigService.set({ submitTxResolveOn: Cord.Chain.IS_IN_BLOCK });
    await Cord.connect(networkAddress);

    const api = Cord.ConfigService.get('api');
    console.log(`✅ Connected to ${api.runtimeVersion.specName} (v${api.runtimeVersion.specVersion})`);

    const keyring = new Keyring({ type: 'sr25519' });
    const stash = keyring.createFromUri(stashUri);
    console.log(`🏦 Stash: ${stash.address}`);

    console.log('\n👤 Generating accounts...');
    // Accounts[0] - Issuer, Accounts[1] - Holder
    const accounts = [createAccount(), createAccount(), createAccount()]
      .map(({ account }, i) => {
        console.log(`🏦 Account ${i + 1}: ${account.address}`);
        return account;
      });

    console.log('\n💸 Funding accounts...');
    const fundTxs = accounts.map((account) =>
      api.tx.balances.transferKeepAlive(account.address, TRANSFER_AMOUNT)
    );

    for (const [i, tx] of fundTxs.entries()) {
      await new Promise((resolve, reject) => {
        tx.signAndSend(stash, ({ status, dispatchError }) => {
          if (dispatchError) {
            reject(new Error(`Funding account ${i + 1} failed: ${dispatchError}`));
          } else if (status.isInBlock) {
            console.log(`✅ Funded account ${i + 1}`);
            resolve();
          }
        }).catch(reject);
      });
    }

    // 📝 Profile for Account 1 ( Issuer )
    console.log('\n📝 Creating profile for Account 1 (Issuer)...');
    const rawProfileData1 = {
      pub_name: 'Issuer',
      pub_email: 'issuer@example.com',
    };
    const hashedProfileData1 = Object.entries(rawProfileData1).map(([key, value]) => [
      key,
      blake2AsHex(value),
    ]);

    await Cord.Profile.dispatchSetProfileToChain(hashedProfileData1, accounts[0]);
    const profileIdentifier1 = await waitForEvent(
      api,
      (event) => api.events.profile.ProfileSet.is(event),
      1
    );
    console.log(`✅ Profile set for Account 1 (Issuer) with ID: ${profileIdentifier1}`);

    // 📝 Profile for Account 2 ( Holder )
    console.log('\n📝 Creating profile for Account 2 (Holder)...');
    const rawProfileData2 = {
      pub_name: 'Holder',
      pub_email: 'holder@example.com',
    };
    const hashedProfileData2 = Object.entries(rawProfileData2).map(([key, value]) => [
      key,
      blake2AsHex(value),
    ]);

    await Cord.Profile.dispatchSetProfileToChain(hashedProfileData2, accounts[1]);
    const profileIdentifier2 = await waitForEvent(
      api,
      (event) => api.events.profile.ProfileSet.is(event),
      1
    );
    console.log(`✅ Profile set for Account 2 (Holder) with ID: ${profileIdentifier2}`);

    /* Create did based on that profile-id */

        /* We need to get 'DID' as a variable while issuing */
    // const issuerAccountDid = `did:web:${issuerAccount.address}.myn.social`;
    // const holderDid = `did:web:${holderAccount.address}.myn.social`;

    const issuerDid = 'did:cord:' + profileIdentifier1;
    const holderDid = 'did:cord:' + profileIdentifier2;

    const issuerAccount = accounts[0];
    const holderAccount = accounts[1];

    console.log('✅ Identities created!');

    // 🔄 Create Registry
    console.log('\n🔄 Creating registry...');

    const schema = require('./schema.json');

    const registryBlob = {
      title: 'VC Export Registry',
      schema: JSON.stringify(schema),
      date: new Date().toISOString(),
    };
    const registryStringifiedBlob = JSON.stringify(registryBlob);
    const registryTxHash = await Cord.Registry.getDigestFromRawData(registryStringifiedBlob);

    const registryProperties = await Cord.Registry.registryCreateProperties(
      registryTxHash,
      null, // no blob
    );
    await Cord.Registry.dispatchCreateToChain(registryProperties, accounts[0]);

    const identifier = await waitForEvent(
      api,
      (event) => api.events.registry.RegistryCreated.is(event),
      0
    ) as string;
    const registryId = identifier;
    console.log(`✅ Registry created with URI: ${registryId}`);

    // Step 4: Issuer creates a new Verifiable Document
    console.log('\n📝 Creating registry entry...');

    let newCredContent = await buildVcFromContent(
        // We used to add the uri of the schema for the json and send it
        // schemaProperties.schema,
        // Now only send raw json of schema, as we dont have the uri for it.
        schema,
        {
            name: 'Alice',
            age: 29,
            id: '123456789987654321',
            country: 'India',
            address: {
                street: 'Central Street',
                pin: 560032,
                location: {
                    state: 'Karnataka',
                },
            },
        },
        issuerDid,
        holderDid,
        // options are also not required for now.
        // {
        //     spaceUri: space.uri,
        //     schemaUri: schemaUri,
        // },
    );

    let proofId = "PAN-1234"
    let vc = await addProof(
        newCredContent,
        async (data) => ({
            signature: issuerAccount.sign(data),
            keyType: issuerAccount.type,
            keyUri: issuerDid,
        }),
        registryId,
        issuerAccount.address,
        api,
        {
            needSDR: true,
            needEntryProof: true,
        },
        proofId, /* Optional proof-id, example PAN ID */
    );
    console.dir(vc, {
        depth: null,
        colors: true,
    });

    const proof = vc.proof ? vc.proof[1]: {};

    /* Proof contains more than required fields for IRegistryEntry but still works :) */
    await Cord.Entry.dispatchCreateEntryToChain(proof, accounts[0]);

    const entryIdentifier = await waitForEvent(
      api,
      (event) => api.events.entry.RegistryEntryCreated.is(event),
      2
    ) as string;

    console.log(`✅ Entry created with URI: ${entryIdentifier}`);

    /* TODO: Check if this is the right way. If entryIdentifier has to be externally passed, since we dont have the entry-id at addProof level. */
    await verifyVC(vc, api, entryIdentifier);

    console.log(`✅ VC is verified from Chain - ${entryIdentifier}`);

    let vp = await makePresentation(
        [vc],
        holderDid,
        async (data) => ({
            signature: holderAccount.sign(data),
            keyType: holderAccount.type,
            keyUri: holderDid,
        }),
        getChallenge(),
        api,
        {
            needSDR: true,
            selectedFields: ['age', 'address'],
        },
    );
    console.dir(vp, { colors: true, depth: null });

    /* VP verification would 'throw' an error in case of error */
    //await verifyVP(vp);

    /* sample for document hash anchor on CORD */
    /* Can be moved at last of the demo-script, so the flow is not broken */
    // const content: any = fs.readFileSync('./package.json');
    // let digest: Cord.HexString = Cord.blake2AsHex(content);
    // var docProof = await constructCordProof2025(
    //     registryId,
    //     digest,
    //     /* Check if profile-id or account address makes sense */
    //     issuerAccount.address,
    //     api,
    // );
    // docProof = {
    //     ...docProof,
    //     blob: null,
    // }
    // await Cord.Entry.dispatchCreateEntryToChain(docProof, accounts[0]);
    // const entryIdentifier1 = await waitForEvent(
    //   api,
    //   (event) => api.events.entry.RegistryEntryCreated.is(event),
    //   2
    // ) as string;
    // console.log(`✅ Entry created with URI: ${entryIdentifier1}`);
    // await verifyProofElement(docProof, digest, undefined, entryIdentifier1);

    console.log("\n🔄 Updating VC...");

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
        registryId,
        /* TODO: Check if passing entry-id externally from vc is correct */
        //vc.proof[1].elementUri,
        entryIdentifier,
        updatedCredContent,
        async (data) => ({
            signature: await issuerAccount.sign(data),
            keyType: issuerAccount.type,
            keyUri: issuerDid,
        }),
        issuerAccount.address,
        api,
        {
            needSDR: true,
            needEntryProof: true,
        },
    );

    console.dir(updatedVc, {
        depth: null,
        colors: true,
    });

    const updatedProof = updatedVc.proof ? updatedVc.proof[1]: {};
    /* TODO: Check on ideal way to pass entry-id */
    updatedProof.registryEntryId = entryIdentifier;

    await Cord.Entry.dispatchUpdateEntryToChain(updatedProof, accounts[0]);
    console.log(`✅ Entry updated with URI: ${entryIdentifier}`);

    await verifyVC(updatedVc, api, entryIdentifier);
} catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : error);
  } finally {
    console.log('\n🔌 Disconnecting from CORD...');
    await Cord.disconnect();
    console.log('✅ Disconnected');
  }
}

main().catch((error) => {
  console.error('❌ Unexpected error:', error instanceof Error ? error.message : error);
  process.exit(1);
});
