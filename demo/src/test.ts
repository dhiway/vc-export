import * as Cord from '@cord.network/sdk'
// import { UUID, Crypto } from '@cord.network/utils'
import { createDid } from './generateDid'
import { randomUUID } from 'crypto'
import 'dotenv/config'

import { buildFromContent, addProof } from '../../src/index';

import {
  requestJudgement,
  setIdentity,
  setRegistrar,
  provideJudgement,
} from './utils/createRegistrar'

function getChallenge(): string {
  return Cord.Utils.UUID.generate()
}

async function main() {
  const { NETWORK_ADDRESS, ANCHOR_URI, DID_NAME } = process.env
  const networkAddress = NETWORK_ADDRESS
  const anchorUri = ANCHOR_URI
  const didName = DID_NAME
  Cord.ConfigService.set({ submitTxResolveOn: Cord.Chain.IS_IN_BLOCK })
  await Cord.connect(networkAddress)

  // Step 1: Setup Membership
  // Setup transaction author account - CORD Account.

  console.log(`\n❄️  New Network Member`)
  const authorIdentity = Cord.Utils.Crypto.makeKeypairFromUri(
    anchorUri,
    'sr25519'
  )

  // Create Holder DID
  const { mnemonic: holderMnemonic, document: holderDid } = await createDid(
    authorIdentity
  )

  // Create issuer DID
  const { mnemonic: issuerMnemonic, document: issuerDid } = await createDid(
    authorIdentity
  )
  const issuerKeys = Cord.Utils.Keys.generateKeypairs(issuerMnemonic, 'ed25519')
  console.log(
    `🏛   Issuer (${issuerDid?.assertionMethod![0].type}): ${issuerDid.uri}`
  )
  const conformingDidDocument = Cord.Did.exportToDidDocument(
    issuerDid,
    'application/json'
  )
  console.dir(conformingDidDocument, {
    depth: null,
    colors: true,
  })
  console.log('✅ Identities created!')

  console.log(`\n❄️  Chain Space Creation `)
  const spaceProperties = await Cord.ChainSpace.buildFromProperties(
    issuerDid.uri
  )
  console.dir(spaceProperties, {
    depth: null,
    colors: true,
  })

  console.log(`\n❄️  Chain Space Properties `)
  const space = await Cord.ChainSpace.dispatchToChain(
    spaceProperties,
    issuerDid.uri,
    authorIdentity,
    async ({ data }) => ({
      signature: issuerKeys.authentication.sign(data),
      keyType: issuerKeys.authentication.type,
    })
  )
  console.dir(space, {
    depth: null,
    colors: true,
  })

  console.log(`\n❄️  Chain Space Approval `)
  await Cord.ChainSpace.sudoApproveChainSpace(
    authorIdentity,
    space.uri,
    100
  )
  console.log(`✅  Chain Space Approved`)

  // Step 4: Delegate creates a new Verifiable Document
  console.log(`\n❄️  Statement Creation `)

    let newCredContent = await buildFromContent(null, {
	a: "hello",
	b: 20
    }, issuerDid, holderDid.uri, {spaceUri: space.uri, schemaUri: undefined })
  console.dir(newCredContent, {
    depth: null,
    colors: true,
  })

    let vc = await addProof(newCredContent, issuerKeys, issuerDid, { spaceUri: space.uri });
  console.dir(vc, {
    depth: null,
    colors: true,
  })
    const credHash = vc.credentialHash;

  const statementEntry = await Cord.Statement.buildFromProperties(
    credHash,
    space.uri,
    issuerDid.uri,
    undefined,
  )
  console.dir(statementEntry, {
    depth: null,
    colors: true,
  })

  const statement = await Cord.Statement.dispatchRegisterToChain(
    statementEntry,
    issuerDid.uri,
    authorIdentity,
    space.authorization,
    async ({ data }) => ({
      signature: issuerKeys.authentication.sign(data),
      keyType: issuerKeys.authentication.type,
    })
  )

  console.log(`✅ Statement element registered - ${statement}`)

  console.log(`\n❄️  Statement verification `)
  const verificationResult = await Cord.Statement.verifyAgainstProperties(
      statementEntry.elementUri,
      credHash,
      issuerDid.uri,
      space.uri,
      undefined, //schemaUri,
  )

  if (verificationResult.isValid) {
      console.log(`✅ Verification successful! "${statementEntry.elementUri}" 🎉 \n${verificationResult}`)
  } else {
    console.log(`🚫 Verification failed! - "${verificationResult.message}" 🚫`)
  }

}
main()
  .then(() => console.log('\nBye! 👋 👋 👋 '))
  .finally(Cord.disconnect)

process.on('SIGINT', async () => {
  console.log('\nBye! 👋 👋 👋 \n')
  Cord.disconnect()
  process.exit(0)
})
