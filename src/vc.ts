import { hexToBn } from '@polkadot/util'
import { base58Encode, base58Decode } from '@polkadot/util-crypto'
import dayjs from 'moment'

import * as Cord from '@cord.network/sdk'

import {
    VerifiableCredential,
    VerifiablePresentation,
    IContents,
    VCProof,
    ED25519Proof,
    CordSDRProof2024,
    CordProof2024,
} from './types'

export function calculateVCHash(vc: VerifiableCredential, contentHashes: Cord.HexString[] | undefined): Cord.HexString {
    const {
	issuanceDate,
	validFrom,
	validUntil,
	issuer,
	credentialSubject,
    } = vc;

    let newCredContent: IContents = { issuanceDate, validFrom, validUntil, issuer, credentialSubject };
    if (contentHashes) {
	newCredContent = { issuanceDate, validFrom, validUntil, issuer, holder: credentialSubject.id, contentHashes };
    }
    const serializedCred = Cord.Utils.Crypto.encodeObjectAsStr(newCredContent)
    const credHash = Cord.Utils.Crypto.hashStr(serializedCred)

    return credHash;
}


/* TODO: not sure why, the sign() of the key is giving the same output if treated as a function,
   but when compared with output of locally created sign, they are different */
export async function addProof(
    vc: VerifiableCredential,
    issuerKeys:  Cord.ICordKeyPair,
    issuerDid:  Cord.DidDocument,
    options: any
) {
    const now = dayjs();
    let credHash: Cord.HexString = calculateVCHash(vc, undefined);

    /* TODO: Bring selective disclosure here */
    let proof2: CordSDRProof2024 | undefined = undefined;
    if (options.needSDR) {
	let contents = { ...vc.credentialSubject};
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
	}
	let vocabulary = `${options.schemaUri}#`;
	vc.credentialSubject['@context'] = { 'vocab': vocabulary }
	credHash = calculateVCHash(vc, hashes.hashes);
    }
    vc.credentialHash = credHash;

    /* proof 0 - Ed25519 */
    /* validates ownership by checking the signature against the DID */

    let signature = await issuerKeys.assertionMethod.sign(vc.credentialHash);
    let keyType = 'assertionMethod';
    let keyUri = `${issuerDid.uri}${
	issuerDid.assertionMethod![0].id
      }` as Cord.DidResourceUri;

    let proof0: ED25519Proof  = {
	type: "Ed25519Signature2020",
	created: now.toDate().toString(),
	proofPurpose: keyType,
	verificationMethod: keyUri,
	proofValue: 'z' + base58Encode(signature),
	challenge: undefined
    }

    /* proof 1 - CordProof */
    /* contains check for revoke */
    const statementEntry = Cord.Statement.buildFromProperties(
	vc.credentialHash,
	options.spaceUri!,
	issuerDid.uri,
	options.schemaUri ?? undefined
    )
    let elem = statementEntry.elementUri.split(':');
    let proof1: CordProof2024 = {
	type: "CordProof2024",
	elementUri: statementEntry.elementUri,
	spaceUri: statementEntry.spaceUri,
	schemaUri: statementEntry.schemaUri,
	creatorUri: issuerDid.uri,
	digest: vc.credentialHash,
	identifier: `${elem[0]}:${elem[1]}:${elem[2]}`
    }
    vc.id = proof1.identifier;

    vc['proof'] = [ proof0, proof1 ];
    if (proof2) vc.proof.push(proof2);

    return vc;
}

function jsonLDcontents(
  contents: IContents,
  schemaId: string,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  const flattenedContents = Cord.Utils.DataUtils.flattenObject(contents || {});
  const vocabulary = `${schemaId}#`;
  result['@context'] =  { '@vocab': vocabulary };

  Object.entries(flattenedContents).forEach(([key, value]) => {
    result[vocabulary + key] = value;
  });

  return result;
}

export function toJsonLD(
  contents: IContents,
  schemaId: string,
): Record<string, unknown> {
  const credentialSubject = jsonLDcontents(contents, schemaId)
    return credentialSubject;
}

function makeStatementsJsonLD(contents: IContents, schemaId: string): string[] {
  const normalized = jsonLDcontents(contents, schemaId)
  return Object.entries(normalized).map(([key, value]) =>
    JSON.stringify({ [key]: value })
  )
}

export function hashContents(
  contents: IContents,
  schemaId: string,
  options: Cord.Utils.Crypto.HashingOptions & {
    selectedAttributes?: string[],
  } = {}
): {
  hashes: Cord.HexString[]
  nonceMap: Record<string, string>
} {
  // use canonicalisation algorithm to make hashable statement strings
  const statements = makeStatementsJsonLD(contents, schemaId)

  let filteredStatements = statements
  if (options.selectedAttributes && options.selectedAttributes.length) {
    filteredStatements = Cord.Utils.DataUtils.filterStatements(statements, options.selectedAttributes);
  }

  // iterate over statements to produce salted hashes
  const processed = Cord.Utils.Crypto.hashStatements(filteredStatements, options)

  // produce array of salted hashes to add to credential
  const hashes = processed
    .map(({ saltedHash }) => saltedHash)
    .sort((a, b) => hexToBn(a).cmp(hexToBn(b)))

  // produce nonce map, where each nonce is keyed with the unsalted hash
  const nonceMap = {}
  processed.forEach(({ digest, nonce, statement }) => {
    // throw if we can't map a digest to a nonce - this should not happen if the nonce map is complete and the credential has not been tampered with
    if (!nonce) throw new Cord.Utils.SDKErrors.ContentNonceMapMalformedError(statement)
    nonceMap[digest] = nonce
  }, {})
  return { hashes, nonceMap }
}

export function buildVcFromContent(
  schema: Cord.ISchema,
  contents: IContents,
  issuer: Cord.DidDocument,
  holder: Cord.DidUri,
  options: any,
) {
    Cord.Schema.verifyObjectAgainstSchema(contents, schema)

    const { evidenceIds, validFrom, validUntil, templates, labels } = options

    const now = new Date();
    const issuanceDate = now.toISOString()
    const validFromString = validFrom ? validFrom.toISOString() : now.toISOString()
    const validUntilString = validUntil ? validUntil.toISOString() : new Date(new Date().setFullYear(now.getFullYear() + 1)).toISOString()

    const credentialSubject = {
	...contents,
	id: holder,
    }
    let vc: any = {
	'@context': [
	    'https://www.w3.org/2018/credentials/v1',
	    'https://cord.network/2023/cred/v1'
	],
	type: ["VerifiableCredential"],
	issuer: issuer.uri,
	issuanceDate,
	credentialSubject,
	validFrom: validFromString,
	validUntil: validUntilString,
	metadata: {
	    evidence: evidenceIds,
	    template: templates,
	    label: labels,
	},
	credentialSchema: schema,
    }
    vc.credentialHash = calculateVCHash(vc, undefined);

  return vc as VerifiableCredential;
}

export async function makePresentation(
    vcs: VerifiableCredential[],
    holder: Cord.DidDocument,
    holderKeys: Cord.ICordKeyPair,
    challenge: string,
    options: any,
) {
    const now = dayjs();
    let copiedVcs = vcs;
    if (options?.needSDR) {
	copiedVcs = []

	for (let i = 0; i < vcs.length; i++) {
	    let vc = vcs[i];

	    if (options.selectedFields) {
		let subject = vc.credentialSubject;
		let newSubject = {
		    id: subject.id,
		    ['@context']: subject['@context'],
		}

		Object.keys(subject).forEach((key) => {
		    if (options.selectedFields.includes(key)) {
			newSubject[key] = subject[key]
		    }
		});
		let copyOfVC = {
		    ...vc,
		    credentialSubject: newSubject
		};
		copiedVcs.push(copyOfVC);
	    } else {
		copiedVcs.push(vc);
	    }
	}
    }
    let signature = await holderKeys.assertionMethod.sign(challenge);

    let keyType = 'assertionMethod';
    let keyUri = `${holder.uri}${
	holder.assertionMethod![0].id
      }` as Cord.DidResourceUri;

    let proof0: ED25519Proof  = {
	"challenge": challenge,
	"type": "Ed25519Signature2020",
	"created": now.toDate().toString(),
	"proofPurpose": keyType,
	"verificationMethod": keyUri,
	"proofValue": 'z' + base58Encode(signature),
    }
    let vp: VerifiablePresentation = {
	'@context': [
	    'https://www.w3.org/2018/credentials/v1',
	    'https://cord.network/2023/cred/v1'
	],
	type: ["VerifiablePresentation"],
	holder: holder.uri,
	VerifiableCredential: copiedVcs,
	metadata: {},
	proof: proof0,
    }

    return vp;
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
    if (!schemaId)
	throw 'schemaId is needed for SDR verification'

    const statements = makeStatementsJsonLD(content, schemaId);
    let filteredStatements = statements
    if (attributes && attributes.length) {
	filteredStatements = Cord.Utils.DataUtils.filterStatements(statements, attributes);
    }

    // iterate over statements to produce salted hashes
    const hashed = Cord.Utils.Crypto.hashStatements(filteredStatements, { nonces: nonceMap })
    // check resulting hashes
    const digestsInProof = Object.keys(nonceMap)
    const { verified, errors } = hashed.reduce<{
	verified: boolean
	errors: Error[]
    }>(
	(status, { saltedHash, statement, digest, nonce }) => {
	    // check if the statement digest was contained in the proof and mapped it to a nonce
	    if (!digestsInProof.includes(digest) || !nonce) {
		status.errors.push(new Cord.Utils.SDKErrors.NoProofForStatementError(statement))
		return { ...status, verified: false }
	    }
	    // check if the hash is whitelisted in the proof
	    if (!hashes.includes(saltedHash)) {
		status.errors.push(
		    new Cord.Utils.SDKErrors.InvalidProofForStatementError(statement)
		)
		return { ...status, verified: false }
	    }
	    return status
	},
	{ verified: true, errors: [] }
    )
    if (verified !== true) {
	throw new Cord.Utils.SDKErrors.ContentUnverifiableError(
	    'One or more statements in the content could not be verified',
	    { cause: errors }
	)
    }
}


export async function verifyProofElement(proof: VCProof, credHash: string | Cord.HexString | undefined, vc: VerifiableCredential | undefined) {

    if (proof.type === 'CordProof2024') {
	/* verify the proof */
	let obj = proof as unknown as CordProof2024

	if (obj.digest !== credHash) {
	    throw 'credential Digest mismatch';
	}
	if (obj.elementUri !== `${obj.identifier}:${credHash.replace('0x','')}`) {
	       throw 'elementUri mismatch';
	}

	const verificationResult = await Cord.Statement.verifyAgainstProperties(
	    obj.elementUri,
	    obj.digest,
	    obj.creatorUri,
	    obj.spaceUri,
	    obj.schemaUri,
	)

	if (!verificationResult.isValid) {
	    throw 'Failed to verify CordProof2024';
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
	    throw 'the challenge/digest passed for verification is invalid'
	await Cord.Did.verifyDidSignature({
	    message,
	    signature: base58Decode(str),
	    keyUri: obj.verificationMethod as unknown as Cord.DidResourceUri
	});
	/* all is good, no throw */
    }
    if (proof.type === 'CordSDRProof2024') {
	let obj = proof as unknown as CordSDRProof2024;

	/* make sure from whats is present in content, we get back the same content nonces */
	let subject = vc?.credentialSubject ? { ...vc.credentialSubject } : {id: 'dummy', '@context': 'dummy'};
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
	let hashes = (proofs.type === 'CordSDRProof2024') ? proofs.hashes : undefined;
	let credHash =  calculateVCHash(vc, hashes);
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
	    credHash =  calculateVCHash(vc, obj.hashes);
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
