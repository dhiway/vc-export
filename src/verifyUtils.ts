import { base58Decode } from '@polkadot/util-crypto'

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

import {
    makeStatementsJsonLD,
    calculateVCHash,
} from './utils'

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
