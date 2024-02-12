import * as Cord from '@cord.network/sdk';

import { CordProof2024 } from './types';

/*
import { base58Encode, base58Decode } from '@polkadot/util-crypto'
import dayjs from 'moment'
import { hexToBn } from '@polkadot/util'
function hash(value: string) {
    const hash = crypto.createHash('sha256');
    hash.update(value);
    return hash.digest('hex');
}
*/

// path: file path on storage
export async function getCordProofForDigest(
    digest: Cord.HexString,
    issuerDid: Cord.DidDocument,
    options: any,
) {
    const statementEntry = Cord.Statement.buildFromProperties(
        digest,
        options.spaceUri!,
        issuerDid.uri,
        undefined /* no schema for regular file */,
    );
    let elem = statementEntry.elementUri.split(':');
    let proof: CordProof2024 = {
        type: 'CordProof2024',
        elementUri: statementEntry.elementUri,
        spaceUri: statementEntry.spaceUri,
        creatorUri: issuerDid.uri,
        digest: digest,
        identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
    };

    return proof;
}
