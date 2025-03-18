import * as Cord from '@cord.network/sdk';

import { ApiPromise } from '@cord.network/types';

import { CordProof2025 } from './types';

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
    issuerDid: string,
    network: ApiPromise,
    options: any,
) {
    const genesisHash: string = await Cord.getGenesisHash(network);
    const statementEntry = Cord.Statement.buildFromProperties(
        digest,
        options.spaceUri!,
        issuerDid,
        undefined /* no schema for regular file */,
    );
    let elem = statementEntry.elementUri.split(':');
    let proof: CordProof2025 = {
        type: 'CordProof2025',
        elementUri: statementEntry.elementUri,
        spaceUri: statementEntry.spaceUri,
        creatorAddress: issuerDid,
        digest: digest,
        identifier: `${elem[0]}:${elem[1]}:${elem[2]}`,
        genesisHash: genesisHash,
    };

    return proof;
}
