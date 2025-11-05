import { hexToBn } from '@polkadot/util';
import { KeypairType } from '@polkadot/util-crypto/types';

import * as Cord from '@cord.network/sdk';

import { VerifiableCredential, IContents } from './types.js';

export function calculateVCHash(
    vc: VerifiableCredential,
    contentHashes: Cord.HexString[] | undefined,
): Cord.HexString {
    const { issuanceDate, validFrom, validUntil, issuer, credentialSubject } =
        vc;

    let newCredContent: IContents = {
        issuanceDate,
        validFrom,
        validUntil,
        issuer,
        credentialSubject,
    };
    if (contentHashes) {
        newCredContent = {
            issuanceDate,
            validFrom,
            validUntil,
            issuer,
            holder: credentialSubject.id,
            contentHashes,
        };
    }
    const serializedCred = Cord.Utils.Crypto.encodeObjectAsStr(newCredContent);
    const credHash = Cord.Utils.Crypto.hashStr(serializedCred);

    return credHash;
}

export function calculateNewVCHash(
    vc: VerifiableCredential,
    contentHashes: Cord.HexString[] | undefined,
): Cord.HexString {
    const { issuanceDate, expirationDate, issuer, credentialSubject, holder } =
        vc;

    let newCredContent: IContents = {
        issuanceDate,
        expirationDate,
        issuer,
        credentialSubject,
    };
    if (contentHashes) {
        newCredContent = {
            issuanceDate,
            expirationDate,
            issuer,
            holder: holder.id,
            contentHashes,
        };
    }
    const serializedCred = Cord.Utils.Crypto.encodeObjectAsStr(newCredContent);
    const credHash = Cord.Utils.Crypto.hashStr(serializedCred);
    return credHash;
}

function jsonLDcontents(
    contents: IContents,
    schemaId: string | undefined,
): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    const flattenedContents = Cord.Utils.DataUtils.flattenObject(
        contents || {},
    );
    const vocabulary = `${schemaId}#`;
    result['@context'] = { '@vocab': vocabulary };

    Object.entries(flattenedContents).forEach(([key, value]) => {
        result[vocabulary + key] = value;
    });

    return result;
}

export function toJsonLD(
    contents: IContents,
    schemaId: string,
): Record<string, unknown> {
    const credentialSubject = jsonLDcontents(contents, schemaId);
    return credentialSubject;
}

export function makeStatementsJsonLD(
    contents: IContents,
    schemaId: string | undefined,
): string[] {
    const normalized = jsonLDcontents(contents, undefined);
    return Object.entries(normalized).map(([key, value]) =>
        JSON.stringify({ [key]: value }),
    );
}

export function hashContents(
    contents: IContents,
    schemaId: string | undefined,
    options: Cord.Utils.Crypto.HashingOptions & {
        selectedAttributes?: string[];
    } = {},
): {
    hashes: Cord.HexString[];
    nonceMap: Record<string, string>;
} {
    // use canonicalisation algorithm to make hashable statement strings
    const statements = makeStatementsJsonLD(contents, schemaId);

    let filteredStatements = statements;
    if (options.selectedAttributes && options.selectedAttributes.length) {
        filteredStatements = Cord.Utils.DataUtils.filterStatements(
            statements,
            options.selectedAttributes,
        );
    }

    // iterate over statements to produce salted hashes
    const processed = Cord.Utils.Crypto.hashStatements(
        filteredStatements,
        options,
    );

    // produce array of salted hashes to add to credential
    const hashes = processed
        .map(({ saltedHash }) => saltedHash)
        .sort((a, b) => hexToBn(a).cmp(hexToBn(b)));

    // produce nonce map, where each nonce is keyed with the unsalted hash
    const nonceMap: Record<string, string> = {};
    processed.forEach(({ digest, nonce, statement }) => {
        // throw if we can't map a digest to a nonce - this should not happen if the nonce map is complete and the credential has not been tampered with
        if (!nonce)
            throw new Cord.Utils.SDKErrors.ContentNonceMapMalformedError(
                statement,
            );
        nonceMap[digest] = nonce;
    }, {});
    return { hashes, nonceMap };
}

/**
 * `createAccount` creates a new account from a mnemonic
 * @param mnemonic - The mnemonic phrase to use to generate the account. If not provided, a new
 * mnemonic will be generated.
 * @returns An object with two properties: account and mnemonic.
 */
export function createAccount(
    mnemonic = Cord.Utils.Crypto.mnemonicGenerate(24),
    type: KeypairType = 'sr25519',
): {
    account: Cord.CordKeyringPair;
    mnemonic: string;
} {
    const keyring = new Cord.Utils.Keyring({
        ss58Format: 29,
        type,
    });
    return {
        account: keyring.addFromMnemonic(mnemonic) as Cord.CordKeyringPair,
        mnemonic,
    };
}
