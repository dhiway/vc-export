/**
* Utils file for Registry Entry.
* These are the functions originally defined at Cord SDK Entry.
* Due to having issue with 'api' being unavailable at SDK level from VC-Export,
* Redeine the functions here to be used in VC-Export whichever uses api internally.
**/

import * as Cord from '@cord.network/sdk';

import { 
  EntryId,
  RegistryId,
  HexString,
  IRegistryEntryChainStorage,
  Option
} from "@cord.network/types";

import { DecoderUtils } from '@cord.network/utils';

import { PalletEntryRegistryEntryDetails } from "@cord.network/augment-api";

import { SDKErrors } from '@cord.network/utils';

/**
 * Verifies the input properties of a registry entry URI against its on-chain details.
 *
 * Ensures that the provided transaction hash, and optional creator URI and registry URI,
 * match the data stored on the blockchain. Also checks if the entry is revoked or if URIs mismatch.
 *
 * @param registryEntryId - The id of the entry to verify.
 * @param tx_hash - The expected transaction hash associated with the entry.
 * @param creatorAddress - Optional address of the entry’s creator profile id.
 * @param registryId - Optional id of the registry.
 * @returns A promise resolving to an object with `isValid` (boolean) and `message` (string) describing the verification result.
 * @throws {Error} If an unexpected error occurs during verification.
 *
 * @example
 * ```typescript
 * const result = await verifyAgainstInputProperties(
 *   '2Lwedabc123...',
 *   '0x1234abcd...',
 *   '2wed3xygo...',
 *   '3HJB3xygo...'
 * );
 * console.log('✅', result.isValid, result.message);
 * ```
 */
export async function verifyAgainstInputProperties2025(
  registryEntryId: EntryId,
  tx_hash: HexString,
  creator?: string,
  registryId?: RegistryId,
): Promise<{ isValid: boolean; message: string }> {
  try {
    const registryEntryStatus = await fetchRegistryEntryDetailsFromChain2025(registryEntryId);

    if (!registryEntryStatus) {
      return {
        isValid: false,
        message: `Registry Entry details for "${tx_hash}" not found.`,
      }
    }
    
    if (tx_hash !== registryEntryStatus.tx_hash) {
      return {
        isValid: false,
        message: 'Digest does not match with Registry Entry Digest.',
      }
    }

    if (registryEntryStatus?.revoked) {
      return {
        isValid: false,
        message: `Registry Entry "${registryEntryId}" Revoked.`,
      }
    }

    if (registryEntryId !== registryEntryStatus.registryEntryId) {
      return {
        isValid: false,
        message: 'Registry Entry and Chain Entry URI details does not match.',
      }
    }

    if (creator) {
      if (creator !== registryEntryStatus.creator) {
        return {
          isValid: false,
          message: 'Registry Entry and Digest creator does not match.',
        }
      }
    }

    if (registryId) {
      if (registryId !== registryEntryStatus.registryId) {
        return {
          isValid: false,
          message: 'Registry URI and Chain Registry URI does not match.',
        }
      }
    }

    return {
      isValid: true,
      message:
        'Digest properties provided are valid and matches the registry entry details.',
    }
  } catch (error) {
    if (error instanceof Error) {
      return {
        isValid: false,
        message: `Error verifying properties: ${error}`,
      }
    }
    return {
      isValid: false,
      message: 'An unknown error occurred while verifying the properties.',
    }
  }
}


/**
 * Decodes the registry entry details from the blockchain state.
 *
 * Takes an optional encoded entry and an identifier, then extracts and formats the relevant properties
 * into a structured object containing the entry’s URI, transaction hash, revocation status, creator,
 * and registry URI.
 *
 * @param encoded - The optional encoded data from the blockchain, containing entry details or `None`.
 * @param registryEntryId - The identifier used to generate the entry’s id
 * @returns The decoded entry details as `IRegistryEntryChainStorage`, or `null` if `encoded` is `None`.
 *
 * @example
 * ```typescript
 * const encoded = await api.query.entry.registryEntries('abc123');
 * const details = decodeRegistryEntryDetailsFromChain(encoded, 'abc123');
 * console.log(details); // { uri: 'entry:cord:abc123...', tx_hash: '0x...', ... }
 * ```
 */
export function decodeRegistryEntryDetailsFromChain2025(
  encoded: Option<PalletEntryRegistryEntryDetails>,
  registryEntryId: string
): IRegistryEntryChainStorage | null {
  if (encoded.isNone) {
    return null; 
  }

  const chainRegistryEntry = encoded.unwrap(); 
  const registryId = DecoderUtils.hexToString(chainRegistryEntry.registryId.toString());

  /* 
   * Below code block encodes the data from the chain present in raw
   * to its respective formats.
   */
  const registryEntry: IRegistryEntryChainStorage = {
    registryEntryId: registryEntryId,
    tx_hash: chainRegistryEntry.txHash.toHex(),
    revoked: chainRegistryEntry.revoked.valueOf(),
    creator: chainRegistryEntry.creator.toHuman() as string,
    registryId: registryId
  };

  return registryEntry;
}


/**
 * Retrieves the details of a registry entry from the blockchain using the provided identifier.
 *
 * Queries the blockchain for the registry entry associated with the specified identifier and decodes
 * the details into a structured format.
 *
 * @param registryEntryId - The identifier used to query the entry (without `entry:cord:` prefix).
 * @returns A promise resolving to the decoded entry details as `IRegistryEntryChainStorage`, or `null` if not found.
 * @throws {SDKErrors.CordFetchError} If no entry exists for the provided identifier.
 *
 * @example
 * ```typescript
 * const details = await getDetailsfromChain('abc123');
 * console.log(details); // { uri: 'entry:cord:abc123...', tx_hash: '0x...', ... }
 * ```
 */
export async function getDetailsfromChain2025(
  registryEntryId: string
): Promise<IRegistryEntryChainStorage | null> {
  const api = Cord.ConfigService.get('api');

  const registryEntry = await api.query.entry.registryEntries(registryEntryId);

  const decodedDetails = decodeRegistryEntryDetailsFromChain2025(registryEntry, registryEntryId);

  if (!decodedDetails) {
    throw new SDKErrors.CordFetchError(
      `There is no registry entry with the provided ID "${registryEntryId}" present on the chain.`
    );
  }

  return decodedDetails;
}


/**
 * Fetches the registry entry details from the blockchain using the specified entry URI.
 *
 * Converts the entry URI into its corresponding identifier, retrieves the details from the blockchain,
 * and returns them in a structured format.
 *
 * @param registryEntryId - The id of the entry to fetch
 * @returns A promise resolving to the decoded entry details as `IRegistryEntryChainStorage`.
 * @throws {SDKErrors.CordFetchError} If no entry exists for the provided URI.
 *
 */
export async function fetchRegistryEntryDetailsFromChain2025(
  registryEntryId: EntryId
): Promise<IRegistryEntryChainStorage> {
  const entryDetails = await getDetailsfromChain2025(registryEntryId);

  if (!entryDetails) {
    throw new SDKErrors.CordFetchError(
      `There is no registry entry with the provided ID "${registryEntryId}" present on the chain.`
    );
  }

  return entryDetails;
}