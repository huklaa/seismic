import { describe, expect, test } from 'bun:test'

import {
  testAddressExplorerUrlBuildsCorrectUrl,
  testAddressExplorerUrlReturnsNullWithoutExplorer,
  testAddressExplorerUrlWithTab,
  testBlockExplorerUrlBuildsCorrectUrl,
  testBlockExplorerUrlWithTab,
  testGetExplorerUrlBuildsItemUrl,
  testGetExplorerUrlBuildsItemUrlWithTab,
  testGetExplorerUrlReturnsBaseUrlWithoutOptions,
  testGetExplorerUrlReturnsNullForChainWithoutExplorer,
  testGetExplorerUrlReturnsNullForUndefinedChain,
  testSanvilHasNoExplorer,
  testTokenExplorerUrlBuildsCorrectUrl,
  testTokenExplorerUrlWithTab,
  testTxExplorerUrlBuildsCorrectUrl,
  testTxExplorerUrlReturnsNullWithoutChain,
  testTxExplorerUrlWithTab,
} from '@sviem-tests/tests/explorerUrl.ts'
import {
  testSerializeMissingChainId,
  testSerializeMissingData,
  testSerializeMissingEncryptionNonce,
  testSerializeMissingEncryptionPubkey,
  testSerializeMissingExpiresAtBlock,
  testSerializeMissingGas,
  testSerializeMissingGasPrice,
  testSerializeMissingNonce,
  testSerializeMissingRecentBlockHash,
  testSerializeMissingTo,
  testSerializeValidTxDoesNotThrow,
} from '@sviem-tests/tests/seismicTxValidation.ts'
import {
  testComputeKeyHashDifferentKeysProduceDifferentHashes,
  testComputeKeyHashIsDeterministic,
  testComputeKeyHashMatchesKeccak256,
  testParseEncryptedDataRoundtrip,
  testParseEncryptedDataRoundtripLargeAmount,
  testParseEncryptedDataThrowsOnEmpty,
  testParseEncryptedDataThrowsOnEmptyString,
} from '@sviem-tests/tests/src20Crypto.ts'
import {
  testEmptyAuthorizationListHash,
  testTypedDataIncludesAuthorizationListHash,
} from '@sviem-tests/tests/typedDataUnit.ts'
import { AesGcmCrypto } from '@sviem/crypto/aes.ts'

describe('Explorer URL utilities', () => {
  test(
    'getExplorerUrl returns null for undefined chain',
    testGetExplorerUrlReturnsNullForUndefinedChain
  )
  test(
    'getExplorerUrl returns null for chain without explorer',
    testGetExplorerUrlReturnsNullForChainWithoutExplorer
  )
  test(
    'getExplorerUrl returns base URL without options',
    testGetExplorerUrlReturnsBaseUrlWithoutOptions
  )
  test('getExplorerUrl builds item URL', testGetExplorerUrlBuildsItemUrl)
  test(
    'getExplorerUrl builds item URL with tab',
    testGetExplorerUrlBuildsItemUrlWithTab
  )
  test('txExplorerUrl builds correct URL', testTxExplorerUrlBuildsCorrectUrl)
  test('txExplorerUrl appends tab param', testTxExplorerUrlWithTab)
  test(
    'txExplorerUrl returns null without chain',
    testTxExplorerUrlReturnsNullWithoutChain
  )
  test(
    'addressExplorerUrl builds correct URL',
    testAddressExplorerUrlBuildsCorrectUrl
  )
  test('addressExplorerUrl appends tab param', testAddressExplorerUrlWithTab)
  test(
    'addressExplorerUrl returns null without explorer',
    testAddressExplorerUrlReturnsNullWithoutExplorer
  )
  test(
    'blockExplorerUrl builds correct URL',
    testBlockExplorerUrlBuildsCorrectUrl
  )
  test('blockExplorerUrl appends tab param', testBlockExplorerUrlWithTab)
  test(
    'tokenExplorerUrl builds correct URL',
    testTokenExplorerUrlBuildsCorrectUrl
  )
  test('tokenExplorerUrl appends tab param', testTokenExplorerUrlWithTab)
  test('sanvil chain has no explorer', testSanvilHasNoExplorer)
})

describe('seismic tx field validation', () => {
  test('throws when chainId is missing', testSerializeMissingChainId)
  test('throws when nonce is missing', testSerializeMissingNonce)
  test('throws when gasPrice is missing', testSerializeMissingGasPrice)
  test('throws when gas is missing', testSerializeMissingGas)
  test('throws when to is missing', testSerializeMissingTo)
  test(
    'throws when encryptionPubkey is missing',
    testSerializeMissingEncryptionPubkey
  )
  test(
    'throws when encryptionNonce is missing',
    testSerializeMissingEncryptionNonce
  )
  test(
    'throws when recentBlockHash is missing',
    testSerializeMissingRecentBlockHash
  )
  test(
    'throws when expiresAtBlock is missing',
    testSerializeMissingExpiresAtBlock
  )
  test('throws when data is missing', testSerializeMissingData)
  test('valid tx does not throw', testSerializeValidTxDoesNotThrow)
})

describe('SRC20 parseEncryptedData', () => {
  test('throws on empty hex (0x)', testParseEncryptedDataThrowsOnEmpty)
  test('throws on empty string', testParseEncryptedDataThrowsOnEmptyString)
  test(
    'encrypt → pack → parse → decrypt roundtrip',
    testParseEncryptedDataRoundtrip
  )
  test(
    'roundtrip with large amount and different key',
    testParseEncryptedDataRoundtripLargeAmount
  )
})

describe('Directory computeKeyHash', () => {
  test('is deterministic', testComputeKeyHashIsDeterministic)
  test('matches keccak256', testComputeKeyHashMatchesKeccak256)
  test(
    'different keys produce different hashes',
    testComputeKeyHashDifferentKeysProduceDifferentHashes
  )
})

describe('Seismic EIP-712 typed data', () => {
  test('hashes an empty authorization list', testEmptyAuthorizationListHash)
  test(
    'includes authorizationListHash',
    testTypedDataIncludesAuthorizationListHash
  )
})

describe('AES-GCM numeric nonces', () => {
  const crypto = new AesGcmCrypto(
    '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
  )

  test('encodes the complete unsigned 96-bit field', () => {
    expect(crypto.createNonce(5n)).toBe('0x000000000000000000000005')
    expect(crypto.createNonce(2n ** 64n + 5n)).toBe(
      '0x000000010000000000000005'
    )
    expect(crypto.createNonce(2n ** 96n - 1n)).toBe(
      '0xffffffffffffffffffffffff'
    )
  })

  test('rejects values outside the unsigned 96-bit domain', () => {
    expect(() => crypto.createNonce(-1n)).toThrow(RangeError)
    expect(() => crypto.createNonce(2n ** 96n)).toThrow(RangeError)
    expect(() => crypto.createNonce(Number.MAX_SAFE_INTEGER + 1)).toThrow(
      RangeError
    )
  })
})
