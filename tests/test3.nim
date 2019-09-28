# Copyright (c) 2019 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import unittest

import twofish/twofish256

suite "twofish-256":
  test "encryption":
    const
      cipherBlock1Ans = [0x9D73FF57'u32, 0x1B2CC94D'u32, 0x7001FCD7'u32, 0x6F21C80C'u32]
      cipherBlock2Ans = [0x55B73BD4'u32, 0x462EA36E'u32, 0xB782A2F2'u32, 0x0D4E5BD4'u32]
      cipherBlock3Ans = [0x1BE9AF90'u32, 0x4F5488B2'u32, 0x23DC322C'u32, 0xE635269B'u32]
      zeroBlock = [0'u32, 0'u32, 0'u32, 0'u32]

      zeroKey = [0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32]
      nonZeroKey = [cipherBlock1Ans[0], cipherBlock1Ans[1], cipherBlock1Ans[2], cipherBlock1Ans[3], 0'u32, 0'u32, 0'u32, 0'u32]

    let
      cipherBlock1 = encryptBlock(zeroBlock, zeroKey)
      cipherBlock2 = encryptBlock(cipherBlock1Ans, key = zeroKey)
      cipherBlock3 = encryptBlock(cipherBlock2Ans, key = nonZeroKey)

    for i, ans in cipherBlock1Ans:
      check cipherBlock1[i] == ans

    for i, ans in cipherBlock2Ans:
      check cipherBlock2[i] == ans

    for i, ans in cipherBlock3Ans:
      check cipherBlock3[i] == ans

  test "decryption":
    const
      plainBlock1 = [0'u32, 0'u32, 0'u32, 0'u32]
      plainBlock2 = [0x5C9F589F'u32, 0x322C12F6'u32, 0x2FECBFB6'u32, 0x5AC3E82A'u32]
      plainBlock3 = [0x16DB91D4'u32, 0x9EC3B1E7'u32, 0x6B08CB86'u32, 0x19549F78'u32]
      plainBlock4 = [0x09989F01'u32, 0x851117DE'u32, 0xA3C3AA8F'u32, 0xC3FB20BA'u32]
      zeroKey = [0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32]
      nonZeroKey = [plainBlock1[0], plainBlock1[1], plainBlock1[2], plainBlock1[3], 0'u32, 0'u32, 0'u32, 0'u32]

    let
      encDec1 = plainBlock1.encryptBlock(zeroKey).decryptBlock(zeroKey)
      encDec2 = plainBlock2.encryptBlock(zeroKey).decryptBlock(zeroKey)
      encDec3 = plainBlock3.encryptBlock(nonZeroKey).decryptBlock(nonZeroKey)
      encDec4 = plainBlock4.encryptBlock(nonZeroKey).decryptBlock(nonZeroKey)

    for i, p in plainBlock1:
      check encDec1[i] == p

    for i, p in plainBlock2:
      check encDec2[i] == p

    for i, p in plainBlock3:
      check encDec3[i] == p

    for i, p in plainBlock4:
      check encDec4[i] == p
