# Copyright (c) 2019 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import unittest

import twofish/twofish128

suite "twofish-128":
  test "encryption":
    const
      cipherBlock1Ans = [0x5C9F589F'u32, 0x322C12F6'u32, 0x2FECBFB6'u32, 0x5AC3E82A'u32]
      cipherBlock2Ans = [0x16DB91D4'u32, 0x9EC3B1E7'u32, 0x6B08CB86'u32, 0x19549F78'u32]
      cipherBlock3Ans = [0x09989F01'u32, 0x851117DE'u32, 0xA3C3AA8F'u32, 0xC3FB20BA'u32]
      zeroBlock = [0'u32, 0'u32, 0'u32, 0'u32]

    let
      cipherBlock1 = encryptBlock(zeroBlock, key = zeroBlock)
      cipherBlock2 = encryptBlock(cipherBlock1Ans, key = zeroBlock)
      cipherBlock3 = encryptBlock(cipherBlock2Ans, key = cipherBlock1Ans)

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

    let
      encDec1 = plainBlock1.encryptBlock(plainBlock1).decryptBlock(plainBlock1)
      encDec2 = plainBlock2.encryptBlock(plainBlock1).decryptBlock(plainBlock1)
      encDec3 = plainBlock3.encryptBlock(plainBlock2).decryptBlock(plainBlock2)
      encDec4 = plainBlock4.encryptBlock(plainBlock3).decryptBlock(plainBlock3)

    for i, p in plainBlock1:
      check encDec1[i] == p

    for i, p in plainBlock2:
      check encDec2[i] == p

    for i, p in plainBlock3:
      check encDec3[i] == p

    for i, p in plainBlock4:
      check encDec4[i] == p
