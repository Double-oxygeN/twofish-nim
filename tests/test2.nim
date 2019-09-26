# Copyright (c) 2019 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import unittest

import twofish/twofish192

suite "twofish-192":
  test "encryption":
    const
      cipherText1Ans = [0x781FA7EF'u32, 0x44BD6589'u32, 0x1760F853'u32, 0x0191C18F'u32]
      cipherText2Ans = [0x70B2B288'u32, 0x365E106B'u32, 0x6DBB46B4'u32, 0x881E1A73'u32]
      cipherText3Ans = [0xD669DA39'u32, 0xD59749BA'u32, 0x07DCB685'u32, 0xB241A33C'u32]
      zeroText = [0'u32, 0'u32, 0'u32, 0'u32]

      zeroKey = [0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32]
      nonZeroKey = [cipherText1Ans[0], cipherText1Ans[1], cipherText1Ans[2], cipherText1Ans[3], 0'u32, 0'u32]

    let
      cipherText1 = encryptText(zeroText, zeroKey)
      cipherText2 = encryptText(cipherText1Ans, key = zeroKey)
      cipherText3 = encryptText(cipherText2Ans, key = nonZeroKey)

    for i, ans in cipherText1Ans:
      check cipherText1[i] == ans

    for i, ans in cipherText2Ans:
      check cipherText2[i] == ans

    for i, ans in cipherText3Ans:
      check cipherText3[i] == ans

  test "decryption":
    const
      plainText1 = [0'u32, 0'u32, 0'u32, 0'u32]
      plainText2 = [0x5C9F589F'u32, 0x322C12F6'u32, 0x2FECBFB6'u32, 0x5AC3E82A'u32]
      plainText3 = [0x16DB91D4'u32, 0x9EC3B1E7'u32, 0x6B08CB86'u32, 0x19549F78'u32]
      plainText4 = [0x09989F01'u32, 0x851117DE'u32, 0xA3C3AA8F'u32, 0xC3FB20BA'u32]
      zeroKey = [0'u32, 0'u32, 0'u32, 0'u32, 0'u32, 0'u32]
      nonZeroKey = [plainText1[0], plainText1[1], plainText1[2], plainText1[3], 0'u32, 0'u32]

    let
      encDec1 = plainText1.encryptText(zeroKey).decryptText(zeroKey)
      encDec2 = plainText2.encryptText(zeroKey).decryptText(zeroKey)
      encDec3 = plainText3.encryptText(nonZeroKey).decryptText(nonZeroKey)
      encDec4 = plainText4.encryptText(nonZeroKey).decryptText(nonZeroKey)

    for i, p in plainText1:
      check encDec1[i] == p

    for i, p in plainText2:
      check encDec2[i] == p

    for i, p in plainText3:
      check encDec3[i] == p

    for i, p in plainText4:
      check encDec4[i] == p
