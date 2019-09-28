# Copyright (c) 2019 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import unittest
import strutils

include twofish/twofish128

func `==`(a, b: Text): bool =
  seq[Byte](a) == seq[Byte](b)

suite "converter":
  setup:
    let table = [
      ("Hello, World!", Text(@[0x48'u8, 0x65'u8, 0x6C'u8, 0x6C'u8, 0x6F'u8, 0x2C'u8, 0x20'u8, 0x57'u8, 0x6F'u8, 0x72'u8, 0x6C'u8, 0x64'u8, 0x21'u8]), Text(@[0x48'u8, 0x65'u8, 0x6C'u8, 0x6C'u8, 0x6F'u8, 0x2C'u8, 0x20'u8, 0x57'u8, 0x6F'u8, 0x72'u8, 0x6C'u8, 0x64'u8, 0x21'u8, 0x03'u8, 0x03'u8, 0x03'u8])),
      ("", Text(@[]), Text(@[0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8, 0x10'u8])),
      ("The quick brown fox jumps over the lazy dog.", Text(@[0x54'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x71'u8, 0x75'u8, 0x69'u8, 0x63'u8, 0x6B'u8, 0x20'u8, 0x62'u8, 0x72'u8, 0x6F'u8, 0x77'u8, 0x6E'u8, 0x20'u8, 0x66'u8, 0x6F'u8, 0x78'u8, 0x20'u8, 0x6A'u8, 0x75'u8, 0x6D'u8, 0x70'u8, 0x73'u8, 0x20'u8, 0x6F'u8, 0x76'u8, 0x65'u8, 0x72'u8, 0x20'u8, 0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x6C'u8, 0x61'u8, 0x7A'u8, 0x79'u8, 0x20'u8, 0x64'u8, 0x6F'u8, 0x67'u8, 0x2E'u8]), Text(@[0x54'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x71'u8, 0x75'u8, 0x69'u8, 0x63'u8, 0x6B'u8, 0x20'u8, 0x62'u8, 0x72'u8, 0x6F'u8, 0x77'u8, 0x6E'u8, 0x20'u8, 0x66'u8, 0x6F'u8, 0x78'u8, 0x20'u8, 0x6A'u8, 0x75'u8, 0x6D'u8, 0x70'u8, 0x73'u8, 0x20'u8, 0x6F'u8, 0x76'u8, 0x65'u8, 0x72'u8, 0x20'u8, 0x74'u8, 0x68'u8, 0x65'u8, 0x20'u8, 0x6C'u8, 0x61'u8, 0x7A'u8, 0x79'u8, 0x20'u8, 0x64'u8, 0x6F'u8, 0x67'u8, 0x2E'u8, 0x04'u8, 0x04'u8, 0x04'u8, 0x04'u8]))
    ]

  test "toText":
    for (s, ans, _) in table:
      check toText(s) == ans

  test "toStr":
    for (s, txt, ptxt) in table:
      check $toText(s) == s

  test "addPadding":
    for (_, txt, ptxt) in table:
      check txt.addPadding() == ptxt

  test "removePadding":
    for (_, txt, ptxt) in table:
      check ptxt.removePadding() == txt

suite "cipher":
  setup:
    const
      testcases = [
        "Hello, World!",
        "",
        "The quick brown fox jumps over the lazy dog.",
        "[ same content ][ same content ][ same content ][ same content ]"
      ]
      key = [0xF0F1F2F3'u32, 0xF4F5F6F7'u32, 0xF8F9FAFB'u32, 0xFCFDFEFF'u32]
      iv {.used.} = [0x10111213'u32, 0x14151617'u32, 0x18191A1B'u32, 0x1C1D1E1F'u32]


  test "ECB encryption":
    for tc in testcases:
      let cipher = encryptECB(tc, key)
      echo cipher.toHex()
      check decryptECB(cipher, key) == toText(tc)

  test "CBC encryption":
    for tc in testcases:
      let cipher = encryptCBC(tc, key, iv)
      echo cipher.toHex()
      check decryptCBC(cipher, key, iv) == toText(tc)

  test "CFB encryption":
    for tc in testcases:
      let cipher = encryptCFB(tc, key, iv)
      echo cipher.toHex()
      check decryptCFB(cipher, key, iv) == toText(tc)

  test "OFB encryption":
    for tc in testcases:
      let cipher = encryptOFB(tc, key, iv)
      echo cipher.toHex()
      check decryptOFB(cipher, key, iv) == toText(tc)

  test "CTR encryption":
    const nonce: Nonce = [iv[0], iv[1], iv[2]]
    for tc in testcases:
      let cipher = encryptCTR(tc, key, nonce)
      echo cipher.toHex()
      check decryptCTR(cipher, key, nonce) == toText(tc)

  test "CCM encryption and verification":
    const nonce: Nonce = [iv[0], iv[1], iv[2]]
    for tc in testcases:
      let cipher = generateEncryptCCM(tc, key, nonce)
      echo cipher.toHex()

      let dvresult1 = decryptVerifyCCM(cipher, key, nonce)
      check dvresult1.isValid
      check dvresult1.plaintext == toText(tc)

      var glitched = cipher
      (seq[Byte](glitched))[3] = not (seq[Byte](glitched))[3]
      let dvresult2 = decryptVerifyCCM(glitched, key, nonce)
      check not dvresult2.isValid
