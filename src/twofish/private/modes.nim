# Copyright (c) 2019 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import ropes
from strutils import toHex

# [for debug]
# const keySize = 128
# include core

type
  Text* = distinct seq[Byte]
  Nonce* = array[0..2, Word]
  ResultVerify* = object
    case isValid*: bool
    of true:
      plaintext*: Text
    of false:
      nil


func add(txt: var Text; b: Byte) = seq[Byte](txt).add(b)
func `[]`*(txt: Text; idx: Natural): Byte = seq[Byte](txt)[idx]
func `[]`*(txt: Text; idx: BackwardsIndex): Byte = seq[Byte](txt)[idx]
func len*(txt: Text): Natural = len(seq[Byte](txt))
func low*(txt: Text): Natural = low(seq[Byte](txt))
func high*(txt: Text): Natural = high(seq[Byte](txt))


func add(txt: var Text; blck: Block) =
  for w in blck:
    for i in 0..3:
      txt.add Byte(w shr (i shl 3) and 0xff)


iterator items*(txt: Text): Byte =
  if len(txt) > 0:
    for i in 0..high(txt):
      yield txt[i]


iterator pairs*(txt: Text): tuple[key: Natural, val: Byte] =
  if len(txt) > 0:
    for i in 0..high(txt):
      yield (Natural(i), txt[i])


iterator blocks*(txt: Text): Block =
  assert len(txt) mod 16 == 0
  var
    i = 0
    blck: Block
  while i < len(txt):
    for j in 0..3:
      blck[j] = uint32(txt[i + j shl 2]) or (uint32(txt[i + j shl 2 + 1]) shl 8) or (uint32(txt[i + j shl 2 + 2]) shl 16) or (uint32(txt[i + j shl 2 + 3]) shl 24)

    yield blck
    inc i, 16


func toText(str: string): Text =
  for c in str:
    result.add(Byte(c))


proc `$`*(txt: Text): string =
  var r: Rope

  for b in txt:
    r.add($chr(b))

  result = $r


proc toHex*(txt: Text): string =
  var r: Rope

  for idx, b in txt:
    r.add(toHex(b))
    if idx mod 16 == 15: r.add(" ")

  result = $r


proc addPadding(txt: Text): Text =
  # Add PKCS#7-style padding.
  let
    strLen = len(txt)
    paddingLen = 16 - strLen mod 16

  result = txt
  for i in 1..paddingLen:
    result.add Byte(paddingLen)


proc removePadding(txt: Text): Text =
  let paddingLen = int(txt[^1])

  result = txt
  setLen(seq[Byte](result), len(txt) - paddingLen)

proc `xor`(a, b: Block): Block =
  for i in 0..3:
    result[i] = a[i] xor b[i]


# Various modes

# ECB (Electronic CodeBook) mode

proc encryptECB*(txt: Text; key: Key): Text =
  let ptext = txt.addPadding()
  for blck in blocks(ptext):
    let cipherBlock = encryptBlock(blck, key)
    result.add cipherBlock

proc encryptECB*(plaintext: string; key: Key): Text =
  encryptECB(toText(plaintext), key)

proc decryptECB*(cipher: Text; key: Key): Text =
  for blck in blocks(cipher):
    let plainBlock = decryptBlock(blck, key)
    result.add plainBlock

  result = removePadding(result)

# CBC (Cipher Block Chaining) mode

proc encryptCBC*(txt: Text; key: Key; iv: Block): Text =
  let ptext = addPadding(txt)
  var prevBlock = iv
  for blck in blocks(ptext):
    let cipherBlock = encryptBlock(blck xor prevBlock, key)
    result.add cipherBlock
    prevBlock = cipherBlock

proc encryptCBC*(plaintext: string; key: Key; iv: Block): Text =
  encryptCBC(toText(plaintext), key, iv)

proc decryptCBC*(cipher: Text; key: Key; iv: Block): Text =
  var prevBlock = iv
  for blck in blocks(cipher):
    let plainBlock = decryptBlock(blck, key) xor prevBlock
    result.add plainBlock
    prevBlock = blck

  result = removePadding(result)

# CFB (Cipher FeedBack) mode

proc encryptCFB*(txt: Text; key: Key; iv: Block): Text =
  let ptext = addPadding(txt)
  var prevBlock = iv
  for blck in blocks(ptext):
    let cipherBlock = encryptBlock(prevBlock, key) xor blck
    result.add cipherBlock
    prevBlock = cipherBlock

  setLen(seq[Byte](result), len(txt))

proc encryptCFB*(plaintext: string; key: Key; iv: Block): Text =
  encryptCFB(toText(plaintext), key, iv)

proc decryptCFB*(cipher: Text; key: Key; iv: Block): Text =
  let ptext = addPadding(cipher)
  var prevBlock = iv
  for blck in blocks(ptext):
    let cipherBlock = encryptBlock(prevBlock, key) xor blck
    result.add cipherBlock
    prevBlock = blck

  setLen(seq[Byte](result), len(cipher))

# OFB (Output FeedBack) mode

proc encryptOFB*(txt: Text; key: Key; iv: Block): Text =
  let ptext = addPadding(txt)
  var keyStream = iv
  for blck in blocks(ptext):
    keyStream = encryptBlock(keyStream, key)
    let cipherBlock = blck xor keyStream
    result.add cipherBlock

  setLen(seq[Byte](result), len(txt))

proc encryptOFB*(plaintext: string; key: Key; iv: Block): Text =
  encryptOFB(toText(plaintext), key, iv)

proc decryptOFB*(cipher: Text; key: Key; iv: Block): Text =
  encryptOFB(cipher, key, iv)

# CTR (CounTeR) mode

proc encryptCTR*(txt: Text; key: Key; nonce: Nonce; offset = 0'u32): Text =
  let ptext = addPadding(txt)
  var ctr = [nonce[0], nonce[1], nonce[2], offset]
  for blck in blocks(ptext):
    let
      keyStream = encryptBlock(ctr, key)
      cipherBlock = blck xor keyStream
    result.add cipherBlock

    inc(ctr[3])

  setLen(seq[Byte](result), len(txt))

proc encryptCTR*(plaintext: string; key: Key; nonce: Nonce; offset = 0'u32): Text =
  encryptCTR(toText(plaintext), key, nonce, offset)

proc decryptCTR*(cipher: Text; key: Key; nonce: Nonce; offset = 0'u32): Text =
  encryptCTR(cipher, key, nonce, offset)

# CCM (Conter with CBC-MAC) mode

proc generateEncryptCCM*(txt: Text; key: Key; nonce: Nonce): Text =
  let
    txtLen = len(txt)
    b0 = @[
      0b00110010'u8,
      uint8(nonce[0] and 0xff), uint8((nonce[0] shr 8) and 0xff), uint8((nonce[0] shr 16) and 0xff), uint8((nonce[0] shr 24) and 0xff),
      uint8(nonce[1] and 0xff), uint8((nonce[1] shr 8) and 0xff), uint8((nonce[1] shr 16) and 0xff), uint8((nonce[1] shr 24) and 0xff),
      uint8(nonce[2] and 0xff), uint8((nonce[2] shr 8) and 0xff), uint8((nonce[2] shr 16) and 0xff), uint8((nonce[2] shr 24) and 0xff),
      uint8(txtLen and 0xff), uint8((txtLen shr 8) and 0xff), uint8((txtLen shr 16) and 0xff)
    ]
    b = Text(b0 & seq[Byte](txt))

    cipher = encryptCTR(txt, key, nonce, 0x1'u32)
    cipherCBCRaw = seq[Byte](encryptCBC(b, key, [0'u32, 0'u32, 0'u32, 0'u32]))
    cipherCBCLastBlock = [
      (uint32(cipherCBCRaw[^16]) or uint32(cipherCBCRaw[^15]) shl 8 or uint32(cipherCBCRaw[^14]) shl 16 or uint32(cipherCBCRaw[^13]) shl 24),
      (uint32(cipherCBCRaw[^12]) or uint32(cipherCBCRaw[^11]) shl 8 or uint32(cipherCBCRaw[^10]) shl 16 or uint32(cipherCBCRaw[^9]) shl 24),
      (uint32(cipherCBCRaw[^8]) or uint32(cipherCBCRaw[^7]) shl 8 or uint32(cipherCBCRaw[^6]) shl 16 or uint32(cipherCBCRaw[^5]) shl 24),
      (uint32(cipherCBCRaw[^4]) or uint32(cipherCBCRaw[^3]) shl 8 or uint32(cipherCBCRaw[^2]) shl 16 or uint32(cipherCBCRaw[^1]) shl 24)
    ]
    mac = [nonce[0], nonce[1], nonce[2], 0'u32] xor cipherCBCLastBlock

  result = cipher
  result.add mac

proc generateEncryptCCM*(plaintext: string; key: Key; nonce: Nonce): Text =
  generateEncryptCCM(toText(plaintext), key, nonce)

proc decryptVerifyCCM*(cipher: Text; key: Key; nonce: Nonce): ResultVerify =
  let
    cipherLen = len(cipher)
    txtLen = cipherLen - 16
  if txtLen < 0:
    return ResultVerify(isValid: false)

  let
    cipherPart = Text(seq[Byte](cipher)[0..<cipherLen - 16])
    macPartRaw = seq[Byte](cipher)[cipherLen - 16..cipherLen - 1]
    plaintext = decryptCTR(cipherPart, key, nonce, 1'u32)
    mac0 = [
      (uint32(macPartRaw[0]) or uint32(macPartRaw[1]) shl 8 or uint32(macPartRaw[2]) shl 16 or uint32(macPartRaw[3]) shl 24),
      (uint32(macPartRaw[4]) or uint32(macPartRaw[5]) shl 8 or uint32(macPartRaw[6]) shl 16 or uint32(macPartRaw[7]) shl 24),
      (uint32(macPartRaw[8]) or uint32(macPartRaw[9]) shl 8 or uint32(macPartRaw[10]) shl 16 or uint32(macPartRaw[11]) shl 24),
      (uint32(macPartRaw[12]) or uint32(macPartRaw[13]) shl 8 or uint32(macPartRaw[14]) shl 16 or uint32(macPartRaw[15]) shl 24),
    ]
    t = [nonce[0], nonce[1], nonce[2], 0'u32] xor mac0

  let
    b0 = @[
      0b00110010'u8,
      uint8(nonce[0] and 0xff), uint8((nonce[0] shr 8) and 0xff), uint8((nonce[0] shr 16) and 0xff), uint8((nonce[0] shr 24) and 0xff),
      uint8(nonce[1] and 0xff), uint8((nonce[1] shr 8) and 0xff), uint8((nonce[1] shr 16) and 0xff), uint8((nonce[1] shr 24) and 0xff),
      uint8(nonce[2] and 0xff), uint8((nonce[2] shr 8) and 0xff), uint8((nonce[2] shr 16) and 0xff), uint8((nonce[2] shr 24) and 0xff),
      uint8(txtLen and 0xff), uint8((txtLen shr 8) and 0xff), uint8((txtLen shr 16) and 0xff)
    ]
    b = Text(b0 & seq[Byte](plaintext))
    cipherCBCRaw = seq[Byte](encryptCBC(b, key, [0'u32, 0'u32, 0'u32, 0'u32]))
    cipherCBCLastBlock = [
      (uint32(cipherCBCRaw[^16]) or uint32(cipherCBCRaw[^15]) shl 8 or uint32(cipherCBCRaw[^14]) shl 16 or uint32(cipherCBCRaw[^13]) shl 24),
      (uint32(cipherCBCRaw[^12]) or uint32(cipherCBCRaw[^11]) shl 8 or uint32(cipherCBCRaw[^10]) shl 16 or uint32(cipherCBCRaw[^9]) shl 24),
      (uint32(cipherCBCRaw[^8]) or uint32(cipherCBCRaw[^7]) shl 8 or uint32(cipherCBCRaw[^6]) shl 16 or uint32(cipherCBCRaw[^5]) shl 24),
      (uint32(cipherCBCRaw[^4]) or uint32(cipherCBCRaw[^3]) shl 8 or uint32(cipherCBCRaw[^2]) shl 16 or uint32(cipherCBCRaw[^1]) shl 24)
    ]

  if t != cipherCBCLastBlock:
    return ResultVerify(isValid: false)

  result = ResultVerify(isValid: true, plaintext: plaintext)
