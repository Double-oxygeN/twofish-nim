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

proc encryptCTR*(txt: Text; key: Key; nonce: Block): Text =
  let ptext = addPadding(txt)
  var ctr = nonce
  for blck in blocks(ptext):
    let
      keyStream = encryptBlock(ctr, key)
      cipherBlock = blck xor keyStream
    result.add cipherBlock

    inc(ctr[3])

  setLen(seq[Byte](result), len(txt))

proc encryptCTR*(plaintext: string; key: Key; nonce: Block): Text =
  encryptCTR(toText(plaintext), key, nonce)

proc decryptCTR*(cipher: Text; key: Key; nonce: Block): Text =
  encryptCTR(cipher, key, nonce)
