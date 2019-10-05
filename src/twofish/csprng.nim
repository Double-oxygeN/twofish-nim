# Copyright (c) 2019 Double-oxygeN
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

## Cryptographically Secure Pseudo Random Number Generator

import streams
import twofish256

type
  SecureRand* = object
    ctr: Block
    key: Key
    buf: seq[uint32]

proc initSecureRand*(prng: var SecureRand) =
  const urandom = "/dev/urandom"
  var strm = openFileStream(urandom, fmRead, 16)
  discard strm.readData(addr prng.ctr[0], 16)
  discard strm.readData(addr prng.key[0], 32)
  close strm
  prng.buf = @[]

proc getNum*(prng: var SecureRand): uint32 =
  if prng.buf.len == 0:
    let randomBlock = encryptBlock(prng.ctr, prng.key)

    inc prng.ctr[3]
    prng.buf.add randomBlock

  result = pop prng.buf
