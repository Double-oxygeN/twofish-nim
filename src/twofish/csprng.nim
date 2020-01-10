# Copyright (c) 2019 Double-oxygeN
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

## Cryptographically Secure Pseudo Random Number Generator

import streams
import twofish256

when defined(windows):
  {.emit: "/*INCLUDESECTION*/\p#define _CRT_RAND_S".}

  proc randSecure(randomValue: ptr cuint): cint {.importc: "rand_s", cdecl, header: "<stdlib.h>".}

type
  SecureRand* = object
    ctr: Block
    key: Key
    buf: seq[uint32]

proc initSecureRand*(prng: var SecureRand) =
  when defined(windows):
    for ctrWord in prng.ctr.mitems:
      if randSecure(addr ctrWord) != 0:
        stderr.writeLine "Something is wrong with rand_s() function!"

    for keyWord in prng.key.mitems:
      if randSecure(addr keyWord) != 0:
        stderr.writeLine "Something is wrong with rand_s() function!"

  else:
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
