# Copyright (c) 2020 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import unittest
from strutils import toHex

import twofish/csprng

suite "csprng":
  setup:
    var rnd: SecureRand
    initSecureRand(rnd)

  test "preview":
    for row in 1..12:
      for column in 1..3:
        stdout.write rnd.getNum().toHex(), " "

      stdout.write rnd.getNum().toHex(), "\p"
