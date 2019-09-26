# Copyright (c) 2019 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import unittest

const keySize = 128

include twofish/private/core

func `==`[T: Nibble | GF69h | GF4Dh](x, y: T): bool =
  uint8(x) == uint8(y)

suite "nibble":
  test "split":
    for n in 0'u8..255'u8:
      let (a, b) = splitToNibbles(n)

      check (n div 16) == uint8(a)
      check (n mod 16) == uint8(b)

  test "merge":
    for a0 in 0'u8..15'u8:
      let a = Nibble(a0)

      for b0 in 0'u8..15'u8:
        let b = Nibble(b0)

        let n = mergeNibbles(a, b)

        check (n div 16) == a0
        check (n mod 16) == b0

  test "rotate-right":
    for x0 in 0'u8..15'u8:
      let x = Nibble(x0)

      check rotateRightBits(x, 0) == x

      check rotateRightBits(x, 1) ==
        (if (x0 and 1) == 0: Nibble(x0 shr 1) else: Nibble(0b1000'u8 or (x0 shr 1)))

      check rotateRightBits(x, 3) ==
        (if (x0 and 0b1000) == 0: Nibble((x0 shl 1) mod 16) else: Nibble((1'u8 or (x0 shl 1)) mod 16))

  test "nibbles":
    check [Nibble(0'u8)] == nibbles"0"
    check [Nibble(9'u8)] == nibbles"9"
    check [Nibble(10'u8)] == nibbles"A"
    check [Nibble(15'u8)] == nibbles"F"
    check [Nibble(10'u8)] == nibbles"a"
    check [Nibble(15'u8)] == nibbles"f"

    check [Nibble(4'u8), Nibble(13'u8)] == nibbles"4D"
    check [Nibble(4'u8), Nibble(13'u8)] == nibbles"4_D"
    check [Nibble(2'u8), Nibble(7'u8), Nibble(15'u8), Nibble(3'u8), Nibble(11'u8), Nibble(7'u8), Nibble(1'u8), Nibble(0'u8)] == nibbles"27F3_B710"

suite "Galois-field":
  test "GF(69h)":
    check [GF69h(1'u8)] == gf69s"01"
    check [GF69h(0x5B'u8)] == gf69s"5B"

    check [GF69h(1'u8), GF69h(0xEF'u8), GF69h(0x5B'u8), GF69h(0x5B'u8)] == gf69s"01EF5B5B"
    check [GF69h(1'u8), GF69h(0xEF'u8), GF69h(0x5B'u8), GF69h(0x5B'u8)] == gf69s"01_EF_5B_5B"

  test "GF(4Dh)":
    check [GF4Dh(2'u8)] == gf4Ds"02"
    check [GF4Dh(0xFC'u8)] == gf4Ds"FC"

    check [GF4Dh(1'u8), GF4Dh(0xA4'u8), GF4Dh(0x55'u8), GF4Dh(0x87'u8), GF4Dh(0x5A'u8), GF4Dh(0x58'u8), GF4Dh(0xDB'u8), GF4Dh(0x9E'u8)] == gf4Ds"01_A4_55_87_5A_58_DB_9E"

  test "multiplication on GF(69h)":
    check GF69h(0'u8) * GF69h(0'u8) == GF69h(0'u8)
    check GF69h(0'u8) * GF69h(0x42'u8) == GF69h(0'u8)
    check GF69h(0xF3'u8) * GF69h(0'u8) == GF69h(0'u8)

    for n in 2'u8..255'u8:
      check GF69h(1'u8) * GF69h(n) == GF69h(n)
      check GF69h(n) * GF69h(1'u8) == GF69h(n)

    check GF69h(0x10'u8) * GF69h(0x80'u8) == GF69h(0xF3'u8)
    check GF69h(0xCD'u8) * GF69h(0xD2'u8) == GF69h(0x18'u8)
    check GF69h(0xEF'u8) * GF69h(0xA5'u8) == GF69h(0x30'u8)

  test "multiplication on GF(4Dh)":
    check GF4Dh(0'u8) * GF4Dh(0'u8) == GF4Dh(0'u8)
    check GF4Dh(0'u8) * GF4Dh(0x42'u8) == GF4Dh(0'u8)
    check GF4Dh(0xF3'u8) * GF4Dh(0'u8) == GF4Dh(0'u8)

    for n in 2'u8..255'u8:
      check GF4Dh(1'u8) * GF4Dh(n) == GF4Dh(n)
      check GF4Dh(n) * GF4Dh(1'u8) == GF4Dh(n)

    check GF4Dh(0x10'u8) * GF4Dh(0x80'u8) == GF4Dh(0xF2'u8)

suite "permutation":
  test "q0":
    check q0(0x00'u8) == 0xA9'u8
    check q0(0xA9'u8) == 0x87'u8
    check q0(0x87'u8) == 0xD2'u8
    check q0(0x75'u8) == 0xCD'u8
    check q0(0xCD'u8) == 0x1F'u8
    check q0(0x3A'u8) == 0xA5'u8

  test "q1":
    check q1(0x00'u8) == 0x75'u8
    check q1(0x75'u8) == 0x3A'u8
    check q1(0x3A'u8) == 0x4C'u8
    check q1(0x87'u8) == 0xB3'u8
    check q1(0xA9'u8) == 0x23'u8
    check q1(0x23'u8) == 0x5B'u8
