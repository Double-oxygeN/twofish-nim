# Copyright (c) 2019 double-oxygen
# 
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

import bitops, macros
from strutils import fromHex, HexDigits


const
  k = keySize div 64


type
  Nibble = distinct range[0x0'u8..0xf'u8]
  Byte = byte
  Word* = uint32
  Block* = array[0..3, Word]
  Key* = array[0..2 * k - 1, Word]
  ExKey = Word
  SBox = Word
  RoundCount = range[0..15]

  GF69h = distinct Byte
  GF4Dh = distinct Byte
  GF = GF69h | GF4Dh


# operators for nibbles (4-bit data)

func splitToNibbles(x: Byte): tuple[a, b: Nibble] =
  (Nibble(x shr 4), Nibble(x and 0xf'u8))


func mergeNibbles(x, y: Nibble): Byte =
  (uint8(x) shl 4) or uint8(y)


func `xor`(x, y: Nibble): Nibble =
  Nibble(uint8(x) xor uint8(y))


func `shl`(value: Nibble; amount: range[0..3]): Nibble =
  Nibble((uint8(value) shl amount) and 0xf'u8)


func rotateRightBits(value: Nibble; amount: range[0..3]): Nibble =
  Nibble(((uint8(value) shr amount) or (uint8(value) shl ((- amount) and 3))) and 0xf'u8)


macro nibbles(lit: string): untyped =
  result = nnkBracket.newTree()

  for c in $lit:
    case c
    of '0'..'9': result.add(newCall("Nibble", newIntLitNode(int(c) - int('0'))))
    of 'a'..'f': result.add(newCall("Nibble", newIntLitNode(int(c) - int('a') + 10)))
    of 'A'..'F': result.add(newCall("Nibble", newIntLitNode(int(c) - int('A') + 10)))
    of '_': discard
    else: error("Unexpected character '" & c & "' is detected.\pOnly hexadecimal digit characters or underscores are supported.", lit)


# permutations

template q(n: untyped; ts: array[0..3, array[0x0'u8..0xf'u8, Nibble]]): untyped =
  func `q n`(x: Byte): Byte =
    let
      (a0, b0) = splitToNibbles(x)
      (a1, b1) = (a0 xor b0, a0 xor rotateRightBits(b0, 1) xor (a0 shl 3))
      (a2, b2) = (ts[0][uint8(a1)], ts[1][uint8(b1)])
      (a3, b3) = (a2 xor b2, a2 xor rotateRightBits(b2, 1) xor (a2 shl 3))
      (a4, b4) = (ts[2][uint8(a3)], ts[3][uint8(b3)])
    result = mergeNibbles(b4, a4)


q(0, [nibbles"817D_6F32_0B59_ECA4", nibbles"ECB8_1235_F4A6_709D", nibbles"BA5E_6D90_C8F3_2471", nibbles"D7F4_126E_9B30_85CA"])
q(1, [nibbles"28BD_F76E_3194_0AC5", nibbles"1E2B_4C37_6DA5_F908", nibbles"4C75_169A_0ED8_2B3F", nibbles"B951_C3DE_647F_208A"])


# Galois Field

template gfs(id: untyped; ty: typedesc): untyped =
  const tyStr = $ty
  macro id(lit: string): untyped =
    result = nnkBracket.newTree()
    let litStr = $lit

    var ctr: Natural = 0
    while ctr < len(litStr):
      let c = litStr[ctr]

      if c in HexDigits:
        if ctr == high(litStr):
          error("Unexpected End-Of-String is found.", lit)

        if litStr[ctr + 1] notin HexDigits:
          error("Unexpected characted '" & litStr[ctr + 1] & "' is found.", lit)

        result.add(newCall(tyStr, newIntLitNode(fromHex[int](c & litStr[ctr+1]))))

        inc ctr, 2

      elif c == '_':
        inc ctr

      else:
        error("Unexpected character '" & c & "' is found.", lit)


gfs(gf69s, GF69h)
gfs(gf4Ds, GF4Dh)


func makeGFLookUpTable(polynomial: Byte): tuple[v2p, p2v: array[0'u8..255'u8, Byte]] =
  result.p2v[0x00'u8] = 0x01'u8
  result.v2p[0x01'u8] = 0x00'u8

  for n in 0x01'u8..0xFF'u8:
    let predVec = result.p2v[pred(n)]
    result.p2v[n] = (predVec shl 1) xor (if (predVec and 0x80'u8) == 0'u8: 0'u8 else: polynomial)

    if n != high(uint8): result.v2p[result.p2v[n]] = n


const
  mds: array[0..3, array[0..3, GF69h]] = [
    gf69s"01_EF_5B_5B",
    gf69s"5B_EF_EF_01",
    gf69s"EF_5B_01_EF",
    gf69s"EF_01_EF_5B"
  ]

  rs: array[0..3, array[0..7, GF4Dh]] = [
    gf4Ds"01_A4_55_87_5A_58_DB_9E",
    gf4Ds"A4_56_82_F3_1E_C6_68_E5",
    gf4Ds"02_A1_FC_C1_47_AE_3D_19",
    gf4Ds"A4_55_87_5A_58_DB_9E_03"
  ]


func `+`[T: GF](x, y: T): T =
  T(uint8(x) xor uint8(y))


func `*`(x, y: GF69h): GF69h =
  const (v2p, p2v) = makeGFLookUpTable(0x69'u8)

  if Word(x) * Word(y) == 0'u8: GF69h(0'u8)
  else:
    let
      ab = uint16(v2p[uint8(x)]) + uint16(v2p[uint8(y)])
      c = uint8(ab shr 8) + uint8(ab and 0xff)
    GF69h(p2v[c])


func `*`(x, y: GF4Dh): GF4Dh =
  const (v2p, p2v) = makeGFLookUpTable(0x4D'u8)

  if Word(x) * Word(y) == 0'u8: GF4Dh(0'u8)
  else:
    let
      ab = uint16(v2p[uint8(x)]) + uint16(v2p[uint8(y)])
      c = uint8(ab shr 8) + uint8(ab and 0xff)
    GF4Dh(p2v[c])


# the function h

func splitToBytes(w: Word): array[0..3, Byte] =
  result[0] = uint8( w         and 0xff)
  result[1] = uint8((w shr 8)  and 0xff)
  result[2] = uint8((w shr 16) and 0xff)
  result[3] = uint8((w shr 24) and 0xff)


func mergeBytes(x1, x2, x3, x4: Byte): Word =
  (Word(x1) shl 24) or (Word(x2) shl 16) or (Word(x3) shl 8) or Word(x4)


func h(x: Word; ls: array[0..k - 1, Word]): Word =
  var
    ys: array[0..k, array[0..3, Byte]]
    lss: array[0..k - 1, array[0..3, Byte]]

  ys[k] = splitToBytes(x)

  for i in 0..<k:
    lss[i] = splitToBytes(ls[i])

  when k == 4:
    ys[3][0] = q1(ys[4][0]) xor lss[3][0]
    ys[3][1] = q0(ys[4][1]) xor lss[3][1]
    ys[3][2] = q0(ys[4][2]) xor lss[3][2]
    ys[3][3] = q1(ys[4][3]) xor lss[3][3]

  when k >= 3:
    ys[2][0] = q1(ys[3][0]) xor lss[2][0]
    ys[2][1] = q1(ys[3][1]) xor lss[2][1]
    ys[2][2] = q0(ys[3][2]) xor lss[2][2]
    ys[2][3] = q0(ys[3][3]) xor lss[2][3]

  ys[1][0] = q1(q0(q0(ys[2][0]) xor lss[1][0]) xor lss[0][0])
  ys[1][1] = q0(q0(q1(ys[2][1]) xor lss[1][1]) xor lss[0][1])
  ys[1][2] = q1(q1(q0(ys[2][2]) xor lss[1][2]) xor lss[0][2])
  ys[1][3] = q0(q1(q1(ys[2][3]) xor lss[1][3]) xor lss[0][3])

  for i in 0..3:
    # GF(2^8) with generating polynomial x^8 + x^6 + x^5 + x^3 + 1.
    ys[0][i] = Byte(mds[i][0] * GF69h(ys[1][0]) + mds[i][1] * GF69h(ys[1][1]) + mds[i][2] * GF69h(ys[1][2]) + mds[i][3] * GF69h(ys[1][3]))

  result = mergeBytes(ys[0][3], ys[0][2], ys[0][1], ys[0][0])


# the function g

template g(x: Word; sBoxes: array[0..k - 1, SBox]): Word = h(x, sBoxes)


# the function F

func f(r0, r1: Word; r: RoundCount; exKeys: array[0..39, ExKey]; sBoxes: array[0..k - 1, SBox]): tuple[f0, f1: Word] =
  let
    t0 = g(r0, sBoxes)
    t1 = g(rotateLeftBits(r1, 8), sBoxes)

  result = (f0: t0 + t1 + exKeys[2 * r + 8], f1: t0 + (t1 shl 1) + exKeys[2 * r + 9])


const
  rho: Word = 0x01_01_01_01'u32


func whitening(blck: Block; keys: array[0..3, ExKey]): Block =
  for i in 0..3:
    result[i] = blck[i] xor keys[i]


func divideKey(key: Key): tuple[keyEven, keyOdd: array[0..k - 1, Word]] =
  for idx, k in key:
    if (idx and 1) == 0:
      result.keyEven[idx div 2] = k

    else:
      result.keyOdd[idx div 2] = k


func makeExKeys(key: Key): array[0..39, ExKey] =
  let (keyEven, keyOdd) = divideKey(key)

  for i in 0..<20:
    let
      a = h(uint32(2 * i) * rho, keyEven)
      b = rotateLeftBits(h(uint32(2 * i + 1) * rho, keyOdd), 8)

    result[i shl 1] = a + b
    result[i shl 1 + 1] = rotateLeftBits(a + (b shl 1), 9)


func makeSBoxes(key: Key): array[0..k - 1, SBox] =
  var
    ms: array[0..8 * k - 1, Byte]
    ss: array[0..3, Byte]

  for i, k in key:
    for j, m in splitToBytes(k):
      ms[4 * i + j] = m

  for i in 0..<k:
    # GF(2^8) with generating polynomial x^8 + x^6 + x^3 + x^2 + 1.
    for j in 0..3:
      ss[j] = Byte(rs[j][0] * GF4Dh(ms[8 * i]) + rs[j][1] * GF4Dh(ms[8 * i + 1]) +
        rs[j][2] * GF4Dh(ms[8 * i + 2]) + rs[j][3] * GF4Dh(ms[8 * i + 3]) + rs[j][4] * GF4Dh(ms[8 * i + 4]) +
        rs[j][5] * GF4Dh(ms[8 * i + 5]) + rs[j][6] * GF4Dh(ms[8 * i + 6]) + rs[j][7] * GF4Dh(ms[8 * i + 7]))

    result[k - i - 1] = mergeBytes(ss[3], ss[2], ss[1], ss[0])


# encrypt / decrypt

func encryptBlock*(blck: Block; key: Key): Block =
  ## Encrypt the plain text blck (``blck``).
  let
    exKeys = makeExKeys(key)
    sBoxes = makeSBoxes(key)

  # input whitening
  result = whitening(blck, [exKeys[0], exKeys[1], exKeys[2], exKeys[3]])

  # round 1 to 16
  for round in 0..15:
    let
      (r0, r1) = (result[0], result[1])
      (f0, f1) = f(r0, r1, round, exKeys, sBoxes)

    result[0] = rotateRightBits(result[2] xor f0, 1)
    result[1] = rotateLeftBits(result[3], 1) xor f1
    (result[2], result[3]) = (r0, r1)

  # undo last swap
  block:
    let tmp = [result[2], result[3], result[0], result[1]]
    result = tmp

  # output whitening
  result = whitening(result, [exKeys[4], exKeys[5], exKeys[6], exKeys[7]])


func decryptBlock*(blck: Block; key: Key): Block =
  ## Decrypt the cipher text blck (``blck``).
  let
    exKeys = makeExKeys(key)
    sBoxes = makeSBoxes(key)

  # undo output whitening
  result = whitening(blck, [exKeys[4], exKeys[5], exKeys[6], exKeys[7]])

  # swap
  block:
    let tmp = [result[2], result[3], result[0], result[1]]
    result = tmp

  # undo round 16 to 1
  for round in 0..15:
    let
      (r0, r1) = (result[2], result[3])
      (f0, f1) = f(r0, r1, 15 - round, exKeys, sBoxes)

    result[2] = rotateLeftBits(result[0], 1) xor f0
    result[3] = rotateRightBits(result[1] xor f1, 1)
    (result[0], result[1]) = (r0, r1)

  # undo input whitening
  result = whitening(result, [exKeys[0], exKeys[1], exKeys[2], exKeys[3]])
