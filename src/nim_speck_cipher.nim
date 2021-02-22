const ROUNDS = 32

proc to_input*(data: array[16, byte]): array[2, uint64] {.inline.} =
  var a = uint64(data[0])
  a = a shl 8 or data[1]
  a = a shl 8 or data[2]
  a = a shl 8 or data[3]
  a = a shl 8 or data[4]
  a = a shl 8 or data[5]
  a = a shl 8 or data[6]
  a = a shl 8 or data[7]

  var b = uint64(data[8])
  b = b shl 8 or data[9]
  b = b shl 8 or data[10]
  b = b shl 8 or data[11]
  b = b shl 8 or data[12]
  b = b shl 8 or data[13]
  b = b shl 8 or data[14]
  b = b shl 8 or data[15]

  return [b, a]

proc to_output*(data: array[2, uint64]): array[16, byte] {.inline.} =
  result[0] = byte(data[1] shr 56 and 0xff)
  result[1] = byte(data[1] shr 48 and 0xff)
  result[2] = byte(data[1] shr 40 and 0xff)
  result[3] = byte(data[1] shr 32 and 0xff)
  result[4] = byte(data[1] shr 24 and 0xff)
  result[5] = byte(data[1] shr 16 and 0xff)
  result[6] = byte(data[1] shr 8 and 0xff)
  result[7] = byte(data[1] shr 0 and 0xff)

  result[8] = byte(data[0] shr 56 and 0xff)
  result[9] = byte(data[0] shr 48 and 0xff)
  result[10] = byte(data[0] shr 40 and 0xff)
  result[11] = byte(data[0] shr 32 and 0xff)
  result[12] = byte(data[0] shr 24 and 0xff)
  result[13] = byte(data[0] shr 16 and 0xff)
  result[14] = byte(data[0] shr 8 and 0xff)
  result[15] = byte(data[0] shr 0 and 0xff)


proc ROR(x: var uint64, r: uint64) {.inline.} =
  x = (x shr r) or (x shl (64 - r))

proc ROL(x: var uint64, r: uint64) {.inline.} =
  x = (x shl r) or (x shr (64 - r))

proc ER (x: var uint64, y: var uint64, k: uint64) {.inline.} =
  ROR(x, 8)
  x += y
  x = x xor k
  ROL(y, 3)
  y = y xor x

proc DR (x: var uint64, y: var uint64, k: uint64) {.inline.} =
  y = y xor x
  ROR(y, 3)
  x = x xor k
  x -= y
  ROL(x, 8)

proc key_schedule*(key: array[16, byte], rks: var array[ROUNDS, uint64]) =
  var
    input = to_input(key)
    a = input[0]
    b = input[1]

  for i in 0..ROUNDS - 2:
    rks[i] = a
    ER(b, a, uint64(i))

  rks[ROUNDS-1] = a

proc encrypt_otf*(ct: var array[16, byte], pt: array[16, byte], key: array[16, byte]) =
  # encrypt a block of plaintext. the round keys are calculated on-the-fly
  # this method is somewhat slower than encrypt due to extra work done for every round
  var
    key_inp = to_input(key)
    pt_inp = to_input(pt)
    ct_inp = to_input(ct)
    a = key_inp[0]
    b = key_inp[1]

  ct_inp[0] = pt_inp[0]
  ct_inp[1] = pt_inp[1]

  for i in 0..<ROUNDS:
    ER(ct_inp[1], ct_inp[0], a)
    ER(b, a, uint64(i))

  ct = to_output(ct_inp)

proc encrypt*(ct: var array[16, byte], pt: array[16, byte], rks: array[ROUNDS, uint64]) =
  # encrypt a block of plaintext. needs the precomputed roundkeys.
  var
    pt2 = to_input(pt)
    ct2 = to_input(ct)

  ct2[0] = pt2[0]
  ct2[1] = pt2[1]

  for i in 0..<ROUNDS:
    ER(ct2[1], ct2[0], rks[i])

  ct = to_output(ct2)

proc decrypt*(pt: var array[16, byte], ct: array[16, byte], rks: array[ROUNDS, uint64]) =
  # decrypt a block of plaintext. needs the precomputed roundkeys.
  var
    pt_inp = to_input(pt)
    ct_inp = to_input(ct)
  pt_inp[0] = ct_inp[0]
  pt_inp[1] = ct_inp[1]

  for i in countdown(ROUNDS-1, 0):
    DR(pt_inp[1], pt_inp[0], rks[i])

  pt = to_output(pt_inp)
