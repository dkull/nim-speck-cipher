const ROUNDS = 32

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

proc key_schedule*(key: array[2, uint64], rks: var array[ROUNDS, uint64]) =
  var
    a = key[0]
    b = key[1]

  for i in 0..ROUNDS - 2:
    rks[i] = a
    ER(b, a, uint64(i))

  rks[ROUNDS-1] = a

proc encrypt_otf*(ct: var array[2, uint64], pt: array[2, uint64], key: array[2, uint64]) =
  # encrypt a block of plaintext. the round keys are calculated on-the-fly
  # this method is somewhat slower than encrypt due to extra work done for every round
  var
    A = key[0]
    B = key[1]

  ct[0] = pt[0]
  ct[1] = pt[1]

  for i in 0..<ROUNDS:
    ER(ct[1], ct[0], A)
    ER(B, A, uint64(i))

proc encrypt*(ct: var array[2, uint64], pt: array[2, uint64], rks: array[ROUNDS, uint64]) =
  # encrypt a block of plaintext. needs the precomputed roundkeys.
  ct[0] = pt[0]
  ct[1] = pt[1]

  for i in 0..<ROUNDS:
    ER(ct[1], ct[0], rks[i])

proc decrypt*(pt: var array[2, uint64], ct: array[2, uint64], rks: array[ROUNDS, uint64]) =
  # decrypt a block of plaintext. needs the precomputed roundkeys.
  pt[0] = ct[0]
  pt[1] = ct[1]

  for i in countdown(ROUNDS-1, 0):
    DR(pt[1], pt[0], rks[i])
