import unittest
import nim_speck_cipher

import strutils
import times
import std/monotimes

# vectors from page 42 in https://eprint.iacr.org/2013/404.pdf
let
  pt = "6c617669757165207469206564616d20"
  key = "0f0e0d0c0b0a09080706050403020100"
  ct = "a65d9851797832657860fedf5c570d18"

let
  pt_ints = [fromHex[uint64](pt[16..31]), fromHex[uint64](pt[0..15])]
  key_ints = [fromHex[uint64](key[16..31]), fromHex[uint64](key[0..15])]
  ct_ints = [fromHex[uint64](ct[16..31]), fromHex[uint64](ct[0..15])]

# do the key schedule
var
  rks: array[32, uint64]
key_schedule(key_ints, rks)


test "can encrypt":
  var out_ints: array[2, uint64] = [uint64(0), 0]
  encrypt(out_ints, pt_ints, rks)
  check (ct_ints == out_ints)

test "can encrypt_otf":
  var out_ints: array[2, uint64] = [uint64(0), 0]
  encrypt_otf(out_ints, pt_ints, key_ints)
  check (ct_ints == out_ints)

test "can decrypt":
  var
    out_ints: array[2, uint64] = [uint64(0), 0]

  decrypt(out_ints, ct_ints, rks)
  check (pt_ints == out_ints)

test "bench":
  const ITERS = 1_000_000
  var
    out_ints: array[2, uint64] = [uint64(0), 0]
    begin = getMonoTime()
    delta = (getMonoTime() - begin).inMilliseconds()

  # benchmark
  begin = getMonoTime()
  for i in 0..ITERS:
    encrypt(out_ints, out_ints, rks)
  delta = (getMonoTime() - begin).inMilliseconds()
  echo "encrypt - 1 mil blocks in ", $delta, " ms"

  # benchmark
  begin = getMonoTime()
  for i in 0..ITERS:
    encrypt_otf(out_ints, out_ints, key_ints)
  delta = (getMonoTime() - begin).inMilliseconds()
  echo "encrypt_otf - 1 mil blocks in ", $delta, " ms"

  # benchmark
  begin = getMonoTime()
  for i in 0..ITERS:
    decrypt(out_ints, out_ints, rks)
  delta = (getMonoTime() - begin).inMilliseconds()
  echo "decrypt - 1 mil blocks in ", $delta, " ms"
