import unittest
import nim_speck_cipher

import parseutils
import strutils
import times
import std/monotimes

# vectors from page 42 in https://eprint.iacr.org/2013/404.pdf
let
  pt_hex = "6c617669757165207469206564616d20"
  key_hex = "0f0e0d0c0b0a09080706050403020100"
  ct_hex = "a65d9851797832657860fedf5c570d18"

var
  pt: array[16, byte]
  key: array[16, byte]
  ct: array[16, byte]

for i in 0..15:
  pt[i] = fromHex[byte](pt_hex[i*2..(i*2)+1])
for i in 0..15:
  key[i] = fromHex[byte](key_hex[i*2..(i*2)+1])
for i in 0..15:
  ct[i] = fromHex[byte](ct_hex[i*2..(i*2)+1])

let
  pt_ints = [fromHex[uint64](pt_hex[16..31]), fromHex[uint64](pt_hex[0..15])]
  key_ints = [fromHex[uint64](key_hex[16..31]), fromHex[uint64](key_hex[0..15])]
  ct_ints = [fromHex[uint64](ct_hex[16..31]), fromHex[uint64](ct_hex[0..15])]

# do the key schedule
var
  rks: array[32, uint64]
key_schedule(key, rks)

test "can convert to input":
  let
    key_ints = [fromHex[uint64](key_hex[16..31]), fromHex[uint64](key_hex[0..15])]
    key_ints_2 = to_input(key)
  check (key_ints == key_ints_2)

test "can convert to output":
  let
    key_ints = [fromHex[uint64](key_hex[16..31]), fromHex[uint64](key_hex[0..15])]
    key_ints_2 = to_output(key_ints)
  check (key == key_ints_2)

test "can encrypt":
  var output: array[16, byte]
  encrypt(output, pt, rks)
  check (output == ct)

test "can encrypt_otf":
  var out_ints: array[2, uint64] = [uint64(0), 0]
  encrypt_otf(out_ints, pt_ints, key_ints)
  check (ct_ints == out_ints)

test "can decrypt":
  var out_ints: array[2, uint64] = [uint64(0), 0]
  decrypt(out_ints, ct_ints, rks)
  check (pt_ints == out_ints)

test "bench":
  const ITERS = 1_000_000
  var
    out_ints: array[2, uint64] = [uint64(0), 0]
    output: array[16, byte]
    begin = getMonoTime()
    delta = (getMonoTime() - begin).inMilliseconds()

  # benchmark
  begin = getMonoTime()
  for i in 0..ITERS:
    encrypt(output, pt, rks)
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
