import unittest
import speck_cipher

import strformat
import parseutils
import strutils
import times
import std/monotimes

# vectors from page 42 in https://eprint.iacr.org/2013/404.pdf
let test_vectors = [
  ("6c617669757165207469206564616d20", "0f0e0d0c0b0a09080706050403020100", "a65d9851797832657860fedf5c570d18"),
  #("206D616465206974206571756976616C", "000102030405060708090A0B0C0D0E0F", "180D575CDFFE60786532787951985DA6"),
]

proc run_test(pt_hex: string, key_hex:string, ct_hex:string): bool =
  var
    pt: array[16, byte]
    key: array[16, byte]
    ct: array[16, byte]
    rks: array[32, uint64]

  for i in 0..15:
    pt[i] = fromHex[byte](pt_hex[i*2..(i*2)+1])
  for i in 0..15:
    key[i] = fromHex[byte](key_hex[i*2..(i*2)+1])
  for i in 0..15:
    ct[i] = fromHex[byte](ct_hex[i*2..(i*2)+1])

  # do the key schedule
  key_schedule(key, rks)

  var output_ct: array[16, byte]
  var output_pt: array[16, byte]

  # test regular encrypt

  encrypt(output_ct, pt, rks)
  decrypt(output_pt, ct, rks)

  check (output_ct == ct)
  check (output_pt == pt)

  # test otf encrypt

  encrypt_otf(output_ct, pt, key)
  check (output_ct == ct)

  return true

test "test_vectors":
  for i, vector in test_vectors:
    discard run_test(vector[0], vector[1], vector[2])
    echo i, " OK"

test "bench":
  let
    vec = test_vectors[0]
    start = getMonoTime()

  var buf1: array[16, byte]
  for i in 0..1_000_000:
    encrypt_otf(buf1, buf1, buf1)

  let
    finish = getMonoTime()
    delta = finish-start

  echo &"{delta}"
