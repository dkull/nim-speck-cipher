# nim-speck-cipher
Nim implementation of the NSA Speck cipher

This is a pure Nim implementation.

NOTE: This is a work-in-progress. Do not use for anything important.

# Test
```
$ nimble test
or for better benchmarks:
$ nimble -d:release --opt:fast --passC:-march=native test
```

# Run
```nim
import speck_cipher

var
  key: array[16, byte]
  pt: array[16, byte]

var
  rks: array[32, uint64]
  ct_1: array[16, byte]
  ct_2: array[16, byte]
  pt_out: array[16, byte]

# create the round keys for 'encrypt' and 'decrypt'
key_schedule(key, rks)

# slightly faster in a loop than encrypt_otf
encrypt(ct_1, pt, rks)

# round keys calculated on-the-fly
encrypt_otf(ct_2, pt, key)

assert(ct_1 == ct_2)

# decrypt the ct using the round keys
decrypt(pt_out, ct_1, rks)

assert(pt_out == pt)
```
