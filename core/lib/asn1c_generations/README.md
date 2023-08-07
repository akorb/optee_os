We need an own copy of the asn1c generated files for the core,
since the generated code needs to be adapted.

- Remove file IO functions
- Remove usages of errno (errno.h not implemented by OP-TEE)
- Replace printf/fprintf by according EMSG/DMSG macro
- Replace call to POSIX function `random` in `asn_random_fill.c` by `crypto_rng_read`
