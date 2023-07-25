/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021, Huawei Technologies Co., Ltd
 */

/*
 * Provide remote attestation services
 */

#ifndef __PTA_ATTESTATION_H
#define __PTA_ATTESTATION_H

#include <stdint.h>
#include <mbedtls/md.h>

#define PTA_ATTESTATION_UUID { 0x39800861, 0x182a, 0x4720, \
		{ 0x9b, 0x67, 0x2b, 0xcd, 0x62, 0x2b, 0xc0, 0xb5 } }

/*
 * Get the RSA public key that should be used to verify the values returned by
 * other commands.
 *
 * [out]    memref[0]        Public key exponent in big endian order
 * [out]    memref[1]        Modulus in big endian order
 * [out]    value[2]         Signature algorithm used by other commands.
 *                           Currently always
 *                           TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_GENERIC - Internal error
 * TEE_ERROR_SHORT_BUFFER - One or both buffers are too small, required size
 *                          is provided in memref[i].size
 */
#define PTA_ATTESTATION_GET_PUBKEY 0x0

/*
 * Return the digest found in the header of a Trusted Application binary or a
 * Trusted Shared library
 *
 * [in]     memref[0]        UUID of the TA or shared library
 * [in]     memref[1]        Nonce (random non-NULL, non-empty buffer of any
 *                           size to prevent replay attacks)
 * [out]    memref[2]        Output buffer. Receives the signed digest.
 *                           - The first 32 bytes are the digest itself (from
 *                             the TA signed header: struct shdr::hash)
 *                           - The following bytes are a signature:
 *                               SIG(SHA256(Nonce | digest))
 *                           - The algorithm is
 *                             TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 with a salt
 *                             length of 32.
 *                           - The key pair is generated internally and stored
 *                             in secure storage. The public key can be
 *                             retrieved with command PTA_ATTESTATION_GET_PUBKEY
 *                             (typically during device provisioning).
 *                           Given that the sigature length is equal to the
 *                           RSA modulus size in bytes, the output buffer size
 *                           should be at least (digest size + modulus size)
 *                           bytes. For example, for a 32-byte SHA256 digest and
 *                           2048 bit key (256 bytes) the minimum buffer size is
 *                           288 bytes.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_GET_TA_SHDR_DIGEST 0x1

/*
 * Return a signed hash for a running user space TA, which must be the caller
 * of this PTA. It is a runtime measurement of the memory pages that contain
 * immutable data (code and read-only data).
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        SHA256 hash of the TA memory followed by a
 *                           signature. See PTA_ATTESTATION_GET_TA_HDR_DIGEST
 *                           for a description of the signature.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_ACCESS_DENIED - Caller is not a user space TA
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_HASH_TA_MEMORY 0x2

/*
 * Return a signed hash of the TEE OS (kernel) memory. It is a runtime
 * measurement of the memory pages that contain immutable data (code and
 * read-only data).
 *
 * [in]     memref[0]        Nonce
 * [out]    memref[1]        SHA256 hash of the TEE memory followed by a
 *                           signature. See PTA_ATTESTATION_GET_TA_HDR_DIGEST
 *                           for a description of the signature.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_HASH_TEE_MEMORY 0x3

/*
 * Returns a DICE certificate chain where the leaf represents a EKCert.
 * The EKCert contains a measurement of the calling TA (which should be a fTPM).
 *
 * [out]    memref[0]        The certificate chain.
 *
 * Return codes:
 * TEE_SUCCESS
 * TEE_ERROR_SHORT_BUFFER - Output buffer size less than required
 */
#define PTA_ATTESTATION_GET_EKCERT_CHAIN 0x4

typedef struct cert_info
{
    const uint8_t *subject_key;   /* Buffer containing the subject key in PEM format  */
    size_t subject_key_len;       /* Size of subject key in its PEM format            */
    const uint8_t *issuer_key;    /* Buffer containing the issue key in PEM format    */
    size_t issuer_key_len;        /* Size of issue key in its PEM format              */
    const char *subject_name;     /* subject name for certificate                          */
    const char *issuer_name;      /* issuer name for certificate                           */
    const char *not_before;       /* validity period not before                            */
    const char *not_after;        /* validity period not after                             */
    const char *serial;           /* serial number string                                  */
    int selfsign;                 /* selfsign the certificate                              */
    int is_ca;                    /* is a CA certificate                                   */
    int max_pathlen;              /* maximum CA path length                                */
    int authority_identifier;     /* add authority identifier to CRT                       */
    int subject_identifier;       /* add subject identifier to CRT                         */
    int basic_constraints;        /* add basic constraints ext to CRT                      */
    int version;                  /* CRT version                                           */
    mbedtls_md_type_t md;         /* Hash used for signing                                 */
    unsigned char key_usage;      /* key usage flags                                       */
    unsigned char ns_cert_type;   /* NS cert type                                          */
    const uint8_t *certificate_policy_val;
    const uint8_t *tci; /* Trused Componentent Identifier aka Firmware ID (FWID)*/
} cert_info;

/*
Generated via https://kjur.github.io/jsrsasign/tool/tool_asn1encoder.html with:

{
    "seq": [
        {
            "seq": [
                {
                    "oid": {
                        "oid": "2.23.133.5.4.100.6"
                    }
                }
            ]
        }
    ]
}
*/
static const uint8_t certificate_policy_val_IDevID[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x06};
static const uint8_t certificate_policy_val_LDevID[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x07};

static const uint8_t attestation_extension_value_preface[] = {
    0x30, 0x31, 0xa6, 0x2f, 0x30, 0x2d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20};

// SHA256, 256 Bits = 32 Bytes
#define TCI_LEN 32
#define CERTIFICATE_POLICY_VAL_LEN sizeof(certificate_policy_val_IDevID)

static const char dice_attestation_oid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};
static const uint8_t tci_bl1[TCI_LEN] = {0x4c, 0xce, 0xfa, 0x68, 0x7d, 0x38, 0xbe, 0x8f,
                                         0xe1, 0x85, 0xc0, 0xbf, 0x92, 0xb2, 0x8c, 0xdb,
                                         0x69, 0xe8, 0x27, 0xe0, 0xe2, 0x39, 0x20, 0xbe,
                                         0x2c, 0xcf, 0x4a, 0xb2, 0xba, 0x0d, 0xe9, 0x60};

#define DFL_NOT_BEFORE "20230725000000"
#define DFL_NOT_AFTER "99991231235959"
#define DFL_SERIAL "1"
#define DFL_SELFSIGN 0
#define DFL_IS_CA 0
#define DFL_MAX_PATHLEN -1
#define DFL_KEY_USAGE 0
#define DFL_NS_CERT_TYPE 0
#define DFL_VERSION 3
#define DFL_AUTH_IDENT 1
#define DFL_SUBJ_IDENT 1
#define DFL_CONSTRAINTS 1
#define DFL_DIGEST MBEDTLS_MD_SHA256

#define MBEDTLS_EXIT_SUCCESS 0
#define MBEDTLS_EXIT_FAILURE 1

#define MAX_CERT_SIZE 2048

static const uint8_t crt_bl1[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADA2MQ8wDQYDVQQDDAZ0aGUg\n\
Q04xFTATBgNVBAoMDENvb2wgY29tcGFueTEMMAoGA1UEBhMDR0VSMCAXDTIzMDcy\n\
NTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA1MQwwCgYDVQQDDANCTDExFzAVBgNV\n\
BAoMDkFQIFRydXN0ZWQgUk9NMQwwCgYDVQQGEwNHRVIwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQCGNlLKbBq17LxHDFhuzJ+e1R9CM1XVjC5anlu7iDpm\n\
R+4sXSdCLxIyQV46mpOJydphKmWq43NZsAsue1LIf/g11t8Kgxwr4CgKuBj0aHY5\n\
bVg6S/r/XVlx/Wcy8CTqNoNZs+NiQya/Fx66WocTyZGtgiNWzQkt5V5+7DOWdZ/t\n\
hD0MoUDRrToyl+BtmIXc/ZUcu0NWxIIy1lBAL5t6Q1NBwWYfDuqnCttcjhC3njQN\n\
6PqnRz8uCslaw0HozudIJxz0oPLyqyo8V+kzrV4vjatS30iXewDpxlTo4XbY5LXj\n\
+w9K28gSuy/gun9SVTrckCB2h+Me3EZvrU41raJqw+upAgMBAAGjgbkwgbYwDwYD\n\
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUYppir0Fmp2azmjvLLTmoyYsD++kwHwYD\n\
VR0jBBgwFoAUPPQ7+P7vCsdxyT1HZqyvZCYCoZIwDgYDVR0PAQH/BAQDAgIEMBQG\n\
A1UdIAQNMAswCQYHZ4EFBQRkBjA9BgZngQUFBAEEMzAxpi8wLQYJYIZIAWUDBAIB\n\
BCBMzvpofTi+j+GFwL+Ssozbaegn4OI5IL4sz0qyug3pYDANBgkqhkiG9w0BAQsF\n\
AAOCAQEAXlmkmn5GZvkL3T10WYVL7iOl55jgAiKx11ujI7Trzjxr1FHSfkGYK3Xc\n\
UUn93Bzh7EiPJmTq0LSf4fFslOzOLaMV7Dt80leShjiVq7i0AyCvUeAKAKvmdIz9\n\
Qa4TyT1d/1X2Zj3GjmlDS0RzDbeZec1Iksdo2pfcPAgQZX9TRhpH6KphLasugZYL\n\
vo/K2Ay4Cs5dy4nDoIZScLIiVkBvqiUDQzYoxXgBdVG7O0qBRtoyGGLlr1obwMt2\n\
LVsH1SCOFo8/MZAUEbVro0hQw2wLtRl+Zr5rpX628VNduKU218mMaTYFzINksySU\n\
HriLUH+WZQ4LHlGcUNVT0ow40A2kvg==\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl2[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDqDCCApCgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MQwwCgYDVQQDDANCTDEx\n\
FzAVBgNVBAoMDkFQIFRydXN0ZWQgUk9NMQwwCgYDVQQGEwNHRVIwIBcNMjMwNzI1\n\
MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDwxDDAKBgNVBAMMA0JMMTEeMBwGA1UE\n\
CgwVVHJ1c3RlZCBCb290IEZpcm13YXJlMQwwCgYDVQQGEwNHRVIwggEiMA0GCSqG\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCm43Xa7wgNS40QodAPxozddoBlVrx0LEW7\n\
NE4Jr4A5gzUjp8M5w3nqQ8yDWF50OTYv1YgS7656NcAZBV6JmQC2h8v0e71Zusde\n\
JIX1Ef7zu9+mB63oBHkA/W8SlrC28mx3l4GqotbzQbQ60sTYucsGNDp7ibGwVVXn\n\
YgDU20rrgFeu5RZyUIwyEHv+tIfkMDxRM/H8ZlRcbYtjZJDZx4dY3JtbKi8D0UX1\n\
0AJKJAPKzpRHX2zvm90wIeg6A7oWgUAArAHmEYB0OTGPEMA74H0moAD2syPx4Vn8\n\
+GxdEJ3fnRW6ukHbExrHZe56GEYn9xynPdY0kOAjWAruWyz28lKBAgMBAAGjgbkw\n\
gbYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUG4MJM4Hk6/pfko5Cyf8UiA0W\n\
BZkwHwYDVR0jBBgwFoAUYppir0Fmp2azmjvLLTmoyYsD++kwDgYDVR0PAQH/BAQD\n\
AgIEMBQGA1UdIAQNMAswCQYHZ4EFBQRkBzA9BgZngQUFBAEEMzAxpi8wLQYJYIZI\n\
AWUDBAIBBCBMzvpofTi+j+GFwL+Ssozbaegn4OI5IL4sz0qyug3pYDANBgkqhkiG\n\
9w0BAQsFAAOCAQEAG044UyX5p9bnezTegTFkSJ0mlePgGyBG5PrKxZeH0oHuGZUe\n\
etfVS2vEru59Bx/GGALmjnq7TtHDJqxOlqEQKX5ND5/lgpPsmwAumHphBKWmt6vI\n\
nX0BwC3BHFUZw6ZeWfh5cVZDY/91aBZUciirPwmpXbX5J0gWYPfAR/xoodtP6EiQ\n\
AMNyloqW6zgGHb8R0qAFJiVdEoTa8Bgn6Gd22Feleul/WYs2WGyZnSyDmt+YqEbU\n\
l1Y8tr1vEunCJzH+pGAWzGDp/3DzCYi94VFUYJnr3pqT2rEoqBm3WAVoMxnXYcy6\n\
M21Bra1lMsJCrc2Kz7ciyK+lfXzK2HCzvVaBRA==\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl31[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDrjCCApagAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQwwCgYDVQQDDANCTDEx\n\
HjAcBgNVBAoMFVRydXN0ZWQgQm9vdCBGaXJtd2FyZTEMMAoGA1UEBhMDR0VSMCAX\n\
DTIzMDcyNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA7MQwwCgYDVQQDDANCTDEx\n\
HTAbBgNVBAoMFEVMMyBSdW50aW1lIFNvZnR3YXJlMQwwCgYDVQQGEwNHRVIwggEi\n\
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCn26rb+/QuObmLHEto4mB7/h+J\n\
DUUhoWpQ4txEQR8Tg8V8he/9PEB/oOjYiJ4O67bx/HUoShkFxQSNEh2WbiDHAKDF\n\
3Zb86My/uBJ+OQ1weGCeNkY7WF3t0C/DfiLJf30jdTgYksS5I93HuDmkAuVRvHR9\n\
ViJCQVKXzK0PBVfTbsk0Y7HUoF8sUL94QyJXgQiWsRDQrKEOS7TsvZBNX0XK7MdQ\n\
cXRLWJ5O8sy91nVS5+d8QoRfuhTwUCKlLLxufbPFUSsvuU9wSWj7ic1AiOiae5lt\n\
VBa77Zh1c8VUop8x3doPJ+P1BGik+RrkZg5BPBeNG0EBg4z13ImgdQSn6VtNAgMB\n\
AAGjgbkwgbYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUs3Ke3i8pF+A9ceYD\n\
mcHSshvYnFIwHwYDVR0jBBgwFoAUG4MJM4Hk6/pfko5Cyf8UiA0WBZkwDgYDVR0P\n\
AQH/BAQDAgIEMBQGA1UdIAQNMAswCQYHZ4EFBQRkBzA9BgZngQUFBAEEMzAxpi8w\n\
LQYJYIZIAWUDBAIBBCBMzvpofTi+j+GFwL+Ssozbaegn4OI5IL4sz0qyug3pYDAN\n\
BgkqhkiG9w0BAQsFAAOCAQEAnRKGX2KMCixSRn0u/mUijGzIjWo2JTgS5HGM+KbC\n\
O3Q/jCV7RW+oZBhnan1sa/krey35C5m1UF1o2v1pPFab95DFC4cQtcRGD4dbaCNi\n\
mFXldbp/RTq5o0+e2sr2mgvMOTvJ1Dsh5l3cJ5lM/S6hurUdmYdB8raZKZaGPLVm\n\
+etP7omJedJHu/J2nY3SICGodMWOXcapr+u7l5yIDWLhAH0VbmsLSI8QB3PEs5IT\n\
IrYEuWsGziEUyEs8ObQXfNZONg/d40cuufumEGvTnogAkaPAr4QVRIuxoCQxAYzp\n\
8aRBVfGa59pnqGQ8MeKGcsEmz0SbaJqQTsySDbtyx+T4+Q==\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl32[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDojCCAoqgAwIBAgIBATANBgkqhkiG9w0BAQsFADA7MQwwCgYDVQQDDANCTDEx\n\
HTAbBgNVBAoMFEVMMyBSdW50aW1lIFNvZnR3YXJlMQwwCgYDVQQGEwNHRVIwIBcN\n\
MjMwNzI1MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDAxDDAKBgNVBAMMA0JMMTES\n\
MBAGA1UECgwJT1AtVEVFIE9TMQwwCgYDVQQGEwNHRVIwggEiMA0GCSqGSIb3DQEB\n\
AQUAA4IBDwAwggEKAoIBAQCZHmB/jGls35xWyGtguxIRIvaX1ncTBdKyrXPbBm5T\n\
+7CraPLgQpLVhAN1oN67XOXNNLiaKCb0/I2MgLsq0+SI1YYPZU5nSRZ9rVVtTMym\n\
8AtASwPjDOBJm/s6Hp9+Q8gxHazYEH9BCc2v6j9A3kjV6cslynaiwZvN4K+aix6k\n\
1mdoTitJylhVN1k/1a2ZsFHicLPnWPtXgOoZ0PDdN6YLZbS0Ka6BdAEuKTVH/UHz\n\
4bVz3eAsLM881cIHyAzhauPanpcs2FuAC6HOSn6AXPuTfiBcTuwFFw0PFVIGhZaW\n\
/bptcc3elB60Mqy5EwjeJaV2C4/Bc4LoqqDFuJl8ES5jAgMBAAGjgbkwgbYwDwYD\n\
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUG5tZTkK8L26sIIQ1mWTom4eb6t8wHwYD\n\
VR0jBBgwFoAUs3Ke3i8pF+A9ceYDmcHSshvYnFIwDgYDVR0PAQH/BAQDAgIEMBQG\n\
A1UdIAQNMAswCQYHZ4EFBQRkBzA9BgZngQUFBAEEMzAxpi8wLQYJYIZIAWUDBAIB\n\
BCBMzvpofTi+j+GFwL+Ssozbaegn4OI5IL4sz0qyug3pYDANBgkqhkiG9w0BAQsF\n\
AAOCAQEAgqPZLeICZ9AKjTK3V+NCv6LuPuvx9ZRTIPv3Tfwmr36qfCQ3G/cwAoUR\n\
uzjr4XHl4ABFfiIB9DRzmQwkzpQuYWZtW+Z6zDZ4BpZwFnayaMXuAvk+uC/Z4D/V\n\
GZCXBV25RodNpiYrrAJJPvOjStc82P5YOsqStOh07jtIcI0M33Vk20VrrKpQ/HTK\n\
l2nwcziFaZBABpjRHjvFSFPUjeRzv8CVIKuaRUy8TOqLS2xOr2TW/u1i7urrYW3N\n\
TnP85FFwP4YajI91iDzI9UTjRnrhe1k+wmNL/EaYt2Hm5N3bct5p0Mxeff1r87z7\n\
ACi2j3Jaf1J94i2Wz6GlTRRBYYMuWw==\n\
-----END CERTIFICATE-----";

static const uint8_t key_bl32[] =
"-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZHmB/jGls35xW\n\
yGtguxIRIvaX1ncTBdKyrXPbBm5T+7CraPLgQpLVhAN1oN67XOXNNLiaKCb0/I2M\n\
gLsq0+SI1YYPZU5nSRZ9rVVtTMym8AtASwPjDOBJm/s6Hp9+Q8gxHazYEH9BCc2v\n\
6j9A3kjV6cslynaiwZvN4K+aix6k1mdoTitJylhVN1k/1a2ZsFHicLPnWPtXgOoZ\n\
0PDdN6YLZbS0Ka6BdAEuKTVH/UHz4bVz3eAsLM881cIHyAzhauPanpcs2FuAC6HO\n\
Sn6AXPuTfiBcTuwFFw0PFVIGhZaW/bptcc3elB60Mqy5EwjeJaV2C4/Bc4LoqqDF\n\
uJl8ES5jAgMBAAECggEANbBIjsCpoLLBa06IFBlUCu0zAOeCxglHKT6XfoeBPPJm\n\
Lpw0eTzupm5NFjwrjQ/URgFD702/5yv85/SlbC1zFyWjhZd0h9PBTpzt9M62fZxy\n\
nX8QJFc596V5UBY3v3q94bbxiaszK5dn51RgDHtEl7kL8brNoWD4pBYyDKLWQl6e\n\
eFyOpa3RQRny3cp02qK+QQjgmrdrSjP6rPzk6rF3FpypWhBU9iPPTw61+4YvRpK5\n\
7ZtQfxtup9UPX5oepvARIxXt3nWExICr5yRfMObJ4IR9qnszR4/yXMccRtMHPrxF\n\
t1V+iIy89QuBkfPyhXqs9nnlLBLbD1E6AjA3EEu4TQKBgQDG6ULiCWz6qxSodibM\n\
9vqzmBsEIrl5++NTe7xU0jpwP3GFZCHzRlMN74jJODBpuIwvFavfMzm2cVePB9Mw\n\
HjK4yv2V4AOBXarPKLUwoN2y30n2A7UMZNVv6P+s3XKuXOJTI8E/k3NUOt0H00kD\n\
HlEPlnK9iY3UqwJuf2K3U38STQKBgQDFEJIDFMohR3aJ9JYtfIIP25NkOtJzOwQQ\n\
eJ7I18oPxKjhxe6kmu7NadcD2Lho7lwWJyXo55JIvuKfKlcP1FFC08sVLmzSIqEq\n\
QbfKgiWRSocadz/sX4uDqaWg0QGBTzIQQhWC5AyBFWrCaK1WGC60wLkX2JGbvvRX\n\
vDQgFQK7bwKBgAbiM6pW4SqbmQ9rZ1RYh7yHWwf9m6WZDfjpo07cJ6GS0H7pRDOD\n\
D4S/8V/lTeeat185xMTopOqnaXxNrQVRRjgW7kethPGJKEwbAIo6RvHVwF1/K1jO\n\
dIR278Ivt7RJCpwN9LYaiDc2AkgvC6vL9MoxTq84f2wIrwDb77KgdRlRAoGAJto6\n\
f2ME6wTE6TQQu80Vc3zuFU/HmDJlfb3aSGzLCMrUJRc6Erf9JwCcBMUgrod4HmH/\n\
hmjJnZAM7CaT3aoVj2BkZLuvdsqfDc7BJqr8LyYLdvtV3guEXSQAZLFwY4cyrqPo\n\
y9KcaILJdqTer9+6raZll776DkPatsWDXWPnEv8CgYEArXmRBpTf/f4Emu7wk8Dn\n\
ZvWDaeDatH/iCS6DzS9ZGsIwaBk0C1CKZfE9vjfW4TCs79mowdVsP8LLdcEGva8A\n\
SO9u/JAbum//Pcn0HuPwNT7W3o2nai/u5MYp670H2Y9PYNc8wIrkf1Fswp0LDElw\n\
LEcjyM3xY1lzeNnNR7YORnI=\n\
-----END PRIVATE KEY-----";

#endif /* __PTA_ATTESTATION_H */
