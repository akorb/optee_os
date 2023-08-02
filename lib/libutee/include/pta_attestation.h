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
AQUAA4IBDwAwggEKAoIBAQDpKT4T5vga8PM6FKU/SFkjfdHAFYnD3Do+kEqgNwX5\n\
985Uu5uDyb+2l0u31NpEZJ5UTAVODI3io2AAV9brCFxg7BzgKHEADEboBe0CEv8o\n\
RB3ZtT8CEa2BKWlTmGCYJhcWdqKzS+KNNA3+R2iax3qDeZVPKJMoAu1sUCFEC24p\n\
CCZXeAbFYUzR01QXzgdFu2vbdAegvOLpt4Fj2BRJbb3I4cKzUoYm3iqMe5S+w16/\n\
gAc2F3Sb2LtT0JU9XX4NkF3YatnbCINt+XPpGKj+cok4VrboIwidPQzaf4zF70FF\n\
5E8gLHFtSsT7rH5+dsygPVaWrgMblQrsbtmpNLf9Y0zdAgMBAAGjgbkwgbYwDwYD\n\
VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUwjlE+01gLKjo1qxhBQmSwcM2Sx4wHwYD\n\
VR0jBBgwFoAUEyEYCj7Jv//w0VyqItEl7H/x+MUwDgYDVR0PAQH/BAQDAgIEMBQG\n\
A1UdIAQNMAswCQYHZ4EFBQRkBjA9BgZngQUFBAEEMzAxpi8wLQYJYIZIAWUDBAIB\n\
BCBMzvpofTi+j+GFwL+Ssozbaegn4OI5IL4sz0qyug3pYDANBgkqhkiG9w0BAQsF\n\
AAOCAQEAnDHUxCMkgY6QnBTeFlX4VYPi/AUNl4HGSxcmUKBCAzZn870oeDNLA1az\n\
rFRKxtIzDOv8qTTZEitfr6LWxLaeWsFUuf+LZU4HajXyAJ6CfLwZpjFPiKhNlsO2\n\
tUJ+oZVkoM6FxkmhYkdrNrFzu8uqBblAUdtgLKtxJkqXn7HIBLoy3+FzlFtCtIP/\n\
sRuG8UR7otAhkTtKWXIvclA8IiLHAT0KaTJMXpZ3N2+fN3Ve+QYCOJVH31wKaxhd\n\
vw78XNL7T63gtSruR+TXmLMIco2ZjdSsXW0+Y+7jvvO3RGqIznoLl4Fz9zTbI5SY\n\
yFud0Bf9RC50BEJ3O/wIGpvT1SLG7w==\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl2[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDqDCCApCgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MQwwCgYDVQQDDANCTDEx\n\
FzAVBgNVBAoMDkFQIFRydXN0ZWQgUk9NMQwwCgYDVQQGEwNHRVIwIBcNMjMwNzI1\n\
MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDwxDDAKBgNVBAMMA0JMMjEeMBwGA1UE\n\
CgwVVHJ1c3RlZCBCb290IEZpcm13YXJlMQwwCgYDVQQGEwNHRVIwggEiMA0GCSqG\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjFsJNdcLwTrkvBE3dVkbx15MzA27TTFmJ\n\
jgT8iQ0RpCaHoD/hISiUZjpzB6iDMVseG1uTFR4DKpHNzFH7CUXmOEfj9rky3uvB\n\
5jEKm21w55+FlZ4f7CiFjVuX3/sKk8o80fJ98S6+2vDiOAPQyrSgG86OKMUVyAHy\n\
ZIwQU7SnQ2MVqyHS0KbVEDiAenJ6OMG6IBxIJctC0jbx0Kz4WGy/nnNi/pDzwI5n\n\
XGuHT3QdbcbOS29s8BDLskh4MDIYn8YR79mAMtYueVxG898anZjQ2Eg4yFO8FW5a\n\
IkDVC6b8r8w2hwik/OtwwwJySH2DvG1zrKUnKM+ddEnw56j0e0ibAgMBAAGjgbkw\n\
gbYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU1ORltUU+wirfYZe3HMdaMzvl\n\
0g8wHwYDVR0jBBgwFoAUwjlE+01gLKjo1qxhBQmSwcM2Sx4wDgYDVR0PAQH/BAQD\n\
AgIEMBQGA1UdIAQNMAswCQYHZ4EFBQRkBzA9BgZngQUFBAEEMzAxpi8wLQYJYIZI\n\
AWUDBAIBBCBMzvpofTi+j+GFwL+Ssozbaegn4OI5IL4sz0qyug3pYDANBgkqhkiG\n\
9w0BAQsFAAOCAQEAdgXMutf5Z/Q1piJAbH4C0w1HdiX4iF7kDUIm4BXTxe4x3GRn\n\
1op3ARX7sGqp9HDOKvy33dxuY652GHdIt8VTyf0zjOvJZUOBNAzo5Pl74LOYG9aW\n\
yrK/ycFS/qj7qhBZxIhKf6KcCyA0KPS9oAPvCpZmae0sboxVBOJEPfOpojw1ZalJ\n\
bFfa52wCs/k3CzjZPrnACBuKez+8QkForg6ooehsJI1da8OLPY0koCPZVe0GG8o8\n\
7/00ZvUor9U/GNCBRAHC9njxzOC3C7Z3WqCM/e26IPGJhxSgciDXH0zybzj24bSy\n\
KMwNhHUyxaKVuXWBCmsg017OKf8v67aRbKNRxQ==\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl31[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDrzCCApegAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQwwCgYDVQQDDANCTDIx\n\
HjAcBgNVBAoMFVRydXN0ZWQgQm9vdCBGaXJtd2FyZTEMMAoGA1UEBhMDR0VSMCAX\n\
DTIzMDcyNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA8MQ0wCwYDVQQDDARCTDMx\n\
MR0wGwYDVQQKDBRFTDMgUnVudGltZSBTb2Z0d2FyZTEMMAoGA1UEBhMDR0VSMIIB\n\
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3IEoDKjVDuXHStnRlbrTOeuQ\n\
tlsnrc2A2PhS58mlYS+vuX+3DuWUp4XRkA1jN+6gU5Ee2UJesh8bjUi7c0vH2Uew\n\
G2kh8W/p6p25rxKHaLLHZKNgULQ3lafBBQnO/2RD50nn3ABX9OoR84QAivbkAzwW\n\
k5CZYWtA4j3ysuDiKDsxezZrvFrNHYaX73SB+jC9jzpdCj3P0Rj8Rpp3pzzhoflU\n\
Pxorc69U8llVfomh3d/sgfoUrG1O++IEYW+0kHtIejpfDZB9XOJe4DwO0gEL5SZf\n\
0badXc7Pcbu43zmP2i0WBZZOOZvUfG4iTG7Eh1sDRtWlRzg/nDJHEncrYemNrQID\n\
AQABo4G5MIG2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOx1ABkTDDYU5i8r\n\
wvGqgHws51LMMB8GA1UdIwQYMBaAFNTkZbVFPsIq32GXtxzHWjM75dIPMA4GA1Ud\n\
DwEB/wQEAwICBDAUBgNVHSAEDTALMAkGB2eBBQUEZAcwPQYGZ4EFBQQBBDMwMaYv\n\
MC0GCWCGSAFlAwQCAQQgTM76aH04vo/hhcC/krKM22noJ+DiOSC+LM9KsroN6WAw\n\
DQYJKoZIhvcNAQELBQADggEBAI7whrVvyFOJMiTGyeSdgzLWJqMldZVxVPXQ28E8\n\
/OMEHOU2T38PbBg061fAnc6+/9PxA+O2kj1e6ViP5dEgpGEXWOaeE+6mf/dcjeJs\n\
sOEYkSUzlbjWWEVLxgluqANRb+7Zjzc23F39lf6+NRo6elAolHsktQBdoOha9vnp\n\
2LUqWqKpRKSM8L4qg7TaMoqN7bFGbOhROLetdUaKYdDpknYi29BxORf4/JPvj0bX\n\
aYIYKTtyrrnkaDwA3VNdvxzcK2mf4/Sb47f1aGqhilpozOIW0Nr6DJsHIAC4ielI\n\
Ttt1L/ccZK9Rod39i8aWykvnV6qjhOgQk4HWJGF/2A81ns0=\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl32[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQ0wCwYDVQQDDARCTDMx\n\
MR0wGwYDVQQKDBRFTDMgUnVudGltZSBTb2Z0d2FyZTEMMAoGA1UEBhMDR0VSMCAX\n\
DTIzMDcyNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAxMQ0wCwYDVQQDDARCTDMy\n\
MRIwEAYDVQQKDAlPUC1URUUgT1MxDDAKBgNVBAYTA0dFUjCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBANxIqS1o39R+UE8XLHf0UI6EAcVgaE81QY6Rv+rV\n\
4r8KFlI4qozQ8f7tcl1F1eJwwAsE6SFuM7KTIaorVSYEcWyJecpr/PCJRGQmz/+a\n\
skCgiUd6XPtzJn9oNPAVD5wNE88sj0xx99lgjFXjAP8zOQwN7u+jb9s9esr4e9Cu\n\
Cb2nJzuzaTQi+zzrpKU59+chU+wAubXxKMOu5F4E8ltFW6PSUc8nfyuEFguLeBbl\n\
9phit8kTTWjqWvntMAJSKIjWn9lJHmYT2rggPIzgG5Z79ODqQXZjhu0POPK1tnZf\n\
IWdMrqErcH0SIRZcjhKhCYJmGGW/dkm+hYA8Zj0Eqg84qp0CAwEAAaOBuTCBtjAP\n\
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBShxy4X9KrgInxKbnVHh/7w2tSrvjAf\n\
BgNVHSMEGDAWgBTsdQAZEww2FOYvK8LxqoB8LOdSzDAOBgNVHQ8BAf8EBAMCAgQw\n\
FAYDVR0gBA0wCzAJBgdngQUFBGQHMD0GBmeBBQUEAQQzMDGmLzAtBglghkgBZQME\n\
AgEEIEzO+mh9OL6P4YXAv5KyjNtp6Cfg4jkgvizPSrK6DelgMA0GCSqGSIb3DQEB\n\
CwUAA4IBAQADLbYHNDHLiy35zf3Vmw/5FNkIPwbqBAYUonM1wieeR4i+Rid/kLXX\n\
iPaHCz8nIUljZAqeRjfpbzNHq0vJ+7Ew6UR35Cj2bhamheeM20/v6IvDg9ZXi7eA\n\
auXlVPx9vV71yymlReef2Dk6/vIwfM/L/suhNOXWAfRfZ7Bl2UfQdICNqxYzZ5V/\n\
yXz6j2wgu8NyW3gsH+FIE/3PBSx4JDBIv+vIOUbBvr8onVBXGcPBGODM+dvgArQz\n\
hU+iNuTkDSwHR5+h4+Wf5N3MR15vJWgXDxjoGMobz1RTyna9ANDguzDp5Qkue7M7\n\
jvJTSq11VN4QCJszsImx1iJud8cjf+bi\n\
-----END CERTIFICATE-----";

static const uint8_t key_bl32[] =
"-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDcSKktaN/UflBP\n\
Fyx39FCOhAHFYGhPNUGOkb/q1eK/ChZSOKqM0PH+7XJdRdXicMALBOkhbjOykyGq\n\
K1UmBHFsiXnKa/zwiURkJs//mrJAoIlHelz7cyZ/aDTwFQ+cDRPPLI9McffZYIxV\n\
4wD/MzkMDe7vo2/bPXrK+HvQrgm9pyc7s2k0Ivs866SlOffnIVPsALm18SjDruRe\n\
BPJbRVuj0lHPJ38rhBYLi3gW5faYYrfJE01o6lr57TACUiiI1p/ZSR5mE9q4IDyM\n\
4BuWe/Tg6kF2Y4btDzjytbZ2XyFnTK6hK3B9EiEWXI4SoQmCZhhlv3ZJvoWAPGY9\n\
BKoPOKqdAgMBAAECggEAAJ9m9QUnHtFlljelTUiAQsreO2nYmaK3pvjD/1yv6aTU\n\
Z9KXrtK3YGZY7KkSH/P8IvvWUd0fIcnXLkU1ligsjuc7lCYmfqKQsizG6TzNdK/P\n\
e4d9xEswyGrpvWT92I3T6MHCPO/UiMWEWAjOe6owJtfSPVSrsAW2N2Uo6m/XgLT7\n\
KGCaU1RiZvzrbdvDMEMAJ4mC+udjPaQCUHiU5HoRRjZlkyxwDD73HNN5zjd8UQ3X\n\
cCOn4h6q4icMWBlaOn8wILJR565yeKvAr0uTg+cn8XHCMAHh2GXbUxH5j35WmCkS\n\
6ueGuwvdPCsU0uXS4w6FlcIDNs0SNJ+dvsQ2r/w/SQKBgQDzNH/IkW0n3zLfqtYY\n\
cozcnC1UJ0ukItHDiEQKlquL83m4HHKgj3D+I1vnGsK+j1yum0WzS3OjHhbDxpuG\n\
sW4hPIN4PENOFKvept6wkH/QW0Vi7mvQkeaLR7mlu3Zk/0R6qOvZa2S8lTzTdu+K\n\
Z2DQHdTx0O+uw8SSvRA31YhatQKBgQDn33T8+Mo74I8UvrP1iFs7feP0s8uql4k9\n\
MRqSswlmRr0VSEgVSXyo83bmDVrLf/7KrHbbB6DcumusomT98niPWtuej5b9Gf1g\n\
QCkQiWAy5LewNwd2ZqBAmPOX2y212BSIS+6Ptq9sD16d9lmyZs6ANSAbA0vkocRb\n\
x98XFuK5SQKBgQCUJxAMq2J2XoZMMHKZk/ZxUYZfdEyk4T0tQu5IEP7Rk3E7kcDW\n\
RGtNtVZ/0xJ9KTIJf7cXAMihvmuZuXv2slFnV8iyzuslPnxwdvDDWFM0JtV+7cSp\n\
2qc5g2j5J9h4r/QUUKDT4pMMOlFCdHp5sn4MaY/V+zR3HvS5ewjNKnwU3QKBgQCb\n\
yJ7x4zkEN6AJwQJpQT6CXtdLrYx1RbBX42jGDPGQvJAG/3QmkSPm4wQMFgbdWFZX\n\
1r1X9O0Xv0veRZDyqPhk4BdTlYdM7ywzgYfVa2atassa4i3qV5LtM5Xdfc1dMhrB\n\
Y7qY5ZVAVactG7kxyi6NJqQ2YeWYazLgsw1oluCmuQKBgQDOIs2hzOd4p3NqX3ly\n\
4dkroCbrNTfd0uGgeRquYH7Hf7yAr/+VcgM3t27L6GpsJgq2snY6NylR3Jvazbwl\n\
ZUyz+ZupSR3EfZLJVj3L1Ykasm3dg6p3A8xyqoMk3dUfD+b4uWhPR/ffevM6s3t7\n\
/z7Nq74ynvslHU8tE2ZWpiURBg==\n\
-----END PRIVATE KEY-----";

#endif /* __PTA_ATTESTATION_H */
