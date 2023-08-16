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
MIIDZzCCAk+gAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MRUwEwYDVQQDDAxNYW51\n\
ZmFjdHVyZXIxFTATBgNVBAoMDENvb2wgY29tcGFueTEMMAoGA1UEBhMDR0VSMCAX\n\
DTIzMDcyNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA1MQwwCgYDVQQDDANCTDEx\n\
FzAVBgNVBAoMDkFQIFRydXN0ZWQgUk9NMQwwCgYDVQQGEwNHRVIwggEiMA0GCSqG\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCgxgP2su+h8lbK5EXvytKpOSe16wE9vluL\n\
2mHXTaX1ctBlCD9KudIshaNOHipljxbATJkYcMwm8KbmP7pM+m76+GALfDjRaMSo\n\
csyHEvW+xtOvBYQKqRwuLlRcN5o+nBy0vdiwAyEPHI+F1E1QsMiLUldLuMasdecg\n\
pqWx6QTqp4scg25zKmDaCzc3wQp0PcQ5HvBE+GivhdD6dUUo5Nq7WEQxUzfGY3x4\n\
8os529XlCr53MSIdElWBZ+8SMZonQIAPG86rY2ovyTGBcICniGNSa4rOY4oVpQcm\n\
pJjO0gXLVBFhffWCc4Ik+6vD/JPVL29+zFGN2Eq9Al41phkif0/9AgMBAAGjeTB3\n\
MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK6Nmxq4+MIXc3yI92hpgJFQq0Yb\n\
MB8GA1UdIwQYMBaAFOvOk3cAoR3rWpt8BNndXgzkEM/0MA4GA1UdDwEB/wQEAwIC\n\
BDAUBgNVHSAEDTALMAkGB2eBBQUEZAYwDQYJKoZIhvcNAQELBQADggEBAGwmzcR0\n\
nyEf1QbrHKPT7XV437VmavMUQd1Hd4Gilnw4zItlEz0DmZg5n2dZg1mDDp5EO8dW\n\
RKzOqln8WJN8PSKgDe8qWQEfJQanblM6Hd7gwv5lRcSJkm0lMaQqjl86XBPMC3nx\n\
UwZAUH3CokP5uPG85Hm7QtjY5avNIhG3o1UlkeH3RXIBaAqXE8yE1NAwE1zhKqJb\n\
NcIO6W8g//VOKBrPAI1hU36ev1qdXu2w83n300vPuGum1VQy53N8pAt63KnaXB6Y\n\
/GWbZoAvo6/CzVrhQzgloVSaB6KIeFVjcMRkCr9+YDCWkyYJaUvJ5+6klb3zN58t\n\
Y7MsVQmG9Hoib4k=\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl2[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDqDCCApCgAwIBAgIBATANBgkqhkiG9w0BAQsFADA1MQwwCgYDVQQDDANCTDEx\n\
FzAVBgNVBAoMDkFQIFRydXN0ZWQgUk9NMQwwCgYDVQQGEwNHRVIwIBcNMjMwNzI1\n\
MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDwxDDAKBgNVBAMMA0JMMjEeMBwGA1UE\n\
CgwVVHJ1c3RlZCBCb290IEZpcm13YXJlMQwwCgYDVQQGEwNHRVIwggEiMA0GCSqG\n\
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMSSOIRY50/HAQumplWSok6Mrqaw7fpeVg\n\
8kZqVMls2VF7MvgWpZCA1+9FI5ViIkDgNI1cuBOmgzd+ZATtLuhg7UAQQjzaTYYQ\n\
6Hz9YxRucFDk8R0mPGbADHCfBv7msPkL2tQMUgvFikMhSucbDerY8igBgt83PeB5\n\
uikKn7ZhDCjbOsM+zFf6mC5+zJGGNUO30uyB4vpIgzmU00nExU7pws07IcQBYHwV\n\
bI7b+yu6RxD8PmAhh7+ps9G4mEelUDXyoTSG0K4qlqqpMu9o9tcQlk6W4wgxEXa3\n\
lAbq58nayvs6i1QAvD/NcgTPo3L9Qx0EVWYDJZBjainQpSwy5pRjAgMBAAGjgbkw\n\
gbYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUmOU7mLY1fZc4v5PDzYT2e82B\n\
vtcwHwYDVR0jBBgwFoAUro2bGrj4whdzfIj3aGmAkVCrRhswDgYDVR0PAQH/BAQD\n\
AgIEMBQGA1UdIAQNMAswCQYHZ4EFBQRkBzA9BgZngQUFBAEEMzAxpi8wLQYJYIZI\n\
AWUDBAIBBCDhEsWQtS/h8u8Ixt8YMrNcTMVyXCUKuuvNdIqTglloizANBgkqhkiG\n\
9w0BAQsFAAOCAQEAcHMh3MWr7IRlRq9ipC9F0n+oem/vc42fos2n2V0fzGCSq8CO\n\
H6UsqFiYaW1n3a9++AH5BJ+2KXtXrgVpeVKql/J9j0/lWEA8yI8psMITbzs9oogw\n\
/aiPLKD/HlgqxZyzKZuHDJUASxd+J3FSD0hJ7Q8NTQI0XCWfjiSiAelstXbg+9hJ\n\
eTGSQVfXD5YraQ1sH1hWZShlCXtVNLPu86MtEnkddnT3/07jLCdECkTaY17WdMFl\n\
8kCfafOZ+w24tX3FqfSg2KhvZiEQ40Z5a7IBH/88XItD3KpLdVZt0ALvAYU1xg4y\n\
TWkFhbD6DCnixWzD0t4zMYpuXU1Mk406SluP7w==\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl31[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDrzCCApegAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQwwCgYDVQQDDANCTDIx\n\
HjAcBgNVBAoMFVRydXN0ZWQgQm9vdCBGaXJtd2FyZTEMMAoGA1UEBhMDR0VSMCAX\n\
DTIzMDcyNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjA8MQ0wCwYDVQQDDARCTDMx\n\
MR0wGwYDVQQKDBRFTDMgUnVudGltZSBTb2Z0d2FyZTEMMAoGA1UEBhMDR0VSMIIB\n\
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoZ38sbmmH2vWdq3zhvPIgDLr\n\
f4jzVaRE4IfLmqj52N2Y6TVPrkRBGdlc1UxvC7+QIruQrhWuKe3nomYQQGRqQa9r\n\
d+Zb6lmK0yRZ2lQDfZXylpFCBurQenkjuhHua3sEhLgKikg+0bsCKN9e4FIHo6qj\n\
teybC+9Vf8ZnEaTFeGIXc3KP/sXvdUbqA2fYrP2SjahMwn+ExPRy9LG93dPgT+9U\n\
MJ+zHBDTbR9go6oANPKHronsVPV6l3na8xS1Flq99M/5eCDqDNOXAf1PmTzEtsDZ\n\
sWIumag7VLU9ymMPoV+Zabs+xYh1qaKfIVge+6ORt4RqdC/vUmGh9kt6AQxwOwID\n\
AQABo4G5MIG2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCzfjEHIPjwMgcCN\n\
b3xTNVWxYERzMB8GA1UdIwQYMBaAFJjlO5i2NX2XOL+Tw82E9nvNgb7XMA4GA1Ud\n\
DwEB/wQEAwICBDAUBgNVHSAEDTALMAkGB2eBBQUEZAcwPQYGZ4EFBQQBBDMwMaYv\n\
MC0GCWCGSAFlAwQCAQQgPzi/cSEgktf6qkVbG/yOcA1QA5oI0xgx0DsyVG8lX4cw\n\
DQYJKoZIhvcNAQELBQADggEBABWILohbTcRJAsqDai7LIlAmqAmb02bXkZ9rmYyN\n\
EpnHf/55YDAaaKLz4PQXK4sJQPRHDOD7kDRBLsp2LEGySAbk9oEEGyTd+xzLe9K3\n\
7U7/iIEW4z6eCdWMgp3wX8/XVANZJFTAB54mlO7eXwKJiyIJXNCVAym1c68vobQe\n\
Egdr6mbmsKCURyFcZ5Aj+tyE3W5Cueiyv/7P7mpuklFyS2jihMreyHDYKIvx2n//\n\
y+wgJJJG0hT3QIVH81cgxQBPOF7ORrpimjT7fnwUBgcUUG52q0eLx1e1+qzHR9Lq\n\
dxjzZEmqoip0AWSmDsWqGVabdosgjFkvkpXHS4wjtw1pXWA=\n\
-----END CERTIFICATE-----";

static const uint8_t crt_bl32[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQ0wCwYDVQQDDARCTDMx\n\
MR0wGwYDVQQKDBRFTDMgUnVudGltZSBTb2Z0d2FyZTEMMAoGA1UEBhMDR0VSMCAX\n\
DTIzMDcyNTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAxMQ0wCwYDVQQDDARCTDMy\n\
MRIwEAYDVQQKDAlPUC1URUUgT1MxDDAKBgNVBAYTA0dFUjCCASIwDQYJKoZIhvcN\n\
AQEBBQADggEPADCCAQoCggEBAI2ExPnRAbkY+D15u8p5jiUW8sCxCDjN1znVdnX4\n\
QJB72YZbF2NxPa5Oe2/SzPV24+4tt0TjIODHYXglMmY6NTR50E5jF3053k/z6Q60\n\
fjks2u/cAOi3JT/cZ2kteJIjbWi2pk1El8tusV1u0CKLb9dTPCkCturkBtUMNa7j\n\
59S4211Rkxd/hqKZbimfLlg2aU2ufnLjSMZKgpNc552XSAzGbkXyO1Of/nywZhJH\n\
2u1Mcxu78pcLn+nTdwIFFl3eh7tSM5Zqshf+2B9cvrh3uceIIDGL7/d5fYgEkyxT\n\
YJ/VouOjAUrwcJ+JLRooJP7iJevRmaWQzIRgmaL9i4FS83kCAwEAAaOBuTCBtjAP\n\
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQArrhmFQ6k0z0N/UrUMibSKdoMnzAf\n\
BgNVHSMEGDAWgBQs34xByD48DIHAjW98UzVVsWBEczAOBgNVHQ8BAf8EBAMCAgQw\n\
FAYDVR0gBA0wCzAJBgdngQUFBGQHMD0GBmeBBQUEAQQzMDGmLzAtBglghkgBZQME\n\
AgEEIMj0I4uxct2ZChbjG5UaarrLduN7qXDZFoZkZW63etMjMA0GCSqGSIb3DQEB\n\
CwUAA4IBAQAt+9yeMZJ6NRk7/U5JiXf3WWGultloVRTnUD6WXdwfwETE1BajVQ1i\n\
7eD7DJKx9kw2cZAR8xsx/nqVW0wlXfm7Ux6pvOPxaUlepbHs/KCNaqo9uT51BtCh\n\
J0xIvl+sQ8HfTLryBLMAOJP1HwVSw2+MrysCbJbyida2uc+tOqse29yG50yHxjfe\n\
Fgogc3299lgQ1edSW3lNDwNxGDUPcnTUBFxBdQ/SCHAJdEKSz8BciVKT9WbmTKLx\n\
8ZYEr4CncrHC1XcukRkDZvdswcE/GeiQpje9gltMhLxv866PLA2XcIL5jhFAj1RQ\n\
Yl7DQFdOpnMFH/L/ZyNuXHWTKX6gwZ3r\n\
-----END CERTIFICATE-----";

static const uint8_t key_bl32[] =
"-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCNhMT50QG5GPg9\n\
ebvKeY4lFvLAsQg4zdc51XZ1+ECQe9mGWxdjcT2uTntv0sz1duPuLbdE4yDgx2F4\n\
JTJmOjU0edBOYxd9Od5P8+kOtH45LNrv3ADotyU/3GdpLXiSI21otqZNRJfLbrFd\n\
btAii2/XUzwpArbq5AbVDDWu4+fUuNtdUZMXf4aimW4pny5YNmlNrn5y40jGSoKT\n\
XOedl0gMxm5F8jtTn/58sGYSR9rtTHMbu/KXC5/p03cCBRZd3oe7UjOWarIX/tgf\n\
XL64d7nHiCAxi+/3eX2IBJMsU2Cf1aLjowFK8HCfiS0aKCT+4iXr0ZmlkMyEYJmi\n\
/YuBUvN5AgMBAAECggEACMynnszzKXo2/UOTfKyAPSgnIfogA8Aw0MTIH9+2zAUX\n\
anZBhwpkhnEU1cgqvFyPIaEwExV4VuGu2tSdRKP76O5mGGmq7Ttq6lfFNwfcDVwP\n\
pPhuCgpRQ55Fw9Fy/Ms9I1SwFH/eXGTenGumf29iHeZsCDTGAOb60cZ3lA9Ru/VG\n\
6o95ZEol70SgpcbVkbJ8MP87agS1IVc8GDA/pv4fRqbe+GGqC8zO4WufpRhMwVY8\n\
T1SdIs6qrwEXXvp91XT1jaTNUSREn4yIyeP4TcptPPABKAsXUwhDrtlJRJITZXoo\n\
WiGKhmrwnAiZeiCP/EcWxj62AxWLoDApc1jlxlzYgQKBgQDAhS2/vlYUzXp0NBDI\n\
BqBRL3yg0Orghxjr/qSmnzzNG0FlLsJyg3W0xmfF66pVlFY5RZg2L9DKKrce/4fJ\n\
dz1tZb9D75nrrUyHmMvn2VPmIl3Ns83ixHRG2U1/pCXNVbszQo8mhrDbh3L466js\n\
7FtzPRDulbm/29k5ooDCN3YLsQKBgQC8Ln7rrN6sGvGfyLvcdCKSRtBnIm8RnLZ+\n\
DcGf1vpojP6+4b9+l1IC9cPg4BHQYUFB98ETcr0Y3HZ4S7+m/bKxQgOUH5Xs8C7+\n\
xHXwdIw8OJfw3Nbn8CQDqfFOF1P2MxNZDtWeletWFc/fs/3MZ8VkIlCT1KBplsN0\n\
o20SthD+SQKBgH5tdzO6LRGQNuBk6LhTEaj/BFsfl39HeOhR25LIc8dGJNXrtSo6\n\
hmvm93MUZlG5Dj6iI2lCUVzSXFtw950oPyC+drKIgI4yylUp1I43PE+fNfbGI2jO\n\
FoYIYkp2Y5TKvhrVlOh5/17LPoeVSuP7+7pb2ei0Tr1eBPNCckgY396hAoGAcNS0\n\
Fx0kui7Bl5ulQE6F+AzrohscW4QKS9R1tyAQLqXzjIIQ7pdOfiXb17aiF75ogWRK\n\
6R1P0ltF0WUhub+959h8CtFRdKqikvE7AfzvpKAOQkY3uQPcpDG+VKNaHXGMdUaW\n\
wSqE263iYPAsCeZijWKhy7GeqRDTitj+akyuLbkCgYEAwCjxvEKl406rMx0inTQp\n\
XOrY9imIKd+2AzM3FboWZ9bp7GUyWzv21y2Xcr/0hawPOcMAixxJWy75cEzqMICm\n\
dPyu9B1fOROompKjagG4gbO87WC4yQNiz+sgI2ukVlWUZ06sMpr1Q72X0Sz92NYe\n\
hYNwVn9npDi5dC/4SxTiDH4=\n\
-----END PRIVATE KEY-----";

#endif /* __PTA_ATTESTATION_H */
