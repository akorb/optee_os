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
    const uint8_t *subject_alt_name;
    size_t subject_alt_name_len;
    const uint8_t *certificate_policy_val;
    const uint8_t *fwid; /* Trused Componentent Identifier aka Firmware ID (FWID)*/
} cert_info;

/*
Generated via https://kjur.github.io/jsrsasign/tool/tool_asn1encoder.html with:

{
    "seq": [
        {
            "seq": [
                {
                    "oid": {
                        "oid": "2.23.133.5.4.100.9"
                    }
                }
            ]
        }
    ]
}
*/
static const uint8_t certificate_policy_attestation[] = {0x30, 0x0b, 0x30, 0x09, 0x06, 0x07, 0x67, 0x81, 0x05, 0x05, 0x04, 0x64, 0x09};

// SHA256, 256 Bits = 32 Bytes
#define FWID_LEN (256 / 8)
#define CERTIFICATE_POLICY_VAL_LEN sizeof(certificate_policy_attestation)

static const char dice_attestation_oid[] = {0x67, 0x81, 0x05, 0x05, 0x04, 0x01};

#ifdef CFG_DFL_NOT_BEFORE
#define DFL_NOT_BEFORE CFG_DFL_NOT_BEFORE
#else
#define DFL_NOT_BEFORE "20230725000000"
#endif
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

#define COUNT_OF_BYTES(array) sizeof((char[]){ array })

// "id:44494345", where 44494345 is ASCII for "DICE"
// Generated with command `echo -n "id:44494345" | xxd -i`
#define SUB_ALT_TPM_MANUFACTURER 0x69, 0x64, 0x3a, 0x34, 0x34, 0x34, 0x39, 0x34, 0x33, 0x34, 0x35
// "firmware"
#define SUB_ALT_TPM_MODEL 0x46, 0x57
// It is a TPM 2 model. But only major version specified. Minor version is written to be 0, but must be derived from TCI
// "id:00020000"
#define SUB_ALT_TPM_VERSION 0x69, 0x64, 0x3a, 0x30, 0x30, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30

#define MBEDTLS_EXIT_SUCCESS 0
#define MBEDTLS_EXIT_FAILURE 1

#define MAX_CERT_SIZE 2048

#endif /* __PTA_ATTESTATION_H */
