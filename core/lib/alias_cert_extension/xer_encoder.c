/*-
 * Copyright (c) 2003, 2004 Lev Walkin <vlm@lionet.info>. All rights reserved.
 * Redistribution and modifications are permitted subject to BSD license.
 */
#include <asn_internal.h>
#include <stdio.h>

/*
 * The XER encoder of any type. May be invoked by the application.
 */
asn_enc_rval_t
xer_encode(const asn_TYPE_descriptor_t *td, const void *sptr,
           enum xer_encoder_flags_e xer_flags, asn_app_consume_bytes_f *cb,
           void *app_key) {
    asn_enc_rval_t er = {0, 0, 0};
	asn_enc_rval_t tmper;
	const char *mname;
	size_t mlen;
	int xcan = (xer_flags & XER_F_CANONICAL) ? 1 : 2;

	if(!td || !sptr) goto cb_failed;

	mname = td->xml_tag;
	mlen = strlen(mname);

	ASN__CALLBACK3("<", 1, mname, mlen, ">", 1);

	tmper = td->op->xer_encoder(td, sptr, 1, xer_flags, cb, app_key);
	if(tmper.encoded == -1) return tmper;
	er.encoded += tmper.encoded;

	ASN__CALLBACK3("</", 2, mname, mlen, ">\n", xcan);

	ASN__ENCODED_OK(er);
cb_failed:
	ASN__ENCODE_FAILED;
}

struct xer_buffer {
    char *buffer;
    size_t buffer_size;
    size_t allocated_size;
};

static int
xer__buffer_append(const void *buffer, size_t size, void *app_key) {
    struct xer_buffer *xb = app_key;

    while(xb->buffer_size + size + 1 > xb->allocated_size) {
        size_t new_size = 2 * (xb->allocated_size ? xb->allocated_size : 64);
        char *new_buf = MALLOC(new_size);
        if(!new_buf) return -1;
        if (xb->buffer) {
            memcpy(new_buf, xb->buffer, xb->buffer_size);
        }
        FREEMEM(xb->buffer);
        xb->buffer = new_buf;
        xb->allocated_size = new_size;
    }

    memcpy(xb->buffer + xb->buffer_size, buffer, size);
    xb->buffer_size += size;
    xb->buffer[xb->buffer_size] = '\0';
    return 0;
}

enum xer_equivalence_e
xer_equivalent(const struct asn_TYPE_descriptor_s *td, const void *struct1,
               const void *struct2) {
    struct xer_buffer xb1 = {0, 0, 0};
    struct xer_buffer xb2 = {0, 0, 0};
    asn_enc_rval_t e1, e2;
    asn_dec_rval_t rval;
    void *sptr = NULL;

    if(!td || !struct1 || !struct2) {
        if(!td) DMSG("Type descriptor missing");
        if(!struct1) DMSG("Structure 1 missing");
        if(!struct2) DMSG("Structure 2 missing");
        return XEQ_FAILURE;
    }

    e1 = xer_encode(td, struct1, XER_F_BASIC, xer__buffer_append, &xb1);
    if(e1.encoded == -1) {
        EMSG("XER Encoding of %s failed", td->name);
        FREEMEM(xb1.buffer);
        return XEQ_ENCODE1_FAILED;
    }

    e2 = xer_encode(td, struct2, XER_F_BASIC, xer__buffer_append, &xb2);
    if(e2.encoded == -1) {
        EMSG("XER Encoding of %s failed", td->name);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ENCODE1_FAILED;
    }

    if(xb1.buffer_size != xb2.buffer_size
       || memcmp(xb1.buffer, xb2.buffer, xb1.buffer_size) != 0) {
            DMSG("Structures XER-encoded into different byte streams:\n=== "
                    "Structure 1 ===\n%s\n=== Structure 2 ===\n%s",
                    xb1.buffer, xb2.buffer);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_DIFFERENT;
    } else {
        EMSG("Both structures encoded into the same XER byte stream "
            "of size %" ASN_PRI_SIZE ":\n%s",
            xb1.buffer_size, xb1.buffer);
    }

    rval = xer_decode(NULL, td, (void **)&sptr, xb1.buffer,
               xb1.buffer_size);
    switch(rval.code) {
    case RC_OK:
        break;
    case RC_WMORE:
        EMSG("Structure %s XER decode unexpectedly requires "
            "more data:\n%s",
            td->name, xb1.buffer);
        /* Fall through */
    case RC_FAIL:
    default:
        EMSG("Structure %s XER decoding resulted in failure.",
                td->name);
        ASN_STRUCT_FREE(*td, sptr);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_DECODE_FAILED;
    }

    if(rval.consumed != xb1.buffer_size
       && ((rval.consumed > xb1.buffer_size)
           || xer_whitespace_span(xb1.buffer + rval.consumed,
                                  xb1.buffer_size - rval.consumed)
                  != (xb1.buffer_size - rval.consumed))) {
        DMSG("Round-trip decode of %s required less bytes (%" ASN_PRI_SIZE ") than "
            "encoded (%" ASN_PRI_SIZE ")",
            td->name, rval.consumed, xb1.buffer_size);
        ASN_STRUCT_FREE(*td, sptr);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ROUND_TRIP_FAILED;
    }

    /*
     * Reuse xb2 to encode newly decoded structure.
     */
    FREEMEM(xb2.buffer);
    memset(&xb2, 0, sizeof(xb2));

    e2 = xer_encode(td, sptr, XER_F_BASIC, xer__buffer_append, &xb2);
    if(e2.encoded == -1) {
        EMSG("XER Encoding of round-trip decode of %s failed",
                td->name);
        ASN_STRUCT_FREE(*td, sptr);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ROUND_TRIP_FAILED;
    }

    ASN_STRUCT_FREE(*td, sptr);
    sptr = 0;

    if(xb1.buffer_size != xb2.buffer_size
       || memcmp(xb1.buffer, xb2.buffer, xb1.buffer_size) != 0) {
        DMSG("XER Encoding of round-trip decode of %s resulted in "
                "different byte stream:\n"
                "=== Original ===\n%s\n"
                "=== Round-tripped ===\n%s",
                xb1.buffer, xb2.buffer, td->name);
        FREEMEM(xb1.buffer);
        FREEMEM(xb2.buffer);
        return XEQ_ROUND_TRIP_FAILED;
    }

	FREEMEM(xb1.buffer);
	FREEMEM(xb2.buffer);
	return XEQ_SUCCESS;
}

