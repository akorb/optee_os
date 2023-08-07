/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "AliasCertExtension"
 * 	found in "attestation.asn1"
 * 	`asn1c -D gen -no-gen-OER -no-gen-PER -no-gen-example`
 */

#include "DiceTcbInfo.h"

static asn_TYPE_member_t asn_MBR_DiceTcbInfo_1[] = {
	{ ATF_POINTER, 10, offsetof(struct DiceTcbInfo, vendor),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTF8String,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"vendor"
		},
	{ ATF_POINTER, 9, offsetof(struct DiceTcbInfo, model),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTF8String,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"model"
		},
	{ ATF_POINTER, 8, offsetof(struct DiceTcbInfo, version),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_UTF8String,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"version"
		},
	{ ATF_POINTER, 7, offsetof(struct DiceTcbInfo, svn),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"svn"
		},
	{ ATF_POINTER, 6, offsetof(struct DiceTcbInfo, layer),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"layer"
		},
	{ ATF_POINTER, 5, offsetof(struct DiceTcbInfo, index),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_NativeInteger,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"index"
		},
	{ ATF_POINTER, 4, offsetof(struct DiceTcbInfo, fwids),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_FWIDLIST,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fwids"
		},
	{ ATF_POINTER, 3, offsetof(struct DiceTcbInfo, flags),
		(ASN_TAG_CLASS_CONTEXT | (7 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OperationalFlags,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"flags"
		},
	{ ATF_POINTER, 2, offsetof(struct DiceTcbInfo, vendorInfo),
		(ASN_TAG_CLASS_CONTEXT | (8 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"vendorInfo"
		},
	{ ATF_POINTER, 1, offsetof(struct DiceTcbInfo, type),
		(ASN_TAG_CLASS_CONTEXT | (9 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_OCTET_STRING,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"type"
		},
};
static const ber_tlv_tag_t asn_DEF_DiceTcbInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DiceTcbInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* vendor */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* model */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* svn */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* layer */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* index */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 }, /* fwids */
    { (ASN_TAG_CLASS_CONTEXT | (7 << 2)), 7, 0, 0 }, /* flags */
    { (ASN_TAG_CLASS_CONTEXT | (8 << 2)), 8, 0, 0 }, /* vendorInfo */
    { (ASN_TAG_CLASS_CONTEXT | (9 << 2)), 9, 0, 0 } /* type */
};
static asn_SEQUENCE_specifics_t asn_SPC_DiceTcbInfo_specs_1 = {
	sizeof(struct DiceTcbInfo),
	offsetof(struct DiceTcbInfo, _asn_ctx),
	asn_MAP_DiceTcbInfo_tag2el_1,
	10,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DiceTcbInfo = {
	"DiceTcbInfo",
	"DiceTcbInfo",
	&asn_OP_SEQUENCE,
	asn_DEF_DiceTcbInfo_tags_1,
	sizeof(asn_DEF_DiceTcbInfo_tags_1)
		/sizeof(asn_DEF_DiceTcbInfo_tags_1[0]), /* 1 */
	asn_DEF_DiceTcbInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_DiceTcbInfo_tags_1)
		/sizeof(asn_DEF_DiceTcbInfo_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_DiceTcbInfo_1,
	10,	/* Elements count */
	&asn_SPC_DiceTcbInfo_specs_1	/* Additional specs */
};

