include core/lib/asn1c_generations/Makefile.am.libasncodec

global-incdirs-y += .
cflags$(sm) += $(ASN_MODULE_CFLAGS)
srcs-y += $(ASN_MODULE_SRCS)
