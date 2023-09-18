include core/lib/alias_cert_extension/Makefile.am.libasncodec

global-incdirs-y += .
cflags$(sm) += $(ASN_MODULE_CFLAGS)
srcs-y += $(ASN_MODULE_SRCS)
