include core/lib/asn1c_generations/Makefile.am.libasncodec

global-incdirs-y += .
cflags$(sm) += $(ASN_MODULE_CFLAGS)
#cflags$(sm) += -D__STDC_FORMAT_MACROS
#cflags-remove-y += -Wsuggest-attribute=format
srcs-y += $(ASN_MODULE_SRCS)
# cppflags-y += $(ASN_MODULE_CFLAGS)
