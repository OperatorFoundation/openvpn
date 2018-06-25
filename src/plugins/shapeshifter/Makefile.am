MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(OPTIONAL_CRYPTO_CFLAGS)

if ENABLE_PLUGIN_shapeshifter
plugin_LTLIBRARIES = openvpn-plugin-shapeshifter.la
endif

openvpn_plugin_shapeshifter_la_SOURCES = \
	shapeshifter.c \
	shapeshifter.exports

if WIN32
openvpn_plugin_shapeshifter_la_SOURCES += shapeshifter-win32.c
openvpn_plugin_shapeshifter_la_LIBADD = -lws2_32 -lwininet
else !WIN32
openvpn_plugin_shapeshifter_la_SOURCES += shapeshifter-posix.c
# No LIBADD necessary; we assume we can access the global symbol space,
# and core OpenVPN will already link with everything needed for sockets.
endif

openvpn_plugin_shapeshifter_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/shapeshifter.exports" \
	-module -shared -avoid-version -no-undefined
