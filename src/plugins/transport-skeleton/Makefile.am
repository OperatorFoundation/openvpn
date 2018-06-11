MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(OPTIONAL_CRYPTO_CFLAGS)

if ENABLE_PLUGIN_transport_skeleton
plugin_LTLIBRARIES = openvpn-plugin-transport-skeleton.la
endif

openvpn_plugin_transport_skeleton_la_SOURCES = \
	transport-skeleton.c \
	transport-skeleton.exports

if WIN32
openvpn_plugin_transport_skeleton_la_SOURCES += transport-skeleton-win32.c
openvpn_plugin_transport_skeleton_la_LIBADD = -lws2_32 -lwininet
else !WIN32
openvpn_plugin_transport_skeleton_la_SOURCES += transport-skeleton-posix.c
# No LIBADD necessary; we assume we can access the global symbol space,
# and core OpenVPN will already link with everything needed for sockets.
endif

openvpn_plugin_transport_skeleton_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/transport-skeleton.exports" \
	-module -shared -avoid-version -no-undefined
