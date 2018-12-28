MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(OPTIONAL_CRYPTO_CFLAGS)

if ENABLE_PLUGIN_OBFS_TEST
plugin_LTLIBRARIES = openvpn-plugin-obfs-test.la
endif

openvpn_plugin_obfs_test_la_SOURCES = \
	obfs-test.c \
	obfs-test-munging.c \
	obfs-test-args.c \
	obfs-test.exports

if WIN32
openvpn_plugin_obfs_test_la_SOURCES += obfs-test-win32.c
openvpn_plugin_obfs_test_la_LIBADD = -lws2_32 -lwininet
else !WIN32
openvpn_plugin_obfs_test_la_SOURCES += obfs-test-posix.c
# No LIBADD necessary; we assume we can access the global symbol space,
# and core OpenVPN will already link with everything needed for sockets.
endif

openvpn_plugin_obfs_test_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/obfs-test.exports" \
	-module -shared -avoid-version -no-undefined
