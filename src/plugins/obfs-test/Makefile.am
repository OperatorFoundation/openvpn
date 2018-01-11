MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(OPTIONAL_CRYPTO_CFLAGS)

if ENABLE_PLUGIN_OBFS_TEST
plugin_LTLIBRARIES = openvpn-plugin-obfs-test.la
endif

if WIN32
openvpn_plugin_obfs_test_la_LIBADD = -lws2_32 -lwininet
endif

openvpn_plugin_obfs_test_la_SOURCES = \
	obfs-test.c \
	obfs-test-munging.c \
	obfs-test-posix.c \
	obfs-test-win32.c \
	obfs-test.exports
openvpn_plugin_obfs_test_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/obfs-test.exports" \
	-module -shared -avoid-version -no-undefined
