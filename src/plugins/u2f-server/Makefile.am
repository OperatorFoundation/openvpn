MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(PLUGIN_U2F_SERVER_CFLAGS) \
	$(OPTIONAL_CRYPTO_CFLAGS)

if ENABLE_PLUGIN_U2F_SERVER
plugin_LTLIBRARIES = openvpn-plugin-u2f-server.la
endif

openvpn_plugin_u2f_server_la_SOURCES = \
	u2f-server.c \
	u2f-server.exports
openvpn_plugin_u2f_server_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/u2f-server.exports" \
	-module -shared -avoid-version -no-undefined
