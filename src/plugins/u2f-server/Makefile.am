MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(PLUGIN_U2F_SERVER_CFLAGS) \
	$(OPTIONAL_CRYPTO_CFLAGS)

if ENABLE_PLUGIN_U2F_SERVER
plugin_LTLIBRARIES = openvpn-plugin-u2f-server.la
sbin_PROGRAMS = openvpn-2fserver
endif

openvpn_2fserver_SOURCES = \
	process-2fserver.c \
	comm-2fserver.c
openvpn_2fserver_LDADD = \
	$(SOCKETS_LIBS)

# Blessed workaround to give non-libtool compilation of
# comm-2fserver.c a different object basename.
openvpn_2fserver_CFLAGS = $(AM_CFLAGS)

openvpn_plugin_u2f_server_la_SOURCES = \
	plugin-u2f-server.c \
	comm-2fserver.c \
	u2f-server.exports
openvpn_plugin_u2f_server_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/u2f-server.exports" \
	-module -shared -avoid-version -no-undefined
