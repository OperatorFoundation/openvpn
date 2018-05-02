MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	$(PLUGIN_U2F_CLIENT_CFLAGS) \
	$(OPTIONAL_CRYPTO_CFLAGS)

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(PLUGIN_U2F_CLIENT_CFLAGS) \
	$(OPTIONAL_CRYPTO_CFLAGS)

if ENABLE_PLUGIN_U2F_CLIENT
plugin_LTLIBRARIES = openvpn-plugin-u2f-client.la
sbin_PROGRAMS = openvpn-2fclient
endif

openvpn_2fclient_SOURCES = \
	process-2fclient.c \
	comm-2fclient.c
openvpn_2fclient_LDADD = \
	$(SOCKETS_LIBS)

# Blessed workaround to give non-libtool compilation of
# comm-2fclient.c a different object basename.
openvpn_2fclient_CFLAGS = $(AM_CFLAGS)

openvpn_plugin_u2f_client_la_SOURCES = \
	plugin-u2f-client.c \
	comm-2fclient.c \
	u2f-client.exports
openvpn_plugin_u2f_client_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/u2f-client.exports" \
	-module -shared -avoid-version -no-undefined
