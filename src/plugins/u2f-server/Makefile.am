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

# If you ever would remove the openvpn_2fserver_CFLAGS line, instead
# replace it with an assignment from $(AM_CFLAGS); this is the blessed
# workaround to give non-libtool compilation of comm-2fserver.c a
# different object basename, which is necessary to let the plugin and
# subprocess share that source file.

openvpn_2fserver_SOURCES = \
	2fserver-main.c \
	2fserver-http.c \
	2fserver-model.c \
	2fserver-support.c \
	u2fdbt.c \
	comm-2fserver.c
openvpn_2fserver_CFLAGS = \
	$(AM_CFLAGS) $(LIBMICROHTTPD_CFLAGS)
# TODO: is -lcrypt always right? Move this to autoconf.
openvpn_2fserver_LDADD = \
	$(SOCKETS_LIBS) $(LIBMICROHTTPD_LIBS) -lcrypt

openvpn_plugin_u2f_server_la_SOURCES = \
	plugin-u2f-server.c \
	comm-2fserver.c \
	u2f-server.exports
openvpn_plugin_u2f_server_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/u2f-server.exports" \
	-module -shared -avoid-version -no-undefined
