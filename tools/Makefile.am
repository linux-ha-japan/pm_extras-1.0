MAINTAINERCLEANFILES = Makefile.in

INCLUDES		= -I/usr/include/pacemaker \
			-I/usr/include/glib-2.0 \
			-I$(libdir)/glib-2.0/include \
			-I/usr/include/libxml2

halibdir		= $(CRM_DAEMON_DIR)
halib_PROGRAMS		= ifcheckd

plugindir		= $(libdir)
plugin_LTLIBRARIES	= iface_check.la

# BUILD

ifcheckd_SOURCES	= ifcheckd.c
ifcheckd_LDADD		= -lcrmcommon \
			  -lcib \
			  -lcrmcluster

iface_check_la_SOURCES	= iface_check.c
iface_check_la_LDFLAGS	= -export-dynamic -module -avoid-version
iface_check_la_LIBADD	= -lcrmcommon

install-data-hook:
	-chgrp $(CRM_DAEMON_GROUP) $(DESTDIR)/$(halibdir)/ifcheckd
	-chmod g+s,a-w $(DESTDIR)/$(halibdir)/ifcheckd

nstall-exec-local:
	echo Ensure $(plugindir)/$(lib_LTLIBRARIES:.la=.so) is later linked/copied to $(LCRSODIR)/$(lib_LTLIBRARIES:.la=.lcrso)

