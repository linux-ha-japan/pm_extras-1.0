MAINTAINERCLEANFILES = Makefile.in

OCFDIR = /usr/lib/ocf/resource.d/heartbeat
EXTDIR = @libdir@/stonith/plugins/external

ocfdir = $(OCFDIR)
ocf_SCRIPTS = NVclient VIPcheck

extdir = $(EXTDIR)
ext_SCRIPTS = stonith-helper

# BUILD

SPEC                    = $(PACKAGE_NAME).spec
TARFILE                 = $(PACKAGE_NAME)-$(VERSION).tar.gz
EXTRA_DIST              = $(ocf_SCRIPTS) $(ext_SCRIPTS) $(SPEC)

$(TARFILE):
	$(MAKE) dist

rpm: clean
	cp $(TARFILE) `rpm -E "%_sourcedir"`
	rpmbuild -ba $(SPEC)

srpm: clean
	cp $(TARFILE) `rpm -E "%_sourcedir"`
	rpmbuild --nodeps -bs  $(SPEC)

