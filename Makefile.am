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

srpm: clean
        $(MAKE) $(SPEC) $(TARFILE)
        rpmbuild --nodeps -bs $(SPEC)

rpm: clean
        $(MAKE) $(SPEC) $(TARFILE)
        rpmbuild -ba $(SPEC)
