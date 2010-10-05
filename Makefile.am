MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = resources

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

