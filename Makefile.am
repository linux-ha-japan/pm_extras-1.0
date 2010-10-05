MAINTAINERCLEANFILES = Makefile.in

SUBDIRS = resources

SPEC                    = $(PACKAGE_NAME).spec
TARFILE                 = $(PACKAGE_NAME)-$(VERSION).tar.gz
EXTRA_DIST              = $(SPEC)

$(TARFILE):
	$(MAKE) dist

RPM_ROOT		= $(shell pwd)
RPMBUILDOPTS		= --define "_sourcedir $(RPM_ROOT)" \
			  --define "_specdir $(RPM_ROOT)"

srpm: clean
	rm -f $(TARFILE)
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) --nodeps -bs --rmsource $(SPEC)

rpm: clean
	rm -f $(TARFILE)
	$(MAKE) $(SPEC) $(TARFILE)
	rpmbuild $(RPMBUILDOPTS) -ba --rmsource $(SPEC)

