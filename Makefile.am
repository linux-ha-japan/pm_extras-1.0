MAINTAINERCLEANFILES = Makefile.in

SUBDIRS		= resources tools
doc_DATA	= README HowToBuild_pm_extras.txt

SPEC                    = $(PACKAGE_NAME).spec
TARFILE                 = $(PACKAGE_NAME)-$(VERSION).tar.gz
EXTRA_DIST              = HowToBuild_pm_extras.txt $(SPEC)

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

install-exec-local:
	rm -f $(DESTDIR)$(LCRSODIR)/iface_check.lcrso
	mkdir -p $(DESTDIR)$(LCRSODIR)
	cp $(DESTDIR)$(libdir)/iface_check.so $(DESTDIR)$(LCRSODIR)/iface_check.lcrso
