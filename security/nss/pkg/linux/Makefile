#
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"$Id$"
#

CORE_DEPTH = ../../..

NAME        = sun-nss
RELEASE     = 1
VERSION     = `grep NSS_VERSION $(CORE_DEPTH)/../dist/public/security/nss.h \
		| sed -e 's/"$$//' -e 's/.*"//' -e 's/ .*//'`
PWD         = `pwd`
BUILDROOT   = $(PWD)\/$(NAME)-root

include $(CORE_DEPTH)/coreconf/config.mk

publish:
	$(MAKE) clean
	mkdir -p SOURCES SRPMS RPMS BUILD
	mkdir -p usr/lib/mps
	find $(CORE_DEPTH)/../dist/$(OBJDIR)/lib -type l \
		\( -name "*.so" -o -name "*.chk" \) \
        -exec cp {} usr/lib/mps \;
	(cd $(CORE_DEPTH)/../dist/public && tar cphf - .) \
		| (mkdir -p usr/include/mps && cd usr/include/mps && tar xvfBp -)
	tar czvf $(NAME)-$(VERSION).tar.gz usr
	echo "%define _topdir `pwd`" >temp.spec
	sed -e "s/NAME_REPLACE/$(NAME)/" \
		-e "s/VERSION_REPLACE/$(VERSION)/" \
		-e "s/RELEASE_REPLACE/$(RELEASE)/" \
	<$(NAME).spec >>temp.spec
	echo "" >>temp.spec
	echo "%files" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	echo "%dir /usr" >>temp.spec
	echo "%dir /usr/lib" >>temp.spec
	echo "%dir /usr/lib/mps" >>temp.spec
	find usr \( -name "*.so" -o -name "*.chk" \) \
		| sed -e "s-^-/-" >>temp.spec
	echo "" >>temp.spec
	echo "%files devel" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	find usr -type d | sed -e "s-^-%dir /-" >>temp.spec
	find usr -type f ! \( -name "*.so" -o -name "*.chk" \) \
		| sed -e "s-^-/-" >>temp.spec
	cp $(NAME)-$(VERSION).tar.gz SOURCES
	rpm -ba temp.spec

clean::
	rm -rf SOURCES SRPMS RPMS BUILD
	rm -rf usr
	rm -f temp.spec
	rm -f $(NAME)-$(VERSION).tar.gz

include $(CORE_DEPTH)/coreconf/rules.mk
