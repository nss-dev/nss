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
	mkdir -p opt/sun/private/lib 
	find $(CORE_DEPTH)/../dist/$(OBJDIR)/lib -type l \
		\( -name "*.so" -o -name "*.chk" \) \
        -exec cp {} opt/sun/private/lib \;
	rm opt/sun/private/lib/libnspr4.so opt/sun/private/lib/libplc4.so \
		opt/sun/private/lib/libplds4.so
	mkdir -p opt/sun/private/bin
	(cd $(CORE_DEPTH)/../dist/$(OBJDIR)/bin && tar cphf - \
		certutil cmsutil crlutil modutil pk12util signtool \
		signver ssltap ) | (cd opt/sun/private/bin && tar xvfBp -)
	(cd $(CORE_DEPTH)/../dist/public && tar cphf - .) \
		| (mkdir -p opt/sun/private/include && cd opt/sun/private/include && tar xvfBp -)

	tar czvf $(NAME)-$(VERSION).tar.gz opt 
	echo "%define _topdir `pwd`" >temp.spec
	sed -e "s/NAME_REPLACE/$(NAME)/" \
		-e "s/VERSION_REPLACE/$(VERSION)/" \
		-e "s/RELEASE_REPLACE/$(RELEASE)/" \
	<$(NAME).spec >>temp.spec
	echo "" >>temp.spec
	echo "%files" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	echo "%dir /opt" >>temp.spec
	echo "%dir /opt/sun" >>temp.spec
	echo "%dir /opt/sun/private" >>temp.spec
	echo "%dir /opt/sun/private/lib" >>temp.spec
	echo "%dir /opt/sun/private/bin" >>temp.spec
	find opt \( -name "*.so" -o -name "*.chk" -o -type f \
		-perm u=rwx,g=rx,o=rx \) | sed -e "s-^-/-" >>temp.spec
	echo "" >>temp.spec
	echo "%files devel" >>temp.spec
	echo "%defattr(-,root,root)" >>temp.spec
	find opt -type d | sed -e "s-^-%dir /-" >>temp.spec
	find opt -type f ! \( -name "*.so" -o -name "*.chk" \) \
		| sed -e "s-^-/-" >>temp.spec
	cp $(NAME)-$(VERSION).tar.gz SOURCES
	rpm -ba temp.spec

clean::
	rm -rf SOURCES SRPMS RPMS BUILD
	rm -rf opt 
	rm -f temp.spec
	rm -f $(NAME)-$(VERSION).tar.gz

include $(CORE_DEPTH)/coreconf/rules.mk
