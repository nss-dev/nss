#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"$Id$"
#

CORE_DEPTH = ../../..

%: %.ksh
	$(RM) $@
	cp $< $@
	chmod +x $@

HEADER_DIR = public/nss

DIRS = \
	SUNWtls \
	SUNWtlsu \
	SUNWtlsd

include Makefile.com

PROTO = \
	$(ROOT) \
	$(ROOT)/usr/lib/mps \
	$(ROOT)/usr/include/mps \
	$(ROOT)/usr/sfw/bin

ifeq ($(MACH), sparc)
	PROTO += $(ROOT)/usr/lib/mps/sparcv9 \
	$(ROOT)/usr/sfw/bin/sparcv9
endif

DIST64 = $(shell echo $(DIST) | sed -e "s|_OPT|_64_OPT|g" -e "s|_DBG|_64_DBG|g")

awk_pkginfo: bld_awk_pkginfo
	./bld_awk_pkginfo -m $(MACH) -p "$(PRODUCT_VERSION)" -o $@ -v $(PRODUCT_VERSION)

all:: awk_pkginfo $(PROTO)
publish: awk_pkginfo $(PROTO)
	+$(LOOP_OVER_DIRS)

clean clobber::
	$(RM) awk_pkginfo bld_awk_pkginfo
	$(RM) -r $(ROOT)

$(ROOT):
	mkdir -p $@

$(ROOT)/usr/lib/mps:
	mkdir -p $@
	$(CP) -r $(DIST)/lib/*.so $@
	$(CP) -r $(DIST)/lib/*.chk $@
$(ROOT)/usr/sfw/bin:
	mkdir -p $@
	-$(CP) -r $(DIST)/bin/* $@
$(ROOT)/usr/include/mps:
	mkdir -p $@
	$(CP) -r $(SOURCE_PREFIX)/$(HEADER_DIR)/*.h $@
$(ROOT)/usr/lib/mps/sparcv9:
	mkdir -p $@
	$(CP) -r $(DIST64)/lib/*.so $@
	$(CP) -r $(DIST64)/lib/*.chk $@
$(ROOT)/usr/sfw/bin/sparcv9:
	mkdir -p $@
	$(CP) -r $(DIST64)/bin/* $@
