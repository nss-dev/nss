#
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
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

ifeq ($(USE_64), 1)
DIRS = \
	SUNWtlsx \
	SUNWtlsux \
	SUNWtlsdx
else
DIRS = \
	SUNWtls \
	SUNWtlsu \
	SUNWtlsd
endif

PROTO = \
	$(ROOT) \
	$(ROOT)/usr \
	$(ROOT)/usr/lib \
	$(ROOT)/usr/lib/mps \
	$(ROOT)/usr/lib/mps/secv1 \
	$(ROOT)/usr/include \
	$(ROOT)/usr/include/mps \
	$(ROOT)/usr/sfw \
	$(ROOT)/usr/sfw/bin


ifdef USE_64
PROTO += $(ROOT)/usr/lib/mps/secv1/sparcv9 \
	$(ROOT)/usr/include/mps/sparcv9 \
	$(ROOT)/usr/sfw/bin/sparcv9

endif

include Makefile.com

awk_pkginfo: bld_awk_pkginfo
	./bld_awk_pkginfo -m $(MACH) -p "$(PRODUCT_VERSION)" -o $@ -v $(PRODUCT_VERSION)

all:: awk_pkginfo $(PROTO)
publish: awk_pkginfo $(PROTO)
	+$(LOOP_OVER_DIRS)

clean clobber::
	$(RM) awk_pkginfo bld_awk_pkginfo
	$(RM) -r $(ROOT)

$(ROOT) $(ROOT)/%:
	mkdir -p $@

ifdef USE_64
$(ROOT)/usr/lib/mps/secv1/sparcv9: $(ROOT)/usr/lib/mps
	$(LN) -sf ../../../../../$(DIST)/lib $@
$(ROOT)/usr/sfw/bin/sparcv9: $(ROOT)/usr/sfw/bin
	$(LN) -sf ../../../../$(DIST)/bin $@
$(ROOT)/usr/include/mps/sparcv9: $(ROOT)/usr/include
	$(LN) -sf ../../../../$(SOURCE_PREFIX)/$(HEADER_DIR) $@
else
$(ROOT)/usr/lib/mps/secv1: $(ROOT)/usr/lib
	$(LN) -sf ../../../../$(DIST)/lib $@
$(ROOT)/usr/sfw/bin: $(ROOT)/usr/sfw
	$(LN) -sf ../../../$(DIST)/bin $@
$(ROOT)/usr/include/mps: $(ROOT)/usr/include
	$(LN) -sf ../../../$(SOURCE_PREFIX)/$(HEADER_DIR) $@
endif
