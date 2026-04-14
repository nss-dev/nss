#! gmake
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#######################################################################
# (1) Include initial platform-independent assignments (MANDATORY).   #
#######################################################################

include manifest.mn

#######################################################################
# (2) Include "global" configuration information. (OPTIONAL)          #
#######################################################################

include $(CORE_DEPTH)/coreconf/config.mk

#######################################################################
# (3) Include "component" configuration information. (OPTIONAL)       #
#######################################################################



#######################################################################
# (4) Include "local" platform-dependent assignments (OPTIONAL).      #
#######################################################################

include config.mk

#######################################################################
# (5) Execute "global" rules. (OPTIONAL)                              #
#######################################################################

include $(CORE_DEPTH)/coreconf/rules.mk

#######################################################################
# (6) Execute "component" rules. (OPTIONAL)                           #
#######################################################################



#######################################################################
# (7) Execute "local" rules. (OPTIONAL).                              #
#######################################################################

# Export the md/ platform-specific headers (cfg files + md headers) to
# dist/public/nss/md/ so that MDCPUCFG="md/_linux.cfg" etc. resolves.
MPR_MD_HDRS = $(wildcard include/md/*.h include/md/*.cfg)
MPR_MD_DEST = $(SOURCE_XPHEADERS_DIR)/md

MPR_PRIV_HDRS = $(wildcard include/private/*.h)
# Install into dist/private/nss/private/ so that prpriv.h's
# #include "private/pprio.h" resolves when consumers compile against the
# exported headers (dist/private/nss is on their -I path).
MPR_PRIV_DEST = $(SOURCE_XPPRIVATE_DIR)/private

# Add install_mpr_md and install_mpr_private as prerequisites of export
# without adding a recipe (GNU make merges prerequisites from multiple
# single-colon rules for the same target).
export: install_mpr_md install_mpr_private

install_mpr_md:
	$(NSINSTALL) -D $(MPR_MD_DEST)
	$(INSTALL) -m 444 $(MPR_MD_HDRS) $(MPR_MD_DEST)
	$(INSTALL) -m 444 include/md/$(MPR_CPUCFG_H) $(SOURCE_XPHEADERS_DIR)
	mv -f $(SOURCE_XPHEADERS_DIR)/$(MPR_CPUCFG_H) $(SOURCE_XPHEADERS_DIR)/prcpucfg.h

install_mpr_private:
	$(NSINSTALL) -D $(MPR_PRIV_DEST)
	$(INSTALL) -m 444 $(MPR_PRIV_HDRS) $(MPR_PRIV_DEST)
