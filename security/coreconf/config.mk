#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
# 
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
# 
# The Original Code is the Netscape security libraries.
# 
# The Initial Developer of the Original Code is Netscape
# Communications Corporation.  Portions created by Netscape are 
# Copyright (C) 1994-2000 Netscape Communications Corporation.  All
# Rights Reserved.
# 
# Contributor(s):
# 
# Alternatively, the contents of this file may be used under the
# terms of the GNU General Public License Version 2 or later (the
# "GPL"), in which case the provisions of the GPL are applicable 
# instead of those above.  If you wish to allow use of your 
# version of this file only under the terms of the GPL and not to
# allow others to use your version of this file under the MPL,
# indicate your decision by deleting the provisions above and
# replace them with the notice and other provisions required by
# the GPL.  If you do not delete the provisions above, a recipient
# may use your version of this file under either the MPL or the
# GPL.
#
# Configuration information for building in the "Core Components" source module
#

#######################################################################
# [1.0] Master "Core Components" default command macros               #
#       (NOTE: may be overridden in $(OS_CONFIG).mk)                  #
#######################################################################

include $(CORECONF_SOURCE)/command.mk

#######################################################################
# [2.0] Master "Core Components" source and release <platform> tags   #
#       (dependent upon <architecture> tags)                          #
#######################################################################

include $(CORECONF_SOURCE)/platform.mk

#######################################################################
# [3.0] Master "Core Components" release <tree> tags                  #
#       (dependent upon <architecture> tags)                          #
#######################################################################

include $(CORECONF_SOURCE)/tree.mk

#######################################################################
# [4.0] Master "Core Components" source and release <component> tags  #
#       NOTE:  A component is also called a module or a subsystem.    #
#       (dependent upon $(MODULE) being defined on the                #
#        command line, as an environment variable, or in individual   #
#        makefiles, or more appropriately, manifest.mn)               #
#######################################################################

include $(CORECONF_SOURCE)/module.mk

#######################################################################
# [5.0] Master "Core Components" release <version> tags               #
#       (dependent upon $(MODULE) being defined on the                #
#        command line, as an environment variable, or in individual   #
#        makefiles, or more appropriately, manifest.mn)               #
#######################################################################

include $(CORECONF_SOURCE)/version.mk

#######################################################################
# [6.0] Master "Core Components" macros to figure out                 #
#       binary code location                                          #
#       (dependent upon <platform> tags)                              #
#######################################################################

include $(CORECONF_SOURCE)/location.mk

#######################################################################
# [7.0] Master "Core Components" <component>-specific source path     #
#       (dependent upon <user_source_tree>, <source_component>,       #
#        <version>, and <platform> tags)                              #
#######################################################################

include $(CORECONF_SOURCE)/source.mk

#######################################################################
# [8.0] Master "Core Components" include switch for support header    #
#        files                                                        #
#        (dependent upon <tree>, <component>, <version>,              #
#         and <platform> tags)                                        #
#######################################################################

include $(CORECONF_SOURCE)/headers.mk

#######################################################################
# [9.0] Master "Core Components" for computing program prefixes       #
#######################################################################

include $(CORECONF_SOURCE)/prefix.mk

#######################################################################
# [10.0] Master "Core Components" for computing program suffixes      #
#        (dependent upon <architecture> tags)                         #
#######################################################################

include $(CORECONF_SOURCE)/suffix.mk

#######################################################################
# [11.0] Master "Core Components" for defining JDK                    #
#        (dependent upon <architecture>, <source>, and <suffix>  tags)#
#######################################################################

include $(CORECONF_SOURCE)/jdk.mk

#######################################################################
# [12.0] Master "Core Components" rule set                            #
#        (should always be the last file included by config.mk)       #
#######################################################################

include $(CORECONF_SOURCE)/ruleset.mk

