#! /bin/sh
#
# The contents of this file are subject to the Netscape Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/NPL/
#
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
#
# The Original Code is mozilla.org code.
#
# The Initial Developer of the Original Code is Netscape
# Communications Corporation.  Portions created by Netscape are
# Copyright (C) 1999 Netscape Communications Corporation. All
# Rights Reserved.
#
# Contributor(s): 
#

# allmakefiles.sh - List of all makefiles. 
#   Appends the list of makefiles to the variable, MAKEFILES.
#   There is no need to rerun autoconf after adding makefiles.
#   You only need to run configure.
#
#   Please keep the modules in this file in sync with those in
#   mozilla/build/unix/modules.mk
#

MAKEFILES=""

# add_makefiles - Shell function to add makefiles to MAKEFILES
add_makefiles() {
    MAKEFILES="$MAKEFILES $*"
}

if [ "$srcdir" = "" ]; then
    srcdir=.
fi

#
# Common makefiles used by everyone
#

MAKEFILES_coreconf="
coreconf/autoconf.mk:../coreconf/autoconf.mk.in
coreconf/Makefile:../coreconf/Makefile.in
coreconf/mkdepend/Makefile:../coreconf/mkdepend/Makefile.in
coreconf/nsinstall/Makefile:../coreconf/nsinstall/Makefile.in
"

MAKEFILES_nss=`cat ${srcdir}/makefiles`

add_makefiles "
$MAKEFILES_coreconf
$MAKEFILES_nss
"
