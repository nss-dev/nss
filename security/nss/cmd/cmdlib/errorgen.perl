#!perl
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
$cvs_id = '@(#) $RCSfile$ $Revision$ $Date$ $Name$';

$cfile = shift;
open(CFILE, "> $cfile") || die "Can't open $cfile: $!"; 

print CFILE <<EOD
/* THIS IS A GENERATED FILE */
/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

#ifndef NSSBASE_H
#include "nssbase.h"
#endif /* NSSBASE_H */

struct error_strings_str {
  NSSError e;
  char *text;
};

static const struct error_strings_str error_strings[] = {
EOD
    ;

$count = 0;
while(<>) {
  next if (/^\s*$/ or /^#/);
  chomp;
  $err = $_;
  $errstr = <>;
  chomp $errstr;
  if ($count > 0) {
    print CFILE ",\n";
  }
  print CFILE "  {\n    $err,\n    $errstr\n  }";
  $count++;
}

print CFILE <<EOD

};

static const PRUint32 num_errors = $count;

static char *get_error_text(NSSError e)
{
    PRInt32 i, low = 0, high = num_errors;

    /* XXX make sure table is in ascending order */

    while (low + 1 < high) {
	i = (low + high) / 2;
	if (e == error_strings[i].e)
	    return error_strings[i].text;
	if (e < error_strings[i].e)
	    high = i;
	else
	    low = i;
    }
    if (e == error_strings[low].e)
	return error_strings[low].text;
    if (e == error_strings[high].e)
	return error_strings[high].text;
    return NULL;
}

void
CMD_PrintError(char *message, ...)
{
    NSSError e;
    char *text;
    va_list args;

    e = NSS_GetError();
    text = get_error_text(e);

    va_start(args, message);

    PR_vfprintf(PR_STDERR, message, args);
    if (text) {
	PR_fprintf(PR_STDERR, ": %s\\n", text);
    } else {
	PR_fprintf(PR_STDERR, ": (%d)\\n", e);
    }

    va_end(args);
}

EOD
    ;
