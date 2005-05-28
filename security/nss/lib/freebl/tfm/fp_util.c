/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/* these functions are added for compatibility with MPI */

#include <tfm.h>

void fp_exch(fp_int* p, fp_int* q) {
    fp_int tmp;
    fp_copy(q, &tmp);
    fp_copy(p, q);
    fp_copy(&tmp, p);
}

int fp_to_fixlen_octets(fp_int* fp, unsigned char* str, int len) {
    int size;

    if (fp == NULL || str == NULL)
        return FP_VAL;

    /* get the size of the bignum to fit in the buffer */
    size = fp_unsigned_bin_size(fp);
    if (size > len)
        return FP_VAL;

    /* pad the buffer with zeroes before copying the bignum */
    while(len > size) {
        *str++ = 0;
        --len;
    }

    /* do the actual copy */
    fp_to_unsigned_bin(fp, str);
    return FP_OKAY;
}
