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

#ifdef DEBUG
static const char CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef BASE_H
#include "base.h"
#endif /* BASE_H */

static NSSUTF8
match_start_quote
(
  NSSUTF8 startquote
)
{
    switch (startquote) {
    case '\'': return '\'';
    case '\"': return '\"';
    case '{': return '}';
    case '[': return ']';
    case '(': return ')';
    case '<': return '>';
    default: return ' ';
    }
}

static PRUint32
get_param_length
(
  NSSUTF8 *paramstring,
  NSSUTF8 startquote, 
  NSSUTF8 endquote
)
{
    NSSUTF8 *mark;
    PRUint32 iter, len;
    mark = paramstring;
    if (endquote != ' ') ++mark;
    iter = 1;
    len = 0;
    while (PR_TRUE) {
	if (*mark == endquote) {
	    if (--iter == 0) break;
	} else if (*mark == startquote) {
	    ++iter;
	} else if (*mark == '\0') {
	    if (endquote == ' ') break;
	    return 0;
	} else if (*mark == '\\') {
	    ++mark;
	}
	++mark;
	++len;
    }
    return len;
}

static NSSUTF8 *
get_param_string
(
  NSSUTF8 *paramstring,
  NSSUTF8 startquote, 
  NSSUTF8 endquote,
  NSSUTF8 **value
)
{
    NSSUTF8 *mark;
    PRUint32 iter, len;
    mark = paramstring;
    if (endquote != ' ') ++mark;
    iter = 1;
    len = 0;
    while (PR_TRUE) {
	if (!*mark) {
	    break;
	} else if (*mark == endquote) {
	    if (--iter == 0) break;
	} else if (endquote != ' ' && *mark == startquote) {
	    ++iter;
	} else if (*mark == '\\') {
	    ++mark;
	}
	(*value)[len++] = *mark++;
    }
    (*value)[len] = '\0';
    if (*mark) ++mark;
    while (*mark && isspace(*mark)) ++mark; /* skip trailing whitespace */
    return mark;
}

NSS_IMPLEMENT PRStatus
nssCryptokiArgs_ParseNextPair
(
  NSSUTF8 *start,
  NSSUTF8 **attrib,
  NSSUTF8 **value,
  NSSUTF8 **remainder,
  NSSArena *arenaOpt
)
{
    NSSUTF8 *mark;
    PRUint32 length;
    NSSUTF8 startquote, endquote;
    while (*start && isspace(*start)) ++start; /* skip leading whitespace */
    mark = start;
    while (*mark && *mark != '=') ++mark;
    if (!*mark) {
	return PR_FAILURE;
    }
    *attrib = nssUTF8_Create(arenaOpt, nssStringType_PrintableString, 
                             start, mark - start);
    ++mark;
    if (!*mark) {
	nss_ZFreeIf(*attrib);
	return PR_FAILURE;
    }
    startquote = *mark;
    endquote = match_start_quote(startquote);
    length = get_param_length(mark, startquote, endquote);
    if (length == 0) {
	*value = NULL;
	*remainder = ++mark;
	return PR_SUCCESS;
    }
    *value = nss_ZNEWARRAY(arenaOpt, NSSUTF8, length);
    *remainder = get_param_string(mark, startquote, endquote, value);
    return PR_SUCCESS;
}
