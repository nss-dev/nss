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
static const char CVS_ID[] = "@(#) $Source$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef PKIXM_H
#include "../include/pkixm.h"
#endif /* PKIXM_H */

/* XXX for time, may move */
#include "nsspki.h"

/*
 * nssPKIXTime_template
 *
 */

/* XXX times should decode to strings, not items */
const NSSASN1Template nssPKIXTime_template[] = 
{
#if 0
 { NSSASN1_CHOICE,     0, NULL, sizeof(NSSPKIXTime)     },
#endif
 { NSSASN1_UTC_TIME, offsetof(NSSPKIXTime, utcTime) },
#if 0
 { NSSASN1_GENERALIZED_TIME, offsetof(NSSPKIXTime, generalizedTime) },
#endif
 { 0 }
};

static PRStatus
encode_me(NSSPKIXTime *time)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&time->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(time->arena, 
	                                         &time->der,
	                                         time,
	                                         nssPKIXTime_template, 
	                                         encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXTime *time)
{
    if (!NSSITEM_IS_EMPTY(&time->der)) {
	return NSSASN1_DecodeBER(time->arena, time, 
	                         nssPKIXTime_template, &time->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXTime *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXTime *rv = (NSSPKIXTime *)NULL;

    if ((NSSArena *)NULL == arenaOpt) {
	arena = NSSArena_Create();
	if ((NSSArena *)NULL == arena) {
	    goto loser;
	}
	arena_allocated = PR_TRUE;
    } else {
	arena = arenaOpt;
	mark = nssArena_Mark(arena);
	if ((nssArenaMark *)NULL == mark ) {
	    goto loser;
	}
    }

    rv = nss_ZNEW(arena, NSSPKIXTime);
    if ((NSSPKIXTime *)NULL == rv) {
	goto loser;
    }

    rv->arena = arena;
    rv->i_allocated_arena = arena_allocated;

    if ((nssArenaMark *)NULL != mark) {
	if (PR_SUCCESS != nssArena_Unmark(arena, mark)) {
	    goto loser;
	}
    }

    return rv;

loser:
    if ((nssArenaMark *)NULL != mark) {
	(void)nssArena_Release(arena, mark);
    }

    if (PR_TRUE == arena_allocated) {
	(void)NSSArena_Destroy(arena);
    }

    return (NSSPKIXTime *)NULL;
}

#if 0
NSS_IMPLEMENT NSSPKIXTime *
nssPKIXTime_CreateFromUTCTime
(
  NSSArena *arenaOpt,
  NSSUTF8 *utcTime
)
{
    NSSPKIXTime *rv = (NSSPKIXTime *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXTime *)NULL;
    }

    rv->utcTime.data = (void *)utcTime;
    rv->utcTime.size = NSSUTF8_Length(utcTime);

    return rv;
}
#endif

NSS_IMPLEMENT void
nssPKIXTime_SetArena
(
  NSSPKIXTime *time,
  NSSArena *arena
)
{
    time->arena = arena;
}

NSS_IMPLEMENT NSSPKIXTime *
nssPKIXTime_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXTime *rv = (NSSPKIXTime *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXTime *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    return rv;

loser:
    nssPKIXTime_Destroy(rv);
    return (NSSPKIXTime *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXTime_Destroy
(
  NSSPKIXTime *time
)
{
    if (PR_TRUE == time->i_allocated_arena) {
	return NSSArena_Destroy(time->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXTime_Encode
(
  NSSPKIXTime *time,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(time);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &time->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

NSS_IMPLEMENT PRBool
nssPKIXTime_Equal
(
  NSSPKIXTime *one,
  NSSPKIXTime *two,
  PRStatus *statusOpt
)
{
    PRStatus status;

    /* either one or both have been encoded, get encoding and compare */
    if (!(NSSITEM_IS_EMPTY(&one->der) && NSSITEM_IS_EMPTY(&two->der))) {
	status = PR_SUCCESS;
	if (NSSITEM_IS_EMPTY(&one->der)) {
	    status = encode_me(one);
	} else if (NSSITEM_IS_EMPTY(&two->der)) {
	    status = encode_me(two);
	}
	if (status != PR_SUCCESS) {
	    if (statusOpt) *statusOpt = status;
	    return PR_FALSE;
	}
	return NSSItem_Equal(&one->der, &two->der, statusOpt);
    }

    /* both only exist as decoded parts, compare parts */
    /* XXX */
    return PR_FALSE;
}

NSS_IMPLEMENT PRStatus
nssPKIXTime_duplicate
(
  NSSPKIXTime *time,
  NSSArena *arena,
  NSSPKIXTime *copy
)
{
#if 0
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&time->der)) {
	if (NSSItem_Duplicate(&time->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    /* XXX */

    return PR_SUCCESS;
#endif
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSPKIXTime *
nssPKIXTime_Duplicate
(
  NSSPKIXTime *time,
  NSSArena *arenaOpt
)
{
    NSSPKIXTime *rv = (NSSPKIXTime *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXTime_duplicate(time, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXTime_Destroy(rv);
	    return (NSSPKIXTime *)NULL;
	}
    }

    return rv;
}

NSS_IMPLEMENT NSSTime
nssPKIXTime_GetTime
(
  NSSPKIXTime *time,
  PRStatus *statusOpt
)
{
    PRStatus status;
    if (time->timeValid) {
	if (statusOpt) *statusOpt = PR_SUCCESS;
	return time->time;
    } else {
	time->time = NSSTime_CreateFromUTCTime(time->utcTime.data, &status);
	if (status == PR_SUCCESS) {
	    if (statusOpt) *statusOpt = PR_SUCCESS;
	    time->timeValid = PR_TRUE;
	    return time->time;
	}
    }
    if (statusOpt) *statusOpt = PR_FAILURE;
    return -1;
}

/*
 * NSSPKIXTime_Create
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_OID
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  A valid pointer to an NSSPKIXTime upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXTime *
NSSPKIXTime_Create
(
  NSSArena *arenaOpt,
  NSSPKIXTime *notBefore,
  NSSPKIXTime *notAfter
)
{
    nss_ClearErrorStack();

    return nssPKIXTime_Create(arenaOpt, notBefore, notAfter);
}
#endif

/*
 * NSSPKIXTime_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXTime upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXTime *
NSSPKIXTime_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXTime_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXTime_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXTime_Destroy
(
  NSSPKIXTime *time
)
{
    nss_ClearErrorStack();

    return nssPKIXTime_Destroy(time);
}

/*
 * NSSPKIXTime_Duplicate
 *
 */

NSS_IMPLEMENT NSSPKIXTime *
NSSPKIXTime_Duplicate
(
  NSSPKIXTime *time,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXTime_Duplicate(time, arenaOpt);
}

/*
 * NSSPKIXTime_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXTime_Encode
(
  NSSPKIXTime *time,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either time has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(time));
#endif

    return nssPKIXTime_Encode(time, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSTime
NSSPKIXTime_GetTime
(
  NSSPKIXTime *time,
  PRStatus *statusOpt
)
{
    return nssPKIXTime_GetTime(time, statusOpt);
}

