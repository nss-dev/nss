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

/*
 * nssPKIXValidity_template
 *
 */

const NSSASN1Template nssPKIXValidity_template[] = 
{
 { NSSASN1_SEQUENCE,     0, NULL, sizeof(NSSPKIXValidity)     },
 { NSSASN1_SAVE, offsetof(NSSPKIXValidity, notBefore.der) },
 { NSSASN1_INLINE, offsetof(NSSPKIXValidity, notBefore),
     nssPKIXTime_template },
 { NSSASN1_SAVE, offsetof(NSSPKIXValidity, notAfter.der) },
 { NSSASN1_INLINE, offsetof(NSSPKIXValidity, notAfter),
     nssPKIXTime_template },
 { 0 }
};

static PRStatus
encode_me(NSSPKIXValidity *validity)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&validity->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(validity->arena, 
	                                         &validity->der,
	                                         validity,
	                                         nssPKIXValidity_template, 
	                                         encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXValidity *validity)
{
    if (!NSSITEM_IS_EMPTY(&validity->der)) {
	return NSSASN1_DecodeBER(validity->arena, validity, 
	                         nssPKIXValidity_template, &validity->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXValidity *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXValidity *rv = (NSSPKIXValidity *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXValidity);
    if ((NSSPKIXValidity *)NULL == rv) {
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

    return (NSSPKIXValidity *)NULL;
}

NSS_IMPLEMENT NSSPKIXValidity *
nssPKIXValidity_Create
(
  NSSArena *arenaOpt,
  NSSPKIXTime *notBefore,
  NSSPKIXTime *notAfter
)
{
    NSSPKIXValidity *rv = (NSSPKIXValidity *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXValidity *)NULL;
    }

    rv->notBefore = *notBefore;
    rv->notAfter = *notAfter;

    return rv;
}

NSS_IMPLEMENT void
nssPKIXValidity_SetArena
(
  NSSPKIXValidity *validity,
  NSSArena *arena
)
{
    validity->arena = arena;
    nssPKIXTime_SetArena(&validity->notBefore, arena);
    nssPKIXTime_SetArena(&validity->notAfter, arena);
}

NSS_IMPLEMENT NSSPKIXValidity *
nssPKIXValidity_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXValidity *rv = (NSSPKIXValidity *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXValidity *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    nssPKIXValidity_SetArena(rv, rv->arena);

    return rv;

loser:
    nssPKIXValidity_Destroy(rv);
    return (NSSPKIXValidity *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXValidity_Destroy
(
  NSSPKIXValidity *validity
)
{
    if (PR_TRUE == validity->i_allocated_arena) {
	return NSSArena_Destroy(validity->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXValidity_Encode
(
  NSSPKIXValidity *validity,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(validity);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &validity->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

NSS_IMPLEMENT PRBool
nssPKIXValidity_Equal
(
  NSSPKIXValidity *one,
  NSSPKIXValidity *two,
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

    if (!nssPKIXTime_Equal(&one->notBefore, &two->notBefore, statusOpt)) {
	return PR_FALSE;
    }
    return (nssPKIXTime_Equal(&one->notAfter, &two->notAfter, statusOpt));
}

NSS_IMPLEMENT PRStatus
nssPKIXValidity_duplicate
(
  NSSPKIXValidity *validity,
  NSSArena *arena,
  NSSPKIXValidity *copy
)
{
#if 0
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&validity->der)) {
	if (NSSItem_Duplicate(&validity->der, arena, &copy->der) 
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

NSS_IMPLEMENT NSSPKIXValidity *
nssPKIXValidity_Duplicate
(
  NSSPKIXValidity *validity,
  NSSArena *arenaOpt
)
{
    NSSPKIXValidity *rv = (NSSPKIXValidity *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXValidity_duplicate(validity, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXValidity_Destroy(rv);
	    return (NSSPKIXValidity *)NULL;
	}
    }

    return rv;
}

NSS_IMPLEMENT NSSPKIXTime *
nssPKIXValidity_GetNotBefore
(
  NSSPKIXValidity *validity
)
{
    if (NSSITEM_IS_EMPTY(&validity->notBefore.der)) {
	if (NSSITEM_IS_EMPTY(&validity->der) ||
	    decode_me(validity) == PR_FAILURE)
	{
	    return (NSSPKIXTime *)NULL;
	}
    }
    return &validity->notBefore;
}

NSS_IMPLEMENT NSSPKIXTime *
nssPKIXValidity_GetNotAfter
(
  NSSPKIXValidity *validity
)
{
    if (NSSITEM_IS_EMPTY(&validity->notAfter.der)) {
	if (NSSITEM_IS_EMPTY(&validity->der) ||
	    decode_me(validity) == PR_FAILURE)
	{
	    return (NSSPKIXTime *)NULL;
	}
    }
    return &validity->notAfter;
}

/*
 * NSSPKIXValidity_Create
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
 *  A valid pointer to an NSSPKIXValidity upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXValidity *
NSSPKIXValidity_Create
(
  NSSArena *arenaOpt,
  NSSPKIXTime *notBefore,
  NSSPKIXTime *notAfter
)
{
    nss_ClearErrorStack();

    return nssPKIXValidity_Create(arenaOpt, notBefore, notAfter);
}

/*
 * NSSPKIXValidity_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXValidity upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXValidity *
NSSPKIXValidity_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXValidity_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXValidity_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXValidity_Destroy
(
  NSSPKIXValidity *validity
)
{
    nss_ClearErrorStack();

    return nssPKIXValidity_Destroy(validity);
}

/*
 * NSSPKIXValidity_Duplicate
 *
 */

NSS_IMPLEMENT NSSPKIXValidity *
NSSPKIXValidity_Duplicate
(
  NSSPKIXValidity *validity,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXValidity_Duplicate(validity, arenaOpt);
}

/*
 * NSSPKIXValidity_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXValidity_Encode
(
  NSSPKIXValidity *validity,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either validity has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(validity));
#endif

    return nssPKIXValidity_Encode(validity, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSPKIXTime *
NSSPKIXValidity_GetNotBefore
(
  NSSPKIXValidity *validity
)
{
    return nssPKIXValidity_GetNotBefore(validity);
}

NSS_IMPLEMENT NSSPKIXTime *
NSSPKIXValidity_GetNotAfter
(
  NSSPKIXValidity *validity
)
{
    return nssPKIXValidity_GetNotAfter(validity);
}

