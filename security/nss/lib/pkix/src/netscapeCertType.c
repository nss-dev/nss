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
 * The Original Code is the netscape security libraries.
 * 
 * The Initial Developer of the Original Code is netscape
 * Communications Corporation.  Portions created by netscape are 
 * Copyright (C) 1994-2000 netscape Communications Corporation.  All
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

/* XXX */
#include "asn1.h"

struct NSSPKIXnetscapeCertTypeStr {
  NSSArena *arena;
  PRBool i_allocated_arena;
  NSSDER der;
  NSSPKIXnetscapeCertTypeValue nsCertType;
};

static PRStatus
encode_me(NSSPKIXnetscapeCertType *nsCertType)
{
#if 0
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&nsCertType->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(
	                                    nsCertType->arena, 
	                                    &nsCertType->der,
	                                    nsCertType,
	                                    nssASN1Template_BitString, 
	                                    encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
#endif
    return PR_FAILURE;
}

static PRStatus
decode_me(NSSPKIXnetscapeCertType *nsCertType, NSSBitString *nsct)
{
    if (!NSSITEM_IS_EMPTY(&nsCertType->der)) {
	return NSSASN1_DecodeBER(nsCertType->arena, nsct, 
	                         nssASN1Template_BitString, 
                                 &nsCertType->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXnetscapeCertType *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXnetscapeCertType *rv = (NSSPKIXnetscapeCertType *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXnetscapeCertType);
    if ((NSSPKIXnetscapeCertType *)NULL == rv) {
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

    return (NSSPKIXnetscapeCertType *)NULL;
}

#if 0
NSS_IMPLEMENT NSSPKIXnetscapeCertType *
nssPKIXnetscapeCertType_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    NSSPKIXnetscapeCertType *rv = (NSSPKIXnetscapeCertType *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXnetscapeCertType *)NULL;
    }

#if 0
    NSSOID_Encode(extnID, &rv->extnID);
#endif
    rv->critical = critical;
    rv->extnValue = *extnValue;

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXnetscapeCertType *
nssPKIXnetscapeCertType_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXnetscapeCertType *rv = (NSSPKIXnetscapeCertType *)NULL;
    NSSBitString nsct = { 0 };
    PRStatus status;
    PRUint32 i, bit;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXnetscapeCertType *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv, &nsct);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    /* XXX this faulty logic belongs elsewhere, methinks */
    for (i=0; i<=nsct.size; i++) {
	bit = 0x80 >> (i % 8);
	if (((unsigned char *)nsct.data)[i/8] & bit) {
	    rv->nsCertType |= (1 << i);
	}
    }

    return rv;

loser:
    nssPKIXnetscapeCertType_Destroy(rv);
    return (NSSPKIXnetscapeCertType *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXnetscapeCertType_Destroy
(
  NSSPKIXnetscapeCertType *nsCertType
)
{
    if (PR_TRUE == nsCertType->i_allocated_arena) {
	return NSSArena_Destroy(nsCertType->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXnetscapeCertType_Encode
(
  NSSPKIXnetscapeCertType *nsCertType,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(nsCertType);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &nsCertType->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

#if 0
NSS_IMPLEMENT PRBool
nssPKIXnetscapeCertType_Equal
(
  NSSPKIXnetscapeCertType *one,
  NSSPKIXnetscapeCertType *two,
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

}

NSS_IMPLEMENT PRStatus
nssPKIXnetscapeCertType_duplicate
(
  NSSPKIXnetscapeCertType *nsCertType,
  NSSArena *arena,
  NSSPKIXnetscapeCertType *copy
)
{
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&nsCertType->der)) {
	if (NSSItem_Duplicate(&nsCertType->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    if (NSSItem_Duplicate(&nsCertType->extnID, arena,  &copy->extnID)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    if (NSSItem_Duplicate(&nsCertType->extnValue, arena,  &copy->extnValue)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    copy->extnID = nsCertType->extnID;
    copy->critical = nsCertType->critical;

    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXnetscapeCertType *
nssPKIXnetscapeCertType_Duplicate
(
  NSSPKIXnetscapeCertType *nsCertType,
  NSSArena *arenaOpt
)
{
    NSSPKIXnetscapeCertType *rv = (NSSPKIXnetscapeCertType *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXnetscapeCertType_duplicate(nsCertType, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXnetscapeCertType_Destroy(rv);
	    return (NSSPKIXnetscapeCertType *)NULL;
	}
    }

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXnetscapeCertTypeValue
nssPKIXnetscapeCertType_GetValue
(
  NSSPKIXnetscapeCertType *nsCertType
)
{
    return nsCertType->nsCertType;
}

/*
 * NSSPKIXnetscapeCertType_Create
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
 *  A valid pointer to an NSSPKIXnetscapeCertType upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXnetscapeCertType *
NSSPKIXnetscapeCertType_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    nss_ClearErrorStack();

    return nssPKIXnetscapeCertType_Create(arenaOpt, extnID, critical, extnValue);
}
#endif

/*
 * NSSPKIXnetscapeCertType_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXnetscapeCertType upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXnetscapeCertType *
NSSPKIXnetscapeCertType_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXnetscapeCertType_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXnetscapeCertType_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXnetscapeCertType_Destroy
(
  NSSPKIXnetscapeCertType *nsCertType
)
{
    nss_ClearErrorStack();

    return nssPKIXnetscapeCertType_Destroy(nsCertType);
}

/*
 * NSSPKIXnetscapeCertType_Duplicate
 *
 */

#if 0
NSS_IMPLEMENT NSSPKIXnetscapeCertType *
NSSPKIXnetscapeCertType_Duplicate
(
  NSSPKIXnetscapeCertType *nsCertType,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXnetscapeCertType_Duplicate(nsCertType, arenaOpt);
}
#endif

/*
 * NSSPKIXnetscapeCertType_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXnetscapeCertType_Encode
(
  NSSPKIXnetscapeCertType *nsCertType,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either nsCertType has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(nsCertType));
#endif

    return nssPKIXnetscapeCertType_Encode(nsCertType, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSPKIXnetscapeCertTypeValue
NSSPKIXnetscapeCertType_GetValue
(
  NSSPKIXnetscapeCertType *nsCertType
)
{
    return nssPKIXnetscapeCertType_GetValue(nsCertType);
}

