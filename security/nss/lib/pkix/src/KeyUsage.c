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

/* XXX */
#include "asn1.h"

static PRStatus
encode_me(NSSPKIXKeyUsage *keyUsage)
{
#if 0
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&keyUsage->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(
	                                    keyUsage->arena, 
	                                    &keyUsage->der,
	                                    keyUsage,
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
decode_me(NSSPKIXKeyUsage *keyUsage, NSSBitString *ku)
{
    if (!NSSITEM_IS_EMPTY(&keyUsage->der)) {
	return NSSASN1_DecodeBER(keyUsage->arena, ku, 
	                         nssASN1Template_BitString, 
                                 &keyUsage->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXKeyUsage *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXKeyUsage *rv = (NSSPKIXKeyUsage *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXKeyUsage);
    if ((NSSPKIXKeyUsage *)NULL == rv) {
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

    return (NSSPKIXKeyUsage *)NULL;
}

#if 0
NSS_IMPLEMENT NSSPKIXKeyUsage *
nssPKIXKeyUsage_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    NSSPKIXKeyUsage *rv = (NSSPKIXKeyUsage *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXKeyUsage *)NULL;
    }

#if 0
    NSSOID_Encode(extnID, &rv->extnID);
#endif
    rv->critical = critical;
    rv->extnValue = *extnValue;

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXKeyUsage *
nssPKIXKeyUsage_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXKeyUsage *rv = (NSSPKIXKeyUsage *)NULL;
    NSSBitString ku = { 0 };
    PRStatus status;
    PRUint32 i, bit;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXKeyUsage *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv, &ku);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    /* XXX this faulty logic belongs elsewhere, methinks */
    for (i=0; i<=ku.size; i++) {
	bit = 0x80 >> (i % 8);
	if (((unsigned char *)ku.data)[i/8] & bit) {
	    rv->keyUsage |= (1 << i);
	}
    }

    return rv;

loser:
    nssPKIXKeyUsage_Destroy(rv);
    return (NSSPKIXKeyUsage *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXKeyUsage_Destroy
(
  NSSPKIXKeyUsage *keyUsage
)
{
    if (PR_TRUE == keyUsage->i_allocated_arena) {
	return NSSArena_Destroy(keyUsage->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXKeyUsage_Encode
(
  NSSPKIXKeyUsage *keyUsage,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(keyUsage);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &keyUsage->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

#if 0
NSS_IMPLEMENT PRBool
nssPKIXKeyUsage_Equal
(
  NSSPKIXKeyUsage *one,
  NSSPKIXKeyUsage *two,
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
nssPKIXKeyUsage_duplicate
(
  NSSPKIXKeyUsage *keyUsage,
  NSSArena *arena,
  NSSPKIXKeyUsage *copy
)
{
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&keyUsage->der)) {
	if (NSSItem_Duplicate(&keyUsage->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    if (NSSItem_Duplicate(&keyUsage->extnID, arena,  &copy->extnID)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    if (NSSItem_Duplicate(&keyUsage->extnValue, arena,  &copy->extnValue)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    copy->extnID = keyUsage->extnID;
    copy->critical = keyUsage->critical;

    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXKeyUsage *
nssPKIXKeyUsage_Duplicate
(
  NSSPKIXKeyUsage *keyUsage,
  NSSArena *arenaOpt
)
{
    NSSPKIXKeyUsage *rv = (NSSPKIXKeyUsage *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXKeyUsage_duplicate(keyUsage, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXKeyUsage_Destroy(rv);
	    return (NSSPKIXKeyUsage *)NULL;
	}
    }

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXKeyUsageValue
nssPKIXKeyUsage_GetValue
(
  NSSPKIXKeyUsage *keyUsage
)
{
    return keyUsage->keyUsage;
}

/*
 * NSSPKIXKeyUsage_Create
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
 *  A valid pointer to an NSSPKIXKeyUsage upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXKeyUsage *
NSSPKIXKeyUsage_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    nss_ClearErrorStack();

    return nssPKIXKeyUsage_Create(arenaOpt, extnID, critical, extnValue);
}
#endif

/*
 * NSSPKIXKeyUsage_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXKeyUsage upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXKeyUsage *
NSSPKIXKeyUsage_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXKeyUsage_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXKeyUsage_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXKeyUsage_Destroy
(
  NSSPKIXKeyUsage *keyUsage
)
{
    nss_ClearErrorStack();

    return nssPKIXKeyUsage_Destroy(keyUsage);
}

/*
 * NSSPKIXKeyUsage_Duplicate
 *
 */

#if 0
NSS_IMPLEMENT NSSPKIXKeyUsage *
NSSPKIXKeyUsage_Duplicate
(
  NSSPKIXKeyUsage *keyUsage,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXKeyUsage_Duplicate(keyUsage, arenaOpt);
}
#endif

/*
 * NSSPKIXKeyUsage_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXKeyUsage_Encode
(
  NSSPKIXKeyUsage *keyUsage,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either keyUsage has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(keyUsage));
#endif

    return nssPKIXKeyUsage_Encode(keyUsage, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSPKIXKeyUsageValue
NSSPKIXKeyUsage_GetValue
(
  NSSPKIXKeyUsage *keyUsage
)
{
    return nssPKIXKeyUsage_GetValue(keyUsage);
}

