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
 * nssPKIXSubjectPublicKeyInfo_template
 *
 */

const NSSASN1Template nssPKIXSubjectPublicKeyInfo_template[] = 
{
 { NSSASN1_SEQUENCE,   0, NULL, sizeof(NSSPKIXSubjectPublicKeyInfo)     },
 { NSSASN1_ANY,        offsetof(NSSPKIXSubjectPublicKeyInfo, 
                                                      algorithm.der)    },
 { NSSASN1_BIT_STRING, offsetof(NSSPKIXSubjectPublicKeyInfo, 
                                                      subjectPublicKey) },
 { 0 }
};

static PRStatus
encode_me(NSSPKIXSubjectPublicKeyInfo *spki)
{
#if 0
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&spki->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(
	                                    spki->arena, 
	                                    &spki->der,
	                                    spki,
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
decode_me(NSSPKIXSubjectPublicKeyInfo *spki)
{
    if (!NSSITEM_IS_EMPTY(&spki->der)) {
	return NSSASN1_DecodeBER(spki->arena, spki, 
	                         nssPKIXSubjectPublicKeyInfo_template, 
                                 &spki->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXSubjectPublicKeyInfo *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXSubjectPublicKeyInfo *rv = (NSSPKIXSubjectPublicKeyInfo *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXSubjectPublicKeyInfo);
    if ((NSSPKIXSubjectPublicKeyInfo *)NULL == rv) {
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

    return (NSSPKIXSubjectPublicKeyInfo *)NULL;
}

#if 0
NSS_IMPLEMENT NSSPKIXSubjectPublicKeyInfo *
nssPKIXSubjectPublicKeyInfo_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    NSSPKIXSubjectPublicKeyInfo *rv = (NSSPKIXSubjectPublicKeyInfo *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXSubjectPublicKeyInfo *)NULL;
    }

#if 0
    NSSOID_Encode(extnID, &rv->extnID);
#endif
    rv->critical = critical;
    rv->extnValue = *extnValue;

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXSubjectPublicKeyInfo *
nssPKIXSubjectPublicKeyInfo_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXSubjectPublicKeyInfo *rv = (NSSPKIXSubjectPublicKeyInfo *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXSubjectPublicKeyInfo *)NULL;
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
    nssPKIXSubjectPublicKeyInfo_Destroy(rv);
    return (NSSPKIXSubjectPublicKeyInfo *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXSubjectPublicKeyInfo_Destroy
(
  NSSPKIXSubjectPublicKeyInfo *spki
)
{
    if (PR_TRUE == spki->i_allocated_arena) {
	return NSSArena_Destroy(spki->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXSubjectPublicKeyInfo_Encode
(
  NSSPKIXSubjectPublicKeyInfo *spki,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(spki);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &spki->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

#if 0
NSS_IMPLEMENT PRBool
nssPKIXSubjectPublicKeyInfo_Equal
(
  NSSPKIXSubjectPublicKeyInfo *one,
  NSSPKIXSubjectPublicKeyInfo *two,
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
nssPKIXSubjectPublicKeyInfo_duplicate
(
  NSSPKIXSubjectPublicKeyInfo *spki,
  NSSArena *arena,
  NSSPKIXSubjectPublicKeyInfo *copy
)
{
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&spki->der)) {
	if (NSSItem_Duplicate(&spki->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    if (NSSItem_Duplicate(&spki->extnID, arena,  &copy->extnID)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    if (NSSItem_Duplicate(&spki->extnValue, arena,  &copy->extnValue)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    copy->extnID = spki->extnID;
    copy->critical = spki->critical;

    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXSubjectPublicKeyInfo *
nssPKIXSubjectPublicKeyInfo_Duplicate
(
  NSSPKIXSubjectPublicKeyInfo *spki,
  NSSArena *arenaOpt
)
{
    NSSPKIXSubjectPublicKeyInfo *rv = (NSSPKIXSubjectPublicKeyInfo *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXSubjectPublicKeyInfo_duplicate(spki, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXSubjectPublicKeyInfo_Destroy(rv);
	    return (NSSPKIXSubjectPublicKeyInfo *)NULL;
	}
    }

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
nssPKIXSubjectPublicKeyInfo_GetAlgorithm
(
  NSSPKIXSubjectPublicKeyInfo *spki
)
{
    if (NSSITEM_IS_EMPTY(&spki->algorithm.der)) {
	if (NSSITEM_IS_EMPTY(&spki->der) ||
	    decode_me(spki) == PR_FAILURE)
	{
	    return (NSSBitString *)NULL;
	}
    }
    return &spki->algorithm;
}

NSS_IMPLEMENT NSSBitString *
nssPKIXSubjectPublicKeyInfo_GetSubjectPublicKey
(
  NSSPKIXSubjectPublicKeyInfo *spki
)
{
    if (NSSITEM_IS_EMPTY(&spki->subjectPublicKey)) {
	if (NSSITEM_IS_EMPTY(&spki->der) ||
	    decode_me(spki) == PR_FAILURE)
	{
	    return (NSSBitString *)NULL;
	}
    }
    return &spki->subjectPublicKey;
}

/*
 * NSSPKIXSubjectPublicKeyInfo_Create
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
 *  A valid pointer to an NSSPKIXSubjectPublicKeyInfo upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXSubjectPublicKeyInfo *
NSSPKIXSubjectPublicKeyInfo_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    nss_ClearErrorStack();

    return nssPKIXSubjectPublicKeyInfo_Create(arenaOpt, extnID, critical, extnValue);
}
#endif

/*
 * NSSPKIXSubjectPublicKeyInfo_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXSubjectPublicKeyInfo upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXSubjectPublicKeyInfo *
NSSPKIXSubjectPublicKeyInfo_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXSubjectPublicKeyInfo_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXSubjectPublicKeyInfo_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXSubjectPublicKeyInfo_Destroy
(
  NSSPKIXSubjectPublicKeyInfo *spki
)
{
    nss_ClearErrorStack();

    return nssPKIXSubjectPublicKeyInfo_Destroy(spki);
}

/*
 * NSSPKIXSubjectPublicKeyInfo_Duplicate
 *
 */

#if 0
NSS_IMPLEMENT NSSPKIXSubjectPublicKeyInfo *
NSSPKIXSubjectPublicKeyInfo_Duplicate
(
  NSSPKIXSubjectPublicKeyInfo *spki,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXSubjectPublicKeyInfo_Duplicate(spki, arenaOpt);
}
#endif

/*
 * NSSPKIXSubjectPublicKeyInfo_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXSubjectPublicKeyInfo_Encode
(
  NSSPKIXSubjectPublicKeyInfo *spki,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either spki has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(spki));
#endif

    return nssPKIXSubjectPublicKeyInfo_Encode(spki, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
NSSPKIXSubjectPublicKeyInfo_GetAlgorithm
(
  NSSPKIXSubjectPublicKeyInfo *spki
)
{
    return nssPKIXSubjectPublicKeyInfo_GetAlgorithm(spki);
}

NSS_IMPLEMENT NSSBitString *
NSSPKIXSubjectPublicKeyInfo_GetSubjectPublicKey
(
  NSSPKIXSubjectPublicKeyInfo *spki
)
{
    return nssPKIXSubjectPublicKeyInfo_GetSubjectPublicKey(spki);
}

