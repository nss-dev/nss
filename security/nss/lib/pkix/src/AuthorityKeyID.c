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

/* XXX move to common location */
static const NSSASN1Template NSSASN1Template_OctetString[] =
{
  { NSSASN1_OCTET_STRING | NSSASN1_MAY_STREAM, 0, NULL, sizeof(NSSItem) }
};
static const NSSASN1Template NSSASN1Template_Integer[] =
{
  { NSSASN1_INTEGER, 0, NULL, sizeof(NSSItem) }
};
static const NSSASN1Template NSSASN1Template_Any[] =
{
  { NSSASN1_ANY, 0, NULL, sizeof(NSSItem) }
};

/* XXX move to GeneralNames.c */
const NSSASN1Template nssPKIXGeneralNames_template[] =
{
  { NSSASN1_SEQUENCE_OF, 0, NSSASN1Template_Any }
};

/*
 * nssPKIXAuthorityKeyIdentifier_template
 *
 */

const NSSASN1Template nssPKIXAuthorityKeyIdentifier_template[] = 
{
 { NSSASN1_SEQUENCE, 0, NULL, sizeof(NSSPKIXAuthorityKeyIdentifier)   },
 { NSSASN1_OPTIONAL | 
    NSSASN1_CONTEXT_SPECIFIC | 0, 
       offsetof(NSSPKIXAuthorityKeyIdentifier, keyIdentifier),
       NSSASN1Template_OctetString },
 { NSSASN1_OPTIONAL | 
    NSSASN1_CONSTRUCTED |
     NSSASN1_CONTEXT_SPECIFIC | 1, 
       offsetof(NSSPKIXAuthorityKeyIdentifier, authorityCertIssuer.der),
       nssPKIXGeneralNames_template },
 { NSSASN1_OPTIONAL | 
    NSSASN1_CONTEXT_SPECIFIC | 2, 
       offsetof(NSSPKIXAuthorityKeyIdentifier, authorityCertSerialNumber),
       NSSASN1Template_Integer },
 { 0 }
};

static PRStatus
encode_me(NSSPKIXAuthorityKeyIdentifier *akid)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&akid->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(
	                                akid->arena, 
	                                &akid->der,
	                                akid,
	                                nssPKIXAuthorityKeyIdentifier_template, 
	                                encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXAuthorityKeyIdentifier *akid)
{
    if (!NSSITEM_IS_EMPTY(&akid->der)) {
	return NSSASN1_DecodeBER(akid->arena, akid, 
	                         nssPKIXAuthorityKeyIdentifier_template, 
                                 &akid->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXAuthorityKeyIdentifier *
create_me (
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXAuthorityKeyIdentifier *rv = (NSSPKIXAuthorityKeyIdentifier *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXAuthorityKeyIdentifier);
    if ((NSSPKIXAuthorityKeyIdentifier *)NULL == rv) {
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

    return (NSSPKIXAuthorityKeyIdentifier *)NULL;
}

#if 0
NSS_IMPLEMENT NSSPKIXAuthorityKeyIdentifier *
nssPKIXAuthorityKeyIdentifier_Create (
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    NSSPKIXAuthorityKeyIdentifier *rv = (NSSPKIXAuthorityKeyIdentifier *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXAuthorityKeyIdentifier *)NULL;
    }

#if 0
    NSSOID_Encode(extnID, &rv->extnID);
#endif
    rv->critical = critical;
    rv->extnValue = *extnValue;

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXAuthorityKeyIdentifier *
nssPKIXAuthorityKeyIdentifier_Decode (
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXAuthorityKeyIdentifier *rv = (NSSPKIXAuthorityKeyIdentifier *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXAuthorityKeyIdentifier *)NULL;
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
    nssPKIXAuthorityKeyIdentifier_Destroy(rv);
    return (NSSPKIXAuthorityKeyIdentifier *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXAuthorityKeyIdentifier_Destroy (
  NSSPKIXAuthorityKeyIdentifier *akid
)
{
    if (PR_TRUE == akid->i_allocated_arena) {
	return NSSArena_Destroy(akid->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXAuthorityKeyIdentifier_Encode (
  NSSPKIXAuthorityKeyIdentifier *akid,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(akid);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &akid->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

#if 0
NSS_IMPLEMENT PRBool
nssPKIXAuthorityKeyIdentifier_Equal (
  NSSPKIXAuthorityKeyIdentifier *one,
  NSSPKIXAuthorityKeyIdentifier *two,
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
#endif

NSS_IMPLEMENT PRStatus
nssPKIXAuthorityKeyIdentifier_duplicate (
  NSSPKIXAuthorityKeyIdentifier *akid,
  NSSArena *arena,
  NSSPKIXAuthorityKeyIdentifier *copy
)
{
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&akid->der)) {
	if (NSSItem_Duplicate(&akid->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    if (!NSSITEM_IS_EMPTY(&akid->keyIdentifier)) {
	if (NSSItem_Duplicate(&akid->keyIdentifier, arena, 
	                      &copy->keyIdentifier) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    /* XXX do the rest */

    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXAuthorityKeyIdentifier *
nssPKIXAuthorityKeyIdentifier_Duplicate (
  NSSPKIXAuthorityKeyIdentifier *akid,
  NSSArena *arenaOpt
)
{
    NSSPKIXAuthorityKeyIdentifier *rv = (NSSPKIXAuthorityKeyIdentifier *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXAuthorityKeyIdentifier_duplicate(akid, rv->arena, rv) 
	  != PR_SUCCESS) 
	{
	    nssPKIXAuthorityKeyIdentifier_Destroy(rv);
	    return (NSSPKIXAuthorityKeyIdentifier *)NULL;
	}
    }

    return rv;
}

NSS_IMPLEMENT NSSPKIXKeyIdentifier *
nssPKIXAuthorityKeyIdentifier_GetKeyIdentifier (
  NSSPKIXAuthorityKeyIdentifier *aki
)
{
    return &aki->keyIdentifier;
}

/*
 * NSSPKIXAuthorityKeyIdentifier_Create
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
 *  A valid pointer to an NSSPKIXAuthorityKeyIdentifier upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXAuthorityKeyIdentifier *
NSSPKIXAuthorityKeyIdentifier_Create (
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    nss_ClearErrorStack();

    return nssPKIXAuthorityKeyIdentifier_Create(arenaOpt, extnID, critical, extnValue);
}
#endif

/*
 * NSSPKIXAuthorityKeyIdentifier_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXAuthorityKeyIdentifier upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXAuthorityKeyIdentifier *
NSSPKIXAuthorityKeyIdentifier_Decode (
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXAuthorityKeyIdentifier_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXAuthorityKeyIdentifier_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXAuthorityKeyIdentifier_Destroy (
  NSSPKIXAuthorityKeyIdentifier *akid
)
{
    nss_ClearErrorStack();

    return nssPKIXAuthorityKeyIdentifier_Destroy(akid);
}

/*
 * NSSPKIXAuthorityKeyIdentifier_Duplicate
 *
 */

#if 0
NSS_IMPLEMENT NSSPKIXAuthorityKeyIdentifier *
NSSPKIXAuthorityKeyIdentifier_Duplicate (
  NSSPKIXAuthorityKeyIdentifier *akid,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXAuthorityKeyIdentifier_Duplicate(akid, arenaOpt);
}
#endif

/*
 * NSSPKIXAuthorityKeyIdentifier_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXAuthorityKeyIdentifier_Encode (
  NSSPKIXAuthorityKeyIdentifier *akid,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either akid has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(akid));
#endif

    return nssPKIXAuthorityKeyIdentifier_Encode(akid, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSPKIXKeyIdentifier *
NSSPKIXAuthorityKeyIdentifier_GetKeyIdentifier (
  NSSPKIXAuthorityKeyIdentifier *akid
)
{
    return nssPKIXAuthorityKeyIdentifier_GetKeyIdentifier(akid);
}

