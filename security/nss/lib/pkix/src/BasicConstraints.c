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
 * nssPKIXBasicConstraints_template
 *
 */

const NSSASN1Template nssPKIXBasicConstraints_template[] = 
{
 { NSSASN1_SEQUENCE, 0, NULL, sizeof(NSSPKIXBasicConstraints)   },
 { NSSASN1_OPTIONAL | 
    NSSASN1_BOOLEAN, offsetof(NSSPKIXBasicConstraints, cA)    },
 { NSSASN1_OPTIONAL |
    NSSASN1_INTEGER, offsetof(NSSPKIXBasicConstraints, plcItem) },
 { 0 }
};

static PRStatus
encode_me(NSSPKIXBasicConstraints *basicConstraints)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&basicConstraints->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(
	                                    basicConstraints->arena, 
	                                    &basicConstraints->der,
	                                    basicConstraints,
	                                    nssPKIXBasicConstraints_template, 
	                                    encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXBasicConstraints *basicConstraints)
{
    if (!NSSITEM_IS_EMPTY(&basicConstraints->der)) {
	return NSSASN1_DecodeBER(basicConstraints->arena, basicConstraints, 
	                         nssPKIXBasicConstraints_template, 
                                 &basicConstraints->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXBasicConstraints *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXBasicConstraints *rv = (NSSPKIXBasicConstraints *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXBasicConstraints);
    if ((NSSPKIXBasicConstraints *)NULL == rv) {
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

    return (NSSPKIXBasicConstraints *)NULL;
}

#if 0
NSS_IMPLEMENT NSSPKIXBasicConstraints *
nssPKIXBasicConstraints_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    NSSPKIXBasicConstraints *rv = (NSSPKIXBasicConstraints *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXBasicConstraints *)NULL;
    }

#if 0
    NSSOID_Encode(extnID, &rv->extnID);
#endif
    rv->critical = critical;
    rv->extnValue = *extnValue;

    return rv;
}
#endif

NSS_IMPLEMENT NSSPKIXBasicConstraints *
nssPKIXBasicConstraints_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXBasicConstraints *rv = (NSSPKIXBasicConstraints *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXBasicConstraints *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    /* XXX this logic belongs elsewhere, methinks */
    if (rv->plcItem.data == NULL) {
	/* the path length constraint is not present, for a CA cert
	 * this implies unlimited path.
	 */
	if (rv->cA) {
	    rv->pathLenConstraint = NSSPKIX_UNLIMITED_PATH_CONSTRAINT;
	}
    } else if (rv->cA) {
	    /* XXX hack, should happen in decoder */
	unsigned char *d = (unsigned char *)rv->plcItem.data;
	rv->pathLenConstraint = d[0] << 24 |
	                        d[1] << 16 |
	                        d[2] << 8  |
	                        d[3];
    } else {
	/* XXX set error */
	goto loser;
    }

    return rv;

loser:
    nssPKIXBasicConstraints_Destroy(rv);
    return (NSSPKIXBasicConstraints *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXBasicConstraints_Destroy
(
  NSSPKIXBasicConstraints *basicConstraints
)
{
    if (PR_TRUE == basicConstraints->i_allocated_arena) {
	return NSSArena_Destroy(basicConstraints->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXBasicConstraints_Encode
(
  NSSPKIXBasicConstraints *basicConstraints,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(basicConstraints);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &basicConstraints->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

#if 0
NSS_IMPLEMENT PRBool
nssPKIXBasicConstraints_Equal
(
  NSSPKIXBasicConstraints *one,
  NSSPKIXBasicConstraints *two,
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
nssPKIXBasicConstraints_duplicate
(
  NSSPKIXBasicConstraints *basicConstraints,
  NSSArena *arena,
  NSSPKIXBasicConstraints *copy
)
{
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&basicConstraints->der)) {
	if (NSSItem_Duplicate(&basicConstraints->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    if (NSSItem_Duplicate(&basicConstraints->extnID, arena,  &copy->extnID)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    if (NSSItem_Duplicate(&basicConstraints->extnValue, arena,  &copy->extnValue)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    copy->extnID = basicConstraints->extnID;
    copy->critical = basicConstraints->critical;

    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXBasicConstraints *
nssPKIXBasicConstraints_Duplicate
(
  NSSPKIXBasicConstraints *basicConstraints,
  NSSArena *arenaOpt
)
{
    NSSPKIXBasicConstraints *rv = (NSSPKIXBasicConstraints *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXBasicConstraints_duplicate(basicConstraints, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXBasicConstraints_Destroy(rv);
	    return (NSSPKIXBasicConstraints *)NULL;
	}
    }

    return rv;
}
#endif

/*
 * NSSPKIXBasicConstraints_Create
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
 *  A valid pointer to an NSSPKIXBasicConstraints upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXBasicConstraints *
NSSPKIXBasicConstraints_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    nss_ClearErrorStack();

    return nssPKIXBasicConstraints_Create(arenaOpt, extnID, critical, extnValue);
}
#endif

/*
 * NSSPKIXBasicConstraints_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXBasicConstraints upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXBasicConstraints *
NSSPKIXBasicConstraints_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXBasicConstraints_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXBasicConstraints_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXBasicConstraints_Destroy
(
  NSSPKIXBasicConstraints *basicConstraints
)
{
    nss_ClearErrorStack();

    return nssPKIXBasicConstraints_Destroy(basicConstraints);
}

/*
 * NSSPKIXBasicConstraints_Duplicate
 *
 */

#if 0
NSS_IMPLEMENT NSSPKIXBasicConstraints *
NSSPKIXBasicConstraints_Duplicate
(
  NSSPKIXBasicConstraints *basicConstraints,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXBasicConstraints_Duplicate(basicConstraints, arenaOpt);
}
#endif

/*
 * NSSPKIXBasicConstraints_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXBasicConstraints_Encode
(
  NSSPKIXBasicConstraints *basicConstraints,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either basicConstraints has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(basicConstraints));
#endif

    return nssPKIXBasicConstraints_Encode(basicConstraints, encoding, rvOpt, arenaOpt);
}

