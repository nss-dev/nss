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

/* XXX oid */
#include "nsspki1.h"

/*
 * nssPKIXExtension_template
 *
 */

const NSSASN1Template nssPKIXExtension_template[] = 
{
 { NSSASN1_SEQUENCE,     0, NULL, sizeof(NSSPKIXExtension)     },
 { NSSASN1_OBJECT_ID,    offsetof(NSSPKIXExtension, extnID)    },
 { NSSASN1_OPTIONAL | 
    NSSASN1_BOOLEAN,     offsetof(NSSPKIXExtension, critical)  },
 { NSSASN1_OCTET_STRING, offsetof(NSSPKIXExtension, extnValue) },
 { 0 }
};

static PRStatus
encode_me(NSSPKIXExtension *extension)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&extension->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(extension->arena, 
	                                         &extension->der,
	                                         extension,
	                                         nssPKIXExtension_template, 
	                                         encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXExtension *extension)
{
    if (!NSSITEM_IS_EMPTY(&extension->der)) {
	return NSSASN1_DecodeBER(extension->arena, extension, 
	                         nssPKIXExtension_template, &extension->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXExtension *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXExtension *rv = (NSSPKIXExtension *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXExtension);
    if ((NSSPKIXExtension *)NULL == rv) {
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

    return (NSSPKIXExtension *)NULL;
}

NSS_IMPLEMENT NSSPKIXExtension *
nssPKIXExtension_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    NSSPKIXExtension *rv = (NSSPKIXExtension *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXExtension *)NULL;
    }

#if 0
    NSSOID_Encode(extnID, &rv->extnID);
#endif
    rv->critical = critical;
    rv->extnValue = *extnValue;

    return rv;
}

NSS_IMPLEMENT void
nssPKIXExtension_SetArena
(
  NSSPKIXExtension *extension,
  NSSArena *arena
)
{
    extension->arena = arena;
}

NSS_IMPLEMENT NSSPKIXExtension *
nssPKIXExtension_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXExtension *rv = (NSSPKIXExtension *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXExtension *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    nssPKIXExtension_SetArena(rv, rv->arena);

    return rv;

loser:
    nssPKIXExtension_Destroy(rv);
    return (NSSPKIXExtension *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXExtension_Destroy
(
  NSSPKIXExtension *extension
)
{
    if (PR_TRUE == extension->i_allocated_arena) {
	return NSSArena_Destroy(extension->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXExtension_Encode
(
  NSSPKIXExtension *extension,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(extension);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &extension->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

NSS_IMPLEMENT void
nssPKIXExtension_SetExtensionID
(
  NSSPKIXExtension *extension,
  NSSOID *extnID
)
{
#if 0
    NSSOID_Encode(extnID, extension->arena, &extension->extnID);
#endif
}

NSS_IMPLEMENT PRBool
nssPKIXExtension_GetExtensionCritical
(
  NSSPKIXExtension *extension
)
{
    return extension->critical;
}

NSS_IMPLEMENT void
nssPKIXExtension_SetExtensionCritical
(
  NSSPKIXExtension *extension,
  PRBool critical
)
{
    extension->critical = critical;
}

NSS_IMPLEMENT NSSItem *
nssPKIXExtension_GetExtensionValue
(
  NSSPKIXExtension *extension
)
{
    return &extension->extnValue;
}

NSS_IMPLEMENT PRBool
nssPKIXExtension_Equal
(
  NSSPKIXExtension *one,
  NSSPKIXExtension *two,
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

#if 0
    if (!NSSOID_Equal(one->extnID, two->extnID)) {
	return PR_FALSE;
    }
#endif
    if (one->critical != two->critical) {
	return PR_FALSE;
    }
    return NSSItem_Equal(&one->extnValue, &two->extnValue, statusOpt);
}

NSS_IMPLEMENT PRStatus
nssPKIXExtension_duplicate
(
  NSSPKIXExtension *extension,
  NSSArena *arena,
  NSSPKIXExtension *copy
)
{
    if (!NSSITEM_IS_EMPTY(&extension->der)) {
	if (NSSItem_Duplicate(&extension->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    if (NSSItem_Duplicate(&extension->extnID, arena,  &copy->extnID)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    if (NSSItem_Duplicate(&extension->extnValue, arena,  &copy->extnValue)
         == (NSSItem *)NULL)
    {
	return PR_FAILURE;
    }

    copy->extnID = extension->extnID;
    copy->critical = extension->critical;

    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXExtension *
nssPKIXExtension_Duplicate
(
  NSSPKIXExtension *extension,
  NSSArena *arenaOpt
)
{
    NSSPKIXExtension *rv = (NSSPKIXExtension *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXExtension_duplicate(extension, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXExtension_Destroy(rv);
	    return (NSSPKIXExtension *)NULL;
	}
    }

    return rv;
}

NSS_IMPLEMENT NSSOID *
nssPKIXExtension_GetExtensionID
(
  NSSPKIXExtension *extension
)
{
    if (NSSITEM_IS_EMPTY(&extension->extnID)) {
	if (NSSITEM_IS_EMPTY(&extension->der) ||
	    decode_me(extension) == PR_FAILURE)
	{
	    return (NSSOID *)NULL;
	}
    }
    return NSSOID_Create(&extension->extnID);
}

/*
 * NSSPKIXExtension_Create
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
 *  A valid pointer to an NSSPKIXExtension upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXExtension *
NSSPKIXExtension_Create
(
  NSSArena *arenaOpt,
  NSSOID *extnID,
  PRBool critical,
  NSSItem *extnValue
)
{
    nss_ClearErrorStack();

    return nssPKIXExtension_Create(arenaOpt, extnID, critical, extnValue);
}

/*
 * NSSPKIXExtension_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXExtension upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXExtension *
NSSPKIXExtension_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXExtension_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXExtension_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXExtension_Destroy
(
  NSSPKIXExtension *extension
)
{
    nss_ClearErrorStack();

    return nssPKIXExtension_Destroy(extension);
}

/*
 * NSSPKIXExtension_Duplicate
 *
 */

NSS_IMPLEMENT NSSPKIXExtension *
NSSPKIXExtension_Duplicate
(
  NSSPKIXExtension *extension,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXExtension_Duplicate(extension, arenaOpt);
}

/*
 * NSSPKIXExtension_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXExtension_Encode
(
  NSSPKIXExtension *extension,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either extension has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(extension));
#endif

    return nssPKIXExtension_Encode(extension, encoding, rvOpt, arenaOpt);
}

