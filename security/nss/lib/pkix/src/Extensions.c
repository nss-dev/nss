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

#ifndef NSSPKI1_H
#include "nsspki1.h"
#endif /* NSSPKI1_H */

/*
 * nssPKIXExtensions_template
 *
 */

const NSSASN1Template nssPKIXExtensions_template[] = 
{
#if 0
 { NSSASN1_SEQUENCE_OF, offsetof(NSSPKIXExtensions, extensions), 
   nssPKIXExtension_template, sizeof(NSSPKIXExtensions) }
#endif
 { NSSASN1_SEQUENCE_OF, offsetof(NSSPKIXExtensions, extensions), 
   nssPKIXExtension_template }
};

static PRStatus
encode_me(NSSPKIXExtensions *extensions)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&extensions->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(extensions->arena, 
	                                         &extensions->der,
	                                         extensions,
	                                         nssPKIXExtensions_template, 
	                                         encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXExtensions *extensions)
{
    if (!NSSITEM_IS_EMPTY(&extensions->der)) {
	return NSSASN1_DecodeBER(extensions->arena, extensions, 
	                         nssPKIXExtensions_template, &extensions->der);
    } else {
	return PR_FAILURE;
    }
}

static PRStatus
count_me(NSSPKIXExtensions *extensions)
{
    extensions->count = 0;
    if (!extensions->extensions) {
	if (NSSITEM_IS_EMPTY(&extensions->der)) {
	    return 0; /* there are none */
	}
	if (decode_me(extensions) == PR_FAILURE) {
	    return PR_FAILURE;
	}
    }
    while (extensions->extensions[++extensions->count]);
    return extensions->count;
}

static NSSPKIXExtensions *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXExtensions *rv = (NSSPKIXExtensions *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXExtensions);
    if ((NSSPKIXExtensions *)NULL == rv) {
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

    return (NSSPKIXExtensions *)NULL;
}

NSS_IMPLEMENT NSSPKIXExtensions *
nssPKIXExtensions_CreateFromArray
(
  NSSArena *arenaOpt,
  PRUint32 count,
  NSSPKIXExtension **extensions
)
{
    NSSPKIXExtensions *rv = (NSSPKIXExtensions *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXExtensions *)NULL;
    }

    rv->count = count;
    rv->extensions = extensions;

    return rv;
}

NSS_IMPLEMENT void
nssPKIXExtensions_SetArena
(
  NSSPKIXExtensions *extensions,
  NSSArena *arena
)
{
    extensions->arena = arena;
}

NSS_IMPLEMENT NSSPKIXExtensions *
nssPKIXExtensions_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXExtensions *rv = (NSSPKIXExtensions *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXExtensions *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    nssPKIXExtensions_SetArena(rv, rv->arena);

    return rv;

loser:
    nssPKIXExtensions_Destroy(rv);
    return (NSSPKIXExtensions *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXExtensions_Destroy
(
  NSSPKIXExtensions *extensions
)
{
    if (PR_TRUE == extensions->i_allocated_arena) {
	return NSSArena_Destroy(extensions->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXExtensions_Encode
(
  NSSPKIXExtensions *extensions,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(extensions);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &extensions->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

NSS_IMPLEMENT PRBool
nssPKIXExtensions_Equal
(
  NSSPKIXExtensions *one,
  NSSPKIXExtensions *two,
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

    /* XXX */ return PR_FALSE;
}

NSS_IMPLEMENT PRStatus
nssPKIXExtensions_duplicate
(
  NSSPKIXExtensions *extensions,
  NSSArena *arena,
  NSSPKIXExtensions *copy
)
{
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&extensions->der)) {
	if (NSSItem_Duplicate(&extensions->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    /* XXX */ return PR_FAILURE;
}

NSS_IMPLEMENT NSSPKIXExtensions *
nssPKIXExtensions_Duplicate
(
  NSSPKIXExtensions *extensions,
  NSSArena *arenaOpt
)
{
    NSSPKIXExtensions *rv = (NSSPKIXExtensions *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXExtensions_duplicate(extensions, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXExtensions_Destroy(rv);
	    return (NSSPKIXExtensions *)NULL;
	}
    }

    return rv;
}

NSS_IMPLEMENT PRInt32
nssPKIXExtensions_GetExtensionCount
(
  NSSPKIXExtensions *extensions
)
{
    if (extensions->count == 0) {
	count_me(extensions);
    }
    return extensions->count;
}

NSS_IMPLEMENT NSSPKIXExtension *
nssPKIXExtensions_GetExtension
(
  NSSPKIXExtensions *extensions,
  PRInt32 i
)
{
    if (extensions->count == 0) {
	count_me(extensions);
	if (extensions->count < 0) {
	    return (NSSPKIXExtension *)NULL;
	}
    }

    if (i < 0 || i >= extensions->count) {
	return (NSSPKIXExtension *)NULL;
    }

    return extensions->extensions[i];
}

NSS_IMPLEMENT NSSPKIXBasicConstraints *
nssPKIXExtensions_GetBasicConstraints
(
  NSSPKIXExtensions *extensions
)
{
    NSSOID *extnOID;
    NSSPKIXBasicConstraints *rv = NULL;
    NSSPKIXExtension **extns;
    PRIntn i;
    if (extensions->count == 0) {
	count_me(extensions);
	if (extensions->count < 0) {
	    return (NSSPKIXBasicConstraints *)NULL;
	}
    }
    extns = extensions->extensions;
    for (i = 0; i < extensions->count; i++) {
	extnOID = nssPKIXExtension_GetExtensionID(extns[i]);
	if (NSSOID_IsTag(extnOID, NSS_OID_X509_BASIC_CONSTRAINTS)) {
	    if (extns[i]->extnData) {
		return (NSSPKIXBasicConstraints *)extns[i]->extnData;
	    }
	    rv = nssPKIXBasicConstraints_Decode(extns[i]->arena,
	                                        &extns[i]->extnValue);
	    if (rv) {
		extns[i]->extnData = (void *)rv;
	    }
	}
    }
    return rv;
}

NSS_IMPLEMENT NSSPKIXKeyUsage *
nssPKIXExtensions_GetKeyUsage
(
  NSSPKIXExtensions *extensions
)
{
    NSSOID *extnOID;
    NSSPKIXKeyUsage *rv = NULL;
    NSSPKIXExtension **extns;
    PRIntn i;
    if (extensions->count == 0) {
	count_me(extensions);
	if (extensions->count < 0) {
	    return (NSSPKIXKeyUsage *)NULL;
	}
    }
    extns = extensions->extensions;
    for (i = 0; i < extensions->count; i++) {
	extnOID = nssPKIXExtension_GetExtensionID(extns[i]);
	if (NSSOID_IsTag(extnOID, NSS_OID_X509_KEY_USAGE)) {
	    if (extns[i]->extnData) {
		return (NSSPKIXKeyUsage *)extns[i]->extnData;
	    }
	    rv = nssPKIXKeyUsage_Decode(extns[i]->arena,
	                                &extns[i]->extnValue);
	    if (rv) {
		extns[i]->extnData = (void *)rv;
	    }
	}
    }
    return rv;
}

NSS_IMPLEMENT NSSPKIXnetscapeCertType *
nssPKIXExtensions_GetNetscapeCertType
(
  NSSPKIXExtensions *extensions
)
{
    NSSOID *extnOID;
    NSSPKIXnetscapeCertType *rv = NULL;
    NSSPKIXExtension **extns;
    PRIntn i;
    if (extensions->count == 0) {
	count_me(extensions);
	if (extensions->count < 0) {
	    return (NSSPKIXnetscapeCertType *)NULL;
	}
    }
    extns = extensions->extensions;
    for (i = 0; i < extensions->count; i++) {
	extnOID = nssPKIXExtension_GetExtensionID(extns[i]);
	if (NSSOID_IsTag(extnOID, NSS_OID_NS_CERT_EXT_CERT_TYPE)) {
	    if (extns[i]->extnData) {
		return (NSSPKIXnetscapeCertType *)extns[i]->extnData;
	    }
	    rv = nssPKIXnetscapeCertType_Decode(extns[i]->arena,
	                                        &extns[i]->extnValue);
	    if (rv) {
		extns[i]->extnData = (void *)rv;
	    }
	}
    }
    return rv;
}

/*
 * NSSPKIXExtensions_Create
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
 *  A valid pointer to an NSSPKIXExtensions upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXExtensions *
NSSPKIXExtensions_CreateFromArray
(
  NSSArena *arenaOpt,
  PRUint32 count,
  NSSPKIXExtension **extensions
)
{
    nss_ClearErrorStack();

    return nssPKIXExtensions_CreateFromArray(arenaOpt, count, extensions);
}

/*
 * NSSPKIXExtensions_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXExtensions upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXExtensions *
NSSPKIXExtensions_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXExtensions_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXExtensions_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXExtensions_Destroy
(
  NSSPKIXExtensions *extensions
)
{
    nss_ClearErrorStack();

    return nssPKIXExtensions_Destroy(extensions);
}

/*
 * NSSPKIXExtensions_Duplicate
 *
 */

NSS_IMPLEMENT NSSPKIXExtensions *
NSSPKIXExtensions_Duplicate
(
  NSSPKIXExtensions *extensions,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXExtensions_Duplicate(extensions, arenaOpt);
}

/*
 * NSSPKIXExtensions_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXExtensions_Encode
(
  NSSPKIXExtensions *extensions,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either extensions has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(extensions));
#endif

    return nssPKIXExtensions_Encode(extensions, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRInt32
NSSPKIXExtensions_GetExtensionCount
(
  NSSPKIXExtensions *extensions
)
{
    return nssPKIXExtensions_GetExtensionCount(extensions);
}

NSS_IMPLEMENT NSSPKIXBasicConstraints *
NSSPKIXExtensions_GetBasicConstraints
(
  NSSPKIXExtensions *extensions
)
{
    return nssPKIXExtensions_GetBasicConstraints(extensions);
}

NSS_IMPLEMENT NSSPKIXKeyUsage *
NSSPKIXExtensions_GetKeyUsage
(
  NSSPKIXExtensions *extensions
)
{
    return nssPKIXExtensions_GetKeyUsage(extensions);
}

NSS_IMPLEMENT NSSPKIXnetscapeCertType *
NSSPKIXExtensions_GetNetscapeCertType
(
  NSSPKIXExtensions *extensions
)
{
    return nssPKIXExtensions_GetNetscapeCertType(extensions);
}

