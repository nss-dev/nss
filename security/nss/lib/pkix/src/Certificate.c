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
 * nssPKIXCertificate_template
 *
 */

const NSSASN1Template nssPKIXCertificate_template[] = 
{
 { NSSASN1_SEQUENCE,   0, NULL, sizeof(NSSPKIXCertificate)                  },
 { NSSASN1_ANY,        offsetof(NSSPKIXCertificate, tbsCertificate.der)     },
 { NSSASN1_ANY,        offsetof(NSSPKIXCertificate, signatureAlgorithm.der) },
 { NSSASN1_BIT_STRING, offsetof(NSSPKIXCertificate, signature)              },
 { 0 }
};

static PRStatus
encode_me(NSSPKIXCertificate *cert)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&cert->der)) {
#if 0
	if (NSSITEM_IS_EMPTY(&cert->tbsCertificate.der)) {
	    status = nssTBSCertificate_Encode(&cert->tbsCertificate);
	}
	if (NSSITEM_IS_EMPTY(&cert->signatureAlgorithm.der)) {
	    status = nssAlgorithmIdentifer_Encode(&cert->signatureAlgorithm);
	}
#endif
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(cert->arena, 
	                                         &cert->der,
	                                         cert,
	                                         nssPKIXCertificate_template, 
	                                         encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXCertificate *cert)
{
    if (!NSSITEM_IS_EMPTY(&cert->der)) {
	return NSSASN1_DecodeBER(cert->arena, cert, 
	                         nssPKIXCertificate_template, &cert->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXCertificate *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXCertificate *rv = (NSSPKIXCertificate *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXCertificate);
    if ((NSSPKIXCertificate *)NULL == rv) {
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

    return (NSSPKIXCertificate *)NULL;
}

NSS_IMPLEMENT NSSPKIXCertificate *
nssPKIXCertificate_Create
(
  NSSArena *arenaOpt,
  NSSPKIXTBSCertificate *tbsCert,
  NSSPKIXAlgorithmIdentifier *algID,
  NSSItem *signature
)
{
    NSSPKIXCertificate *rv = (NSSPKIXCertificate *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXCertificate *)NULL;
    }

    rv->tbsCertificate = *tbsCert;
    rv->signatureAlgorithm = *algID;
    rv->signature = *signature;

    return rv;
}

NSS_IMPLEMENT NSSPKIXCertificate *
nssPKIXCertificate_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXCertificate *rv = (NSSPKIXCertificate *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXCertificate *)NULL;
    }

    if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
	goto loser;
    }

    status = decode_me(rv);
    if (PR_SUCCESS != status) {
	goto loser;
    }

    nssPKIXCertificate_SetArena(rv, rv->arena);

    return rv;

loser:
    nssPKIXCertificate_Destroy(rv);
    return (NSSPKIXCertificate *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXCertificate_Destroy
(
  NSSPKIXCertificate *cert
)
{

    if (PR_TRUE == cert->i_allocated_arena) {
	return NSSArena_Destroy(cert->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXCertificate_Encode
(
  NSSPKIXCertificate *cert,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(cert);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &cert->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

NSS_IMPLEMENT void
nssPKIXCertificate_SetArena
(
  NSSPKIXCertificate *cert,
  NSSArena *arena
)
{
    cert->arena = arena;
    nssPKIXTBSCertificate_SetArena(&cert->tbsCertificate, arena);
#if 0
    nssPKIXAlgorithmIdentifier_SetArena(&cert->signatureAlgorithm, arena);
#endif
}

NSS_IMPLEMENT NSSPKIXTBSCertificate *
nssPKIXCertificate_GetTBSCertificate
(
  NSSPKIXCertificate *cert
)
{
    return &cert->tbsCertificate;
}

NSS_IMPLEMENT void
nssPKIXCertificate_SetTBSCertificate
(
  NSSPKIXCertificate *cert,
  NSSPKIXTBSCertificate *tbsCert
)
{
    cert->tbsCertificate = *tbsCert;
}

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
nssPKIXCertificate_GetAlgorithmIdentifier
(
  NSSPKIXCertificate *cert
)
{
    return &cert->signatureAlgorithm;
}

NSS_IMPLEMENT void
nssPKIXCertificate_SetAlgorithmIdentifier
(
  NSSPKIXCertificate *cert,
  NSSPKIXAlgorithmIdentifier *algid
)
{
    cert->signatureAlgorithm = *algid;
}

NSS_IMPLEMENT NSSItem *
nssPKIXCertificate_GetSignature
(
  NSSPKIXCertificate *cert
)
{
    if (cert->signature.data == NULL) {
	return (NSSItem *)NULL;
    }
    return &cert->signature;
}

NSS_IMPLEMENT void
nssPKIXCertificate_SetSignature
(
  NSSPKIXCertificate *cert,
  NSSItem *signature
)
{
    cert->signature = *signature;
}

NSS_IMPLEMENT PRBool
nssPKIXCertificate_Equal
(
  NSSPKIXCertificate *one,
  NSSPKIXCertificate *two,
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

    if (!nssPKIXTBSCertificate_Equal(&one->tbsCertificate,
                                     &two->tbsCertificate, statusOpt))
    {
	return PR_FALSE;
    }

#if 0
    if (!nssPKIXAlgorithmIdentifier_Equal(&one->signatureAlgorithm,
                                          &two->signatureAlgorithm, statusOpt))
    {
	return PR_FALSE;
    }
#endif

    return NSSItem_Equal(&one->signature, &two->signature, statusOpt);
}

NSS_IMPLEMENT PRStatus
nssPKIXCertificate_duplicate
(
  NSSPKIXCertificate *cert,
  NSSArena *arena,
  NSSPKIXCertificate *copy
)
{
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&cert->der)) {
	if (NSSItem_Duplicate(&cert->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    status = nssPKIXTBSCertificate_duplicate(&cert->tbsCertificate,
                                             arena,
                                             &copy->tbsCertificate);
    if (status != PR_SUCCESS) {
	return status;
    }

#if 0
    status = nssPKIXAlgorithmIdentifier_duplicate(&cert->signatureAlgorithm,
                                                  arena,
                                                  &copy->signatureAlgorithm);
    if (status != PR_SUCCESS) {
	return status;
    }
#endif

    if (!NSSITEM_IS_EMPTY(&cert->signature)) {
	if (NSSItem_Duplicate(&cert->signature, arena, &copy->signature)
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }
    
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXCertificate *
nssPKIXCertificate_Duplicate
(
  NSSPKIXCertificate *cert,
  NSSArena *arenaOpt
)
{
    NSSPKIXCertificate *rv = (NSSPKIXCertificate *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXCertificate_duplicate(cert, rv->arena, rv) != PR_SUCCESS) 
	{
	    nssPKIXCertificate_Destroy(rv);
	    return (NSSPKIXCertificate *)NULL;
	}
    }

    return rv;
}

/*
 * NSSPKIXCertificate_Create
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
 *  A valid pointer to an NSSPKIXCertificate upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXCertificate *
NSSPKIXCertificate_Create
(
  NSSArena *arenaOpt,
  NSSPKIXTBSCertificate *tbsCert,
  NSSPKIXAlgorithmIdentifier *algID,
  NSSItem *signature
)
{
    nss_ClearErrorStack();

    return nssPKIXCertificate_Create(arenaOpt, tbsCert, algID, signature);
}

/*
 * NSSPKIXCertificate_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXCertificate upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXCertificate *
NSSPKIXCertificate_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXCertificate_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXCertificate_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXCertificate_Destroy
(
  NSSPKIXCertificate *cert
)
{
    nss_ClearErrorStack();

    return nssPKIXCertificate_Destroy(cert);
}

/*
 * NSSPKIXCertificate_Duplicate
 *
 */

NSS_IMPLEMENT NSSPKIXCertificate *
NSSPKIXCertificate_Duplicate
(
  NSSPKIXCertificate *cert,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXCertificate_Duplicate(cert, arenaOpt);
}

/*
 * NSSPKIXCertificate_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXCertificate_Encode
(
  NSSPKIXCertificate *cert,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    /* XXX the idea is: assert that either cert has the DER or all of the
     * parts, as that could only be an application error
     */
#if 0
    PKIX_Assert(am_i_complete(cert));
#endif

    return nssPKIXCertificate_Encode(cert, encoding, rvOpt, arenaOpt);
}
/*
 * NSSPKIXCertificate_GetTBSCertificate
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_CERTIFICATE
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid pointer to an NSSPKIXTBSCertificate upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXTBSCertificate *
NSSPKIXCertificate_GetTBSCertificate
(
  NSSPKIXCertificate *cert
)
{
    nss_ClearErrorStack();

    return nssPKIXCertificate_GetTBSCertificate(cert);
}

/*
 * NSSPKIXCertificate_GetSignature
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid NSSOID pointer upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSItem *
NSSPKIXCertificate_GetSignature
(
  NSSPKIXCertificate *cert
)
{
    nss_ClearErrorStack();

    return nssPKIXCertificate_GetSignature(cert);
}

