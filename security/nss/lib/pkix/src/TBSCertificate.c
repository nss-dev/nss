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
 * nssPKIXTBSCertificate_template
 *
 */
#if 0
   offsetof(NSSPKIXTBSCertificate, version),
   { NSSASN1_INTEGER, 0, NULL, sizeof(NSSPKIXVersion) } },
#endif

static const NSSASN1Template skipper[] = {
  { NSSASN1_SKIP }
};

static const NSSASN1Template sub_any[] = {
  { NSSASN1_ANY }
};

const NSSASN1Template nssPKIXTBSCertificate_template[] = 
{
 { NSSASN1_SEQUENCE,   0, NULL, sizeof(NSSPKIXTBSCertificate) },
 { NSSASN1_EXPLICIT | NSSASN1_OPTIONAL | 
   NSSASN1_CONSTRUCTED | NSSASN1_CONTEXT_SPECIFIC | 0, 0, skipper },
 { NSSASN1_INTEGER, offsetof(NSSPKIXTBSCertificate, serialNumber) },
 { NSSASN1_SKIP }, /* XXX signature */
 { NSSASN1_ANY, offsetof(NSSPKIXTBSCertificate, issuer.der) },
 { NSSASN1_ANY, offsetof(NSSPKIXTBSCertificate, validity.der) },
 { NSSASN1_ANY, offsetof(NSSPKIXTBSCertificate, subject.der) },
 { NSSASN1_SKIP }, /* XXX pubkey */
 { NSSASN1_OPTIONAL |  /* issuerID */
   NSSASN1_CONSTRUCTED | NSSASN1_CONTEXT_SPECIFIC | 1, 0, skipper },
 { NSSASN1_OPTIONAL |  /* subjectID */
   NSSASN1_CONSTRUCTED | NSSASN1_CONTEXT_SPECIFIC | 2, 0, skipper },
 { NSSASN1_EXPLICIT | NSSASN1_OPTIONAL | 
   NSSASN1_CONSTRUCTED | NSSASN1_CONTEXT_SPECIFIC | 3,
     offsetof(NSSPKIXTBSCertificate, extensions.der),
     sub_any },
 { 0 }
};

static PRStatus
encode_me(NSSPKIXTBSCertificate *tbsCert)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&tbsCert->der)) {
	if ((NSSBER *)NULL == 
	      NSSASN1_EncodeItem(tbsCert->arena, 
	                         &tbsCert->der,
	                         tbsCert,
	                         nssPKIXTBSCertificate_template, 
	                         encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXTBSCertificate *tbsCert)
{
    if (!NSSITEM_IS_EMPTY(&tbsCert->der)) {
	return NSSASN1_DecodeBER(tbsCert->arena, tbsCert, 
	                         nssPKIXTBSCertificate_template, 
	                         &tbsCert->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXTBSCertificate *
create_me
(
  NSSArena *arenaOpt
)
{
    NSSArena *arena;
    PRBool arena_allocated = PR_FALSE;
    nssArenaMark *mark = (nssArenaMark *)NULL;
    NSSPKIXTBSCertificate *rv = (NSSPKIXTBSCertificate *)NULL;

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

    rv = nss_ZNEW(arena, NSSPKIXTBSCertificate);
    if ((NSSPKIXTBSCertificate *)NULL == rv) {
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

    return (NSSPKIXTBSCertificate *)NULL;
}

NSS_IMPLEMENT NSSPKIXTBSCertificate *
nssPKIXTBSCertificate_Create
(
  NSSArena *arenaOpt,
  NSSPKIXVersion version,
  NSSPKIXCertificateSerialNumber *serialNumber,
  NSSPKIXAlgorithmIdentifier *signature,
  NSSPKIXName *issuer,
  NSSPKIXValidity *validity,
  NSSPKIXName *subject,
  NSSPKIXSubjectPublicKeyInfo *spki,
  NSSPKIXUniqueIdentifier *issuerUniqueID,
  NSSPKIXUniqueIdentifier *subjectUniqueID,
  NSSPKIXExtensions *extensions
)
{
    NSSPKIXTBSCertificate *rv = (NSSPKIXTBSCertificate *)NULL;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXTBSCertificate *)NULL;
    }

    return rv;
}

NSS_IMPLEMENT NSSPKIXTBSCertificate *
nssPKIXTBSCertificate_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    NSSPKIXTBSCertificate *rv = (NSSPKIXTBSCertificate *)NULL;
    PRStatus status;

    rv = create_me(arenaOpt);
    if (!rv) {
	return (NSSPKIXTBSCertificate *)NULL;
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
    nssPKIXTBSCertificate_Destroy(rv);
    return (NSSPKIXTBSCertificate *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXTBSCertificate_Destroy
(
  NSSPKIXTBSCertificate *tbsCert
)
{

    if (PR_TRUE == tbsCert->i_allocated_arena) {
	return NSSArena_Destroy(tbsCert->arena);
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSBER *
nssPKIXTBSCertificate_Encode
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    PRStatus status;
    switch (encoding) {
    case NSSASN1BER:
    case NSSASN1DER:
	status = encode_me(tbsCert);
	if (status == PR_FAILURE) {
	    return (NSSBER *)NULL;
	}
	return &tbsCert->der;
    default:
#ifdef nodef
	nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
	return (NSSBER *)NULL;
    }
}

NSS_IMPLEMENT void
nssPKIXTBSCertificate_SetArena
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSArena *arena
)
{
    tbsCert->arena = arena;
    nssPKIXName_SetArena(&tbsCert->issuer, arena);
    nssPKIXValidity_SetArena(&tbsCert->validity, arena);
    nssPKIXName_SetArena(&tbsCert->subject, arena);
    nssPKIXExtensions_SetArena(&tbsCert->extensions, arena);
}

NSS_IMPLEMENT NSSPKIXCertificateSerialNumber *
nssPKIXTBSCertificate_GetSerialNumber
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    if (NSSITEM_IS_EMPTY(&tbsCert->serialNumber)) {
	if (NSSITEM_IS_EMPTY(&tbsCert->der) ||
	    decode_me(tbsCert) == PR_FAILURE)
	{
	    return (NSSPKIXCertificateSerialNumber *)NULL;
	}
    }
    return &tbsCert->serialNumber;
}

NSS_IMPLEMENT NSSPKIXName *
nssPKIXTBSCertificate_GetIssuer
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    if (NSSITEM_IS_EMPTY(&tbsCert->issuer.der)) {
	if (NSSITEM_IS_EMPTY(&tbsCert->der) ||
	    decode_me(tbsCert) == PR_FAILURE)
	{
	    return (NSSPKIXName *)NULL;
	}
    }
    return &tbsCert->issuer;
}

NSS_IMPLEMENT PRStatus
nssPKIXTBSCertificate_SetIssuer
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSPKIXName *issuer
)
{
    tbsCert->issuer = *issuer;
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXValidity *
nssPKIXTBSCertificate_GetValidity
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    if (NSSITEM_IS_EMPTY(&tbsCert->validity.der)) {
	if (NSSITEM_IS_EMPTY(&tbsCert->der) ||
	    decode_me(tbsCert) == PR_FAILURE)
	{
	    return (NSSPKIXValidity *)NULL;
	}
    }
    return &tbsCert->validity;
}

NSS_IMPLEMENT NSSPKIXName *
nssPKIXTBSCertificate_GetSubject
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    if (NSSITEM_IS_EMPTY(&tbsCert->subject.der)) {
	if (NSSITEM_IS_EMPTY(&tbsCert->der) ||
	    decode_me(tbsCert) == PR_FAILURE)
	{
	    return (NSSPKIXName *)NULL;
	}
    }
    return &tbsCert->subject;
}

NSS_IMPLEMENT PRStatus
nssPKIXTBSCertificate_SetSubject
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSPKIXName *subject
)
{
    tbsCert->subject = *subject;
    return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXExtensions *
nssPKIXTBSCertificate_GetExtensions
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    if (NSSITEM_IS_EMPTY(&tbsCert->subject.der)) {
	if (NSSITEM_IS_EMPTY(&tbsCert->der) ||
	    decode_me(tbsCert) == PR_FAILURE)
	{
	    return (NSSPKIXExtensions *)NULL;
	}
    }
    return &tbsCert->extensions;
}

NSS_IMPLEMENT PRBool
nssPKIXTBSCertificate_Equal
(
  NSSPKIXTBSCertificate *one,
  NSSPKIXTBSCertificate *two,
  PRStatus *statusOpt
)
{
    encode_me(one);
    encode_me(two);
    return NSSItem_Equal(&one->der, &two->der, statusOpt);
}

NSS_IMPLEMENT PRStatus
nssPKIXTBSCertificate_duplicate
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSArena *arena,
  NSSPKIXTBSCertificate *copy
)
{
#if 0
    PRStatus status;

    if (!NSSITEM_IS_EMPTY(&tbsCert->der)) {
	if (NSSItem_Duplicate(&tbsCert->der, arena, &copy->der) 
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }

    status = nssPKIXTBSCertificate_duplicate(&tbsCert->tbsCertificate,
                                             arena,
                                             &copy->tbsCertificate);
    if (status != PR_SUCCESS) {
	return status;
    }

    if (!NSSITEM_IS_EMPTY(&tbsCert->signature)) {
	if (NSSItem_Duplicate(&tbsCert->signature, arena, &copy->signature)
	     == (NSSItem *)NULL) 
	{
	    return PR_FAILURE;
	}
    }
    
    return PR_SUCCESS;
#endif
    return PR_FAILURE;
}

NSS_IMPLEMENT NSSPKIXTBSCertificate *
nssPKIXTBSCertificate_Duplicate
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSArena *arenaOpt
)
{
    NSSPKIXTBSCertificate *rv = (NSSPKIXTBSCertificate *)NULL;

    rv = create_me(arenaOpt);
    if (rv) {
	if (nssPKIXTBSCertificate_duplicate(tbsCert, rv->arena, rv) 
	     != PR_SUCCESS) 
	{
	    nssPKIXTBSCertificate_Destroy(rv);
	    return (NSSPKIXTBSCertificate *)NULL;
	}
    }

    return rv;
}

/*
 * NSSPKIXTBSCertificate_Create
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
 *  A valid pointer to an NSSPKIXTBSCertificate upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXTBSCertificate *
NSSPKIXTBSCertificate_Create
(
  NSSArena *arenaOpt,
  NSSPKIXVersion version,
  NSSPKIXCertificateSerialNumber *serialNumber,
  NSSPKIXAlgorithmIdentifier *signature,
  NSSPKIXName *issuer,
  NSSPKIXValidity *validity,
  NSSPKIXName *subject,
  NSSPKIXSubjectPublicKeyInfo *spki,
  NSSPKIXUniqueIdentifier *issuerUniqueID,
  NSSPKIXUniqueIdentifier *subjectUniqueID,
  NSSPKIXExtensions *extensions
)
{
    nss_ClearErrorStack();

    return nssPKIXTBSCertificate_Create(arenaOpt, version, serialNumber,
                                        signature, issuer, validity,
                                        subject, spki, issuerUniqueID,
                                        subjectUniqueID, extensions);
}

/*
 * NSSPKIXTBSCertificate_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXTBSCertificate upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXTBSCertificate *
NSSPKIXTBSCertificate_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
    nss_ClearErrorStack();

    return nssPKIXTBSCertificate_Decode(arenaOpt, ber);
}

/*
 * NSSPKIXTBSCertificate_Destroy
 *
 */

NSS_IMPLEMENT PRStatus
NSSPKIXTBSCertificate_Destroy
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    nss_ClearErrorStack();

    return nssPKIXTBSCertificate_Destroy(tbsCert);
}

/*
 * NSSPKIXTBSCertificate_Duplicate
 *
 */

NSS_IMPLEMENT NSSPKIXTBSCertificate *
NSSPKIXTBSCertificate_Duplicate
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXTBSCertificate_Duplicate(tbsCert, arenaOpt);
}

/*
 * NSSPKIXTBSCertificate_Encode
 *
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXTBSCertificate_Encode
(
  NSSPKIXTBSCertificate *tbsCert,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
    nss_ClearErrorStack();

    return nssPKIXTBSCertificate_Encode(tbsCert, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT NSSPKIXCertificateSerialNumber *
NSSPKIXTBSCertificate_GetSerialNumber
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    return nssPKIXTBSCertificate_GetSerialNumber(tbsCert);
}

/*
 * NSSPKIXTBSCertificate_GetIssuer
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_TBS_CERTIFICATE
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
NSSPKIXTBSCertificate_GetIssuer
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    nss_ClearErrorStack();

    return nssPKIXTBSCertificate_GetIssuer(tbsCert);
}

NSS_IMPLEMENT NSSPKIXValidity *
NSSPKIXTBSCertificate_GetValidity
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    return nssPKIXTBSCertificate_GetValidity(tbsCert);
}

NSS_IMPLEMENT NSSPKIXExtensions *
NSSPKIXTBSCertificate_GetExtensions
(
  NSSPKIXTBSCertificate *tbsCert
)
{
    return nssPKIXTBSCertificate_GetExtensions(tbsCert);
}

