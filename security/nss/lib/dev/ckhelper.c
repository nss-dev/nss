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
static const char CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef NSSCKEPV_H
#include "nssckepv.h"
#endif /* NSSCKEPV_H */

#ifndef DEVM_H
#include "devm.h"
#endif /* DEVM_H */

#ifndef CKHELPER_H
#include "ckhelper.h"
#endif /* CKHELPER_H */

static const CK_BBOOL s_true = CK_TRUE;
NSS_IMPLEMENT_DATA const NSSItem
g_ck_true = { (CK_VOID_PTR)&s_true, sizeof(s_true) };

static const CK_BBOOL s_false = CK_FALSE;
NSS_IMPLEMENT_DATA const NSSItem
g_ck_false = { (CK_VOID_PTR)&s_false, sizeof(s_false) };

static const CK_OBJECT_CLASS s_class_cert = CKO_CERTIFICATE;
NSS_IMPLEMENT_DATA const NSSItem
g_ck_class_cert = { (CK_VOID_PTR)&s_class_cert, sizeof(s_class_cert) };

static const CK_OBJECT_CLASS s_class_pubkey = CKO_PUBLIC_KEY;
NSS_IMPLEMENT_DATA const NSSItem
g_ck_class_pubkey = { (CK_VOID_PTR)&s_class_pubkey, sizeof(s_class_pubkey) };

static const CK_OBJECT_CLASS s_class_privkey = CKO_PRIVATE_KEY;
NSS_IMPLEMENT_DATA const NSSItem
g_ck_class_privkey = { (CK_VOID_PTR)&s_class_privkey, sizeof(s_class_privkey) };

static PRBool
is_string_attribute
(
  CK_ATTRIBUTE_TYPE aType
)
{
    PRBool isString;
    switch (aType) {
    case CKA_LABEL:
    case CKA_NETSCAPE_EMAIL:
	isString = PR_TRUE;
	break;
    default:
	isString = PR_FALSE;
	break;
    }
    return isString;
}

NSS_IMPLEMENT PRStatus 
nssCKObject_GetAttributes
(
  CK_OBJECT_HANDLE object,
  CK_ATTRIBUTE_PTR obj_template,
  CK_ULONG count,
  NSSArena *arenaOpt,
  nssSession *session,
  NSSSlot *slot
)
{
    nssArenaMark *mark = NULL;
    CK_SESSION_HANDLE hSession;
    CK_ULONG i = 0;
    CK_RV ckrv;
    PRStatus nssrv;
    PRBool alloced = PR_FALSE;
    void *epv = nssSlot_GetCryptokiEPV(slot);
    hSession = session->handle; 
    if (arenaOpt) {
	mark = nssArena_Mark(arenaOpt);
	if (!mark) {
	    goto loser;
	}
    }
    nssSession_EnterMonitor(session);
    /* XXX kinda hacky, if the storage size is already in the first template
     * item, then skip the alloc portion
     */
    if (obj_template[0].ulValueLen == 0) {
	/* Get the storage size needed for each attribute */
	ckrv = CKAPI(epv)->C_GetAttributeValue(hSession,
	                                       object, obj_template, count);
	if (ckrv != CKR_OK && 
	    ckrv != CKR_ATTRIBUTE_TYPE_INVALID &&
	    ckrv != CKR_ATTRIBUTE_SENSITIVE) 
	{
	    nssSession_ExitMonitor(session);
	    /* set an error here */
	    goto loser;
	}
	/* Allocate memory for each attribute. */
	for (i=0; i<count; i++) {
	    CK_ULONG ulValueLen = obj_template[i].ulValueLen;
	    if (ulValueLen == 0) continue;
	    if (ulValueLen == (CK_ULONG) -1) {
		obj_template[i].ulValueLen = 0;
		continue;
	    }
	    if (is_string_attribute(obj_template[i].type)) {
		ulValueLen++;
	    }
	    obj_template[i].pValue = nss_ZAlloc(arenaOpt, ulValueLen);
	    if (!obj_template[i].pValue) {
		nssSession_ExitMonitor(session);
		goto loser;
	    }
	}
	alloced = PR_TRUE;
    }
    /* Obtain the actual attribute values. */
    ckrv = CKAPI(epv)->C_GetAttributeValue(hSession,
                                           object, obj_template, count);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK && 
        ckrv != CKR_ATTRIBUTE_TYPE_INVALID &&
        ckrv != CKR_ATTRIBUTE_SENSITIVE) 
    {
	/* set an error here */
	goto loser;
    }
    if (alloced && arenaOpt) {
	nssrv = nssArena_Unmark(arenaOpt, mark);
	if (nssrv != PR_SUCCESS) {
	    goto loser;
	}
    }

    if (count > 1 && ((ckrv == CKR_ATTRIBUTE_TYPE_INVALID) || 
					(ckrv == CKR_ATTRIBUTE_SENSITIVE))) {
	/* old tokens would keep the length of '0' and not deal with any
	 * of the attributes we passed. For those tokens read them one at
	 * a time */
	for (i=0; i < count; i++) {
	    if ((obj_template[i].ulValueLen == 0) 
				|| (obj_template[i].ulValueLen == -1)) {
		obj_template[i].ulValueLen=0;
		(void) nssCKObject_GetAttributes(object,&obj_template[i], 1,
			arenaOpt, session, slot);
	    }
	}
    }
    return PR_SUCCESS;
loser:
    if (alloced) {
	if (arenaOpt) {
	    /* release all arena memory allocated before the failure. */
	    (void)nssArena_Release(arenaOpt, mark);
	} else {
	    CK_ULONG j;
	    /* free each heap object that was allocated before the failure. */
	    for (j=0; j<i; j++) {
		nss_ZFreeIf(obj_template[j].pValue);
	    }
	}
    }
    return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssCKObject_GetAttributeItem
(
  CK_OBJECT_HANDLE object,
  CK_ATTRIBUTE_TYPE attribute,
  NSSArena *arenaOpt,
  nssSession *session,
  NSSSlot *slot,
  NSSItem *rvItem
)
{
    CK_ATTRIBUTE attr = { 0, NULL, 0 };
    PRStatus nssrv;
    attr.type = attribute;
    nssrv = nssCKObject_GetAttributes(object, &attr, 1, 
                                      arenaOpt, session, slot);
    if (nssrv != PR_SUCCESS) {
	return nssrv;
    }
    rvItem->data = (void *)attr.pValue;
    rvItem->size = (PRUint32)attr.ulValueLen;
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRBool
nssCKObject_IsAttributeTrue
(
  CK_OBJECT_HANDLE object,
  CK_ATTRIBUTE_TYPE attribute,
  nssSession *session,
  NSSSlot *slot,
  PRStatus *rvStatus
)
{
    CK_BBOOL bool;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE atemplate = { 0, NULL, 0 };
    CK_RV ckrv;
    void *epv = nssSlot_GetCryptokiEPV(slot);
    attr = &atemplate;
    NSS_CK_SET_ATTRIBUTE_VAR(attr, attribute, bool);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_GetAttributeValue(session->handle, object, 
                                           &atemplate, 1);
    nssSession_ExitMonitor(session);
    if (ckrv != CKR_OK) {
	*rvStatus = PR_FAILURE;
	return PR_FALSE;
    }
    *rvStatus = PR_SUCCESS;
    return (PRBool)(bool == CK_TRUE);
}

NSS_IMPLEMENT PRStatus 
nssCKObject_SetAttributes
(
  CK_OBJECT_HANDLE object,
  CK_ATTRIBUTE_PTR obj_template,
  CK_ULONG count,
  nssSession *session,
  NSSSlot  *slot
)
{
    CK_RV ckrv;
    void *epv = nssSlot_GetCryptokiEPV(slot);
    nssSession_EnterMonitor(session);
    ckrv = CKAPI(epv)->C_SetAttributeValue(session->handle, object, 
                                           obj_template, count);
    nssSession_ExitMonitor(session);
    if (ckrv == CKR_OK) {
	return PR_SUCCESS;
    } else {
	return PR_FAILURE;
    }
}

NSS_IMPLEMENT PRBool
nssCKObject_IsTokenObjectTemplate
(
  CK_ATTRIBUTE_PTR objectTemplate, 
  CK_ULONG otsize
)
{
    CK_ULONG ul;
    for (ul=0; ul<otsize; ul++) {
	if (objectTemplate[ul].type == CKA_TOKEN) {
	    return (*((CK_BBOOL*)objectTemplate[ul].pValue) == CK_TRUE);
	}
    }
    return PR_FALSE;
}

NSS_IMPLEMENT CK_ULONG
nssCKTemplate_SetOperationAttributes
(
  CK_ATTRIBUTE_PTR objTemplate,
  CK_ULONG otSize,
  NSSOperations operations
)
{
    PRUint32 op, numSet;
    CK_ATTRIBUTE_PTR attr;
    static const CK_ATTRIBUTE_TYPE operation_types[9] = {
	CKA_ENCRYPT,  CKA_DECRYPT,
	CKA_WRAP,     CKA_UNWRAP,
	CKA_SIGN,     CKA_SIGN_RECOVER,
	CKA_VERIFY,   CKA_VERIFY_RECOVER,
	CKA_DERIVE
    };
    PRUint32 numOp = sizeof(operation_types) / sizeof(CK_ATTRIBUTE_TYPE);
    PR_ASSERT(numOp <= otSize);
    attr = objTemplate;
    for (op = 0, numSet = 0; op < numOp; op++) {
	if (operations & (1 << op)) {
	    NSS_CK_SET_ATTRIBUTE_ITEM(attr, operation_types[op], &g_ck_true);
	    numSet++;
	    PR_ASSERT(numSet <= otSize);
	}
    }
    return numSet;
}

NSS_IMPLEMENT CK_ULONG
nssCKTemplate_SetPropertyAttributes
(
  CK_ATTRIBUTE_PTR objTemplate,
  CK_ULONG otSize,
  NSSProperties properties
)
{
    PRUint32 prop, numSet;
    CK_ATTRIBUTE_PTR attr;
    static const CK_ATTRIBUTE_TYPE property_types[4] = {
	CKA_PRIVATE,          CKA_MODIFIABLE,
	CKA_SENSITIVE,        CKA_EXTRACTABLE
    };
    PRUint32 numProp = sizeof(property_types) / sizeof(CK_ATTRIBUTE_TYPE);
    PR_ASSERT(numProp <= otSize);
    attr = objTemplate;
    for (prop = 0, numSet = 0; prop < numProp; prop++) {
	if (properties & (1 << prop)) {
	    NSS_CK_SET_ATTRIBUTE_ITEM(attr, property_types[prop], &g_ck_true);
	    numSet++;
	}
    }
    return numSet;
}

static NSSCertificateType
nss_cert_type_from_ck_attrib(CK_ATTRIBUTE_PTR attrib)
{
    CK_CERTIFICATE_TYPE ckCertType;
    if (!attrib->pValue) {
	/* default to PKIX */
	return NSSCertificateType_PKIX;
    }
    ckCertType = *((CK_ULONG *)attrib->pValue);
    switch (ckCertType) {
    case CKC_X_509:
	return NSSCertificateType_PKIX;
    default:
	break;
    }
    return NSSCertificateType_Unknown;
}

/* incoming pointers must be valid */
NSS_IMPLEMENT PRStatus
nssCryptokiCertificate_GetAttributes
(
  nssCryptokiObject *certObject,
  NSSArena *arenaOpt,
  NSSCertificateType *certTypeOpt,
  NSSItem *idOpt,
  NSSDER *encodingOpt,
  NSSDER *issuerOpt,
  NSSDER *serialOpt,
  NSSDER *subjectOpt,
  NSSASCII7 **emailOpt
)
{
    PRStatus status;
    PRUint32 i;
    nssTokenObjectCache *cache;
    NSSSlot *slot;
    CK_ULONG template_size;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE cert_template[7];

    /* Set up a template of all options chosen by caller */
    NSS_CK_TEMPLATE_START(cert_template, attr, template_size);
    if (certTypeOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_CERTIFICATE_TYPE);
    }
    if (idOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_ID);
    }
    if (encodingOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_VALUE);
    }
    if (issuerOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_ISSUER);
    }
    if (serialOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_SERIAL_NUMBER);
    }
    if (subjectOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_SUBJECT);
    }
    if (emailOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_NETSCAPE_EMAIL);
    }
    NSS_CK_TEMPLATE_FINISH(cert_template, attr, template_size);
    if (template_size == 0) {
	/* caller didn't want anything */
	return PR_SUCCESS;
    }

    status = PR_FAILURE;
    cache = nssToken_GetObjectCache(certObject->token);
    if (cache) {
	status = nssTokenObjectCache_GetObjectAttributes(cache, NULL,
	                                                 certObject, 
	                                                 CKO_CERTIFICATE,
	                                                 cert_template, 
	                                                 template_size);
    }
    if (status != PR_SUCCESS) {

	slot = nssToken_GetSlot(certObject->token);
	status = nssCKObject_GetAttributes(certObject->handle, 
	                                   cert_template, template_size,
	                                   arenaOpt, certObject->session, 
	                                   slot);
	nssSlot_Destroy(slot);
	if (status != PR_SUCCESS) {
	    return status;
	}
    }

    i=0;
    if (certTypeOpt) {
	*certTypeOpt = nss_cert_type_from_ck_attrib(&cert_template[i]); i++;
    }
    if (idOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&cert_template[i], idOpt); i++;
    }
    if (encodingOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&cert_template[i], encodingOpt); i++;
    }
    if (issuerOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&cert_template[i], issuerOpt); i++;
    }
    if (serialOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&cert_template[i], serialOpt); i++;
    }
    if (subjectOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&cert_template[i], subjectOpt); i++;
    }
    if (emailOpt) {
	NSS_CK_ATTRIBUTE_TO_UTF8(&cert_template[i], *emailOpt); i++;
    }
    return PR_SUCCESS;
}

static NSSKeyPairType
nss_key_pair_type_from_ck_attrib(CK_ATTRIBUTE_PTR attrib)
{
    CK_KEY_TYPE ckKeyType;
    PR_ASSERT(attrib->pValue);
    ckKeyType = *((CK_ULONG *)attrib->pValue);
    switch (ckKeyType) {
    case CKK_RSA: return NSSKeyPairType_RSA;
    case CKK_DSA: return NSSKeyPairType_DSA;
    case CKK_DH:  return NSSKeyPairType_DiffieHellman;
    default: break;
    }
    return NSSKeyPairType_Unknown;
}

NSS_IMPLEMENT PRStatus
nssCryptokiPrivateKey_GetAttributes
(
  nssCryptokiObject *keyObject,
  NSSArena *arenaOpt,
  NSSKeyPairType *keyTypeOpt,
  NSSItem *idOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSSlot *slot;
    CK_ULONG template_size;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[2];
    /* Set up a template of all options chosen by caller */
    NSS_CK_TEMPLATE_START(key_template, attr, template_size);
    if (keyTypeOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_KEY_TYPE);
    }
    if (idOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_ID);
    }
    NSS_CK_TEMPLATE_FINISH(key_template, attr, template_size);
    if (template_size == 0) {
	/* caller didn't want anything */
	return PR_SUCCESS;
    }

    slot = nssToken_GetSlot(keyObject->token);
    status = nssCKObject_GetAttributes(keyObject->handle, 
                                       key_template, template_size,
                                       arenaOpt, keyObject->session, slot);
    nssSlot_Destroy(slot);
    if (status != PR_SUCCESS) {
	return status;
    }

    i=0;
    if (keyTypeOpt) {
	*keyTypeOpt = nss_key_pair_type_from_ck_attrib(&key_template[i]); i++;
    }
    if (idOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&key_template[i], idOpt); i++;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssCryptokiPublicKey_GetAttributes
(
  nssCryptokiObject *keyObject,
  NSSArena *arenaOpt,
  NSSKeyPairType *keyTypeOpt,
  NSSItem *idOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSSlot *slot;
    CK_ULONG template_size;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[2];
    /* Set up a template of all options chosen by caller */
    NSS_CK_TEMPLATE_START(key_template, attr, template_size);
    if (keyTypeOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_KEY_TYPE);
    }
    if (idOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_ID);
    }
    NSS_CK_TEMPLATE_FINISH(key_template, attr, template_size);
    if (template_size == 0) {
	/* caller didn't want anything */
	return PR_SUCCESS;
    }

    slot = nssToken_GetSlot(keyObject->token);
    status = nssCKObject_GetAttributes(keyObject->handle, 
                                       key_template, template_size,
                                       arenaOpt, keyObject->session, slot);
    nssSlot_Destroy(slot);
    if (status != PR_SUCCESS) {
	return status;
    }

    i=0;
    if (keyTypeOpt) {
	*keyTypeOpt = nss_key_pair_type_from_ck_attrib(&key_template[i]); i++;
    }
    if (idOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&key_template[i], idOpt); i++;
    }
    return PR_SUCCESS;
}

static nssTrustLevel 
get_nss_trust
(
  CK_TRUST ckt
)
{
    nssTrustLevel t;
    switch (ckt) {
    case CKT_NETSCAPE_UNTRUSTED: t = nssTrustLevel_NotTrusted; break;
    case CKT_NETSCAPE_TRUSTED_DELEGATOR: t = nssTrustLevel_TrustedDelegator; 
	break;
    case CKT_NETSCAPE_VALID_DELEGATOR: t = nssTrustLevel_ValidDelegator; break;
    case CKT_NETSCAPE_TRUSTED: t = nssTrustLevel_Trusted; break;
    case CKT_NETSCAPE_VALID: t = nssTrustLevel_Valid; break;
    case CKT_NETSCAPE_MUST_VERIFY:
    case CKT_NETSCAPE_TRUST_UNKNOWN:
    default:
	t = nssTrustLevel_Unknown; break;
    }
    return t;
}

NSS_IMPLEMENT PRStatus
nssCryptokiTrust_GetAttributes
(
  nssCryptokiObject *trustObject,
  nssTrustLevel *serverAuth,
  nssTrustLevel *clientAuth,
  nssTrustLevel *codeSigning,
  nssTrustLevel *emailProtection
)
{
    PRStatus status;
    NSSSlot *slot;
    nssTokenObjectCache *cache;
    CK_BBOOL isToken;
    CK_TRUST saTrust, caTrust, epTrust, csTrust;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE trust_template[5];
    CK_ULONG trust_size;

    /* Use the trust object to find the trust settings */
    NSS_CK_TEMPLATE_START(trust_template, attr, trust_size);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TOKEN,                  isToken);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_SERVER_AUTH,      saTrust);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_CLIENT_AUTH,      caTrust);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_EMAIL_PROTECTION, epTrust);
    NSS_CK_SET_ATTRIBUTE_VAR(attr, CKA_TRUST_CODE_SIGNING,     csTrust);
    NSS_CK_TEMPLATE_FINISH(trust_template, attr, trust_size);

    status = PR_FAILURE;
    cache = nssToken_GetObjectCache(trustObject->token);
    if (cache) {
	status = nssTokenObjectCache_GetObjectAttributes(cache, NULL,
	                                                 trustObject, 
	                                                 CKO_NETSCAPE_TRUST,
	                                                 trust_template, 
	                                                 trust_size);
    }
    if (status != PR_SUCCESS) {

	slot = nssToken_GetSlot(trustObject->token);
	status = nssCKObject_GetAttributes(trustObject->handle,
	                                   trust_template, trust_size,
	                                   NULL, trustObject->session, slot);
	nssSlot_Destroy(slot);
	if (status != PR_SUCCESS) {
	    return status;
	}
    }

    *serverAuth = get_nss_trust(saTrust);
    *clientAuth = get_nss_trust(caTrust);
    *emailProtection = get_nss_trust(epTrust);
    *codeSigning = get_nss_trust(csTrust);
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssCryptokiCRL_GetAttributes
(
  nssCryptokiObject *crlObject,
  NSSArena *arenaOpt,
  NSSItem *encodingOpt,
  NSSUTF8 **urlOpt,
  PRBool *isKRLOpt
)
{
    PRStatus status;
    NSSSlot *slot;
    nssTokenObjectCache *cache;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE crl_template[5];
    CK_ULONG crl_size;
    PRUint32 i;

    NSS_CK_TEMPLATE_START(crl_template, attr, crl_size);
    if (encodingOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_VALUE);
    }
    if (urlOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_NETSCAPE_URL);
    }
    if (isKRLOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_NETSCAPE_KRL);
    }
    NSS_CK_TEMPLATE_FINISH(crl_template, attr, crl_size);

    status = PR_FAILURE;
    cache = nssToken_GetObjectCache(crlObject->token);
    if (cache) {
	status = nssTokenObjectCache_GetObjectAttributes(cache, NULL,
	                                                 crlObject, 
	                                                 CKO_NETSCAPE_CRL,
	                                                 crl_template, 
	                                                 crl_size);
    }
    if (status != PR_SUCCESS) {

	slot = nssToken_GetSlot(crlObject->token);
	status = nssCKObject_GetAttributes(crlObject->handle, 
	                                   crl_template, crl_size,
	                                   arenaOpt, crlObject->session, slot);
	nssSlot_Destroy(slot);
	if (status != PR_SUCCESS) {
	    return status;
	}
    }

    i=0;
    if (encodingOpt) {
	NSS_CK_ATTRIBUTE_TO_ITEM(&crl_template[i], encodingOpt); i++;
    }
    if (urlOpt) {
	NSS_CK_ATTRIBUTE_TO_UTF8(&crl_template[i], *urlOpt); i++;
    }
    if (isKRLOpt) {
	NSS_CK_ATTRIBUTE_TO_BOOL(&crl_template[i], *isKRLOpt); i++;
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssCryptokiPrivateKey_SetCertificate
(
  nssCryptokiObject *keyObject,
  nssSession *session,
  NSSUTF8 *nickname,
  NSSItem *id,
  NSSDER *subject
)
{
    CK_RV ckrv;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[3];
    CK_ULONG key_size;
    void *epv = nssToken_GetCryptokiEPV(keyObject->token);

    PR_ASSERT(session); /* XXX remove later */
    PR_ASSERT(session->isRW);

    NSS_CK_TEMPLATE_START(key_template, attr, key_size);
    NSS_CK_SET_ATTRIBUTE_UTF8(attr, CKA_LABEL, nickname);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_ID, id);
    NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_SUBJECT, subject);
    NSS_CK_TEMPLATE_FINISH(key_template, attr, key_size);

    ckrv = CKAPI(epv)->C_SetAttributeValue(session->handle,
                                           keyObject->handle,
                                           key_template,
                                           key_size);

    return (ckrv == CKR_OK) ? PR_SUCCESS : PR_FAILURE;
}

static NSSSymmetricKeyType
nss_symm_key_type_from_ck_attrib(CK_ATTRIBUTE_PTR attrib)
{
    CK_KEY_TYPE ckKeyType;
    PR_ASSERT(attrib->pValue);
    ckKeyType = *((CK_ULONG *)attrib->pValue);
    switch (ckKeyType) {
    case CKK_DES:  return NSSSymmetricKeyType_DES;
    case CKK_DES3: return NSSSymmetricKeyType_TripleDES;
    case CKK_RC2:  return NSSSymmetricKeyType_RC2;
    case CKK_RC4:  return NSSSymmetricKeyType_RC4;
    case CKK_RC5:  return NSSSymmetricKeyType_RC5;
    case CKK_AES:  return NSSSymmetricKeyType_AES;
    default: break;
    }
    return NSSKeyPairType_Unknown;
}

NSS_IMPLEMENT PRStatus
nssCryptokiSymmetricKey_GetAttributes
(
  nssCryptokiObject *keyObject,
  NSSArena *arenaOpt,
  NSSSymmetricKeyType *keyTypeOpt,
  PRUint32 *keyLengthOpt,
  NSSOperations *opsOpt
)
{
    PRStatus status;
    PRUint32 i;
    NSSSlot *slot;
    CK_ULONG template_size;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE key_template[8];
    /* Set up a template of all options chosen by caller */
    NSS_CK_TEMPLATE_START(key_template, attr, template_size);
    if (keyTypeOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_KEY_TYPE);
    }
    if (keyLengthOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_VALUE_LEN);
    }
    if (opsOpt) {
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_ENCRYPT);
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_DECRYPT);
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_SIGN);
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_VERIFY);
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_WRAP);
	NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_UNWRAP);
    }
    NSS_CK_TEMPLATE_FINISH(key_template, attr, template_size);
    if (template_size == 0) {
	/* caller didn't want anything */
	return PR_SUCCESS;
    }

    slot = nssToken_GetSlot(keyObject->token);
    status = nssCKObject_GetAttributes(keyObject->handle, 
                                       key_template, template_size,
                                       arenaOpt, keyObject->session, slot);
    nssSlot_Destroy(slot);
    if (status != PR_SUCCESS) {
	return status;
    }

    i=0;
    if (keyTypeOpt) {
	*keyTypeOpt = nss_symm_key_type_from_ck_attrib(&key_template[i]); i++;
    }
    if (keyLengthOpt) {
	/* may not be defined for some keys */
	if (key_template[i].ulValueLen != (CK_ULONG)-1 &&
	    key_template[i].ulValueLen != (CK_ULONG)0)
	{
	    NSS_CK_ATTRIBUTE_TO_UINT(&key_template[i], *keyLengthOpt);
	}
	/* XXX need to set for those (DES) */
	i++;
    }
    if (opsOpt) {
	PRBool isTrue;
	*opsOpt = 0;
	NSS_CK_ATTRIBUTE_TO_BOOL(&key_template[i], isTrue); i++;
	if (isTrue) {
	    *opsOpt |= NSSOperations_ENCRYPT;
	}
	NSS_CK_ATTRIBUTE_TO_BOOL(&key_template[i], isTrue); i++;
	if (isTrue) {
	    *opsOpt |= NSSOperations_DECRYPT;
	}
	NSS_CK_ATTRIBUTE_TO_BOOL(&key_template[i], isTrue); i++;
	if (isTrue) {
	    *opsOpt |= NSSOperations_SIGN;
	}
	NSS_CK_ATTRIBUTE_TO_BOOL(&key_template[i], isTrue); i++;
	if (isTrue) {
	    *opsOpt |= NSSOperations_VERIFY;
	}
	NSS_CK_ATTRIBUTE_TO_BOOL(&key_template[i], isTrue); i++;
	if (isTrue) {
	    *opsOpt |= NSSOperations_WRAP;
	}
	NSS_CK_ATTRIBUTE_TO_BOOL(&key_template[i], isTrue); i++;
	if (isTrue) {
	    *opsOpt |= NSSOperations_UNWRAP;
	}
    }
    return PR_SUCCESS;
}

NSS_IMPLEMENT nssCryptokiObject *
nssCryptokiSymmetricKey_Copy
(
  nssCryptokiObject *sourceKey,
  nssSession *sourceSession,
  NSSToken *destination,
  nssSession *destinationSession,
  PRBool asTokenObject
)
{
    CK_RV ckrv;
    CK_ATTRIBUTE_PTR attr;
    CK_ATTRIBUTE symmkey_template[7];
    CK_ULONG tsize;
    CK_OBJECT_HANDLE keyh;
    void *epv = nssToken_GetCryptokiEPV(destination);
    PRStatus status;
    NSSArena *arena;
    nssCryptokiObject *key;
    NSSSlot *slot;

    arena = nssArena_Create();
    if (!arena) {
	return (nssCryptokiObject *)NULL;
    }

    NSS_CK_TEMPLATE_START(symmkey_template, attr, tsize);
    NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_CLASS);
    NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_KEY_TYPE);
    NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_VALUE);
    NSS_CK_SET_ATTRIBUTE_NULL(attr, CKA_LABEL);
    NSS_CK_TEMPLATE_FINISH(symmkey_template, attr, tsize);

    slot = nssToken_GetSlot(sourceKey->token);
    status = nssCKObject_GetAttributes(sourceKey->handle, 
                                       symmkey_template, tsize,
                                       arena, sourceSession, slot);
    nssSlot_Destroy(slot);
    if (status == PR_FAILURE) {
    }

    /* Now fill in destination-specific attributes */
    if (asTokenObject) {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_true); tsize++;
	/* XXX always private? */
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_PRIVATE, &g_ck_true); tsize++;
    } else {
	NSS_CK_SET_ATTRIBUTE_ITEM(attr, CKA_TOKEN, &g_ck_false); tsize++;
    }

    ckrv = CKAPI(epv)->C_CreateObject(destinationSession->handle, 
                                      symmkey_template, tsize, &keyh);
    if (ckrv != CKR_OK) {
	goto loser;
    }

    key = nssCryptokiObject_Create(destination, destinationSession, keyh);
    if (!key) {
	goto loser;
    }

    nssArena_Destroy(arena);
    return key;
loser:
    nssArena_Destroy(arena);
    return (nssCryptokiObject *)NULL;
}

