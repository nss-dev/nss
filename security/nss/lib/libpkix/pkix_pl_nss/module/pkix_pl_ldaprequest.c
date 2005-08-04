/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Sun Microsystems
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
/*
 * pkix_pl_ldaprequest.c
 *
 */

#include "pkix_pl_ldaprequest.h"

/* --Private-LdapRequest-Functions------------------------------------- */

/* Note: lengths do not include the NULL terminator */
static unsigned char caAttr[] = "caCertificate;binary";
static unsigned int caAttrLen = sizeof(caAttr) - 1;
static unsigned char uAttr[] = "userCertificate;binary";
static unsigned int uAttrLen = sizeof(uAttr) - 1;
static unsigned char ccpAttr[] = "crossCertificatePair;binary";
static unsigned int ccpAttrLen = sizeof(ccpAttr) - 1;
static unsigned char crlAttr[] = "certificateRevocationList;binary";
static unsigned int crlAttrLen = sizeof(crlAttr) - 1;
static unsigned char arlAttr[] = "authorityRevocationList;binary";
static unsigned int arlAttrLen = sizeof(arlAttr) - 1;

/*
 * FUNCTION: pkix_pl_LdapRequest_EncodeAttrs
 * DESCRIPTION:
 *
 *  This function obtains the attribute mask bits from the LdapRequest pointed
 *  to by "request", creates the corresponding array of AttributeTypes for the
 *  encoding of the SearchRequest message.
 *
 * PARAMETERS
 *  "request"
 *      The address of the LdapRequest whose attributes are to be encoded. Must
 *      be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an LdapRequest Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 *  "plContext"
 *      Platform-specific context pointer.
 * XXX need Docs
 */
static PKIX_Error *
pkix_pl_LdapRequest_EncodeAttrs(
        PKIX_PL_LdapRequest *request,
        void *plContext)
{
        SECItem *encoding = NULL;
        SECItem **attrArray = NULL;
        PKIX_UInt32 attrIndex = 0;
        LdapAttrIncludeMask attrBits;

        PKIX_ENTER(LDAPREQUEST, "pkix_pl_LdapRequest_EncodeAttrs");
        PKIX_NULLCHECK_ONE(request);

        /* construct "attrs" according to bits in request->attrBits */
        attrBits = request->attrBits;
        attrArray = request->attrArray;
        if ((attrBits & LDAPATTR_INCLUDE_CACERTS) ==
                 LDAPATTR_INCLUDE_CACERTS) {
                attrArray[attrIndex] = &(request->attributes[attrIndex]);
                request->attributes[attrIndex].type = siAsciiString;
                request->attributes[attrIndex].data = caAttr;
                request->attributes[attrIndex].len = caAttrLen;
                attrIndex++;
        }
        if ((attrBits & LDAPATTR_INCLUDE_USERCERTS) ==
                 LDAPATTR_INCLUDE_USERCERTS) {
                attrArray[attrIndex] = &(request->attributes[attrIndex]);
                request->attributes[attrIndex].type = siAsciiString;
                request->attributes[attrIndex].data = uAttr;
                request->attributes[attrIndex].len = uAttrLen;
                attrIndex++;
        }
        if ((attrBits & LDAPATTR_INCLUDE_CROSSPAIRCERTS) ==
                 LDAPATTR_INCLUDE_CROSSPAIRCERTS) {
                attrArray[attrIndex] = &(request->attributes[attrIndex]);
                request->attributes[attrIndex].type = siAsciiString;
                request->attributes[attrIndex].data = ccpAttr;
                request->attributes[attrIndex].len = ccpAttrLen;
                attrIndex++;
        }
        if ((attrBits & LDAPATTR_INCLUDE_CERTREVLIST) ==
                 LDAPATTR_INCLUDE_CERTREVLIST) {
                attrArray[attrIndex] = &(request->attributes[attrIndex]);
                request->attributes[attrIndex].type = siAsciiString;
                request->attributes[attrIndex].data = crlAttr;
                request->attributes[attrIndex].len = crlAttrLen;
                attrIndex++;
        }
        if ((attrBits & LDAPATTR_INCLUDE_AUTHREVLIST) ==
                 LDAPATTR_INCLUDE_AUTHREVLIST) {
                attrArray[attrIndex] = &(request->attributes[attrIndex]);
                request->attributes[attrIndex].type = siAsciiString;
                request->attributes[attrIndex].data = arlAttr;
                request->attributes[attrIndex].len = arlAttrLen;
                attrIndex++;
        }
        attrArray[attrIndex] = (SECItem *)NULL;

cleanup:

        PKIX_RETURN(LDAPREQUEST);
}

/*
 * FUNCTION: pkix_pl_LdapRequest_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_LdapRequest_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_PL_LdapRequest *ldapRq = NULL;

        PKIX_ENTER(LDAPREQUEST, "pkix_pl_LdapRequest_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType(object, PKIX_LDAPREQUEST_TYPE, plContext),
                    "Object is not a LdapRequest");

        ldapRq = (PKIX_PL_LdapRequest *)object;

        /*
         * All dynamic field in an LDAPRequest are allocated
         * in an arena, and will be freed when the arena is destroyed.
         */

cleanup:

        PKIX_RETURN(LDAPREQUEST);
}

/*
 * FUNCTION: pkix_pl_LdapRequest_Hashcode
 * (see comments for PKIX_PL_HashcodeCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_LdapRequest_Hashcode(
        PKIX_PL_Object *object,
        PKIX_UInt32 *pHashcode,
        void *plContext)
{
        PKIX_UInt32 dataLen = 0;
        PKIX_UInt32 dindex = 0;
        PKIX_UInt32 sizeOfLength = 0;
        PKIX_UInt32 idLen = 0;
        const unsigned char *msgBuf = NULL;
        PKIX_PL_LdapRequest *ldapRq = NULL;

        PKIX_ENTER(LDAPREQUEST, "pkix_pl_LdapRequest_Hashcode");
        PKIX_NULLCHECK_TWO(object, pHashcode);

        PKIX_CHECK(pkix_CheckType(object, PKIX_LDAPREQUEST_TYPE, plContext),
                    "Object is not a LdapRequest");

        ldapRq = (PKIX_PL_LdapRequest *)object;

        *pHashcode = 0;

        /*
         * Two requests that differ only in msgnum are a match! Therefore,
         * start hashcoding beyond the encoded messageID field.
         */
        if (ldapRq->encoded) {
                msgBuf = (const unsigned char *)ldapRq->encoded->data;
                /* Is message length short form (one octet) or long form? */
                if ((msgBuf[1] & 0x80) != 0) {
                        sizeOfLength = msgBuf[1] & 0x7F;
                        for (dindex = 0; dindex < sizeOfLength; dindex++) {
                                dataLen = (dataLen << 8) + msgBuf[dindex + 2];
                        }
                } else {
                        dataLen = msgBuf[1];
                }

                /* How many bytes for the messageID? (Assume short form) */
                idLen = msgBuf[dindex + 3] + 2;
                dindex += idLen;
                dataLen -= idLen;
                msgBuf = &msgBuf[dindex + 2];

                PKIX_CHECK(pkix_hash(msgBuf, dataLen, pHashcode, plContext),
                        "pkix_hash failed");
        }

cleanup:

        PKIX_RETURN(LDAPREQUEST);

}

/*
 * FUNCTION: pkix_pl_LdapRequest_Equals
 * (see comments for PKIX_PL_Equals_Callback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_LdapRequest_Equals(
        PKIX_PL_Object *firstObj,
        PKIX_PL_Object *secondObj,
        PKIX_Boolean *pResult,
        void *plContext)
{
        PKIX_PL_LdapRequest *firstReq = NULL;
        PKIX_PL_LdapRequest *secondReq = NULL;
        PKIX_UInt32 secondType = 0;
        PKIX_Boolean compare = PKIX_FALSE;
        PKIX_UInt32 firstLen = 0;
        const unsigned char *firstData = NULL;
        const unsigned char *secondData = NULL;
        PKIX_UInt32 sizeOfLength = 0;
        PKIX_UInt32 dindex = 0;
        PKIX_UInt32 i = 0;

        PKIX_ENTER(LDAPREQUEST, "pkix_pl_LdapRequest_Equals");
        PKIX_NULLCHECK_THREE(firstObj, secondObj, pResult);

        /* test that firstObj is a LdapRequest */
        PKIX_CHECK(pkix_CheckType(firstObj, PKIX_LDAPREQUEST_TYPE, plContext),
                    "firstObj argument is not a LdapRequest");

        /*
         * Since we know firstObj is a LdapRequest, if both references are
         * identical, they must be equal
         */
        if (firstObj == secondObj){
                *pResult = PKIX_TRUE;
                goto cleanup;
        }

        /*
         * If secondObj isn't a LdapRequest, we don't throw an error.
         * We simply return a Boolean result of FALSE
         */
        *pResult = PKIX_FALSE;
        PKIX_CHECK(PKIX_PL_Object_GetType
                    (secondObj, &secondType, plContext),
                    "Could not get type of second argument");
        if (secondType != PKIX_LDAPREQUEST_TYPE) {
                goto cleanup;
        }

        firstReq = (PKIX_PL_LdapRequest *)firstObj;
        secondReq = (PKIX_PL_LdapRequest *)secondObj;

        /* If either lacks an encoded string, they cannot be compared */
        if (!(firstReq->encoded) || !(secondReq->encoded)) {
                goto cleanup;
        }

        if (firstReq->encoded->len != secondReq->encoded->len) {
                goto cleanup;
        }

        firstData = (const unsigned char *)firstReq->encoded->data;
        secondData = (const unsigned char *)secondReq->encoded->data;

        /*
         * Two requests that differ only in msgnum are equal! Therefore,
         * start the byte comparison beyond the encoded messageID field.
         */

        /* Is message length short form (one octet) or long form? */
        if ((firstData[1] & 0x80) != 0) {
                sizeOfLength = firstData[1] & 0x7F;
                for (dindex = 0; dindex < sizeOfLength; dindex++) {
                        firstLen = (firstLen << 8) + firstData[dindex + 2];
                }
        } else {
                firstLen = firstData[1];
        }

        /* How many bytes for the messageID? (Assume short form) */
        i = firstData[dindex + 3] + 2;
        dindex += i;
        firstLen -= i;
        firstData = &firstData[dindex + 2];

        /*
         * In theory, we have to calculate where the second message data
         * begins by checking its length encodings. But if these messages
         * are equal, we can re-use the calculation we already did. If they
         * are not equal, the byte comparisons will surely fail.
         */

        secondData = &secondData[dindex + 2];
        
        for (i = 0; i < firstLen; i++) {
                if (firstData[i] != secondData[i]) {
                        goto cleanup;
                }
        }

        *pResult = PKIX_TRUE;

cleanup:

        PKIX_RETURN(LDAPREQUEST);
}

/*
 * FUNCTION: pkix_pl_LdapRequest_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_LDAPREQUEST_TYPE and its related functions with
 *  systemClasses[]
 * PARAMETERS:
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_pl_LdapRequest_RegisterSelf(void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(LDAPREQUEST, "pkix_pl_LdapRequest_RegisterSelf");

        entry.description = "LdapRequest";
        entry.destructor = pkix_pl_LdapRequest_Destroy;
        entry.equalsFunction = pkix_pl_LdapRequest_Equals;
        entry.hashcodeFunction = pkix_pl_LdapRequest_Hashcode;
        entry.toStringFunction = NULL;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_LDAPREQUEST_TYPE] = entry;

cleanup:

        PKIX_RETURN(LDAPREQUEST);
}

/* --Public-Functions------------------------------------------------------- */

/*
 * FUNCTION: pkix_pl_LdapRequest_Create
 * DESCRIPTION:
 *
 *  This function creates an LdapRequest using the PRArenaPool pointed to by
 *  "arena", a message number whose value is "msgnum", a base object pointed to
 *  by "issuerDN", a scope whose value is "scope", a derefAliases flag whose
 *  value is "derefAliases", a sizeLimit whose value is "sizeLimit", a timeLimit
 *  whose value is "timeLimit", an attrsOnly flag whose value is "attrsOnly", a
 *  subjectName pointed to by "subjectName", and attribute bits whose value is
 *  "attrBits"; storing the result at "pRequestMsg".
 *
 *  See pkix_pl_ldaptemplates.c (and below) for the ASN.1 representation of
 *  message components, and see pkix_pl_ldapt.h for data types.
 *
 * PARAMETERS
 *  "arena"
 *      The address of the PRArenaPool to be used in the encoding. Must be
 *      non-NULL.
 *  "msgnum"
 *      The UInt32 message number to be used for the messageID component of the
 *      LDAP message exchange.
 *  "issuerDN"
 *      The address of the string to be used for the baseObject component of the
 *      LDAP SearchRequest message. Must be non-NULL.
 *  "scope"
 *      The (enumerated) ScopeType to be used for the scope component of the
 *      LDAP SearchRequest message
 *  "derefAliases"
 *      The (enumerated) DerefType to be used for the derefAliases component of
 *      the LDAP SearchRequest message
 *  "sizeLimit"
 *      The UInt32 value to be used for the sizeLimit component of the LDAP
 *      SearchRequest message
 *  "timeLimit"
 *      The UInt32 value to be used for the timeLimit component of the LDAP
 *      SearchRequest message
 *  "attrsOnly"
 *      The Boolean value to be used for the attrsOnly component of the LDAP
 *      SearchRequest message
 *  "subjectName"
 *      The address of the SECItem to be used for the filter component of the
 *      LDAP SearchRequest message
 *  "attrBits"
 *      The LdapAttrIncludeMask bits indicating the attributes to be included
 *      in the attributes sequence of the LDAP SearchRequest message
 *  "pRequestMsg"
 *      The address at which the address of the LdapRequest is stored. Must
 *      be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an LdapRequest Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
/*
 * SearchRequest ::=
 *      [APPLICATION 3] SEQUENCE {
 *              baseObject      LDAPDN,
 *              scope           ENUMERATED {
 *                                      baseObject              (0),
 *                                      singleLevel             (1),
 *                                      wholeSubtree            (2)
 *                              },
 *              derefAliases    ENUMERATED {
 *                                      neverDerefAliases       (0),
 *                                      derefInSearching        (1),
 *                                      derefFindingBaseObj     (2),
 *                                      alwaysDerefAliases      (3)
 *                              },
 *              sizeLimit       INTEGER (0 .. MAXINT),
 *                              -- value of 0 implies no sizeLimit
 *              timeLimit       INTEGER (0 .. MAXINT),
 *                              -- value of 0 implies no timeLimit
 *              attrsOnly       BOOLEAN,
 *                              -- TRUE, if only attributes (without values)
 *                              -- to be returned
 *              filter          Filter,
 *              attributes      SEQUENCE OF AttributeType
 *      }
 *
 * Filter ::=
 *      CHOICE {
 *              and             [0] SET OF Filter,
 *              or              [1] SET OF Filter,
 *              not             [2] Filter,
 *              equalityMatch   [3] AttributeValueAssertion,
 *              substrings      [4] SubstringFilter,
 *              greaterOrEqual  [5] AttributeValueAssertion,
 *              lessOrEqual     [6] AttributeValueAssertion,
 *              present         [7] AttributeType,
 *              approxMatch     [8] AttributeValueAssertion
 *      }
 *
 * SubstringFilter ::=
 *      SEQUENCE {
 *              type            AttributeType,
 *              SEQUENCE OF CHOICE {
 *                      initial [0] LDAPString,
 *                      any     [1] LDAPString,
 *                      final   [2] LDAPString,
 *              }
 *      }
 *
 * AttributeValueAssertion ::=
 *      SEQUENCE {
 *              attributeType   AttributeType,
 *              attributeValue  AttributeValue,
 *      }
 *
 * AttributeValue ::= OCTET STRING
 *
 * AttributeType ::= LDAPString
 *               -- text name of the attribute, or dotted
 *               -- OID representation
 *
 * LDAPDN ::= LDAPString
 *
 * LDAPString ::= OCTET STRING
 *
 */
PKIX_Error *
pkix_pl_LdapRequest_Create(
        PRArenaPool *arena,
        PKIX_UInt32 msgnum,
        char *issuerDN,
        ScopeType scope,
        DerefType derefAliases,
        PKIX_UInt32 sizeLimit,
        PKIX_UInt32 timeLimit,
        char attrsOnly,
        SECItem *subjectName,
        LdapAttrIncludeMask attrBits,
        PKIX_PL_LdapRequest **pRequestMsg,
        void *plContext)
{
        LDAPMessage msg;
        LDAPSearch *search;
        PKIX_PL_LdapRequest *ldapRequest = NULL;
        char scopeTypeAsChar;
        char derefAliasesTypeAsChar;
        SECItem *attrArray[MAX_LDAPATTRS + 1];

        PKIX_ENTER(LDAPREQUEST, "pkix_pl_LdapRequest_Create");
        PKIX_NULLCHECK_THREE(arena, issuerDN, pRequestMsg);

        /* create a PKIX_PL_LdapRequest object */
        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_LDAPREQUEST_TYPE,
                    sizeof (PKIX_PL_LdapRequest),
                    (PKIX_PL_Object **)&ldapRequest,
                    plContext),
                    "Could not create object");

        ldapRequest->arena = arena;
        ldapRequest->msgnum = msgnum;
        ldapRequest->issuerDN = issuerDN;
        ldapRequest->scope = scope;
        ldapRequest->derefAliases = derefAliases;
        ldapRequest->sizeLimit = sizeLimit;
        ldapRequest->timeLimit = timeLimit;
        ldapRequest->attrsOnly = attrsOnly;
        ldapRequest->subjectName = subjectName;
        ldapRequest->attrBits = attrBits;

        ldapRequest->attrArray = attrArray;

        PKIX_CHECK(pkix_pl_LdapRequest_EncodeAttrs
                (ldapRequest, plContext),
                "pkix_pl_LdapRequest_EncodeAttrs failed");

        PKIX_PL_NSSCALL
                (LDAPREQUEST, PORT_Memset, (&msg, 0, sizeof (LDAPMessage)));

        msg.messageID.type = siUnsignedInteger;
        msg.messageID.data = (void*)&msgnum;
        msg.messageID.len = sizeof (msgnum);

        msg.protocolOp.selector = LDAP_SEARCH_TYPE;

        search = &(msg.protocolOp.op.searchMsg);

        search->baseObject.type = siAsciiString;
        search->baseObject.data = (void *)issuerDN;
        search->baseObject.len = strlen(issuerDN);
        scopeTypeAsChar = (char)scope;
        search->scope.type = siUnsignedInteger;
        search->scope.data = (void *)&scopeTypeAsChar;
        search->scope.len = sizeof (scopeTypeAsChar);
        derefAliasesTypeAsChar = (char)derefAliases;
        search->derefAliases.type = siUnsignedInteger;
        search->derefAliases.data =
                (void *)&derefAliasesTypeAsChar;
        search->derefAliases.len =
                sizeof (derefAliasesTypeAsChar);
        search->sizeLimit.type = siUnsignedInteger;
        search->sizeLimit.data = (void *)&sizeLimit;
        search->sizeLimit.len = sizeof (PKIX_UInt32);
        search->timeLimit.type = siUnsignedInteger;
        search->timeLimit.data = (void *)&timeLimit;
        search->timeLimit.len = sizeof (PKIX_UInt32);
        search->attrsOnly.type = siBuffer;
        search->attrsOnly.data = (void *)&attrsOnly;
        search->attrsOnly.len = sizeof (attrsOnly);

        search->filter.selector = LDAP_EQUALITYMATCHFILTER_TYPE;
        search->filter.filter.equalityMatchFilter.attrType.data = (void *)"cn";
        search->filter.filter.equalityMatchFilter.attrType.len = 2;
        search->filter.filter.equalityMatchFilter.attrValue.data =
                subjectName->data;
#if 0
                (void *)"Basic Directory Trust Anchor SubSubCA1";
#endif
        search->filter.filter.equalityMatchFilter.attrValue.len =
                subjectName->len;
#if 0
                strlen(search->filter.filter.equalityMatchFilter.attrValue.data);
#endif

        search->attributes = attrArray;

        PKIX_PL_NSSCALLRV
                (LDAPCERTSTORECONTEXT,
                ldapRequest->encoded,
                SEC_ASN1EncodeItem,
                (arena, NULL, (void *)&msg, LDAPMessageTemplate));
        if (!(ldapRequest->encoded)) {
                PKIX_ERROR("failed in encoding searchRequest");
        }

        *pRequestMsg = ldapRequest;

cleanup:

        if (PKIX_ERROR_RECEIVED) {
                PKIX_DECREF(ldapRequest);
        }

        PKIX_RETURN(LDAPREQUEST);
}

/*
 * FUNCTION: pkix_pl_LdapRequest_GetEncoded
 * DESCRIPTION:
 *
 *  This function obtains the encoded message from the LdapRequest pointed to
 *  by "request", storing the result at "pRequestBuf".
 *
 * PARAMETERS
 *  "request"
 *      The address of the LdapRequest whose encoded message is to be
 *      retrieved. Must be non-NULL.
 *  "pRequestBuf"
 *      The address at which is stored the address of the encoded message. Must
 *      be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an LdapRequest Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_pl_LdapRequest_GetEncoded(
        PKIX_PL_LdapRequest *request,
        SECItem **pRequestBuf,
        void *plContext)
{
        PKIX_PL_LdapRequest *ldapRequest = NULL;

        PKIX_ENTER(LDAPREQUEST, "pkix_pl_LdapRequest_GetEncoded");
        PKIX_NULLCHECK_TWO(request, pRequestBuf);

        *pRequestBuf = request->encoded;
cleanup:

        PKIX_RETURN(LDAPREQUEST);
}
