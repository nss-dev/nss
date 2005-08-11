/*
 * ***** BEGIN LICENSE BLOCK *****
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

#ifndef _LDAP_H_
#define _LDAP_H_

#include "certt.h"
#include "pkixt.h"

#ifdef __cplusplus
extern "C" {
#endif

SEC_ASN1_CHOOSER_DECLARE(PKIX_PL_LDAPMessageTemplate)

/* ********************************************************************** */

#define SEC_ASN1_LDAP_STRING SEC_ASN1_OCTET_STRING

#define LDAPATTR_INCLUDE_CACERTS        (1<<0)
#define LDAPATTR_INCLUDE_USERCERTS      (1<<1)
#define LDAPATTR_INCLUDE_CROSSPAIRCERTS (1<<2)
#define LDAPATTR_INCLUDE_CERTREVLIST    (1<<3)
#define LDAPATTR_INCLUDE_AUTHREVLIST    (1<<4)
#define MAX_LDAPATTRS                   5
typedef PKIX_UInt32 LdapAttrIncludeMask;

typedef enum {
        SIMPLE_AUTH                     = 0,
        KRBV42LDAP_AUTH                 = 1,
        KRBV42DSA_AUTH                  = 2
} AuthType;

typedef enum {
        BASE_OBJECT                     = 0,
        SINGLE_LEVEL                    = 1,
        WHOLE_SUBTREE                   = 2
} ScopeType;

typedef enum {
        NEVER_DEREF                     = 0,
        DEREF_IN_SEARCHING              = 1,
        DEREF_FINDING_BASEOBJ           = 2,
        ALWAYS_DEREF                    = 3
} DerefType;

typedef enum {
        LDAP_ANDFILTER_TYPE             = 0,
        LDAP_ORFILTER_TYPE              = 1,
        LDAP_NOTFILTER_TYPE             = 2,
        LDAP_EQUALITYMATCHFILTER_TYPE   = 3,
        LDAP_SUBSTRINGFILTER_TYPE       = 4,
        LDAP_GREATEROREQUALFILTER_TYPE  = 5,
        LDAP_LESSOREQUALFILTER_TYPE     = 6,
        LDAP_PRESENTFILTER_TYPE         = 7,
        LDAP_APPROXMATCHFILTER_TYPE     = 8
} LDAPFilterType;

typedef enum {
        LDAP_BIND_TYPE                  = 0,
        LDAP_BINDRESPONSE_TYPE          = 1,
        LDAP_UNBIND_TYPE                = 2,
        LDAP_SEARCH_TYPE                = 3,
        LDAP_SEARCHRESPONSEENTRY_TYPE   = 4,
        LDAP_SEARCHRESPONSERESULT_TYPE  = 5,
        LDAP_ABANDONREQUEST_TYPE        = 16
} LDAPMessageType;

typedef enum {
        SUCCESS                         = 0,
        OPERATIONSERROR                 = 1,
        PROTOCOLERROR                   = 2,
        TIMELIMITEXCEEDED               = 3,
        SIZELIMITEXCEEDED               = 4,
        COMPAREFALSE                    = 5,
        COMPARETRUE                     = 6,
        AUTHMETHODNOTSUPPORTED          = 7,
        STRONGAUTHREQUIRED              = 8,
        NOSUCHATTRIBUTE                 = 16,
        UNDEFINEDATTRIBUTETYPE          = 17,
        INAPPROPRIATEMATCHING           = 18,
        CONSTRAINTVIOLATION             = 19,
        ATTRIBUTEORVALUEEXISTS          = 20,
        INVALIDATTRIBUTESYNTAX          = 21,
        NOSUCHOBJECT                    = 32,
        ALIASPROBLEM                    = 33,
        INVALIDDNSYNTAX                 = 34,
        ISLEAF                          = 35,
        ALIASDEREFERENCINGPROBLEM       = 36,
        INAPPROPRIATEAUTHENTICATION     = 48,
        INVALIDCREDENTIALS              = 49,
        INSUFFICIENTACCESSRIGHTS        = 50,
        BUSY                            = 51,
        UNAVAILABLE                     = 52,
        UNWILLINGTOPERFORM              = 53,
        LOOPDETECT                      = 54,
        NAMINGVIOLATION                 = 64,
        OBJECTCLASSVIOLATION            = 65,
        NOTALLOWEDONNONLEAF             = 66,
        NOTALLOWEDONRDN                 = 67,
        ENTRYALREADYEXISTS              = 68,
        OBJECTCLASSMODSPROHIBITED       = 69,
        OTHER                           = 80
} LDAPResultCode;

typedef struct LDAPBindAuthStruct {
        AuthType selector;
        union {
                SECItem simple;
                SECItem krbv42LDAP;
                SECItem krbv42DSA;
        } ch;
} LDAPBindAuth;

typedef struct LDAPBindStruct {
        SECItem version;
        SECItem bindName;
#if 0
        LDAPBindAuth authentication;
#endif
        SECItem authentication;
} LDAPBind;

typedef struct LDAPResultStruct LDAPBindResponse;

typedef struct LDAPResultStruct {
        SECItem resultCode;
        SECItem matchedDN;
        SECItem errorMessage;
} LDAPResult;

typedef struct LDAPSearchResponseAttrStruct {
        SECItem attrType;
        SECItem **val;
} LDAPSearchResponseAttr;

typedef struct LDAPSearchResponseEntryStruct {
        SECItem objectName;
        LDAPSearchResponseAttr **attributes;
} LDAPSearchResponseEntry;

typedef struct LDAPResultStruct LDAPSearchResponseResult;

typedef struct LDAPUnbindStruct {
        SECItem dummy;
} LDAPUnbind;

typedef struct LDAPAndFilterStruct {
        SECItem **setOfFilter;
} LDAPAndFilter;

/* How do we prevent this from being infinitely recursive? */
/* typedef LDAPFilter LDAPNotFilter; */

typedef struct LDAPSubstringFilterStruct {
        SECItem attrType;
        SECItem *substrChoice;
} LDAPSubstringFilter;

typedef struct LDAPPresentFilterStruct {
        SECItem attrType;
} LDAPPresentFilter;

typedef struct LDAPAttributeValueAssertionStruct {
        SECItem attrType;
        SECItem attrValue;
} LDAPAttributeValueAssertion;

typedef LDAPAndFilter               LDAPOrFilter;
typedef LDAPAttributeValueAssertion LDAPEqualityMatchFilter;
typedef LDAPAttributeValueAssertion LDAPGreaterOrEqualFilter;
typedef LDAPAttributeValueAssertion LDAPLessOrEqualFilter;
typedef LDAPAttributeValueAssertion LDAPApproxMatchFilter;

typedef struct LDAPFilterStruct {
        LDAPFilterType selector;
        union {
                LDAPAndFilter andFilter;
                LDAPOrFilter orFilter;
             /* LDAPNotFilter notFilter; */
                LDAPEqualityMatchFilter equalityMatchFilter;
                LDAPSubstringFilter substringFilter;
                LDAPGreaterOrEqualFilter greaterOrEqualFilter;
                LDAPLessOrEqualFilter lessOrEqualFilter;
                LDAPPresentFilter presentFilter;
                LDAPApproxMatchFilter approxMatchFilter;
        } filter;
} LDAPFilter;

typedef LDAPFilter LDAPNotFilter;

typedef struct LDAPSearchStruct {
        SECItem baseObject;
        SECItem scope;
        SECItem derefAliases;
        SECItem sizeLimit;
        SECItem timeLimit;
        SECItem attrsOnly;
        LDAPFilter filter;
        SECItem **attributes;
} LDAPSearch;

typedef struct LDAPAbandonRequestStruct {
        SECItem messageID;
} LDAPAbandonRequest;

typedef struct protocolOpStruct {
        LDAPMessageType selector;
        union {
                LDAPBind bindMsg;
                LDAPBindResponse bindResponseMsg;
                LDAPUnbind unbindMsg;
                LDAPSearch searchMsg;
                LDAPSearchResponseEntry searchResponseEntryMsg;
                LDAPSearchResponseResult searchResponseResultMsg;
                LDAPAbandonRequest abandonRequestMsg;
        } op;
} LDAPProtocolOp;

typedef struct LDAPMessageStruct {
        SECItem messageID;
        LDAPProtocolOp protocolOp;
} LDAPMessage;

#ifdef __cplusplus
}
#endif

#endif
