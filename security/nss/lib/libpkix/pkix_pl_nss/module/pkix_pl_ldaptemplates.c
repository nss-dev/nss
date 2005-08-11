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

#include "pkix_pl_ldapt.h"

/*
 * BindRequest ::=
 *      [APPLICATION 0] SEQUENCE {
 *                      version INTEGER (1..127),
 *                      name    LDAPDN,
 *                      authentication CHOICE {
 *                              simple          [0] OCTET STRING,
 *                              krbv42LDAP      [1] OCTET STRING,
 *                              krbv42DSA       [2] OCTET STRING
 *                      }
 *      }
 *
 * LDAPDN ::= LDAPString
 *
 * LDAPString ::= OCTET STRING
 */

#define LDAPStringTemplate SEC_OctetStringTemplate
#define SequenceOfLDAPStringTemplate SEC_SequenceOfOctetStringTemplate

static const SEC_ASN1Template LDAPBindAuthTemplate[] = {
    { SEC_ASN1_CHOICE, offsetof(LDAPBindAuth, selector), 0, sizeof (LDAPBindAuth) },
    { SEC_ASN1_INLINE, offsetof(LDAPBindAuth, ch.simple),
                SEC_OctetStringTemplate, SIMPLE_AUTH },
    { SEC_ASN1_INLINE, offsetof(LDAPBindAuth, ch.krbv42LDAP),
                SEC_OctetStringTemplate, KRBV42LDAP_AUTH },
    { SEC_ASN1_INLINE, offsetof(LDAPBindAuth, ch.krbv42DSA),
                SEC_OctetStringTemplate, KRBV42DSA_AUTH },
    { 0 }
};

static const SEC_ASN1Template LDAPBindApplTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL },
    { SEC_ASN1_INTEGER, offsetof(LDAPBind, version) },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPBind, bindName) },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPBind, authentication) },
    { 0 }
};

static const SEC_ASN1Template LDAPBindTemplate[] = {
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_APPLICATION | LDAP_BIND_TYPE, 0,
        LDAPBindApplTemplate, sizeof (LDAPBind) } /* ,
    { 0 } */
};

/*
 * BindResponse ::= [APPLICATION 1] LDAPResult
 *
 * LDAPResult ::=
 *      SEQUENCE {
 *              resultCode      ENUMERATED {
 *                              success                         (0),
 *                              operationsError                 (1),
 *                              protocolError                   (2),
 *                              timeLimitExceeded               (3),
 *                              sizeLimitExceeded               (4),
 *                              compareFalse                    (5),
 *                              compareTrue                     (6),
 *                              authMethodNotSupported          (7),
 *                              strongAuthRequired              (8),
 *                              noSuchAttribute                 (16),
 *                              undefinedAttributeType          (17),
 *                              inappropriateMatching           (18),
 *                              constraintViolation             (19),
 *                              attributeOrValueExists          (20),
 *                              invalidAttributeSyntax          (21),
 *                              noSuchObject                    (32),
 *                              aliasProblem                    (33),
 *                              invalidDNSyntax                 (34),
 *                              isLeaf                          (35),
 *                              aliasDereferencingProblem       (36),
 *                              inappropriateAuthentication     (48),
 *                              invalidCredentials              (49),
 *                              insufficientAccessRights        (50),
 *                              busy                            (51),
 *                              unavailable                     (52),
 *                              unwillingToPerform              (53),
 *                              loopDetect                      (54),
 *                              namingViolation                 (64),
 *                              objectClassViolation            (65),
 *                              notAllowedOnNonLeaf             (66),
 *                              notAllowedOnRDN                 (67),
 *                              entryAlreadyExists              (68),
 *                              objectClassModsProhibited       (69),
 *                              other                           (80)
 *                              },
 *              matchedDN       LDAPDN,
 *              errorMessage    LDAPString
 *      }
 */

static const SEC_ASN1Template LDAPResultTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL },
    { SEC_ASN1_ENUMERATED, offsetof(LDAPResult, resultCode) },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPResult, matchedDN) },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPResult, errorMessage) },
    { 0 }
};

static const SEC_ASN1Template LDAPBindResponseTemplate[] = {
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_APPLICATION | LDAP_BINDRESPONSE_TYPE, 0,
        LDAPResultTemplate, sizeof (LDAPBindResponse) } /* ,
    { 0 } */
};

/*
 * UnbindRequest ::= [APPLICATION 2] NULL
 */

static const SEC_ASN1Template LDAPUnbindTemplate[] = {
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_APPLICATION | LDAP_UNBIND_TYPE, 0,
        SEC_NullTemplate } /* ,
    { 0 } */
};

/*
 * AttributeValueAssertion ::=
 *      SEQUENCE {
 *              attributeType   AttributeType,
 *              attributeValue  AttributeValue,
 *      }
 *
 * AttributeType ::= LDAPString
 *               -- text name of the attribute, or dotted
 *               -- OID representation
 *
 * AttributeValue ::= OCTET STRING
 */

#define LDAPAttributeTypeTemplate LDAPStringTemplate

static const SEC_ASN1Template LDAPAttributeValueAssertionTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof (LDAPAttributeValueAssertion) },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPAttributeValueAssertion, attrType) },
    { SEC_ASN1_OCTET_STRING, offsetof(LDAPAttributeValueAssertion, attrValue) },
    { 0 }
};

/*
 * SubstringFilter ::=
 *      SEQUENCE {
 *              type            AttributeType,
 *              SEQUENCE OF CHOICE {
 *                      initial [0] LDAPString,
 *                      any     [1] LDAPString,
 *                      final   [2] LDAPString,
 *              }
 *      }
 */

#define LDAPSubstringFilterInitialTemplate LDAPStringTemplate
#define LDAPSubstringFilterAnyTemplate LDAPStringTemplate
#define LDAPSubstringFilterFinalTemplate LDAPStringTemplate

/*
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
        }
 */

static const SEC_ASN1Template LDAPSubstringFilterChoiceTemplate[] = {
    { SEC_ASN1_SEQUENCE_OF, 0, NULL, sizeof (SECItem) },
    { SEC_ASN1_CONTEXT_SPECIFIC | 0, 0, LDAPSubstringFilterInitialTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | 1, 0, LDAPSubstringFilterAnyTemplate },
    { SEC_ASN1_CONTEXT_SPECIFIC | 2, 0, LDAPSubstringFilterFinalTemplate },
    { 0 }
};

static const SEC_ASN1Template LDAPSubstringFilterTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof (LDAPSubstringFilter) },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPSubstringFilter, attrType) },
    { SEC_ASN1_POINTER, offsetof(LDAPSubstringFilter, substrChoice),
        LDAPSubstringFilterChoiceTemplate },
    { 0 }
};

#define LDAPNotFilterTemplate LDAPFilterTemplate
#define LDAPEqualityMatchFilterTemplate LDAPAttributeValueAssertionTemplate
#define LDAPGreaterOrEqualFilterTemplate LDAPAttributeValueAssertionTemplate
#define LDAPLessOrEqualFilterTemplate LDAPAttributeValueAssertionTemplate
#define LDAPApproxMatchFilterTemplate LDAPAttributeValueAssertionTemplate
#define LDAPPresentFilterTemplate LDAPAttributeTypeTemplate

static const SEC_ASN1Template LDAPFilterTemplate[10]; /* forward reference */

static const SEC_ASN1Template LDAPAndFilterTemplate[] = {
    { SEC_ASN1_SET_OF, 0, LDAPFilterTemplate }
};
static const SEC_ASN1Template LDAPOrFilterTemplate[] = {
    { SEC_ASN1_SET_OF, 0, LDAPFilterTemplate }
};

static const SEC_ASN1Template LDAPFilterTemplate[] = {
    { SEC_ASN1_CHOICE, offsetof(LDAPFilter, selector), 0, sizeof(LDAPFilter) },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_ANDFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPAndFilterTemplate, LDAP_ANDFILTER_TYPE },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_ORFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPOrFilterTemplate, LDAP_ORFILTER_TYPE },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_EQUALITYMATCHFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPEqualityMatchFilterTemplate, LDAP_EQUALITYMATCHFILTER_TYPE },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_SUBSTRINGFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPSubstringFilterTemplate, LDAP_SUBSTRINGFILTER_TYPE },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_GREATEROREQUALFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPGreaterOrEqualFilterTemplate, LDAP_GREATEROREQUALFILTER_TYPE },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_LESSOREQUALFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPLessOrEqualFilterTemplate, LDAP_LESSOREQUALFILTER_TYPE },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_PRESENTFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPPresentFilterTemplate, LDAP_PRESENTFILTER_TYPE },
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_CONTEXT_SPECIFIC | LDAP_APPROXMATCHFILTER_TYPE,
        offsetof(LDAPFilter, filter),
        LDAPApproxMatchFilterTemplate, LDAP_APPROXMATCHFILTER_TYPE },
    { 0 }
};

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
 */

static const SEC_ASN1Template LDAPAttributeTemplate[] = {
    { SEC_ASN1_LDAP_STRING, 0, NULL, sizeof (SECItem) }
};

static const SEC_ASN1Template LDAPSearchApplTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPSearch, baseObject) },
    { SEC_ASN1_ENUMERATED, offsetof(LDAPSearch, scope) },
    { SEC_ASN1_ENUMERATED, offsetof(LDAPSearch, derefAliases) },
    { SEC_ASN1_INTEGER, offsetof(LDAPSearch, sizeLimit) },
    { SEC_ASN1_INTEGER, offsetof(LDAPSearch, timeLimit) },
    { SEC_ASN1_BOOLEAN, offsetof(LDAPSearch, attrsOnly) },
    { SEC_ASN1_INLINE, offsetof(LDAPSearch, filter), LDAPFilterTemplate },
    { SEC_ASN1_SEQUENCE_OF, offsetof(LDAPSearch, attributes), LDAPAttributeTemplate },
    { 0 }
};

static const SEC_ASN1Template LDAPSearchTemplate[] = {
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_APPLICATION | LDAP_SEARCH_TYPE, 0,
        LDAPSearchApplTemplate, sizeof (LDAPSearch) } /* ,
    { 0 } */
};

/*
 * SearchResponse ::=
 *      CHOICE {
 *              entry   [APPLICATION 4] SEQUENCE {
 *                              objectName      LDAPDN,
 *                              attributes      SEQUENCE OF SEQUENCE {
 *                                                      AttributeType,
 *                                                      SET OF AttributeValue
 *                                              }
 *                      }
 *              resultCode [APPLICATION 5] LDAPResult
 *      }
 */

static const SEC_ASN1Template LDAPSearchResponseAttrTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPSearchResponseAttr, attrType) },
    { SEC_ASN1_SET_OF, offsetof(LDAPSearchResponseAttr, val), LDAPStringTemplate },
    { 0 }
};

static const SEC_ASN1Template LDAPEntryTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL },
    { SEC_ASN1_LDAP_STRING, offsetof(LDAPSearchResponseEntry, objectName) },
    { SEC_ASN1_SEQUENCE_OF, offsetof(LDAPSearchResponseEntry, attributes),
        LDAPSearchResponseAttrTemplate },
    { 0 }
};

static const SEC_ASN1Template LDAPSearchResponseEntryTemplate[] = {
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_APPLICATION | LDAP_SEARCHRESPONSEENTRY_TYPE, 0,
        LDAPEntryTemplate, sizeof (LDAPSearchResponseEntry) } /* ,
    { 0 } */
};

static const SEC_ASN1Template LDAPSearchResponseResultTemplate[] = {
    { SEC_ASN1_APPLICATION | LDAP_SEARCHRESPONSERESULT_TYPE, 0,
        LDAPResultTemplate, sizeof (LDAPSearchResponseResult) } /* ,
    { 0 } */
};

/*
 * AbandonRequest ::=
 *      [APPLICATION 16] MessageID
 */

static const SEC_ASN1Template LDAPAbandonTemplate[] = {
    { SEC_ASN1_INTEGER, offsetof(LDAPAbandonRequest, messageID) }
};

static const SEC_ASN1Template LDAPAbandonRequestTemplate[] = {
    { SEC_ASN1_CONSTRUCTED | SEC_ASN1_APPLICATION | LDAP_ABANDONREQUEST_TYPE, 0,
        LDAPAbandonTemplate, sizeof (LDAPAbandonRequest) } /* ,
    { 0 } */
};

/*
 * LDAPMessage ::=
 *      SEQUENCE {
 *              messageID       MessageID,
 *              protocolOp      CHOICE {
 *                                      bindRequest     BindRequest,
 *                                      bindResponse    BindResponse,
 *                                      unbindRequest   UnbindRequest,
 *                                      searchRequest   SearchRequest,
 *                                      searchResponse  SearchResponse,
 *                                      abandonRequest  AbandonRequest
 *                              }
 *      }
 *
 *                                      (other choices exist, not shown)
 *
 * MessageID ::= INTEGER (0 .. maxInt)
 */

static const SEC_ASN1Template LDAPMessageProtocolOpTemplate[] = {
    { SEC_ASN1_CHOICE, offsetof(LDAPProtocolOp, selector), 0, sizeof (LDAPProtocolOp) },
    { SEC_ASN1_INLINE, offsetof(LDAPProtocolOp, op.bindMsg),
        LDAPBindTemplate, LDAP_BIND_TYPE },
    { SEC_ASN1_INLINE, offsetof(LDAPProtocolOp, op.bindResponseMsg),
        LDAPBindResponseTemplate, LDAP_BINDRESPONSE_TYPE },
    { SEC_ASN1_INLINE, offsetof(LDAPProtocolOp, op.unbindMsg),
        LDAPUnbindTemplate, LDAP_UNBIND_TYPE },
    { SEC_ASN1_INLINE, offsetof(LDAPProtocolOp, op.searchMsg),
        LDAPSearchTemplate, LDAP_SEARCH_TYPE },
    { SEC_ASN1_INLINE, offsetof(LDAPProtocolOp, op.searchResponseEntryMsg),
        LDAPSearchResponseEntryTemplate, LDAP_SEARCHRESPONSEENTRY_TYPE },
    { SEC_ASN1_INLINE, offsetof(LDAPProtocolOp, op.searchResponseResultMsg),
        LDAPSearchResponseResultTemplate, LDAP_SEARCHRESPONSERESULT_TYPE },
    { SEC_ASN1_INLINE, offsetof(LDAPProtocolOp, op.abandonRequestMsg),
        LDAPAbandonRequestTemplate, LDAP_ABANDONREQUEST_TYPE },
    { 0 }
};

const SEC_ASN1Template PKIX_PL_LDAPMessageTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL },
    { SEC_ASN1_INTEGER, offsetof(LDAPMessage, messageID) },
    { SEC_ASN1_INLINE, offsetof(LDAPMessage, protocolOp),
        LDAPMessageProtocolOpTemplate },
    { 0 }
};

/* This function simply returns the address of the message template.
 * This is necessary for Windows DLLs.
 */
SEC_ASN1_CHOOSER_IMPLEMENT(PKIX_PL_LDAPMessageTemplate)
