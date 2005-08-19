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
 * pkix_pl_ldaprequest.h
 *
 * LdapRequest Object Definitions
 *
 */

#ifndef _PKIX_PL_LDAPREQUEST_H
#define _PKIX_PL_LDAPREQUEST_H

#include "pkix_pl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Note: the following definitions are taken unchanged from the Mozilla
 * file /mozilla/directory/c-sdk/ldap/include/ldaprot.h. If that
 * file is accessible to this build these definitions should be replaced
 * by an "include" of that file:
 */
#define LDAP_VERSION1   1
#define LDAP_VERSION2   2
#define LDAP_VERSION3   3
#define LDAP_VERSION    LDAP_VERSION2

/* possible operations a client can invoke */
#define LDAP_REQ_BIND           0x60L   /* application + constructed + 0 */
#define LDAP_REQ_UNBIND         0x42L   /* application + primitive   + 2 */
#define LDAP_REQ_SEARCH         0x63L   /* application + constructed + 3 */
#define LDAP_REQ_MODIFY         0x66L   /* application + constructed + 6 */
#define LDAP_REQ_ADD            0x68L   /* application + constructed + 8 */
#define LDAP_REQ_DELETE         0x4aL   /* application + primitive   + 10 */
#define LDAP_REQ_MODRDN         0x6cL   /* application + constructed + 12 */
#define LDAP_REQ_MODDN          0x6cL   /* application + constructed + 12 */
#define LDAP_REQ_RENAME         0x6cL   /* application + constructed + 12 */
#define LDAP_REQ_COMPARE        0x6eL   /* application + constructed + 14 */
#define LDAP_REQ_ABANDON        0x50L   /* application + primitive   + 16 */
#define LDAP_REQ_EXTENDED       0x77L   /* application + constructed + 23 */
/*
 * End of Ldaprot.h definitions
 */

typedef enum {
        USER_CERT,
        CA_CERT,
        CROSS_CERT,
        CRL,
        ARL,
        DELTA_CRL
} PKIX_PL_LdapAttr;

struct PKIX_PL_LdapRequestStruct{
        PRArenaPool *arena;
        PKIX_UInt32 msgnum;
        char *issuerDN;
        ScopeType scope;
        DerefType derefAliases;
        PKIX_UInt32 sizeLimit;
        PKIX_UInt32 timeLimit;
        char attrsOnly;
        LDAPFilter *filter;
        LdapAttrMask attrBits;
        SECItem attributes[MAX_LDAPATTRS];
        SECItem **attrArray;
        SECItem *encoded;
};

/* see source file for function documentation */

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
        LDAPFilter *filter,
        LdapAttrMask attrBits,
        PKIX_PL_LdapRequest **pRequestMsg,
        void *plContext);

PKIX_Error *
pkix_pl_LdapRequest_AttrTypeToBit(
        SECItem *attrType,
        LdapAttrMask *pAttrBit,
        void *plContext);

PKIX_Error *
pkix_pl_LdapRequest_GetEncoded(
        PKIX_PL_LdapRequest *request,
        SECItem **pRequestBuf,
        void *plContext);

PKIX_Error *pkix_pl_LdapRequest_RegisterSelf(void *plContext);

#ifdef __cplusplus
}
#endif

#endif /* _PKIX_PL_LDAPREQUEST_H */
