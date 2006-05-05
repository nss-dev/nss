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
 * This file defines the types in the libpkix API.
 * XXX Maybe we should specify the API version number in all API header files
 *
 */

#ifndef _PKIXT_H
#define _PKIXT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Types
 *
 * This header file provides typedefs for the abstract types used by libpkix.
 * It also provides several useful macros.
 *
 * Note that all these abstract types are typedef'd as opaque structures. This
 * is intended to discourage the caller from looking at the contents directly,
 * since the format of the contents may change from one version of the library
 * to the next. Instead, callers should only access these types using the
 * functions defined in the public header files.
 *
 * An instance of an abstract type defined in this file is called an "object"
 * here, although C does not have real support for objects.
 *
 * Because C does not typically have automatic garbage collection, the caller
 * is expected to release the reference to any object that they create or that
 * is returned to them by a libpkix function. The caller should do this by
 * using the PKIX_PL_Object_DecRef function. Note that the caller should not
 * release the reference to an object if the object has been passed to a
 * libpkix function and that function has not returned.
 *
 * Please refer to libpkix Programmer's Guide for more details.
 */

/* Version
 *
 * These macros specify the major and minor version of the libpkix API defined
 * by this header file.
 */

#define PKIX_MAJOR_VERSION              ((PKIX_UInt32) 0)
#define PKIX_MINOR_VERSION              ((PKIX_UInt32) 3)

/* Maximum minor version
 *
 * This macro is used to specify that the caller wants the largest minor
 * version available.
 */

#define PKIX_MAX_MINOR_VERSION          ((PKIX_UInt32) 4000000000)

/* Define Cert Store type for database access */
#define PKIX_STORE_TYPE_NONE            0
#define PKIX_STORE_TYPE_PK11            1

/* Portable Code (PC) data types
 *
 * These types are used to perform the primary operations of this library:
 * building and validating chains of X.509 certificates.
 */

typedef struct PKIX_ErrorStruct PKIX_Error;
typedef struct PKIX_ProcessingParamsStruct PKIX_ProcessingParams;
typedef struct PKIX_ValidateParamsStruct PKIX_ValidateParams;
typedef struct PKIX_ValidateResultStruct PKIX_ValidateResult;
typedef struct PKIX_ResourceLimitsStruct PKIX_ResourceLimits;
typedef struct PKIX_BuildResultStruct PKIX_BuildResult;
typedef struct PKIX_CertStoreStruct PKIX_CertStore;
typedef struct PKIX_CertChainCheckerStruct PKIX_CertChainChecker;
typedef struct PKIX_RevocationCheckerStruct PKIX_RevocationChecker;
typedef struct PKIX_CertSelectorStruct PKIX_CertSelector;
typedef struct PKIX_CRLSelectorStruct PKIX_CRLSelector;
typedef struct PKIX_ComCertSelParamsStruct PKIX_ComCertSelParams;
typedef struct PKIX_ComCRLSelParamsStruct PKIX_ComCRLSelParams;
typedef struct PKIX_TrustAnchorStruct PKIX_TrustAnchor;
typedef struct PKIX_PolicyNodeStruct PKIX_PolicyNode;
typedef struct PKIX_LoggerStruct PKIX_Logger;
typedef struct PKIX_ListStruct PKIX_List;
typedef struct PKIX_ForwardBuilderStateStruct PKIX_ForwardBuilderState;
typedef struct PKIX_DefaultRevocationCheckerStruct
                        PKIX_DefaultRevocationChecker;
typedef struct PKIX_OcspCheckerStruct PKIX_OcspChecker;

/* Portability Layer (PL) data types
 *
 * These types are used are used as portable data types that are defined
 * consistently across platforms
 */

typedef struct PKIX_PL_ObjectStruct PKIX_PL_Object;
typedef struct PKIX_PL_ByteArrayStruct PKIX_PL_ByteArray;
typedef struct PKIX_PL_HashTableStruct PKIX_PL_HashTable;
typedef struct PKIX_PL_MutexStruct PKIX_PL_Mutex;
typedef struct PKIX_PL_RWLockStruct PKIX_PL_RWLock;
typedef struct PKIX_PL_MonitorLockStruct PKIX_PL_MonitorLock;
typedef struct PKIX_PL_BigIntStruct PKIX_PL_BigInt;
typedef struct PKIX_PL_StringStruct PKIX_PL_String;
typedef struct PKIX_PL_OIDStruct PKIX_PL_OID;
typedef struct PKIX_PL_CertStruct PKIX_PL_Cert;
typedef struct PKIX_PL_GeneralNameStruct PKIX_PL_GeneralName;
typedef struct PKIX_PL_X500NameStruct PKIX_PL_X500Name;
typedef struct PKIX_PL_PublicKeyStruct PKIX_PL_PublicKey;
typedef struct PKIX_PL_DateStruct PKIX_PL_Date;
typedef struct PKIX_PL_CertNameConstraintsStruct PKIX_PL_CertNameConstraints;
typedef struct PKIX_PL_CertBasicConstraintsStruct PKIX_PL_CertBasicConstraints;
typedef struct PKIX_PL_CertPoliciesStruct PKIX_PL_CertPolicies;
typedef struct PKIX_PL_CertPolicyInfoStruct PKIX_PL_CertPolicyInfo;
typedef struct PKIX_PL_CertPolicyQualifierStruct PKIX_PL_CertPolicyQualifier;
typedef struct PKIX_PL_CertPolicyMapStruct PKIX_PL_CertPolicyMap;
typedef struct PKIX_PL_CRLStruct PKIX_PL_CRL;
typedef struct PKIX_PL_CRLEntryStruct PKIX_PL_CRLEntry;
typedef struct PKIX_PL_CollectionCertStoreStruct PKIX_PL_CollectionCertStore;
typedef struct PKIX_PL_CollectionCertStoreContext
                        PKIX_PL_CollectionCertStoreContext;
typedef struct PKIX_PL_LdapCertStoreContext PKIX_PL_LdapCertStoreContext;
typedef struct PKIX_PL_LdapRequestStruct PKIX_PL_LdapRequest;
typedef struct PKIX_PL_LdapResponseStruct PKIX_PL_LdapResponse;
typedef struct PKIX_PL_LdapDefaultClientStruct PKIX_PL_LdapDefaultClient;
typedef struct PKIX_PL_SocketStruct PKIX_PL_Socket;
typedef struct PKIX_PL_InfoAccessStruct PKIX_PL_InfoAccess;
typedef struct PKIX_PL_AIAMgrStruct PKIX_PL_AIAMgr;
typedef struct PKIX_PL_OcspRequestStruct PKIX_PL_OcspRequest;
typedef struct PKIX_PL_OcspResponseStruct PKIX_PL_OcspResponse;
typedef struct PKIX_PL_HttpClientStruct PKIX_PL_HttpClient;
typedef struct PKIX_PL_HttpDefaultClientStruct PKIX_PL_HttpDefaultClient;
typedef struct PKIX_PL_HttpCertStoreContextStruct PKIX_PL_HttpCertStoreContext;

/* Primitive types
 *
 * In order to guarantee desired behavior as well as platform-independence, we
 * typedef these types depending on the platform. XXX This needs more work!
 */

/* XXX Try compiling these files (and maybe the whole libpkix-nss) on Win32.
 * We don't know what type is at least 32 bits long. ISO C probably requires
 * at least 32 bits for long. we could default to that and only list platforms
 * where that's not true.
 *
 * #elif
 * #error
 * #endif
 */

/* currently, int is 32 bits on all our supported platforms */

typedef unsigned int PKIX_UInt32;
typedef int PKIX_Int32;

typedef int PKIX_Boolean;

/* Object Types
 *
 * Every reference-counted PKIX_PL_Object is associated with an integer type.
 */

#define PKIX_OBJECT_TYPE                ((PKIX_UInt32) 0)
#define PKIX_BIGINT_TYPE                ((PKIX_UInt32) 1)
#define PKIX_BYTEARRAY_TYPE             ((PKIX_UInt32) 2)
#define PKIX_ERROR_TYPE                 ((PKIX_UInt32) 3)
#define PKIX_HASHTABLE_TYPE             ((PKIX_UInt32) 4)
#define PKIX_LIST_TYPE                  ((PKIX_UInt32) 5)
#define PKIX_LOGGER_TYPE                ((PKIX_UInt32) 6)
#define PKIX_MUTEX_TYPE                 ((PKIX_UInt32) 7)
#define PKIX_OID_TYPE                   ((PKIX_UInt32) 8)
#define PKIX_RWLOCK_TYPE                ((PKIX_UInt32) 9)
#define PKIX_STRING_TYPE                ((PKIX_UInt32) 10)

#define PKIX_CERTBASICCONSTRAINTS_TYPE  ((PKIX_UInt32) 11)
#define PKIX_CERT_TYPE                  ((PKIX_UInt32) 12)
#define PKIX_HTTPCLIENT_TYPE            ((PKIX_UInt32) 13)
#define PKIX_CRL_TYPE                   ((PKIX_UInt32) 14)
#define PKIX_CRLENTRY_TYPE              ((PKIX_UInt32) 15)
#define PKIX_DATE_TYPE                  ((PKIX_UInt32) 16)
#define PKIX_GENERALNAME_TYPE           ((PKIX_UInt32) 17)
#define PKIX_CERTNAMECONSTRAINTS_TYPE   ((PKIX_UInt32) 18)
#define PKIX_PUBLICKEY_TYPE             ((PKIX_UInt32) 19)
#define PKIX_TRUSTANCHOR_TYPE           ((PKIX_UInt32) 20)

#define PKIX_X500NAME_TYPE              ((PKIX_UInt32) 21)
#define PKIX_HTTPCERTSTORECONTEXT_TYPE  ((PKIX_UInt32) 22)
#define PKIX_BUILDRESULT_TYPE           ((PKIX_UInt32) 23)
#define PKIX_PROCESSINGPARAMS_TYPE      ((PKIX_UInt32) 24)
#define PKIX_VALIDATEPARAMS_TYPE        ((PKIX_UInt32) 25)
#define PKIX_VALIDATERESULT_TYPE        ((PKIX_UInt32) 26)
#define PKIX_CERTSTORE_TYPE             ((PKIX_UInt32) 27)
#define PKIX_CERTCHAINCHECKER_TYPE      ((PKIX_UInt32) 28)
#define PKIX_REVOCATIONCHECKER_TYPE     ((PKIX_UInt32) 29)
#define PKIX_CERTSELECTOR_TYPE          ((PKIX_UInt32) 30)

#define PKIX_COMCERTSELPARAMS_TYPE      ((PKIX_UInt32) 31)
#define PKIX_CRLSELECTOR_TYPE           ((PKIX_UInt32) 32)
#define PKIX_COMCRLSELPARAMS_TYPE       ((PKIX_UInt32) 33)
#define PKIX_CERTPOLICYINFO_TYPE        ((PKIX_UInt32) 34)
#define PKIX_CERTPOLICYQUALIFIER_TYPE   ((PKIX_UInt32) 35)
#define PKIX_CERTPOLICYMAP_TYPE         ((PKIX_UInt32) 36)
#define PKIX_CERTPOLICYNODE_TYPE        ((PKIX_UInt32) 37)
#define PKIX_TARGETCERTCHECKERSTATE_TYPE ((PKIX_UInt32) 38)
#define PKIX_BASICCONSTRAINTSCHECKERSTATE_TYPE ((PKIX_UInt32) 39)
#define PKIX_CERTPOLICYCHECKERSTATE_TYPE ((PKIX_UInt32) 40)

#define PKIX_COLLECTIONCERTSTORECONTEXT_TYPE ((PKIX_UInt32) 41)
#define PKIX_DEFAULTCRLCHECKERSTATE_TYPE ((PKIX_UInt32) 42)
#define PKIX_FORWARDBUILDERSTATE_TYPE   ((PKIX_UInt32) 43)
#define PKIX_SIGNATURECHECKERSTATE_TYPE ((PKIX_UInt32) 44)
#define PKIX_CERTNAMECONSTRAINTSCHECKERSTATE_TYPE ((PKIX_UInt32) 45)
#define PKIX_DEFAULTREVOCATIONCHECKER_TYPE ((PKIX_UInt32) 46)
#define PKIX_LDAPREQUEST_TYPE           ((PKIX_UInt32) 47)
#define PKIX_LDAPRESPONSE_TYPE          ((PKIX_UInt32) 48)
#define PKIX_LDAPDEFAULTCLIENT_TYPE     ((PKIX_UInt32) 49)
#define PKIX_SOCKET_TYPE                ((PKIX_UInt32) 50)

#define PKIX_RESOURCELIMITS_TYPE        ((PKIX_UInt32) 51)
#define PKIX_MONITORLOCK_TYPE           ((PKIX_UInt32) 52)
#define PKIX_INFOACCESS_TYPE            ((PKIX_UInt32) 53)
#define PKIX_AIAMGR_TYPE                ((PKIX_UInt32) 54)
#define PKIX_OCSPCHECKER_TYPE           ((PKIX_UInt32) 55)
#define PKIX_OCSPREQUEST_TYPE           ((PKIX_UInt32) 56)
#define PKIX_OCSPRESPONSE_TYPE          ((PKIX_UInt32) 57)
#define PKIX_HTTPDEFAULTCLIENT_TYPE     ((PKIX_UInt32) 58)

#define PKIX_NUMTYPES                   ((PKIX_UInt32) 59)

/* User Define Object Types
 *
 * User may define their own object types offset from PKIX_USER_OBJECT_TYPE
 */
#define PKIX_USER_OBJECT_TYPEBASE 1000

/* Error Codes
 *
 * Every PKIX_Error is associated with an integer error code. Therefore
 * this list must correspond, one-to-one, with the strings in the table
 * "const char *PKIX_ERRORNAMES[PKIX_NUMERRORS]" in pkix_error.c and the
 * table "const char PKIX_COMPONENTNAMES[PKIX_NUMERRORS]" in pkix_logger.c.
 *
 * Also, those Error Codes that doesn't have association with Object Types
 * defined earlier are sometimes used as the Object Type for the macro
 * PKIX_ENTER(). This is because there are functions that are not associated
 * with any defined Objects but need to relate to an Object Type.
 */

#define PKIX_OBJECT_ERROR               ((PKIX_UInt32) 0)
#define PKIX_FATAL_ERROR                ((PKIX_UInt32) 1)
#define PKIX_MEM_ERROR                  ((PKIX_UInt32) 2)
#define PKIX_ERROR_ERROR                ((PKIX_UInt32) 3)
#define PKIX_MUTEX_ERROR                ((PKIX_UInt32) 4)
#define PKIX_RWLOCK_ERROR               ((PKIX_UInt32) 5)
#define PKIX_STRING_ERROR               ((PKIX_UInt32) 6)
#define PKIX_OID_ERROR                  ((PKIX_UInt32) 7)
#define PKIX_LIST_ERROR                 ((PKIX_UInt32) 8)
#define PKIX_BYTEARRAY_ERROR            ((PKIX_UInt32) 9)
#define PKIX_BIGINT_ERROR               ((PKIX_UInt32) 10)
#define PKIX_HASHTABLE_ERROR            ((PKIX_UInt32) 11)
#define PKIX_CERT_ERROR                 ((PKIX_UInt32) 12)
#define PKIX_X500NAME_ERROR             ((PKIX_UInt32) 13)
#define PKIX_GENERALNAME_ERROR          ((PKIX_UInt32) 14)
#define PKIX_PUBLICKEY_ERROR            ((PKIX_UInt32) 15)
#define PKIX_DATE_ERROR                 ((PKIX_UInt32) 16)
#define PKIX_TRUSTANCHOR_ERROR          ((PKIX_UInt32) 17)
#define PKIX_PROCESSINGPARAMS_ERROR     ((PKIX_UInt32) 18)
#define PKIX_HTTPCLIENT_ERROR           ((PKIX_UInt32) 19)
#define PKIX_VALIDATEPARAMS_ERROR       ((PKIX_UInt32) 20)
#define PKIX_VALIDATE_ERROR             ((PKIX_UInt32) 21)
#define PKIX_VALIDATERESULT_ERROR       ((PKIX_UInt32) 22)
#define PKIX_CERTCHAINCHECKER_ERROR     ((PKIX_UInt32) 23)
#define PKIX_CERTSELECTOR_ERROR         ((PKIX_UInt32) 24)
#define PKIX_COMCERTSELPARAMS_ERROR     ((PKIX_UInt32) 25)
#define PKIX_TARGETCERTCHECKERSTATE_ERROR ((PKIX_UInt32) 26)
#define PKIX_CERTBASICCONSTRAINTS_ERROR ((PKIX_UInt32) 27)
#define PKIX_CERTPOLICYQUALIFIER_ERROR  ((PKIX_UInt32) 28)
#define PKIX_CERTPOLICYINFO_ERROR       ((PKIX_UInt32) 29)
#define PKIX_CERTPOLICYNODE_ERROR       ((PKIX_UInt32) 30)
#define PKIX_CERTPOLICYCHECKERSTATE_ERROR       ((PKIX_UInt32) 31)
#define PKIX_LIFECYCLE_ERROR            ((PKIX_UInt32) 32)
#define PKIX_BASICCONSTRAINTSCHECKERSTATE_ERROR ((PKIX_UInt32) 33)
#define PKIX_COMCRLSELPARAMS_ERROR      ((PKIX_UInt32) 34)
#define PKIX_CERTSTORE_ERROR            ((PKIX_UInt32) 35)
#define PKIX_COLLECTIONCERTSTORECONTEXT_ERROR ((PKIX_UInt32) 36)
#define PKIX_DEFAULTCRLCHECKERSTATE_ERROR ((PKIX_UInt32) 37)
#define PKIX_CRL_ERROR                  ((PKIX_UInt32) 38)
#define PKIX_CRLENTRY_ERROR             ((PKIX_UInt32) 39)
#define PKIX_CRLSELECTOR_ERROR          ((PKIX_UInt32) 40)
#define PKIX_CERTPOLICYMAP_ERROR        ((PKIX_UInt32) 41)
#define PKIX_BUILD_ERROR                ((PKIX_UInt32) 42)
#define PKIX_BUILDRESULT_ERROR          ((PKIX_UInt32) 43)
#define PKIX_HTTPCERTSTORECONTEXT_ERROR ((PKIX_UInt32) 44)
#define PKIX_FORWARDBUILDERSTATE_ERROR  ((PKIX_UInt32) 45)
#define PKIX_SIGNATURECHECKERSTATE_ERROR ((PKIX_UInt32) 46)
#define PKIX_CERTNAMECONSTRAINTS_ERROR ((PKIX_UInt32) 47)
#define PKIX_CERTNAMECONSTRAINTSCHECKERSTATE_ERROR ((PKIX_UInt32) 48)
#define PKIX_REVOCATIONCHECKER_ERROR    ((PKIX_UInt32) 49)
#define PKIX_USERDEFINEDMODULES_ERROR   ((PKIX_UInt32) 50)
#define PKIX_CONTEXT_ERROR              ((PKIX_UInt32) 51)
#define PKIX_DEFAULTREVOCATIONCHECKER_ERROR ((PKIX_UInt32) 52)
#define PKIX_LDAPREQUEST_ERROR          ((PKIX_UInt32) 53)
#define PKIX_LDAPRESPONSE_ERROR         ((PKIX_UInt32) 54)
#define PKIX_LDAPCLIENT_ERROR           ((PKIX_UInt32) 55)
#define PKIX_LDAPDEFAULTCLIENT_ERROR    ((PKIX_UInt32) 56)
#define PKIX_SOCKET_ERROR               ((PKIX_UInt32) 57)
#define PKIX_RESOURCELIMITS_ERROR       ((PKIX_UInt32) 58)
#define PKIX_LOGGER_ERROR               ((PKIX_UInt32) 59)
#define PKIX_MONITORLOCK_ERROR          ((PKIX_UInt32) 60)
#define PKIX_INFOACCESS_ERROR           ((PKIX_UInt32) 61)
#define PKIX_AIAMGR_ERROR               ((PKIX_UInt32) 62)
#define PKIX_OCSPCHECKER_ERROR          ((PKIX_UInt32) 63)
#define PKIX_OCSPREQUEST_ERROR          ((PKIX_UInt32) 64)
#define PKIX_OCSPRESPONSE_ERROR         ((PKIX_UInt32) 65)
#define PKIX_HTTPDEFAULTCLIENT_ERROR    ((PKIX_UInt32) 66)

/* YOU NEED TO UPDATE NEW ENTRY at pkix_error.c and pkix_logger.c */
#define PKIX_NUMERRORS                  ((PKIX_UInt32) 67)

/* String Formats
 *
 * These formats specify supported encoding formats for Strings.
 */

#define PKIX_ESCASCII           0
#define PKIX_UTF8               1
#define PKIX_UTF16              2
#define PKIX_UTF8_NULL_TERM     3
#define PKIX_ESCASCII_DEBUG     4

/* Name Types
 *
 * These types specify supported formats for GeneralNames.
 */

#define PKIX_OTHER_NAME         1
#define PKIX_RFC822_NAME        2
#define PKIX_DNS_NAME           3
#define PKIX_X400_ADDRESS       4
#define PKIX_DIRECTORY_NAME     5
#define PKIX_EDIPARTY_NAME      6
#define PKIX_URI_NAME           7
#define PKIX_IP_NAME            8
#define PKIX_OID_NAME           9

/* Key Usages
 *
 * These typess specify supported Key Usages
 */

#define PKIX_DIGITAL_SIGNATURE  0x001
#define PKIX_NON_REPUDIATION    0x002
#define PKIX_KEY_ENCIPHERMENT   0x004
#define PKIX_DATA_ENCIPHERMENT  0x008
#define PKIX_KEY_AGREEMENT      0x010
#define PKIX_KEY_CERT_SIGN      0x020
#define PKIX_CRL_SIGN           0x040
#define PKIX_ENCIPHER_ONLY      0x080
#define PKIX_DECIPHER_ONLY      0x100

/* Reason Flags
 *
 * These macros specify supported Reason Flags
 */

#define PKIX_UNUSED                     0x001
#define PKIX_KEY_COMPROMISE             0x002
#define PKIX_CA_COMPROMISE              0x004
#define PKIX_AFFILIATION_CHANGED        0x008
#define PKIX_SUPERSEDED                 0x010
#define PKIX_CESSATION_OF_OPERATION     0x020
#define PKIX_CERTIFICATE_HOLD           0x040
#define PKIX_PRIVILEGE_WITHDRAWN        0x080
#define PKIX_AA_COMPROMISE              0x100

/* Boolean values
 *
 * These macros specify the Boolean values of TRUE and FALSE
 * XXX Is it the case that any non-zero value is actually considered TRUE
 * and this is just a convenient mnemonic macro?
 */

#define PKIX_TRUE                       ((PKIX_Boolean) 1)
#define PKIX_FALSE                      ((PKIX_Boolean) 0)

/*
 * Define constants for basic constraints selector
 *      (see comments in pkix_certsel.h)
 */

#define PKIX_CERTSEL_ENDENTITY_MIN_PATHLENGTH (-2)
#define PKIX_CERTSEL_ALL_MATCH_MIN_PATHLENGTH (-1)

/*
 * PKIX_ALLOC_ERROR is a special error object hard-coded into the pkix_error.o
 * object file. It is thrown if system memory cannot be allocated or may be
 * thrown for other unrecoverable errors. PKIX_ALLOC_ERROR is immutable.
 * IncRef, DecRef and all Settor functions cannot be called.
 * XXX Does anyone actually need to know about this?
 * XXX Why no DecRef? Would be good to handle it the same.
 */

PKIX_Error* PKIX_ALLOC_ERROR(void);

/*
 * In a CertBasicConstraints extension, if the CA flag is set,
 * indicating the certificate refers to a Certification
 * Authority, then the pathLen field indicates how many intermediate
 * certificates (not counting self-signed ones) can exist in a valid
 * chain following this certificate. If the pathLen has the value
 * of this constant, then the length of the chain is unlimited
 */
#define PKIX_UNLIMITED_PATH_CONSTRAINT ((PKIX_Int32) -1)

/*
 * Define Certificate Extension hard-coded OID's
 */
#define PKIX_CERTKEYUSAGE_OID "2.5.29.15"
#define PKIX_CERTSUBJALTNAME_OID "2.5.29.17"
#define PKIX_BASICCONSTRAINTS_OID "2.5.29.19"
#define PKIX_CRLREASONCODE_OID "2.5.29.21"
#define PKIX_NAMECONSTRAINTS_OID "2.5.29.30"
#define PKIX_CERTIFICATEPOLICIES_OID "2.5.29.32"
#define PKIX_CERTIFICATEPOLICIES_ANYPOLICY_OID "2.5.29.32.0"
#define PKIX_POLICYMAPPINGS_OID "2.5.29.33"
#define PKIX_POLICYCONSTRAINTS_OID "2.5.29.36"
#define PKIX_EXTENDEDKEYUSAGE_OID "2.5.29.37"
#define PKIX_INHIBITANYPOLICY_OID "2.5.29.54"

#ifdef __cplusplus
}
#endif

#endif /* _PKIXT_H */
