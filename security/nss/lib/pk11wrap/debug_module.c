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
#include "prlog.h"
#include <stdio.h>

static PRLogModuleInfo *modlog = NULL;

static CK_FUNCTION_LIST_PTR module_functions;

static CK_FUNCTION_LIST debug_functions;

static void print_final_statistics(void);

/* The AIX 64-bit compiler chokes on large switch statements (see
 * bug #63815).  I tried the trick recommended there, using -O2 in
 * debug builds, and it didn't work.  Instead, I'll suppress some of
 * the verbose output and just dump values.
 */

static void get_attr_type_str(CK_ATTRIBUTE_TYPE atype, char *str, int len)
{
#ifndef AIX_64BIT
#define CASE(attr) case attr: a = #attr ; break

    const char * a = NULL;

    switch (atype) {
    CASE(CKA_CLASS);
    CASE(CKA_TOKEN);
    CASE(CKA_PRIVATE);
    CASE(CKA_LABEL);
    CASE(CKA_APPLICATION);
    CASE(CKA_VALUE);
    CASE(CKA_OBJECT_ID);
    CASE(CKA_CERTIFICATE_TYPE);
    CASE(CKA_ISSUER);
    CASE(CKA_SERIAL_NUMBER);
    CASE(CKA_AC_ISSUER);
    CASE(CKA_OWNER);
    CASE(CKA_ATTR_TYPES);
    CASE(CKA_TRUSTED);
    CASE(CKA_KEY_TYPE);
    CASE(CKA_SUBJECT);
    CASE(CKA_ID);
    CASE(CKA_SENSITIVE);
    CASE(CKA_ENCRYPT);
    CASE(CKA_DECRYPT);
    CASE(CKA_WRAP);
    CASE(CKA_UNWRAP);
    CASE(CKA_SIGN);
    CASE(CKA_SIGN_RECOVER);
    CASE(CKA_VERIFY);
    CASE(CKA_VERIFY_RECOVER);
    CASE(CKA_DERIVE);
    CASE(CKA_START_DATE);
    CASE(CKA_END_DATE);
    CASE(CKA_MODULUS);
    CASE(CKA_MODULUS_BITS);
    CASE(CKA_PUBLIC_EXPONENT);
    CASE(CKA_PRIVATE_EXPONENT);
    CASE(CKA_PRIME_1);
    CASE(CKA_PRIME_2);
    CASE(CKA_EXPONENT_1);
    CASE(CKA_EXPONENT_2);
    CASE(CKA_COEFFICIENT);
    CASE(CKA_PRIME);
    CASE(CKA_SUBPRIME);
    CASE(CKA_BASE);
    CASE(CKA_PRIME_BITS);
    CASE(CKA_SUB_PRIME_BITS);
    CASE(CKA_VALUE_BITS);
    CASE(CKA_VALUE_LEN);
    CASE(CKA_EXTRACTABLE);
    CASE(CKA_LOCAL);
    CASE(CKA_NEVER_EXTRACTABLE);
    CASE(CKA_ALWAYS_SENSITIVE);
    CASE(CKA_KEY_GEN_MECHANISM);
    CASE(CKA_MODIFIABLE);
    CASE(CKA_ECDSA_PARAMS);
    CASE(CKA_EC_POINT);
    CASE(CKA_SECONDARY_AUTH);
    CASE(CKA_AUTH_PIN_FLAGS);
    CASE(CKA_HW_FEATURE_TYPE);
    CASE(CKA_RESET_ON_INIT);
    CASE(CKA_HAS_RESET);
    CASE(CKA_VENDOR_DEFINED);
    CASE(CKA_NETSCAPE_URL);
    CASE(CKA_NETSCAPE_EMAIL);
    CASE(CKA_NETSCAPE_SMIME_INFO);
    CASE(CKA_NETSCAPE_SMIME_TIMESTAMP);
    CASE(CKA_NETSCAPE_PKCS8_SALT);
    CASE(CKA_NETSCAPE_PASSWORD_CHECK);
    CASE(CKA_NETSCAPE_EXPIRES);
    CASE(CKA_NETSCAPE_KRL);
    CASE(CKA_NETSCAPE_PQG_COUNTER);
    CASE(CKA_NETSCAPE_PQG_SEED);
    CASE(CKA_NETSCAPE_PQG_H);
    CASE(CKA_NETSCAPE_PQG_SEED_BITS);
    CASE(CKA_TRUST);
    CASE(CKA_TRUST_DIGITAL_SIGNATURE);
    CASE(CKA_TRUST_NON_REPUDIATION);
    CASE(CKA_TRUST_KEY_ENCIPHERMENT);
    CASE(CKA_TRUST_DATA_ENCIPHERMENT);
    CASE(CKA_TRUST_KEY_AGREEMENT);
    CASE(CKA_TRUST_KEY_CERT_SIGN);
    CASE(CKA_TRUST_CRL_SIGN);
    CASE(CKA_TRUST_SERVER_AUTH);
    CASE(CKA_TRUST_CLIENT_AUTH);
    CASE(CKA_TRUST_CODE_SIGNING);
    CASE(CKA_TRUST_EMAIL_PROTECTION);
    CASE(CKA_TRUST_IPSEC_END_SYSTEM);
    CASE(CKA_TRUST_IPSEC_TUNNEL);
    CASE(CKA_TRUST_IPSEC_USER);
    CASE(CKA_TRUST_TIME_STAMPING);
    CASE(CKA_CERT_SHA1_HASH);
    CASE(CKA_CERT_MD5_HASH);
    CASE(CKA_NETSCAPE_DB);
    CASE(CKA_NETSCAPE_TRUST);
    default: break;
    }
    if (a)
	PR_snprintf(str, len, "%s", a);
    else
#endif
	PR_snprintf(str, len, "0x%p", atype);
}

static void get_obj_class(CK_OBJECT_CLASS objClass, char *str, int len)
{

#ifndef AIX_64BIT
    const char * a = NULL;

    switch (objClass) {
    CASE(CKO_DATA);
    CASE(CKO_CERTIFICATE);
    CASE(CKO_PUBLIC_KEY);
    CASE(CKO_PRIVATE_KEY);
    CASE(CKO_SECRET_KEY);
    CASE(CKO_HW_FEATURE);
    CASE(CKO_DOMAIN_PARAMETERS);
    CASE(CKO_NETSCAPE_CRL);
    CASE(CKO_NETSCAPE_SMIME);
    CASE(CKO_NETSCAPE_TRUST);
    CASE(CKO_NETSCAPE_BUILTIN_ROOT_LIST);
    default: break;
    }
    if (a)
	PR_snprintf(str, len, "%s", a);
    else
#endif
	PR_snprintf(str, len, "0x%p", objClass);
}

static void get_trust_val(CK_TRUST trust, char *str, int len)
{
#ifndef AIX_64BIT
    const char * a = NULL;

    switch (trust) {
    CASE(CKT_NETSCAPE_TRUSTED);
    CASE(CKT_NETSCAPE_TRUSTED_DELEGATOR);
    CASE(CKT_NETSCAPE_UNTRUSTED);
    CASE(CKT_NETSCAPE_MUST_VERIFY);
    CASE(CKT_NETSCAPE_TRUST_UNKNOWN);
    CASE(CKT_NETSCAPE_VALID);
    CASE(CKT_NETSCAPE_VALID_DELEGATOR);
    default: break;
    }
    if (a)
	PR_snprintf(str, len, "%s", a);
    else
#endif
	PR_snprintf(str, len, "0x%p", trust);
}

static void log_rv(CK_RV rv)
{
#ifndef AIX_64BIT
    const char * a = NULL;

    switch (rv) {
    CASE(CKR_OK);
    CASE(CKR_CANCEL);
    CASE(CKR_HOST_MEMORY);
    CASE(CKR_SLOT_ID_INVALID);
    CASE(CKR_GENERAL_ERROR);
    CASE(CKR_FUNCTION_FAILED);
    CASE(CKR_ARGUMENTS_BAD);
    CASE(CKR_NO_EVENT);
    CASE(CKR_NEED_TO_CREATE_THREADS);
    CASE(CKR_CANT_LOCK);
    CASE(CKR_ATTRIBUTE_READ_ONLY);
    CASE(CKR_ATTRIBUTE_SENSITIVE);
    CASE(CKR_ATTRIBUTE_TYPE_INVALID);
    CASE(CKR_ATTRIBUTE_VALUE_INVALID);
    CASE(CKR_DATA_INVALID);
    CASE(CKR_DATA_LEN_RANGE);
    CASE(CKR_DEVICE_ERROR);
    CASE(CKR_DEVICE_MEMORY);
    CASE(CKR_DEVICE_REMOVED);
    CASE(CKR_ENCRYPTED_DATA_INVALID);
    CASE(CKR_ENCRYPTED_DATA_LEN_RANGE);
    CASE(CKR_FUNCTION_CANCELED);
    CASE(CKR_FUNCTION_NOT_PARALLEL);
    CASE(CKR_FUNCTION_NOT_SUPPORTED);
    CASE(CKR_KEY_HANDLE_INVALID);
    CASE(CKR_KEY_SIZE_RANGE);
    CASE(CKR_KEY_TYPE_INCONSISTENT);
    CASE(CKR_KEY_NOT_NEEDED);
    CASE(CKR_KEY_CHANGED);
    CASE(CKR_KEY_NEEDED);
    CASE(CKR_KEY_INDIGESTIBLE);
    CASE(CKR_KEY_FUNCTION_NOT_PERMITTED);
    CASE(CKR_KEY_NOT_WRAPPABLE);
    CASE(CKR_KEY_UNEXTRACTABLE);
    CASE(CKR_MECHANISM_INVALID);
    CASE(CKR_MECHANISM_PARAM_INVALID);
    CASE(CKR_OBJECT_HANDLE_INVALID);
    CASE(CKR_OPERATION_ACTIVE);
    CASE(CKR_OPERATION_NOT_INITIALIZED);
    CASE(CKR_PIN_INCORRECT);
    CASE(CKR_PIN_INVALID);
    CASE(CKR_PIN_LEN_RANGE);
    CASE(CKR_PIN_EXPIRED);
    CASE(CKR_PIN_LOCKED);
    CASE(CKR_SESSION_CLOSED);
    CASE(CKR_SESSION_COUNT);
    CASE(CKR_SESSION_HANDLE_INVALID);
    CASE(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    CASE(CKR_SESSION_READ_ONLY);
    CASE(CKR_SESSION_EXISTS);
    CASE(CKR_SESSION_READ_ONLY_EXISTS);
    CASE(CKR_SESSION_READ_WRITE_SO_EXISTS);
    CASE(CKR_SIGNATURE_INVALID);
    CASE(CKR_SIGNATURE_LEN_RANGE);
    CASE(CKR_TEMPLATE_INCOMPLETE);
    CASE(CKR_TEMPLATE_INCONSISTENT);
    CASE(CKR_TOKEN_NOT_PRESENT);
    CASE(CKR_TOKEN_NOT_RECOGNIZED);
    CASE(CKR_TOKEN_WRITE_PROTECTED);
    CASE(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
    CASE(CKR_UNWRAPPING_KEY_SIZE_RANGE);
    CASE(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
    CASE(CKR_USER_ALREADY_LOGGED_IN);
    CASE(CKR_USER_NOT_LOGGED_IN);
    CASE(CKR_USER_PIN_NOT_INITIALIZED);
    CASE(CKR_USER_TYPE_INVALID);
    CASE(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
    CASE(CKR_USER_TOO_MANY_TYPES);
    CASE(CKR_WRAPPED_KEY_INVALID);
    CASE(CKR_WRAPPED_KEY_LEN_RANGE);
    CASE(CKR_WRAPPING_KEY_HANDLE_INVALID);
    CASE(CKR_WRAPPING_KEY_SIZE_RANGE);
    CASE(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
    CASE(CKR_RANDOM_SEED_NOT_SUPPORTED);
    CASE(CKR_RANDOM_NO_RNG);
    CASE(CKR_DOMAIN_PARAMS_INVALID);
    CASE(CKR_BUFFER_TOO_SMALL);
    CASE(CKR_SAVED_STATE_INVALID);
    CASE(CKR_INFORMATION_SENSITIVE);
    CASE(CKR_STATE_UNSAVEABLE);
    CASE(CKR_CRYPTOKI_NOT_INITIALIZED);
    CASE(CKR_CRYPTOKI_ALREADY_INITIALIZED);
    CASE(CKR_MUTEX_BAD);
    CASE(CKR_MUTEX_NOT_LOCKED);
    CASE(CKR_FUNCTION_REJECTED);
    CASE(CKR_KEY_PARAMS_INVALID);
    default: break;
    }
    if (a)
	PR_LOG(modlog, 1, ("  rv = %s\n", a));
    else
#endif
	PR_LOG(modlog, 1, ("  rv = 0x%x\n", rv));
}

static void print_attr_value(CK_ATTRIBUTE_PTR attr)
{
    char atype[48];
    char valstr[48];
    int len;
    get_attr_type_str(attr->type, atype, sizeof atype);
    switch (attr->type) {
    case CKA_TOKEN:
    case CKA_PRIVATE:
    case CKA_SENSITIVE:
    case CKA_ENCRYPT:
    case CKA_DECRYPT:
    case CKA_WRAP:
    case CKA_UNWRAP:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_DERIVE:
    case CKA_EXTRACTABLE:
    case CKA_LOCAL:
    case CKA_NEVER_EXTRACTABLE:
    case CKA_ALWAYS_SENSITIVE:
    case CKA_MODIFIABLE:
	if (attr->ulValueLen > 0 && attr->pValue) {
	    CK_BBOOL tf = *((CK_BBOOL *)attr->pValue);
	    len = sizeof(valstr);
	    PR_snprintf(valstr, len, "%s", tf ? "CK_TRUE" : "CK_FALSE");
	    PR_LOG(modlog, 4, ("    %s = %s [%d]", 
	           atype, valstr, attr->ulValueLen));
	    break;
	}
    case CKA_CLASS:
	if (attr->ulValueLen > 0 && attr->pValue) {
	    CK_OBJECT_CLASS objClass = *((CK_OBJECT_CLASS *)attr->pValue);
	    get_obj_class(objClass, valstr, sizeof valstr);
	    PR_LOG(modlog, 4, ("    %s = %s [%d]", 
	           atype, valstr, attr->ulValueLen));
	    break;
	}
    case CKA_TRUST_SERVER_AUTH:
    case CKA_TRUST_CLIENT_AUTH:
    case CKA_TRUST_CODE_SIGNING:
    case CKA_TRUST_EMAIL_PROTECTION:
	if (attr->ulValueLen > 0 && attr->pValue) {
	    CK_TRUST trust = *((CK_TRUST *)attr->pValue);
	    get_trust_val(trust, valstr, sizeof valstr);
	    PR_LOG(modlog, 4, ("    %s = %s [%d]", 
	           atype, valstr, attr->ulValueLen));
	    break;
	}
    case CKA_LABEL:
    case CKA_NETSCAPE_EMAIL:
    case CKA_NETSCAPE_URL:
	if (attr->ulValueLen > 0 && attr->pValue) {
	    len = PR_MIN(attr->ulValueLen + 1, sizeof valstr);
	    PR_snprintf(valstr, len, "%s", attr->pValue);
	    PR_LOG(modlog, 4, ("    %s = %s [%d]", 
	           atype, valstr, attr->ulValueLen));
	    break;
	}
    default:
	PR_LOG(modlog, 4, ("    %s = 0x%p [%d]", 
	       atype, attr->pValue, attr->ulValueLen));
	break;
    }
}

static void print_template(CK_ATTRIBUTE_PTR templ, CK_ULONG tlen)
{
    CK_ULONG i;
    for (i=0; i<tlen; i++) {
	print_attr_value(&templ[i]);
    }
}

static void print_mechanism(CK_MECHANISM_PTR m)
{
    PR_LOG(modlog, 4, ("      mechanism = 0x%p", m->mechanism));
}

struct nssdbg_prof_str {
    PRUint32 time;
    PRUint32 calls;
    char *function;
};

#define NSSDBG_DEFINE(func) { 0, 0, #func }

struct nssdbg_prof_str nssdbg_prof_data[] = {
#define FUNC_C_INITIALIZE 0
    NSSDBG_DEFINE(C_Initialize),
#define FUNC_C_FINALIZE 1
    NSSDBG_DEFINE(C_Finalize),
#define FUNC_C_GETINFO 2
    NSSDBG_DEFINE(C_GetInfo),
#define FUNC_C_GETFUNCITONLIST 3
    NSSDBG_DEFINE(C_GetFunctionList),
#define FUNC_C_GETSLOTLIST 4
    NSSDBG_DEFINE(C_GetSlotList),
#define FUNC_C_GETSLOTINFO 5
    NSSDBG_DEFINE(C_GetSlotInfo),
#define FUNC_C_GETTOKENINFO 6
    NSSDBG_DEFINE(C_GetTokenInfo),
#define FUNC_C_GETMECHANISMLIST 7
    NSSDBG_DEFINE(C_GetMechanismList),
#define FUNC_C_GETMECHANISMINFO 8
    NSSDBG_DEFINE(C_GetMechanismInfo),
#define FUNC_C_INITTOKEN 9
    NSSDBG_DEFINE(C_InitToken),
#define FUNC_C_INITPIN 10
    NSSDBG_DEFINE(C_InitPIN),
#define FUNC_C_SETPIN 11
    NSSDBG_DEFINE(C_SetPIN),
#define FUNC_C_OPENSESSION 12
    NSSDBG_DEFINE(C_OpenSession),
#define FUNC_C_CLOSESESSION 13
    NSSDBG_DEFINE(C_CloseSession),
#define FUNC_C_CLOSEALLSESSIONS 14
    NSSDBG_DEFINE(C_CloseAllSessions),
#define FUNC_C_GETSESSIONINFO 15
    NSSDBG_DEFINE(C_GetSessionInfo),
#define FUNC_C_GETOPERATIONSTATE 16
    NSSDBG_DEFINE(C_GetOperationState),
#define FUNC_C_SETOPERATIONSTATE 17
    NSSDBG_DEFINE(C_SetOperationState),
#define FUNC_C_LOGIN 18
    NSSDBG_DEFINE(C_Login),
#define FUNC_C_LOGOUT 19
    NSSDBG_DEFINE(C_Logout),
#define FUNC_C_CREATEOBJECT 20
    NSSDBG_DEFINE(C_CreateObject),
#define FUNC_C_COPYOBJECT 21
    NSSDBG_DEFINE(C_CopyObject),
#define FUNC_C_DESTROYOBJECT 22
    NSSDBG_DEFINE(C_DestroyObject),
#define FUNC_C_GETOBJECTSIZE  23
    NSSDBG_DEFINE(C_GetObjectSize),
#define FUNC_C_GETATTRIBUTEVALUE 24
    NSSDBG_DEFINE(C_GetAttributeValue),
#define FUNC_C_SETATTRIBUTEVALUE 25
    NSSDBG_DEFINE(C_SetAttributeValue),
#define FUNC_C_FINDOBJECTSINIT 26
    NSSDBG_DEFINE(C_FindObjectsInit),
#define FUNC_C_FINDOBJECTS 27
    NSSDBG_DEFINE(C_FindObjects),
#define FUNC_C_FINDOBJECTSFINAL 28
    NSSDBG_DEFINE(C_FindObjectsFinal),
#define FUNC_C_ENCRYPTINIT 29
    NSSDBG_DEFINE(C_EncryptInit),
#define FUNC_C_ENCRYPT 30
    NSSDBG_DEFINE(C_Encrypt),
#define FUNC_C_ENCRYPTUPDATE 31
    NSSDBG_DEFINE(C_EncryptUpdate),
#define FUNC_C_ENCRYPTFINAL 32
    NSSDBG_DEFINE(C_EncryptFinal),
#define FUNC_C_DECRYPTINIT 33
    NSSDBG_DEFINE(C_DecryptInit),
#define FUNC_C_DECRYPT 34
    NSSDBG_DEFINE(C_Decrypt),
#define FUNC_C_DECRYPTUPDATE 35
    NSSDBG_DEFINE(C_DecryptUpdate),
#define FUNC_C_DECRYPTFINAL 36
    NSSDBG_DEFINE(C_DecryptFinal),
#define FUNC_C_DIGESTINIT 37
    NSSDBG_DEFINE(C_DigestInit),
#define FUNC_C_DIGEST 38
    NSSDBG_DEFINE(C_Digest),
#define FUNC_C_DIGESTUPDATE 39
    NSSDBG_DEFINE(C_DigestUpdate),
#define FUNC_C_DIGESTKEY 40
    NSSDBG_DEFINE(C_DigestKey),
#define FUNC_C_DIGESTFINAL 41
    NSSDBG_DEFINE(C_DigestFinal),
#define FUNC_C_SIGNINIT 42
    NSSDBG_DEFINE(C_SignInit),
#define FUNC_C_SIGN 43
    NSSDBG_DEFINE(C_Sign),
#define FUNC_C_SIGNUPDATE 44
    NSSDBG_DEFINE(C_SignUpdate),
#define FUNC_C_SIGNFINAL 45
    NSSDBG_DEFINE(C_SignFinal),
#define FUNC_C_SIGNRECOVERINIT 46
    NSSDBG_DEFINE(C_SignRecoverInit),
#define FUNC_C_SIGNRECOVER 47
    NSSDBG_DEFINE(C_SignRecover),
#define FUNC_C_VERIFYINIT 48
    NSSDBG_DEFINE(C_VerifyInit),
#define FUNC_C_VERIFY 49
    NSSDBG_DEFINE(C_Verify),
#define FUNC_C_VERIFYUPDATE 50
    NSSDBG_DEFINE(C_VerifyUpdate),
#define FUNC_C_VERIFYFINAL 51
    NSSDBG_DEFINE(C_VerifyFinal),
#define FUNC_C_VERIFYRECOVERINIT 52
    NSSDBG_DEFINE(C_VerifyRecoverInit),
#define FUNC_C_VERIFYRECOVER 53
    NSSDBG_DEFINE(C_VerifyRecover),
#define FUNC_C_DIGESTENCRYPTUPDATE 54
    NSSDBG_DEFINE(C_DigestEncryptUpdate),
#define FUNC_C_DECRYPTDIGESTUPDATE 55
    NSSDBG_DEFINE(C_DecryptDigestUpdate),
#define FUNC_C_SIGNENCRYPTUPDATE 56
    NSSDBG_DEFINE(C_SignEncryptUpdate),
#define FUNC_C_DECRYPTVERIFYUPDATE 57
    NSSDBG_DEFINE(C_DecryptVerifyUpdate),
#define FUNC_C_GENERATEKEY 58
    NSSDBG_DEFINE(C_GenerateKey),
#define FUNC_C_GENERATEKEYPAIR 59
    NSSDBG_DEFINE(C_GenerateKeyPair),
#define FUNC_C_WRAPKEY 60
    NSSDBG_DEFINE(C_WrapKey),
#define FUNC_C_UNWRAPKEY 61
    NSSDBG_DEFINE(C_UnWrapKey),
#define FUNC_C_DERIVEKEY 62 
    NSSDBG_DEFINE(C_DeriveKey),
#define FUNC_C_SEEDRANDOM 63
    NSSDBG_DEFINE(C_SeedRandom),
#define FUNC_C_GENERATERANDOM 64
    NSSDBG_DEFINE(C_GenerateRandom),
#define FUNC_C_GETFUNCTIONSTATUS 65
    NSSDBG_DEFINE(C_GetFunctionStatus),
#define FUNC_C_CANCELFUNCTION 66
    NSSDBG_DEFINE(C_CancelFunction),
#define FUNC_C_WAITFORSLOTEVENT 67
    NSSDBG_DEFINE(C_WaitForSlotEvent)
};

int nssdbg_prof_size = sizeof(nssdbg_prof_data)/sizeof(nssdbg_prof_data[0]);
    

static void nssdbg_finish_time(PRInt32 fun_number, PRIntervalTime start)
{
    PRIntervalTime ival;
    PRIntervalTime end = PR_IntervalNow();

    ival = end-start;
    /* sigh, lie to PRAtomic add and say we are using signed values */
    PR_AtomicAdd((PRInt32 *)&nssdbg_prof_data[fun_number].time, (PRInt32)ival);
}

static void nssdbg_start_time(PRInt32 fun_number, PRIntervalTime *start)
{
    PR_AtomicIncrement((PRInt32 *)&nssdbg_prof_data[fun_number].calls);
    *start = PR_IntervalNow();
}

#define COMMON_DEFINITIONS \
    CK_RV rv; \
    PRIntervalTime start

CK_RV NSSDBGC_Initialize(
  CK_VOID_PTR pInitArgs
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Initialize"));
    PR_LOG(modlog, 3, ("  pInitArgs = 0x%p", pInitArgs));
    nssdbg_start_time(FUNC_C_INITIALIZE,&start);
    rv = module_functions->C_Initialize(pInitArgs);
    nssdbg_finish_time(FUNC_C_INITIALIZE,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Finalize(
  CK_VOID_PTR pReserved
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Finalize"));
    PR_LOG(modlog, 3, ("  pReserved = 0x%p", pReserved));
    nssdbg_start_time(FUNC_C_FINALIZE,&start);
    rv = module_functions->C_Finalize(pReserved);
    nssdbg_finish_time(FUNC_C_FINALIZE,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetInfo(
  CK_INFO_PTR pInfo
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetInfo"));
    PR_LOG(modlog, 3, ("  pInfo = 0x%p", pInfo));
    nssdbg_start_time(FUNC_C_GETINFO,&start);
    rv = module_functions->C_GetInfo(pInfo);
    nssdbg_finish_time(FUNC_C_GETINFO,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetFunctionList(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetFunctionList"));
    PR_LOG(modlog, 3, ("  ppFunctionList = 0x%p", ppFunctionList));
    nssdbg_start_time(FUNC_C_GETFUNCITONLIST,&start);
    rv = module_functions->C_GetFunctionList(ppFunctionList);
    nssdbg_finish_time(FUNC_C_GETFUNCITONLIST,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetSlotList(
  CK_BBOOL       tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR   pulCount
)
{
    COMMON_DEFINITIONS;

    CK_ULONG i;
    PR_LOG(modlog, 1, ("C_GetSlotList"));
    PR_LOG(modlog, 3, ("  tokenPresent = 0x%x", tokenPresent));
    PR_LOG(modlog, 3, ("  pSlotList = 0x%p", pSlotList));
    PR_LOG(modlog, 3, ("  pulCount = 0x%p", pulCount));
    nssdbg_start_time(FUNC_C_GETSLOTLIST,&start);
    rv = module_functions->C_GetSlotList(tokenPresent,
                                 pSlotList,
                                 pulCount);
    nssdbg_finish_time(FUNC_C_GETSLOTLIST,start);
    PR_LOG(modlog, 4, ("  *pulCount = 0x%x", *pulCount));
    if (pSlotList) {
	for (i=0; i<*pulCount; i++) {
	    PR_LOG(modlog, 4, ("  slotID[%d] = %x", i, pSlotList[i]));
	}
    }
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetSlotInfo(
  CK_SLOT_ID       slotID,
  CK_SLOT_INFO_PTR pInfo
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetSlotInfo"));
    PR_LOG(modlog, 3, ("  slotID = 0x%x", slotID));
    PR_LOG(modlog, 3, ("  pInfo = 0x%p", pInfo));
    nssdbg_start_time(FUNC_C_GETSLOTINFO,&start);
    rv = module_functions->C_GetSlotInfo(slotID,
                                 pInfo);
    nssdbg_finish_time(FUNC_C_GETSLOTINFO,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetTokenInfo(
  CK_SLOT_ID        slotID,
  CK_TOKEN_INFO_PTR pInfo
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetTokenInfo"));
    PR_LOG(modlog, 3, ("  slotID = 0x%x", slotID));
    PR_LOG(modlog, 3, ("  pInfo = 0x%p", pInfo));
    nssdbg_start_time(FUNC_C_GETTOKENINFO,&start);
    rv = module_functions->C_GetTokenInfo(slotID,
                                 pInfo);
    nssdbg_finish_time(FUNC_C_GETTOKENINFO,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetMechanismList(
  CK_SLOT_ID            slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR          pulCount
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetMechanismList"));
    PR_LOG(modlog, 3, ("  slotID = 0x%x", slotID));
    PR_LOG(modlog, 3, ("  pMechanismList = 0x%p", pMechanismList));
    PR_LOG(modlog, 3, ("  pulCount = 0x%p", pulCount));
    nssdbg_start_time(FUNC_C_GETMECHANISMLIST,&start);
    rv = module_functions->C_GetMechanismList(slotID,
                                 pMechanismList,
                                 pulCount);
    nssdbg_finish_time(FUNC_C_GETMECHANISMLIST,start);
    PR_LOG(modlog, 4, ("  *pulCount = 0x%x", *pulCount));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetMechanismInfo(
  CK_SLOT_ID            slotID,
  CK_MECHANISM_TYPE     type,
  CK_MECHANISM_INFO_PTR pInfo
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetMechanismInfo"));
    PR_LOG(modlog, 3, ("  slotID = 0x%x", slotID));
    PR_LOG(modlog, 3, ("  type = 0x%x", type));
    PR_LOG(modlog, 3, ("  pInfo = 0x%p", pInfo));
    nssdbg_start_time(FUNC_C_GETMECHANISMINFO,&start);
    rv = module_functions->C_GetMechanismInfo(slotID,
                                 type,
                                 pInfo);
    nssdbg_finish_time(FUNC_C_GETMECHANISMINFO,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_InitToken(
  CK_SLOT_ID  slotID,
  CK_CHAR_PTR pPin,
  CK_ULONG    ulPinLen,
  CK_CHAR_PTR pLabel
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_InitToken"));
    PR_LOG(modlog, 3, ("  slotID = 0x%x", slotID));
    PR_LOG(modlog, 3, ("  pPin = 0x%p", pPin));
    PR_LOG(modlog, 3, ("  ulPinLen = %d", ulPinLen));
    PR_LOG(modlog, 3, ("  pLabel = 0x%p", pLabel));
    nssdbg_start_time(FUNC_C_INITTOKEN,&start);
    rv = module_functions->C_InitToken(slotID,
                                 pPin,
                                 ulPinLen,
                                 pLabel);
    nssdbg_finish_time(FUNC_C_INITTOKEN,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_InitPIN(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR       pPin,
  CK_ULONG          ulPinLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_InitPIN"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pPin = 0x%p", pPin));
    PR_LOG(modlog, 3, ("  ulPinLen = %d", ulPinLen));
    nssdbg_start_time(FUNC_C_INITPIN,&start);
    rv = module_functions->C_InitPIN(hSession,
                                 pPin,
                                 ulPinLen);
    nssdbg_finish_time(FUNC_C_INITPIN,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SetPIN(
  CK_SESSION_HANDLE hSession,
  CK_CHAR_PTR       pOldPin,
  CK_ULONG          ulOldLen,
  CK_CHAR_PTR       pNewPin,
  CK_ULONG          ulNewLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SetPIN"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pOldPin = 0x%p", pOldPin));
    PR_LOG(modlog, 3, ("  ulOldLen = %d", ulOldLen));
    PR_LOG(modlog, 3, ("  pNewPin = 0x%p", pNewPin));
    PR_LOG(modlog, 3, ("  ulNewLen = %d", ulNewLen));
    nssdbg_start_time(FUNC_C_SETPIN,&start);
    rv = module_functions->C_SetPIN(hSession,
                                 pOldPin,
                                 ulOldLen,
                                 pNewPin,
                                 ulNewLen);
    nssdbg_finish_time(FUNC_C_SETPIN,start);
    log_rv(rv);
    return rv;
}

static PRUint32 numOpenSessions = 0;
static PRUint32 maxOpenSessions = 0;
CK_RV NSSDBGC_OpenSession(
  CK_SLOT_ID            slotID,
  CK_FLAGS              flags,
  CK_VOID_PTR           pApplication,
  CK_NOTIFY             Notify,
  CK_SESSION_HANDLE_PTR phSession
)
{
    COMMON_DEFINITIONS;

    PR_AtomicIncrement((PRInt32 *)&numOpenSessions);
    maxOpenSessions = PR_MAX(numOpenSessions, maxOpenSessions);
    PR_LOG(modlog, 1, ("C_OpenSession"));
    PR_LOG(modlog, 3, ("  slotID = 0x%x", slotID));
    PR_LOG(modlog, 3, ("  flags = 0x%x", flags));
    PR_LOG(modlog, 3, ("  pApplication = 0x%p", pApplication));
    PR_LOG(modlog, 3, ("  Notify = 0x%x", Notify));
    PR_LOG(modlog, 3, ("  phSession = 0x%p", phSession));
    nssdbg_start_time(FUNC_C_OPENSESSION,&start);
    rv = module_functions->C_OpenSession(slotID,
                                 flags,
                                 pApplication,
                                 Notify,
                                 phSession);
    nssdbg_finish_time(FUNC_C_OPENSESSION,start);
    PR_LOG(modlog, 4, ("  *phSession = 0x%x", *phSession));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_CloseSession(
  CK_SESSION_HANDLE hSession
)
{
    COMMON_DEFINITIONS;

    PR_AtomicDecrement((PRInt32 *)&numOpenSessions);
    PR_LOG(modlog, 1, ("C_CloseSession"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    nssdbg_start_time(FUNC_C_CLOSESESSION,&start);
    rv = module_functions->C_CloseSession(hSession);
    nssdbg_finish_time(FUNC_C_CLOSESESSION,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_CloseAllSessions(
  CK_SLOT_ID slotID
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_CloseAllSessions"));
    PR_LOG(modlog, 3, ("  slotID = 0x%x", slotID));
    nssdbg_start_time(FUNC_C_CLOSEALLSESSIONS,&start);
    rv = module_functions->C_CloseAllSessions(slotID);
    nssdbg_finish_time(FUNC_C_CLOSEALLSESSIONS,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetSessionInfo(
  CK_SESSION_HANDLE   hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetSessionInfo"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pInfo = 0x%p", pInfo));
    nssdbg_start_time(FUNC_C_GETSESSIONINFO,&start);
    rv = module_functions->C_GetSessionInfo(hSession,
                                 pInfo);
    nssdbg_finish_time(FUNC_C_GETSESSIONINFO,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetOperationState(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pOperationState,
  CK_ULONG_PTR      pulOperationStateLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetOperationState"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pOperationState = 0x%p", pOperationState));
    PR_LOG(modlog, 3, ("  pulOperationStateLen = 0x%p", pulOperationStateLen));
    nssdbg_start_time(FUNC_C_GETOPERATIONSTATE,&start);
    rv = module_functions->C_GetOperationState(hSession,
                                 pOperationState,
                                 pulOperationStateLen);
    nssdbg_finish_time(FUNC_C_GETOPERATIONSTATE,start);
    PR_LOG(modlog, 4, ("  *pulOperationStateLen = 0x%x", *pulOperationStateLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SetOperationState(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR      pOperationState,
  CK_ULONG         ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SetOperationState"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pOperationState = 0x%p", pOperationState));
    PR_LOG(modlog, 3, ("  ulOperationStateLen = %d", ulOperationStateLen));
    PR_LOG(modlog, 3, ("  hEncryptionKey = 0x%x", hEncryptionKey));
    PR_LOG(modlog, 3, ("  hAuthenticationKey = 0x%x", hAuthenticationKey));
    nssdbg_start_time(FUNC_C_SETOPERATIONSTATE,&start);
    rv = module_functions->C_SetOperationState(hSession,
                                 pOperationState,
                                 ulOperationStateLen,
                                 hEncryptionKey,
                                 hAuthenticationKey);
    nssdbg_finish_time(FUNC_C_SETOPERATIONSTATE,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Login(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE      userType,
  CK_CHAR_PTR       pPin,
  CK_ULONG          ulPinLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Login"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  userType = 0x%x", userType));
    PR_LOG(modlog, 3, ("  pPin = 0x%p", pPin));
    PR_LOG(modlog, 3, ("  ulPinLen = %d", ulPinLen));
    nssdbg_start_time(FUNC_C_LOGIN,&start);
    rv = module_functions->C_Login(hSession,
                                 userType,
                                 pPin,
                                 ulPinLen);
    nssdbg_finish_time(FUNC_C_LOGIN,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Logout(
  CK_SESSION_HANDLE hSession
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Logout"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    nssdbg_start_time(FUNC_C_LOGOUT,&start);
    rv = module_functions->C_Logout(hSession);
    nssdbg_finish_time(FUNC_C_LOGOUT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_CreateObject(
  CK_SESSION_HANDLE    hSession,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phObject
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_CreateObject"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulCount = %d", ulCount));
    PR_LOG(modlog, 3, ("  phObject = 0x%p", phObject));
    print_template(pTemplate, ulCount);
    nssdbg_start_time(FUNC_C_CREATEOBJECT,&start);
    rv = module_functions->C_CreateObject(hSession,
                                 pTemplate,
                                 ulCount,
                                 phObject);
    nssdbg_finish_time(FUNC_C_CREATEOBJECT,start);
    PR_LOG(modlog, 4, ("  *phObject = 0x%x", *phObject));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_CopyObject(
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE     hObject,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_CopyObject"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  hObject = 0x%x", hObject));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulCount = %d", ulCount));
    PR_LOG(modlog, 3, ("  phNewObject = 0x%p", phNewObject));
    print_template(pTemplate, ulCount);
    nssdbg_start_time(FUNC_C_COPYOBJECT,&start);
    rv = module_functions->C_CopyObject(hSession,
                                 hObject,
                                 pTemplate,
                                 ulCount,
                                 phNewObject);
    nssdbg_finish_time(FUNC_C_COPYOBJECT,start);
    PR_LOG(modlog, 4, ("  *phNewObject = 0x%x", *phNewObject));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DestroyObject(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DestroyObject"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  hObject = 0x%x", hObject));
    nssdbg_start_time(FUNC_C_DESTROYOBJECT,&start);
    rv = module_functions->C_DestroyObject(hSession,
                                 hObject);
    nssdbg_finish_time(FUNC_C_DESTROYOBJECT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetObjectSize(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ULONG_PTR      pulSize
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetObjectSize"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  hObject = 0x%x", hObject));
    PR_LOG(modlog, 3, ("  pulSize = 0x%p", pulSize));
    nssdbg_start_time(FUNC_C_GETOBJECTSIZE,&start);
    rv = module_functions->C_GetObjectSize(hSession,
                                 hObject,
                                 pulSize);
    nssdbg_finish_time(FUNC_C_GETOBJECTSIZE,start);
    PR_LOG(modlog, 4, ("  *pulSize = 0x%x", *pulSize));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetAttributeValue(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetAttributeValue"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  hObject = 0x%x", hObject));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulCount = %d", ulCount));
    nssdbg_start_time(FUNC_C_GETATTRIBUTEVALUE,&start);
    rv = module_functions->C_GetAttributeValue(hSession,
                                 hObject,
                                 pTemplate,
                                 ulCount);
    nssdbg_finish_time(FUNC_C_GETATTRIBUTEVALUE,start);
    print_template(pTemplate, ulCount);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SetAttributeValue(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SetAttributeValue"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  hObject = 0x%x", hObject));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulCount = %d", ulCount));
    print_template(pTemplate, ulCount);
    nssdbg_start_time(FUNC_C_SETATTRIBUTEVALUE,&start);
    rv = module_functions->C_SetAttributeValue(hSession,
                                 hObject,
                                 pTemplate,
                                 ulCount);
    nssdbg_finish_time(FUNC_C_SETATTRIBUTEVALUE,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_FindObjectsInit(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_FindObjectsInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulCount = %d", ulCount));
    print_template(pTemplate, ulCount);
    nssdbg_start_time(FUNC_C_FINDOBJECTSINIT,&start);
    rv = module_functions->C_FindObjectsInit(hSession,
                                 pTemplate,
                                 ulCount);
    nssdbg_finish_time(FUNC_C_FINDOBJECTSINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_FindObjects(
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG             ulMaxObjectCount,
  CK_ULONG_PTR         pulObjectCount
)
{
    COMMON_DEFINITIONS;
    CK_ULONG i;

    PR_LOG(modlog, 1, ("C_FindObjects"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  phObject = 0x%p", phObject));
    PR_LOG(modlog, 3, ("  ulMaxObjectCount = %d", ulMaxObjectCount));
    PR_LOG(modlog, 3, ("  pulObjectCount = 0x%p", pulObjectCount));
    nssdbg_start_time(FUNC_C_FINDOBJECTS,&start);
    rv = module_functions->C_FindObjects(hSession,
                                 phObject,
                                 ulMaxObjectCount,
                                 pulObjectCount);
    nssdbg_finish_time(FUNC_C_FINDOBJECTS,start);
    PR_LOG(modlog, 4, ("  *pulObjectCount = 0x%x", *pulObjectCount));
    for (i=0; i<*pulObjectCount; i++) {
	PR_LOG(modlog, 4, ("  phObject[%d] = 0x%x", i, phObject[i]));
    }
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_FindObjectsFinal(
  CK_SESSION_HANDLE hSession
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_FindObjectsFinal"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    nssdbg_start_time(FUNC_C_FINDOBJECTSFINAL,&start);
    rv = module_functions->C_FindObjectsFinal(hSession);
    nssdbg_finish_time(FUNC_C_FINDOBJECTSFINAL,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_EncryptInit(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_EncryptInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hKey = 0x%x", hKey));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_ENCRYPTINIT,&start);
    rv = module_functions->C_EncryptInit(hSession,
                                 pMechanism,
                                 hKey);
    nssdbg_finish_time(FUNC_C_ENCRYPTINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Encrypt(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pEncryptedData,
  CK_ULONG_PTR      pulEncryptedDataLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Encrypt"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pData = 0x%p", pData));
    PR_LOG(modlog, 3, ("  ulDataLen = %d", ulDataLen));
    PR_LOG(modlog, 3, ("  pEncryptedData = 0x%p", pEncryptedData));
    PR_LOG(modlog, 3, ("  pulEncryptedDataLen = 0x%p", pulEncryptedDataLen));
    nssdbg_start_time(FUNC_C_ENCRYPT,&start);
    rv = module_functions->C_Encrypt(hSession,
                                 pData,
                                 ulDataLen,
                                 pEncryptedData,
                                 pulEncryptedDataLen);
    nssdbg_finish_time(FUNC_C_ENCRYPT,start);
    PR_LOG(modlog, 4, ("  *pulEncryptedDataLen = 0x%x", *pulEncryptedDataLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_EncryptUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_EncryptUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  ulPartLen = %d", ulPartLen));
    PR_LOG(modlog, 3, ("  pEncryptedPart = 0x%p", pEncryptedPart));
    PR_LOG(modlog, 3, ("  pulEncryptedPartLen = 0x%p", pulEncryptedPartLen));
    nssdbg_start_time(FUNC_C_ENCRYPTUPDATE,&start);
    rv = module_functions->C_EncryptUpdate(hSession,
                                 pPart,
                                 ulPartLen,
                                 pEncryptedPart,
                                 pulEncryptedPartLen);
    nssdbg_finish_time(FUNC_C_ENCRYPTUPDATE,start);
    PR_LOG(modlog, 4, ("  *pulEncryptedPartLen = 0x%x", *pulEncryptedPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_EncryptFinal(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pLastEncryptedPart,
  CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_EncryptFinal"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pLastEncryptedPart = 0x%p", pLastEncryptedPart));
    PR_LOG(modlog, 3, ("  pulLastEncryptedPartLen = 0x%p", pulLastEncryptedPartLen));
    nssdbg_start_time(FUNC_C_ENCRYPTFINAL,&start);
    rv = module_functions->C_EncryptFinal(hSession,
                                 pLastEncryptedPart,
                                 pulLastEncryptedPartLen);
    nssdbg_finish_time(FUNC_C_ENCRYPTFINAL,start);
    PR_LOG(modlog, 4, ("  *pulLastEncryptedPartLen = 0x%x", *pulLastEncryptedPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DecryptInit(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DecryptInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hKey = 0x%x", hKey));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_DECRYPTINIT,&start);
    rv = module_functions->C_DecryptInit(hSession,
                                 pMechanism,
                                 hKey);
    nssdbg_finish_time(FUNC_C_DECRYPTINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Decrypt(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedData,
  CK_ULONG          ulEncryptedDataLen,
  CK_BYTE_PTR       pData,
  CK_ULONG_PTR      pulDataLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Decrypt"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pEncryptedData = 0x%p", pEncryptedData));
    PR_LOG(modlog, 3, ("  ulEncryptedDataLen = %d", ulEncryptedDataLen));
    PR_LOG(modlog, 3, ("  pData = 0x%p", pData));
    PR_LOG(modlog, 3, ("  pulDataLen = 0x%p", pulDataLen));
    nssdbg_start_time(FUNC_C_DECRYPT,&start);
    rv = module_functions->C_Decrypt(hSession,
                                 pEncryptedData,
                                 ulEncryptedDataLen,
                                 pData,
                                 pulDataLen);
    nssdbg_finish_time(FUNC_C_DECRYPT,start);
    PR_LOG(modlog, 4, ("  *pulDataLen = 0x%x", *pulDataLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DecryptUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DecryptUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pEncryptedPart = 0x%p", pEncryptedPart));
    PR_LOG(modlog, 3, ("  ulEncryptedPartLen = %d", ulEncryptedPartLen));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  pulPartLen = 0x%p", pulPartLen));
    nssdbg_start_time(FUNC_C_DECRYPTUPDATE,&start);
    rv = module_functions->C_DecryptUpdate(hSession,
                                 pEncryptedPart,
                                 ulEncryptedPartLen,
                                 pPart,
                                 pulPartLen);
    nssdbg_finish_time(FUNC_C_DECRYPTUPDATE,start);
    PR_LOG(modlog, 4, ("  *pulPartLen = 0x%x", *pulPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DecryptFinal(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pLastPart,
  CK_ULONG_PTR      pulLastPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DecryptFinal"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pLastPart = 0x%p", pLastPart));
    PR_LOG(modlog, 3, ("  pulLastPartLen = 0x%p", pulLastPartLen));
    nssdbg_start_time(FUNC_C_DECRYPTFINAL,&start);
    rv = module_functions->C_DecryptFinal(hSession,
                                 pLastPart,
                                 pulLastPartLen);
    nssdbg_finish_time(FUNC_C_DECRYPTFINAL,start);
    PR_LOG(modlog, 4, ("  *pulLastPartLen = 0x%x", *pulLastPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DigestInit(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DigestInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_DIGESTINIT,&start);
    rv = module_functions->C_DigestInit(hSession,
                                 pMechanism);
    nssdbg_finish_time(FUNC_C_DIGESTINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Digest(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pDigest,
  CK_ULONG_PTR      pulDigestLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Digest"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pData = 0x%p", pData));
    PR_LOG(modlog, 3, ("  ulDataLen = %d", ulDataLen));
    PR_LOG(modlog, 3, ("  pDigest = 0x%p", pDigest));
    PR_LOG(modlog, 3, ("  pulDigestLen = 0x%p", pulDigestLen));
    nssdbg_start_time(FUNC_C_DIGEST,&start);
    rv = module_functions->C_Digest(hSession,
                                 pData,
                                 ulDataLen,
                                 pDigest,
                                 pulDigestLen);
    nssdbg_finish_time(FUNC_C_DIGEST,start);
    PR_LOG(modlog, 4, ("  *pulDigestLen = 0x%x", *pulDigestLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DigestUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DigestUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  ulPartLen = %d", ulPartLen));
    nssdbg_start_time(FUNC_C_DIGESTUPDATE,&start);
    rv = module_functions->C_DigestUpdate(hSession,
                                 pPart,
                                 ulPartLen);
    nssdbg_finish_time(FUNC_C_DIGESTUPDATE,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DigestKey(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DigestKey"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    nssdbg_start_time(FUNC_C_DIGESTKEY,&start);
    rv = module_functions->C_DigestKey(hSession,
                                 hKey);
    nssdbg_finish_time(FUNC_C_DIGESTKEY,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DigestFinal(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pDigest,
  CK_ULONG_PTR      pulDigestLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DigestFinal"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pDigest = 0x%p", pDigest));
    PR_LOG(modlog, 3, ("  pulDigestLen = 0x%p", pulDigestLen));
    nssdbg_start_time(FUNC_C_DIGESTFINAL,&start);
    rv = module_functions->C_DigestFinal(hSession,
                                 pDigest,
                                 pulDigestLen);
    nssdbg_finish_time(FUNC_C_DIGESTFINAL,start);
    PR_LOG(modlog, 4, ("  *pulDigestLen = 0x%x", *pulDigestLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SignInit(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SignInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hKey = 0x%x", hKey));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_SIGNINIT,&start);
    rv = module_functions->C_SignInit(hSession,
                                 pMechanism,
                                 hKey);
    nssdbg_finish_time(FUNC_C_SIGNINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Sign(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Sign"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pData = 0x%p", pData));
    PR_LOG(modlog, 3, ("  ulDataLen = %d", ulDataLen));
    PR_LOG(modlog, 3, ("  pSignature = 0x%p", pSignature));
    PR_LOG(modlog, 3, ("  pulSignatureLen = 0x%p", pulSignatureLen));
    nssdbg_start_time(FUNC_C_SIGN,&start);
    rv = module_functions->C_Sign(hSession,
                                 pData,
                                 ulDataLen,
                                 pSignature,
                                 pulSignatureLen);
    nssdbg_finish_time(FUNC_C_SIGN,start);
    PR_LOG(modlog, 4, ("  *pulSignatureLen = 0x%x", *pulSignatureLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SignUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SignUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  ulPartLen = %d", ulPartLen));
    nssdbg_start_time(FUNC_C_SIGNUPDATE,&start);
    rv = module_functions->C_SignUpdate(hSession,
                                 pPart,
                                 ulPartLen);
    nssdbg_finish_time(FUNC_C_SIGNUPDATE,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SignFinal(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SignFinal"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pSignature = 0x%p", pSignature));
    PR_LOG(modlog, 3, ("  pulSignatureLen = 0x%p", pulSignatureLen));
    nssdbg_start_time(FUNC_C_SIGNFINAL,&start);
    rv = module_functions->C_SignFinal(hSession,
                                 pSignature,
                                 pulSignatureLen);
    nssdbg_finish_time(FUNC_C_SIGNFINAL,start);
    PR_LOG(modlog, 4, ("  *pulSignatureLen = 0x%x", *pulSignatureLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SignRecoverInit(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SignRecoverInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hKey = 0x%x", hKey));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_SIGNRECOVERINIT,&start);
    rv = module_functions->C_SignRecoverInit(hSession,
                                 pMechanism,
                                 hKey);
    nssdbg_finish_time(FUNC_C_SIGNRECOVERINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SignRecover(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SignRecover"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pData = 0x%p", pData));
    PR_LOG(modlog, 3, ("  ulDataLen = %d", ulDataLen));
    PR_LOG(modlog, 3, ("  pSignature = 0x%p", pSignature));
    PR_LOG(modlog, 3, ("  pulSignatureLen = 0x%p", pulSignatureLen));
    nssdbg_start_time(FUNC_C_SIGNRECOVER,&start);
    rv = module_functions->C_SignRecover(hSession,
                                 pData,
                                 ulDataLen,
                                 pSignature,
                                 pulSignatureLen);
    nssdbg_finish_time(FUNC_C_SIGNRECOVER,start);
    PR_LOG(modlog, 4, ("  *pulSignatureLen = 0x%x", *pulSignatureLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_VerifyInit(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_VerifyInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hKey = 0x%x", hKey));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_VERIFYINIT,&start);
    rv = module_functions->C_VerifyInit(hSession,
                                 pMechanism,
                                 hKey);
    nssdbg_finish_time(FUNC_C_VERIFYINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_Verify(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_Verify"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pData = 0x%p", pData));
    PR_LOG(modlog, 3, ("  ulDataLen = %d", ulDataLen));
    PR_LOG(modlog, 3, ("  pSignature = 0x%p", pSignature));
    PR_LOG(modlog, 3, ("  ulSignatureLen = %d", ulSignatureLen));
    nssdbg_start_time(FUNC_C_VERIFY,&start);
    rv = module_functions->C_Verify(hSession,
                                 pData,
                                 ulDataLen,
                                 pSignature,
                                 ulSignatureLen);
    nssdbg_finish_time(FUNC_C_VERIFY,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_VerifyUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_VerifyUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  ulPartLen = %d", ulPartLen));
    nssdbg_start_time(FUNC_C_VERIFYUPDATE,&start);
    rv = module_functions->C_VerifyUpdate(hSession,
                                 pPart,
                                 ulPartLen);
    nssdbg_finish_time(FUNC_C_VERIFYUPDATE,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_VerifyFinal(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_VerifyFinal"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pSignature = 0x%p", pSignature));
    PR_LOG(modlog, 3, ("  ulSignatureLen = %d", ulSignatureLen));
    nssdbg_start_time(FUNC_C_VERIFYFINAL,&start);
    rv = module_functions->C_VerifyFinal(hSession,
                                 pSignature,
                                 ulSignatureLen);
    nssdbg_finish_time(FUNC_C_VERIFYFINAL,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_VerifyRecoverInit"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hKey = 0x%x", hKey));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_VERIFYRECOVERINIT,&start);
    rv = module_functions->C_VerifyRecoverInit(hSession,
                                 pMechanism,
                                 hKey);
    nssdbg_finish_time(FUNC_C_VERIFYRECOVERINIT,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_VerifyRecover(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen,
  CK_BYTE_PTR       pData,
  CK_ULONG_PTR      pulDataLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_VerifyRecover"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pSignature = 0x%p", pSignature));
    PR_LOG(modlog, 3, ("  ulSignatureLen = %d", ulSignatureLen));
    PR_LOG(modlog, 3, ("  pData = 0x%p", pData));
    PR_LOG(modlog, 3, ("  pulDataLen = 0x%p", pulDataLen));
    nssdbg_start_time(FUNC_C_VERIFYRECOVER,&start);
    rv = module_functions->C_VerifyRecover(hSession,
                                 pSignature,
                                 ulSignatureLen,
                                 pData,
                                 pulDataLen);
    nssdbg_finish_time(FUNC_C_VERIFYRECOVER,start);
    PR_LOG(modlog, 4, ("  *pulDataLen = 0x%x", *pulDataLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DigestEncryptUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  ulPartLen = %d", ulPartLen));
    PR_LOG(modlog, 3, ("  pEncryptedPart = 0x%p", pEncryptedPart));
    PR_LOG(modlog, 3, ("  pulEncryptedPartLen = 0x%p", pulEncryptedPartLen));
    nssdbg_start_time(FUNC_C_DIGESTENCRYPTUPDATE,&start);
    rv = module_functions->C_DigestEncryptUpdate(hSession,
                                 pPart,
                                 ulPartLen,
                                 pEncryptedPart,
                                 pulEncryptedPartLen);
    nssdbg_finish_time(FUNC_C_DIGESTENCRYPTUPDATE,start);
    PR_LOG(modlog, 4, ("  *pulEncryptedPartLen = 0x%x", *pulEncryptedPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DecryptDigestUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pEncryptedPart = 0x%p", pEncryptedPart));
    PR_LOG(modlog, 3, ("  ulEncryptedPartLen = %d", ulEncryptedPartLen));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  pulPartLen = 0x%p", pulPartLen));
    nssdbg_start_time(FUNC_C_DECRYPTDIGESTUPDATE,&start);
    rv = module_functions->C_DecryptDigestUpdate(hSession,
                                 pEncryptedPart,
                                 ulEncryptedPartLen,
                                 pPart,
                                 pulPartLen);
    nssdbg_finish_time(FUNC_C_DECRYPTDIGESTUPDATE,start);
    PR_LOG(modlog, 4, ("  *pulPartLen = 0x%x", *pulPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SignEncryptUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  ulPartLen = %d", ulPartLen));
    PR_LOG(modlog, 3, ("  pEncryptedPart = 0x%p", pEncryptedPart));
    PR_LOG(modlog, 3, ("  pulEncryptedPartLen = 0x%p", pulEncryptedPartLen));
    nssdbg_start_time(FUNC_C_SIGNENCRYPTUPDATE,&start);
    rv = module_functions->C_SignEncryptUpdate(hSession,
                                 pPart,
                                 ulPartLen,
                                 pEncryptedPart,
                                 pulEncryptedPartLen);
    nssdbg_finish_time(FUNC_C_SIGNENCRYPTUPDATE,start);
    PR_LOG(modlog, 4, ("  *pulEncryptedPartLen = 0x%x", *pulEncryptedPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DecryptVerifyUpdate"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pEncryptedPart = 0x%p", pEncryptedPart));
    PR_LOG(modlog, 3, ("  ulEncryptedPartLen = %d", ulEncryptedPartLen));
    PR_LOG(modlog, 3, ("  pPart = 0x%p", pPart));
    PR_LOG(modlog, 3, ("  pulPartLen = 0x%p", pulPartLen));
    nssdbg_start_time(FUNC_C_DECRYPTVERIFYUPDATE,&start);
    rv = module_functions->C_DecryptVerifyUpdate(hSession,
                                 pEncryptedPart,
                                 ulEncryptedPartLen,
                                 pPart,
                                 pulPartLen);
    nssdbg_finish_time(FUNC_C_DECRYPTVERIFYUPDATE,start);
    PR_LOG(modlog, 4, ("  *pulPartLen = 0x%x", *pulPartLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GenerateKey(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GenerateKey"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulCount = %d", ulCount));
    PR_LOG(modlog, 3, ("  phKey = 0x%p", phKey));
    print_template(pTemplate, ulCount);
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_GENERATEKEY,&start);
    rv = module_functions->C_GenerateKey(hSession,
                                 pMechanism,
                                 pTemplate,
                                 ulCount,
                                 phKey);
    nssdbg_finish_time(FUNC_C_GENERATEKEY,start);
    PR_LOG(modlog, 4, ("  *phKey = 0x%x", *phKey));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GenerateKeyPair(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
  CK_ULONG             ulPublicKeyAttributeCount,
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
  CK_ULONG             ulPrivateKeyAttributeCount,
  CK_OBJECT_HANDLE_PTR phPublicKey,
  CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GenerateKeyPair"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  pPublicKeyTemplate = 0x%p", pPublicKeyTemplate));
    PR_LOG(modlog, 3, ("  ulPublicKeyAttributeCount = %d", ulPublicKeyAttributeCount));
    PR_LOG(modlog, 3, ("  pPrivateKeyTemplate = 0x%p", pPrivateKeyTemplate));
    PR_LOG(modlog, 3, ("  ulPrivateKeyAttributeCount = %d", ulPrivateKeyAttributeCount));
    PR_LOG(modlog, 3, ("  phPublicKey = 0x%p", phPublicKey));
    PR_LOG(modlog, 3, ("  phPrivateKey = 0x%p", phPrivateKey));
    print_template(pPublicKeyTemplate, ulPublicKeyAttributeCount);
    print_template(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_GENERATEKEYPAIR,&start);
    rv = module_functions->C_GenerateKeyPair(hSession,
                                 pMechanism,
                                 pPublicKeyTemplate,
                                 ulPublicKeyAttributeCount,
                                 pPrivateKeyTemplate,
                                 ulPrivateKeyAttributeCount,
                                 phPublicKey,
                                 phPrivateKey);
    nssdbg_finish_time(FUNC_C_GENERATEKEYPAIR,start);
    PR_LOG(modlog, 4, ("  *phPublicKey = 0x%x", *phPublicKey));
    PR_LOG(modlog, 4, ("  *phPrivateKey = 0x%x", *phPrivateKey));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_WrapKey(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hWrappingKey,
  CK_OBJECT_HANDLE  hKey,
  CK_BYTE_PTR       pWrappedKey,
  CK_ULONG_PTR      pulWrappedKeyLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_WrapKey"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hWrappingKey = 0x%x", hWrappingKey));
    PR_LOG(modlog, 3, ("  hKey = 0x%x", hKey));
    PR_LOG(modlog, 3, ("  pWrappedKey = 0x%p", pWrappedKey));
    PR_LOG(modlog, 3, ("  pulWrappedKeyLen = 0x%p", pulWrappedKeyLen));
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_WRAPKEY,&start);
    rv = module_functions->C_WrapKey(hSession,
                                 pMechanism,
                                 hWrappingKey,
                                 hKey,
                                 pWrappedKey,
                                 pulWrappedKeyLen);
    nssdbg_finish_time(FUNC_C_WRAPKEY,start);
    PR_LOG(modlog, 4, ("  *pulWrappedKeyLen = 0x%x", *pulWrappedKeyLen));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_UnwrapKey(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_OBJECT_HANDLE     hUnwrappingKey,
  CK_BYTE_PTR          pWrappedKey,
  CK_ULONG             ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_UnwrapKey"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hUnwrappingKey = 0x%x", hUnwrappingKey));
    PR_LOG(modlog, 3, ("  pWrappedKey = 0x%p", pWrappedKey));
    PR_LOG(modlog, 3, ("  ulWrappedKeyLen = %d", ulWrappedKeyLen));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulAttributeCount = %d", ulAttributeCount));
    PR_LOG(modlog, 3, ("  phKey = 0x%p", phKey));
    print_template(pTemplate, ulAttributeCount);
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_UNWRAPKEY,&start);
    rv = module_functions->C_UnwrapKey(hSession,
                                 pMechanism,
                                 hUnwrappingKey,
                                 pWrappedKey,
                                 ulWrappedKeyLen,
                                 pTemplate,
                                 ulAttributeCount,
                                 phKey);
    nssdbg_finish_time(FUNC_C_UNWRAPKEY,start);
    PR_LOG(modlog, 4, ("  *phKey = 0x%x", *phKey));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_DeriveKey(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_OBJECT_HANDLE     hBaseKey,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_DeriveKey"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pMechanism = 0x%p", pMechanism));
    PR_LOG(modlog, 3, ("  hBaseKey = 0x%x", hBaseKey));
    PR_LOG(modlog, 3, ("  pTemplate = 0x%p", pTemplate));
    PR_LOG(modlog, 3, ("  ulAttributeCount = %d", ulAttributeCount));
    PR_LOG(modlog, 3, ("  phKey = 0x%p", phKey));
    print_template(pTemplate, ulAttributeCount);
    print_mechanism(pMechanism);
    nssdbg_start_time(FUNC_C_DERIVEKEY,&start);
    rv = module_functions->C_DeriveKey(hSession,
                                 pMechanism,
                                 hBaseKey,
                                 pTemplate,
                                 ulAttributeCount,
                                 phKey);
    nssdbg_finish_time(FUNC_C_DERIVEKEY,start);
    PR_LOG(modlog, 4, ("  *phKey = 0x%x", *phKey));
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_SeedRandom(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSeed,
  CK_ULONG          ulSeedLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_SeedRandom"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  pSeed = 0x%p", pSeed));
    PR_LOG(modlog, 3, ("  ulSeedLen = %d", ulSeedLen));
    nssdbg_start_time(FUNC_C_SEEDRANDOM,&start);
    rv = module_functions->C_SeedRandom(hSession,
                                 pSeed,
                                 ulSeedLen);
    nssdbg_finish_time(FUNC_C_SEEDRANDOM,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GenerateRandom(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       RandomData,
  CK_ULONG          ulRandomLen
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GenerateRandom"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    PR_LOG(modlog, 3, ("  RandomData = 0x%p", RandomData));
    PR_LOG(modlog, 3, ("  ulRandomLen = %d", ulRandomLen));
    nssdbg_start_time(FUNC_C_GENERATERANDOM,&start);
    rv = module_functions->C_GenerateRandom(hSession,
                                 RandomData,
                                 ulRandomLen);
    nssdbg_finish_time(FUNC_C_GENERATERANDOM,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_GetFunctionStatus(
  CK_SESSION_HANDLE hSession
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_GetFunctionStatus"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    nssdbg_start_time(FUNC_C_GETFUNCTIONSTATUS,&start);
    rv = module_functions->C_GetFunctionStatus(hSession);
    nssdbg_finish_time(FUNC_C_GETFUNCTIONSTATUS,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_CancelFunction(
  CK_SESSION_HANDLE hSession
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_CancelFunction"));
    PR_LOG(modlog, 3, ("  hSession = 0x%x", hSession));
    nssdbg_start_time(FUNC_C_CANCELFUNCTION,&start);
    rv = module_functions->C_CancelFunction(hSession);
    nssdbg_finish_time(FUNC_C_CANCELFUNCTION,start);
    log_rv(rv);
    return rv;
}

CK_RV NSSDBGC_WaitForSlotEvent(
  CK_FLAGS       flags,
  CK_SLOT_ID_PTR pSlot,
  CK_VOID_PTR    pRserved
)
{
    COMMON_DEFINITIONS;

    PR_LOG(modlog, 1, ("C_WaitForSlotEvent"));
    PR_LOG(modlog, 3, ("  flags = 0x%x", flags));
    PR_LOG(modlog, 3, ("  pSlot = 0x%p", pSlot));
    PR_LOG(modlog, 3, ("  pRserved = 0x%p", pRserved));
    nssdbg_start_time(FUNC_C_WAITFORSLOTEVENT,&start);
    rv = module_functions->C_WaitForSlotEvent(flags,
                                 pSlot,
                                 pRserved);
    nssdbg_finish_time(FUNC_C_WAITFORSLOTEVENT,start);
    log_rv(rv);
    return rv;
}

CK_FUNCTION_LIST_PTR nss_InsertDeviceLog(
  CK_FUNCTION_LIST_PTR devEPV
)
{
    module_functions = devEPV;
    modlog = PR_NewLogModule("nss_mod_log");
    debug_functions.C_Initialize = NSSDBGC_Initialize;
    debug_functions.C_Finalize = NSSDBGC_Finalize;
    debug_functions.C_GetInfo = NSSDBGC_GetInfo;
    debug_functions.C_GetFunctionList = NSSDBGC_GetFunctionList;
    debug_functions.C_GetSlotList = NSSDBGC_GetSlotList;
    debug_functions.C_GetSlotInfo = NSSDBGC_GetSlotInfo;
    debug_functions.C_GetTokenInfo = NSSDBGC_GetTokenInfo;
    debug_functions.C_GetMechanismList = NSSDBGC_GetMechanismList;
    debug_functions.C_GetMechanismInfo = NSSDBGC_GetMechanismInfo;
    debug_functions.C_InitToken = NSSDBGC_InitToken;
    debug_functions.C_InitPIN = NSSDBGC_InitPIN;
    debug_functions.C_SetPIN = NSSDBGC_SetPIN;
    debug_functions.C_OpenSession = NSSDBGC_OpenSession;
    debug_functions.C_CloseSession = NSSDBGC_CloseSession;
    debug_functions.C_CloseAllSessions = NSSDBGC_CloseAllSessions;
    debug_functions.C_GetSessionInfo = NSSDBGC_GetSessionInfo;
    debug_functions.C_GetOperationState = NSSDBGC_GetOperationState;
    debug_functions.C_SetOperationState = NSSDBGC_SetOperationState;
    debug_functions.C_Login = NSSDBGC_Login;
    debug_functions.C_Logout = NSSDBGC_Logout;
    debug_functions.C_CreateObject = NSSDBGC_CreateObject;
    debug_functions.C_CopyObject = NSSDBGC_CopyObject;
    debug_functions.C_DestroyObject = NSSDBGC_DestroyObject;
    debug_functions.C_GetObjectSize = NSSDBGC_GetObjectSize;
    debug_functions.C_GetAttributeValue = NSSDBGC_GetAttributeValue;
    debug_functions.C_SetAttributeValue = NSSDBGC_SetAttributeValue;
    debug_functions.C_FindObjectsInit = NSSDBGC_FindObjectsInit;
    debug_functions.C_FindObjects = NSSDBGC_FindObjects;
    debug_functions.C_FindObjectsFinal = NSSDBGC_FindObjectsFinal;
    debug_functions.C_EncryptInit = NSSDBGC_EncryptInit;
    debug_functions.C_Encrypt = NSSDBGC_Encrypt;
    debug_functions.C_EncryptUpdate = NSSDBGC_EncryptUpdate;
    debug_functions.C_EncryptFinal = NSSDBGC_EncryptFinal;
    debug_functions.C_DecryptInit = NSSDBGC_DecryptInit;
    debug_functions.C_Decrypt = NSSDBGC_Decrypt;
    debug_functions.C_DecryptUpdate = NSSDBGC_DecryptUpdate;
    debug_functions.C_DecryptFinal = NSSDBGC_DecryptFinal;
    debug_functions.C_DigestInit = NSSDBGC_DigestInit;
    debug_functions.C_Digest = NSSDBGC_Digest;
    debug_functions.C_DigestUpdate = NSSDBGC_DigestUpdate;
    debug_functions.C_DigestKey = NSSDBGC_DigestKey;
    debug_functions.C_DigestFinal = NSSDBGC_DigestFinal;
    debug_functions.C_SignInit = NSSDBGC_SignInit;
    debug_functions.C_Sign = NSSDBGC_Sign;
    debug_functions.C_SignUpdate = NSSDBGC_SignUpdate;
    debug_functions.C_SignFinal = NSSDBGC_SignFinal;
    debug_functions.C_SignRecoverInit = NSSDBGC_SignRecoverInit;
    debug_functions.C_SignRecover = NSSDBGC_SignRecover;
    debug_functions.C_VerifyInit = NSSDBGC_VerifyInit;
    debug_functions.C_Verify = NSSDBGC_Verify;
    debug_functions.C_VerifyUpdate = NSSDBGC_VerifyUpdate;
    debug_functions.C_VerifyFinal = NSSDBGC_VerifyFinal;
    debug_functions.C_VerifyRecoverInit = NSSDBGC_VerifyRecoverInit;
    debug_functions.C_VerifyRecover = NSSDBGC_VerifyRecover;
    debug_functions.C_DigestEncryptUpdate = NSSDBGC_DigestEncryptUpdate;
    debug_functions.C_DecryptDigestUpdate = NSSDBGC_DecryptDigestUpdate;
    debug_functions.C_SignEncryptUpdate = NSSDBGC_SignEncryptUpdate;
    debug_functions.C_DecryptVerifyUpdate = NSSDBGC_DecryptVerifyUpdate;
    debug_functions.C_GenerateKey = NSSDBGC_GenerateKey;
    debug_functions.C_GenerateKeyPair = NSSDBGC_GenerateKeyPair;
    debug_functions.C_WrapKey = NSSDBGC_WrapKey;
    debug_functions.C_UnwrapKey = NSSDBGC_UnwrapKey;
    debug_functions.C_DeriveKey = NSSDBGC_DeriveKey;
    debug_functions.C_SeedRandom = NSSDBGC_SeedRandom;
    debug_functions.C_GenerateRandom = NSSDBGC_GenerateRandom;
    debug_functions.C_GetFunctionStatus = NSSDBGC_GetFunctionStatus;
    debug_functions.C_CancelFunction = NSSDBGC_CancelFunction;
    debug_functions.C_WaitForSlotEvent = NSSDBGC_WaitForSlotEvent;
    return &debug_functions;
}

/*
 * scale the time factor up accordingly.
 * This routine tries to keep at least 2 significant figures on output.
 *    If the time is 0, then indicate that with a 'z' for units.
 *    If the time is greater than 10 minutes, output the time in minutes.
 *    If the time is less than 10 minutes but greater than 10 seconds output 
 * the time in second.
 *    If the time is less than 10 seconds but greater than 10 milliseconds 
 * output * the time in millisecond.
 *    If the time is less than 10 milliseconds but greater than 0 ticks output 
 * the time in microsecond.
 *
 */
static PRUint32 getPrintTime(PRIntervalTime time ,char **type)
{
	PRUint32 prTime;

        /* detect a programming error by outputting 'bu' to the output stream
	 * rather than crashing */
 	*type = "bug";
	if (time == 0) {
	    *type = "z";
	    return 0;
	}

	prTime = PR_IntervalToSeconds(time);

	if (prTime >= 600) {
	    *type="m";
	    return prTime/60;
	}
        if (prTime >= 10) {
	    *type="s";
	    return prTime;
	} 
	prTime = PR_IntervalToMilliseconds(time);
        if (prTime >= 10) {
	    *type="ms";
	    return prTime;
	} 
 	*type = "us";
	return PR_IntervalToMicroseconds(time);
}

static void print_final_statistics(void)
{
    int total_calls = 0;
    PRIntervalTime total_time = 0;
    PRUint32 pr_total_time;
    char *type;
    char *fname;
    FILE *outfile = NULL;
    int i;

    fname = PR_GetEnv("NSS_OUTPUT_FILE");
    if (fname) {
	/* need to add an optional process id to the filename */
	outfile = fopen(fname,"w+");
    }
    if (!outfile) {
	outfile = stdout;
    }
	

    fprintf(outfile,"%-25s %10s %12s %12s %10s\n", "Function", "# Calls", 
				"Time", "Avg.", "% Time");
    fprintf(outfile,"\n");
    for (i=0; i < nssdbg_prof_size; i++) {
	total_calls += nssdbg_prof_data[i].calls;
	total_time += nssdbg_prof_data[i].time;
    }
    for (i=0; i < nssdbg_prof_size; i++) {
	PRIntervalTime time = nssdbg_prof_data[i].time;
	PRUint32 usTime = PR_IntervalToMicroseconds(time);
	PRUint32 prTime = 0;
	PRUint32 calls = nssdbg_prof_data[i].calls;
	/* don't print out functions that weren't even called */
	if (calls == 0) {
	    continue;
	}

	prTime = getPrintTime(time,&type);

	fprintf(outfile,"%-25s %10d %10d%2s ", nssdbg_prof_data[i].function, 
						calls, prTime, type);
	/* for now always output the average in microseconds */
	fprintf(outfile,"%10.2f%2s", (float)usTime / (float)calls, "us" );
	fprintf(outfile,"%10.2f%%", ((float)time / (float)total_time) * 100);
	fprintf(outfile,"\n");
    }
    fprintf(outfile,"\n");

    pr_total_time = getPrintTime(total_time,&type);

    fprintf(outfile,"%25s %10d %10d%2s\n", "Totals", total_calls, 
							pr_total_time, type);
    fprintf(outfile,"\n\nMaximum number of concurrent open sessions: %d\n\n",
							 maxOpenSessions);
    fflush (outfile);
    if (outfile != stdout) {
	fclose(outfile);
    }
}

