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

#ifndef NSSDEVT_H
#define NSSDEVT_H

#ifdef DEBUG
static const char NSSDEVT_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * nssdevt.h
 *
 * This file contains definitions for the low-level cryptoki devices.
 */

#ifndef NSSBASET_H
#include "nssbaset.h"
#endif /* NSSBASET_H */

PR_BEGIN_EXTERN_C

typedef struct NSSModuleStr NSSModule;

typedef struct NSSSlotStr NSSSlot;

typedef struct NSSTokenStr NSSToken;

/*
 * NSSAlgorithmAndParameters
 *
 * Algorithm is an OID
 * Parameters depend on the algorithm
 */

typedef struct NSSAlgorithmAndParametersStr NSSAlgorithmAndParameters;

struct version_str
{
  PRUint32 major;
  PRUint32 minor;
};


typedef struct
{
  NSSUTF8 *name;
  NSSUTF8 *libraryName;
  PRBool isThreadSafe;
  PRBool isInternal;
  PRBool isFIPS;
  PRBool isModuleDB;
  PRBool isModuleDBOnly;
  PRBool isCritical;
  struct version_str cryptokiVersion;
  NSSUTF8 *manufacturerID;
  NSSUTF8 *libraryDescription;
  struct version_str libraryVersion;
  NSSUTF8 **slotNames;
  PRUint32 numSlots;
} 
NSSModuleInfo;

typedef struct 
{
  NSSUTF8 *name;
  NSSUTF8 *description;
  NSSUTF8 *manufacturerID;
  struct version_str hardwareVersion;
  struct version_str firmwareVersion;
  NSSUTF8 *moduleName;
  NSSUTF8 *tokenName;
  PRBool isTokenPresent;
  PRBool isTokenRemovable;
  PRBool isHardware;
} 
NSSSlotInfo;

typedef struct 
{
  NSSUTF8 *name;
  NSSUTF8 *manufacturerID;
  NSSUTF8 *model;
  NSSUTF8 *serialNumber;
  struct {
    PRUint32 maximum;
    PRUint32 active;
  } sessions;
  struct {
    PRUint32 maximum;
    PRUint32 active;
  } readWriteSessions;
  struct {
    PRUint32 minimum;
    PRUint32 maximum;
  } pinRange;
  struct {
    PRUint32 total;
    PRUint32 free;
  } publicMemory;
  struct {
    PRUint32 total;
    PRUint32 free;
  } privateMemory;
  struct version_str hardwareVersion;
  struct version_str firmwareVersion;
  NSSUTF8 *utcTime;
  PRBool hasRNG;
  PRBool isWriteProtected;
  PRBool isLoginRequired;
  PRBool isPINInitialized;
  PRBool hasClock;
  PRBool hasProtectedAuthPath;
  PRBool supportsDualCrypto;
} 
NSSTokenInfo;

/*
 * NSSCallback
 *
 * At minimum, a "challenge" method and a closure argument.
 * Usually the challenge will just be prompting for a password.
 * How OO do we want to make it?
 */

typedef struct NSSCallbackStr NSSCallback;

struct NSSCallbackStr {
    /* Prompt for a password to initialize a slot.  */
    PRStatus (* getInitPW)(NSSUTF8 *slotName, void *arg, NSSUTF8 **password); 
    /* Prompt for slot password.  */
    PRStatus (* getPW)(NSSUTF8 *slotName, PRUint32 retries, void *arg,
                       NSSUTF8 **password); 
    void *arg;
};

typedef enum {
  NSSCertificateType_Unknown = 0,
  NSSCertificateType_PKIX = 1
} NSSCertificateType;

typedef enum
{
  NSSKeyPairType_Unknown = 0,
  NSSKeyPairType_RSA = 1,
  NSSKeyPairType_DSA = 2,
  NSSKeyPairType_DiffieHellman = 3
} NSSKeyPairType;

typedef enum
{
  NSSSymmetricKeyType_Unknown = 0,
  NSSSymmetricKeyType_DES = 1,
  NSSSymmetricKeyType_TripleDES = 2,
  NSSSymmetricKeyType_RC2 = 3,
  NSSSymmetricKeyType_RC4 = 4,
  NSSSymmetricKeyType_RC5 = 5,
  NSSSymmetricKeyType_AES = 6
} NSSSymmetricKeyType;

/* set errors - user cancelled, ... */

typedef enum {
  NSSAlgorithmType_NULL   =  0,
  NSSAlgorithmType_RSA    =  1,
  NSSAlgorithmType_DSA    =  2,
  NSSAlgorithmType_DH     =  3,
  NSSAlgorithmType_DES    =  4,
  NSSAlgorithmType_3DES   =  5,
  NSSAlgorithmType_AES    =  6,
  NSSAlgorithmType_RC2    =  7,
  NSSAlgorithmType_RC4    =  8,
  NSSAlgorithmType_RC5    =  9,
  NSSAlgorithmType_MD2    = 10,
  NSSAlgorithmType_MD5    = 11,
  NSSAlgorithmType_SHA1   = 12,
  NSSAlgorithmType_PBE    = 13,
  NSSAlgorithmType_MAC    = 14,
  NSSAlgorithmType_HMAC   = 15
} NSSAlgorithmType;

/*
 * RSA
 */

/* key generation */
typedef struct NSSRSAKeyGenParametersStr
{
  PRUint32 modulusBits;
  PRUint32 publicExponent;
}
NSSRSAKeyGenParameters;

/*
 * cipher operations
 * DEFAULT: RAW (X.509)
 */
typedef enum {
  NSSRSABlockFormat_RAW              = 0,
  NSSRSABlockFormat_PKCS1            = 1,
  NSSRSABlockFormat_PKCS1_WITH_MD2   = 2,
  NSSRSABlockFormat_PKCS1_WITH_MD5   = 3,
  NSSRSABlockFormat_PKCS1_WITH_SHA1  = 4,
  NSSRSABlockFormat_PKCS1_OAEP       = 5
} NSSRSABlockFormat;

typedef NSSRSABlockFormat NSSRSAParameters;

/*
 * DSA
 */

/* key generation */
typedef struct NSSDSAKeyGenParametersStr
{
  PRUint32 primeBits;
  NSSItem p, q, g;          /* set of PQG parameters (can be zero)    */
}
NSSDSAKeyGenParameters;

/*
 * signature/verification
 * DEFAULT: "raw" (no hashing)
 */
typedef NSSAlgorithmType NSSDSAParameters; /* hash algorithm */

/*
 * Diffie-Hellman
 */

/*
 * key generation
 *
 * Note: the size of p and g in Diffie-Hellman is not bounded above.
 * The parameters must use an unconstrained datum to represent p and g.
 * The memory used for p and g below is within the scope of the caller,
 * any NSS function will copy as necessary.
 */
typedef struct NSSDHParametersStr 
{
  PRUint32 valueBits;
  PRUint32 primeBits;
  NSSItem p, g; /* P and G values (can be zero) */
}
NSSDHKeyGenParameters;

/*
 * DES and Triple-DES
 */

/* key generation */
NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_DESKeyGen;

NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_3DESKeyGen;

/* 
 * encryption/decryption parameters 
 * DEFAULT: ECB mode
 */
typedef struct NSSDESParametersStr
{
  PRBool pkcsPad;
  NSSItem iv;
}
NSSDESParameters;

/*
 * AES
 */

/* key generation */
NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_AESKeyGen;

/* encryption/decryption parameters */
typedef struct NSSAESParametersStr
{
#if 0
  /* PKCS #11 is assuming 128-bit blocks */
  PRUint32 blockSizeInBits;
#endif
  PRBool pkcsPad;
  NSSItem iv;
}
NSSAESParameters;

/*
 * RC2
 */

/* key generation */
NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_RC2KeyGen;

/* encryption/decryption parameters */
typedef struct NSSRC2ParametersStr
{
  PRUint32 effectiveKeySizeInBits;
  PRBool pkcsPad;
  NSSItem iv;
}
NSSRC2Parameters;

/*
 * RC4
 */

/* key generation */
NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_RC4KeyGen;

/* encryption/decryption (parameters are always NULL) */
NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_RC4;

/*
 * RC5
 */

/* key generation */
NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_RC5KeyGen;

/* encryption/decryption parameters */
typedef struct NSSRC5ParametersStr
{
  PRUint32 wordSize;
  PRUint32 numRounds;
  PRBool pkcsPad;
  NSSItem iv;
}
NSSRC5Parameters;

/* 
 * MD2 
 */

NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_MD2;

/* 
 * MD5 
 */

NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_MD5;

/* 
 * SHA-1 
 */

NSS_EXTERN_DATA const NSSAlgorithmAndParameters *
                      NSSAlgorithmAndParameters_SHA1;

/*
 * HMAC
 *
 * DEFAULT: maximum length, specific to hash algorithm
 */

typedef PRUint32 NSSHMACParameters; /* length in bytes of desired output */

/*
 * Key derivation
 */

typedef struct NSSKeyDerivationParametersStr
{
}
NSSKeyDerivationParameters;

/*
 * PBE key generation
 */

/* NSS will always copy from this data */
typedef struct NSSPBEKeyGenParametersStr
{
  NSSItem iv;
  NSSUTF8 *password;
  NSSItem salt;
  PRUint32 iterations;
}
NSSPBEKeyGenParameters;

/* XXX */
typedef enum {
  NSSSSLVersion_v2 = 0,
  NSSSSLVersion_v3 = 1,
  NSSSSLVersion_TLS = 2
} NSSSSLVersion;

typedef union
{
  NSSRSAKeyGenParameters rsakg;
  NSSDSAKeyGenParameters dsakg;
  NSSDHKeyGenParameters  dhkg;
  NSSPBEKeyGenParameters pbekg;
  NSSRSAParameters       rsa;
  NSSDSAParameters       dsa;
  NSSDESParameters       des;
  NSSAESParameters       aes;
  NSSRC2Parameters       rc2;
  NSSRC5Parameters       rc5;
  NSSHMACParameters      hmac;
}
NSSParameters;

typedef PRUint32 NSSOperations;
/* 1) Do we want these to be preprocessor definitions or constants? */
/* 2) What is the correct and complete list? */

#define NSSOperations_ENCRYPT           0x0001
#define NSSOperations_DECRYPT           0x0002
#define NSSOperations_WRAP              0x0004
#define NSSOperations_UNWRAP            0x0008
#define NSSOperations_SIGN              0x0010
#define NSSOperations_SIGN_RECOVER      0x0020
#define NSSOperations_VERIFY            0x0040
#define NSSOperations_VERIFY_RECOVER    0x0080
#define NSSOperations_DERIVE            0x0100

typedef PRUint32 NSSProperties;

#define NSSProperties_PRIVATE          0x0001
#define NSSProperties_READ_ONLY        0x0002
#define NSSProperties_SENSITIVE        0x0004 /* keys only */
#define NSSProperties_EXTRACTABLE      0x0008 /* keys only */

PR_END_EXTERN_C

#endif /* NSSDEVT_H */
