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
    PRStatus (* getPW)(NSSUTF8 *slotName, PRBool *retry, void *arg,
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
  NSSKeyPairType_DH = 3
} NSSKeyPairType;

typedef struct NSSRSAPublicKeyInfoStr
{
  NSSItem modulus;
  NSSItem publicExponent;
}
NSSRSAPublicKeyInfo;

typedef struct NSSDSAPublicKeyInfoStr
{
#if 0
  NSSPQGParameters params;
#endif
  NSSItem publicValue;
}
NSSDSAPublicKeyInfo;

typedef struct NSSDHPublicKeyInfoStr
{
  NSSItem prime;
  NSSItem base;
  NSSItem publicValue;
}
NSSDHPublicKeyInfo;

typedef struct NSSPublicKeyInfoStr
{
  NSSKeyPairType kind;
  union {
    NSSRSAPublicKeyInfo rsa;
    NSSDSAPublicKeyInfo dsa;
    NSSDHPublicKeyInfo  dh;
  } u;
}
NSSPublicKeyInfo;

typedef enum
{
  NSSSymmetricKeyType_Unknown = 0,
  NSSSymmetricKeyType_DES = 1,
  NSSSymmetricKeyType_TripleDES = 2,
  NSSSymmetricKeyType_RC2 = 3,
  NSSSymmetricKeyType_RC4 = 4,
  NSSSymmetricKeyType_RC5 = 5,
  NSSSymmetricKeyType_AES = 6,
  NSSSymmetricKeyType_SSLPMS = 7,
  NSSSymmetricKeyType_SSLMS = 8
} NSSSymmetricKeyType;

/*
 * RSA
 */

/* key generation */
typedef struct NSSRSAKeyGenParametersStr
{
  PRUint32 modulusBits;
  NSSItem publicExponent; /* Big-Endian */
}
NSSRSAKeyGenParameters;

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
 *
 * only IV when in CBC mode
 */

/*
 * AES
 *
 * PKCS #11 is assuming 128-bit blocks, so no params for now
 * except IV when in CBC mode
 */

/*
 * RC2
 */

/* encryption/decryption parameters */
typedef struct NSSRC2ParametersStr
{
  PRUint32 effectiveKeySizeInBits;
  NSSItem iv;
  NSSItem version; /* IGNORE */
}
NSSRC2Parameters;

/*
 * RC4
 *
 * no params
 */

/*
 * RC5
 */

/* encryption/decryption parameters */
typedef struct NSSRC5ParametersStr
{
  PRUint32 wordSize;
  PRUint32 numRounds;
  NSSItem iv;
}
NSSRC5Parameters;

/*
 * HMAC
 *
 * DEFAULT: maximum length, specific to hash algorithm
 */

typedef PRUint32 NSSHMACParameters; /* length in bytes of desired output */

/*
 * Key derivation
 */

#if 0
typedef struct NSSKeyDerivationParametersStr
{
}
NSSKeyDerivationParameters;
#endif

/*
 * PBE key generation
 */

#define PBE_IV_LENGTH 8

typedef struct NSSPBEParametersStr
{
  unsigned char iv[PBE_IV_LENGTH];
  NSSItem salt;
  PRUint32 iteration;
  NSSItem iterIt; /* XXX until ASN.1 decodes ints */
}
NSSPBEParameters;

/*
 * SSL
 */

/* XXX */
typedef enum {
  NSSSSLVersion_SSLv2 = 0,
  NSSSSLVersion_SSLv3 = 1,
  NSSSSLVersion_TLS = 2
} NSSSSLVersion;

typedef NSSSSLVersion NSSSSLPMSParameters;

typedef struct NSSSSLMSParametersStr 
{
  NSSItem clientRandom;
  NSSItem serverRandom;
  NSSSSLVersion version;
  PRBool isDH;
} 
NSSSSLMSParameters;

typedef struct NSSSSLSessionKeyParametersStr
{
  NSSSSLVersion version;
  PRUint32 macSizeInBits;
  PRUint32 keySizeInBits;
  PRUint32 ivSizeInBits;
  PRBool isExport;
  NSSItem clientRandom;
  NSSItem serverRandom;
  PRUint8 *clientIV;
  PRUint8 *serverIV;
} 
NSSSSLSessionKeyParameters;


typedef union
{
  NSSItem                iv; /* for all generic CBC ciphers */
  NSSRSAKeyGenParameters rsakg;
  NSSDSAKeyGenParameters dsakg;
  NSSDHKeyGenParameters  dhkg;
  NSSRC2Parameters       rc2;
  NSSRC5Parameters       rc5;
  NSSHMACParameters      hmac;
  NSSPBEParameters       pbe;
  NSSSSLPMSParameters    sslpms;
  NSSSSLMSParameters     sslms;
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

PR_END_EXTERN_C

#endif /* NSSDEVT_H */
