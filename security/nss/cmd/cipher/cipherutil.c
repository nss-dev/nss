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

#include <string.h>

#include "nsspki1.h"
#include "cipher.h"

#define IS_CIPHER(s, c) \
    (strncmp(c, s, strlen(c)) == 0)

NSSToken *
GetSoftwareToken()
{
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    return NSSTrustDomain_FindTokenByName(td, SOFTOKEN_NAME);
}

NSSAlgNParam *
GetHashAP(char *cipher)
{
    NSSOIDTag alg;
    if (strcmp(cipher, "sha") == 0 || strcmp(cipher, "sha1") == 0 ||
        strcmp(cipher, "sha-1") == 0)
    {
	alg = NSS_OID_SHA1;
    } else if (strcmp(cipher, "md5") == 0) {
	alg = NSS_OID_MD5;
    } else if (strcmp(cipher, "md2") == 0) {
	alg = NSS_OID_MD2;
    } else {
	fprintf(stderr, "Unknown hashing algorithm \"%s\"\n", cipher);
	return NULL;
    }
    return NSSOIDTag_CreateAlgNParam(alg, NULL, NULL);
}

PRStatus
Hash
(
  NSSCryptoContext *cc,
  char *cipher,
  CMDRunTimeData *rtData
)
{
    NSSItem *input, *output;
    NSSAlgNParam *hasher;

    input = CMD_GetInput(rtData);
    if (!input) {
	return PR_FAILURE;
    }
    hasher = GetHashAP(cipher);
    if (!hasher) {
	NSSItem_Destroy(input);
	return PR_FAILURE;
    }
    output = NSSCryptoContext_Digest(cc, hasher, input, NULL, NULL, NULL);
    if (!output) {
	fprintf(stderr, "Digest operation failed\n");
	NSSItem_Destroy(input);
	return PR_FAILURE;
    }
    CMD_DumpOutput(output, rtData);
    NSSItem_Destroy(input);
    NSSItem_Destroy(output);
    NSSAlgNParam_Destroy(hasher);
    return PR_SUCCESS;
}

NSSAlgNParam *
GetSymKeyGenAP(char *cipher)
{
    NSSOIDTag alg;
    NSSAlgNParam *ap;

    if (IS_CIPHER(cipher, "des")) {
	alg = NSS_OID_DES_ECB;
    } else if (IS_CIPHER(cipher, "des3")) {
	alg = NSS_OID_DES_EDE3_CBC; /* XXX cbc? */
    } else if (IS_CIPHER(cipher, "rc2")) {
	alg = NSS_OID_RC2_CBC; /* XXX cbc? */
    } else if (IS_CIPHER(cipher, "rc4")) {
	alg = NSS_OID_RC4;
    } else if (IS_CIPHER(cipher, "rc5")) {
	alg = NSS_OID_RC5_CBC_PAD;
    } else {
	PR_fprintf(PR_STDERR, "Unknown symmetric key algorithm \"%s\"\n", 
	                       cipher);
	return NULL;
    }
    ap = NSSOIDTag_CreateAlgNParamForKeyGen(alg, NULL, NULL);
    if (!ap) {
	PR_fprintf(PR_STDERR, "Failed to create keygen alg/param for %s\n",
	                       cipher);
    }
    return ap;
}

NSSSymKey *
GenerateSymKey
(
  NSSTrustDomain *td,
  /*NSSCryptoContext *cc,*/
  NSSToken *token,
  char *cipher,
  unsigned int length,
  char *name
)
{
    NSSAlgNParam *keygen;
    NSSSymKey *skey;

    keygen = GetSymKeyGenAP(cipher);
    if (!keygen) {
	return NULL;
    }

    skey = NSSTrustDomain_GenerateSymKey(td, keygen, length, 
                                               token, NULL);

    NSSAlgNParam_Destroy(keygen);

    return skey;
}

NSSAlgNParam *
GetSymCipherAP(char *cipher, char *iv)
{
    char *paramStr, *p;
    NSSItem cbcIV = { 0 };
    NSSParameters params;
    NSSParameters *pParams = NULL;
    NSSOIDTag alg;
    NSSAlgNParam *ap;
    PRBool haveIV = PR_FALSE;

    memset(&params, 0, sizeof(params));

    paramStr = strchr(cipher, '-');
    if (paramStr) {
	*paramStr++ = '\0';
    }
    if (strncmp(paramStr, "cbc", 3) == 0) {
	if (iv) {
	    cbcIV.data = iv;
	    cbcIV.size = strlen(iv);
	} else {
	    NSSItem_Create(NULL, &cbcIV, MAX_IV_LENGTH, NULL);
	    if (NSS_GenerateRandom(MAX_IV_LENGTH, cbcIV.data, NULL) == NULL) {
		CMD_PrintError("failed to generate IV");
		return NULL;
	    }
	}
	haveIV = PR_TRUE;
	/* move to the actual params */
	paramStr = strchr(paramStr, '-');
	if (paramStr) paramStr++;
    } else if (iv) {
	PR_fprintf(PR_STDERR, "IV not used with this cipher\n");
	return NULL;
    }
    if (IS_CIPHER(cipher, "des")) {
	if (haveIV) {
	    alg = NSS_OID_DES_CBC;
	    cbcIV.size = DES_IV_LENGTH;
	    params.iv = cbcIV;
	    pParams = &params;
	} else {
	    alg = NSS_OID_DES_ECB;
	}
    } else if (IS_CIPHER(cipher, "des3")) {
	if (haveIV) {
	    alg = NSS_OID_DES_EDE3_CBC;
	    cbcIV.size = DES3_IV_LENGTH;
	    params.iv = cbcIV;
	    pParams = &params;
	} else {
#if 0
	    alg = NSS_OID_DES_ECB;
#endif
	    return NULL;
	}
    } else if (IS_CIPHER(cipher, "aes")) {
	return NULL;
    } else if (IS_CIPHER(cipher, "rc2")) {
	if (paramStr) {
	    params.rc2.effectiveKeySizeInBits = atoi(paramStr);
	} else {
	    params.rc2.effectiveKeySizeInBits = RC2_EFF_KEY_BITS_DEFAULT;
	}
	if (haveIV) {
	    alg = NSS_OID_RC2_CBC;
	    cbcIV.size = RC2_IV_LENGTH;
	    params.rc2.iv = cbcIV;
	    pParams = &params;
	} else {
#if 0
	    alg = NSS_OID_DES_ECB;
#endif
	    return NULL;
	}
    } else if (IS_CIPHER(cipher, "rc4")) {
	alg = NSS_OID_RC4;
    } else if (IS_CIPHER(cipher, "rc5")) {
	if (paramStr) {
	    p = strchr(paramStr, '-');
	    if (!p) {
		PR_fprintf(PR_STDERR, "Must specify both wordSize and "
		                      "numRounds for RC5\n");
		return NULL;
	    }
	    *p++ = '\0';
	    params.rc5.wordSize = atoi(paramStr);
	    params.rc5.numRounds = atoi(p);
	} else {
	    params.rc5.wordSize = RC5_WORDSIZE_DEFAULT;
	    params.rc5.numRounds = RC5_NUMROUNDS_DEFAULT;
	}
	if (haveIV) {
	    alg = NSS_OID_RC5_CBC_PAD; /* XXX PAD? */
	    cbcIV.size = params.rc5.wordSize * 2;
	    params.rc5.iv = cbcIV;
	    pParams = &params;
	} else {
#if 0
	    alg = NSS_OID_DES_ECB;
#endif
	    return NULL;
	}
    } else {
	PR_fprintf(PR_STDERR, "algorithm type \"%s\" unknown.\n", cipher);
    }
    ap = NSSOIDTag_CreateAlgNParam(alg, pParams, NULL);
    if (!ap) {
	PR_fprintf(PR_STDERR, "Failed to create encryption alg/param for %s\n",
	                       cipher);
    }
    return ap;
}

PRStatus
Encrypt
(
  NSSCryptoContext *cc,
  char *cipher,
  char *key,
  char *iv,
  CMDRunTimeData *rtData
)
{
    NSSItem *input, *output;
    NSSAlgNParam *cryptor;

    input = CMD_GetInput(rtData);
    if (!input) {
	return PR_FAILURE;
    }
    cryptor = GetSymCipherAP(cipher, iv);
    if (!cryptor) {
	NSSItem_Destroy(input);
	return PR_FAILURE;
    }
    output = NSSCryptoContext_Encrypt(cc, cryptor, input, NULL, NULL, NULL);
    if (!output) {
	fprintf(stderr, "Encrypt operation failed\n");
	NSSItem_Destroy(input);
	return PR_FAILURE;
    }
    CMD_DumpOutput(output, rtData);
    NSSItem_Destroy(input);
    NSSItem_Destroy(output);
    return PR_SUCCESS;
}

NSSAlgNParam *
GetKeyPairGenAP(char *cipher)
{
    PRStatus status;
    char *paramStr, *param;
    NSSParameters params;
    NSSOIDTag alg;

    memset(&params, 0, sizeof(params));

    paramStr = strchr(cipher, '-');
    if (paramStr) {
	*paramStr++ = '\0';
    }
    if (strcmp(cipher, "rsa") == 0) {
	int pe;
	alg = NSS_OID_PKCS1_RSA_ENCRYPTION;
	if (paramStr) {
	    param = paramStr;
	    paramStr = strchr(paramStr, '-');
	    if (paramStr) {
		*paramStr++ = '\0';
	    }
	    params.rsakg.modulusBits = atoi(param);
	} else {
	    params.rsakg.modulusBits = 1024;
	}
	pe = paramStr ? atoi(paramStr) : 65537;
	status = CMD_SetRSAPE(&params.rsakg.publicExponent, pe);
	if (status == PR_FAILURE) {
	    return NULL;
	}
    } else if (strcmp(cipher, "dsa") == 0) {
	alg = NSS_OID_ANSIX9_DSA_SIGNATURE;
	if (paramStr) {
	    param = paramStr;
	    paramStr = strchr(paramStr, '-');
	    if (paramStr) {
		*paramStr++ = '\0';
	    }
	    params.dsakg.primeBits = atoi(param);
	} else {
	    params.dsakg.primeBits = 1024;
	}
	/* XXX pqg from file */
    } else if (strcmp(cipher, "dh") == 0) {
	alg = NSS_OID_X942_DIFFIE_HELLMAN_KEY;
	if (paramStr) {
	    param = paramStr;
	    paramStr = strchr(paramStr, '-');
	    if (paramStr) {
		*paramStr++ = '\0';
	    }
	    params.dhkg.primeBits = atoi(param);
	} else {
	    params.dhkg.primeBits = 1024;
	}
	if (paramStr) {
	    param = paramStr;
	    paramStr = strchr(paramStr, '-');
	    if (paramStr) {
		*paramStr++ = '\0';
	    }
	    params.dhkg.valueBits = atoi(param);
	} else {
	    params.dhkg.valueBits = 1024;
	}
	/* XXX pg from file */
    } else {
	fprintf(stderr, "Unknown keypair type\"%s\"\n", cipher);
	return (NSSAlgNParam *)NULL;
    }
    return NSSOIDTag_CreateAlgNParamForKeyGen(alg, &params, NULL);
}

PRStatus
GenerateKeyPair
(
  NSSTrustDomain *td,
  /*NSSCryptoContext *cc,*/
  NSSToken *token,
  char *cipher,
  char *name,
  NSSPrivateKey **privateKey,
  NSSPublicKey **publicKey
)
{
    PRStatus status;
    const NSSAlgNParam *keygen;

    keygen = GetKeyPairGenAP(cipher);
    if (!keygen) {
	return PR_FAILURE;
    }

    status = NSSTrustDomain_GenerateKeyPair(td, keygen,
                                            publicKey, privateKey,
                                            name, 0, 0,
                                            token, NULL);

    return status;
}

