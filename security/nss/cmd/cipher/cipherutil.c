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

NSSToken *
GetSoftwareToken()
{
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    return NSSTrustDomain_FindTokenByName(td, SOFTOKEN_NAME);
}

NSSAlgorithmAndParameters *
GetHashAP(char *cipher)
{
    NSSOID *alg;
    if (strcmp(cipher, "sha") == 0 || strcmp(cipher, "sha1") == 0 ||
        strcmp(cipher, "sha-1") == 0)
    {
	alg = NSSOID_CreateFromTag(NSS_OID_SHA1);
    } else if (strcmp(cipher, "md5") == 0) {
	alg = NSSOID_CreateFromTag(NSS_OID_MD5);
    } else if (strcmp(cipher, "md2") == 0) {
	alg = NSSOID_CreateFromTag(NSS_OID_MD2);
    } else {
	fprintf(stderr, "Unknown hashing algorithm \"%s\"\n", cipher);
	return NULL;
    }
    return NSSOID_CreateAlgorithmAndParameters(alg, NULL, NULL);
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
    NSSAlgorithmAndParameters *hasher;

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
    NSSAlgorithmAndParameters_Destroy(hasher);
    return PR_SUCCESS;
}

NSSAlgorithmAndParameters *
GetSymKeyGenAP(char *cipher)
{
    NSSOID *alg;
    if (strcmp(cipher, "des") == 0) {
	alg = NSSOID_CreateFromTag(NSS_OID_DES_ECB);
    } else if (strcmp(cipher, "des3") == 0) {
	alg = NSSOID_CreateFromTag(NSS_OID_DES_EDE3_CBC); /* XXX cbc? */
    } else if (strcmp(cipher, "rc2") == 0) {
	alg = NSSOID_CreateFromTag(NSS_OID_RC2_CBC); /* XXX cbc? */
    } else if (strcmp(cipher, "rc4") == 0) {
	alg = NSSOID_CreateFromTag(NSS_OID_RC4);
#if 0
    } else if (strcmp(cipher, "rc5") == 0) {
	alg = ;
#endif
    } else {
	fprintf(stderr, "Unknown symmetric key algorithm \"%s\"\n", cipher);
	return NULL;
    }
    return NSSOID_CreateAlgorithmAndParametersForKeyGen(alg, NULL, NULL);
}

NSSSymmetricKey *
GenerateSymmetricKey
(
  NSSTrustDomain *td,
  /*NSSCryptoContext *cc,*/
  NSSToken *token,
  char *cipher,
  unsigned int length,
  char *name
)
{
    NSSAlgorithmAndParameters *keygen;
    NSSSymmetricKey *skey;

    keygen = GetSymKeyGenAP(cipher);
    if (!keygen) {
	return NULL;
    }

    skey = NSSTrustDomain_GenerateSymmetricKey(td, keygen, length, 
                                               token, NULL);

    NSSAlgorithmAndParameters_Destroy(keygen);

    return skey;
}

NSSAlgorithmAndParameters *
GetSymCipherAP(char *cipher, char *iv)
{
    char *paramStr;
    NSSItem cbcIV = { 0 };
    NSSParameters params;
    NSSParameters *pParams = NULL;
    NSSOID *alg;

    memset(&params, 0, sizeof(params));

    paramStr = strchr(cipher, '-');
    if (paramStr) {
	*paramStr++ = '\0';
    }
    if (iv) {
	cbcIV.data = iv;
	cbcIV.size = strlen(iv);
    }
    if (strcmp(cipher, "des") == 0) {
	if (iv) {
	    alg = NSSOID_CreateFromTag(NSS_OID_DES_CBC);
	    params.des.iv = cbcIV;
	    pParams = &params;
	} else {
	    alg = NSSOID_CreateFromTag(NSS_OID_DES_ECB);
	}
    } else if (strcmp(cipher, "des3") == 0) {
	return NULL;
    } else if (strcmp(cipher, "aes") == 0) {
	return NULL;
    } else if (strcmp(cipher, "rc2") == 0) {
	return NULL;
    } else if (strcmp(cipher, "rc4") == 0) {
	return NULL;
    } else if (strcmp(cipher, "rc5") == 0) {
	return NULL;
    } else {
	fprintf(stderr, "algorithm type \"%s\" unknown.\n", cipher);
    }
    return NSSOID_CreateAlgorithmAndParameters(alg, pParams, NULL);
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
    NSSAlgorithmAndParameters *cryptor;

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

NSSAlgorithmAndParameters *
GetKeyPairGenAP(char *cipher)
{
    PRStatus status;
    char *paramStr, *param;
    NSSParameters params;
    NSSOID *alg;

    memset(&params, 0, sizeof(params));

    paramStr = strchr(cipher, '-');
    if (paramStr) {
	*paramStr++ = '\0';
    }
    if (strcmp(cipher, "rsa") == 0) {
	int pe;
	alg = NSSOID_CreateFromTag(NSS_OID_PKCS1_RSA_ENCRYPTION);
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
	alg = NSSOID_CreateFromTag(NSS_OID_ANSIX9_DSA_SIGNATURE);
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
	alg = NSSOID_CreateFromTag(NSS_OID_X942_DIFFIE_HELLMAN_KEY);
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
	return (NSSAlgorithmAndParameters *)NULL;
    }
    return NSSOID_CreateAlgorithmAndParametersForKeyGen(alg, &params, NULL);
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
    const NSSAlgorithmAndParameters *keygen;

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

