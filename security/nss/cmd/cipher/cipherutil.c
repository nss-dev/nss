
#include <string.h>

#include "cipher.h"

NSSToken *
GetSoftwareToken()
{
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    return NSSTrustDomain_FindTokenByName(td, SOFTOKEN_NAME);
}

static const NSSAlgorithmAndParameters *
get_hash_algorithm(char *cipher)
{
    if (strcmp(cipher, "sha") == 0 || strcmp(cipher, "sha1") == 0 ||
        strcmp(cipher, "sha-1") == 0)
    {
	return NSSAlgorithmAndParameters_SHA1;
    } else if (strcmp(cipher, "md5") == 0) {
	return NSSAlgorithmAndParameters_MD5;
    } else if (strcmp(cipher, "md2") == 0) {
	return NSSAlgorithmAndParameters_MD2;
    } else {
	fprintf(stderr, "Unknown hashing algorithm \"%s\"\n", cipher);
	return NULL;
    }
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
    const NSSAlgorithmAndParameters *hasher;

    input = CMD_GetInput(rtData);
    if (!input) {
	return PR_FAILURE;
    }
    hasher = get_hash_algorithm(cipher);
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
    return PR_SUCCESS;
}

static const NSSAlgorithmAndParameters *
get_symmetric_keygen_algorithm(char *cipher)
{
    if (strcmp(cipher, "des") == 0) {
	return NSSAlgorithmAndParameters_DESKeyGen;
    } else if (strcmp(cipher, "des3") == 0) {
	return NSSAlgorithmAndParameters_3DESKeyGen;
    } else if (strcmp(cipher, "rc2") == 0) {
	return NSSAlgorithmAndParameters_RC2KeyGen;
    } else if (strcmp(cipher, "rc4") == 0) {
	return NSSAlgorithmAndParameters_RC4KeyGen;
    } else if (strcmp(cipher, "rc5") == 0) {
	return NSSAlgorithmAndParameters_RC5KeyGen;
    } else {
	fprintf(stderr, "Unknown symmetric key algorithm \"%s\"\n", cipher);
	return (const NSSAlgorithmAndParameters *)NULL;
    }
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
    NSSItem *input, *output;
    const NSSAlgorithmAndParameters *keygen;
    NSSSymmetricKey *skey;

    keygen = get_symmetric_keygen_algorithm(cipher);
    if (!keygen) {
	return NULL;
    }

    skey = NSSTrustDomain_GenerateSymmetricKey(td, keygen, length, 
                                               token, NULL);

    return skey;
}

static NSSAlgorithmAndParameters *
get_symmetric_key_ap(char *cipher, char *iv)
{
    char *paramStr;
    NSSItem cbcIV = { 0 };
    NSSParameters params;
    NSSParameters *pParams = NULL;
    NSSAlgorithmType algType = NSSAlgorithmType_NULL;

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
	algType = NSSAlgorithmType_DES;
	if (iv || paramStr) {
	    if (strcmp(paramStr, "pkcs")) {
		params.des.pkcsPad = PR_TRUE;
	    } else {
		fprintf(stderr, "DES parameters \"%s\" invalid.\n", paramStr);
	    }
	    params.des.iv = cbcIV;
	    pParams = &params;
	}
    } else if (strcmp(cipher, "des3") == 0) {
    } else if (strcmp(cipher, "aes") == 0) {
    } else if (strcmp(cipher, "rc2") == 0) {
    } else if (strcmp(cipher, "rc4") == 0) {
    } else if (strcmp(cipher, "rc5") == 0) {
    } else {
	fprintf(stderr, "algorithm type \"%s\" unknown.\n", cipher);
    }
    return NSSAlgorithmAndParameters_Create(NULL, algType, pParams);
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
    cryptor = get_symmetric_key_ap(cipher, iv);
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

static NSSAlgorithmAndParameters *
get_keypair_gen_algorithm(char *cipher)
{
    char *paramStr, *param;
    NSSParameters params;
    NSSAlgorithmType algType = NSSAlgorithmType_NULL;

    memset(&params, 0, sizeof(params));

    paramStr = strchr(cipher, '-');
    if (paramStr) {
	*paramStr++ = '\0';
    }
    if (strcmp(cipher, "rsa") == 0) {
	algType = NSSAlgorithmType_RSA;
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
	if (paramStr) {
	    params.rsakg.publicExponent = atoi(paramStr);
	} else {
	    params.rsakg.publicExponent = 65537;
	}
    } else if (strcmp(cipher, "dsa") == 0) {
	algType = NSSAlgorithmType_DSA;
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
	algType = NSSAlgorithmType_DH;
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
    return NSSAlgorithmAndParameters_CreateKeyGen(NULL, algType, &params);
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

    keygen = get_keypair_gen_algorithm(cipher);
    if (!keygen) {
	return PR_FAILURE;
    }

    status = NSSTrustDomain_GenerateKeyPair(td, keygen,
                                            publicKey, privateKey,
                                            PR_TRUE, token, NULL);

    return status;
}

