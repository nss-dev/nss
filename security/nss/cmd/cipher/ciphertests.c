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

#define WRAPKEY_PW "asdf"
#define UNWRAPPING_KEY_FILE "wrapkey.txt"
#define WRAPPING_CERT_FILE "wrapcert.txt"
#define SYMKEY_TEST_FILE  "symtests.txt"

PRStatus
EncryptionTest(NSSSymKey *symKey,
               NSSAlgNParam *cipher,
               NSSItem *plaintext,
               NSSItem *ciphertext)
{
    NSSItem *encryptedData, *decryptedData;
    NSSCryptoContext *cc;

    /* Create a crypto context for encryption with the symkey */
    cc = NSSSymKey_CreateCryptoContext(symKey, cipher, NULL);
    if (!cc) {
	CMD_PrintError("Failed to create crypto context");
	return PR_FAILURE;
    }

    /* Encrypt with the key and alg/param */
    encryptedData = NSSCryptoContext_Encrypt(cc, NULL, plaintext,
                                             NULL, NULL, NULL);
    if (!encryptedData || !NSSItem_Equal(encryptedData, ciphertext, NULL)) 
    {
	if (encryptedData) NSSItem_Destroy(encryptedData);
	NSSCryptoContext_Destroy(cc);
	CMD_PrintError("Encryption failed");
	return PR_FAILURE;
    }
    NSSItem_Destroy(encryptedData);

    /* repeat using symkey directly */
    encryptedData = NSSSymKey_Encrypt(symKey, cipher, 
                                            plaintext,
                                            NULL, NULL, NULL);
    if (!encryptedData || !NSSItem_Equal(encryptedData, ciphertext, NULL))
    {
	NSSItem_Destroy(encryptedData);
	NSSCryptoContext_Destroy(cc);
	CMD_PrintError("Encryption failed");
	return PR_FAILURE;
    }
    NSSItem_Destroy(encryptedData);

    /* Decrypt with the key and alg/param */
    decryptedData = NSSCryptoContext_Decrypt(cc, NULL, ciphertext,
                                             NULL, NULL, NULL);
    if (!decryptedData || !NSSItem_Equal(decryptedData, plaintext, NULL)) 
    {
	NSSItem_Destroy(decryptedData);
	NSSCryptoContext_Destroy(cc);
	CMD_PrintError("Decryption failed");
	return PR_FAILURE;
    }
    NSSItem_Destroy(decryptedData);

    /* repeat using symkey directly */
    decryptedData = NSSSymKey_Decrypt(symKey, cipher, 
                                            ciphertext,
                                            NULL, NULL, NULL);
    if (!decryptedData || !NSSItem_Equal(decryptedData, plaintext, NULL)) 
    {
	NSSItem_Destroy(decryptedData);
	CMD_PrintError("Decryption failed");
	return PR_FAILURE;
    }
    NSSItem_Destroy(decryptedData);

    NSSCryptoContext_Destroy(cc);
    return PR_SUCCESS;
}

enum {
  cipherAlgID = 0,
  cipherKey,
  cipherPlaintext,
  cipherCiphertext
};

static const char *cipherArgs[] = {
  "ALGID",
  "KEY",
  "PTXT",
  "CTXT"
};

static int numCipherArgs = sizeof(cipherArgs) / sizeof(cipherArgs[0]);

static NSSSymKey *
unwrap_symkey(NSSVolatileDomain *vd, NSSPrivateKey *unwrapKey, 
              NSSAlgNParam *wrapAP,
              NSSSymKeyType keyType, char *value)
{
    NSSSymKey *symKey = NULL;
    NSSItem *wrappedKey;
    wrappedKey = CMD_ConvertHex(value, strlen(value), NULL);
    if (wrappedKey) {
	symKey = NSSVolatileDomain_UnwrapSymKey(vd, wrapAP,
	                                        unwrapKey,
	                                        wrappedKey,
	                                        keyType,
	                                        NULL, 0, 0);
	NSSItem_Destroy(wrappedKey);
    }
    return symKey;
}

PRStatus
SymmetricCipherTests(CMDRunTimeData *rtData, 
                     NSSVolatileDomain *vd,
                     NSSPrivateKey *unwrapKey,
                     NSSAlgNParam *wrapAP)
{
    int arg;
    char *value;
    PRStatus status;
    NSSArena *arena = NULL;
    NSSSymKey *symKey = NULL;
    NSSAlgNParam *ap = NULL;
    NSSItem *plaintext = NULL;
    NSSItem *ciphertext = NULL;
    NSSItem *algID;
    NSSOIDTag alg;
    NSSSymKeyType keyType;
    CMDReadBuf buf;

    buf.start = buf.finish = 0;
    while ((arg = CMD_ReadArgValue(rtData, &buf, &value,
                                   cipherArgs, numCipherArgs)) >= 0) 
    {
	switch (arg) {
	case cipherAlgID:
	    if (symKey || !arena) {
		if (ap) {
		    NSSAlgNParam_Destroy(ap); ap = NULL;
		}
		if (symKey) {
		    NSSSymKey_Destroy(symKey); symKey = NULL;
		}
		if (arena) {
		    NSSArena_Destroy(arena);
		}
		plaintext = NULL;
		ciphertext = NULL;
		/* start a new test */
		arena = NSSArena_Create();
		if (!arena) {
		    CMD_PrintError("memory");
		    goto loser;
		}
	    }
	    algID = CMD_ConvertHex(value, strlen(value), arena);
	    if (!algID) {
		goto loser;
	    }
	    ap = NSSAlgNParam_Decode(algID, arena);
	    NSSItem_Destroy(algID);
	    if (!ap) {
		goto loser;
	    }
	    break;
	case cipherKey:
	    alg = NSSAlgNParam_GetAlgorithm(ap);
	    keyType = NSSOIDTag_GetSymKeyType(alg);
	    symKey = unwrap_symkey(vd, unwrapKey, wrapAP, keyType, value);
	    if (!symKey) {
		goto loser;
	    }
	    break;
	case cipherPlaintext:
	    plaintext = CMD_ConvertHex(value, strlen(value), arena);
	    if (!plaintext) {
		goto loser;
	    }
	    break;
	case cipherCiphertext:
	    ciphertext = CMD_ConvertHex(value, strlen(value), arena);
	    if (!ciphertext) {
		goto loser;
	    }
	    status = EncryptionTest(symKey, ap, plaintext, ciphertext);
	    if (status == PR_SUCCESS) {
		PR_fprintf(PR_STDOUT, "test successful\n");
	    } else {
		PR_fprintf(PR_STDOUT, "test failed\n");
	    }
	    break;
	default:
	    goto loser;
	}
    }

    NSSArena_Destroy(arena);
    return PR_SUCCESS;
loser:
    NSSArena_Destroy(arena);
    return PR_FAILURE;
}

static NSSToken *
GetInternalCryptoToken()
{
/*
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    return NSSTrustDomain_FindTokenByName(td, "NSS Generic Crypto Services");
*/
    return GetSoftwareToken();
}

PRStatus
SelfTest()
{
    PRStatus status;
    NSSVolatileDomain *vd;
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    NSSToken *token = GetInternalCryptoToken();
    CMDRunTimeData rtData;
    NSSPrivateKey *unwrapKey;
    NSSAlgNParam *wrapAP;
    NSSItem *encodedKey;

    status = CMD_SetRunTimeData(UNWRAPPING_KEY_FILE, NULL, "ascii",
                                NULL, "binary", &rtData);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    encodedKey = CMD_GetInput(&rtData);
    CMD_FinishRunTimeData(&rtData);
    if (!encodedKey) {
	PR_fprintf(PR_STDERR, "failed to extract encoded key\n");
	return PR_FAILURE;
    }

    /* create a volatile domain for the temp objects */
    vd = NSSTrustDomain_CreateVolatileDomain(td, NULL);
    if (!vd) {
	CMD_PrintError("failed to create volatile domain");
	return PR_FAILURE;
    }

    /* decode the key in the volatile domain */
    unwrapKey = NSSVolatileDomain_ImportEncodedPrivateKey(vd, encodedKey,
                                                          NSSKeyPairType_RSA, 
							  0, 0, NULL,
                                    CMD_PWCallbackForKeyEncoding(WRAPKEY_PW), 
                                                          token /*, NULL*/);
    NSSItem_Destroy(encodedKey);
    if (!unwrapKey) {
	NSSVolatileDomain_Destroy(vd);
	CMD_PrintError("failed to import unwrapping key");
	return PR_FAILURE;
    }

    status = CMD_SetRunTimeData(SYMKEY_TEST_FILE, NULL, "binary",
                                NULL, "binary", &rtData);
    if (status == PR_FAILURE) {
	NSSPrivateKey_Destroy(unwrapKey);
	return PR_FAILURE;
    }

    wrapAP = NSSOIDTag_CreateAlgNParam(NSS_OID_PKCS1_RSA_ENCRYPTION, 
                                       NULL, NULL);
    if (!wrapAP) {
	NSSPrivateKey_Destroy(unwrapKey);
	CMD_PrintError("failed to create alg/param for unwrap");
	return PR_FAILURE;
    }

    status = SymmetricCipherTests(&rtData, vd, unwrapKey, wrapAP);
    return status;
}

PRStatus
CreateASelfTest(char *cipher, int keysize, char *input)
{
    PRStatus status;
    NSSVolatileDomain *vd;
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    CMDRunTimeData rtData;
    NSSAlgNParam *ap, *wrapAP;
    NSSSymKey *symKey;
    NSSItem *wrappedKey, *algID, plaintext, *ciphertext;
    NSSToken *token = GetInternalCryptoToken();
    NSSCert *wrapCert;
    NSSItem *encodedCert;

    plaintext.data = input; plaintext.size = strlen(input);

    status = CMD_SetRunTimeData(WRAPPING_CERT_FILE, NULL, "ascii",
                                NULL, "binary", &rtData);
    if (status == PR_FAILURE) {
	return PR_FAILURE;
    }
    encodedCert = CMD_GetInput(&rtData);
    CMD_FinishRunTimeData(&rtData);
    if (!encodedCert) {
	PR_fprintf(PR_STDERR, "failed to extract encoded cert\n");
	return PR_FAILURE;
    }

    /* create a volatile domain for the temp objects */
    vd = NSSTrustDomain_CreateVolatileDomain(td, NULL);
    if (!vd) {
	CMD_PrintError("failed to create volatile domain");
	return PR_FAILURE;
    }

    /* import the cert into the volatile domain */
    wrapCert = NSSVolatileDomain_ImportEncodedCert(vd, encodedCert, 
                                                   NULL, NULL);
    NSSItem_Destroy(encodedCert);
    if (!wrapCert) {
	NSSVolatileDomain_Destroy(vd);
	CMD_PrintError("failed to import wrapping cert");
	return PR_FAILURE;
    }

    status = CMD_SetRunTimeData(NULL, NULL, "binary",
                                NULL, "binary", &rtData);
    if (status == PR_FAILURE) {
	NSSCert_Destroy(wrapCert);
	return PR_FAILURE;
    }

    wrapAP = NSSOIDTag_CreateAlgNParam(NSS_OID_PKCS1_RSA_ENCRYPTION, 
                                       NULL, NULL);
    if (!wrapAP) {
	NSSCert_Destroy(wrapCert);
	CMD_PrintError("failed to create alg/param for unwrap");
	return PR_FAILURE;
    }

    ap = GetSymKeyGenAP(cipher);
    if (!ap) {
	return PR_FAILURE;
    }

    symKey = NSSVolatileDomain_GenerateSymKey(vd, ap, keysize, NULL,
                                              0, 0, token, NULL);
    NSSAlgNParam_Destroy(ap);
    if (!symKey) {
	CMD_PrintError("failed to generate symkey");
	return PR_FAILURE;
    }

    ap = GetSymCipherAP(cipher, NULL); /* generate the IV */
    if (!ap) {
	return PR_FAILURE;
    }

    ciphertext = NSSSymKey_Encrypt(symKey, ap, &plaintext, NULL, NULL, NULL);
    if (!ciphertext) {
	CMD_PrintError("encryption failed\n");
	return PR_FAILURE;
    }

    wrappedKey = NSSCert_WrapSymKey(wrapCert, wrapAP, symKey, 
                                    NSSTime_Now(), NULL, NULL,
                                    NULL, NULL, NULL);

    algID = NSSAlgNParam_Encode(ap, NULL, NULL);

    CMD_WriteArgValue(&rtData, cipherArgs[cipherAlgID], 
                      algID, CMDFileMode_Hex);
    CMD_WriteArgValue(&rtData, cipherArgs[cipherKey], 
                      wrappedKey, CMDFileMode_Hex);
    CMD_WriteArgValue(&rtData, cipherArgs[cipherPlaintext], 
                      &plaintext, CMDFileMode_Hex);
    CMD_WriteArgValue(&rtData, cipherArgs[cipherCiphertext], 
                      ciphertext, CMDFileMode_Hex);

    return PR_SUCCESS;
}

