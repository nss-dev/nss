
#include <string.h>

#include "cipher.h"

PRStatus
Test1()
{
    PRStatus status;
    char *message = "Test Message 1";
    char *iv = "abcdefgh";
    NSSPrivateKey *privateKey = NULL;
    NSSPublicKey *publicKey = NULL;
    NSSSymmetricKey *symKey = NULL;
    NSSItem data, *encryptedData, *decryptedData;
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    NSSCryptoContext *cc;
    NSSToken *softoken = GetSoftwareToken();
    NSSAlgorithmAndParameters *desEncrypt;
    NSSAlgorithmAndParameters *rsaKeyGen;
    const NSSAlgorithmAndParameters *desKeyGen = 
                                       NSSAlgorithmAndParameters_DESKeyGen;
    NSSParameters params;

    /* 0a. Set up parameters for DES encryption */
    params.des.iv.data = iv;
    params.des.iv.size = strlen(iv);
    desEncrypt = NSSAlgorithmAndParameters_Create(NULL, 
                                                  NSSAlgorithmType_DES, 
                                                  &params);
    if (!desEncrypt) {
	fprintf(stderr, "Failed to create algorithm and parameters.\n");
	return PR_FAILURE;
    }

    /* 0b. Set up parameters for RSA keygen */
    params.rsakg.modulusBits = 1024;
    params.rsakg.publicExponent = 65537;
    rsaKeyGen = NSSAlgorithmAndParameters_CreateKeyGen(NULL, 
                                                       NSSAlgorithmType_RSA, 
                                                       &params);
    if (!rsaKeyGen) {
	fprintf(stderr, "Failed to create algorithm and parameters.\n");
	return PR_FAILURE;
    }

    /* 1. Generate an RSA key pair in the default trust domain */
    status = NSSTrustDomain_GenerateKeyPair(td, rsaKeyGen, 
                                            &publicKey, &privateKey,
                                            "Test1 Key Pair", 0, 0,
                                            softoken, NULL);
    if (status == PR_SUCCESS) {
	printf("Generated RSA key pair in trust domain.\n");
    } else {
	fprintf(stderr, "Failed to generate key pair.\n");
	return PR_FAILURE;
    }

    /* 2. Create a crypto context for DES encryption */
    cc = NSSTrustDomain_CreateCryptoContext(td, desEncrypt, NULL);
    if (cc) {
	printf("Created crypto context for DES encryption.\n");
    } else {
	fprintf(stderr, "Failed to create crypto context.\n");
	return PR_FAILURE;
    }

    /* 3. Generate a DES key in the crypto context */
    symKey = NSSCryptoContext_GenerateSymmetricKey(cc, desKeyGen, 0,
                                                   softoken, NULL);
    if (symKey) {
	printf("Generated symmetric key in crypto context.\n");
    } else {
	fprintf(stderr, "Failed to generate symmetric key.\n");
	return PR_FAILURE;
    }

    /* 4. Encrypt with the DES key and iv */
    data.data = message;
    data.size = strlen(message) + 1;
    encryptedData = NSSCryptoContext_Encrypt(cc, NULL, &data, 
                                             NULL, NULL, NULL);
    if (status == PR_SUCCESS) {
	printf("Encrypted message.\n");
    } else {
	fprintf(stderr, "Encryption failed.\n");
	return PR_FAILURE;
    }

    /* 5. Decrypt same */
    decryptedData = NSSSymmetricKey_Decrypt(symKey, desEncrypt, 
                                            encryptedData,
                                            NULL, NULL, NULL);
    if (status == PR_SUCCESS) {
	printf("Decrypted message.\n");
    } else {
	fprintf(stderr, "Decryption failed.\n");
	return PR_FAILURE;
    }

    /* 6. Compare results */
    if (NSSItem_Equal(&data, decryptedData, NULL)) {
	printf("Results matched.\n");
    } else {
	fprintf(stderr, "Results did not match.\n");
    }

    NSSItem_Destroy(encryptedData);
    NSSItem_Destroy(decryptedData);
    NSSAlgorithmAndParameters_Destroy(desEncrypt);
    NSSAlgorithmAndParameters_Destroy(rsaKeyGen);
    NSSSymmetricKey_Destroy(symKey);
    NSSPublicKey_Destroy(publicKey);
    NSSPrivateKey_Destroy(privateKey);
    NSSCryptoContext_Destroy(cc);

    return status;
}

