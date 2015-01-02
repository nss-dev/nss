/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* NSPR Headers */
#include <prthread.h>
#include <plgetopt.h>
#include <prerror.h>
#include <prinit.h>
#include <prlog.h>
#include <prtypes.h>
#include <plstr.h>

/* NSS headers */
#include <keyhi.h>
#include <pk11priv.h>

/* our samples utilities */
#include "util.h"

#define BUFFERSIZE            80
#define DIGESTSIZE            16
#define PTEXT_MAC_BUFFER_SIZE 96
#define CIPHERSIZE            96
#define BLOCKSIZE             32
#define DEFAULT_KEY_BITS      1024


#define CIPHER_HEADER         "-----BEGIN CIPHER-----"
#define CIPHER_TRAILER        "-----END CIPHER-----"
#define ENCKEY_HEADER         "-----BEGIN WRAPPED ENCKEY-----"
#define ENCKEY_TRAILER        "-----END WRAPPED ENCKEY-----"
#define MACKEY_HEADER         "-----BEGIN WRAPPED MACKEY-----"
#define MACKEY_TRAILER        "-----END WRAPPED MACKEY-----"
#define IV_HEADER             "-----BEGIN IV-----"
#define IV_TRAILER            "-----END IV-----"
#define MAC_HEADER            "-----BEGIN MAC-----"
#define MAC_TRAILER           "-----END MAC-----"
#define PAD_HEADER            "-----BEGIN PAD-----"
#define PAD_TRAILER           "-----END PAD-----"
#define LAB_HEADER            "-----BEGIN KEY LABEL-----"
#define LAB_TRAILER           "-----END KEY LABEL-----"

typedef enum {
    GENWRAPKEY,
    ENCRYPT,
    DECRYPT,
    UNKNOWN
} CommandType;

typedef enum {
   SYMKEY = 0,
   MACKEY = 1,
   IV     = 2,
   MAC    = 3,
   PAD    = 4,
   LAB    = 5
} HeaderType;


/*
 * Print usage message and exit
 */
static void
Usage(const char *progName)
{
    fprintf(stderr, "\nUsage:  %s -c <a|b|c> -d <dbdirpath> [-z <noisefilename>] "
            "[-p <dbpwd> | -f <dbpwdfile>] -i <ipfilename> -o <opfilename> -k <keyLabel>\n\n",
            progName);
    fprintf(stderr, "%-20s  Specify 'a' for generating RSA keypair for wrapping\n\n",
             "-c <a|b|c>");
    fprintf(stderr, "%-20s  Specify 'b' for encrypt operation\n\n",
             " ");
    fprintf(stderr, "%-20s  Specify 'c' for decrypt operation\n\n",
             " ");
    fprintf(stderr, "%-20s  Specify db directory path\n\n",
             "-d <dbdirpath>");
    fprintf(stderr, "%-20s  Specify db password [optional]\n\n",
             "-p <dbpwd>");
    fprintf(stderr, "%-20s  Specify db password file [optional]\n\n",
             "-f <dbpwdfile>");
    fprintf(stderr, "%-20s  Specify noise file name [optional]\n\n",
             "-z <noisefilename>");
    fprintf(stderr, "%-21s Specify an input file name\n\n",
             "-i <ipfilename>");
    fprintf(stderr, "%-21s Specify an output file name\n\n",
             "-o <opfilename>");
    fprintf(stderr, "%-21s Specify a nick name for the RSA wrapping key\n\n",
             "-k <keyLabel>");
    fprintf(stderr, "%-7s For encrypt, it takes <ipfilename> as an input file and produces\n",
             "Note :");
    fprintf(stderr, "%-7s <ipfilename>.enc and <ipfilename>.header as intermediate output files.\n\n",
             "");
    fprintf(stderr, "%-7s For decrypt, it takes <ipfilename>.enc and <ipfilename>.header\n",
             "");
    fprintf(stderr, "%-7s as input files and produces <opfilename> as a final output file.\n\n",
             "");
    exit(-1);
}

/*
 * Wrap the symkey using public key
 */
SECStatus
WrapKey(PK11SymKey* key, SECKEYPublicKey *pubKey, SECItem **wrappedKey)
{
    SECStatus rv;
    SECItem *data = (SECItem *)PORT_ZAlloc(sizeof(SECItem));

    if (!data) {
        PR_fprintf(PR_STDERR, "Error while allocating memory\n");
        rv = SECFailure;
        goto cleanup;
    }

    data->len = SECKEY_PublicKeyStrength(pubKey);
    data->data = (unsigned char*)PORT_ZAlloc((data->len)*sizeof(unsigned int));

    if (!data->data) {
        PR_fprintf(PR_STDERR, "Error while allocating memory\n");
        rv = SECFailure;
        goto cleanup;
    }
    
    rv = PK11_PubWrapSymKey(CKM_RSA_PKCS, pubKey, key, data);
    if (rv != SECSuccess) {
        rv = SECFailure;
    } else {
        *wrappedKey = data;
        return SECSuccess;
    }

cleanup:
    if (data) {
        SECITEM_FreeItem(data, PR_TRUE);
    }
    return rv;
}

/*
 * Generate a Symmetric Key
 */
PK11SymKey *
GenerateSYMKey(PK11SlotInfo  *slot, CK_MECHANISM_TYPE mechanism,
               int keySize, SECItem *keyID, secuPWData *pwdata)
{
    SECStatus      rv;
    PK11SymKey    *key;

    if (PK11_NeedLogin(slot)) {
        rv = PK11_Authenticate(slot, PR_TRUE, pwdata);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "Could not authenticate to token %s.\n",
                       PK11_GetTokenName(slot));
            return NULL;
        }
    }

    /* Generate the symmetric key */
    key = PK11_TokenKeyGen(slot, mechanism,
                           NULL, keySize, keyID, PR_FALSE, pwdata);

    if (!key) {
        PR_fprintf(PR_STDERR, "Symmetric Key Generation Failed \n");
    }

    return key;
}

/*
 * MacInit
 */
SECStatus
MacInit(PK11Context *ctx)
{
    SECStatus rv = PK11_DigestBegin(ctx);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Compute MAC Failed : PK11_DigestBegin()\n");
    }
    return rv;
}

/*
 * MacUpdate
 */
SECStatus
MacUpdate(PK11Context *ctx,
          unsigned char *msg, unsigned int msgLen)
{
    SECStatus rv = PK11_DigestOp(ctx, msg, msgLen);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Compute MAC Failed : DigestOp()\n");
    }
    return rv;
}

/*
 * Finalize MACing
 */
SECStatus
MacFinal(PK11Context *ctx,
         unsigned char *mac, unsigned int *macLen, unsigned int maxLen)
{
    SECStatus rv = PK11_DigestFinal(ctx, mac, macLen, maxLen);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Compute MAC Failed : PK11_DigestFinal()\n");
    }
    return SECSuccess;
}

/*
 * Compute Mac
 */
SECStatus
ComputeMac(PK11Context *ctxmac,
           unsigned char *ptext, unsigned int ptextLen,
           unsigned char *mac, unsigned int *macLen,
           unsigned int maxLen)
{
    SECStatus rv = MacInit(ctxmac);
    if (rv != SECSuccess) return rv;
    rv = MacUpdate(ctxmac, ptext, ptextLen);
    if (rv != SECSuccess) return rv;
    rv = MacFinal(ctxmac, mac, macLen, maxLen);
    return rv;
}

/*
 * WriteToHeaderFile
 */
SECStatus
WriteToHeaderFile(const char *buf, unsigned int len, HeaderType type,
                  PRFileDesc *outFile)
{
    SECStatus      rv;
    char           header[40];
    char           trailer[40];

    switch (type) { 
    case SYMKEY:
        strcpy(header, ENCKEY_HEADER); 
        strcpy(trailer, ENCKEY_TRAILER); 
        break;
    case MACKEY:
        strcpy(header, MACKEY_HEADER); 
        strcpy(trailer, MACKEY_TRAILER); 
        break;
    case IV:
        strcpy(header, IV_HEADER); 
        strcpy(trailer, IV_TRAILER); 
        break;
    case MAC:
        strcpy(header, MAC_HEADER);
        strcpy(trailer, MAC_TRAILER);
        break;
    case PAD:
        strcpy(header, PAD_HEADER);
        strcpy(trailer, PAD_TRAILER);
        break;
    case LAB:
        strcpy(header, LAB_HEADER);
        strcpy(trailer, LAB_TRAILER);
        PR_fprintf(outFile, "%s\n", header);
        PR_fprintf(outFile, "%s\n", buf); 
        PR_fprintf(outFile, "%s\n\n", trailer);
        return SECSuccess;
        break;
    }

    PR_fprintf(outFile, "%s\n", header);
    PrintAsHex(outFile, buf, len);
    PR_fprintf(outFile, "%s\n\n", trailer);
    return SECSuccess;
}

/*
 * Initialize for encryption or decryption - common code
 */
PK11Context *
CryptInit(PK11SymKey *key,
          unsigned char *iv, unsigned int ivLen,
          CK_MECHANISM_TYPE type, CK_ATTRIBUTE_TYPE operation)
{
    SECItem ivItem = { siBuffer, iv, ivLen };
    PK11Context *ctx = NULL;

    SECItem *secParam = PK11_ParamFromIV(type, &ivItem);
    if (secParam == NULL) {
        PR_fprintf(PR_STDERR, "Crypt Failed : secParam NULL\n");
        return NULL;
    }
    ctx = PK11_CreateContextBySymKey(type, operation, key, secParam);
    if (ctx == NULL) {
        PR_fprintf(PR_STDERR, "Crypt Failed : can't create a context\n");
        goto cleanup;

    }
cleanup:
    if (secParam) {
        SECITEM_FreeItem(secParam, PR_TRUE);
    }
    return ctx;
}

/*
 * Common encryption and decryption code
 */
SECStatus
Crypt(PK11Context *ctx,
      unsigned char *out, unsigned int *outLen, unsigned int maxOut,
      unsigned char *in, unsigned int inLen)
{
    SECStatus rv;

    rv = PK11_CipherOp(ctx, out, outLen, maxOut, in, inLen);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Crypt Failed : PK11_CipherOp returned %d\n", rv);
        goto cleanup;
    }

cleanup:
    if (rv != SECSuccess) {
        return rv;
    }
    return SECSuccess;
}

/*
 * Decrypt
 */
SECStatus
Decrypt(PK11Context *ctx,
        unsigned char *out, unsigned int *outLen, unsigned int maxout,
        unsigned char *in, unsigned int inLen)
{
    return Crypt(ctx, out, outLen, maxout, in, inLen);
}

/*
 * Encrypt
 */
SECStatus
Encrypt(PK11Context* ctx,
        unsigned char *out, unsigned int *outLen, unsigned int maxout,
        unsigned char *in, unsigned int inLen)
{
    return Crypt(ctx, out, outLen, maxout, in, inLen);
}

/*
 * EncryptInit
 */
PK11Context *
EncryptInit(PK11SymKey *ek, unsigned char *iv, unsigned int ivLen,
            CK_MECHANISM_TYPE type)
{
    return CryptInit(ek, iv, ivLen, type, CKA_ENCRYPT);
}

/*
 * DecryptInit
 */
PK11Context *
DecryptInit(PK11SymKey *dk, unsigned char *iv, unsigned int ivLen,
            CK_MECHANISM_TYPE type)
{
    return CryptInit(dk, iv, ivLen, type, CKA_DECRYPT);
}

/*
 * Read cryptographic parameters from the header file
 */
SECStatus
ReadFromHeaderFile(const char *fileName, HeaderType type,
                   SECItem *item, PRBool isHexData)
{
    SECStatus      rv;
    PRFileDesc*    file;
    SECItem        filedata;
    SECItem        outbuf;
    unsigned char *nonbody;
    unsigned char *body;
    char           header[40];
    char           trailer[40];

    outbuf.type = siBuffer;
    file = PR_Open(fileName, PR_RDONLY, 0);
    if (!file) {
        PR_fprintf(PR_STDERR, "Failed to open %s\n", fileName);
        return SECFailure;
    }
    switch (type) {
    case SYMKEY:
        strcpy(header, ENCKEY_HEADER);
        strcpy(trailer, ENCKEY_TRAILER);
        break;
    case MACKEY:
        strcpy(header, MACKEY_HEADER);
        strcpy(trailer, MACKEY_TRAILER);
        break;
    case IV:
        strcpy(header, IV_HEADER);
        strcpy(trailer, IV_TRAILER);
        break;
    case MAC:
        strcpy(header, MAC_HEADER);
        strcpy(trailer, MAC_TRAILER);
        break;
    case PAD:
        strcpy(header, PAD_HEADER);
        strcpy(trailer, PAD_TRAILER);
        break;
    case LAB:
        strcpy(header, LAB_HEADER);
        strcpy(trailer, LAB_TRAILER);
        break;
    }

    rv = FileToItem(&filedata, file);
    nonbody = (char *)filedata.data;
    if (!nonbody) {
        PR_fprintf(PR_STDERR, "unable to read data from input file\n");
        rv = SECFailure;
        goto cleanup;
    }

    /* check for headers and trailers and remove them */
    if ((body = strstr(nonbody, header)) != NULL) {
        char *trail = NULL;
        nonbody = body;
        body = PORT_Strchr(body, '\n');
        if (!body)
            body = PORT_Strchr(nonbody, '\r'); /* maybe this is a MAC file */
        if (body)
            trail = strstr(++body, trailer);
        if (trail != NULL) {
            *trail = '\0';
        } else {
            PR_fprintf(PR_STDERR,  "input has header but no trailer\n");
            PORT_Free(filedata.data);
            return SECFailure;
        }
    } else {
        body = nonbody;
    }

cleanup:
    PR_Close(file);
    HexToBuf(body, item, isHexData);
    return SECSuccess;
}

/*
 * EncryptAndMac
 */
SECStatus
EncryptAndMac(PRFileDesc *inFile,
              PRFileDesc *headerFile,
              PRFileDesc *encFile,
              PK11SymKey *ek,
              PK11SymKey *mk,
              unsigned char *iv, unsigned int ivLen,
              PRBool ascii)
{   
    SECStatus      rv;
    unsigned char  ptext[BLOCKSIZE];
    unsigned int   ptextLen;
    unsigned char  mac[DIGESTSIZE];
    unsigned int   macLen;
    unsigned int   nwritten;
    unsigned char  encbuf[BLOCKSIZE];
    unsigned int   encbufLen;
    SECItem        noParams = { siBuffer, NULL, 0 };
    PK11Context   *ctxmac = NULL;
    PK11Context   *ctxenc = NULL;
    unsigned int   pad[1];
    SECItem        padItem;
    unsigned int   paddingLength;

    static unsigned int firstTime = 1;
    int j;

    ctxmac = PK11_CreateContextBySymKey(CKM_MD5_HMAC, CKA_SIGN, mk, &noParams);
    if (ctxmac == NULL) {
        PR_fprintf(PR_STDERR, "Can't create MAC context\n");
        rv = SECFailure;
        goto cleanup;
    }
    rv = MacInit(ctxmac);
    if (rv != SECSuccess) {
        goto cleanup;
    }

    ctxenc = EncryptInit(ek, iv, ivLen, CKM_AES_CBC);

    /* read a buffer of plaintext from input file */
    while ((ptextLen = PR_Read(inFile, ptext, sizeof(ptext))) > 0) {

        /* Encrypt using it using CBC, using previously created IV */
        if (ptextLen != BLOCKSIZE) {
            paddingLength = BLOCKSIZE - ptextLen;
            for ( j=0; j < paddingLength; j++) {
                ptext[ptextLen+j] = (unsigned char)paddingLength;
            }
            ptextLen = BLOCKSIZE;
        }
        rv  = Encrypt(ctxenc,
                encbuf, &encbufLen, sizeof(encbuf),
                ptext, ptextLen);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "Encrypt Failure\n");
            goto cleanup;
        }

        /* save the last block of ciphertext as the next IV */
        iv = encbuf;
        ivLen = encbufLen;

        /* write the cipher text to intermediate file */
        nwritten = PR_Write(encFile, encbuf, encbufLen);
        /*PR_Assert(nwritten == encbufLen);*/

        rv = MacUpdate(ctxmac, ptext, ptextLen);
    }

    rv = MacFinal(ctxmac, mac, &macLen, DIGESTSIZE);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "MacFinal Failure\n");
        goto cleanup;
    }
    if (macLen == 0) {
        PR_fprintf(PR_STDERR, "Bad MAC length\n");
        rv = SECFailure;
        goto cleanup;
    }
    WriteToHeaderFile(mac, macLen, MAC, headerFile);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Write MAC Failure\n");
        goto cleanup;
    }

    pad[0] = paddingLength;
    padItem.type = siBuffer;
    padItem.data = (unsigned char *)pad;
    padItem.len  = sizeof(pad[0]);

    WriteToHeaderFile(padItem.data, padItem.len, PAD, headerFile);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Write PAD Failure\n");
        goto cleanup;
    }

    rv = SECSuccess;

cleanup:
    if (ctxmac != NULL) {
        PK11_DestroyContext(ctxmac, PR_TRUE);
    }
    if (ctxenc != NULL) {
        PK11_DestroyContext(ctxenc, PR_TRUE);
    }

    return rv;
}

/*
 * Decrypt and Verify MAC
 */
SECStatus
DecryptAndVerifyMac(const char* outFileName,
    char *encryptedFileName,
    SECItem *cItem, SECItem *macItem,
    PK11SymKey* ek, PK11SymKey* mk, SECItem *ivItem, SECItem *padItem)
{
    SECStatus      rv;
    PRFileDesc*    inFile;
    PRFileDesc*    outFile;

    unsigned char  decbuf[64];
    unsigned int   decbufLen;

    unsigned char  ptext[BLOCKSIZE];
    unsigned int   ptextLen = 0;
    unsigned char  ctext[64];
    unsigned int   ctextLen;
    unsigned char  newmac[DIGESTSIZE];
    unsigned int   newmacLen                 = 0;
    unsigned int   newptextLen               = 0;
    unsigned int   count                     = 0;
    unsigned int   temp                      = 0;
    unsigned int   blockNumber               = 0;
    SECItem        noParams = { siBuffer, NULL, 0 };
    PK11Context   *ctxmac = NULL;
    PK11Context   *ctxenc = NULL;

    unsigned char iv[BLOCKSIZE];
    unsigned int ivLen = ivItem->len;
    unsigned int fileLength;
    unsigned int paddingLength;
    int j;

    memcpy(iv, ivItem->data, ivItem->len);
    paddingLength = (unsigned int)padItem->data[0];

    ctxmac = PK11_CreateContextBySymKey(CKM_MD5_HMAC, CKA_SIGN, mk, &noParams);
    if (ctxmac == NULL) {
        PR_fprintf(PR_STDERR, "Can't create MAC context\n");
        rv = SECFailure;
        goto cleanup;
    }

    /*  Open the input file.  */
    inFile = PR_Open(encryptedFileName, PR_RDONLY , 0);
    if (!inFile) {
        PR_fprintf(PR_STDERR,
                   "Unable to open \"%s\" for writing.\n",
                   encryptedFileName);
        return SECFailure;
    }
    /*  Open the output file.  */
    outFile = PR_Open(outFileName,
                      PR_CREATE_FILE | PR_TRUNCATE | PR_RDWR , 00660);
    if (!outFile) {
        PR_fprintf(PR_STDERR,
                   "Unable to open \"%s\" for writing.\n",
                   outFileName);
        return SECFailure;
    }

    rv = MacInit(ctxmac);
    if (rv != SECSuccess) goto cleanup;

    ctxenc = DecryptInit(ek, iv, ivLen, CKM_AES_CBC);
    fileLength = FileSize(encryptedFileName);

    while ((ctextLen = PR_Read(inFile, ctext, sizeof(ctext))) > 0) {

        count += ctextLen;
        
        /* decrypt cipher text buffer using CBC and IV */

        rv = Decrypt(ctxenc, decbuf, &decbufLen, sizeof(decbuf),
                     ctext, ctextLen);

        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "Decrypt Failure\n");
            goto cleanup;
        }

        if (decbufLen == 0) break;

        rv = MacUpdate(ctxmac, decbuf, decbufLen);
        if (rv != SECSuccess) { goto cleanup; }
        if (count == fileLength) {
            decbufLen = decbufLen-paddingLength;
        }

        /* write the plain text to out file */
        temp = PR_Write(outFile, decbuf, decbufLen);
        if (temp != decbufLen) {
            PR_fprintf(PR_STDERR, "write error\n");
            rv = SECFailure;
            break;
        }

        /* save last block of ciphertext */
        memcpy(iv, decbuf, decbufLen);
        ivLen = decbufLen;
        blockNumber++;
    }

    if (rv != SECSuccess) { goto cleanup; }

    rv = MacFinal(ctxmac, newmac, &newmacLen, sizeof(newmac));
    if (rv != SECSuccess) { goto cleanup; }

    if (PORT_Memcmp(macItem->data, newmac, newmacLen) == 0) {
        rv = SECSuccess;
    } else {
        PR_fprintf(PR_STDERR, "Check MAC : Failure\n");
        PR_fprintf(PR_STDERR, "Extracted : ");
        PrintAsHex(PR_STDERR, macItem->data, macItem->len);
        PR_fprintf(PR_STDERR, "Computed  : ");
        PrintAsHex(PR_STDERR, newmac, newmacLen);
        rv = SECFailure;
    }
cleanup:
    if (ctxmac) {
        PK11_DestroyContext(ctxmac, PR_TRUE);
    }
    if (ctxenc) {
        PK11_DestroyContext(ctxenc, PR_TRUE);
    }
    if (outFile) {
        PR_Close(outFile);
    }

    return rv;
}

/*
 * Gets IV, Key label, wrapped AES key and wrapped MAC key
 */
SECStatus
GetParametersFromHeader(const char *cipherFileName, SECItem *keyLabelItem,
            SECItem *ivItem, SECItem *wrappedEncKeyItem, SECItem *wrappedMacKeyItem)
{
    SECStatus      rv;

    /* open intermediate file, read in header, get IV, Key label,
     * wrapped AES key and wrapped MAC key from it
     */
    rv = ReadFromHeaderFile(cipherFileName, IV, ivItem, PR_TRUE);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Could not retrieve IV from cipher file\n");
        goto cleanup;
    }

    rv = ReadFromHeaderFile(cipherFileName, SYMKEY, wrappedEncKeyItem, PR_TRUE);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR,
        "Could not retrieve wrapped AES key from cipher file\n");
        goto cleanup;
    }
    rv = ReadFromHeaderFile(cipherFileName, MACKEY, wrappedMacKeyItem, PR_TRUE);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR,
            "Could not retrieve wrapped MAC key from cipher file\n");
        goto cleanup;
    }
    rv = ReadFromHeaderFile(cipherFileName, LAB, keyLabelItem, PR_FALSE);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR,
        "Could not retrieve key label from cipher file\n");
        goto cleanup;
    }
cleanup:
    return rv;
}

SECKEYPrivateKey *
GetRSAPrivateKey(PK11SlotInfo *slot,
                const char   *dbdir,
                secuPWData   *pwdata,
                const char   *keyLabel)
{
    SECKEYPrivateKeyList     *list;
    SECKEYPrivateKeyListNode *node;
    SECKEYPrivateKey         *privKey   = NULL;
    char                     *keyName   = NULL;

    if (slot == NULL) {
        fprintf(stderr, "Empty Slot\n");
        goto cleanup;
    }
    if (PK11_Authenticate(slot, PR_TRUE, pwdata) != SECSuccess) {
        fprintf(stderr, "could not authenticate to token %s.",
                PK11_GetTokenName(slot));
        goto cleanup;
    }

    list = PK11_ListPrivKeysInSlot(slot, (char *)keyLabel, pwdata);
    if (list == NULL) {
        fprintf(stderr, "problem listing keys\n");
        goto cleanup;
    }
    for (node=PRIVKEY_LIST_HEAD(list);
         !PRIVKEY_LIST_END(node,list);
         node=PRIVKEY_LIST_NEXT(node)) {
        keyName = PK11_GetPrivateKeyNickname(node->key);
        if (!keyName || PL_strcmp(keyName,keyLabel)) {
            PORT_Free((void *)keyName);
            continue;
        } else {
            privKey = SECKEY_CopyPrivateKey(node->key);
            break;
        }
    }
cleanup:
    if (list) {
        SECKEY_DestroyPrivateKeyList(list);
    }
    if (keyName) {
        PORT_Free((void *)keyName);
    }
    return privKey;
}


/*
 * DecryptFile
 */
SECStatus
DecryptFile(PK11SlotInfo *slot,
             const char   *dbdir,
             const char   *outFileName,
             const char   *headerFileName,
             char         *encryptedFileName,
             secuPWData   *pwdata,
             PRBool       ascii)
{
    /*
     * The DB is open read only and we have authenticated to it
     * open input file, read in header, get IV and CKA_IDs of two keys from it
     * find those keys in the DB token
     * Open output file
     * loop until EOF(input):
     *     read a buffer of ciphertext from input file,
     *     Save last block of ciphertext
     *     decrypt ciphertext buffer using CBC and IV,
     *     compute and check MAC, then remove MAC from plaintext
     *     replace IV with saved last block of ciphertext
     *     write the plain text to output file
     * close files
     * report success
     */

    SECStatus           rv;
    SECItem             ivItem;
    SECItem             wrappedEncKeyItem;
    SECItem             wrappedMacKeyItem;
    SECItem             cipherItem;
    SECItem             macItem;
    SECItem             padItem;
    SECItem             keyLabelItem;
    PK11SymKey         *encKey              = NULL;
    PK11SymKey         *macKey              = NULL;
    SECKEYPrivateKey   *privKey             = NULL;


    /* open intermediate file, read in header, get IV and CKA_IDs of two keys
     * from it
     */
    rv = GetParametersFromHeader(headerFileName, &keyLabelItem,
               &ivItem, &wrappedEncKeyItem, &wrappedMacKeyItem);
    if (rv != SECSuccess) {
        goto cleanup;
    }

    /* find those keys in the DB token */
    privKey = GetRSAPrivateKey(slot, dbdir, pwdata, keyLabelItem.data); 
    if (privKey == NULL) {
        PR_fprintf(PR_STDERR, "Can't find private key\n");
        rv = SECFailure;
        goto cleanup;
    }

    encKey = PK11_PubUnwrapSymKey(privKey, &wrappedEncKeyItem, 
                                  CKM_AES_CBC, CKA_ENCRYPT, 0);
    if (encKey == NULL) {
        PR_fprintf(PR_STDERR, "Can't unwrap the encryption key\n");
        rv = SECFailure;
        goto cleanup;
    }

    /* CKM_MD5_HMAC or CKM_EXTRACT_KEY_FROM_KEY */
    macKey = PK11_PubUnwrapSymKey(privKey, &wrappedMacKeyItem, 
                                  CKM_MD5_HMAC, CKA_SIGN, 160/8);
    if (macKey == NULL) {
        PR_fprintf(PR_STDERR, "Can't unwrap the Mac key\n");
        rv = SECFailure;
        goto cleanup;
    }

    /* Read in the Mac into item from the intermediate file */
    rv = ReadFromHeaderFile(headerFileName, MAC, &macItem, PR_TRUE);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR,
                   "Could not retrieve MAC from cipher file\n");
        goto cleanup;
    }
    if (macItem.data == NULL) {
        PR_fprintf(PR_STDERR, "MAC has NULL data\n");
        rv = SECFailure;
        goto cleanup;
    }
    if (macItem.len == 0) {
        PR_fprintf(PR_STDERR, "MAC has data has 0 length\n");
        /*rv = SECFailure;
        goto cleanup;*/
    }

    rv = ReadFromHeaderFile(headerFileName, PAD, &padItem, PR_TRUE);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Could not retrieve PAD detail from header file\n");
        goto cleanup;
    }

    if (rv == SECSuccess) {
        /* Decrypt and Remove Mac */
        rv = DecryptAndVerifyMac(outFileName, encryptedFileName,
                &cipherItem, &macItem, encKey, macKey, &ivItem, &padItem);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "Failed while decrypting and removing MAC\n");
        }
    }

cleanup:
    if (slot) {
        PK11_FreeSlot(slot);
    }
    if (encKey) {
        PK11_FreeSymKey(encKey);
    }
    if (macKey) {
        PK11_FreeSymKey(macKey);
    }
    if (privKey) {
        SECKEY_DestroyPrivateKey(privKey);
    }
    return rv;
}

/*
 * GenerateWrappingKey
 */
SECStatus
GenerateWrappingKey(PK11SlotInfo     *slot,
             const char       *dbdir,
             const char       *keyLabel,
             const char       *noiseFileName,
             secuPWData       *pwdata)
{
    SECKEYPrivateKey   *privKey                = NULL;
    SECKEYPublicKey    *pubKey                 = NULL;
    PK11RSAGenParams    rsaparams;
    void               *params;
    int                 publicExponent         = 0x010001;
    int                 keysize                = DEFAULT_KEY_BITS;
    unsigned char       randbuf[BLOCKSIZE+1];
    SECStatus           rv;

    if (slot == NULL) {
        rv = SECFailure;
        goto cleanup;
    }
    if (PK11_Authenticate(slot, PR_TRUE, pwdata) != SECSuccess) {
        rv = SECFailure;
        goto cleanup;
    }
    if (noiseFileName) {
        rv = SeedFromNoiseFile(noiseFileName);
        if (rv != SECSuccess) {
            PORT_SetError(PR_END_OF_FILE_ERROR);
            fprintf(stderr, "Error while generating the random numbers\n");
            rv = SECFailure;
            goto cleanup;
        }
    } else {
        rv = GenerateRandom(randbuf, BLOCKSIZE);
        if (rv != SECSuccess) {
            fprintf(stderr, "Error while generating the random numbers\n");
            rv = SECFailure;
            goto cleanup;
        }
        PK11_RandomUpdate(randbuf, BLOCKSIZE);
    }
    rsaparams.keySizeInBits = keysize;
    rsaparams.pe            = publicExponent;
    params                  = &rsaparams;
    fprintf(stderr, "\n\n");
    fprintf(stderr, "Generating key.  This may take a few moments...\n\n");
    privKey = PK11_GenerateKeyPair(slot, CKM_RSA_PKCS_KEY_PAIR_GEN, params, &pubKey,
                                   PR_TRUE /*isPerm*/, PR_TRUE /*isSensitive*/,
                                   pwdata);
    if (privKey != NULL) {
        rv = PK11_SetPrivateKeyNickname(privKey, keyLabel);
        if (rv != SECSuccess) {
            fprintf(stderr, "Error while setting the key label\n");
            rv = SECFailure;
        }
    } else {
        fprintf(stderr, "Error while generating the key\n");
        rv = SECFailure;
    }

cleanup:
    if (slot) {
        PK11_FreeSlot(slot);
    }
    if (privKey) {
        SECKEY_DestroyPrivateKey(privKey);
    }
    if (pubKey) {
        SECKEY_DestroyPublicKey(pubKey);
    }
    return rv;
}

SECKEYPublicKey *
GetRSAPublicKey(PK11SlotInfo *slot,
                const char   *dbdir,
                secuPWData   *pwdata, 
                const char   *keyLabel)
{
    SECKEYPrivateKeyList     *list;
    SECKEYPrivateKeyListNode *node;
    SECKEYPublicKey          *pubKey    = NULL;
    char                     *keyName   = NULL;

    if (slot == NULL) {
        fprintf(stderr, "Empty Slot\n");
        goto cleanup;
    }
    if (PK11_Authenticate(slot, PR_TRUE, pwdata) != SECSuccess) {
        fprintf(stderr, "could not authenticate to token %s.",
                PK11_GetTokenName(slot));
        goto cleanup;
    }

    list = PK11_ListPrivKeysInSlot(slot, (char *)keyLabel, pwdata);
    if (list == NULL) {
        fprintf(stderr, "problem listing keys\n");
        goto cleanup;
    }
    for (node=PRIVKEY_LIST_HEAD(list);
         !PRIVKEY_LIST_END(node,list);
         node=PRIVKEY_LIST_NEXT(node)) {
        keyName = PK11_GetPrivateKeyNickname(node->key);
        if (!keyName || PL_strcmp(keyName,keyLabel)) {
            PORT_Free((void *)keyName);
            continue;
        } else {
            pubKey = SECKEY_ConvertToPublicKey(node->key);
            break;
        }
    }
cleanup:
    if (list) {
        SECKEY_DestroyPrivateKeyList(list);
    }
    if (keyName) {
        PORT_Free((void *)keyName);
    }
    return pubKey;
}

/*
 * EncryptFile
 */
SECStatus
EncryptFile(PK11SlotInfo *slot,
             const char   *dbdir,
             const char   *inFileName,
             const char   *headerFileName,
             const char   *encryptedFileName,
             const char   *noiseFileName,
             secuPWData   *pwdata, 
             PRBool       ascii,
             const char   *keyLabel)
{
    /*
     * The DB is open for read/write and we have authenticated to it.
     * generate a symmetric AES key as a token object.
     * generate a second key to use for MACing, also a token object.
     * get their  CKA_IDs
     * generate a random value to use as IV for AES CBC
     * open an input file and an output file,
     * write a header to the output that identifies the two keys by
     *  their CKA_IDs, May include original file name and length.
     * loop until EOF(input)
     *    read a buffer of plaintext from input file,
     *    MAC it, append the MAC to the plaintext
     *    encrypt it using CBC, using previously created IV,
     *    store the last block of ciphertext as the new IV,
     *    write the cipher text to intermediate file
     *    close files
     *    report success
     */
    SECKEYPublicKey    *pubKey;
    SECStatus           rv;
    SECStatus           rvShutdown;
    PRFileDesc         *inFile;
    PRFileDesc         *headerFile;
    PRFileDesc         *encFile;

    unsigned char      *encKeyId = (unsigned char *) "Encrypt Key";
    unsigned char      *macKeyId = (unsigned char *) "MAC Key";
    SECItem encKeyID = { siAsciiString, encKeyId, PL_strlen(encKeyId) };
    SECItem macKeyID = { siAsciiString, macKeyId, PL_strlen(macKeyId) };

    unsigned char       iv[BLOCKSIZE];
    SECItem             ivItem;
    PK11SymKey         *encKey = NULL;
    PK11SymKey         *macKey = NULL;
    SECItem            *wrappedEncKey;
    SECItem            *wrappedMacKey;
    unsigned char       c;

    pubKey = GetRSAPublicKey(slot, dbdir, pwdata, keyLabel);
    if (pubKey == NULL) {
        PR_fprintf(PR_STDERR, "Error while getting RSA public key\n");
        rv = SECFailure;
        goto cleanup;
    } 
    /* generate a symmetric AES key as a token object. */
    encKey = GenerateSYMKey(slot, CKM_AES_KEY_GEN, 128/8, &encKeyID, pwdata);
    if (encKey == NULL) {
        PR_fprintf(PR_STDERR, "GenerateSYMKey for AES returned NULL.\n");
        rv = SECFailure;
        goto cleanup;
    }

    /* generate a second key to use for MACing, also a token object. */
    macKey = GenerateSYMKey(slot, CKM_GENERIC_SECRET_KEY_GEN, 160/8, &macKeyID, pwdata);
    if (macKey == NULL) {
        PR_fprintf(PR_STDERR, "GenerateSYMKey for MACing returned NULL.\n");
        rv = SECFailure;
        goto cleanup;
    }

    /* Wrap encrypt key */
    rv = WrapKey(encKey, pubKey, &wrappedEncKey);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Error while wrapping encrypt key\n");
        goto cleanup;
    }

    /* Wrap Mac key */
    rv = WrapKey(macKey, pubKey, &wrappedMacKey);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Error while wrapping Mac key\n");
        goto cleanup;
    }

    if (noiseFileName) {
        rv = SeedFromNoiseFile(noiseFileName);
        if (rv != SECSuccess) {
            PORT_SetError(PR_END_OF_FILE_ERROR);
            return SECFailure;
        }
        rv = PK11_GenerateRandom(iv, BLOCKSIZE);
        if (rv != SECSuccess) {
            goto cleanup;
        }

    } else {
        /* generate a random value to use as IV for AES CBC */
        GenerateRandom(iv, BLOCKSIZE);
    }

    headerFile = PR_Open(headerFileName,
                         PR_CREATE_FILE | PR_TRUNCATE | PR_RDWR, 00660);
    if (!headerFile) {
        PR_fprintf(PR_STDERR,
                   "Unable to open \"%s\" for writing.\n",
                   headerFileName);
        return SECFailure;
    }
    encFile = PR_Open(encryptedFileName,
                      PR_CREATE_FILE | PR_TRUNCATE | PR_RDWR, 00660);
    if (!encFile) {
        PR_fprintf(PR_STDERR,
                   "Unable to open \"%s\" for writing.\n",
                   encryptedFileName);
        return SECFailure;
    }
    /* write to a header file the IV and the CKA_IDs
     * identifying the two keys
     */
    ivItem.type = siBuffer;
    ivItem.data = iv;
    ivItem.len = BLOCKSIZE;

    rv = WriteToHeaderFile(iv, BLOCKSIZE, IV, headerFile);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Error writing IV to cipher file - %s\n",
                   headerFileName);
        goto cleanup;
    }

    rv = WriteToHeaderFile(wrappedEncKey->data, wrappedEncKey->len, SYMKEY, headerFile);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Error writing wrapped AES key to cipher file - %s\n",
        encryptedFileName);
        goto cleanup;
    }
    rv = WriteToHeaderFile(wrappedMacKey->data, wrappedMacKey->len, MACKEY, headerFile);
    if (rv != SECSuccess) {
        PR_fprintf(PR_STDERR, "Error writing wrapped MAC key to cipher file - %s\n",
                   headerFileName);
        goto cleanup;
    }

    rv = WriteToHeaderFile(keyLabel, strlen(keyLabel), LAB, headerFile);

    /*  Open the input file.  */
    inFile = PR_Open(inFileName, PR_RDONLY, 0);
    if (!inFile) {
        PR_fprintf(PR_STDERR, "Unable to open \"%s\" for reading.\n",
                   inFileName);
        return SECFailure;
    }

    /* Macing and Encryption */
    if (rv == SECSuccess) {
        rv = EncryptAndMac(inFile, headerFile, encFile,
                           encKey, macKey, ivItem.data, ivItem.len, ascii);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "Failed : Macing and Encryption\n");
            goto cleanup;
        }
    }

cleanup:
    if (inFile) {
        PR_Close(inFile);
    }
    if (headerFile) {
        PR_Close(headerFile);
    }
    if (encFile) {
        PR_Close(encFile);
    }
    if (slot) {
        PK11_FreeSlot(slot);
    }
    if (encKey) {
        PK11_FreeSymKey(encKey);
    }
    if (macKey) {
        PK11_FreeSymKey(macKey);
    }
    if (wrappedEncKey) {
        SECITEM_FreeItem(wrappedEncKey, PR_TRUE);
    }
    if (wrappedMacKey) {
        SECITEM_FreeItem(wrappedMacKey, PR_TRUE);
    }
    if (pubKey) {
        SECKEY_DestroyPublicKey(pubKey);
    }
    return rv;
}

/*
 * This example illustrates basic encryption/decryption and MACing
 * Generates the RSA key pair as token object with user supplied key label.
 * Generates the encryption/mac keys as session objects.
 * Encrypts/MACs the input file using encryption keys and outputs the encrypted
 * contents into intermediate header file.
 * Wraps the encryption keys using RSA public key and outputs wrapped keys and 
 * RSA label into intermediate header file.
 * Reads the intermediate headerfile for wrapped keys,RSA label and encrypted 
 * contents and decrypts into output file.
 *
 * How this sample is different from sample3 ?
 *
 * 1. Generate encryption/mac keys as session objects instead of token objects
 * 2. Wrap the encryption/mac keys with RSA public key and store the wrapped keys
 *    and RSA key label into intermediate header file instead of storing CKA_IDs of
 *    encryption/mac keys into intermediate headerfile.
 * 3. Find private key by label and unwraps the wrapped keys to obtain encryption/mac
 *    session objects instead of finding encryption/mac token objects by their CKA_IDs. 
 *    Rest is the same.
 */
int
main(int argc, char **argv)
{
    SECStatus           rv;
    SECStatus           rvShutdown;
    PK11SlotInfo        *slot = NULL;
    PLOptState          *optstate;
    PLOptStatus         status;
    char                headerFileName[50];
    char                encryptedFileName[50];
    PRFileDesc         *inFile;
    PRFileDesc         *outFile;
    PRBool              ascii = PR_FALSE;
    CommandType         cmd = UNKNOWN;
    const char         *command             = NULL;
    const char         *dbdir               = NULL;
    const char         *inFileName          = NULL;
    const char         *outFileName         = NULL;
    const char         *noiseFileName       = NULL;
    secuPWData          pwdata              = { PW_NONE, 0 };
    const char         *keyLabel            = NULL;

    char * progName = strrchr(argv[0], '/');
    progName = progName ? progName + 1 : argv[0];

    /* Parse command line arguments */
    optstate = PL_CreateOptState(argc, argv, "c:d:i:o:f:p:z:a:k:");
    while ((status = PL_GetNextOpt(optstate)) == PL_OPT_OK) {
        switch (optstate->option) {
        case 'a':
            ascii = PR_TRUE;
            break;
        case 'c':
            command = strdup(optstate->value);
            break;
        case 'k':
            keyLabel = strdup(optstate->value);
            break;
        case 'd':
            dbdir = strdup(optstate->value);
            break;
        case 'f':
            pwdata.source = PW_FROMFILE;
            pwdata.data = strdup(optstate->value);
            break;
        case 'p':
            pwdata.source = PW_PLAINTEXT;
            pwdata.data = strdup(optstate->value);
            break;
        case 'i':
            inFileName = strdup(optstate->value);
            break;
        case 'o':
            outFileName = strdup(optstate->value);
            break;
        case 'z':
            noiseFileName = strdup(optstate->value);
            break;
        default:
            Usage(progName);
            break;
        }
    }
    PL_DestroyOptState(optstate);

    if (PL_strlen(command)==0)
    	Usage(progName);
    cmd = command[0] == 'a' ? GENWRAPKEY : command[0] == 'b' ? ENCRYPT : command[0] == 'c' ? DECRYPT : UNKNOWN;

    if (!command || !dbdir)
        Usage(progName);

    if (command[0] == 'a' || command[0] == 'b') {
        if (!keyLabel) {
             Usage(progName);
        }
    }
    if (command[0] == 'b' || command[0] == 'c') {
        if (!inFileName || !outFileName) {
            Usage(progName);
        }

        /*  Open the input file.  */
        inFile = PR_Open(inFileName, PR_RDONLY, 0);
        if (!inFile) {
            PR_fprintf(PR_STDERR, "Unable to open \"%s\" for reading.\n",
                       inFileName);
            return SECFailure;
        }
        PR_Close(inFile);

        /* For intermediate header file, choose filename as inputfile name
           with extension ".header" */
        strcpy(headerFileName, inFileName);
        strcat(headerFileName, ".header");

       /* For intermediate encrypted file, choose filename as inputfile name
          with extension ".enc" */
       strcpy(encryptedFileName, inFileName);
       strcat(encryptedFileName, ".enc");
    }
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);

    switch (cmd) {
    case GENWRAPKEY:
       /* Open DB for read/write and authenticate to it. */
        rv = NSS_InitReadWrite(dbdir);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "NSS_InitReadWrite Failed\n");
            goto cleanup;
        }

        PK11_SetPasswordFunc(GetModulePassword);
        slot = PK11_GetInternalKeySlot();
        if (PK11_NeedLogin(slot)) {
            rv = PK11_Authenticate(slot, PR_TRUE, &pwdata);
            if (rv != SECSuccess) {
                PR_fprintf(PR_STDERR, "Could not authenticate to token %s.\n",
                           PK11_GetTokenName(slot));
                goto cleanup;
            }
        }
        rv = GenerateWrappingKey(slot, dbdir, keyLabel,
                          noiseFileName, &pwdata);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "GenerateWrappingKey : Failed\n");
            return SECFailure;
        }
        break;
    case ENCRYPT:
        /* If the intermediate header file already exists, delete it */
        if (PR_Access(headerFileName, PR_ACCESS_EXISTS) == PR_SUCCESS) {
            PR_Delete(headerFileName);
        }
        /* If the intermediate encrypted  already exists, delete it */
        if (PR_Access(encryptedFileName, PR_ACCESS_EXISTS) == PR_SUCCESS) {
            PR_Delete(encryptedFileName);
        }

        /* Open DB for read/write and authenticate to it. */
        rv = NSS_InitReadWrite(dbdir);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "NSS_InitReadWrite Failed\n");
            goto cleanup;
        }

        PK11_SetPasswordFunc(GetModulePassword);
        slot = PK11_GetInternalKeySlot();
        if (PK11_NeedLogin(slot)) {
            rv = PK11_Authenticate(slot, PR_TRUE, &pwdata);
            if (rv != SECSuccess) {
                PR_fprintf(PR_STDERR, "Could not authenticate to token %s.\n",
                           PK11_GetTokenName(slot));
                goto cleanup;
            }
        }
        rv = EncryptFile(slot, dbdir,
                          inFileName, headerFileName, encryptedFileName,
                          noiseFileName, &pwdata, ascii, keyLabel);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "EncryptFile : Failed\n");
            return SECFailure;
        }
        break;
    case DECRYPT:
        /* Open DB read only, authenticate to it */
        PK11_SetPasswordFunc(GetModulePassword);

        rv = NSS_Init(dbdir);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "NSS_Init Failed\n");
            return SECFailure;
        }

        slot = PK11_GetInternalKeySlot();
        if (PK11_NeedLogin(slot)) {
            rv = PK11_Authenticate(slot, PR_TRUE, &pwdata);
            if (rv != SECSuccess) {
                PR_fprintf(PR_STDERR, "Could not authenticate to token %s.\n",
                           PK11_GetTokenName(slot));
                goto cleanup;
            }
        }

        rv = DecryptFile(slot, dbdir,
                         outFileName, headerFileName,
                         encryptedFileName, &pwdata, ascii);
        if (rv != SECSuccess) {
            PR_fprintf(PR_STDERR, "DecryptFile : Failed\n");
            return SECFailure;
        }
        break;
    }

cleanup:
    rvShutdown = NSS_Shutdown();
    if (rvShutdown != SECSuccess) {
        PR_fprintf(PR_STDERR, "Failed : NSS_Shutdown()\n");
        rv = SECFailure;
    }

    PR_Cleanup();

    return rv;
}
