/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * Merge the source token into the target token.
 */

#include "secmod.h"
#include "secmodi.h"
#include "secmodti.h"
#include "pk11pub.h"
#include "pk11priv.h"
#include "pkcs11.h"
#include "seccomon.h"
#include "secerr.h"
#include "keyhi.h"
#include "hasht.h"
#include "cert.h"
#include "certdb.h"

/*************************************************************************
 *
 *             short utilities to aid in the merge
 *
 *************************************************************************/

/*
 * write a bunch of attributes out to an existing object.
 */
static SECStatus
pk11_setAttributes(PK11SlotInfo *slot, CK_OBJECT_HANDLE id,
                   CK_ATTRIBUTE *setTemplate, CK_ULONG setTemplCount)
{
    CK_RV crv;
    CK_SESSION_HANDLE rwsession;

    rwsession = PK11_GetRWSession(slot);
    if (rwsession == CK_INVALID_HANDLE) {
        PORT_SetError(SEC_ERROR_BAD_DATA);
        return SECFailure;
    }
    crv = PK11_GETTAB(slot)->C_SetAttributeValue(rwsession, id,
                                                 setTemplate, setTemplCount);
    PK11_RestoreROSession(slot, rwsession);
    if (crv != CKR_OK) {
        PORT_SetError(PK11_MapError(crv));
        return SECFailure;
    }
    return SECSuccess;
}

/*
 * copy a template of attributes from a source object to a target object.
 * if target object is not given, create it.
 */
static SECStatus
pk11_copyAttributes(PLArenaPool *arena,
                    PK11SlotInfo *targetSlot, CK_OBJECT_HANDLE targetID,
                    PK11SlotInfo *sourceSlot, CK_OBJECT_HANDLE sourceID,
                    CK_ATTRIBUTE *copyTemplate, CK_ULONG copyTemplateCount)
{
    SECStatus rv;
    CK_ATTRIBUTE *newTemplate = NULL;
    CK_RV crv;

    crv = PK11_GetAttributes(arena, sourceSlot, sourceID,
                             copyTemplate, copyTemplateCount);
    /* if we have missing attributes, just skip them and create the object */
    if (crv == CKR_ATTRIBUTE_TYPE_INVALID) {
        CK_ULONG i, j;
        newTemplate = PORT_NewArray(CK_ATTRIBUTE, copyTemplateCount);
        if (!newTemplate) {
            return SECFailure;
        }
        /* remove the unknown attributes. If we don't have enough attributes
         * PK11_CreateNewObject() will fail */
        for (i = 0, j = 0; i < copyTemplateCount; i++) {
            if (copyTemplate[i].ulValueLen != -1) {
                newTemplate[j] = copyTemplate[i];
                j++;
            }
        }
        copyTemplate = newTemplate;
        copyTemplateCount = j;
        crv = PK11_GetAttributes(arena, sourceSlot, sourceID,
                                 copyTemplate, copyTemplateCount);
    }
    if (crv != CKR_OK) {
        PORT_SetError(PK11_MapError(crv));
        PORT_Free(newTemplate);
        return SECFailure;
    }
    if (targetID == CK_INVALID_HANDLE) {
        /* we need to create the object */
        rv = PK11_CreateNewObject(targetSlot, CK_INVALID_HANDLE,
                                  copyTemplate, copyTemplateCount, PR_TRUE, &targetID);
    } else {
        /* update the existing object with the new attributes */
        rv = pk11_setAttributes(targetSlot, targetID,
                                copyTemplate, copyTemplateCount);
    }
    if (newTemplate) {
        PORT_Free(newTemplate);
    }
    return rv;
}

static CK_OBJECT_CLASS
pk11_getClassFromTemplate(CK_ATTRIBUTE *template, CK_ULONG tsize)
{
    CK_ULONG i;
    for (i = 0; i < tsize; i++) {
        if ((template[i].type == CKA_CLASS) &&
            template[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            return *(CK_OBJECT_CLASS *)template[i].pValue;
        }
    }
    return CK_INVALID_HANDLE;
}

static void
pk11_setClassInTemplate(CK_ATTRIBUTE *template, CK_ULONG tsize,
                        CK_OBJECT_CLASS objClass)
{
    CK_ULONG i;
    for (i = 0; i < tsize; i++) {
        if ((template[i].type == CKA_CLASS) &&
            template[i].ulValueLen == sizeof(objClass)) {
            PORT_Memcpy(template[i].pValue, &objClass, sizeof(objClass));
        }
    }
}

/*
 * look for a matching object across tokens.
 */
static SECStatus
pk11_matchAcrossTokens(PLArenaPool *arena, PK11SlotInfo *targetSlot,
                       PK11SlotInfo *sourceSlot,
                       CK_ATTRIBUTE *template, CK_ULONG tsize,
                       CK_OBJECT_HANDLE id, CK_OBJECT_HANDLE *peer)
{

    CK_RV crv;
    CK_OBJECT_CLASS objclass = CK_INVALID_HANDLE;
    *peer = CK_INVALID_HANDLE;

    crv = PK11_GetAttributes(arena, sourceSlot, id, template, tsize);
    if (crv != CKR_OK) {
        PORT_SetError(PK11_MapError(crv));
        goto loser;
    }

    if (template[0].ulValueLen == -1) {
        crv = CKR_ATTRIBUTE_TYPE_INVALID;
        PORT_SetError(PK11_MapError(crv));
        goto loser;
    }

    /* if the source is a CKO_NSS_TRUST, first look to see if the target
     * has a CKO_TRUST object */
    objclass = pk11_getClassFromTemplate(template, tsize);
    if (objclass == CKO_NSS_TRUST) {
        pk11_setClassInTemplate(template, tsize, CKO_TRUST);
        objclass = CKO_TRUST;
    }

    *peer = pk11_FindObjectByTemplate(targetSlot, template, tsize);
    /* if we coun't find a CKO_TRUST object, look for a CKO_NSS_TRUST object */
    if ((*peer == CK_INVALID_HANDLE && objclass == CKO_TRUST)) {
        pk11_setClassInTemplate(template, tsize, CKO_NSS_TRUST);
        *peer = pk11_FindObjectByTemplate(targetSlot, template, tsize);
    }
    return SECSuccess;

loser:
    return SECFailure;
}

/*
 * Encrypt using key and parameters
 */
SECStatus
pk11_encrypt(PK11SymKey *symKey, CK_MECHANISM_TYPE mechType, SECItem *param,
             SECItem *input, SECItem **output)
{
    PK11Context *ctxt = NULL;
    SECStatus rv = SECSuccess;

    if (*output) {
        SECITEM_FreeItem(*output, PR_TRUE);
    }
    *output = SECITEM_AllocItem(NULL, NULL, input->len + 20 /*slop*/);
    if (!*output) {
        rv = SECFailure;
        goto done;
    }

    ctxt = PK11_CreateContextBySymKey(mechType, CKA_ENCRYPT, symKey, param);
    if (ctxt == NULL) {
        rv = SECFailure;
        goto done;
    }

    rv = PK11_CipherOp(ctxt, (*output)->data,
                       (int *)&((*output)->len),
                       (*output)->len, input->data, input->len);

done:
    if (ctxt) {
        PK11_Finalize(ctxt);
        PK11_DestroyContext(ctxt, PR_TRUE);
    }
    if (rv != SECSuccess) {
        if (*output) {
            SECITEM_FreeItem(*output, PR_TRUE);
            *output = NULL;
        }
    }
    return rv;
}

/*************************************************************************
 *
 *            Private Keys
 *
 *************************************************************************/

/*
 * Fetch the key usage based on the pkcs #11 flags
 */
unsigned int
pk11_getPrivateKeyUsage(PK11SlotInfo *slot, CK_OBJECT_HANDLE id)
{
    unsigned int usage = 0;

    if ((PK11_HasAttributeSet(slot, id, CKA_UNWRAP, PR_FALSE) ||
         PK11_HasAttributeSet(slot, id, CKA_DECRYPT, PR_FALSE))) {
        usage |= KU_KEY_ENCIPHERMENT;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_DERIVE, PR_FALSE)) {
        usage |= KU_KEY_AGREEMENT;
    }
    if ((PK11_HasAttributeSet(slot, id, CKA_SIGN_RECOVER, PR_FALSE) ||
         PK11_HasAttributeSet(slot, id, CKA_SIGN, PR_FALSE))) {
        usage |= KU_DIGITAL_SIGNATURE;
    }
    return usage;
}

/*
 * merge a private key,
 *
 * Private keys are merged using PBE wrapped keys with a random
 * value as the 'password'. Once the base key is moved, The remaining
 * attributes (SUBJECT) is copied.
 */
static SECStatus
pk11_mergePrivateKey(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                     CK_OBJECT_HANDLE id, void *targetPwArg, void *sourcePwArg)
{
    SECKEYPrivateKey *sourceKey = NULL;
    CK_OBJECT_HANDLE targetKeyID;
    SECKEYEncryptedPrivateKeyInfo *epki = NULL;
    char *nickname = NULL;
    SECItem nickItem;
    SECItem pwitem;
    SECItem publicValue;
    PLArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    unsigned int keyUsage;
    unsigned char randomData[SHA1_LENGTH];
    SECOidTag algTag = SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC;
    CK_ATTRIBUTE privTemplate[] = {
        { CKA_ID, NULL, 0 },
        { CKA_CLASS, NULL, 0 }
    };
    CK_ULONG privTemplateCount = sizeof(privTemplate) / sizeof(privTemplate[0]);
    CK_ATTRIBUTE privCopyTemplate[] = {
        { CKA_SUBJECT, NULL, 0 }
    };
    CK_ULONG privCopyTemplateCount =
        sizeof(privCopyTemplate) / sizeof(privCopyTemplate[0]);

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        rv = SECFailure;
        goto done;
    }

    /* check to see if the key is already in the target slot */
    rv = pk11_matchAcrossTokens(arena, targetSlot, sourceSlot, privTemplate,
                                privTemplateCount, id, &targetKeyID);
    if (rv != SECSuccess) {
        goto done;
    }

    if (targetKeyID != CK_INVALID_HANDLE) {
        /* match found,  not an error ... */
        goto done;
    }

    /* get an NSS representation of our source key */
    sourceKey = PK11_MakePrivKey(sourceSlot, nullKey, PR_FALSE,
                                 id, sourcePwArg);
    if (sourceKey == NULL) {
        rv = SECFailure;
        goto done;
    }

    /* Load the private key */
    /* generate a random pwitem */
    rv = PK11_GenerateRandom(randomData, sizeof(randomData));
    if (rv != SECSuccess) {
        goto done;
    }
    pwitem.data = randomData;
    pwitem.len = sizeof(randomData);
    /* fetch the private key encrypted */
    epki = PK11_ExportEncryptedPrivKeyInfo(sourceSlot, algTag, &pwitem,
                                           sourceKey, 1, sourcePwArg);
    if (epki == NULL) {
        rv = SECFailure;
        goto done;
    }
    nickname = PK11_GetObjectNickname(sourceSlot, id);
    /* NULL nickanme is fine (in fact is often normal) */
    if (nickname) {
        nickItem.data = (unsigned char *)nickname;
        nickItem.len = PORT_Strlen(nickname);
    }
    keyUsage = pk11_getPrivateKeyUsage(sourceSlot, id);
    /* pass in the CKA_ID */
    publicValue.data = privTemplate[0].pValue;
    publicValue.len = privTemplate[0].ulValueLen;
    rv = PK11_ImportEncryptedPrivateKeyInfo(targetSlot, epki, &pwitem,
                                            nickname ? &nickItem : NULL, &publicValue,
                                            PR_TRUE, PR_TRUE, sourceKey->keyType, keyUsage,
                                            targetPwArg);
    if (rv != SECSuccess) {
        goto done;
    }

    /* make sure it made it */
    rv = pk11_matchAcrossTokens(arena, targetSlot, sourceSlot, privTemplate,
                                privTemplateCount, id, &targetKeyID);
    if (rv != SECSuccess) {
        goto done;
    }

    if (targetKeyID == CK_INVALID_HANDLE) {
        /* this time the key should exist */
        rv = SECFailure;
        goto done;
    }

    /* fill in remaining attributes */
    rv = pk11_copyAttributes(arena, targetSlot, targetKeyID, sourceSlot, id,
                             privCopyTemplate, privCopyTemplateCount);
done:
    /* make sure the 'key' is cleared */
    PORT_Memset(randomData, 0, sizeof(randomData));
    if (nickname) {
        PORT_Free(nickname);
    }
    if (sourceKey) {
        SECKEY_DestroyPrivateKey(sourceKey);
    }
    if (epki) {
        SECKEY_DestroyEncryptedPrivateKeyInfo(epki, PR_TRUE);
    }
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    return rv;
}

/*************************************************************************
 *
 *            Secret Keys
 *
 *************************************************************************/

/*
 * we need to find a unique CKA_ID.
 *  The basic idea is to just increment the lowest byte.
 *  This code also handles the following corner cases:
 *   1) the single byte overflows. On overflow we increment the next byte up
 *    and so forth until we have overflowed the entire CKA_ID.
 *   2) If we overflow the entire CKA_ID we expand it by one byte.
 *   3) the CKA_ID is non-existent, we create a new one with one byte.
 *    This means no matter what CKA_ID is passed, the result of this function
 *    is always a new CKA_ID, and this function will never return the same
 *    CKA_ID the it has returned in the passed.
 */
static SECStatus
pk11_incrementID(PLArenaPool *arena, CK_ATTRIBUTE *ptemplate)
{
    unsigned char *buf = ptemplate->pValue;
    CK_ULONG len = ptemplate->ulValueLen;

    if (buf == NULL || len == (CK_ULONG)-1) {
        /* we have no valid CKAID, we'll create a basic one byte CKA_ID below */
        len = 0;
    } else {
        CK_ULONG i;

        /* walk from the back to front, incrementing
         * the CKA_ID until we no longer have a carry,
         * or have hit the front of the id. */
        for (i = len; i != 0; i--) {
            buf[i - 1]++;
            if (buf[i - 1] != 0) {
                /* no more carries, the increment is complete */
                return SECSuccess;
            }
        }
        /* we've now overflowed, fall through and expand the CKA_ID by
         * one byte */
    }
    /* if we are here we've run the counter to zero (indicating an overflow).
     * create an CKA_ID that is all zeros, but has one more zero than
     * the previous CKA_ID */
    buf = PORT_ArenaZAlloc(arena, len + 1);
    if (buf == NULL) {
        return SECFailure;
    }
    ptemplate->pValue = buf;
    ptemplate->ulValueLen = len + 1;
    return SECSuccess;
}

static CK_FLAGS
pk11_getSecretKeyFlags(PK11SlotInfo *slot, CK_OBJECT_HANDLE id)
{
    CK_FLAGS flags = 0;

    if (PK11_HasAttributeSet(slot, id, CKA_UNWRAP, PR_FALSE)) {
        flags |= CKF_UNWRAP;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_WRAP, PR_FALSE)) {
        flags |= CKF_WRAP;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_ENCRYPT, PR_FALSE)) {
        flags |= CKF_ENCRYPT;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_DECRYPT, PR_FALSE)) {
        flags |= CKF_DECRYPT;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_DERIVE, PR_FALSE)) {
        flags |= CKF_DERIVE;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_SIGN, PR_FALSE)) {
        flags |= CKF_SIGN;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_SIGN_RECOVER, PR_FALSE)) {
        flags |= CKF_SIGN_RECOVER;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_VERIFY, PR_FALSE)) {
        flags |= CKF_VERIFY;
    }
    if (PK11_HasAttributeSet(slot, id, CKA_VERIFY_RECOVER, PR_FALSE)) {
        flags |= CKF_VERIFY_RECOVER;
    }
    return flags;
}

static const char testString[] =
    "My Encrytion Test Data (should be at least 32 bytes long)";
/*
 * merge a secret key,
 *
 * Secret keys may collide by CKA_ID as we merge 2 token. If we collide
 * on the CKA_ID, we need to make sure we are dealing with different keys.
 * The reason for this is it is possible that we've merged this database
 * before, and this key could have been merged already.  If the keys are
 * the same, we are done. If they are not, we need to update the CKA_ID of
 * the source key and try again.
 *
 * Once we know we have a unique key to merge in, we use NSS's underlying
 * key Move function which will do a key exchange if necessary to move
 * the key from one token to another. Then we set the CKA_ID and additional
 * pkcs #11 attributes.
 */
static SECStatus
pk11_mergeSecretKey(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                    CK_OBJECT_HANDLE id, void *targetPwArg, void *sourcePwArg)
{
    PK11SymKey *sourceKey = NULL;
    PK11SymKey *targetKey = NULL;
    SECItem *sourceOutput = NULL;
    SECItem *targetOutput = NULL;
    SECItem *param = NULL;
    int blockSize;
    SECItem input;
    CK_OBJECT_HANDLE targetKeyID;
    CK_FLAGS flags;
    PLArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    CK_MECHANISM_TYPE keyMechType, cryptoMechType;
    CK_KEY_TYPE sourceKeyType, targetKeyType;
    CK_ATTRIBUTE symTemplate[] = {
        { CKA_ID, NULL, 0 },
        { CKA_CLASS, NULL, 0 }
    };
    const CK_ULONG symTemplateCount = sizeof(symTemplate) / sizeof(symTemplate[0]);
    CK_ATTRIBUTE symCopyTemplate[] = {
        { CKA_LABEL, NULL, 0 }
    };
    CK_ULONG symCopyTemplateCount =
        sizeof(symCopyTemplate) / sizeof(symCopyTemplate[0]);

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        rv = SECFailure;
        goto done;
    }

    sourceKeyType = PK11_ReadULongAttribute(sourceSlot, id, CKA_KEY_TYPE);
    if (sourceKeyType == (CK_ULONG)-1) {
        rv = SECFailure;
        goto done;
    }

    /* get the key mechanism */
    keyMechType = PK11_GetKeyMechanism(sourceKeyType);
    /* get a mechanism suitable to encryption.
     * PK11_GetKeyMechanism returns a mechanism that is unique to the key
     * type. It tries to return encryption/decryption mechanisms, however
     * CKM_DES3_CBC uses and abmiguous keyType, so keyMechType is returned as
     * 'keygen' mechanism. Detect that case here */
    cryptoMechType = keyMechType;
    if ((keyMechType == CKM_DES3_KEY_GEN) ||
        (keyMechType == CKM_DES2_KEY_GEN)) {
        cryptoMechType = CKM_DES3_CBC;
    }

    sourceKey = PK11_SymKeyFromHandle(sourceSlot, NULL, PK11_OriginDerive,
                                      keyMechType, id, PR_FALSE, sourcePwArg);
    if (sourceKey == NULL) {
        rv = SECFailure;
        goto done;
    }

    /* check to see a key with the same CKA_ID  already exists in
     * the target slot. If it does, then we need to verify if the keys
     * really matches. If they don't import the key with a new CKA_ID
     * value. */
    rv = pk11_matchAcrossTokens(arena, targetSlot, sourceSlot,
                                symTemplate, symTemplateCount, id, &targetKeyID);
    if (rv != SECSuccess) {
        goto done;
    }

    /* set up the input test */
    input.data = (unsigned char *)testString;
    blockSize = PK11_GetBlockSize(cryptoMechType, NULL);
    if (blockSize < 0) {
        rv = SECFailure;
        goto done;
    }
    input.len = blockSize;
    if (input.len == 0) {
        input.len = sizeof(testString);
    }
    while (targetKeyID != CK_INVALID_HANDLE) {
        /* test to see if the keys are identical */
        targetKeyType = PK11_ReadULongAttribute(sourceSlot, id, CKA_KEY_TYPE);
        if (targetKeyType == sourceKeyType) {
            /* same keyType  - see if it's the same key */
            targetKey = PK11_SymKeyFromHandle(targetSlot, NULL,
                                              PK11_OriginDerive, keyMechType, targetKeyID, PR_FALSE,
                                              targetPwArg);
            /* get a parameter if we don't already have one */
            if (!param) {
                param = PK11_GenerateNewParam(cryptoMechType, sourceKey);
                if (param == NULL) {
                    rv = SECFailure;
                    goto done;
                }
            }
            /* use the source key to encrypt a reference */
            if (!sourceOutput) {
                rv = pk11_encrypt(sourceKey, cryptoMechType, param, &input,
                                  &sourceOutput);
                if (rv != SECSuccess) {
                    goto done;
                }
            }
            /* encrypt the reference with the target key */
            rv = pk11_encrypt(targetKey, cryptoMechType, param, &input,
                              &targetOutput);
            if (rv == SECSuccess) {
                if (SECITEM_ItemsAreEqual(sourceOutput, targetOutput)) {
                    /* they produce the same output, they must be the
                     * same key */
                    goto done;
                }
                SECITEM_FreeItem(targetOutput, PR_TRUE);
                targetOutput = NULL;
            }
            PK11_FreeSymKey(targetKey);
            targetKey = NULL;
        }
        /* keys aren't equal, update the KEY_ID and look again */
        rv = pk11_incrementID(arena, &symTemplate[0]);
        if (rv != SECSuccess) {
            goto done;
        }
        targetKeyID = pk11_FindObjectByTemplate(targetSlot,
                                                symTemplate, symTemplateCount);
    }

    /* we didn't find a matching key, import this one with the new
     * CKAID */
    flags = pk11_getSecretKeyFlags(sourceSlot, id);
    targetKey = PK11_MoveSymKey(targetSlot, PK11_OriginDerive, flags, PR_TRUE,
                                sourceKey);
    if (targetKey == NULL) {
        rv = SECFailure;
        goto done;
    }
    /* set the key new CKAID */
    rv = pk11_setAttributes(targetSlot, targetKey->objectID, symTemplate, 1);
    if (rv != SECSuccess) {
        goto done;
    }

    /* fill in remaining attributes */
    rv = pk11_copyAttributes(arena, targetSlot, targetKey->objectID,
                             sourceSlot, id, symCopyTemplate, symCopyTemplateCount);
done:
    if (sourceKey) {
        PK11_FreeSymKey(sourceKey);
    }
    if (targetKey) {
        PK11_FreeSymKey(targetKey);
    }
    if (sourceOutput) {
        SECITEM_FreeItem(sourceOutput, PR_TRUE);
    }
    if (targetOutput) {
        SECITEM_FreeItem(targetOutput, PR_TRUE);
    }
    if (param) {
        SECITEM_FreeItem(param, PR_TRUE);
    }
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    return rv;
}

/*************************************************************************
 *
 *            Public Keys
 *
 *************************************************************************/

/*
 * Merge public key
 *
 * Use the high level NSS calls to extract the public key and import it
 * into the token. Extra attributes are then copied to the new token.
 */
static SECStatus
pk11_mergePublicKey(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                    CK_OBJECT_HANDLE id, void *targetPwArg, void *sourcePwArg)
{
    SECKEYPublicKey *sourceKey = NULL;
    CK_OBJECT_HANDLE targetKeyID;
    PLArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    CK_ATTRIBUTE pubTemplate[] = {
        { CKA_ID, NULL, 0 },
        { CKA_CLASS, NULL, 0 }
    };
    CK_ULONG pubTemplateCount = sizeof(pubTemplate) / sizeof(pubTemplate[0]);
    CK_ATTRIBUTE pubCopyTemplate[] = {
        { CKA_ID, NULL, 0 },
        { CKA_LABEL, NULL, 0 },
        { CKA_SUBJECT, NULL, 0 }
    };
    CK_ULONG pubCopyTemplateCount =
        sizeof(pubCopyTemplate) / sizeof(pubCopyTemplate[0]);

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        rv = SECFailure;
        goto done;
    }

    /* check to see if the key is already in the target slot */
    rv = pk11_matchAcrossTokens(arena, targetSlot, sourceSlot, pubTemplate,
                                pubTemplateCount, id, &targetKeyID);
    if (rv != SECSuccess) {
        goto done;
    }

    /* Key is already in the target slot */
    if (targetKeyID != CK_INVALID_HANDLE) {
        /* not an error ... */
        goto done;
    }

    /* fetch an NSS representation of the public key */
    sourceKey = PK11_ExtractPublicKey(sourceSlot, nullKey, id);
    if (sourceKey == NULL) {
        rv = SECFailure;
        goto done;
    }

    /* load the public key into the target token. */
    targetKeyID = PK11_ImportPublicKey(targetSlot, sourceKey, PR_TRUE);
    if (targetKeyID == CK_INVALID_HANDLE) {
        rv = SECFailure;
        goto done;
    }

    /* fill in remaining attributes */
    rv = pk11_copyAttributes(arena, targetSlot, targetKeyID, sourceSlot, id,
                             pubCopyTemplate, pubCopyTemplateCount);

done:
    if (sourceKey) {
        SECKEY_DestroyPublicKey(sourceKey);
    }
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    return rv;
}

/*************************************************************************
 *
 *            Certificates
 *
 *************************************************************************/

/*
 * Two copies of the source code for this algorithm exist in NSS.
 * Changes must be made in both copies.
 * The other copy is in sftkdb_resolveConflicts() in softoken/sftkdb.c.
 */
static char *
pk11_IncrementNickname(char *nickname)
{
    char *newNickname = NULL;
    int end;
    int digit;
    int len = strlen(nickname);

    /* does nickname end with " #n*" ? */
    for (end = len - 1;
         end >= 2 && (digit = nickname[end]) <= '9' && digit >= '0';
         end--) /* just scan */
        ;
    if (len >= 3 &&
        end < (len - 1) /* at least one digit */ &&
        nickname[end] == '#' &&
        nickname[end - 1] == ' ') {
        /* Already has a suitable suffix string */
    } else {
        /* ... append " #2" to the name */
        static const char num2[] = " #2";
        newNickname = PORT_Realloc(nickname, len + sizeof(num2));
        if (newNickname) {
            PORT_Strcat(newNickname, num2);
        } else {
            PORT_Free(nickname);
        }
        return newNickname;
    }

    for (end = len - 1;
         end >= 0 && (digit = nickname[end]) <= '9' && digit >= '0';
         end--) {
        if (digit < '9') {
            nickname[end]++;
            return nickname;
        }
        nickname[end] = '0';
    }

    /* we overflowed, insert a new '1' for a carry in front of the number */
    newNickname = PORT_Realloc(nickname, len + 2);
    if (newNickname) {
        newNickname[++end] = '1';
        PORT_Memset(&newNickname[end + 1], '0', len - end);
        newNickname[len + 1] = 0;
    } else {
        PORT_Free(nickname);
    }
    return newNickname;
}

/*
 * merge a certificate object
 *
 * Use the high level NSS calls to extract and import the certificate.
 */
static SECStatus
pk11_mergeCert(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
               CK_OBJECT_HANDLE id, void *targetPwArg, void *sourcePwArg)
{
    CERTCertificate *sourceCert = NULL;
    CK_OBJECT_HANDLE targetCertID = CK_INVALID_HANDLE;
    char *nickname = NULL;
    SECStatus rv = SECSuccess;
    PLArenaPool *arena = NULL;
    CK_ATTRIBUTE sourceCKAID = { CKA_ID, NULL, 0 };
    CK_ATTRIBUTE targetCKAID = { CKA_ID, NULL, 0 };
    SECStatus lrv = SECSuccess;
    int error = SEC_ERROR_LIBRARY_FAILURE;

    sourceCert = PK11_MakeCertFromHandle(sourceSlot, id, NULL);
    if (sourceCert == NULL) {
        rv = SECFailure;
        goto done;
    }

    nickname = PK11_GetObjectNickname(sourceSlot, id);

    /* The database code will prevent nickname collisions for certs with
     * different subjects. This code will prevent us from getting
     * actual import errors */
    if (nickname) {
        const char *tokenName = PK11_GetTokenName(targetSlot);
        char *tokenNickname = NULL;

        do {
            tokenNickname = PR_smprintf("%s:%s", tokenName, nickname);
            if (!tokenNickname) {
                break;
            }
            if (!SEC_CertNicknameConflict(tokenNickname,
                                          &sourceCert->derSubject, CERT_GetDefaultCertDB())) {
                break;
            }
            nickname = pk11_IncrementNickname(nickname);
            if (!nickname) {
                break;
            }
            PR_smprintf_free(tokenNickname);
        } while (1);
        if (tokenNickname) {
            PR_smprintf_free(tokenNickname);
        }
    }

    /* see if the cert is already there */
    targetCertID = PK11_FindCertInSlot(targetSlot, sourceCert, targetPwArg);
    if (targetCertID == CK_INVALID_HANDLE) {
        /* cert doesn't exist load the cert in. */
        /* OK for the nickname to be NULL, not all certs have nicknames */
        rv = PK11_ImportCert(targetSlot, sourceCert, CK_INVALID_HANDLE,
                             nickname, PR_FALSE);
        goto done;
    }

    /* the cert already exists, see if the nickname and/or  CKA_ID need
     * to be updated */

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        rv = SECFailure;
        goto done;
    }

    /* does our source have a CKA_ID ? */
    rv = PK11_GetAttributes(arena, sourceSlot, id, &sourceCKAID, 1);
    if (rv != SECSuccess) {
        sourceCKAID.ulValueLen = 0;
    }

    /* if we have a source CKA_ID, see of we need to update the
     * target's CKA_ID */
    if (sourceCKAID.ulValueLen != 0) {
        rv = PK11_GetAttributes(arena, targetSlot, targetCertID,
                                &targetCKAID, 1);
        if (rv != SECSuccess) {
            targetCKAID.ulValueLen = 0;
        }
        /* if the target has no CKA_ID, update it from the source */
        if (targetCKAID.ulValueLen == 0) {
            lrv = pk11_setAttributes(targetSlot, targetCertID, &sourceCKAID, 1);
            if (lrv != SECSuccess) {
                error = PORT_GetError();
            }
        }
    }
    rv = SECSuccess;

    /* now check if we need to update the nickname */
    if (nickname && *nickname) {
        char *targetname;
        targetname = PK11_GetObjectNickname(targetSlot, targetCertID);
        if (!targetname || !*targetname) {
            /* target has no nickname, or it's empty, update it */
            rv = PK11_SetObjectNickname(targetSlot, targetCertID, nickname);
        }
        if (targetname) {
            PORT_Free(targetname);
        }
    }

    /* restore the error code if CKA_ID failed, but nickname didn't */
    if ((rv == SECSuccess) && (lrv != SECSuccess)) {
        rv = lrv;
        PORT_SetError(error);
    }

done:
    if (nickname) {
        PORT_Free(nickname);
    }
    if (sourceCert) {
        CERT_DestroyCertificate(sourceCert);
    }
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    return rv;
}

/*************************************************************************
 *
 *            Crls
 *
 *************************************************************************/

/*
 * Use the raw PKCS #11 interface to merge the CRLs.
 *
 * In the case where of collision, choose the newest CRL that is valid.
 */
static SECStatus
pk11_mergeCrl(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
              CK_OBJECT_HANDLE id, void *targetPwArg, void *sourcePwArg)
{
    CK_OBJECT_HANDLE targetCrlID;
    PLArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    CK_ATTRIBUTE crlTemplate[] = {
        { CKA_SUBJECT, NULL, 0 },
        { CKA_CLASS, NULL, 0 },
        { CKA_NSS_KRL, NULL, 0 }
    };
    CK_ULONG crlTemplateCount = sizeof(crlTemplate) / sizeof(crlTemplate[0]);
    CK_ATTRIBUTE crlCopyTemplate[] = {
        { CKA_CLASS, NULL, 0 },
        { CKA_TOKEN, NULL, 0 },
        { CKA_LABEL, NULL, 0 },
        { CKA_PRIVATE, NULL, 0 },
        { CKA_MODIFIABLE, NULL, 0 },
        { CKA_SUBJECT, NULL, 0 },
        { CKA_NSS_KRL, NULL, 0 },
        { CKA_NSS_URL, NULL, 0 },
        { CKA_VALUE, NULL, 0 }
    };
    CK_ULONG crlCopyTemplateCount =
        sizeof(crlCopyTemplate) / sizeof(crlCopyTemplate[0]);

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        rv = SECFailure;
        goto done;
    }
    /* check to see if the crl is already in the target slot */
    rv = pk11_matchAcrossTokens(arena, targetSlot, sourceSlot, crlTemplate,
                                crlTemplateCount, id, &targetCrlID);
    if (rv != SECSuccess) {
        goto done;
    }
    if (targetCrlID != CK_INVALID_HANDLE) {
        /* we already have a CRL, check to see which is more up-to-date. */
        goto done;
    }

    /* load the CRL into the target token. */
    rv = pk11_copyAttributes(arena, targetSlot, targetCrlID, sourceSlot, id,
                             crlCopyTemplate, crlCopyTemplateCount);
done:
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    return rv;
}

/*************************************************************************
 *
 *            SMIME objects
 *
 *************************************************************************/

/*
 * use the raw PKCS #11 interface to merge the S/MIME records
 */
static SECStatus
pk11_mergeSmime(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                CK_OBJECT_HANDLE id, void *targetPwArg, void *sourcePwArg)
{
    CK_OBJECT_HANDLE targetSmimeID;
    PLArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    CK_ATTRIBUTE smimeTemplate[] = {
        { CKA_SUBJECT, NULL, 0 },
        { CKA_NSS_EMAIL, NULL, 0 },
        { CKA_CLASS, NULL, 0 },
    };
    CK_ULONG smimeTemplateCount =
        sizeof(smimeTemplate) / sizeof(smimeTemplate[0]);
    CK_ATTRIBUTE smimeCopyTemplate[] = {
        { CKA_CLASS, NULL, 0 },
        { CKA_TOKEN, NULL, 0 },
        { CKA_LABEL, NULL, 0 },
        { CKA_PRIVATE, NULL, 0 },
        { CKA_MODIFIABLE, NULL, 0 },
        { CKA_SUBJECT, NULL, 0 },
        { CKA_NSS_EMAIL, NULL, 0 },
        { CKA_NSS_SMIME_TIMESTAMP, NULL, 0 },
        { CKA_VALUE, NULL, 0 }
    };
    CK_ULONG smimeCopyTemplateCount =
        sizeof(smimeCopyTemplate) / sizeof(smimeCopyTemplate[0]);

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        rv = SECFailure;
        goto done;
    }
    /* check to see if the crl is already in the target slot */
    rv = pk11_matchAcrossTokens(arena, targetSlot, sourceSlot, smimeTemplate,
                                smimeTemplateCount, id, &targetSmimeID);
    if (rv != SECSuccess) {
        goto done;
    }
    if (targetSmimeID != CK_INVALID_HANDLE) {
        /* we already have a SMIME record */
        goto done;
    }

    /* load the SMime Record into the target token. */
    rv = pk11_copyAttributes(arena, targetSlot, targetSmimeID, sourceSlot, id,
                             smimeCopyTemplate, smimeCopyTemplateCount);
done:
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }
    return rv;
}

/*************************************************************************
 *
 *            Trust Objects
 *
 *************************************************************************/

/*
 * decide which trust record entry wins. PR_TRUE (source) or PR_FALSE (target)
 */
#define USE_TARGET PR_FALSE
#define USE_SOURCE PR_TRUE
PRBool
pk11_mergeTrustEntry(CK_ATTRIBUTE *target, CK_ATTRIBUTE *source)
{
    CK_TRUST targetTrust = (target->ulValueLen == sizeof(CK_TRUST)) ? *(CK_TRUST *)target->pValue : CKT_TRUST_UNKNOWN;
    CK_TRUST sourceTrust = (source->ulValueLen == sizeof(CK_TRUST)) ? *(CK_TRUST *)source->pValue : CKT_TRUST_UNKNOWN;

    /*
     * Examine a single entry and deside if the source or target version
     * should win out. When all the entries have been checked, if there is
     * any case we need to update, we will write the whole source record
     * to the target database. That means for each individual record.
     */
    /* if they are identical, short cut the rest of the tests. NOTE:
     * if sourceTrust and targetTrust are different types, but 'identical'
     * then we will continue down these lists, but always select the
     * target anyway because we check the weak source versions first */
    if (sourceTrust == targetTrust) {
        return USE_TARGET; /* which equates to 'do nothing' */
    }

    /* source has no idea, use the target's idea of the trust value */
    if ((sourceTrust == CKT_TRUST_UNKNOWN) || (sourceTrust == CKT_NSS_TRUST_UNKNOWN)) {
        return USE_TARGET;
    }

    /* target has no idea, use the source's idea of the trust value */
    if ((targetTrust == CKT_TRUST_UNKNOWN) || (targetTrust == CKT_NSS_TRUST_UNKNOWN)) {
        /* source overwrites the target */
        return USE_SOURCE;
    }

    /* so both the target and the source have some idea of what this
     * trust attribute should be, and neither agree exactly.
     * At this point, we prefer 'hard' attributes over 'soft' ones.
     * 'hard' ones are CKT_TRUSTED, CKT_TRUST_ANCHOR, CKT_UNTRUTED and
     * their CKT_NSS equivalents. Soft ones are ones which don't change the
     * actual trust of the cert (CKT_TRUST_MUST_VERIFY_TRUST,
     * CKT_NSS_MUST_VERIFY_TRUST, and CKT_NSS_VALID_DELEGATOR).
     */
    if ((sourceTrust == CKT_TRUST_MUST_VERIFY_TRUST) ||
        (sourceTrust == CKT_NSS_MUST_VERIFY_TRUST) ||
        (sourceTrust == CKT_NSS_VALID_DELEGATOR)) {

        return USE_TARGET;
    }
    if ((targetTrust == CKT_TRUST_MUST_VERIFY_TRUST) ||
        (targetTrust == CKT_NSS_MUST_VERIFY_TRUST) ||
        (targetTrust == CKT_NSS_VALID_DELEGATOR)) {
        /* source overrites the target */
        return USE_SOURCE;
    }

    /* both have hard attributes, we have a conflict, let the target win. */
    return USE_TARGET;
}

/*
 * map the template trust value to the target class value.
 */
void
pk11_map_trust_entry(CK_OBJECT_CLASS targetClass, CK_ATTRIBUTE *template)
{
    CK_TRUST trust;
    CK_TRUST newTrust;

    if (template->ulValueLen != sizeof(CK_TRUST)) {
        return;
    }
    trust = *(CK_TRUST *)template->pValue;
    newTrust = (targetClass == CKO_TRUST) ? CKT_TRUST_UNKNOWN
                                          : CKT_NSS_TRUST_UNKNOWN;

    switch (trust) {
        case CKT_NSS_TRUSTED:
        case CKT_TRUSTED:
            newTrust = (targetClass == CKO_TRUST) ? CKT_TRUSTED
                                                  : CKT_NSS_TRUSTED;
            break;
        case CKT_NSS_TRUSTED_DELEGATOR:
        case CKT_TRUST_ANCHOR:
            newTrust = (targetClass == CKO_TRUST) ? CKT_TRUST_ANCHOR
                                                  : CKT_NSS_TRUSTED_DELEGATOR;
            break;
        case CKT_NSS_VALID_DELEGATOR:
            newTrust = (targetClass == CKO_TRUST) ? CKT_TRUST_MUST_VERIFY_TRUST
                                                  : CKT_NSS_VALID_DELEGATOR;
            break;
        case CKT_NSS_MUST_VERIFY_TRUST:
        case CKT_TRUST_MUST_VERIFY_TRUST:
            newTrust = (targetClass == CKO_TRUST) ? CKT_TRUST_MUST_VERIFY_TRUST
                                                  : CKT_NSS_MUST_VERIFY_TRUST;
            break;
        case CKT_NSS_NOT_TRUSTED:
        case CKT_NOT_TRUSTED:
            newTrust = (targetClass == CKO_TRUST) ? CKT_NOT_TRUSTED
                                                  : CKT_NSS_NOT_TRUSTED;
            break;
        default: /* everything else is trust unknown, which we've already set */
            break;
    }
    PORT_Memcpy(template->pValue, &newTrust, sizeof(newTrust));
    return;
}

/*
 * use the raw PKCS #11 interface to merge the S/MIME records
 */
static SECStatus
pk11_mergeTrust(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                CK_OBJECT_HANDLE id, CK_OBJECT_CLASS sourceClass,
                void *targetPwArg, void *sourcePwArg)
{
    CK_OBJECT_HANDLE targetTrustID;
    PLArenaPool *arena = NULL;
    SECStatus rv = SECSuccess;
    int error = 0;
    CK_ATTRIBUTE trustTemplate[] = {
        { CKA_ISSUER, NULL, 0 },
        { CKA_SERIAL_NUMBER, NULL, 0 },
        { CKA_CLASS, NULL, 0 },
    };
    CK_ULONG trustTemplateCount =
        sizeof(trustTemplate) / sizeof(trustTemplate[0]);
    CK_ATTRIBUTE *trustCopyTemplate = NULL;
    CK_ULONG trustCopyTemplateCount = 0;
    CK_ATTRIBUTE nssTrustCopyTemplate[] = {
        { CKA_CLASS, NULL, 0 },
        { CKA_TOKEN, NULL, 0 },
        { CKA_LABEL, NULL, 0 },
        { CKA_PRIVATE, NULL, 0 },
        { CKA_MODIFIABLE, NULL, 0 },
        { CKA_ISSUER, NULL, 0 },
        { CKA_SERIAL_NUMBER, NULL, 0 },
        { CKA_NSS_CERT_SHA1_HASH, NULL, 0 },
        { CKA_NSS_CERT_MD5_HASH, NULL, 0 },
        { CKA_NSS_TRUST_SERVER_AUTH, NULL, 0 },
        { CKA_NSS_TRUST_CLIENT_AUTH, NULL, 0 },
        { CKA_NSS_TRUST_CODE_SIGNING, NULL, 0 },
        { CKA_NSS_TRUST_EMAIL_PROTECTION, NULL, 0 },
        { CKA_NSS_TRUST_STEP_UP_APPROVED, NULL, 0 }
    };
    CK_ULONG nssTrustCopyTemplateCount = PR_ARRAY_SIZE(nssTrustCopyTemplate);
    CK_ATTRIBUTE pkcsTrustCopyTemplate[] = {
        { CKA_CLASS, NULL, 0 },
        { CKA_TOKEN, NULL, 0 },
        { CKA_LABEL, NULL, 0 },
        { CKA_PRIVATE, NULL, 0 },
        { CKA_MODIFIABLE, NULL, 0 },
        { CKA_ISSUER, NULL, 0 },
        { CKA_SERIAL_NUMBER, NULL, 0 },
        { CKA_HASH_OF_CERTIFICATE, NULL, 0 },
        { CKA_NAME_HASH_ALGORITHM, NULL, 0 },
        { CKA_PKCS_TRUST_SERVER_AUTH, NULL, 0 },
        { CKA_PKCS_TRUST_CLIENT_AUTH, NULL, 0 },
        { CKA_PKCS_TRUST_CODE_SIGNING, NULL, 0 },
        { CKA_PKCS_TRUST_EMAIL_PROTECTION, NULL, 0 },
    };
    CK_ULONG pkcsTrustCopyTemplateCount = PR_ARRAY_SIZE(pkcsTrustCopyTemplate);
    CK_OBJECT_CLASS targetClass;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        rv = SECFailure;
        goto done;
    }
    /* check to see if the trust object is already in the target slot */
    rv = pk11_matchAcrossTokens(arena, targetSlot, sourceSlot, trustTemplate,
                                trustTemplateCount, id, &targetTrustID);
    if (rv != SECSuccess) {
        goto done;
    }
    targetClass = pk11_getClassFromTemplate(trustTemplate, trustTemplateCount);
    if (targetTrustID != CK_INVALID_HANDLE) {
        /* a matching trust record already exists, merge it in */
        CK_ATTRIBUTE_TYPE nssTrustAttrs[] = {
            CKA_NSS_TRUST_SERVER_AUTH, CKA_NSS_TRUST_CLIENT_AUTH,
            CKA_NSS_TRUST_CODE_SIGNING, CKA_NSS_TRUST_EMAIL_PROTECTION,
            CKA_NSS_TRUST_IPSEC_TUNNEL, CKA_NSS_TRUST_TIME_STAMPING
        };
        CK_ATTRIBUTE_TYPE pkcsTrustAttrs[] = {
            CKA_PKCS_TRUST_SERVER_AUTH, CKA_PKCS_TRUST_CLIENT_AUTH,
            CKA_PKCS_TRUST_CODE_SIGNING, CKA_PKCS_TRUST_EMAIL_PROTECTION,
            CKA_TRUST_IPSEC_IKE, CKA_PKCS_TRUST_TIME_STAMPING
        };
        CK_ULONG trustAttrsCount = PR_ARRAY_SIZE(pkcsTrustAttrs);

        CK_ULONG i;
        CK_ATTRIBUTE targetTemplate, sourceTemplate;

        PORT_Assert(trustAttrsCount == PR_ARRAY_SIZE(nssTrustAttrs));

        /* existing trust record, merge the two together */
        for (i = 0; i < trustAttrsCount; i++) {
            targetTemplate.type = (targetClass == CKO_TRUST)
                                      ? nssTrustAttrs[i]
                                      : pkcsTrustAttrs[i];
            targetTemplate.type = (sourceClass == CKO_TRUST)
                                      ? nssTrustAttrs[i]
                                      : pkcsTrustAttrs[i];

            targetTemplate.pValue = sourceTemplate.pValue = NULL;
            targetTemplate.ulValueLen = sourceTemplate.ulValueLen = 0;
            PK11_GetAttributes(arena, sourceSlot, id, &sourceTemplate, 1);
            PK11_GetAttributes(arena, targetSlot, targetTrustID,
                               &targetTemplate, 1);
            if (pk11_mergeTrustEntry(&targetTemplate, &sourceTemplate)) {
                /* source wins, write out the source attribute to the target */
                SECStatus lrv;

                /* store the trust value in the target's object format */
                if (sourceClass != targetClass) {
                    pk11_map_trust_entry(targetClass, &sourceTemplate);
                }

                lrv = pk11_setAttributes(targetSlot, targetTrustID,
                                         &sourceTemplate, 1);
                if (lrv != SECSuccess) {
                    rv = SECFailure;
                    error = PORT_GetError();
                }
            }
        }

        /* Only handle step up if both source and target are NSS Trust
         * objects */
        if ((sourceClass == CKO_NSS_TRUST) && (targetClass == CKO_NSS_TRUST)) {
            /* handle step */
            sourceTemplate.type = CKA_NSS_TRUST_STEP_UP_APPROVED;
            sourceTemplate.pValue = NULL;
            sourceTemplate.ulValueLen = 0;

            /* if the source has steup set, then set it in the target */
            PK11_GetAttributes(arena, sourceSlot, id, &sourceTemplate, 1);
            if ((sourceTemplate.ulValueLen == sizeof(CK_BBOOL)) &&
                (sourceTemplate.pValue) &&
                (*(CK_BBOOL *)sourceTemplate.pValue == CK_TRUE)) {
                SECStatus lrv = pk11_setAttributes(targetSlot, targetTrustID,
                                                   &sourceTemplate, 1);
                if (lrv != SECSuccess) {
                    rv = SECFailure;
                    error = PORT_GetError();
                }
            }
        }

        goto done;
    }

    /* load the new trust Record into the target token. */
    trustCopyTemplate = (sourceClass == CKO_TRUST) ? pkcsTrustCopyTemplate
                                                   : nssTrustCopyTemplate;
    trustCopyTemplateCount = (sourceClass == CKO_TRUST)
                                 ? pkcsTrustCopyTemplateCount
                                 : nssTrustCopyTemplateCount;
    rv = pk11_copyAttributes(arena, targetSlot, targetTrustID, sourceSlot, id,
                             trustCopyTemplate, trustCopyTemplateCount);
done:
    if (arena) {
        PORT_FreeArena(arena, PR_FALSE);
    }

    /* restore the error code */
    if (rv == SECFailure && error) {
        PORT_SetError(error);
    }

    return rv;
}

/*************************************************************************
 *
 *            Central merge code
 *
 *************************************************************************/
/*
 * merge a single object from sourceToken to targetToken
 */
static SECStatus
pk11_mergeObject(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                 CK_OBJECT_HANDLE id, void *targetPwArg, void *sourcePwArg)
{

    CK_OBJECT_CLASS objClass;

    objClass = PK11_ReadULongAttribute(sourceSlot, id, CKA_CLASS);
    if (objClass == (CK_ULONG)-1) {
        PORT_SetError(SEC_ERROR_UNKNOWN_OBJECT_TYPE);
        return SECFailure;
    }

    switch (objClass) {
        case CKO_CERTIFICATE:
            return pk11_mergeCert(targetSlot, sourceSlot, id,
                                  targetPwArg, sourcePwArg);
        case CKO_NSS_TRUST:
        case CKO_TRUST:
            return pk11_mergeTrust(targetSlot, sourceSlot, id,
                                   objClass, targetPwArg, sourcePwArg);
        case CKO_PUBLIC_KEY:
            return pk11_mergePublicKey(targetSlot, sourceSlot, id,
                                       targetPwArg, sourcePwArg);
        case CKO_PRIVATE_KEY:
            return pk11_mergePrivateKey(targetSlot, sourceSlot, id,
                                        targetPwArg, sourcePwArg);
        case CKO_SECRET_KEY:
            return pk11_mergeSecretKey(targetSlot, sourceSlot, id,
                                       targetPwArg, sourcePwArg);
        case CKO_NSS_CRL:
            return pk11_mergeCrl(targetSlot, sourceSlot, id,
                                 targetPwArg, sourcePwArg);
        case CKO_NSS_SMIME:
            return pk11_mergeSmime(targetSlot, sourceSlot, id,
                                   targetPwArg, sourcePwArg);
        default:
            break;
    }

    PORT_SetError(SEC_ERROR_UNKNOWN_OBJECT_TYPE);
    return SECFailure;
}

PK11MergeLogNode *
pk11_newMergeLogNode(PLArenaPool *arena,
                     PK11SlotInfo *slot, CK_OBJECT_HANDLE id, int error)
{
    PK11MergeLogNode *newLog;
    PK11GenericObject *obj;

    newLog = PORT_ArenaZNew(arena, PK11MergeLogNode);
    if (newLog == NULL) {
        return NULL;
    }

    obj = PORT_ArenaZNew(arena, PK11GenericObject);
    if (!obj) {
        return NULL;
    }

    /* initialize it */
    obj->slot = slot;
    obj->objectID = id;
    obj->owner = PR_FALSE;

    newLog->object = obj;
    newLog->error = error;
    return newLog;
}

/*
 * walk down each entry and merge it. keep track of the errors in the log
 */
static SECStatus
pk11_mergeByObjectIDs(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                      CK_OBJECT_HANDLE *objectIDs, int count,
                      PK11MergeLog *log, void *targetPwArg, void *sourcePwArg)
{
    SECStatus rv = SECSuccess;
    int error = SEC_ERROR_LIBRARY_FAILURE;
    int i;

    for (i = 0; i < count; i++) {
        /* try to update the entire database. On failure, keep going,
         * but remember the error to report back to the caller */
        SECStatus lrv;
        PK11MergeLogNode *newLog;

        lrv = pk11_mergeObject(targetSlot, sourceSlot, objectIDs[i],
                               targetPwArg, sourcePwArg);
        if (lrv == SECSuccess) {
            /* merged with no problem, go to next object */
            continue;
        }

        /* remember that we failed and why */
        rv = SECFailure;
        error = PORT_GetError();

        /* log the errors */
        if (!log) {
            /* not logging, go to next entry */
            continue;
        }
        newLog = pk11_newMergeLogNode(log->arena, sourceSlot,
                                      objectIDs[i], error);
        if (!newLog) {
            /* failed to allocate entry, just keep going */
            continue;
        }

        /* link in the errorlog entry */
        newLog->next = NULL;
        if (log->tail) {
            log->tail->next = newLog;
        } else {
            log->head = newLog;
        }
        newLog->prev = log->tail;
        log->tail = newLog;
    }

    /* restore the last error code */
    if (rv != SECSuccess) {
        PORT_SetError(error);
    }
    return rv;
}

/*
 * Merge all the records in sourceSlot that aren't in targetSlot
 *
 *   This function will return failure if not all the objects
 *   successfully merged.
 *
 *   Applications can pass in an optional error log which will record
 *   each failing object and why it failed to import. PK11MergeLog
 *   is modelled after the CERTVerifyLog.
 */
SECStatus
PK11_MergeTokens(PK11SlotInfo *targetSlot, PK11SlotInfo *sourceSlot,
                 PK11MergeLog *log, void *targetPwArg, void *sourcePwArg)
{
    SECStatus rv = SECSuccess, lrv = SECSuccess;
    int error = SEC_ERROR_LIBRARY_FAILURE;
    int count = 0;
    CK_ATTRIBUTE search[2];
    CK_OBJECT_HANDLE *objectIDs = NULL;
    CK_BBOOL ck_true = CK_TRUE;
    CK_OBJECT_CLASS privKey = CKO_PRIVATE_KEY;

    PK11_SETATTRS(&search[0], CKA_TOKEN, &ck_true, sizeof(ck_true));
    PK11_SETATTRS(&search[1], CKA_CLASS, &privKey, sizeof(privKey));
    /*
     * make sure both tokens are already authenticated if need be.
     */
    rv = PK11_Authenticate(targetSlot, PR_TRUE, targetPwArg);
    if (rv != SECSuccess) {
        goto loser;
    }
    rv = PK11_Authenticate(sourceSlot, PR_TRUE, sourcePwArg);
    if (rv != SECSuccess) {
        goto loser;
    }

    /* turns out the old DB's are rather fragile if the private keys aren't
     * merged in first, so do the private keys explicity. */
    objectIDs = pk11_FindObjectsByTemplate(sourceSlot, search, 2, &count);
    if (objectIDs) {
        lrv = pk11_mergeByObjectIDs(targetSlot, sourceSlot,
                                    objectIDs, count, log,
                                    targetPwArg, sourcePwArg);
        if (lrv != SECSuccess) {
            error = PORT_GetError();
        }
        PORT_Free(objectIDs);
        count = 0;
    }

    /* now do the rest  (NOTE: this will repeat the private keys, but
     * that shouldnt' be an issue as we will notice they are already
     * merged in */
    objectIDs = pk11_FindObjectsByTemplate(sourceSlot, search, 1, &count);
    if (!objectIDs) {
        rv = SECFailure;
        goto loser;
    }

    rv = pk11_mergeByObjectIDs(targetSlot, sourceSlot, objectIDs, count, log,
                               targetPwArg, sourcePwArg);
    if (rv == SECSuccess) {
        /* if private keys failed, but the rest succeeded, be sure to let
         * the caller know that private keys failed and why.
         * NOTE: this is highly unlikely since the same keys that failed
         * in the previous merge call will most likely fail in this one */
        if (lrv != SECSuccess) {
            rv = lrv;
            PORT_SetError(error);
        }
    }

loser:
    if (objectIDs) {
        PORT_Free(objectIDs);
    }
    return rv;
}

PK11MergeLog *
PK11_CreateMergeLog(void)
{
    PLArenaPool *arena;
    PK11MergeLog *log;

    arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
    if (arena == NULL) {
        return NULL;
    }

    log = PORT_ArenaZNew(arena, PK11MergeLog);
    if (log == NULL) {
        PORT_FreeArena(arena, PR_FALSE);
        return NULL;
    }
    log->arena = arena;
    log->version = 1;
    return log;
}

void
PK11_DestroyMergeLog(PK11MergeLog *log)
{
    if (log && log->arena) {
        PORT_FreeArena(log->arena, PR_FALSE);
    }
}
