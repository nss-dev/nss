#ifdef PK11_BYPASS
#include "ssl.h" 	/* prereq to sslimpl.h */
#include "certt.h"	/* prereq to sslimpl.h */
#include "keythi.h"	/* prereq to sslimpl.h */
#include "sslimpl.h"
#include "blapi.h"

/* make this a macro! */
#ifdef NOT_A_MACRO
static void
buildSSLKey(unsigned char * keyBlock, unsigned int keyLen, SECItem * result)
{
    result->type = siBuffer;
    result->data = keyBlock;
    result->len  = keyLen;
}
#else
#define buildSSLKey(keyBlock, keyLen, result) \
{ \
    (result)->type = siBuffer; \
    (result)->data = keyBlock; \
    (result)->len  = keyLen; \
}
#endif

#define SSL3_PMS_LENGTH 48
#define SSL3_MASTER_SECRET_LENGTH 48
/*
 * SSL Key generation given pre master secret
 */
#ifndef NUM_MIXERS
#define NUM_MIXERS 9
#endif
static const char * const mixers[NUM_MIXERS] = { 
    "A", 
    "BB", 
    "CCC", 
    "DDDD", 
    "EEEEE", 
    "FFFFFF", 
    "GGGGGGG",
    "HHHHHHHH",
    "IIIIIIIII" 
};


SECStatus
ssl3_KeyAndMacDerive( 
    ssl3CipherSpec *      pwSpec,
    const unsigned char * cr,
    const unsigned char * sr,
    PRBool                isTLS,
    PRBool                isExport)
{
    const ssl3BulkCipherDef *cipher_def = pwSpec->cipher_def;
    unsigned char * key_block    = pwSpec->key_block;
    unsigned char * key_block2   = NULL;
    unsigned int    block_bytes  = 0;
    unsigned int    block_needed = 0;
    unsigned int    i;
    unsigned int    keySize;            /* actual    size of cipher keys */
    unsigned int    effKeySize;		/* effective size of cipher keys */
    unsigned int    macSize;		/* size of MAC secret */
    unsigned int    IVSize;		/* size of IV */
    SECStatus       rv    = SECFailure;
    SECStatus       status = SECSuccess;

    SECItem         srcr;
    SECItem         crsr;

    unsigned char     srcrdata[SSL3_RANDOM_LENGTH * 2];
    unsigned char     crsrdata[SSL3_RANDOM_LENGTH * 2];
    PRUint64          md5buf[22];
    PRUint64          shabuf[40];

#define md5ctx ((MD5Context *)md5buf)
#define shaCtx ((SHA1Context *)shabuf)

    static const SECItem zed  = { siBuffer, NULL, 0 };

    if (pwSpec->msItem.data == NULL ||
        pwSpec->msItem.len  != SSL3_MASTER_SECRET_LENGTH) {
	PORT_SetError(SEC_ERROR_INVALID_ARGS);
	return rv;
    }

    /* figure out how much is needed */
    macSize    = pwSpec->mac_size;
    keySize    = cipher_def->key_size;
    effKeySize = cipher_def->secret_key_size;
    IVSize     = cipher_def->iv_size;
    if (keySize == 0) {
	effKeySize = IVSize = 0; /* only MACing */
    }
    block_needed = 2 * (macSize + effKeySize + ((!isExport) * IVSize));

    /*
     * clear out our returned keys so we can recover on failure
     */
    pwSpec->client.write_key        = zed;
    pwSpec->client.write_mac_key    = zed;
    pwSpec->server.write_key        = zed;
    pwSpec->server.write_mac_key    = zed;

    /* initialize the server random, client random block */
    srcr.type   = siBuffer;
    srcr.data   = srcrdata;
    srcr.len    = sizeof srcrdata;
    PORT_Memcpy(srcrdata, sr, SSL3_RANDOM_LENGTH);
    PORT_Memcpy(srcrdata + SSL3_RANDOM_LENGTH, cr, SSL3_RANDOM_LENGTH);

    /* initialize the client random, server random block */
    crsr.type   = siBuffer;
    crsr.data   = crsrdata;
    crsr.len    = sizeof crsrdata;
    PORT_Memcpy(crsrdata, sr, SSL3_RANDOM_LENGTH);
    PORT_Memcpy(crsrdata + SSL3_RANDOM_LENGTH, cr, SSL3_RANDOM_LENGTH);

    /*
     * generate the key material:
     */
    if (isTLS) {
#ifndef BYPASS_TLS
	abort();
#else
	SECItem       keyblk;

	keyblk.type = siBuffer;
	keyblk.data = key_block;
	keyblk.len  = block_needed;

	status = pk11_PRF(pMasterSecret, "key expansion", &srcr, &keyblk,
			  isFIPS);
	if (status != SECSuccess) {
	    goto key_and_mac_derive_fail;
	}
	block_bytes = ???
#endif
    } else {
	/* key_block = 
	 *     MD5(master_secret + SHA('A' + master_secret + 
	 *                      ServerHello.random + ClientHello.random)) +
	 *     MD5(master_secret + SHA('BB' + master_secret + 
	 *                      ServerHello.random + ClientHello.random)) +
	 *     MD5(master_secret + SHA('CCC' + master_secret + 
	 *                      ServerHello.random + ClientHello.random)) +
	 *     [...];
	 */
	int made = 0;
	for (i = 0; made < block_needed && i < NUM_MIXERS; ++i) {
	    unsigned int    outLen;
	    unsigned char   sha_out[SHA1_LENGTH];

	    SHA1_Begin(shaCtx);
	    SHA1_Update(shaCtx, (unsigned char*)(mixers[i]), i+1);
	    SHA1_Update(shaCtx, pwSpec->msItem.data, pwSpec->msItem.len);
	    SHA1_Update(shaCtx, srcr.data, srcr.len);
	    SHA1_End(shaCtx, sha_out, &outLen, SHA1_LENGTH);
	    PORT_Assert(outLen == SHA1_LENGTH);

	    MD5_Begin(md5ctx);
	    MD5_Update(md5ctx, pwSpec->msItem.data, pwSpec->msItem.len);
	    MD5_Update(md5ctx, sha_out, outLen);
	    MD5_End(md5ctx, key_block + made, &outLen, MD5_LENGTH);
	    PORT_Assert(outLen == MD5_LENGTH);
	    made += MD5_LENGTH;
	}
	block_bytes = made;
    }
    PORT_Assert(block_bytes >= block_needed);
    PORT_Assert(block_bytes <= sizeof pwSpec->key_block);

    /*
     * Put the key material where it goes.
     */
    key_block2 = key_block + block_bytes;
    i = 0;			/* now shows how much consumed */

    /* 
     * The key_block is partitioned as follows:
     * client_write_MAC_secret[CipherSpec.hash_size]
     */
    buildSSLKey(&key_block[i],macSize, &pwSpec->client.write_mac_key);
    i += macSize;

    /* 
     * server_write_MAC_secret[CipherSpec.hash_size]
     */
    buildSSLKey(&key_block[i],macSize, &pwSpec->server.write_mac_key);
    i += macSize;

    if (!keySize) {
	/* only MACing */
	buildSSLKey(NULL, 0, &pwSpec->client.write_key);
	buildSSLKey(NULL, 0, &pwSpec->server.write_key);
	buildSSLKey(NULL, 0, &pwSpec->client.write_iv);
	buildSSLKey(NULL, 0, &pwSpec->server.write_iv);
    } else if (!isExport) {
	/* 
	** Generate Domestic write keys and IVs.
	** client_write_key[CipherSpec.key_material]
	*/
	buildSSLKey(&key_block[i], keySize, &pwSpec->client.write_key);
	i += keySize;

	/* 
	** server_write_key[CipherSpec.key_material]
	*/
	buildSSLKey(&key_block[i], keySize, &pwSpec->server.write_key);
	i += keySize;

	if (IVSize > 0) {
	    /* 
	    ** client_write_IV[CipherSpec.IV_size]
	    */
	    buildSSLKey(&key_block[i], IVSize, &pwSpec->client.write_iv);
	    i += IVSize;

	    /* 
	    ** server_write_IV[CipherSpec.IV_size]
	    */
	    buildSSLKey(&key_block[i], IVSize, &pwSpec->server.write_iv);
	    i += IVSize;
	}
	PORT_Assert(i <= block_bytes);

    } else if (!isTLS) { 
	/*
	** Generate SSL3 Export write keys and IVs.
	*/
	unsigned int    outLen;

	/*
	** client_write_key[CipherSpec.key_material]
	** final_client_write_key = MD5(client_write_key +
	**                   ClientHello.random + ServerHello.random);
	*/
	MD5_Begin(md5ctx);
	MD5_Update(md5ctx, &key_block[i], effKeySize);
	MD5_Update(md5ctx, crsr.data, crsr.len);
	MD5_End(md5ctx, key_block2, &outLen, MD5_LENGTH);
	i += effKeySize;
	buildSSLKey(key_block2, keySize, &pwSpec->client.write_key);
	key_block2 += keySize;

	/*
	** server_write_key[CipherSpec.key_material]
	** final_server_write_key = MD5(server_write_key +
	**                    ServerHello.random + ClientHello.random);
	*/
	MD5_Begin(md5ctx);
	MD5_Update(md5ctx, &key_block[i], effKeySize);
	MD5_Update(md5ctx, srcr.data, srcr.len);
	MD5_End(md5ctx, key_block2, &outLen, MD5_LENGTH);
	i += effKeySize;
	buildSSLKey(key_block2, keySize, &pwSpec->server.write_key);
	key_block2 += keySize;
	PORT_Assert(i <= block_bytes);

	if (IVSize) {
	    /*
	    ** client_write_IV = 
	    **	MD5(ClientHello.random + ServerHello.random);
	    */
	    MD5_Begin(md5ctx);
	    MD5_Update(md5ctx, crsr.data, crsr.len);
	    MD5_End(md5ctx, key_block2, &outLen, MD5_LENGTH);
	    buildSSLKey(key_block2, IVSize, &pwSpec->client.write_key);
	    key_block2 += IVSize;

	    /*
	    ** server_write_IV = 
	    **	MD5(ServerHello.random + ClientHello.random);
	    */
	    MD5_Begin(md5ctx);
	    MD5_Update(md5ctx, srcr.data, srcr.len);
	    MD5_End(md5ctx, key_block2, &outLen, MD5_LENGTH);
	    buildSSLKey(key_block2, IVSize, &pwSpec->server.write_key);
	    key_block2 += IVSize;
	}

	PORT_Assert(key_block2 - key_block <= sizeof pwSpec->key_block);
    } else {
#ifndef BYPASS_TLS
	abort();
#else
	/*
	** Generate TLS Export write keys and IVs.
	*/
	SECItem       secret ;
	SECItem       keyblk ;

	secret.type = siBuffer;
	keyblk.type = siBuffer;
	/*
	** client_write_key[CipherSpec.key_material]
	** final_client_write_key = PRF(client_write_key, 
	**                              "client write key",
	**                              client_random + server_random);
	*/
	secret.data = &key_block[i];
	secret.len  = effKeySize;
	i          += effKeySize;
	keyblk.data = key_block2;
	keyblk.len  = keySize;
	status = pk11_PRF(&secret, "client write key", &crsr, &keyblk, isFIPS);
	if (status != SECSuccess) {
	    goto key_and_mac_derive_fail;
	}
	buildSSLKey(key_block2, keySize, pwSpec->client.write_key);
	key_block2 += keySize;

	/*
	** server_write_key[CipherSpec.key_material]
	** final_server_write_key = PRF(server_write_key,
	**                              "server write key",
	**                              client_random + server_random);
	*/
	secret.data = &key_block[i];
	secret.len  = effKeySize;
	i          += effKeySize;
	keyblk.data = key_block2;
	keyblk.len  = keySize;
	status = pk11_PRF(&secret, "server write key", &crsr, &keyblk, isFIPS);
	if (status != SECSuccess) {
	    goto key_and_mac_derive_fail;
	}
	buildSSLKey(key_block2, keySize, pwSpec->server.write_key);
	key_block2 += keySize;

	/*
	** iv_block = PRF("", "IV block", client_random + server_random);
	** client_write_IV[SecurityParameters.IV_size]
	** server_write_IV[SecurityParameters.IV_size]
	*/
	if (IVSize) {
	    secret.data = NULL;
	    secret.len  = 0;
	    keyblk.data = &key_block[i];
	    keyblk.len  = 2 * IVSize;
	    status = pk11_PRF(&secret, "IV block", &crsr, &keyblk, isFIPS);
	    if (status != SECSuccess) {
		goto key_and_mac_derive_fail;
	    }
	    buildSSLKey(key_block2,          IVSize, pwSpec->client.write_iv);
	    buildSSLKey(key_block2 + IVSize, IVSize, pwSpec->server.write_iv);
	    key_block2 += 2 * IVSize;
	}
	PORT_Assert(key_block2 - key_block <= sizeof pwSpec->key_block);
#endif
    }
    rv = SECSuccess;

key_and_mac_derive_fail:

    MD5_DestroyContext(md5ctx, PR_FALSE);
    SHA1_DestroyContext(shaCtx, PR_FALSE);

    if (rv != SECSuccess) {
	PORT_SetError(SSL_ERROR_SESSION_KEY_GEN_FAILURE);
    }

    return rv;
}
#endif /* PK11_BYPASS */
