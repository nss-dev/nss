/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil -*- */

/*
 * Functions used by https servers to send (download) pre-encrypted files
 * over SSL connections that use Fortezza ciphersuites.
 *
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
 *
 * $Id$
 */

#ifndef NSSDEV_H
#include "nssdev.h"
#endif /* NSSDEV_H */

#ifndef NSSPKI_H
#include "nsspki.h"
#endif /* NSSPKI_H */

#include "ssl.h"
#include "sslimpl.h"
#include "preenc.h"

static unsigned char fromHex(char x) {
    if ((x >= '0') && (x <= '9')) return x-'0';
    if ((x >= 'a') && (x <= 'f')) return x-'a'+10;
    return x-'A'+10;
}

PEHeader *SSL_PreencryptedStreamToFile(PRFileDesc *fd, PEHeader *inHeader, 
								int *headerSize)
{
    NSSSymKey *key, *tek, *Ks;
    sslSocket *ss;
    NSSToken **tokens;
    NSSToken *token;
    NSSOID *skipjack;
    NSSAlgNParam *skipjackWrap;
    int oldHeaderSize;
    PEHeader *header;
    SECStatus rv;
    NSSItem item;
    int i;
    
    if (fd == NULL) {
        /* XXX set an error */
        return NULL;
    }
    
    ss = ssl_FindSocket(fd);
    if (ss == NULL) {
        return NULL;
    }
    
    PORT_Assert(ss->ssl3 != NULL);
    if (ss->ssl3 == NULL) {
	return NULL;
    }

    if (GetInt2(inHeader->magic) != PRE_MAGIC) {
	return NULL;
    }

    oldHeaderSize = GetInt2(inHeader->len);
    header = (PEHeader *) PORT_ZAlloc(oldHeaderSize);
    if (header == NULL) {
	return NULL;
    }

    switch (GetInt2(inHeader->type)) {
    case PRE_FORTEZZA_FILE:
    case PRE_FORTEZZA_GEN_STREAM:
    case PRE_FIXED_FILE:
    case PRE_RSA_FILE:
    default:
	*headerSize = oldHeaderSize;
	PORT_Memcpy(header,inHeader,oldHeaderSize);
	return header;

    case PRE_FORTEZZA_STREAM:
	*headerSize = PE_BASE_HEADER_LEN + sizeof(PEFortezzaHeader);
        PutInt2(header->magic,PRE_MAGIC);
	PutInt2(header->len,*headerSize);
	PutInt2(header->type, PRE_FORTEZZA_FILE);
	PORT_Memcpy(header->version,inHeader->version,sizeof(header->version));
	PORT_Memcpy(header->u.fortezza.hash,inHeader->u.fortezza.hash,
					     sizeof(header->u.fortezza.hash));
	PORT_Memcpy(header->u.fortezza.iv,inHeader->u.fortezza.iv,
					      sizeof(header->u.fortezza.iv));

	/* get the kea context from the session */
	tek = ss->ssl3->fortezza.tek;
	if (tek == NULL) {
	    PORT_Free(header);
	    return NULL;
	}

	/* get the token and the serial number */
	tokens = NSSSymKey_GetTokens(tek, NULL);
	if (tokens == NULL) {
	    PORT_Free(header);
	    return NULL;
	}
	token = tokens[0];
	rv = NSSToken_GetInfo(token, &info);
	if (rv != SECSuccess) {
	    PORT_Free(header);
	    NSSTokenArray_Destroy(tokens);
	    return NULL;
	}

	/* Look up the Token Fixed Key */
	Ks = NSSToken_FindFixedKey(token, NULL, ss->pinCallback);
	NSSTokenArray_Destroy(tokens);
	if (Ks == NULL) {
	    PORT_Free(header);
	    return NULL;
	}

	/* set up the algorithms */
	skipjack = NSSOID_CreateFromTag(NSS_OID_FORTEZZA_SKIPJACK);
	if (!skipjack) {
	    PORT_Free(header);
	    NSSSymKey_Destroy(Ks);
	    return NULL;
	}
	skipjackWrap = NSSAlgNParam_CreateWrap(NULL,
	                             NSSAlgorithmType_Skipjack, NULL);
	if (!skipjackWrap) {
	    PORT_Free(header);
	    NSSSymKey_Destroy(Ks);
	    return NULL;
	}

	/* unwrap the key with the TEK */
	item.data = inHeader->u.fortezza.key;
	item.size = sizeof(inHeader->u.fortezza.key);
	key = NSSSymKey_UnwrapSymKey(tek,
	                                         skipjackWrap,
	                                         &item,
	                                         skipjack,
	                                         NSSOperations_DECRYPT, 0);
#if 0
	key = PK11_UnwrapSymKey(tek,CKM_SKIPJACK_WRAP,
                        NULL, &item, CKM_SKIPJACK_CBC64, CKA_DECRYPT, 0);
#endif
	if (key == NULL) {
	    PORT_Free(header);
	    NSSSymKey_Destroy(Ks);
	    NSSAlgNParam_Destroy(skipjackWrap);
	    return NULL;
	}

	/* rewrap with the local Ks */
	item.data = header->u.fortezza.key;
	item.size = sizeof(header->u.fortezza.key);
	rv = NSSSymKey_Wrap(Ks, skipjackWrap, key,
	                          ss->pinCallback, &item, NULL);
#if 0
	rv = PK11_WrapSymKey(CKM_SKIPJACK_WRAP, NULL, Ks, key, &item);
#endif
	NSSSymKey_Destroy(Ks);
	NSSSymKey_Destroy(key);
	NSSAlgNParam_Destroy(skipjackWrap);
	if (rv != SECSuccess) {
	    PORT_Free(header);
	    return NULL;
	}
    
	/* copy our local serial number into header */
	for (i=0; i < sizeof(header->u.fortezza.serial); i++) {
	    header->u.fortezza.serial[i] = 
		(fromHex(info.serialNumber[i*2]) << 4) 	|
					fromHex(info.serialNumber[i*2 + 1]);
	}
	break;
    case PRE_FIXED_STREAM:
	/* not implemented yet */
	PORT_Free(header);
	return NULL;
    }
    
    return(header);
}

/*
 * this one needs to allocate space and work for RSA & FIXED key files as well
 */
PEHeader *SSL_PreencryptedFileToStream(PRFileDesc *fd, PEHeader *header, 
							int *headerSize)
{
    NSSSymKey *key, *tek, *Ks;
    sslSocket *ss;
    NSSToken **tokens;
    NSSToken *token;
    NSSOID *skipjack;
    NSSAlgNParam *skipjackWrap;
    PRStatus rv;
    NSSItem item;
    
    *headerSize = 0; /* hack */
 
    if (fd == NULL) {
        /* XXX set an error */
        return NULL;
    }
    
    ss = ssl_FindSocket(fd);
    if (ss == NULL) {
        return NULL;
    }
    
    PORT_Assert(ss->ssl3 != NULL);
    if (ss->ssl3 == NULL) {
	return NULL;
    }

    /* get the kea context from the session */
    tek = ss->ssl3->fortezza.tek;
    if (tek == NULL) {
	return NULL;
    }

    slot = PK11_GetSlotFromKey(tek);
    /* get the token and the serial number */
    tokens = NSSSymKey_GetTokens(tek, NULL);
    if (tokens == NULL) {
	return NULL;
    }
    token = tokens[0];
    Ks = NSSToken_FindFixedKey(token, NULL, ss->pinCallback);
#if 0
    Ks = PK11_FindFixedKey(slot, CKM_SKIPJACK_WRAP, NULL, PK11_GetWindow(tek));
#endif
    NSSTokenArray_Destroy(tokens);
    if (Ks == NULL) return NULL;

    /* set up the algorithms */
    skipjack = NSSOID_CreateFromTag(NSS_OID_FORTEZZA_SKIPJACK);
    if (!skipjack) {
	NSSSymKey_Destroy(Ks);
	return NULL;
    }
    skipjackWrap = NSSAlgNParam_CreateWrap(NULL,
                                              NSSAlgorithmType_Skipjack, NULL);
    if (!skipjackWrap) {
	NSSSymKey_Destroy(Ks);
	return NULL;
    }

    /* unwrap with the local Ks */
    item.data = header->u.fortezza.key;
    item.size = sizeof(header->u.fortezza.key);
    /* rewrap the key with the TEK */
    key = NSSSymKey_UnwrapSymKey(Ks, skipjackWrap,
                                             &item, skipjack,
                                             NSSOperations_DECRYPT, 0);
#if 0
    key = PK11_UnwrapSymKey(Ks,CKM_SKIPJACK_WRAP,
                        NULL, &item, CKM_SKIPJACK_CBC64, CKA_DECRYPT, 0);
#endif
    if (key == NULL) {
	NSSSymKey_Destroy(Ks);
	return NULL;
    }

    rv = NSSSymKey_Wrap(tek, skipjackWrap, key,
                              ss->pinCallback, &item, NULL);
#if 0
    rv = PK11_WrapSymKey(CKM_SKIPJACK_WRAP, NULL, tek, key, &item);
#endif
    NSSSymKey_Destroy(Ks);
    NSSSymKey_Destroy(key);
    if (rv != SECSuccess) {
	return NULL;
    }
    
    /* copy over our local serial number */
    PORT_Memset(header->u.fortezza.serial,0,sizeof(header->u.fortezza.serial));
    
    /* change type to stream */
    PutInt2(header->type, PRE_FORTEZZA_STREAM);
    
    return(header);
}


