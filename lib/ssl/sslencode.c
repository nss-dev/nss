/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "nss.h"
#include "prnetdb.h"
#include "ssl.h"
#include "sslimpl.h"

/* Helper function to encode an unsigned integer into a buffer. */
PRUint8 *
ssl_EncodeUintX(PRUint64 value, unsigned int bytes, PRUint8 *to)
{
    PRUint64 encoded;

    PORT_Assert(bytes > 0 && bytes <= sizeof(encoded));

    encoded = PR_htonll(value);
    memcpy(to, ((unsigned char *)(&encoded)) + (sizeof(encoded) - bytes), bytes);
    return to + bytes;
}

/* Grow a buffer to hold newLen bytes of data.  When used for recv/xmit buffers,
 * the caller must hold xmitBufLock or recvBufLock, as appropriate. */
SECStatus
sslBuffer_Grow(sslBuffer *b, unsigned int newLen)
{
    newLen = PR_MAX(newLen, b->len + 1024);
    if (newLen > b->space) {
        unsigned char *newBuf;
        if (b->buf) {
            newBuf = (unsigned char *)PORT_Realloc(b->buf, newLen);
        } else {
            newBuf = (unsigned char *)PORT_Alloc(newLen);
        }
        if (!newBuf) {
            return SECFailure;
        }
        b->buf = newBuf;
        b->space = newLen;
    }
    return SECSuccess;
}

SECStatus
sslBuffer_Append(sslBuffer *b, const void *data, unsigned int len)
{
    SECStatus rv = sslBuffer_Grow(b, b->len + len);
    if (rv != SECSuccess) {
        return rv; /* Code already set. */
    }
    PORT_Memcpy(b->buf + b->len, data, len);
    b->len += len;
    return SECSuccess;
}

SECStatus
sslBuffer_AppendNumber(sslBuffer *b, PRUint64 v, unsigned int size)
{
    SECStatus rv = sslBuffer_Grow(b, b->len + size);
    if (rv != SECSuccess) {
        return rv;
    }
    (void)ssl_EncodeUintX(v, size, b->buf + b->len);
    b->len += size;
    return SECSuccess;
}

SECStatus
sslBuffer_AppendVariable(sslBuffer *b, const PRUint8 *data, unsigned int len,
                         unsigned int size)
{
    SECStatus rv = sslBuffer_Grow(b, b->len + len + size);
    if (rv != SECSuccess) {
        return rv;
    }
    (void)ssl_EncodeUintX(len, size, b->buf + b->len);
    b->len += size;
    PORT_Memcpy(b->buf + b->len, data, len);
    b->len += len;
    return SECSuccess;
}

SECStatus
sslBuffer_AppendBuffer(sslBuffer *b, const sslBuffer *append)
{
    return sslBuffer_Append(b, append->buf, append->len);
}

SECStatus
sslBuffer_AppendBufferVariable(sslBuffer *b, const sslBuffer *append,
                               unsigned int size)
{
    return sslBuffer_AppendVariable(b, append->buf, append->len, size);
}

void
sslBuffer_Clear(sslBuffer *b)
{
    if (b->buf) {
        PORT_Free(b->buf);
        b->buf = NULL;
        b->len = 0;
        b->space = 0;
    }
}

SECStatus
ssl3_AppendToItem(SECItem *item, const unsigned char *buf, PRUint32 bytes)
{
    if (bytes > item->len) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    PORT_Memcpy(item->data, buf, bytes);
    item->data += bytes;
    item->len -= bytes;
    return SECSuccess;
}

SECStatus
ssl3_AppendNumberToItem(SECItem *item, PRUint32 num, PRInt32 lenSize)
{
    SECStatus rv;
    PRUint8 b[sizeof(num)];

    ssl_EncodeUintX(num, lenSize, b);
    rv = ssl3_AppendToItem(item, &b[0], lenSize);
    return rv;
}

SECStatus
ssl3_ConsumeFromItem(SECItem *item, unsigned char **buf, PRUint32 bytes)
{
    if (bytes > item->len) {
        PORT_SetError(SEC_ERROR_BAD_DATA);
        return SECFailure;
    }

    *buf = item->data;
    item->data += bytes;
    item->len -= bytes;
    return SECSuccess;
}

SECStatus
ssl3_ConsumeNumberFromItem(SECItem *item, PRUint32 *num, PRUint32 bytes)
{
    int i;

    if (bytes > item->len || bytes > sizeof(*num)) {
        PORT_SetError(SEC_ERROR_BAD_DATA);
        return SECFailure;
    }

    *num = 0;
    for (i = 0; i < bytes; i++) {
        *num = (*num << 8) + item->data[i];
    }

    item->data += bytes;
    item->len -= bytes;

    return SECSuccess;
}
