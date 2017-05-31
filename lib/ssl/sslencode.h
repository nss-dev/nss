/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is PRIVATE to SSL.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __sslencode_h_
#define __sslencode_h_

PRUint8 *ssl_EncodeUintX(PRUint64 value, unsigned int bytes, PRUint8 *to);

/*
 ** A buffer object.
 */
typedef struct sslBufferStr {
    PRUint8 *buf;
    unsigned int len;
    unsigned int space;
} sslBuffer;

SECStatus sslBuffer_Grow(sslBuffer *b, unsigned int newLen);
SECStatus sslBuffer_Append(sslBuffer *b, const void *data, unsigned int len);
SECStatus sslBuffer_AppendNumber(sslBuffer *b, PRUint64 v, unsigned int size);
SECStatus sslBuffer_AppendVariable(sslBuffer *b, const PRUint8 *data,
                                   unsigned int len, unsigned int size);
SECStatus sslBuffer_AppendBuffer(sslBuffer *b, const sslBuffer *append);
SECStatus sslBuffer_AppendBufferVariable(sslBuffer *b, const sslBuffer *append,
                                         unsigned int size);
void sslBuffer_Clear(sslBuffer *b);

/* All of these functions modify the underlying SECItem, and so should
 * be performed on a shallow copy.*/
SECStatus ssl3_AppendToItem(SECItem *item,
                            const unsigned char *buf, PRUint32 bytes);
SECStatus ssl3_AppendNumberToItem(SECItem *item,
                                  PRUint32 num, PRInt32 lenSize);
SECStatus ssl3_ConsumeFromItem(SECItem *item,
                               unsigned char **buf, PRUint32 bytes);
SECStatus ssl3_ConsumeNumberFromItem(SECItem *item,
                                     PRUint32 *num, PRUint32 bytes);

#endif /* __sslencode_h_ */
