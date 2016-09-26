/*
 * Copyright (c) 2011 Collabora Ltd.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 *
 * Ported to NSS by David Woodhouse <dwmw2@infradead.org> and thus parts
 *
 * Copyright (C) 2016 Intel Corporation
 */

#ifndef _P11URI_H_
#define _P11URI_H_

#include "seccomon.h"

#include "pkcs11.h"

SEC_BEGIN_PROTOS

/*
 * This is the p11-kit URI functionality, as described at
 * https://p11-glue.freedesktop.org/doc/p11-kit/p11-kit-URIs.html
 *
 * Since we support platforms on which p11-kit is not expected to
 * be present, we have our own implementation but it is basically
 * identical in most important aspects, except for the fact that
 * it uses NSS types and behaves like NSS (returning SECStatus where
 * appropriate, etc.).
 *
 * The main visible difference is that P11URI_Format() returns the
 * string value instead of taking a (char **) pointer as an argument,
 * and that the returned string value must be freed by the caller by
 * calling P11URI_FreeString().
 */

typedef enum {
    P11URI_FOR_OBJECT = (1 << 1),
    P11URI_FOR_TOKEN = (1 << 2),
    P11URI_FOR_MODULE = (1 << 3),

    P11URI_FOR_MODULE_WITH_VERSION =
        (1 << 4) | P11URI_FOR_MODULE,

    P11URI_FOR_OBJECT_ON_TOKEN =
        P11URI_FOR_OBJECT | P11URI_FOR_TOKEN,

    P11URI_FOR_OBJECT_ON_TOKEN_AND_MODULE =
        P11URI_FOR_OBJECT_ON_TOKEN | P11URI_FOR_MODULE,

    P11URI_FOR_ANY = 0x0000FFFF,
} P11URIType;

typedef struct P11URIStr P11URI;

CK_INFO_PTR P11URI_GetModuleInfo(P11URI *uri);
PRBool P11URI_MatchModuleInfo(P11URI *uri, CK_INFO_PTR info);

CK_TOKEN_INFO_PTR P11URI_GetTokenInfo(P11URI *uri);
PRBool P11URI_MatchTokenInfo(P11URI *uri, CK_TOKEN_INFO_PTR token_info);

/* CKA_LABEL attributes will be NUL-terminated (with the NUL not
   included in ulValueLen) */
CK_ATTRIBUTE_PTR P11URI_GetAttribute(P11URI *uri, CK_ATTRIBUTE_TYPE attr_type);
SECStatus P11URI_SetAttribute(P11URI *uri, CK_ATTRIBUTE_PTR attr);
PRBool P11URI_ClearAttribute(P11URI *uri, CK_ATTRIBUTE_TYPE attr_type);
CK_ATTRIBUTE_PTR P11URI_GetAttributes(P11URI *uri, CK_ULONG *n_attrs);
SECStatus P11URI_SetAttributes(P11URI *uri, CK_ATTRIBUTE_PTR attrs,
                               CK_ULONG n_attrs);
void P11URI_ClearAttributes(P11URI *uri);
PRBool P11URI_MatchAttributes(P11URI *uri, CK_ATTRIBUTE_PTR attrs,
                              CK_ULONG n_attrs);

const char *P11URI_GetPinValue(P11URI *uri);
SECStatus P11URI_SetPinValue(P11URI *uri, const char *pin);

const char *P11URI_GetPinSource(P11URI *uri);
SECStatus P11URI_SetPinSource(P11URI *uri, const char *pin_source);

void P11URI_SetUnrecognized(P11URI *uri, PRBool unrecognized);
PRBool P11URI_AnyUnrecognized(P11URI *uri);

P11URI *P11URI_New(void);

char *P11URI_Format(P11URI *uri, P11URIType uri_type);
void P11URI_FreeString(char *string);

SECStatus P11URI_Parse(const char *string, P11URIType uri_type, P11URI *uri);

void P11URI_Free(P11URI *uri);

SEC_END_PROTOS

#endif /* _P11URI_H_ */
