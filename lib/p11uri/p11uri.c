/*
 * Copyright (C) 2011 Collabora Ltd.
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
 *
 */

#include "p11uri.h"

#include "base.h"
#include "secport.h"
#include "secerr.h"

#include "pkcs11.h"

#include <stdlib.h>
#include <string.h>

/*
 * RFC7512 only defines three object attributes for use in a URI::
 *     CKA_ID    ('id=')
 *     CKA_LABEL ('object=')
 *     CKA_CLASS ('type=')
 *
 * Thus, instead of the variable-length list that p11-kit uses to
 * manipulate the attributes, and the invented CKA_INVALID terminator,
 * we use a simple array of three CK_ATTRIBUTEs. An attribute is
 * present if its pValue field is non-NULL.
 *
 * It was considered that we might use fixed locations for each attr
 * according to its type (uri->attrs[type &0xff] would have worked).
 * But that would have left us building up a *different* array to be
 * returned by P11URI_GetAttributes(), so it wasn't worth doing.
 */
#define URI_MAX_ATTRS 3

struct P11URIStr {
    PRBool unrecognized;
    CK_INFO module;
    CK_TOKEN_INFO token;
    CK_ATTRIBUTE attrs[URI_MAX_ATTRS];
    char *pin_source;
    char *pin_value;
};

#define P11_URL_WHITESPACE " \n\r\v"

#define P11_URL_VERBATIM "abcdefghijklmnopqrstuvwxyz" \
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                         "0123456789_-."

const static char HEX_CHARS[] = "0123456789abcdef";

#define P11URI_SCHEME "pkcs11:"

static PRBool
match_struct_string(const unsigned char *inuri, const unsigned char *real,
                    size_t length)
{
    PORT_Assert(inuri != NULL);
    PORT_Assert(real != NULL);
    PORT_Assert(length > 0);

    /* NULL matches anything */
    if (inuri[0] == 0)
        return PR_TRUE;

    return memcmp(inuri, real, length) == 0 ? PR_TRUE : PR_FALSE;
}

static PRBool
match_struct_version(CK_VERSION_PTR inuri, CK_VERSION_PTR real)
{
    /* This matches anything */
    if (inuri->major == (CK_BYTE)-1 && inuri->minor == (CK_BYTE)-1)
        return PR_TRUE;

    return (memcmp(inuri, real, sizeof(CK_VERSION)) == 0) ? PR_TRUE : PR_FALSE;
}

CK_INFO_PTR
P11URI_GetModuleInfo(P11URI *uri)
{
    PORT_Assert(uri != NULL);

    return &uri->module;
}

PRBool
P11URI_MatchModuleInfo(P11URI *uri, CK_INFO_PTR info)
{
    PORT_Assert(uri != NULL);
    PORT_Assert(info != NULL);

    if (uri->unrecognized)
        return PR_FALSE;

    return (match_struct_string(uri->module.libraryDescription,
                                info->libraryDescription,
                                sizeof(info->libraryDescription)) &&
            match_struct_string(uri->module.manufacturerID,
                                info->manufacturerID,
                                sizeof(info->manufacturerID)) &&
            match_struct_version(&uri->module.libraryVersion,
                                 &info->libraryVersion));
}

CK_TOKEN_INFO_PTR
P11URI_GetTokenInfo(P11URI *uri)
{
    PORT_Assert(uri != NULL);

    return &uri->token;
}

PRBool
P11URI_MatchTokenInfo(P11URI *uri, CK_TOKEN_INFO_PTR token_info)
{
    PORT_Assert(uri != NULL);
    PORT_Assert(token_info != NULL);

    if (uri->unrecognized)
        return PR_FALSE;

    return (match_struct_string(uri->token.label,
                                token_info->label,
                                sizeof(token_info->label)) &&
            match_struct_string(uri->token.manufacturerID,
                                token_info->manufacturerID,
                                sizeof(token_info->manufacturerID)) &&
            match_struct_string(uri->token.model, token_info->model,
                                sizeof(token_info->model)) &&
            match_struct_string(uri->token.serialNumber,
                                token_info->serialNumber,
                                sizeof(token_info->serialNumber)));
}

CK_ATTRIBUTE_PTR
P11URI_GetAttribute(P11URI *uri, CK_ATTRIBUTE_TYPE attr_type)
{
    int i;

    PORT_Assert(uri != NULL);

    for (i = 0; i < URI_MAX_ATTRS; i++) {
        if (uri->attrs[i].type == attr_type &&
            uri->attrs[i].pValue != NULL)
            return &uri->attrs[i];
    }

    return NULL;
}

static SECStatus
__P11URI_SetAttribute(P11URI *uri, CK_ATTRIBUTE_PTR attr, PRBool take)
{
    int i;
    void *old_pValue = NULL;

    PORT_Assert(uri != NULL);
    PORT_Assert(attr != NULL);

    if (attr->type != CKA_CLASS && attr->type != CKA_LABEL &&
        attr->type != CKA_ID) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    for (i = 0; i < URI_MAX_ATTRS && uri->attrs[i].pValue; i++) {
        if (uri->attrs[i].type == attr->type) {
            old_pValue = uri->attrs[i].pValue;
            break;
        }
    }
    /* The array can never be full unless one of them matches! */
    PORT_Assert(i != URI_MAX_ATTRS);

    if (take) {
        uri->attrs[i].pValue = attr->pValue;
    } else {
        uri->attrs[i].pValue = PORT_ZAlloc(attr->ulValueLen + 1);
        if (uri->attrs[i].pValue == NULL) {
            PORT_SetError(SEC_ERROR_NO_MEMORY);
            return SECFailure;
        }
        memcpy(uri->attrs[i].pValue, attr->pValue, attr->ulValueLen);
    }
    uri->attrs[i].type = attr->type;
    uri->attrs[i].ulValueLen = attr->ulValueLen;

    PORT_Free(old_pValue);

    return SECSuccess;
}

SECStatus
P11URI_SetAttribute(P11URI *uri, CK_ATTRIBUTE_PTR attr)
{
    return __P11URI_SetAttribute(uri, attr, PR_FALSE);
}

PRBool
P11URI_ClearAttribute(P11URI *uri, CK_ATTRIBUTE_TYPE attr_type)
{
    int i;

    PORT_Assert(uri != NULL);

    if (attr_type != CKA_CLASS && attr_type != CKA_LABEL &&
        attr_type != CKA_ID) {
        return PR_FALSE;
    }

    for (i = 0; i < URI_MAX_ATTRS && uri->attrs[i].pValue; i++) {
        if (uri->attrs[i].type == attr_type) {
            PORT_Free(uri->attrs[i].pValue);

            /* Move the rest of the array down */
            while (i < URI_MAX_ATTRS - 1) {
                uri->attrs[i] = uri->attrs[i + 1];
                i++;
            }
            uri->attrs[i].pValue = NULL;
            return PR_TRUE;
        }
    }

    return PR_FALSE;
}

CK_ATTRIBUTE_PTR
P11URI_GetAttributes(P11URI *uri, CK_ULONG_PTR n_attrs)
{
    int i;

    PORT_Assert(n_attrs != NULL);

    for (i = 0; i < URI_MAX_ATTRS; i++)
        if (uri->attrs[i].pValue == NULL)
            break;

    *n_attrs = i;

    return uri->attrs;
}

SECStatus
P11URI_SetAttributes(P11URI *uri, CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
    CK_ULONG i;
    SECStatus rv = SECSuccess;

    PORT_Assert(uri != NULL);

    P11URI_ClearAttributes(uri);

    for (i = 0; i < n_attrs; i++) {
        rv = __P11URI_SetAttribute(uri, &attrs[i], PR_FALSE);
        if (rv != SECSuccess)
            break;
    }

    return rv;
}

void
P11URI_ClearAttributes(P11URI *uri)
{
    int i;

    PORT_Assert(uri != NULL);

    for (i = 0; i < URI_MAX_ATTRS; i++) {
        if (uri->attrs[i].pValue == NULL)
            break;
        PORT_Free(uri->attrs[i].pValue);
        uri->attrs[i].pValue = NULL;
    }
}

PRBool
P11URI_MatchAttributes(P11URI *uri, CK_ATTRIBUTE_PTR attrs, CK_ULONG n_attrs)
{
    CK_ULONG i;

    PORT_Assert(uri != NULL);
    PORT_Assert(attrs != NULL || n_attrs == 0);

    if (uri->unrecognized)
        return PR_FALSE;

    for (i = 0; i < n_attrs; i++) {
        int j;

        if (attrs[i].type != CKA_CLASS && attrs[i].type != CKA_LABEL &&
            attrs[i].type != CKA_ID)
            continue;

        for (j = 0; j < URI_MAX_ATTRS; j++) {
            if (uri->attrs[j].pValue == NULL)
                break;
            if (uri->attrs[j].type != attrs[i].type)
                continue;

            /* Matched type. Now, do the contents match? */
            if (uri->attrs[j].ulValueLen != attrs[i].ulValueLen ||
                memcmp(uri->attrs[j].pValue, attrs[i].pValue,
                       attrs[i].ulValueLen))
                return PR_FALSE;
        }
    }

    return PR_TRUE;
}

void
P11URI_SetUnrecognized(P11URI *uri, PRBool unrecognized)
{
    PORT_Assert(uri != NULL);

    uri->unrecognized = unrecognized;
}

PRBool
P11URI_AnyUnrecognized(P11URI *uri)
{
    PORT_Assert(uri != NULL);

    return uri->unrecognized;
}

const char *
P11URI_GetPinValue(P11URI *uri)
{
    PORT_Assert(uri != NULL);

    return uri->pin_value;
}

SECStatus
P11URI_SetPinValue(P11URI *uri, const char *pin)
{
    PORT_Assert(uri != NULL);

    PORT_Free(uri->pin_value);

    if (pin == NULL)
        uri->pin_value = NULL;
    else {
        uri->pin_value = PL_strdup(pin);
        if (uri->pin_value == NULL) {
            PORT_SetError(SEC_ERROR_NO_MEMORY);
            return SECFailure;
        }
    }
    return SECSuccess;
}

const char *
P11URI_GetPinSource(P11URI *uri)
{
    PORT_Assert(uri != NULL);

    return uri->pin_source;
}

SECStatus
P11URI_SetPinSource(P11URI *uri, const char *pin_source)
{
    PORT_Assert(uri != NULL);

    PORT_Free(uri->pin_source);

    if (pin_source == NULL)
        uri->pin_source = NULL;
    else {
        uri->pin_source = PL_strdup(pin_source);
        if (uri->pin_source == NULL) {
            PORT_SetError(SEC_ERROR_NO_MEMORY);
            return SECFailure;
        }
    }
    return SECSuccess;
}

P11URI *
P11URI_New(void)
{
    P11URI *uri;

    uri = PR_Calloc(1, sizeof(P11URI));
    if (uri == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    /* So that it matches anything */
    uri->module.libraryVersion.major = (CK_BYTE)-1;
    uri->module.libraryVersion.minor = (CK_BYTE)-1;

    return uri;
}

static SECStatus
format_raw_string(char **buf, const char *name, const char *value)
{
    /* Not set */
    if (value == NULL)
        return SECSuccess;

    *buf = PR_sprintf_append(*buf, "%s%s=%s",
                             *buf ? ";" : P11URI_SCHEME,
                             name, value);
    if (*buf == NULL) {
        /* PR_sprintf_append() will already have called
	   PORT_SetError() so we don't need to. */
        return SECFailure;
    }

    return SECSuccess;
}

static SECStatus
format_encode_string(char **buf, const char *name, const unsigned char *value,
                     size_t n_value, PRBool force)
{
    SECStatus rv;
    char *encbuf, *p;
    size_t i;

    /* Not set */
    if (value == NULL)
        return SECSuccess;

    /* Allow space to %-encode *every* character. Plus \0 termination */
    encbuf = PR_Calloc(n_value + 1, 3);
    if (encbuf == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    p = encbuf;

    /* Now loop through looking for escapes */
    for (i = 0; i < n_value; i++) {

        /* These characters we let through verbatim */
        if (!force && value[i] && strchr(P11_URL_VERBATIM, value[i]) != NULL) {
            *(p++) = value[i];

            /* All others get encoded */
        } else {
            *(p++) = '%';
            *(p++) = HEX_CHARS[value[i] >> 4];
            *(p++) = HEX_CHARS[value[i] & 0x0F];
        }
    }
    *(p++) = 0;

    rv = format_raw_string(buf, name, encbuf);
    PORT_Free(encbuf);

    return rv;
}

static SECStatus
format_struct_string(char **buf, const char *name, const unsigned char *value,
                     size_t len)
{
    /* Not set */
    if (!value[0])
        return SECSuccess;

    /* Strip trailing spaces */
    while (len > 0 && value[len - 1] == ' ')
        --len;

    return format_encode_string(buf, name, value, len, PR_FALSE);
}

static SECStatus
format_attribute_string(char **buf, const char *name, CK_ATTRIBUTE_PTR attr,
                        PRBool force)
{
    /* Not set */;
    if (attr == NULL)
        return SECSuccess;

    return format_encode_string(buf, name, attr->pValue, attr->ulValueLen,
                                force);
}

static SECStatus
format_attribute_class(char **buf, const char *name, CK_ATTRIBUTE_PTR attr)
{
    CK_OBJECT_CLASS klass;
    const char *value;

    /* Not set */;
    if (attr == NULL)
        return SECSuccess;

    klass = *((CK_OBJECT_CLASS *)attr->pValue);
    switch (klass) {
        case CKO_DATA:
            value = "data";
            break;
        case CKO_SECRET_KEY:
            value = "secret-key";
            break;
        case CKO_CERTIFICATE:
            value = "cert";
            break;
        case CKO_PUBLIC_KEY:
            value = "public";
            break;
        case CKO_PRIVATE_KEY:
            value = "private";
            break;
        default:
            return SECSuccess;
    }

    return format_raw_string(buf, name, value);
}

static SECStatus
format_struct_version(char **buf, const char *name, CK_VERSION_PTR version)
{
    char verbuf[64];

    /* Not set */
    if (version->major == (CK_BYTE)-1 && version->minor == (CK_BYTE)-1)
        return SECSuccess;

    snprintf(verbuf, sizeof(verbuf), "%d.%d",
             (int)version->major, (int)version->minor);

    return format_raw_string(buf, name, verbuf);
}

/*
 * Here we differ from the p11-kit API in more than just the cosmetics
 * of the function names. Instead of taking a 'char **' argument in
 * which to place the string result, we actually return it. The p11-kit
 * version doesn't do this because more information (an error code) can
 * be returned. But we use PORT_SetError() to give that same information
 * if there's a problem, so a simple boolean is all that's required.
 * That much can be inferred from whether the return is NULL or not.
 *
 * In addition, we provide an API for the caller to free the string that
 * we generate. Especially in the Windows world with multiple heaps, we
 * cannot simply pass an allocated string around and expect the caller
 * to free it. In this case we want to be using PR_smprintf_free() but
 * that is an implementation detail which we'd do better to hide from
 * the callers. Just let them call P11URI_FreeString().
 */
char *
P11URI_Format(P11URI *uri, P11URIType uri_type)
{
    SECStatus rv = SECSuccess;
    char *buffer = NULL;

    PORT_Assert(uri != NULL);

    if ((uri_type & P11URI_FOR_MODULE) == P11URI_FOR_MODULE) {
        rv = format_struct_string(&buffer, "library-description",
                                  uri->module.libraryDescription,
                                  sizeof(uri->module.libraryDescription));
        if (rv == SECFailure)
            goto out;

        rv = format_struct_string(&buffer, "library-manufacturer",
                                  uri->module.manufacturerID,
                                  sizeof(uri->module.manufacturerID));
        if (rv == SECFailure)
            goto out;
    }

    if ((uri_type & P11URI_FOR_MODULE_WITH_VERSION) ==
        P11URI_FOR_MODULE_WITH_VERSION) {
        rv = format_struct_version(&buffer, "library-version",
                                   &uri->module.libraryVersion);
        if (rv == SECFailure)
            goto out;
    }

    if ((uri_type & P11URI_FOR_TOKEN) == P11URI_FOR_TOKEN) {
        rv = format_struct_string(&buffer, "model",
                                  uri->token.model,
                                  sizeof(uri->token.model));
        if (rv == SECFailure)
            goto out;

        rv = format_struct_string(&buffer, "manufacturer",
                                  uri->token.manufacturerID,
                                  sizeof(uri->token.manufacturerID));
        if (rv == SECFailure)
            goto out;

        rv = format_struct_string(&buffer, "serial",
                                  uri->token.serialNumber,
                                  sizeof(uri->token.serialNumber));
        if (rv == SECFailure)
            goto out;

        rv = format_struct_string(&buffer, "token",
                                  uri->token.label,
                                  sizeof(uri->token.label));
        if (rv == SECFailure)
            goto out;
    }

    if ((uri_type & P11URI_FOR_OBJECT) == P11URI_FOR_OBJECT) {
        rv = format_attribute_string(&buffer, "id",
                                     P11URI_GetAttribute(uri, CKA_ID),
                                     PR_TRUE);
        if (rv == SECFailure)
            goto out;

        rv = format_attribute_string(&buffer, "object",
                                     P11URI_GetAttribute(uri, CKA_LABEL),
                                     PR_FALSE);
        if (rv == SECFailure)
            goto out;

        rv = format_attribute_class(&buffer, "type",
                                    P11URI_GetAttribute(uri, CKA_CLASS));
        if (rv == SECFailure)
            goto out;
    }

    if (uri->pin_source) {
        rv = format_encode_string(&buffer, "pin-source",
                                  (const unsigned char *)uri->pin_source,
                                  strlen(uri->pin_source), PR_FALSE);
        if (rv == SECFailure)
            goto out;
    }

    if (uri->pin_value) {
        rv = format_encode_string(&buffer, "pin-value",
                                  (const unsigned char *)uri->pin_value,
                                  strlen(uri->pin_value), PR_FALSE);
        if (rv == SECFailure)
            goto out;
    }

    if (buffer == NULL)
        buffer = PR_smprintf(P11URI_SCHEME);
out:
    if (rv == SECFailure) {
        PR_smprintf_free(buffer);
        return NULL;
    }
    return buffer;
}

static char *
key_decode(const char *value, const char *end)
{
    size_t length = (end - value);
    char *at, *pos;
    char *key;

    key = PORT_Alloc(length + 1);
    if (key == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    memcpy(key, value, length);
    key[length] = '\0';

    /* Do we have any whitespace? Strip it out. */
    if (strcspn(key, P11_URL_WHITESPACE) != length) {
        for (at = key, pos = key; pos != key + length + 1; ++pos) {
            if (!strchr(P11_URL_WHITESPACE, *pos))
                *(at++) = *pos;
        }
        *at = '\0';
    }

    return key;
}

static unsigned char *
url_decode(const char *value, const char *end, const char *skip,
           size_t *length)
{
    char *a, *b;
    unsigned char *result, *p;

    PORT_Assert(value <= end);
    PORT_Assert(skip != NULL);

    /* String can only get shorter */
    result = PORT_Alloc((end - value) + 1);
    if (result == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return NULL;
    }

    /* Now loop through looking for escapes */
    p = result;
    while (value != end) {
        /*
	 * A percent sign followed by two hex digits means
	 * that the digits represent an escaped character.
	 */
        if (*value == '%') {
            value++;
            if (value + 2 > end) {
                PORT_SetError(SEC_ERROR_INVALID_ARGS);
                PORT_Free(result);
                return NULL;
            }
            a = strchr(HEX_CHARS, tolower(value[0]));
            b = strchr(HEX_CHARS, tolower(value[1]));
            if (!a || !b) {
                PORT_SetError(SEC_ERROR_INVALID_ARGS);
                PORT_Free(result);
                return NULL;
            }
            *p = (a - HEX_CHARS) << 4;
            *(p++) |= (b - HEX_CHARS);
            value += 2;

            /* Ignore whitespace characters */
        } else if (strchr(skip, *value)) {
            value++;

            /* A different character */
        } else {
            *(p++) = *(value++);
        }
    }

    /* NUL terminate string, in case it's a string */
    *p = 0;

    if (length)
        *length = p - result;
    return result;
}

static int
parse_string_attribute(const char *name, const char *start, const char *end,
                       P11URI *uri)
{
    CK_ATTRIBUTE attr;
    size_t length;

    PORT_Assert(start <= end);

    if (strcmp("id", name) == 0)
        attr.type = CKA_ID;
    else if (strcmp("object", name) == 0)
        attr.type = CKA_LABEL;
    else
        return 0;

    attr.pValue = url_decode(start, end, P11_URL_WHITESPACE, &length);
    if (attr.pValue == NULL)
        return -1;
    attr.ulValueLen = length;

    if (__P11URI_SetAttribute(uri, &attr, PR_TRUE) == SECFailure)
        return -1;

    return 1;
}

static int
parse_class_attribute(const char *name, const char *start, const char *end,
                      P11URI *uri)
{
    CK_OBJECT_CLASS klass = 0;
    CK_ATTRIBUTE attr;
    char *value;

    PORT_Assert(start <= end);

    /*
     * We accept some variants from older versions of the I-D before
     * the final publication of RFC7512
     */
    if (strcmp("type", name) != 0 && strcmp("objecttype", name) != 0 &&
        strcmp("object-type", name) != 0)
        return 0;

    value = key_decode(start, end);
    if (value == NULL)
        return -1;

    if (strcmp(value, "cert") == 0)
        klass = CKO_CERTIFICATE;
    else if (strcmp(value, "public") == 0)
        klass = CKO_PUBLIC_KEY;
    else if (strcmp(value, "private") == 0)
        klass = CKO_PRIVATE_KEY;
    else if (strcmp(value, "secretkey") == 0)
        klass = CKO_SECRET_KEY;
    else if (strcmp(value, "secret-key") == 0)
        klass = CKO_SECRET_KEY;
    else if (strcmp(value, "data") == 0)
        klass = CKO_DATA;
    else {
        PORT_Free(value);
        uri->unrecognized = PR_TRUE;
        return 1;
    }

    PORT_Free(value);

    attr.pValue = &klass;
    attr.ulValueLen = sizeof(klass);
    attr.type = CKA_CLASS;

    if (__P11URI_SetAttribute(uri, &attr, PR_FALSE) == SECFailure)
        return -1;

    return 1;
}

static int
parse_struct_info(unsigned char *where, size_t length, const char *start,
                  const char *end, P11URI *uri)
{
    unsigned char *value;
    size_t value_length;

    PORT_Assert(start <= end);

    value = url_decode(start, end, P11_URL_WHITESPACE, &value_length);
    if (value == NULL)
        return -1;

    /* Too long, shouldn't match anything */
    if (value_length > length) {
        PORT_Free(value);
        uri->unrecognized = PR_TRUE;
        return 1;
    }

    memset(where, ' ', length);
    memcpy(where, value, value_length);

    PORT_Free(value);
    return 1;
}

static int
parse_token_info(const char *name, const char *start, const char *end,
                 P11URI *uri)
{
    unsigned char *where;
    size_t length;

    PORT_Assert(start <= end);

    if (strcmp(name, "model") == 0) {
        where = uri->token.model;
        length = sizeof(uri->token.model);
    } else if (strcmp(name, "manufacturer") == 0) {
        where = uri->token.manufacturerID;
        length = sizeof(uri->token.manufacturerID);
    } else if (strcmp(name, "serial") == 0) {
        where = uri->token.serialNumber;
        length = sizeof(uri->token.serialNumber);
    } else if (strcmp(name, "token") == 0) {
        where = uri->token.label;
        length = sizeof(uri->token.label);
    } else {
        return 0;
    }

    return parse_struct_info(where, length, start, end, uri);
}

static int
atoin(const char *start, const char *end)
{
    int ret = 0;

    while (start != end) {
        if (strchr(P11_URL_WHITESPACE, *start)) {
            start++;
            continue;
        }
        if (*start < '0' || *start > '9')
            return -1;
        ret *= 10;
        ret += (*start - '0');
        ++start;
    }

    return ret;
}

static int
parse_struct_version(const char *start, const char *end,
                     CK_VERSION_PTR version)
{
    const char *dot;
    int val;

    PORT_Assert(start <= end);

    dot = memchr(start, '.', end - start);
    if (dot == NULL)
        dot = end;

    if (dot == start) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return -1;
    }

    val = atoin(start, dot);
    if (val < 0 || val >= 255) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return -1;
    }

    version->major = (CK_BYTE)val;
    version->minor = 0;

    if (dot != end) {
        if (dot + 1 == end) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return -1;
        }

        val = atoin(dot + 1, end);
        if (val < 0 || val >= 255) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return -1;
        }
        version->minor = (CK_BYTE)val;
    }

    return 1;
}

static int
parse_module_version_info(const char *name, const char *start, const char *end,
                          P11URI *uri)
{
    PORT_Assert(start <= end);

    if (strcmp(name, "library-version") == 0)
        return parse_struct_version(start, end,
                                    &uri->module.libraryVersion);

    return 0;
}

static int
parse_module_info(const char *name, const char *start, const char *end,
                  P11URI *uri)
{
    unsigned char *where;
    size_t length;

    PORT_Assert(start <= end);

    if (strcmp(name, "library-description") == 0) {
        where = uri->module.libraryDescription;
        length = sizeof(uri->module.libraryDescription);
    } else if (strcmp(name, "library-manufacturer") == 0) {
        where = uri->module.manufacturerID;
        length = sizeof(uri->module.manufacturerID);
    } else {
        return 0;
    }

    return parse_struct_info(where, length, start, end, uri);
}

static int
parse_extra_info(const char *name, const char *start, const char *end,
                 P11URI *uri)
{
    unsigned char *pin_source;

    PORT_Assert(start <= end);

    if (strcmp(name, "pin-source") == 0) {
        pin_source = url_decode(start, end, P11_URL_WHITESPACE, NULL);
        if (pin_source == NULL)
            return -1;
        PORT_Free(uri->pin_source);
        uri->pin_source = (char *)pin_source;
        return 1;
    } else if (strcmp(name, "pin-value") == 0) {
        pin_source = url_decode(start, end, P11_URL_WHITESPACE, NULL);
        if (pin_source == NULL)
            return -1;
        PORT_Free(uri->pin_value);
        uri->pin_value = (char *)pin_source;
        return 1;
    }

    return 0;
}

SECStatus
P11URI_Parse(const char *string, P11URIType uri_type, P11URI *uri)
{
    const char *spos, *epos;
    char *key = NULL;
    int ret;

    PORT_Assert(string != NULL);
    PORT_Assert(uri != NULL);

    epos = strchr(string, ':');
    if (epos == NULL) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    /* Include the colon */
    epos++;

    key = key_decode(string, epos);
    if (key == NULL)
        return SECFailure;
    ret = strcmp(key, P11URI_SCHEME);
    PORT_Free(key);

    if (ret != 0) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    string = epos;

    /* Clear everything out */
    memset(&uri->module, 0, sizeof(uri->module));
    memset(&uri->token, 0, sizeof(uri->token));
    P11URI_ClearAttributes(uri);
    uri->module.libraryVersion.major = (CK_BYTE)-1;
    uri->module.libraryVersion.minor = (CK_BYTE)-1;
    uri->unrecognized = 0;
    PORT_Free(uri->pin_source);
    uri->pin_source = NULL;
    PORT_Free(uri->pin_value);
    uri->pin_value = NULL;

    for (;;) {
        spos = strchr(string, ';');
        if (spos == NULL) {
            spos = string + strlen(string);
            PORT_Assert(*spos == '\0');
            if (spos == string)
                break;
        }

        epos = strchr(string, '=');
        if (epos == NULL || spos == string || epos == string || epos >= spos) {
            PORT_SetError(SEC_ERROR_INVALID_ARGS);
            return SECFailure;
        }

        key = key_decode(string, epos);
        if (key == NULL)
            return SECFailure;

        epos++;

        ret = 0;
        if ((uri_type & P11URI_FOR_OBJECT) == P11URI_FOR_OBJECT)
            ret = parse_string_attribute(key, epos, spos, uri);
        if (ret == 0 && (uri_type & P11URI_FOR_OBJECT) == P11URI_FOR_OBJECT)
            ret = parse_class_attribute(key, epos, spos, uri);
        if (ret == 0 && (uri_type & P11URI_FOR_TOKEN) == P11URI_FOR_TOKEN)
            ret = parse_token_info(key, epos, spos, uri);
        if (ret == 0 && (uri_type & P11URI_FOR_MODULE) == P11URI_FOR_MODULE)
            ret = parse_module_info(key, epos, spos, uri);
        if (ret == 0 && (uri_type & P11URI_FOR_MODULE_WITH_VERSION) == P11URI_FOR_MODULE_WITH_VERSION)
            ret = parse_module_version_info(key, epos, spos, uri);
        if (ret == 0)
            ret = parse_extra_info(key, epos, spos, uri);
        PORT_Free(key);

        if (ret < 0)
            return SECFailure;
        if (ret == 0)
            uri->unrecognized = PR_TRUE;

        if (*spos == '\0')
            break;
        string = spos + 1;
    }

    return SECSuccess;
}

void
P11URI_FreeString(char *string)
{
    PR_smprintf_free(string);
}

void
P11URI_Free(P11URI *uri)
{
    if (uri == NULL)
        return;

    P11URI_ClearAttributes(uri);
    PORT_Free(uri->pin_source);
    PORT_Free(uri->pin_value);
    PORT_Free(uri);
}
