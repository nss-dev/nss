/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Sun Microsystems
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */
/*
 * pkix_tools.c
 *
 * Private Utility Functions
 *
 */

#include "pkix_tools.h"

/* --Private-Functions-------------------------------------------- */

/*
 * FUNCTION: pkix_IsCertSelfIssued
 * DESCRIPTION:
 *
 *  Checks whether the Cert pointed to by "cert" is self-issued and stores the
 *  Boolean result at "pSelfIssued". A Cert is considered self-issued if the
 *  Cert's issuer matches the Cert's subject. If the subject or issuer is
 *  not specified, a PKIX_FALSE is returned.
 *
 * PARAMETERS:
 *  "cert"
 *      Address of Cert used to determine whether Cert is self-issued.
 *      Must be non-NULL.
 *  "pSelfIssued"
 *      Address where Boolean will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Cert Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_IsCertSelfIssued(
        PKIX_PL_Cert *cert,
        PKIX_Boolean *pSelfIssued,
        void *plContext)
{
        PKIX_PL_X500Name *subject = NULL;
        PKIX_PL_X500Name *issuer = NULL;

        PKIX_ENTER(CERT, "pkix_isCertSelfIssued");
        PKIX_NULLCHECK_TWO(cert, pSelfIssued);

        PKIX_CHECK(PKIX_PL_Cert_GetSubject(cert, &subject, plContext),
                    "PKIX_PL_Cert_GetSubject failed");

        PKIX_CHECK(PKIX_PL_Cert_GetIssuer(cert, &issuer, plContext),
                    "PKIX_PL_Cert_GetIssuer failed");

        if (subject == NULL || issuer == NULL) {
                *pSelfIssued = PKIX_FALSE;
        } else {

                PKIX_CHECK(PKIX_PL_X500Name_Match
                    (subject, issuer, pSelfIssued, plContext),
                    "PKIX_PL_X500Name_Match failed");
        }

cleanup:
        PKIX_DECREF(subject);
        PKIX_DECREF(issuer);
        PKIX_RETURN(CERT);
}

/*
 * FUNCTION: pkix_Throw
 * DESCRIPTION:
 *
 *  Creates an Error using the value of "errorCode", the character array
 *  pointed to by "funcName", the character array pointed to by "errorText",
 *  and the Error pointed to by "cause" (if any), and stores it at "pError".
 *
 *  If "cause" is not NULL and has an errorCode of "PKIX_FATAL_ERROR",
 *  then there is no point creating a new Error object. Rather, we simply
 *  store "cause" at "pError".
 *
 * PARAMETERS:
 *  "errorCode"
 *      Value of error code.
 *  "funcName"
 *      Address of EscASCII array representing name of function throwing error.
 *      Must be non-NULL.
 *  "errorText"
 *      Address of EscASCII array error description for new error.
 *      Must be non-NULL.
 *  "cause"
 *      Address of Error representing error's cause.
 *  "pError"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an Error Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_Throw(
        PKIX_UInt32 errorCode,
        char *funcName,
        char *errorText,
        PKIX_Error *cause,
        PKIX_Error **pError,
        void *plContext)
{
        PKIX_PL_String *formatString = NULL;
        PKIX_PL_String *funcNameString = NULL;
        PKIX_PL_String *textString = NULL;
        PKIX_PL_String *errorString = NULL;
        PKIX_UInt32 causeCode;
        char *format = NULL;

        PKIX_ENTER(ERROR, "pkix_Throw");
        PKIX_NULLCHECK_THREE(funcName, errorText, pError);

        *pError = NULL;

        /* if cause has error code of PKIX_FATAL_ERROR, return immediately */
        if (cause) {
                pkixTempResult = PKIX_Error_GetErrorCode
                        (cause, &causeCode, plContext);
                if (pkixTempResult) goto cleanup;

                if (causeCode == PKIX_FATAL_ERROR){
                        *pError = cause;
                        goto cleanup;
                }
        }

        format = "%s: %s";

        pkixTempResult = PKIX_PL_String_Create(PKIX_ESCASCII,
                                                (void *)format,
                                                NULL,
                                                &formatString,
                                                plContext);
        if (pkixTempResult) goto cleanup;

        pkixTempResult = PKIX_PL_String_Create(PKIX_ESCASCII,
                                                (void *)funcName,
                                                NULL,
                                                &funcNameString,
                                                plContext);
        if (pkixTempResult) goto cleanup;

        pkixTempResult = PKIX_PL_String_Create(PKIX_ESCASCII,
                                                (void *)errorText,
                                                NULL,
                                                &textString,
                                                plContext);
        if (pkixTempResult) goto cleanup;

        pkixTempResult = PKIX_PL_Sprintf(&errorString,
                                plContext,
                                formatString,
                                funcNameString,
                                textString);

        pkixTempResult = PKIX_Error_Create
                (errorCode, cause, NULL, errorString, pError, plContext);

cleanup:

        PKIX_DECREF(errorString);
        PKIX_DECREF(formatString);
        PKIX_DECREF(funcNameString);
        PKIX_DECREF(textString);
        PKIX_DEBUG_EXIT(ERROR);
        pkixErrorCode = 0;
        return (pkixTempResult);
}

/*
 * FUNCTION: pkix_CheckTypes
 * DESCRIPTION:
 *
 *  Checks that the types of the Object pointed to by "first" and the Object
 *  pointed to by "second" are both equal to the value of "type". If they
 *  are not equal, a PKIX_Error is returned.
 *
 * PARAMETERS:
 *  "first"
 *      Address of first Object. Must be non-NULL.
 *  "second"
 *      Address of second Object. Must be non-NULL.
 *  "type"
 *      Value of type to check against.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an Error Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_CheckTypes(
        PKIX_PL_Object *first,
        PKIX_PL_Object *second,
        PKIX_UInt32 type,
        void *plContext)
{
        PKIX_UInt32 firstType, secondType;

        PKIX_ENTER(OBJECT, "pkix_CheckTypes");
        PKIX_NULLCHECK_TWO(first, second);

        PKIX_CHECK(PKIX_PL_Object_GetType(first, &firstType, plContext),
                    "Could not get first object type");

        PKIX_CHECK(PKIX_PL_Object_GetType(second, &secondType, plContext),
                    "Could not get second object type");

        if ((firstType != type)||(firstType != secondType)) {
                PKIX_ERROR("Object types do not match");
        }

cleanup:

        PKIX_RETURN(OBJECT);
}

/*
 * FUNCTION: pkix_CheckType
 * DESCRIPTION:
 *
 *  Checks that the type of the Object pointed to by "object" is equal to the
 *  value of "type". If it is not equal, a PKIX_Error is returned.
 *
 * PARAMETERS:
 *  "object"
 *      Address of Object. Must be non-NULL.
 *  "type"
 *      Value of type to check against.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns an Error Error if the function fails in a non-fatal way.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_CheckType(
        PKIX_PL_Object *object,
        PKIX_UInt32 type,
        void *plContext)
{
        return (pkix_CheckTypes(object, object, type, plContext));
}

/*
 * FUNCTION: pkix_hash
 * DESCRIPTION:
 *
 *  Computes a hash value for "length" bytes starting at the array of bytes
 *  pointed to by "bytes" and stores the result at "pHash".
 *
 *  XXX To speed this up, we could probably read 32 bits at a time from
 *  bytes (maybe even 64 bits on some platforms)
 *
 * PARAMETERS:
 *  "bytes"
 *      Address of array of bytes to hash. Must be non-NULL.
 *  "length"
 *      Number of bytes to hash.
 *  "pHash"
 *      Address where object pointer will be stored. Must be non-NULL.
 *  "plContext"
 *      Platform-specific context pointer.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns NULL if the function succeeds.
 *  Returns a Fatal Error if the function fails in an unrecoverable way.
 */
PKIX_Error *
pkix_hash(
        const unsigned char *bytes,
        PKIX_UInt32 length,
        PKIX_UInt32 *pHash,
        void *plContext)
{
        PKIX_UInt32 i;
        PKIX_UInt32 hash;

        PKIX_ENTER(OBJECT, "pkix_hash");
        PKIX_NULLCHECK_TWO(bytes, pHash);

        hash = 0;
        for (i = 0; i < length; i++) {
                /* hash = 31 * hash + bytes[i]; */
                hash = (hash << 5) - hash + bytes[i];
        }

        *pHash = hash;

        PKIX_RETURN(OBJECT);
}

/*
 * FUNCTION: pkix_countArray
 * DESCRIPTION:
 *
 *  Counts the number of elements in the  null-terminated array of pointers
 *  pointed to by "array" and returns the result.
 *
 * PARAMETERS
 *  "array"
 *      Address of null-terminated array of pointers.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  Returns the number of elements in the array.
 */
PKIX_UInt32
pkix_countArray(void **array)
{
        PKIX_UInt32 count = 0;

        if (array) {
                while (*array++) {
                        count++;
                }
        }
        return (count);
}

/*
 * FUNCTION: pkix_duplicateImmutable
 * DESCRIPTION:
 *
 *  Convenience callback function used for duplicating immutable objects.
 *  Since the objects can not be modified, this function simply increments the
 *  reference count on the object, and returns a reference to that object.
 *
 *  (see comments for PKIX_PL_DuplicateCallback in pkix_pl_system.h)
 */
PKIX_Error *
pkix_duplicateImmutable(
        PKIX_PL_Object *object,
        PKIX_PL_Object **pNewObject,
        void *plContext)
{
        PKIX_ENTER(OBJECT, "pkix_duplicateImmutable");
        PKIX_NULLCHECK_TWO(object, pNewObject);

        PKIX_INCREF(object);

        *pNewObject = object;

cleanup:

        PKIX_RETURN(OBJECT);
}

/* --String-Encoding-Conversion-Functions------------------------ */

/*
 * FUNCTION: pkix_hex2i
 * DESCRIPTION:
 *
 *  Converts hexadecimal character "c" to its integer value and returns result.
 *
 * PARAMETERS
 *  "c"
 *      Character to convert to a hex value.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  The hexadecimal value of "c". Otherwise -1. (Unsigned 0xFFFFFFFF).
 */
PKIX_UInt32
pkix_hex2i(char c)
{
        if ((c >= '0')&&(c <= '9'))
                return (c-'0');
        else if ((c >= 'a')&&(c <= 'f'))
                return (c-'a'+10);
        else if ((c >= 'A')&&(c <= 'F'))
                return (c-'A'+10);
        else
                return ((PKIX_UInt32)(-1));
}

/*
 * FUNCTION: pkix_i2hex
 * DESCRIPTION:
 *
 *  Converts integer value "digit" to its ASCII hex value
 *
 * PARAMETERS
 *  "digit"
 *      Value of integer to convert to ASCII hex value. Must be 0-15.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  The ASCII hexadecimal value of "digit".
 */
char
pkix_i2hex(char digit)
{
        if ((digit >= 0)&&(digit <= 9))
                return (digit+'0');
        else if ((digit >= 0xa)&&(digit <= 0xf))
                return (digit - 10 + 'a');
        else
                return (-1);
}

/*
 * FUNCTION: pkix_isPlaintext
 * DESCRIPTION:
 *
 *  Returns whether character "c" is plaintext using EscASCII or EscASCII_Debug
 *  depending on the value of "debug".
 *
 *  In EscASCII, [01, 7E] except '&' are plaintext.
 *  In EscASCII_Debug [20, 7E] except '&' are plaintext.
 *
 * PARAMETERS:
 *  "c"
 *      Character to check.
 *  "debug"
 *      Value of debug flag.
 * THREAD SAFETY:
 *  Thread Safe (see Thread Safety Definitions in Programmer's Guide)
 * RETURNS:
 *  True if "c" is plaintext.
 */
PKIX_Boolean
pkix_isPlaintext(unsigned char c, PKIX_Boolean debug) {
        return ((c >= 0x01)&&(c <= 0x7E)&&(c != '&')&&(!debug || (c >= 20)));
}
