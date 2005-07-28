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
 * pkix_pl_string.c
 *
 * String Object Functions
 *
 */

#include "pkix_pl_string.h"

/* --Private-String-Functions------------------------------------- */

/*
 * FUNCTION: pkix_pl_String_Comparator
 * (see comments for PKIX_PL_ComparatorCallback in pkix_pl_system.h)
 *
 * NOTE:
 *  This function is a utility function called by pkix_pl_String_Equals().
 *  It is not officially registered as a comparator.
 */
static PKIX_Error *
pkix_pl_String_Comparator(
        PKIX_PL_String *firstString,
        PKIX_PL_String *secondString,
        PKIX_Int32 *pResult,
        void *plContext)
{
        PKIX_UInt32 i;
        PKIX_Int32 result;
        unsigned char *p1 = NULL;
        unsigned char *p2 = NULL;

        PKIX_ENTER(STRING, "pkix_pl_String_Comparator");
        PKIX_NULLCHECK_THREE(firstString, secondString, pResult);

        result = 0;

        p1 = (unsigned char*) firstString->utf16String;
        p2 = (unsigned char*) secondString->utf16String;

        /* Compare characters until you find a difference */
        for (i = 0; ((i < firstString->utf16Length) &&
                    (i < secondString->utf16Length) &&
                    result == 0); i++, p1++, p2++) {
                if (*p1 < *p2){
                        result = -1;
                } else if (*p1 > *p2){
                        result = 1;
                }
        }

        /* If two arrays are identical so far, the longer one is greater */
        if (result == 0) {
                if (firstString->utf16Length < secondString->utf16Length) {
                        result = -1;
                } else if (firstString->utf16Length >
                            secondString->utf16Length) {
                        result = 1;
                }
        }

        *pResult = result;

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: pkix_pl_String_Destroy
 * (see comments for PKIX_PL_DestructorCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_String_Destroy(
        PKIX_PL_Object *object,
        void *plContext)
{
        PKIX_PL_String *string = NULL;

        PKIX_ENTER(STRING, "pkix_pl_String_Destroy");
        PKIX_NULLCHECK_ONE(object);

        PKIX_CHECK(pkix_CheckType(object, PKIX_STRING_TYPE, plContext),
                    "Argument is not a String");

        string = (PKIX_PL_String*)object;

        /* XXX For debugging Destroy EscASCII String  */
        if (string->escAsciiString != NULL) {
                PKIX_FREE(string->escAsciiString);
                string->escAsciiString = NULL;
                string->escAsciiLength = 0;
        }

        /* Destroy UTF16 String */
        if (string->utf16String != NULL) {
                PKIX_FREE(string->utf16String);
                string->utf16String = NULL;
                string->utf16Length = 0;
        }

cleanup:

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: pkix_pl_String_ToString
 * (see comments for PKIX_PL_ToStringCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_String_ToString(
        PKIX_PL_Object *object,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_String *string = NULL;
        char *ascii = NULL;
        PKIX_UInt32 length;

        PKIX_ENTER(STRING, "pkix_pl_String_ToString");
        PKIX_NULLCHECK_TWO(object, pString);

        PKIX_CHECK(pkix_CheckType(object, PKIX_STRING_TYPE, plContext),
                    "Argument is not a String");

        string = (PKIX_PL_String*)object;

        PKIX_CHECK(PKIX_PL_String_GetEncoded
                (string, PKIX_ESCASCII, (void **)&ascii, &length, plContext),
                "PKIX_PL_String_GetEncoded failed");

        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII, ascii, NULL, pString, plContext),
                    "PKIX_PL_String_Create failed");

cleanup:

        PKIX_FREE(ascii);

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: pkix_pl_String_Equals
 * (see comments for PKIX_PL_EqualsCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_String_Equals(
        PKIX_PL_Object *firstObject,
        PKIX_PL_Object *secondObject,
        PKIX_Boolean *pResult,
        void *plContext)
{
        PKIX_UInt32 secondType;
        PKIX_Int32 cmpResult = 0;

        PKIX_ENTER(STRING, "pkix_pl_String_Equals");
        PKIX_NULLCHECK_THREE(firstObject, secondObject, pResult);

        /* Sanity check: Test that "firstObject" is a Strings */
        PKIX_CHECK(pkix_CheckType(firstObject, PKIX_STRING_TYPE, plContext),
                    "FirstObject argument is not a String");

        /* "SecondObject" doesn't have to be a string */
        PKIX_CHECK(PKIX_PL_Object_GetType
                    (secondObject, &secondType, plContext),
                    "Could not get type of second argument");

        /* If types differ, then we will return false */
        *pResult = PKIX_FALSE;

        if (secondType != PKIX_STRING_TYPE) goto cleanup;

        /* It's safe to cast here */
        PKIX_CHECK(pkix_pl_String_Comparator
                    ((PKIX_PL_String*)firstObject,
                    (PKIX_PL_String*)secondObject,
                    &cmpResult,
                    plContext),
                    "pkix_pl_String_Comparator failed");

        /* Strings are equal iff Comparator Result is 0 */
        *pResult = (cmpResult == 0);

cleanup:

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: pkix_pl_String_Hashcode
 * (see comments for PKIX_PL_HashcodeCallback in pkix_pl_system.h)
 */
static PKIX_Error *
pkix_pl_String_Hashcode(
        PKIX_PL_Object *object,
        PKIX_UInt32 *pHashcode,
        void *plContext)
{
        PKIX_PL_String *string = NULL;

        PKIX_ENTER(STRING, "pkix_pl_String_Hashcode");
        PKIX_NULLCHECK_TWO(object, pHashcode);

        PKIX_CHECK(pkix_CheckType(object, PKIX_STRING_TYPE, plContext),
                    "Object is not a string");

        string = (PKIX_PL_String*)object;

        PKIX_CHECK(pkix_hash
                    ((const unsigned char *)string->utf16String,
                    string->utf16Length,
                    pHashcode,
                    plContext),
                    "pkix_hash failed");

cleanup:

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: pkix_pl_String_RegisterSelf
 * DESCRIPTION:
 *  Registers PKIX_STRING_TYPE and its related functions with systemClasses[]
 * THREAD SAFETY:
 *  Not Thread Safe - for performance and complexity reasons
 *
 *  Since this function is only called by PKIX_PL_Initialize, which should
 *  only be called once, it is acceptable that this function is not
 *  thread-safe.
 */
PKIX_Error *
pkix_pl_String_RegisterSelf(
        void *plContext)
{
        extern pkix_ClassTable_Entry systemClasses[PKIX_NUMTYPES];
        pkix_ClassTable_Entry entry;

        PKIX_ENTER(STRING, "pkix_pl_String_RegisterSelf");

        entry.description = "String";
        entry.destructor = pkix_pl_String_Destroy;
        entry.equalsFunction = pkix_pl_String_Equals;
        entry.hashcodeFunction = pkix_pl_String_Hashcode;
        entry.toStringFunction = pkix_pl_String_ToString;
        entry.comparator = NULL;
        entry.duplicateFunction = pkix_duplicateImmutable;

        systemClasses[PKIX_STRING_TYPE] = entry;

cleanup:

        PKIX_RETURN(STRING);
}


/* --Public-String-Functions----------------------------------------- */

/*
 * FUNCTION: PKIX_PL_String_Create (see comments in pkix_pl_system.h)
 */
PKIX_Error *
PKIX_PL_String_Create(
        PKIX_UInt32 fmtIndicator,
        void *stringRep,
        PKIX_UInt32 stringLen,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_PL_String *string = NULL;
        PKIX_Error *decRefError = NULL;
        unsigned char *utf16Char = NULL;
        PKIX_UInt32 i;

        PKIX_ENTER(STRING, "PKIX_PL_String_Create");
        PKIX_NULLCHECK_TWO(pString, stringRep);

        PKIX_CHECK(PKIX_PL_Object_Alloc
                    (PKIX_STRING_TYPE,
                    sizeof (PKIX_PL_String),
                    (PKIX_PL_Object **)&string,
                    plContext),
                    "Could not allocate new string object");

        string->utf16String = NULL;
        string->utf16Length = 0;

        /* XXX For Debugging */
        string->escAsciiString = NULL;
        string->escAsciiLength = 0;

        switch (fmtIndicator) {
        case PKIX_ESCASCII: case PKIX_ESCASCII_DEBUG:
                PKIX_STRING_DEBUG("\tCalling PL_strlen).\n");
                string->escAsciiLength = PL_strlen(stringRep);

                /* XXX Cache for Debugging */
                PKIX_CHECK(PKIX_PL_Malloc
                            ((string->escAsciiLength)+1,
                            (void **)&string->escAsciiString,
                            plContext),
                            "PKIX_PL_Malloc failed");

                (void) PORT_Memcpy
                        (string->escAsciiString,
                        (void *)((char *)stringRep),
                        (string->escAsciiLength)+1);

                /* Convert the EscASCII string to UTF16 */
                PKIX_CHECK(pkix_EscASCII_to_UTF16
                            (string->escAsciiString,
                            string->escAsciiLength,
                            (fmtIndicator == PKIX_ESCASCII_DEBUG),
                            &string->utf16String,
                            &string->utf16Length,
                            plContext),
                            "pkix_EscASCII_to_UTF16 failed");
                break;
        case PKIX_UTF8:
                /* Convert the UTF8 string to UTF16 */
                PKIX_CHECK(pkix_UTF8_to_UTF16
                            (stringRep,
                            stringLen,
                            &string->utf16String,
                            &string->utf16Length,
                            plContext),
                            "pkix_UTF8_to_UTF16 failed");
                break;
        case PKIX_UTF16:
                /* UTF16 Strings must be even in length */
                if (stringLen%2 == 1) {
                        PKIX_DECREF(string);
                        PKIX_ERROR("UTF16 Alignment Error");
                }

                utf16Char = (unsigned char *)stringRep;

                /* Make sure this is a valid UTF-16 String */
                for (i = 0; \
                    (i < stringLen) && (pkixErrorResult == NULL); \
                    i += 2) {
                        /* Check that surrogate pairs are valid */
                        if ((utf16Char[i] >= 0xD8)&&
                            (utf16Char[i] <= 0xDB)) {
                                if ((i+2) >= stringLen) {
                                        PKIX_ERROR("UTF16 High Zone "
                                                    "Alignment Error");
                                        /* Second pair should be DC00-DFFF */
                                } else if (!((utf16Char[i+2] >= 0xDC)&&
                                            (utf16Char[i+2] <= 0xDF))) {
                                        PKIX_ERROR("UTF16 Low Zone Error");
                                } else {
                                        /*  Surrogate quartet is valid. */
                                        i += 2;
                                }
                        }
                }

                /* Create UTF16 String */
                string->utf16Length = stringLen;

                /* Alloc space for string */
                PKIX_CHECK(PKIX_PL_Malloc
                            (stringLen, &string->utf16String, plContext),
                            "PKIX_PL_Malloc failed");

                PKIX_STRING_DEBUG("\tCalling PORT_Memcpy).\n");
                (void) PORT_Memcpy
                        (string->utf16String, stringRep, stringLen);
                break;

        default:
                PKIX_ERROR("Unknown format");
        }

        *pString = string;

cleanup:

        if (PKIX_ERROR_RECEIVED){
                PKIX_DECREF(string);
        }

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: PKIX_PL_Sprintf (see comments in pkix_pl_system.h)
 */
PKIX_Error *
PKIX_PL_Sprintf(
        PKIX_PL_String **pOut,
        void *plContext,
        const PKIX_PL_String *fmt,
        ...)
{
        PKIX_PL_String *tempString = NULL;
        void **pArgsList = NULL;
        void **stringsAllocated = NULL;
        char *asciiText = NULL;
        char *asciiFormat = NULL;
        char *convertedAsciiFormat = NULL;
        va_list args, argsCopy;
        PKIX_UInt32 numStrings = 0;
        PKIX_UInt32 numNumbers = 0;
        PKIX_UInt32 length, i, j, k, dummyLen;

        PKIX_ENTER(STRING, "PKIX_PL_Sprintf");
        PKIX_NULLCHECK_TWO(pOut, fmt);

        PKIX_CHECK(PKIX_PL_String_GetEncoded
                    ((PKIX_PL_String *)fmt,
                    PKIX_ESCASCII,
                    (void **)&asciiFormat,
                    &length,
                    plContext),
                    "PKIX_PL_String_GetEncoded failed");

        /*
         * Count how many "%s" specifiers there are in the asciiFormat,
         * and how many "%diouxX" specifiers there are in the asciiFormat
         */

        for (i = 0; i < length; i++){
                if ((asciiFormat[i] == '%')&&((i+1) < length)) {
                        switch (asciiFormat[i+1]) {
                        case 's':
                                numStrings++;
                                i++;
                                break;
                        case 'd':
                        case 'i':
                        case 'o':
                        case 'u':
                        case 'x':
                        case 'X':
                                numNumbers++;
                                i++;
                                break;
                        default:
                                break;
                        }
                }
        }

        if (numStrings > 0){
                PKIX_STRING_DEBUG("\tCalling PR_Calloc).\n");
                stringsAllocated = PR_Calloc(numStrings, sizeof (void *));
                if (stringsAllocated == NULL) return PKIX_ALLOC_ERROR;
        }

        if (numNumbers > 0){
                PKIX_STRING_DEBUG("\tCalling PR_Calloc).\n");
                convertedAsciiFormat =
                        PR_Calloc((length + 1) + numNumbers, sizeof (char));
                if (convertedAsciiFormat == NULL) return PKIX_ALLOC_ERROR;
        }

        PKIX_STRING_DEBUG("\tCalling va_start).\n");

        va_start(args, fmt);
        argsCopy = args;

        /* Convert PKIX_PL_Strings to char*s */
        j = 0;
        for (i = 0; i < length; i++) {
                if ((asciiFormat[i] == '%')&&((i+1) < length)) {
                        switch (asciiFormat[i+1]) {
                        case 's':

                                /*
                                 * XXX not clear whether this code is portable
                                 * since it is modifying values on the stack
                                 */

                                pArgsList = (void **)argsCopy;
                                tempString = va_arg
                                        (argsCopy, PKIX_PL_String *);
                                if (tempString != NULL) {
                                        PKIX_CHECK(PKIX_PL_String_GetEncoded
                                                    ((PKIX_PL_String*)
                                                    tempString,
                                                    PKIX_ESCASCII,
                                                    pArgsList,
                                                    &dummyLen,
                                                    plContext),
                                                    "PKIX_PL_String_GetEncoded"
                                                    " failed");
                                        stringsAllocated[j++] = *pArgsList;
                                }
                                break;
                        default:
                                (void) va_arg(argsCopy, PKIX_UInt32);
                                break;
                        }
                        i++;
                }
        }

        /*
         * in order to force PR_vsmprintf to deal with numerical inputs
         * as 32-bit integers, we insert the 'l' (long) size modifier between
         * the '%' and the conversion character ["%d" -> "%ld", etc.]
         */

        if (convertedAsciiFormat){
                k = 0;
                for (i = 0; i < length; i++) {
                        if ((asciiFormat[i] == '%')&&((i+1) < length)) {
                                switch (asciiFormat[i+1]) {
                                case 'd':
                                case 'i':
                                case 'o':
                                case 'u':
                                case 'x':
                                case 'X':
                                        convertedAsciiFormat[k++] = '%';
                                        convertedAsciiFormat[k++] = 'l';
                                        convertedAsciiFormat[k++] =
                                                asciiFormat[i+1];
                                        break;
                                default:
                                        convertedAsciiFormat[k++] =
                                                asciiFormat[i];
                                        convertedAsciiFormat[k++] =
                                                asciiFormat[i+1];
                                }
                                i++;
                        } else {
                                convertedAsciiFormat[k++] = asciiFormat[i];
                        }
                }
                convertedAsciiFormat[k] = '\0';
        }

        PKIX_STRING_DEBUG("\tCalling PR_vsmprintf).\n");
        if (convertedAsciiFormat){
                asciiText =
                        PR_vsmprintf((const char *)convertedAsciiFormat, args);
        } else {
                asciiText = PR_vsmprintf((const char *)asciiFormat, args);
        }

        va_end(args);

        if (asciiText == NULL) {
                PKIX_ERROR("Error in PR_vsmprintf");
        }

        /* Copy temporary char * into a string object */
        PKIX_CHECK(PKIX_PL_String_Create
                (PKIX_ESCASCII, (void *)asciiText, NULL, pOut, plContext),
                "PKIX_PL_String_Create failed");

cleanup:

        PKIX_FREE(asciiFormat);

        if (convertedAsciiFormat){
                PR_Free(convertedAsciiFormat);
                convertedAsciiFormat = NULL;
        }

        if (asciiText){
                PKIX_STRING_DEBUG("\tCalling PR_smprintf_free).\n");
                PR_smprintf_free(asciiText);
                asciiText = NULL;
        }

        if (stringsAllocated){
                for (i = 0; i < j; i++){
                        PKIX_FREE(stringsAllocated[i]);
                }
                PR_Free(stringsAllocated);
                stringsAllocated = NULL;
        }

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: PKIX_PL_GetString (see comments in pkix_pl_system.h)
 */
PKIX_Error *
PKIX_PL_GetString(
        /* ARGSUSED */ PKIX_UInt32 stringID,
        char *defaultString,
        PKIX_PL_String **pString,
        void *plContext)
{
        PKIX_ENTER(STRING, "PKIX_PL_GetString");
        PKIX_NULLCHECK_TWO(pString, defaultString);

        /* XXX Optimization - use stringID for caching */
        PKIX_CHECK(PKIX_PL_String_Create
                    (PKIX_ESCASCII, defaultString, NULL, pString, plContext),
                    "PKIX_PL_String_Create failed");

cleanup:

        PKIX_RETURN(STRING);
}

/*
 * FUNCTION: PKIX_PL_String_GetEncoded (see comments in pkix_pl_system.h)
 */
PKIX_Error *
PKIX_PL_String_GetEncoded(
        PKIX_PL_String *string,
        PKIX_UInt32 fmtIndicator,
        void **pStringRep,
        PKIX_UInt32 *pLength,
        void *plContext)
{
        PKIX_ENTER(STRING, "PKIX_PL_String_GetEncoded");
        PKIX_NULLCHECK_THREE(string, pStringRep, pLength);

        switch (fmtIndicator) {
        case PKIX_ESCASCII: case PKIX_ESCASCII_DEBUG:
                PKIX_CHECK(pkix_UTF16_to_EscASCII
                            (string->utf16String,
                            string->utf16Length,
                            (fmtIndicator == PKIX_ESCASCII_DEBUG),
                            (char **)pStringRep,
                            pLength,
                            plContext),
                            "pkix_UTF16_to_EscASCII failed");
                break;
        case PKIX_UTF8:
                PKIX_CHECK(pkix_UTF16_to_UTF8
                            (string->utf16String,
                            string->utf16Length,
                            PKIX_FALSE,
                            pStringRep,
                            pLength,
                            plContext),
                            "pkix_UTF16_to_UTF8 failed");
                break;
        case PKIX_UTF8_NULL_TERM:
                PKIX_CHECK(pkix_UTF16_to_UTF8
                            (string->utf16String,
                            string->utf16Length,
                            PKIX_TRUE,
                            pStringRep,
                            pLength,
                            plContext),
                            "pkix_UTF16_to_UTF8 failed");
                break;
        case PKIX_UTF16:
                *pLength = string->utf16Length;

                PKIX_CHECK(PKIX_PL_Malloc(*pLength, pStringRep, plContext),
                            "PKIX_PL_Malloc failed");

                PKIX_STRING_DEBUG("\tCalling PORT_Memcpy).\n");
                (void) PORT_Memcpy(*pStringRep, string->utf16String, *pLength);
                break;
        default:
                PKIX_ERROR("Unknown format");
        }

cleanup:

        PKIX_RETURN(STRING);
}
