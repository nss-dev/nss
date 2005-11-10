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
 * pkix_lifecycle.c
 *
 * Top level initialize and shutdown functions
 *
 */

#include "pkix_lifecycle.h"

PKIX_Boolean pkix_initialized = PKIX_FALSE;
char *pkix_PK11ConfigDir = NULL;

/* Lock used by Logger - is reentrant by the same thread */
extern PKIX_PL_MonitorLock *pkixLoggerLock;

/* 
 * Following pkix_* variables are for debugging purpose. They should be taken
 * out eventually. The purpose is to verify cache tables usage (via debugger).
 */
int pkix_ccAddCount = 0;
int pkix_ccLookupCount = 0;
int pkix_ccRemoveCount = 0;
int pkix_cAddCount = 0;
int pkix_cLookupCount = 0;
int pkix_cRemoveCount = 0;
int pkix_ceAddCount = 0;
int pkix_ceLookupCount = 0;

PKIX_PL_HashTable *cachedCrlSigTable = NULL;
PKIX_PL_HashTable *cachedCertSigTable = NULL;
PKIX_PL_HashTable *cachedCertChainTable = NULL;
PKIX_PL_HashTable *cachedCertTable = NULL;
PKIX_PL_HashTable *cachedCrlEntryTable = NULL;

extern PKIX_List *pkixLoggers;
extern PKIX_List *pkixLoggersErrors;
extern PKIX_List *pkixLoggersDebugTrace;

/* --Public-Functions--------------------------------------------- */

/*
 * FUNCTION: PKIX_Initialize (see comments in pkix.h)
 */
PKIX_Error *
PKIX_Initialize(
        PKIX_UInt32 desiredMajorVersion,
        PKIX_UInt32 minDesiredMinorVersion,
        PKIX_UInt32 maxDesiredMinorVersion,
        PKIX_UInt32 *pActualMinorVersion,
        void *plContext)
{
        PKIX_ENTER(LIFECYCLE, "PKIX_Initialize");

        /*
         * This function can only be called once. If it has already been
         * called, we return a statically allocated error. Our technique works
         * most of the time, but may not work if multiple threads call this
         * function simultaneously. However, the function's documentation
         * makes it clear that this is prohibited, so it's not our
         * responsibility.
         */

        if (pkix_initialized){
                return (PKIX_ALLOC_ERROR());
        }

        PKIX_CHECK(PKIX_PL_Initialize(plContext), "PKIX_PL_Initialize failed");

        if (desiredMajorVersion != PKIX_MAJOR_VERSION){
                PKIX_ERROR("Major versions don't match");
        }

        if ((minDesiredMinorVersion > PKIX_MINOR_VERSION) ||
            (maxDesiredMinorVersion < PKIX_MINOR_VERSION)){
                PKIX_ERROR("Minor version doesn't fall between desired "
                            "minimum and maximum");
        }

        *pActualMinorVersion = PKIX_MINOR_VERSION;

        pkix_initialized = PKIX_TRUE;
        pkix_PK11ConfigDir = NULL;

        /* Create Cache Tables */
        PKIX_CHECK(PKIX_PL_HashTable_Create
                    (32, 0, &cachedCertSigTable, plContext),
                    "PKIX_PL_HashTable_Create failed");

        PKIX_CHECK(PKIX_PL_HashTable_Create
                    (32, 0, &cachedCrlSigTable, plContext),
                    "PKIX_PL_HashTable_Create failed");

        PKIX_CHECK(PKIX_PL_HashTable_Create
                    (32, 10, &cachedCertChainTable, plContext),
                    "PKIX_PL_HashTable_Create failed");

        PKIX_CHECK(PKIX_PL_HashTable_Create
                    (32, 10, &cachedCertTable, plContext),
                    "PKIX_PL_HashTable_Create failed");

        PKIX_CHECK(PKIX_PL_HashTable_Create
                    (32, 10, &cachedCrlEntryTable, plContext),
                    "PKIX_PL_HashTable_Create failed");

        if (pkixLoggerLock == NULL) {
                PKIX_CHECK(PKIX_PL_MonitorLock_Create
                        (&pkixLoggerLock, plContext),
                        "PKIX_PL_MonitorLock_Create failed");
        }

cleanup:

        PKIX_RETURN(LIFECYCLE);
}

/*
 * FUNCTION: PKIX_Initialize_SetConfigDir (see comments in pkix.h)
 */
PKIX_Error *
PKIX_Initialize_SetConfigDir(
        PKIX_UInt32 storeType,
        char *configDir,
        void *plContext)
{
        PKIX_ENTER(LIFECYCLE, "PKIX_Initialize_SetConfigDir");
        PKIX_NULLCHECK_ONE(configDir);

        switch(storeType) {

            case PKIX_STORE_TYPE_PK11:

		    pkix_PK11ConfigDir = configDir;
                break;

            default:
                PKIX_ERROR("Invalid Store type for Setting ConfigDir");
                break;
        }

cleanup:

        PKIX_RETURN(LIFECYCLE);
}

/*
 * FUNCTION: PKIX_Shutdown (see comments in pkix.h)
 */
PKIX_Error *
PKIX_Shutdown(void *plContext)
{
        PKIX_List *savedPkixLoggers = NULL;
        PKIX_List *savedPkixLoggersErrors = NULL;
        PKIX_List *savedPkixLoggersDebugTrace = NULL;

        PKIX_ENTER(LIFECYCLE, "PKIX_Shutdown");

        if (!pkix_initialized){
                return (PKIX_ALLOC_ERROR());
        }

        if (pkixLoggers) {
                savedPkixLoggers = pkixLoggers;
                savedPkixLoggersErrors = pkixLoggersErrors;
                savedPkixLoggersDebugTrace = pkixLoggersDebugTrace;
                pkixLoggers = NULL;
                pkixLoggersErrors = NULL;
                pkixLoggersDebugTrace = NULL;
                PKIX_DECREF(savedPkixLoggers);
                PKIX_DECREF(savedPkixLoggersErrors);
                PKIX_DECREF(savedPkixLoggersDebugTrace);
        }
        PKIX_DECREF(pkixLoggerLock);

        /* Destroy Cache Tables */
        PKIX_DECREF(cachedCertSigTable);
        PKIX_DECREF(cachedCrlSigTable);
        PKIX_DECREF(cachedCertChainTable);
        PKIX_DECREF(cachedCertTable);
        PKIX_DECREF(cachedCrlEntryTable);

        PKIX_CHECK(PKIX_PL_Shutdown(plContext), "PKIX_PL_Shutdown failed");

        pkix_initialized = PKIX_FALSE;

cleanup:

        PKIX_RETURN(LIFECYCLE);
}
