/*
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
 */

#include <string.h>
#include "nspr.h"
#include "prtypes.h"
#include "prtime.h"
#include "prlong.h"
#include "nss.h"

#include "nssutil.h"

char *progName = "nssutil";

static PRStatus nssutil_command_dispatcher(cmdCommand *, int);

/*  nssutil commands  */
enum {
    cmd_AddModule = 0,
    cmd_DumpModule,
    cmd_DumpSlot,
    cmd_DumpToken,
    cmd_ListModules,
    cmd_ListSlots,
    cmd_Version,
    nssutil_num_commands
};

/*  nssutil options */
enum {
    opt_Help = 0,
    opt_ProfileDir,
    opt_TokenName,
    opt_LibraryFile,
    opt_Name,
    nssutil_num_options
};

static cmdCommandLineArg nssutil_commands[] =
{
 { /* cmd_AddModule */  
   'A', "add-module", 
   CMDNoArg, 0, PR_FALSE, 
   {
     CMDBIT(opt_LibraryFile),
     0, 0, 0
   },
   {
     CMDBIT(opt_ProfileDir) |
     CMDBIT(opt_Name),
     0, 0, 0
   },
   "Add a module to the profile"
 },
 { /* cmd_DumpModule */
    0 , "dump-module", 
   CMDNoArg, 0, PR_FALSE,
   {
     CMDBIT(opt_Name),
     0, 0, 0
   },
   {
     CMDBIT(opt_ProfileDir),
     0, 0, 0
   },
   "Dump info about a module"
 },
 { /* cmd_DumpSlot */
    0 , "dump-slot", 
   CMDNoArg, 0, PR_FALSE,
   {
     CMDBIT(opt_Name),
     0, 0, 0
   },
   {
     CMDBIT(opt_ProfileDir),
     0, 0, 0
   },
   "dumps"
 },
 { /* cmd_DumpToken */
    0 , "dump-token", 
   CMDNoArg, 0, PR_FALSE,
   {
     CMDBIT(opt_Name),
     0, 0, 0
   },
   {
     CMDBIT(opt_ProfileDir),
     0, 0, 0
   },
   "dumpt"
 },
 { /* cmd_ListModules */  
   'L', "list-modules", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     0, 0, 0, 0 
   },
   {
     CMDBIT(opt_ProfileDir),
     0, 0, 0
   },
   "List modules in the profile"
 },
 { /* cmd_ListSlots */  
    0 , "list-slots", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     0, 0, 0, 0 
   },
   {
     CMDBIT(opt_ProfileDir),
     0, 0, 0
   },
   "lists"
 },
 { /* cmd_Version */  
   0, "version", 
   CMDNoArg, 0, PR_FALSE, 
   { 0, 0, 0, 0 }, 
   { 0, 0, 0, 0 },
   "Report version"
 }
};

static cmdCommandLineOpt nssutil_options[] =
{
 { /* opt_Help        */  '?', "help",     CMDNoArg,   0, PR_FALSE },
 { /* opt_ProfileDir  */  'd', "dbdir",    CMDArgReq,  0, PR_FALSE },
 { /* opt_TokenName   */  'h', "token",    CMDArgReq,  0, PR_FALSE },
 { /* opt_LibraryFile */  'l', "libfile",  CMDArgReq,  0, PR_FALSE },
 { /* opt_Name        */  'n', "name",     CMDArgReq,  0, PR_FALSE }
};

static char * nssutil_options_help[] =
{
 "get help for command",
 "Directory containing security databases (def: \".\")",
 "Name of PKCS#11 token to use (def: internal)",
 "Path to library to load",
 "Name of module/slot/token"
};

static char nssutil_description[] =
"utility for managing NSS config";

int 
main(int argc, char **argv)
{
    char     *profiledir = "./";
    PRStatus  rv         = PR_SUCCESS;

    int cmdToRun;
    cmdCommand nssutil;
    nssutil.ncmd = nssutil_num_commands;
    nssutil.nopt = nssutil_num_options;
    nssutil.cmd = nssutil_commands;
    nssutil.opt = nssutil_options;
    nssutil.optHelp = nssutil_options_help;
    nssutil.description = nssutil_description;

    progName = strrchr(argv[0], '/');
    if (!progName) {
	progName = strrchr(argv[0], '\\');
    }
    progName = progName ? progName+1 : argv[0];

    cmdToRun = CMD_ParseCommandLine(argc, argv, progName, &nssutil);

#if 0
    { int i, nc;
    for (i=0; i<nssutil.ncmd; i++)
	printf("%s: %s <%s>\n", nssutil.cmd[i].s, 
	                        (nssutil.cmd[i].on) ? "on" : "off",
				nssutil.cmd[i].arg);
    for (i=0; i<nssutil.nopt; i++)
	printf("%s: %s <%s>\n", nssutil.opt[i].s, 
	                        (nssutil.opt[i].on) ? "on" : "off",
				nssutil.opt[i].arg);
    }
#endif

    if (nssutil.opt[opt_Help].on)
	CMD_LongUsage(progName, &nssutil);

    if (cmdToRun < 0) {
	CMD_Usage(progName, &nssutil);
	exit(1);
    }

    /* -d */
    if (nssutil.opt[opt_ProfileDir].on) {
	profiledir = strdup(nssutil.opt[opt_ProfileDir].arg);
    }

    /* Display version info and exit */
    if (cmdToRun == cmd_Version) {
	printf("%s\nNSS Version %s\n", NSSUTIL_VERSION_STRING, NSS_VERSION);
	return PR_SUCCESS;
    }

    /* initialize */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    /* XXX allow for read-only and no-db */
    NSS_InitReadWrite(profiledir);

    rv = nssutil_command_dispatcher(&nssutil, cmdToRun);

    NSS_Shutdown();

    return rv;
}

static PRStatus 
nssutil_command_dispatcher(cmdCommand *nssutil, int cmdToRun)
{
    PRStatus status;
    CMDRunTimeData rtData;
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();

    status = CMD_SetRunTimeData(NULL, NULL, "binary", NULL, "pretty-print",
                                &rtData);
    if (status != PR_SUCCESS) {
	return status;
    }
    switch (cmdToRun) {
    case cmd_AddModule:
#if 0
	status = CMD_AddObject(td,
	                       NULL,
	                       NULL,
	                       nssutil->opt[opt_Nickname].arg,
	                       &rtData);
#endif
	break;
    case cmd_DumpModule:
	status = DumpModuleInfo(nssutil->opt[opt_Name].arg, &rtData);
	break;
    case cmd_DumpSlot:
	status = DumpSlotInfo(nssutil->opt[opt_Name].arg, td, &rtData);
	break;
    case cmd_DumpToken:
	status = DumpTokenInfo(nssutil->opt[opt_Name].arg, td, &rtData);
	break;
    case cmd_ListModules:
	status = ListModules(&rtData);
	break;
#if 0
    case cmd_ListSlots:
	status = ListSlots(&rtData);
	break;
#endif
    default:
	status = PR_FAILURE;
	break;
    }
    CMD_FinishRunTimeData(&rtData);
    return status;
}

