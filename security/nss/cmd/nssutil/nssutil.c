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
 },
 { /* cmd_DumpSlot */
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
 },
 { /* cmd_Version */  
   0, "version", 
   CMDNoArg, 0, PR_FALSE, 
   { 0, 0, 0, 0 }, 
   { 0, 0, 0, 0 }
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

void nssutil_usage(cmdPrintState *ps, 
                   int num, PRBool cmd, PRBool header, PRBool footer)
{
#define pusg CMD_PrintUsageString
    if (header) {
	pusg(ps, "utility for managing NSS profiles\n");
    } else if (footer) {
    } else if (cmd) {
	switch(num) {
	case cmd_AddModule: 
	    pusg(ps, "Add a module to the profile"); break;
	case cmd_ListModules:
	    pusg(ps, "List modules in the profile"); break;
	case cmd_DumpModule:
	    pusg(ps, "Dump info about a module"); break;
	case cmd_Version: 
	    pusg(ps, "Report version"); break;
	default:
	    pusg(ps, "Unrecognized command"); break;
	}
    } else {
	switch(num) {
	case opt_ProfileDir:    
	    pusg(ps, "Directory containing security databases (def: \".\")"); 
	    break;
	case opt_TokenName:  
	    pusg(ps, "Name of PKCS#11 token to use (def: internal)"); break;
	case opt_LibraryFile:  
	    pusg(ps, "Path to library to load"); break;
	case opt_Name:
	    pusg(ps, "Name of module/slot/token"); break;
	case opt_Help: break;
	default:
	    pusg(ps, "Unrecognized option");
	}
    }
}

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

    progName = strrchr(argv[0], '/');
    progName = progName ? progName+1 : argv[0];

    cmdToRun = CMD_ParseCommandLine(argc, argv, progName, &nssutil);

    if (nssutil.opt[opt_Help].on)
	CMD_LongUsage(progName, &nssutil, nssutil_usage);

    if (cmdToRun < 0)
	CMD_Usage(progName, &nssutil);

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

