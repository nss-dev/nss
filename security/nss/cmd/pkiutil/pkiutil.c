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
#include "nsspki.h"
#include "nsspkix.h"

/* XXX */
#include "dev.h"

#include "pkiutil.h"

char *progName;

static PRStatus pkiutil_command_dispatcher(cmdCommand *, int);

/*  pkiutil commands  */
enum {
    cmd_Add = 0,
    cmd_ChangePassword,
    cmd_Delete,
    cmd_List,
    cmd_Print,
    cmd_Version,
    pkiutil_num_commands
};

/*  pkiutil options */
enum {
    opt_Help = 0,
    opt_Ascii,
    opt_Chain,
    opt_ProfileDir,
    opt_TokenName,
    opt_InputFile,
    opt_Nickname,
    opt_OutputFile,
    opt_Orphans,
    opt_Binary,
    opt_Trust,
    opt_Type,
    pkiutil_num_options
};

static cmdCommandLineArg pkiutil_commands[] =
{
 { /* cmd_Add */  
   'A', "add", 
   CMDNoArg, 0, PR_FALSE, 
   {
     CMDBIT(opt_Nickname) | 
     CMDBIT(opt_Trust), 
     0, 0, 0
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_InputFile) | 
     CMDBIT(opt_Binary) | 
     CMDBIT(opt_Type),
     0, 0, 0
   },
 },
 { /* cmd_ChangePassword */
    0 , "change-password",
   CMDNoArg, 0, PR_FALSE,
   { 
     CMDBIT(opt_TokenName), 
     0, 0, 0 
   },
   { 
     CMDBIT(opt_ProfileDir),
     0, 0, 0 
   },
 },
 { /* cmd_Delete */
   'D', "delete", 
   CMDNoArg, 0, PR_FALSE, 
   { 0, 0, 0, 0 },
   {
     CMDBIT(opt_Nickname) |
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_Orphans) | 
     CMDBIT(opt_TokenName),
     0, 0, 0
   },
 },
 { /* cmd_List */  
   'L', "list", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     0, 0, 0, 0 
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Binary) | 
     CMDBIT(opt_Nickname) | 
     CMDBIT(opt_Type),
     0, 0, 0
   },
 },
 { /* cmd_Print */
   'P', "print", 
   CMDNoArg, 0, PR_FALSE,
   {
     CMDBIT(opt_Nickname),
     0, 0, 0
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_Chain) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Nickname) | 
     CMDBIT(opt_OutputFile) | 
     CMDBIT(opt_Binary) | 
     CMDBIT(opt_Type),
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

static cmdCommandLineOpt pkiutil_options[] =
{
 { /* opt_Help        */  '?', "help",     CMDNoArg,   0, PR_FALSE },
 { /* opt_Ascii       */  'a', "ascii",    CMDNoArg,   0, PR_FALSE },
 { /* opt_Chain       */   0 , "chain",    CMDNoArg,   0, PR_FALSE },
 { /* opt_ProfileDir  */  'd', "dbdir",    CMDArgReq,  0, PR_FALSE },
 { /* opt_TokenName   */  'h', "token",    CMDArgReq,  0, PR_FALSE },
 { /* opt_InputFile   */  'i', "infile",   CMDArgReq,  0, PR_FALSE },
 { /* opt_Nickname    */  'n', "nickname", CMDArgReq,  0, PR_FALSE },
 { /* opt_OutputFile  */  'o', "outfile",  CMDArgReq,  0, PR_FALSE },
 { /* opt_Orphans     */   0 , "orphans",  CMDNoArg,   0, PR_FALSE },
 { /* opt_Binary      */  'r', "raw",      CMDNoArg,   0, PR_FALSE },
 { /* opt_Trust       */  't', "trust",    CMDArgReq,  0, PR_FALSE },
 { /* opt_Type        */   0 , "type",     CMDArgReq,  0, PR_FALSE }
};

void pkiutil_usage(cmdPrintState *ps, 
                   int num, PRBool cmd, PRBool header, PRBool footer)
{
#define pusg CMD_PrintUsageString
    if (header) {
	pusg(ps, "utility for managing PKCS#11 objects (certs and keys)\n");
    } else if (footer) {
	/*
	printf("certificate trust can be:\n");
	printf(" p - valid peer, P - trusted peer (implies p)\n");
	printf(" c - valid CA\n");
	printf("  T - trusted CA to issue client certs (implies c)\n");
	printf("  C - trusted CA to issue server certs (implies c)\n");
	printf(" u - user cert\n");
	printf(" w - send warning\n");
	*/
    } else if (cmd) {
	switch(num) {
	case cmd_Add:     
	    pusg(ps, "Add an object to the profile/token"); break;
	case cmd_Delete:     
	    pusg(ps, "Delete an object from the profile/token"); break;
	case cmd_List:    
	    pusg(ps, "List objects on the token (-n for single object)"); break;
	case cmd_Print:
	    pusg(ps, "Print or dump a single object"); break;
	case cmd_Version: 
	    pusg(ps, "Report version"); break;
	default:
	    pusg(ps, "Unrecognized command"); break;
	}
    } else {
	switch(num) {
	case opt_Ascii:      
	    pusg(ps, "Use ascii (base-64 encoded) mode for I/O"); break;
	case opt_ProfileDir:    
	    pusg(ps, "Directory containing security databases (def: \".\")"); 
	    break;
	case opt_TokenName:  
	    pusg(ps, "Name of PKCS#11 token to use (def: internal)"); break;
	case opt_InputFile:  
	    pusg(ps, "File for input (def: stdin)"); break;
	case opt_Nickname:   
	    pusg(ps, "Nickname of object"); break;
	case opt_OutputFile: 
	    pusg(ps, "File for output (def: stdout)"); break;
	case opt_Binary:    
	    pusg(ps, "Use raw (binary der-encoded) mode for I/O"); break;
	case opt_Trust:      
	    pusg(ps, "Trust level for certificate"); break;
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
    cmdCommand pkiutil;
    pkiutil.ncmd = pkiutil_num_commands;
    pkiutil.nopt = pkiutil_num_options;
    pkiutil.cmd = pkiutil_commands;
    pkiutil.opt = pkiutil_options;

    progName = strrchr(argv[0], '/');
    if (!progName) {
	progName = strrchr(argv[0], '\\');
    }
    progName = progName ? progName+1 : argv[0];

    cmdToRun = CMD_ParseCommandLine(argc, argv, progName, &pkiutil);

#if 0
    { int i, nc;
    for (i=0; i<pkiutil.ncmd; i++)
	printf("%s: %s <%s>\n", pkiutil.cmd[i].s, 
	                        (pkiutil.cmd[i].on) ? "on" : "off",
				pkiutil.cmd[i].arg);
    for (i=0; i<pkiutil.nopt; i++)
	printf("%s: %s <%s>\n", pkiutil.opt[i].s, 
	                        (pkiutil.opt[i].on) ? "on" : "off",
				pkiutil.opt[i].arg);
    }
#endif

    if (pkiutil.opt[opt_Help].on)
	CMD_LongUsage(progName, &pkiutil, pkiutil_usage);

    if (cmdToRun < 0)
	CMD_Usage(progName, &pkiutil);

    /* -d */
    if (pkiutil.opt[opt_ProfileDir].on) {
	profiledir = strdup(pkiutil.opt[opt_ProfileDir].arg);
    }

    /* Display version info and exit */
    if (cmdToRun == cmd_Version) {
	printf("%s\nNSS Version %s\n", PKIUTIL_VERSION_STRING, NSS_VERSION);
	return PR_SUCCESS;
    }

    /* initialize */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    /* XXX allow for read-only and no-db */
    NSS_InitReadWrite(profiledir);

    /* XXX */
    NSS_EnablePKIXCertificates();

    rv = pkiutil_command_dispatcher(&pkiutil, cmdToRun);

    NSS_Shutdown();

    return rv;
}

static PRStatus 
pkiutil_command_dispatcher(cmdCommand *pkiutil, int cmdToRun)
{
    PRStatus status;
    CMDRunTimeData rtData;
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    NSSSlot *slot = NULL;
    NSSToken *token = NULL;
    NSSCallback *pwcb;
    char *inMode;
    char *outMode;

    if (pkiutil->opt[opt_Ascii].on) {
	inMode = outMode = "ascii";
    } else if (pkiutil->opt[opt_Binary].on) {
	inMode = outMode = "binary";
    } else {
	/* default I/O is binary input, pretty-print output */
	inMode = "binary";
	outMode = "pretty-print";
    }

    pwcb = CMD_GetDefaultPasswordCallback(NULL, NULL);
    if (!pwcb) {
	return PR_FAILURE;
    }
    status = NSSTrustDomain_SetDefaultCallback(td, pwcb, NULL);
    if (status != PR_SUCCESS) {
	return status;
    }
    status = CMD_SetRunTimeData(pkiutil->opt[opt_InputFile].arg, NULL, inMode,
                                pkiutil->opt[opt_OutputFile].arg, outMode,
                                &rtData);
    if (status != PR_SUCCESS) {
	return status;
    }
    if (pkiutil->opt[opt_TokenName].on) {
	NSSUTF8 *tokenOrSlotName = pkiutil->opt[opt_TokenName].arg;
	/* First try by slot name */
	slot = NSSTrustDomain_FindSlotByName(td, tokenOrSlotName);
	if (slot) {
	    token = NSSSlot_GetToken(slot);
	} else {
	    token = NSSTrustDomain_FindTokenByName(td, tokenOrSlotName);
	    if (token) {
		slot = NSSToken_GetSlot(token);
	    }
	}
    }
    switch (cmdToRun) {
    case cmd_Add:
	status = AddObject(td,
	                   NULL,
	                   NULL,
	                   pkiutil->opt[opt_Nickname].arg,
	                   &rtData);
	break;
    case cmd_ChangePassword:
	status = CMD_ChangeSlotPassword(slot);
	break;
    case cmd_Delete:
	if (pkiutil->opt[opt_Orphans].on) {
	    status = DeleteOrphanedKeyPairs(td, NULL, &rtData);
	    break;
	}
	status = DeleteObject(td,
	                      NULL,
	                      NULL,
	                      pkiutil->opt[opt_Nickname].arg);
	break;
    case cmd_List:
	status = ListObjects(td,
	                     NULL,
	                     pkiutil->opt[opt_Type].arg,
	                     pkiutil->opt[opt_Nickname].arg,
	                     0,
	                     &rtData);
	break;
    case cmd_Print:
	status = DumpObject(td,
	                    NULL,
	                    NULL,
	                    pkiutil->opt[opt_Nickname].arg,
	                    pkiutil->opt[opt_Chain].on,
	                    &rtData);
	break;
    default:
	status = PR_FAILURE;
	break;
    }
    CMD_FinishRunTimeData(&rtData);
    CMD_DestroyCallback(pwcb);
    if (slot) {
	NSSSlot_Destroy(slot);
    }
    if (token) {
	NSSToken_Destroy(token);
    }
    return status;
}

