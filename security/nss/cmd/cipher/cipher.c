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

#include "cipher.h"

char *progName = "cipher";

static PRStatus cipher_command_dispatcher(cmdCommand *, int);

/* keygen */

/*  cipher commands  */
enum {
    cmd_Decrypt = 0,
    cmd_Encrypt,
    cmd_Hash,
    cmd_KeyGen,
    cmd_Sign,
    cmd_Test,
    cmd_Verify,
    cmd_Version,
    cipher_num_commands
};

/*  cipher options */
enum {
    opt_Help = 0,
    opt_Ascii,
    opt_Cipher,
    opt_ProfileDir,
    opt_TokenName,
    opt_Input,
    opt_InputFile,
    opt_InputMode,
    opt_OutputFile,
    opt_OutputMode,
    opt_Binary,
    opt_Size,
    cipher_num_options
};

static cmdCommandLineArg cipher_commands[] =
{
 { /* cmd_Decrypt */  
   'D', "decrypt", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     CMDBIT(opt_Cipher) | 
     0, 0, 0 
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Input) | 
     CMDBIT(opt_InputFile) | 
     CMDBIT(opt_InputMode) | 
     CMDBIT(opt_OutputFile) | 
     CMDBIT(opt_OutputMode) | 
     CMDBIT(opt_Binary) | 
     0, 0, 0
   },
 },
 { /* cmd_Encrypt */  
   'E', "encrypt", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     CMDBIT(opt_Cipher) | 
     0, 0, 0 
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Input) | 
     CMDBIT(opt_InputFile) | 
     CMDBIT(opt_InputMode) | 
     CMDBIT(opt_OutputFile) | 
     CMDBIT(opt_OutputMode) | 
     CMDBIT(opt_Binary) | 
     0, 0, 0
   },
 },
 { /* cmd_Hash */  
   'H', "hash", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     CMDBIT(opt_Cipher) | 
     0, 0, 0 
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Input) | 
     CMDBIT(opt_InputFile) | 
     CMDBIT(opt_InputMode) | 
     CMDBIT(opt_OutputFile) | 
     CMDBIT(opt_OutputMode) | 
     CMDBIT(opt_Binary) | 
     0, 0, 0
   },
 },
 { /* cmd_KeyGen */  
   'G', "generate-key", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     CMDBIT(opt_Cipher) | 
     0, 0, 0 
   },
   {
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Size) | 
     0, 0, 0
   },
 },
 { /* cmd_Sign */  
   'S', "sign", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     CMDBIT(opt_Cipher) | 
     0, 0, 0 
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Input) | 
     CMDBIT(opt_InputFile) | 
     CMDBIT(opt_InputMode) | 
     CMDBIT(opt_OutputFile) | 
     CMDBIT(opt_OutputMode) | 
     CMDBIT(opt_Binary) | 
     0, 0, 0
   },
 },
 { /* cmd_Test */  
   'T', "test", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     0, 0, 0, 0 
   },
   {
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     0, 0, 0
   },
 },
 { /* cmd_Verify */  
   'V', "verify", 
   CMDNoArg, 0, PR_FALSE, 
   { 
     CMDBIT(opt_Cipher) | 
     0, 0, 0 
   },
   {
     CMDBIT(opt_Ascii) | 
     CMDBIT(opt_ProfileDir) | 
     CMDBIT(opt_TokenName) | 
     CMDBIT(opt_Input) | 
     CMDBIT(opt_InputFile) | 
     CMDBIT(opt_InputMode) | 
     CMDBIT(opt_OutputFile) | 
     CMDBIT(opt_OutputMode) | 
     CMDBIT(opt_Binary) | 
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

static cmdCommandLineOpt cipher_options[] =
{
 { /* opt_Help        */  '?', "help",     CMDNoArg,   0, PR_FALSE },
 { /* opt_Ascii       */  'a', "ascii",    CMDNoArg,   0, PR_FALSE },
 { /* opt_Cipher      */  'c', "cipher",   CMDArgReq,  0, PR_FALSE },
 { /* opt_ProfileDir  */  'd', "dbdir",    CMDArgReq,  0, PR_FALSE },
 { /* opt_TokenName   */  'h', "token",    CMDArgReq,  0, PR_FALSE },
 { /* opt_Input       */   0 , "input",    CMDArgReq,  0, PR_FALSE },
 { /* opt_InputFile   */  'i', "infile",   CMDArgReq,  0, PR_FALSE },
 { /* opt_InputMode   */   0 , "inmode",   CMDArgReq,  0, PR_FALSE },
 { /* opt_OutputFile  */  'o', "outfile",  CMDArgReq,  0, PR_FALSE },
 { /* opt_OutputMode  */   0 , "outmode",  CMDArgReq,  0, PR_FALSE },
 { /* opt_Binary      */  'r', "raw",      CMDNoArg,   0, PR_FALSE },
 { /* opt_Size        */  's', "size",     CMDArgReq,  0, PR_FALSE }
};

void cipher_usage(cmdPrintState *ps, 
                   int num, PRBool cmd, PRBool header, PRBool footer)
{
#define pusg CMD_PrintUsageString
    if (header) {
	pusg(ps, "utility for managing PKCS#11 objects (certs and keys)\n");
    } else if (footer) {
    } else if (cmd) {
	switch(num) {
	case cmd_Decrypt:     
	    pusg(ps, "Decrypt data"); break;
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
	case opt_OutputFile: 
	    pusg(ps, "File for output (def: stdout)"); break;
	case opt_Binary:    
	    pusg(ps, "Use raw (binary der-encoded) mode for I/O"); break;
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
    PRBool    noDB       = PR_FALSE;

    int cmdToRun;
    cmdCommand cipher;
    cipher.ncmd = cipher_num_commands;
    cipher.nopt = cipher_num_options;
    cipher.cmd = cipher_commands;
    cipher.opt = cipher_options;

    progName = strrchr(argv[0], '/');
    progName = progName ? progName+1 : argv[0];

    cmdToRun = CMD_ParseCommandLine(argc, argv, progName, &cipher);

    if (cipher.opt[opt_Help].on)
	CMD_LongUsage(progName, &cipher, cipher_usage);

    if (cmdToRun < 0)
	CMD_Usage(progName, &cipher);

    /* -d */
    if (cipher.opt[opt_ProfileDir].on) {
	profiledir = strdup(cipher.opt[opt_ProfileDir].arg);
    } else {
	noDB = PR_TRUE;
    }

    /* Display version info and exit */
    if (cmdToRun == cmd_Version) {
	printf("%s\nNSS Version %s\n", CIPHER_VERSION_STRING, NSS_VERSION);
	return PR_SUCCESS;
    }

    /* initialize */
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);

    if (noDB) {
	NSS_NoDB_Init(profiledir);
    } else {
	NSS_InitReadWrite(profiledir);
    }

    rv = cipher_command_dispatcher(&cipher, cmdToRun);

    NSS_Shutdown();

    return rv;
}

static PRStatus 
cipher_command_dispatcher(cmdCommand *cipher, int cmdToRun)
{
    PRStatus status;
    CMDRunTimeData rtData;
    NSSTrustDomain *td = NSS_GetDefaultTrustDomain();
    NSSCryptoContext *cc;
    NSSToken *token;
    NSSSlot *slot;
    NSSCallback *pwcb;
    char *inMode;
    char *outMode;
    unsigned int size;
NSSSymmetricKey *symkey;

    if (cipher->opt[opt_Ascii].on) {
	inMode = outMode = "ascii";
    } else if (cipher->opt[opt_Input].on) {
	/* if string given on command line, default I/O is hex */
	inMode = outMode = "hex";
    } else {
	/* default I/O is binary */
	inMode = outMode = "binary";
    }
    /* overrides defaults */
    if (cipher->opt[opt_InputMode].on) {
	inMode = cipher->opt[opt_InputMode].arg;
    }
    if (cipher->opt[opt_OutputMode].on) {
	outMode = cipher->opt[opt_OutputMode].arg;
    }

    pwcb = CMD_GetDefaultPasswordCallback(NULL, NULL);
    if (!pwcb) {
	return PR_FAILURE;
    }
    status = NSSTrustDomain_SetDefaultCallback(td, pwcb, NULL);
    if (status != PR_SUCCESS) {
	return status;
    }
    cc = NSSTrustDomain_CreateCryptoContext(td, NULL, NULL);
    status = CMD_SetRunTimeData(cipher->opt[opt_InputFile].arg, 
                                cipher->opt[opt_Input].arg, inMode,
                                cipher->opt[opt_OutputFile].arg, outMode,
                                &rtData);
    if (status != PR_SUCCESS) {
	return status;
    }
    if (cipher->opt[opt_TokenName].on) {
	NSSUTF8 *tokenOrSlotName = cipher->opt[opt_TokenName].arg;
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
#if 0
    case cmd_Decrypt:
	status = Decrypt(cc, 
	                 cipher->opt[opt_Cipher].arg, 
	                 cipher->opt[opt_Key].arg, 
	                 cipher->opt[opt_IV].arg, 
	                 cipher->opt[opt_Parameters].arg, 
	                 &rtData);
	break;
    case cmd_Encrypt:
	status = Encrypt(cc, 
	                 cipher->opt[opt_Cipher].arg, 
	                 cipher->opt[opt_Key].arg, 
	                 cipher->opt[opt_IV].arg, 
	                 cipher->opt[opt_Parameters].arg, 
	                 &rtData);
	break;
#endif
    case cmd_Hash:
	status = Hash(cc, 
	              cipher->opt[opt_Cipher].arg, 
	              &rtData);
	break;
    case cmd_KeyGen:
	if (cipher->opt[opt_Size].on) {
	    size = atoi(cipher->opt[opt_Size].arg);
	} else size = 0;
	symkey = GenerateSymmetricKey(td, /*cc, */ token, 
	                              cipher->opt[opt_Cipher].arg, 
	                              size, NULL);
	break;
#if 0
    case cmd_Sign:
	status = Sign(cc, 
	              cipher->opt[opt_Cipher].arg, 
	              cipher->opt[opt_Parameters].arg, 
	              &rtData);
	break;
    case cmd_Verify:
	status = Verify(cc, 
	                cipher->opt[opt_Cipher].arg, 
	                cipher->opt[opt_Parameters].arg, 
	                &rtData);
	break;
#endif
    case cmd_Test:
	status = Test1();
	break;
    default:
	status = PR_FAILURE;
	break;
    }
    CMD_FinishRunTimeData(&rtData);
    CMD_DestroyCallback(pwcb);
    return status;
}

