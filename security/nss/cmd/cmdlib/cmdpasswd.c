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

/* cmdpasswd.c
 *
 * Routines for handling slot login via password callbacks.
 */

#include <string.h>
#include <ctype.h>

#include "nssdev.h"
#include "cmdutil.h"

#ifdef XP_UNIX
#include <termios.h>
#include <unistd.h>
#endif /* XP_UNIX */

#ifdef _WINDOWS
#include <conio.h>
#include <io.h>
#define QUIET_FGETS quiet_fgets
static char * quiet_fgets (char *buf, int length, FILE *input);
#else /* !_WINDOWS */
#define QUIET_FGETS fgets
#endif /* WINDOWS */

#ifdef XP_UNIX
#ifdef VMS
static char consoleName[] = "TT";
#else /* !VMS */
static char consoleName[] = "/dev/tty";
#endif /* VMS */
#else /* !XP_UNIX */
static char consoleName[] = "CON:";
#endif /* XP_UNIX */

static void echoOff(int fd)
{
#if defined(XP_UNIX) && !defined(VMS)
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag &= ~ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
#endif
}

static void echoOn(int fd)
{
#if defined(XP_UNIX) && !defined(VMS)
    if (isatty(fd)) {
	struct termios tio;
	tcgetattr(fd, &tio);
	tio.c_lflag |= ECHO;
	tcsetattr(fd, TCSAFLUSH, &tio);
    }
#endif
}

static NSSUTF8 *
get_password(FILE *input, FILE *output, char *prompt, PRBool (*ok)(char *))
{
    char phrase[200];
    int infd = fileno(input);
#if defined(_WINDOWS) || defined(OS2)
    int isTTY = (input == stdin);
#else
    int isTTY = isatty(infd);
#endif
    for (;;) {
	/* Prompt for password */
	if (isTTY) {
	    fprintf(output, "%s", prompt);
            fflush (output);
	    echoOff(infd);
	}

	QUIET_FGETS ( phrase, sizeof(phrase), input);

	if (isTTY) {
	    fprintf(output, "\n");
	    echoOn(infd);
	}

	/* stomp on newline */
	phrase[strlen(phrase)-1] = 0;

	/* Validate password */
	if (!(*ok)(phrase)) {
	    /* Not weird enough */
	    if (!isTTY) return 0;
	    fprintf(output, "Password must be at least 8 characters long,\n");
	    fprintf(output, "with one or more non-alphabetic characters\n");
	    continue;
	}
	return NSSUTF8_Duplicate(phrase, NULL);
    }
}

#if 0
static PRBool 
check_password(char *cp)
{
    int len;
    char *end;

    len = strlen(cp);
    if (len < 8) {
	return PR_FALSE;
    }
    end = cp + len;
    while (cp < end) {
	unsigned char ch = *cp++;
	if (!((ch >= 'A') && (ch <= 'Z')) &&
	    !((ch >= 'a') && (ch <= 'z'))) {
	    /* pass phrase has at least one non alphabetic in it */
	    return PR_TRUE;
	}
    }
    return PR_FALSE;
}
#endif

static PRBool 
null_check_password(char *cp)
{
    return (cp != NULL);
}

/* Get a password from the input terminal, without echoing */

#ifdef _WINDOWS
static char * quiet_fgets (char *buf, int length, FILE *input)
  {
  int c;
  char *end = buf;

  /* fflush (input); */
  memset (buf, 0, length);

  if (input != stdin) {
     return fgets(buf,length,input);
  }

  while (1)
    {
    c = getch();

    if (c == '\b')
      {
      if (end > buf)
        end--;
      }

    else if (--length > 0)
      *end++ = c;

    if (!c || c == '\n' || c == '\r')
      break;
    }

  return buf;
  }
#endif

#if 0
static void
clear_password(char *p)
{
    if (p) {
	memset(p, 0, strlen(p));
	free(p);
    }
}
#endif

static NSSUTF8 *
get_password_string(char *prompt)
{
    NSSUTF8 *p = NULL;

#ifndef _WINDOWS
    FILE *input, *output;

    /* open terminal */
    input = fopen(consoleName, "r");
    if (input == NULL) {
	fprintf(stderr, "Error opening input terminal for read\n");
	return NULL;
    }

    output = fopen(consoleName, "w");
    if (output == NULL) {
	fprintf(stderr, "Error opening output terminal for write\n");
	return NULL;
    }

    p = get_password(input, output, prompt, null_check_password);

    fclose(input);
    fclose(output);

#else
    /* Win32 version of above. opening the console may fail
       on windows95, and certainly isn't necessary.. */

    p = get_password(stdin, stdout, prompt, null_check_password);

#endif

    return p;
}

static char *
get_password_from_file(char *pwFile)
{
    unsigned char phrase[200];
    PRFileDesc *fd;
    PRInt32 nb;
    int i;

    if (!pwFile)
	return NULL;

    nb = PR_Read(fd, phrase, sizeof(phrase));
    PR_Close(fd);

    /* handle the Windows EOL case */
    i = 0;
    while (phrase[i] != '\r' && phrase[i] != '\n' && i < nb) i++;
    phrase[i] = '\0';
    if (nb == 0) {
	fprintf(stderr,"password file contains no data\n");
	return NULL;
    }
    return strdup(phrase);
}

#if 0
char *
secu_InitSlotPassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char *p0 = NULL;
    char *p1 = NULL;
    FILE *input, *output;
    secuPWData *pwdata = arg;

    if (pwdata->source == PW_FROMFILE) {
	return SECU_FilePasswd(slot, retry, pwdata->data);
    } else if (pwdata->source == PW_PLAINTEXT) {
	return PL_strdup(pwdata->data);
    }
    
    /* PW_NONE - get it from tty */
    /* open terminal */
#ifdef _WINDOWS
    input = stdin;
#else
    input = fopen(consoleName, "r");
#endif
    if (input == NULL) {
	PR_fprintf(PR_STDERR, "Error opening input terminal for read\n");
	return NULL;
    }

    /* we have no password, so initialize database with one */
    PR_fprintf(PR_STDERR, "In order to finish creating your database, you\n");
    PR_fprintf(PR_STDERR, "must enter a password which will be used to\n");
    PR_fprintf(PR_STDERR, "encrypt this key and any future keys.\n\n");
    PR_fprintf(PR_STDERR, "The password must be at least 8 characters long,\n");
    PR_fprintf(PR_STDERR, "and must contain at least one non-alphabetic ");
    PR_fprintf(PR_STDERR, "character.\n\n");

    output = fopen(consoleName, "w");
    if (output == NULL) {
	PR_fprintf(PR_STDERR, "Error opening output terminal for write\n");
	return NULL;
    }


    for (;;) {
	if (!p0) {
	    p0 = SEC_GetPassword(input, output, "Enter new password: ",
			         SEC_BlindCheckPassword);
	}
	if (pwdata->source == PW_NONE) {
	    p1 = SEC_GetPassword(input, output, "Re-enter password: ",
				 SEC_BlindCheckPassword);
	}
	if (pwdata->source != PW_NONE || (PORT_Strcmp(p0, p1) == 0)) {
	    break;
	}
	PR_fprintf(PR_STDERR, "Passwords do not match. Try again.\n");
    }
        
    /* clear out the duplicate password string */
    secu_ClearPassword(p1);
    
    fclose(input);
    fclose(output);

    return p0;
}
#endif

PRStatus
CMD_ChangeSlotPassword(NSSSlot *slot)
{
    PRStatus status;
    char *oldpw = NULL, *newpw1 = NULL, *newpw2 = NULL;
    char prompt[255];
    NSSUTF8 *slotName = "foo";

    /* need user init??? */

    /* first get old and check it in a loop??? */
    
    sprintf(prompt, "Enter Password or Pin for \"%s\": ", slotName);
    oldpw = (NSSUTF8 *)get_password_string(prompt);
    
    sprintf(prompt, "Enter New Password or Pin for \"%s\": ", slotName);
    newpw1 = (NSSUTF8 *)get_password_string(prompt);

    sprintf(prompt, "Re-enter New Password or Pin for \"%s\": ", slotName);
    newpw2 = (NSSUTF8 *)get_password_string(prompt);

    if (strcmp(newpw1, newpw2) == 0) {
	status = NSSSlot_SetPassword(slot, oldpw, newpw1);
	if (status == PR_SUCCESS) {
	    fprintf(stdout, "Password successfully changed.\n");
	} else {
	    fprintf(stderr, "Failed to change password.\n");
	}
    } else {
	fprintf(stdout, "Passwords did not match.\n");
    }

    return PR_FAILURE;
}

static NSSUTF8 *
get_password_from_tty(NSSUTF8 *slotName)
{
    char prompt[255];
    sprintf(prompt, "Enter Password or Pin for \"%s\": ", slotName);
    return (NSSUTF8 *)get_password_string(prompt);
}

static PRStatus
default_slot_password_callback
(
  NSSUTF8 *slotName,
  PRUint32 retries,
  void *arg,
  NSSUTF8 **password
)
{
    if (arg) {
	*password = NSSUTF8_Duplicate((NSSUTF8 *)arg, NULL);
    } else if (retries < 3) {
	*password = get_password_from_tty(slotName);
    } else {
	return PR_FAILURE;
    }
    return PR_SUCCESS;
}

NSSCallback *
CMD_GetDefaultPasswordCallback
(
  char *password,
  char *passwordFile
)
{
    NSSCallback *callback;
    callback = (NSSCallback *)PR_Malloc(sizeof(NSSCallback));
    if (callback) {
	callback->getInitPW = NULL;
	callback->getPW = default_slot_password_callback;
	if (passwordFile) {
	    callback->arg = get_password_from_file(passwordFile);
	} else if (password) {
	    callback->arg = NSSUTF8_Duplicate(password, NULL);
	} else {
	    callback->arg = (NSSUTF8 *)NULL;
	}
    }
    return callback;
}

void
CMD_DestroyCallback
(
  NSSCallback *callback
)
{
    PR_Free(callback);
}

