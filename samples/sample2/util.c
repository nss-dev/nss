/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <prlog.h>
#include <termios.h>
#include <unistd.h>
#include "util.h"

/*
 * These utility functions are adapted from those found in
 * the sectool library used by the NSS security tools and
 * other NSS test applications.
 */

/*
 * echoOff
 */
static void echoOff(int fd)
{
   if (isatty(fd)) {
       struct termios tio;
       tcgetattr(fd, &tio);
       tio.c_lflag &= ~ECHO;
       tcsetattr(fd, TCSAFLUSH, &tio);
   }
}

/*
 * echoOn
 */
static void echoOn(int fd)
{
   if (isatty(fd)) {
       struct termios tio;
       tcgetattr(fd, &tio);
       tio.c_lflag |= ECHO;
       tcsetattr(fd, TCSAFLUSH, &tio);
   }
}

/*
 * CheckPassword
 */
PRBool CheckPassword(char *cp)
{
    int len;
    char *end;
    len = PORT_Strlen(cp);
    if (len < 8) {
        return PR_FALSE;
    }
    end = cp + len;
    while (cp < end) {
        unsigned char ch = *cp++;
        if (!((ch >= 'A') && (ch <= 'Z')) &&
            !((ch >= 'a') && (ch <= 'z'))) {
            return PR_TRUE;
        }
   }
   return PR_FALSE;
}

/*
 * GetPassword
 */
char* GetPassword(FILE *input, FILE *output, char *prompt,
                                PRBool (*ok)(char *))
{
    char phrase[200] = {'\0'};
    int infd         = fileno(input);
    int isTTY        = isatty(infd);

    for (;;) {
        /* Prompt for password */
        if (isTTY) {
            fprintf(output, "%s", prompt);
            fflush (output);
            echoOff(infd);
        }
        fgets(phrase, sizeof(phrase), input);
        if (isTTY) {
            fprintf(output, "\n");
            echoOn(infd);
        }
        /* stomp on newline */
        phrase[PORT_Strlen(phrase)-1] = 0;
        /* Validate password */
        if (!(*ok)(phrase)) {
            if (!isTTY) return 0;
            fprintf(output, "Password must be at least 8 characters long with one or more\n");
            fprintf(output, "non-alphabetic characters\n");
            continue;
        }
        return (char*) PORT_Strdup(phrase);
    }
}

/*
 * FilePasswd extracts the password from a text file
 *
 * Storing passwords is often used with server environments
 * where prompting the user for a password or requiring it
 * to be entered in the commnd line is not a feasible option.
 *
 * This function supports password extraction from files with
 * multipe passwords, one for each token. In the single password
 * case a line would just have the passord whereas in the multi-
 * password variant they could be of the form
 *
 * token_1_name:its_password
 * token_2_name:its_password
 *
 */
char *
FilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char* phrases, *phrase;
    PRFileDesc *fd;
    PRInt32 nb;
    char *pwFile = arg;
    int i;
    const long maxPwdFileSize = 4096;
    char* tokenName = NULL;
    int tokenLen = 0;

    if (!pwFile)
        return 0;

    if (retry) {
        return 0;  /* no good retrying - the files contents will be the same */
    }

    phrases = PORT_ZAlloc(maxPwdFileSize);

    if (!phrases) {
        return 0; /* out of memory */
    }
 
    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) {
        fprintf(stderr, "No password file \"%s\" exists.\n", pwFile);
        PORT_Free(phrases);
        return NULL;
    }

    nb = PR_Read(fd, phrases, maxPwdFileSize);

    PR_Close(fd);

    if (nb == 0) {
        fprintf(stderr,"password file contains no data\n");
        PORT_Free(phrases);
        return NULL;
    }

    if (slot) {
        tokenName = PK11_GetTokenName(slot);
        if (tokenName) {
            tokenLen = PORT_Strlen(tokenName);
        }
    }
    i = 0;
    do {
        int startphrase = i;
        int phraseLen;

        /* handle the Windows EOL case */
        while (phrases[i] != '\r' && phrases[i] != '\n' && i < nb) i++;
        
        /* terminate passphrase */
        phrases[i++] = '\0';
        /* clean up any EOL before the start of the next passphrase */
        while ( (i<nb) && (phrases[i] == '\r' || phrases[i] == '\n')) {
            phrases[i++] = '\0';
        }
        /* now analyze the current passphrase */
        phrase = &phrases[startphrase];
        if (!tokenName)
            break;
        if (PORT_Strncmp(phrase, tokenName, tokenLen)) continue;
        phraseLen = PORT_Strlen(phrase);
        if (phraseLen < (tokenLen+1)) continue;
        if (phrase[tokenLen] != ':') continue;
        phrase = &phrase[tokenLen+1];
        break;

    } while (i<nb);

    phrase = PORT_Strdup((char*)phrase);
    PORT_Free(phrases);
    return phrase;
}

/*
 * GetModulePassword
 */
char* GetModulePassword(PK11SlotInfo *slot, int retry, void *arg)
{
    char prompt[255];
    secuPWData *pwdata = (secuPWData *)arg;
    char *pw;

    if (pwdata == NULL) {
        return NULL;
    }

    if (retry && pwdata->source != PW_NONE) {
        PR_fprintf(PR_STDERR, "Incorrect password/PIN entered.\n");
        return NULL;
    }

    switch (pwdata->source) {
    case PW_NONE:
        sprintf(prompt, "Enter Password or Pin for \"%s\":",
                PK11_GetTokenName(slot));
        return GetPassword(stdin, stdout, prompt, CheckPassword);
    case PW_FROMFILE:
        pw = FilePasswd(slot, retry, pwdata->data);
        pwdata->source = PW_PLAINTEXT;
        pwdata->data = PL_strdup(pw);
        return pw;
    case PW_PLAINTEXT:
        return PL_strdup(pwdata->data);
    default:
        break;
    }
    PR_fprintf(PR_STDERR, "Password check failed:  No password found.\n");
    return NULL;
}

