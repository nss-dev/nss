/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _UTIL_H
#define	_UTIL_H

#include <prlog.h>
#include <termios.h>
#include <base64.h>
#include <unistd.h>
#include <sys/stat.h>
#include "util.h"
#include <prprf.h>
#include <prerror.h>
#include <nss.h>
#include <pk11func.h>

/*
 * These utility functions are adapted from those found in
 * the sectool library used by the NSS security tools and
 * other NSS test applications.
 */

typedef struct {
    enum {
        PW_NONE = 0,        /* no password */
        PW_FROMFILE = 1,    /* password stored in a file */
        PW_PLAINTEXT = 2    /* plain-text password passed in  buffer */
        /* PW_EXTERNAL = 3  */
    } source;
    char *data;
    /* depending on source this can be the actual
     * password or the file to read it from
     */
} secuPWData;


/*
 * PrintAsAscii
 */
extern void
PrintAsAscii(PRFileDesc* out, const unsigned char *data, unsigned int len);

/*
 * PrintAsHex
 */
extern void
PrintAsHex(PRFileDesc* out, const unsigned char *data, unsigned int len);

/*
 * GetDigit
 */
extern int
GetDigit(char c);

/*
 * HexToBuf
 */
extern int
HexToBuf(unsigned char *inString, SECItem *outbuf, PRBool isHexData);

/*
 * FileToItem
 */
extern SECStatus
FileToItem(SECItem *dst, PRFileDesc *src);


/*
 * CheckPassword
 */
extern PRBool
CheckPassword(char *cp);

/*
 * GetPassword
 */
extern char *
GetPassword(FILE   *input,
            FILE   *output,
            char   *prompt,
            PRBool (*ok)(char *));

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
extern char *
FilePasswd(PK11SlotInfo *
           slot, PRBool retry, void *arg);

/*
 * GetModulePassword
 */
extern char *
GetModulePassword(PK11SlotInfo *slot,
                  int          retry, 
                  void         *pwdata);

/*
 * GenerateRandom
 */
extern SECStatus
GenerateRandom(unsigned char *rbuf, 
               int           rsize);

/*
 * FileToItem
 */
extern SECStatus
FileToItem(SECItem    *dst,
           PRFileDesc *src);

/*
 * SeedFromNoiseFile
 */
extern SECStatus
SeedFromNoiseFile(const char *noiseFileName);

/*
 * FileSize
 */
extern long
FileSize(const char* filename);

/*
 * ReadDERFromFile
 */
extern SECStatus
ReadDERFromFile(SECItem *der, const char *inFileName, PRBool ascii);

#endif /* _UTIL_H */
