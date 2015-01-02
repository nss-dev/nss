/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _UTIL_H
#define	_UTIL_H

#include <prprf.h>
#include <nss.h>
#include <pk11func.h>

typedef struct {
    enum {
	PW_NONE = 0,        /* no password */
	PW_FROMFILE = 1,    /* password stored in a file */
	PW_PLAINTEXT = 2    /* plain-text password passed in a buffer */
	/* PW_EXTERNAL = 3  */
    } source;
    char *data;
    /* depending on source this can be the actual
     * password or the file to read it from
     */
} secuPWData;

/*
 * CheckPassword
 */
extern PRBool
CheckPassword(char *cp);

/*
 * GetPassword
 */
extern char *
GetPassword(FILE *input, FILE *output, char *prompt,
            PRBool (*ok)(char *));

/*
 * FilePasswd
 */
char *
FilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg);


/*
 * GetModulePassword
 */
extern char *
GetModulePassword(PK11SlotInfo *slot, int retry, void *pwdata);

#endif /* _UTIL_H */