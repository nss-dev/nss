/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * Test program to mangle 1 bit in a binary
 */

#include "nspr.h"
#include "plstr.h"
#include "plgetopt.h"
#include "prio.h"

static PRFileDesc *pr_stderr;
static void
usage(char *program_name)
{

    MPR_fprintf(pr_stderr, "Usage:");
    MPR_fprintf(pr_stderr, "%s -i shared_library_name -o byte_offset -b bit\n", program_name);
}

int
main(int argc, char **argv)
{
    /* buffers and locals */
    PLOptState *optstate;
    char *programName;
    char cbuf;

    /* parameter set variables */
    const char *libFile = NULL;
    int bitOffset = -1;

    /* return values */
    int retval = 2; /* 0 - test succeeded.
                     * 1 - illegal args
                     * 2 - function failed */
    PRFileDesc *fd = NULL;
    int bytesRead;
    int bytesWritten;
    PROffset32 offset = -1;
    PROffset32 pos;

    programName = MPL_strrchr(argv[0], '/');
    programName = programName ? (programName + 1) : argv[0];

    pr_stderr = PR_STDERR;

    optstate = MPL_CreateOptState(argc, argv, "i:o:b:");
    if (optstate == NULL) {
        return 1;
    }

    while (MPL_GetNextOpt(optstate) == PL_OPT_OK) {
        switch (optstate->option) {
            case 'i':
                libFile = optstate->value;
                break;

            case 'o':
                offset = atoi(optstate->value);
                break;

            case 'b':
                bitOffset = atoi(optstate->value);
                break;
        }
    }

    if (libFile == NULL) {
        usage(programName);
        return 1;
    }
    if ((bitOffset >= 8) || (bitOffset < 0)) {
        usage(programName);
        return 1;
    }

    /* open the target signature file */
    fd = MPR_OpenFile(libFile, PR_RDWR, 0666);
    if (fd == NULL) {
        /* lperror(libFile); */
        MPR_fprintf(pr_stderr, "Couldn't Open %s\n", libFile);
        goto loser;
    }

    if (offset < 0) { /* convert to positive offset */
        pos = MPR_Seek(fd, offset, PR_SEEK_END);
        if (pos == -1) {
            MPR_fprintf(pr_stderr, "Seek for read on %s (to %d) failed\n",
                       libFile, offset);
            goto loser;
        }
        offset = pos;
    }

    /* read the byte */
    pos = MPR_Seek(fd, offset, PR_SEEK_SET);
    if (pos != offset) {
        MPR_fprintf(pr_stderr, "Seek for read on %s (to %d) failed\n",
                   libFile, offset);
        goto loser;
    }
    bytesRead = MPR_Read(fd, &cbuf, 1);
    if (bytesRead != 1) {
        MPR_fprintf(pr_stderr, "Read on %s (to %d) failed\n", libFile, offset);
        goto loser;
    }

    MPR_fprintf(pr_stderr, "Changing byte 0x%08x (%d): from %02x (%d) to ",
               offset, offset, (unsigned char)cbuf, (unsigned char)cbuf);
    /* change it */
    cbuf ^= 1 << bitOffset;
    MPR_fprintf(pr_stderr, "%02x (%d)\n",
               (unsigned char)cbuf, (unsigned char)cbuf);

    /* write it back out */
    pos = MPR_Seek(fd, offset, PR_SEEK_SET);
    if (pos != offset) {
        MPR_fprintf(pr_stderr, "Seek for write on %s (to %d) failed\n",
                   libFile, offset);
        goto loser;
    }
    bytesWritten = MPR_Write(fd, &cbuf, 1);
    if (bytesWritten != 1) {
        MPR_fprintf(pr_stderr, "Write on %s (to %d) failed\n", libFile, offset);
        goto loser;
    }

    retval = 0;

loser:
    if (fd)
        MPR_Close(fd);
    MPR_Cleanup();
    return retval;
}

/*#DEFINES += -DSHLIB_SUFFIX=\"$(DLL_SUFFIX)\" -DSHLIB_PREFIX=\"$(DLL_PREFIX)\" */
