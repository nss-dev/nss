/*
 * Copyright (c) 1987, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)mktemp.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */

#include "watcomfx.h"

#if !defined(_WIN32_WCE)
#ifdef macintosh
#include <unix.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include <errno.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include "mcom_db.h"
#include "hash.h"	/* for NO_FILE */

#if !defined(_WINDOWS) && !defined(XP_OS2_VACPP)
#include <unistd.h>
#endif

#ifdef XP_OS2_VACPP
#define ENOTDIR EBADPOS
#include <process.h>
#include <dirent.h>
#endif

#ifdef _WINDOWS
#if !defined(_WIN32_WCE)
#include <process.h>
#endif
/* #include "winfile.h" */
#endif

#include "private/pprio.h"

#if defined(_WIN32_WCE)
/* This really belongs in a libc compatibility library for WinCE */
static int 
getpid(void)
{
	int pid = 0xffff & (int)GetCurrentProcess();
	return pid;
}
#endif

static int _gettemp(char *path, PRFileDesc **doopen, int extraFlags);

PRFileDesc *
dbm_mkstemp(char *path)
{
	PRFileDesc * fd = NULL;
#ifdef XP_OS2
	FILE *temp = tmpfile();
	if (!temp) {
		SET_ERROR(PR_IO_ERROR, errno);
		return NO_FILE;
	}
	return PR_ImportFile( fileno(temp) );
#else
	return (_gettemp(path, &fd, 0) ? fd : NO_FILE);
#endif
}

#if 0
char *
mktemp(char *path)
{
	return(_gettemp(path, (PRFileDesc **)0, 0) ? path : (char *)0);
}
#endif

/* NB: This routine modifies its input string, and does not always restore it.
** returns 1 on success, 0 on failure.
*/
static int 
_gettemp(char *path, PRFileDesc * *doopen, int extraFlags)
{    
#if !defined(_WINDOWS) || defined(_WIN32)
	extern int errno;                    
#endif
	register char *start, *trv;
	struct PRFileInfo fileInfo;
	unsigned int pid;

	pid = getpid();
	for (trv = path; *trv; ++trv);		/* extra X's get set to 0's */
	while (*--trv == 'X') {
		*trv = (pid % 10) + '0';
		pid /= 10;
	}

	/*
	 * check the target directory; if you have six X's and it
	 * doesn't exist this runs for a *very* long time.
	 */
	for (start = trv + 1;; --trv) {
		char saved;
		if (trv <= path)
			break;
		saved = *trv;
		if (saved == '/' || saved == '\\') {
			int rv;
			*trv = '\0';
			rv = PR_GetFileInfo(path, &fileInfo);
			*trv = saved;
			if (rv)
				return(0);
			if (PR_FILE_DIRECTORY != fileInfo.type) {
				SET_ERROR(PR_NOT_DIRECTORY_ERROR, ENOTDIR);
				return(0);
			}
			break;
		}
	}

	for (;;) {
		if (doopen) {
			*doopen = PR_OpenFile(path, 
                             PR_CREATE_FILE|PR_EXCL|PR_RDWR|extraFlags, 0600);
			if (*doopen != NO_FILE)
				return(1);
			if (PR_GetError() != PR_FILE_EXISTS_ERROR)
				return(0);
		}
		else if (PR_GetFileInfo(path, &fileInfo)) {
			return(PR_GetError() == PR_FILE_NOT_FOUND_ERROR);
		}

		/* tricky little algorithm for backward compatibility */
		for (trv = start;;) {
			if (!*trv)
				return(0);
			if (*trv == 'z')
				*trv++ = 'a';
			else {
				if (isdigit(*trv))
					*trv = 'a';
				else
					++*trv;
				break;
			}
		}
	}
	/*NOTREACHED*/
}
