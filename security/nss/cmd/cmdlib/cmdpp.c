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
#include <ctype.h>

#include "nsspkix.h"
#include "cmdutil.h"

static void
indent(CMDPrinter *printer)
{
    printer->start += INDENT_MULTIPLE;
    for ( ; printer->col < printer->start; printer->col++) {
	PR_fprintf(printer->out, " ");
    }
}

static void
to_indent(CMDPrinter *printer)
{
    for ( ; printer->col < printer->start; printer->col++) {
	PR_fprintf(printer->out, " ");
    }
}

static void
to_offset(CMDPrinter *printer)
{
    for ( ; printer->col - printer->start < printer->offset; 
         printer->col++) 
    {
	PR_fprintf(printer->out, " ");
    }
}

static void
newline(CMDPrinter *printer)
{
    PR_fprintf(printer->out, "\n");
    printer->col = 0;
    to_indent(printer);
    to_offset(printer);
}

static void
newline_reset(CMDPrinter *printer)
{
    printer->offset = 0;
    newline(printer);
}

static void
print_heading(CMDPrinter *printer, char *heading)
{
    PR_fprintf(printer->out, "%s: ", heading);
    printer->offset = strlen(heading) + 2;
    printer->col += printer->offset;
}

void
CMD_InitPrinter(CMDPrinter *printer, PRFileDesc *out, int start, int stop)
{
    printer->out = out;
    printer->start = start;
    printer->stop = stop;
    for (printer->col = 0; printer->col < printer->start; printer->col++) {
	PR_fprintf(out, " ");
    }
}

void
CMD_PrintHex(CMDPrinter *printer, NSSItem *item, char *message)
{
    int i;
    unsigned char *buf = (unsigned char *)item->data;

    print_heading(printer, message);
    for (i = 0; i < item->size; i++) {
	if (i < item->size - 1) {
	    PR_fprintf(printer->out, "%02x:", buf[i]);
	} else {
	    PR_fprintf(printer->out, "%02x", buf[i]);
	}
	printer->col += 4;
	if (printer->col > printer->stop - 4) {
	    newline(printer);
	}
    }
}

void
CMD_PrintBitString(CMDPrinter *printer, NSSItem *item, char *message)
{
    NSSItem it = *item;
    int extra = (item->size % 8) ? 1 : 0;
    it.size = it.size / 8 + extra;
    CMD_PrintHex(printer, &it, message);
}

void
CMD_PrintPKIXTBSCertificate(CMDPrinter *printer, 
                            NSSPKIXTBSCertificate *tbsCert,
                            char *message)
{
    print_heading(printer, message);
    newline(printer);
}

void
CMD_PrintPKIXCertificate(CMDPrinter *printer, NSSPKIXCertificate *pkixCert,
                         char *message)
{
    NSSPKIXTBSCertificate *tbsCert;
#if 0
    NSSPKIXAlgorithmIdentifier *sigAlg;
#endif
    NSSBitString *sig;

    print_heading(printer, message);
    newline_reset(printer);
    indent(printer);

    tbsCert = NSSPKIXCertificate_GetTBSCertificate(pkixCert);
    if (tbsCert) {
	CMD_PrintPKIXTBSCertificate(printer, tbsCert, "Data");
    }

    newline_reset(printer);

#if 0
    sigAlg = NSSPKIXCertificate_GetSignatureAlgorithm(pkixCert);
    if (sigAlg) {
	CMD_PrintPKIXAlgorithmIdentifier(printer, sigAlg, 
	                                 "Algorithm Identifier");
    }

    newline_reset(printer);
#endif

    sig = NSSPKIXCertificate_GetSignature(pkixCert);
    if (sig) {
	CMD_PrintBitString(printer, sig, "Signature");
    }
}

