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
#include "nsspki.h"
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
unindent(CMDPrinter *printer)
{
    printer->start -= INDENT_MULTIPLE;
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
CMD_PrintInteger(CMDPrinter *printer, NSSItem *bignum, char *message)
{
    /* XXX for now */
    CMD_PrintHex(printer, bignum, message);
}

void
CMD_PrintPKIXTime(CMDPrinter *printer, NSSPKIXTime *pkixTime, char *message)
{
    NSSTime time;
    NSSUTF8 *utcTime;

    print_heading(printer, message);

    time = NSSPKIXTime_GetTime(pkixTime, NULL);
    utcTime = NSSTime_GetUTCTime(time, NULL);
    PR_fprintf(printer->out, "%s", utcTime);
    /* NSS_ZFreeIf(utcTime); XXX */
}

void
CMD_PrintPKIXValidity(CMDPrinter *printer, NSSPKIXValidity *validity, 
                      char *message)
{
    NSSPKIXTime *time;

    print_heading(printer, message);
    newline_reset(printer);
    indent(printer);

    time = NSSPKIXValidity_GetNotBefore(validity),
    CMD_PrintPKIXTime(printer, time, "Not Before");
    newline_reset(printer);

    time = NSSPKIXValidity_GetNotAfter(validity),
    CMD_PrintPKIXTime(printer, time, "Not After");

    unindent(printer);
}

void
CMD_PrintPKIXKeyUsage(CMDPrinter *printer, NSSPKIXKeyUsage *keyUsage, 
                      char *message)
{
    NSSPKIXKeyUsageValue ku;
    PRBool first = PR_TRUE;

    print_heading(printer, message);
    newline_reset(printer);
    indent(printer);

    ku = NSSPKIXKeyUsage_GetValue(keyUsage);
    if (ku & NSSPKIXKeyUsage_DigitalSignature) {
	PR_fprintf(printer->out, "digitalSignature");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_NonRepudiation) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "nonRepudiation");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_KeyEncipherment) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "keyEncipherment");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_DataEncipherment) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "dataEncipherment");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_KeyAgreement) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "keyAgreement");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_KeyCertSign) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "keyCertSign");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_CRLSign) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "cRLSign");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_EncipherOnly) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "encipherOnly");
	first = PR_FALSE;
    }
    if (ku & NSSPKIXKeyUsage_DecipherOnly) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "decipherOnly");
	first = PR_FALSE;
    }

    unindent(printer);
}

void
CMD_PrintPKIXnsCertType(CMDPrinter *printer, 
                        NSSPKIXnetscapeCertType *nsCertType, 
                        char *message)
{
    NSSPKIXnetscapeCertTypeValue nsct;
    PRBool first = PR_TRUE;

    print_heading(printer, message);
    newline_reset(printer);
    indent(printer);

    nsct = NSSPKIXnetscapeCertType_GetValue(nsCertType);
    if (nsct & NSSPKIXnetscapeCertType_SSLClient) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "SSL Client");
	first = PR_FALSE;
    }
    if (nsct & NSSPKIXnetscapeCertType_SSLServer) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "SSL Server");
	first = PR_FALSE;
    }
    if (nsct & NSSPKIXnetscapeCertType_Email) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "Email");
	first = PR_FALSE;
    }
    if (nsct & NSSPKIXnetscapeCertType_ObjectSigning) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "Object Signing");
	first = PR_FALSE;
    }
    if (nsct & NSSPKIXnetscapeCertType_SSLCA) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "SSL CA");
	first = PR_FALSE;
    }
    if (nsct & NSSPKIXnetscapeCertType_EmailCA) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "Email CA");
	first = PR_FALSE;
    }
    if (nsct & NSSPKIXnetscapeCertType_ObjectSigningCA) {
	if (!first) newline(printer);
	PR_fprintf(printer->out, "Object Signing CA");
	first = PR_FALSE;
    }

    unindent(printer);
}

void
CMD_PrintPKIXExtensions(CMDPrinter *printer, NSSPKIXExtensions *extensions, 
                        char *message)
{
    NSSPKIXKeyUsage *keyUsage;
    NSSPKIXnetscapeCertType *nsCertType;

    print_heading(printer, message);
    newline_reset(printer);
    indent(printer);

    keyUsage = NSSPKIXExtensions_GetKeyUsage(extensions);
    if (keyUsage) {
	CMD_PrintPKIXKeyUsage(printer, keyUsage, "Key Usage");
	newline_reset(printer);
    }

    nsCertType = NSSPKIXExtensions_GetNetscapeCertType(extensions);
    if (keyUsage) {
	CMD_PrintPKIXnsCertType(printer, nsCertType, "netscape Cert Type");
    }

    unindent(printer);
}

void
CMD_PrintPKIXTBSCertificate(CMDPrinter *printer, 
                            NSSPKIXTBSCertificate *tbsCert,
                            char *message)
{
    NSSPKIXCertificateSerialNumber *serialNum;
    NSSPKIXValidity *validity;
    NSSPKIXExtensions *extensions;

    print_heading(printer, message);
    newline_reset(printer);
    indent(printer);

    serialNum = NSSPKIXTBSCertificate_GetSerialNumber(tbsCert);
    if (serialNum) {
	CMD_PrintInteger(printer, serialNum, "Serial Number");
	newline_reset(printer);
    }

    validity = NSSPKIXTBSCertificate_GetValidity(tbsCert);
    if (validity) {
	CMD_PrintPKIXValidity(printer, validity, "Validity");
	newline_reset(printer);
    }

    extensions = NSSPKIXTBSCertificate_GetExtensions(tbsCert);
    if (extensions) {
	CMD_PrintPKIXExtensions(printer, extensions, "Extensions");
    }

    unindent(printer);
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
	newline_reset(printer);
    }

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

    unindent(printer);
}

