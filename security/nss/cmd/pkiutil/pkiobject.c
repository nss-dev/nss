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
#include "nss.h"
#include "nssbase.h"
#include "nssdev.h"
#include "nsspki.h"
#include "oiddata.h"
#include "nsspki1.h"
/* hmmm...*/
#include "pki.h"
#include "nsspkix.h"

#include "pkiutil.h"

static PKIObjectType
get_object_class(char *type)
{
    if (type == NULL) {
	return PKIAny;
    }
    if (strcmp(type, "certificate") == 0 || strcmp(type, "cert") == 0 ||
        strcmp(type, "Certificate") == 0 || strcmp(type, "Cert") == 0) {
	return PKICert;
    } else if (strcmp(type, "public-key") == 0 || 
               strcmp(type, "PublicKey") == 0) {
	return PKIPublicKey;
    } else if (strcmp(type, "private-key") == 0 || 
               strcmp(type, "PrivateKey") == 0) {
	return PKIPrivateKey;
    } else if (strcmp(type, "all") == 0 || strcmp(type, "any") == 0) {
	return PKIAny;
    }
    fprintf(stderr, "%s: \"%s\" is not a valid PKCS#11 object type.\n",
                     progName, type);
    return PKIUnknown;
}

static NSSKeyPairType
get_key_pair_type(char *type)
{
    if (type == NULL) {
	return NSSKeyPairType_Unknown;
    }
    if (strcmp(type, "rsa") == 0 || strcmp(type, "RSA") == 0) {
	return NSSKeyPairType_RSA;
    } else if (strcmp(type, "dsa") == 0 || strcmp(type, "DSA") == 0) {
	return NSSKeyPairType_DSA;
    } else if (strcmp(type, "dh") == 0 || strcmp(type, "DH") == 0 ||
               strcmp(type, "Diffie-Hellman") == 0) {
	return NSSKeyPairType_DH;
    } else {
	return NSSKeyPairType_Unknown;
    }
}

static NSSOIDTag
get_key_pair_alg(char *type)
{
    NSSKeyPairType kpType = get_key_pair_type(type);
    switch (kpType) {
    case NSSKeyPairType_RSA: 
	return NSS_OID_PKCS1_RSA_ENCRYPTION;
    case NSSKeyPairType_DSA: 
	return NSS_OID_ANSIX9_DSA_SIGNATURE;
    case NSSKeyPairType_DH: 
	return NSS_OID_X942_DIFFIE_HELLMAN_KEY;
    default:
	return NSS_OID_UNKNOWN;
    }
}

/* XXX */
static NSSItem *
get_cert_serial_number(NSSCert *c)
{
    NSSPKIXCertificate *pkixCert;
    NSSPKIXTBSCertificate *tbsCert;
    NSSPKIXCertificateSerialNumber *serialNumber;
    pkixCert = (NSSPKIXCertificate *)NSSCert_GetDecoding(c);
    tbsCert = NSSPKIXCertificate_GetTBSCertificate(pkixCert);
    serialNumber = NSSPKIXTBSCertificate_GetSerialNumber(tbsCert);
    return NSSPKIXCertificateSerialNumber_GetSerialNumber(serialNumber);
}

/* XXX should have a filter function */
static NSSCert *
find_nick_cert_by_sn(NSSTrustDomain *td, char *nickname, char *serial)
{
    int i = 0;
    NSSCert **certs;
    NSSCert *c = NULL;
    certs = NSSTrustDomain_FindCertsByNickname(td, nickname,
                                                      NULL, 0, NULL);
    if (certs) {
	while (certs[i]) {
	    NSSItem *sn = get_cert_serial_number(certs[i]);
	    NSSItem *ser;
	    CMDFileMode mode = CMDFileMode_Hex;
	    ser = CMD_GetDataFromBuffer(serial, strlen(serial), &mode);
	    if (NSSItem_Equal(sn, ser, NULL)) {
		int j = i;
		c = certs[i];
		/* XXX super-hack while not filter */
		while (certs[i+1]) i++;
		certs[j] = certs[i];
		certs[i] = NULL;
		break;
	    }
	    i++;
	}
	NSSCertArray_Destroy(certs);
    }
    return c;
}

static PRStatus
print_cert_callback(NSSCert *c, void *arg)
{
    CMDRunTimeData *rtData = (CMDRunTimeData *)arg;
    CMDPrinter printer;
    NSSUTF8 *nickname = nssCert_GetNickname(c, NULL);
    NSSItem *sn;
    NSSUsages usages;
    PRBool isUserCert = NSSCert_IsPrivateKeyAvailable(c, NULL, NULL);
    sn = get_cert_serial_number(c);
    if (NSSCert_GetTrustedUsages(c, &usages) == NULL) {
	CMD_PrintError("Failed to obtain trusted usages");
	return PR_FAILURE;
    }
    PR_fprintf(rtData->output.file, " %c", (isUserCert) ? 'u' : '-');
    CMD_InitPrinter(&printer, rtData->output.file, 0, 80);
    CMD_PrintCertificateTrust(&printer, &usages, NULL);
    PR_fprintf(rtData->output.file, " %-40s", nickname);
    CMD_PrintHex(&printer, sn, NULL);
    PR_fprintf(rtData->output.file, "    ");
    PR_fprintf(rtData->output.file, "\n");
    return PR_SUCCESS;
}

static PRStatus
print_decoded_cert(CMDRunTimeData *rtData, NSSCert *c)
{
    CMDPrinter printer;

    CMD_InitPrinter(&printer, rtData->output.file, 
                    DEFAULT_LEFT_MARGIN, DEFAULT_RIGHT_MARGIN);

    if (NSSCert_GetType(c) == NSSCertType_PKIX) {
	NSSPKIXCertificate *pkixCert;
	pkixCert = (NSSPKIXCertificate *)NSSCert_GetDecoding(c);
	if (pkixCert) {
	    CMD_PrintPKIXCertificate(&printer, pkixCert, "Cert");
	}
    }
    /* XXX */
    PR_fprintf(printer.out, "\n");
    return PR_FAILURE;
}

static PRStatus
dump_cert_callback(NSSCert *c, void *arg)
{
    CMDRunTimeData *rtData = (CMDRunTimeData *)arg;
    print_decoded_cert(rtData, c);
    return PR_SUCCESS;
}

static PRStatus
print_privkey_callback(NSSPrivateKey *vk, void *arg)
{
    CMDRunTimeData *rtData = (CMDRunTimeData *)arg;
    NSSUTF8 *nickname = nssPrivateKey_GetNickname(vk, NULL);
    NSSCert **certs, **cp;
    NSSPublicKey *pubkey;
    PR_fprintf(rtData->output.file, "Listing %s", nickname);
    certs = NSSPrivateKey_FindCerts(vk, NULL, 0, NULL);
    if (certs) {
	PR_fprintf(rtData->output.file, " for certs ");
	for (cp = certs; *cp; cp++) {
	    nickname = nssCert_GetNickname(*cp, NULL);
	    PR_fprintf(rtData->output.file, "%s ", nickname);
	}
	NSSCertArray_Destroy(certs);
    }
    printf("\n");
    return PR_SUCCESS;
}

static PRStatus
print_rsa_key_info(NSSRSAPublicKeyInfo *rsaInfo, CMDRunTimeData *rtData)
{
    CMDPrinter printer;
    CMD_InitPrinter(&printer, rtData->output.file, 0, 80);
    PR_fprintf(rtData->output.file, "Modulus Bits: %d\n", 
                                    rsaInfo->modulus.size * 8);
    CMD_PrintHex(&printer, &rsaInfo->modulus, "Modulus");
    CMD_PrintHex(&printer, &rsaInfo->publicExponent, "Public Exponent");
    if (rsaInfo->publicExponent.size <= 4) {
	PRUint32 pe = *(PRUint32*)rsaInfo->publicExponent.data;
	pe = PR_ntohl(pe);
	PR_fprintf(rtData->output.file, "(%d)\n", pe);
    }
    return PR_SUCCESS;
}

static PRStatus
print_public_key_info(NSSPublicKey *pubKey, CMDRunTimeData *rtData)
{
    NSSPublicKeyInfo pubKeyInfo;
    NSSPublicKey_GetKeyInfo(pubKey, &pubKeyInfo);
    switch(pubKeyInfo.kind) {
    case NSSKeyPairType_RSA:
	return print_rsa_key_info(&pubKeyInfo.u.rsa, rtData);
    case NSSKeyPairType_DSA:
    case NSSKeyPairType_DH:
    default:
	return PR_FAILURE;
    }
    return PR_FAILURE;
}

static PRStatus
list_nickname_certs
(
  NSSTrustDomain *td,
  char *nickname,
  PRUint32 maximumOpt,
  PRStatus (* callback)(NSSCert *c, void *arg),
  void *arg
)
{
    NSSCert **certs = NULL;
    NSSCert **certp;
    NSSCert *cert[2];
    if (maximumOpt == 1) {
	cert[0] = NSSTrustDomain_FindBestCertByNickname(td,
	                                                       nickname, 
	                                                       NSSTime_Now(),
	                                                       NULL,
	                                                       NULL);
	cert[1] = NULL;
	certs = cert;
    } else {
	certs = NSSTrustDomain_FindCertsByNickname(td,
	                                                  nickname, 
	                                                  NULL,
	                                                  maximumOpt,
	                                                  NULL);
    }
    if (!certs) {
	return PR_SUCCESS;
    }
    for (certp = certs; *certp; certp++) {
	(*callback)(*certp, arg);
	{
	    NSSDER *encoding = nssCert_GetEncoding(*certp);
	    NSSCert *c;
	    c = NSSTrustDomain_FindCertByEncodedCert(td,
                                                                   encoding);
	}
    }
    if (maximumOpt == 1) {
	NSSCert_Destroy(cert[0]);
    } else {
	NSSCertArray_Destroy(certs);
    }
    return PR_SUCCESS;
}

static PRStatus
list_certs
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  CMDRunTimeData *rtData
)
{
    (void)NSSTrustDomain_TraverseCerts(td,
                                              print_cert_callback,
                                              rtData);
    return PR_SUCCESS;
}

static PRStatus
list_private_keys
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  CMDRunTimeData *rtData
)
{
    if (NSSTrustDomain_Login(td, NULL) != PR_SUCCESS) {
	return PR_FAILURE;
    }
    (void)NSSTrustDomain_TraversePrivateKeys(td,
                                             print_privkey_callback,
                                             rtData);
    return PR_SUCCESS;
}

PRStatus
ListObjects
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nicknameOpt,
  PRUint32 maximumOpt,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PKIObjectType objectKind;
    objectKind = get_object_class(objectTypeOpt);
    switch (objectKind) {
    case PKICert:
	if (nicknameOpt) {
	    status = list_nickname_certs(td, nicknameOpt, 0,
	                                  print_cert_callback, rtData);
	} else {
	    status = list_certs(td, tokenOpt, rtData);
	}
	break;
    case PKIPublicKey:
	break;
    case PKIPrivateKey:
#if 0
	if (nicknameOpt) {
	    status = list_nickname_certs(td, tokenOpt, nicknameOpt, 0,
	                                  print_cert_callback, rtData);
	} else {
#endif
	    status = list_private_keys(td, tokenOpt, rtData);
#if 0
	}
#endif
	break;
    case PKIAny:
	if (nicknameOpt) {
	    status = list_nickname_certs(td, nicknameOpt, 0,
	                                  print_cert_callback, rtData);
	} else {
	    status = list_certs(td, tokenOpt, rtData);
	}
	break;
    case PKIUnknown:
	status = PR_FAILURE;
	break;
    }
    return status;
}

PRStatus
ListChain
(
  NSSTrustDomain *td,
  char *nickname,
  char *serial,
  PRUint32 maximumOpt,
  CMDRunTimeData *rtData
)
{
    int i;
    PRStatus status;
    NSSCert *c;
    NSSCert **chain;

    if (serial) {
	c = find_nick_cert_by_sn(td, nickname, serial);
    } else {
	c = NSSTrustDomain_FindBestCertByNickname(td, nickname, 
	                                                 NSSTime_Now(), 
	                                                 NULL, NULL);
    }

    if (!c) {
	CMD_PrintError("Failed to find certificate %s", nickname);
	return PR_FAILURE;
    }

    chain = NSSCert_BuildChain(c, NSSTime_Now(), 
                                      NULL, /* usage      */
                                      NULL, /* policies   */
                                      NULL, /* certs[]    */
                                      0,    /* rvLimit    */
                                      NULL, /* arena      */
                                      &status);
    i = 0;
    while (chain[++i]);
    while (i > 0) {
	--i;
	status = print_cert_callback(chain[i], rtData);
    }
    NSSCertArray_Destroy(chain);
    return PR_SUCCESS;
}

static PRStatus
dump_cert_info
(
  NSSTrustDomain *td,
  NSSCert *c,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PRUint32 i, j;
    NSSToken **tokens, **tp;
    /* XXX
     * When we do searches by nickname, we only get instances of the
     * cert for that nickname.  An instance on another token with a
     * different label will not match.  Should the library do the
     * this workaround?
     */
    NSSDER *issuer = NSSCert_GetIssuer(c);
    NSSDER *serial = NSSCert_GetSerialNumber(c);
    NSSCert *cp = NSSTrustDomain_FindCertByIssuerAndSerialNumber(td, issuer, serial);

    tokens = NSSCert_GetTokens(cp, NULL, 0, NULL);
    if (tokens) {
	for (tp = tokens; *tp; tp++) {
	    PR_fprintf(rtData->output.file, 
	               "nickname \"%s\" on token \"%s\"\n",
	               NSSCert_GetNickname(cp, *tp),
	               NSSToken_GetName(*tp));
	}
	NSSTokenArray_Destroy(tokens);
	PR_fprintf(rtData->output.file, "\n");
    }
    NSSCert_Destroy(cp);
    return PR_SUCCESS;
}

PRStatus
DumpObject
(
  NSSTrustDomain *td,
  char *objectType,
  char *nickname,
  char *serialOpt,
  PRBool info,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    NSSCert *c;
    NSSPrivateKey *vkey;
    NSSPublicKey *bkey;

    switch (get_object_class(objectType)) {
    case PKICert:
    case PKIAny:         /* default to certificate */
	if (serialOpt) {
	    c = find_nick_cert_by_sn(td, nickname, serialOpt);
	    status = dump_cert_info(td, c, rtData);
	    NSSCert_Destroy(c);
	} else if (info) {
	    c = NSSTrustDomain_FindBestCertByNickname(td, nickname, 
	                                                     NSSTime_Now(), 
	                                                     NULL,
	                                                     NULL);
	    status = dump_cert_info(td, c, rtData);
	    NSSCert_Destroy(c);
	} else {
	    status = list_nickname_certs(td, nickname, 1,
	                                 dump_cert_callback, rtData);
	}
	break;
    case PKIPublicKey:
	/* XXX this ain't the right way */
	c = NSSTrustDomain_FindBestCertByNickname(td, nickname, 
	                                                 NSSTime_Now(), 
	                                                 NULL,
	                                                 NULL);
	if (c) {
	    bkey = NSSCert_GetPublicKey(c);
	    if (bkey) {
		print_public_key_info(bkey, rtData);
		NSSPublicKey_Destroy(bkey);
	    }
	    NSSCert_Destroy(c);
	}
	break;
    case PKIPrivateKey:
	/*bkey = NSSPrivateKey_FindPublicKey(vk);*/
	break;
    case PKIUnknown:
	status = PR_FAILURE;
	break;
    }
    return status;
}

static void get_usages_from_string(char *usageStr, NSSUsages *usages)
{
    char usage;
    usages->ca = usages->peer = 0;
    while ((usage = *usageStr++)) {
	switch (usage) {
	case 'c':  usages->peer |= NSSUsage_SSLClient;       break;
	case 'v':  usages->peer |= NSSUsage_SSLServer;       break;
	case 'r':  usages->peer |= NSSUsage_EmailRecipient;  break;
	case 's':  usages->peer |= NSSUsage_EmailSigner;     break;
	case 'o':  usages->peer |= NSSUsage_CodeSigner;      break;
	case 't':  usages->peer |= NSSUsage_StatusResponder; break;
	case 'u':  usages->peer |= NSSUsage_SSLServerWithStepUp; break;
	case 'C':  usages->ca |= NSSUsage_SSLClient;         break;
	case 'V':  usages->ca |= NSSUsage_SSLServer;         break;
	case 'R':  usages->ca |= NSSUsage_EmailRecipient;    break;
	case 'S':  usages->ca |= NSSUsage_EmailSigner;       break;
	case 'O':  usages->ca |= NSSUsage_CodeSigner;        break;
	case 'T':  usages->ca |= NSSUsage_StatusResponder;   break;
	case 'U':  usages->ca |= NSSUsage_SSLServerWithStepUp; break;
	}
    }
}

PRStatus
ValidateCert
(
  NSSTrustDomain *td,
  char *nickname,
  char *serial,
  char *usageStr,
  PRBool info,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    NSSCert *c;
    NSSUsages usages;

    if (usageStr) {
	get_usages_from_string(usageStr, &usages);
    }

    if (serial) {
	c = find_nick_cert_by_sn(td, nickname, serial);
    } else {
	c = NSSTrustDomain_FindBestCertByNickname(td, nickname, 
	                                                 NSSTime_Now(), 
	                                                 NULL,
	                                                 NULL);
    }
    if (!c) {
	CMD_PrintError("Failed to locate cert %s", nickname);
	return PR_FAILURE;
    }

    status = NSSCert_Validate(c, NSSTime_Now(), &usages, NULL);
    if (status == PR_SUCCESS) {
	PR_fprintf(PR_STDOUT, "Cert validated.\n");
    } else {
	CMD_PrintError("Validation failed");
    }

    return status;
}

PRStatus
SetCertTrust
(
  NSSTrustDomain *td,
  char *nickname,
  char *serial,
  char *trustedUsages
)
{
    PRStatus status;
    NSSUsages usages;
    NSSCert *c;


    get_usages_from_string(trustedUsages, &usages);

    /* XXX the current trust object does not allow both ca && peer */
    if (usages.ca & usages.peer) {
	PR_fprintf(PR_STDERR, 
	           "Setting both peer and CA usage not supported\n");
	return PR_FAILURE;
    }

    if (serial) {
	c = find_nick_cert_by_sn(td, nickname, serial);
    } else {
	c = NSSTrustDomain_FindBestCertByNickname(td, nickname, 
	                                                 NSSTime_Now(), 
	                                                 NULL,
	                                                 NULL);
    }
    if (!c) {
	CMD_PrintError("Failed to locate cert %s", nickname);
	return PR_FAILURE;
    }

    status = NSSCert_SetTrustedUsages(c, &usages);

    NSSCert_Destroy(c);
    return status;
}

static PRStatus
import_certificate
(
  NSSTrustDomain *td,
  NSSToken *token,
  char *nickname,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    NSSItem *encoding;
    NSSCert *cert;

    /* get the encoded cert from the input source */
    encoding = CMD_GetInput(rtData);
    /* import into trust domain */
    cert = NSSTrustDomain_ImportEncodedCert(td, encoding, nickname, token);
    if (cert) {
	PR_fprintf(PR_STDOUT, "Import successful.\n");
	dump_cert_info(td, cert, rtData);
	NSSCert_Destroy(cert);
	status = PR_SUCCESS;
    } else {
	PR_fprintf(PR_STDERR, "Import failed!\n");
	status = PR_FAILURE;
    }
    return status;
}

/* XXX */
extern char *key_pass_hardcode;

static PRStatus
import_private_key
(
  NSSTrustDomain *td,
  NSSToken *token,
  char *nickname,
  char *keyTypeOpt,
  char *keypass,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    NSSItem *encoding;
    NSSPrivateKey *vkey;
    NSSOIDTag keyPairAlg;

    if (keyTypeOpt) {
	keyPairAlg = get_key_pair_alg(keyTypeOpt);
	if (keyPairAlg == NSS_OID_UNKNOWN) {
	    PR_fprintf(PR_STDERR, "%s is not a valid key type.\n", 
	                           keyTypeOpt);
	    return PR_FAILURE;
	}
    } else {
	/* default to RSA */
	keyPairAlg = NSS_OID_PKCS1_RSA_ENCRYPTION;
    }

    /* get the encoded key from the input source */
    encoding = CMD_GetInput(rtData);
    /* import into trust domain */
    vkey = NSSTrustDomain_ImportEncodedPrivateKey(td, encoding,
                                                  keyPairAlg, 0, 0,
                                                  NULL,
                                    CMD_PWCallbackForKeyEncoding(keypass), 
                                                  token/*, nickname */);
    if (vkey) {
	PR_fprintf(PR_STDOUT, "Import successful.\n");
	/* dump_cert_info(td, cert, rtData); */
	NSSPrivateKey_Destroy(vkey);
	status = PR_SUCCESS;
    } else {
	PR_fprintf(PR_STDERR, "Import failed!\n");
	status = PR_FAILURE;
    }
    return status;
}

PRStatus
ImportObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname,
  char *keyTypeOpt,
  char *keypass,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PKIObjectType objectKind;

    objectKind = get_object_class(objectTypeOpt);
    switch (objectKind) {
    case PKIAny: /* default to certificate */
    case PKICert:
	status = import_certificate(td, tokenOpt, nickname, rtData);
	break;
    case PKIPublicKey:
	break;
    case PKIPrivateKey:
	tokenOpt = tokenOpt ? tokenOpt : nss_GetDefaultDatabaseToken();
	status = import_private_key(td, tokenOpt, nickname, keyTypeOpt,
	                            keypass, rtData);
	break;
    case PKIUnknown:
	status = PR_FAILURE;
	break;
    }
    return status;
}

static int
numbered_menu_choice (
  void (* display_info)(void *item),
  void **array
)
{
    int i, nb, num;
    void **it;
    char buf[5];
    for (i=0, it = array; *it; it++, i++) {
	PR_fprintf(PR_STDOUT, "%d - ", i);
	(*display_info)(*it);
	PR_fprintf(PR_STDOUT, "\n");
    }
    PR_fprintf(PR_STDOUT, "\nSelection:  ");
    nb = PR_Read(PR_STDIN, buf, sizeof buf);
    num = atoi(buf);
    if (num < 0 || num >= i) {
	return -1;
    }
    return num;
}

#if 0
static void
private_key_choice
#endif

static NSSPrivateKey *
private_key_chooser(NSSPrivateKey **vkeys)
{
#if 0
    int choice;
    choice = numbered_menu_choice(private_key_choice, (void **)vkeys);
    if (choice >= 0) {
	return vkeys[choice];
    }
#endif
    return NULL;
}

static void
cert_choice(void *arg)
{
    NSSCert *c = (NSSCert *)arg;
    NSSUTF8 *nickname = nssCert_GetNickname(c, NULL);
    PR_fprintf(PR_STDOUT, "%s", nickname);
}

static NSSCert *
cert_chooser(NSSCert **certs)
{
    int choice = 0;
    if (certs[1]) {
	/* more than one to choose from, prompt user */
	choice = numbered_menu_choice(cert_choice, (void **)certs);
    }
    if (choice >= 0) {
	return certs[choice];
    }
    return NULL;
}

static PRStatus
export_certificate (
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *nickname,
  CMDRunTimeData *rtData
)
{
    PRStatus status = PR_FAILURE;
    NSSCert *cert, **certs;
    certs = NSSTrustDomain_FindCertsByNickname(td, nickname, 
                                                      NULL, 0, NULL);
    if (certs) {
	cert = cert_chooser(certs);
	if (cert) {
	    NSSDER *enc = nssCert_GetEncoding(cert);
	    CMD_DumpOutput(enc, rtData);
	    status = PR_SUCCESS;
	}
	NSSCertArray_Destroy(certs);
    }
    return status;
}

static PRStatus
generate_salt(NSSItem *salt)
{
    salt->data = NSS_GenerateRandom(16, NULL, NULL);
    salt->size = 16;
    return PR_SUCCESS;
}

static PRStatus
export_private_key (
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *nickname,
  char *keypass,
  CMDRunTimeData *rtData
)
{
    PRStatus status = PR_FAILURE;
    NSSPrivateKey *vkey, **vkeys;
    NSSCert *ucert, **ucerts;

    vkey = NULL;
#if 0
    vkeys = NSSTrustDomain_FindPrivateKeysByNickname(td, nickname);
#else
vkeys = NULL;
#endif
    if (vkeys) {
	vkey = private_key_chooser(vkeys);
    } else {
	/* XXX I shouldn't have to do this, but softoken can't find public
	 *     keys w/o the private key, which needs login... no other way
	 *     to identify user certs
	 */
	status = NSSTrustDomain_Login(td, NULL);
	if (status == PR_FAILURE) return PR_FAILURE;
	ucerts = NSSTrustDomain_FindUserCerts(td, NULL, 0, NULL);
	if (ucerts) {
	    ucert = cert_chooser(ucerts);
	    if (ucert) {
		vkey = NSSCert_FindPrivateKey(ucert, NULL);
	    }
	    NSSCertArray_Destroy(ucerts);
	}
    }
    if (vkey) {
	NSSAlgNParam *pbe;
	NSSParameters params;
	NSSItem *encKey;

	params.pbe.iteration = 1;
	generate_salt(&params.pbe.salt);
	pbe = NSSOIDTag_CreateAlgNParam(NSS_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC, 
	                                &params, NULL);
	if (!pbe) {
	    NSSPrivateKey_Destroy(vkey);
	    return PR_FAILURE;
	}
	encKey = NSSPrivateKey_Encode(vkey, pbe, NULL,
	                              CMD_PWCallbackForKeyEncoding(keypass), 
	                              NULL, NULL);
	nss_ZFreeIf(params.pbe.salt.data); /* XXX */
	NSSAlgNParam_Destroy(pbe);
	if (encKey) {
	    CMD_DumpOutput(encKey, rtData);
	    NSSItem_Destroy(encKey);
	    status = PR_SUCCESS;
	}
	NSSPrivateKey_Destroy(vkey);
    }
    return status;
}

PRStatus
ExportObject (
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname,
  char *keypass,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PKIObjectType objectKind;
    objectKind = get_object_class(objectTypeOpt);
    switch (objectKind) {
    case PKIAny: /* default to certificate */
    case PKICert:
	status = export_certificate(td, tokenOpt, nickname, rtData);
	break;
    case PKIPrivateKey:
	status = export_private_key(td, tokenOpt, nickname, keypass, rtData);
	break;
    case PKIPublicKey: /* don't handle this one */
    case PKIUnknown:
	status = PR_FAILURE;
	break;
    }
    return status;
}

static NSSAlgNParam *
get_rsa_key_gen_params(PRUint32 keySizeInBits, PRUint32 pubExp)
{
    NSSParameters params;

    params.rsakg.modulusBits = keySizeInBits;
    if (CMD_SetRSAPE(&params.rsakg.publicExponent, pubExp) == PR_FAILURE)
	return NULL;

    return NSSOIDTag_CreateAlgNParamForKeyGen(NSS_OID_PKCS1_RSA_ENCRYPTION, 
                                              &params, NULL);
}

PRStatus
GenerateKeyPair
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *keyTypeOpt,
  char *keySizeOpt,
  char *nickname,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    NSSPublicKey *bkey = NULL;
    NSSPrivateKey *vkey = NULL;
    NSSAlgNParam *kpGen = NULL;
    NSSKeyPairType keyPairType;
    PRUint32 keySizeInBits;
    PRUint32 pubExp;
    NSSToken *token;

    /* XXX */
    token = tokenOpt ? tokenOpt : nss_GetDefaultDatabaseToken();

    keySizeInBits = keySizeOpt ? atoi(keySizeOpt) : 1024;
    if (keySizeInBits < 0) {
	PR_fprintf(PR_STDERR, "%s is not a valid key size.\n", keySizeOpt);
	return PR_FAILURE;
    }

    if (keyTypeOpt) {
	keyPairType = get_key_pair_type(keyTypeOpt);
	if (keyPairType == NSSKeyPairType_Unknown) {
	    PR_fprintf(PR_STDERR, "%s is not a valid key type.\n", 
	                           keyTypeOpt);
	    return PR_FAILURE;
	}
    } else {
	/* default to RSA */
	keyPairType = NSSKeyPairType_RSA;
    }

    switch (keyPairType) {
    case NSSKeyPairType_RSA: 
	pubExp = 65537; /* XXX */
	kpGen = get_rsa_key_gen_params(keySizeInBits, pubExp);
	break;
    default:
	PR_fprintf(PR_STDERR, "%s not supported for keygen\n", keyTypeOpt);
	return PR_FAILURE;
    }

    if (!kpGen) {
	CMD_PrintError("Failed to initialize algorithm for keygen");
	return PR_FAILURE;
    }

    status = NSSTrustDomain_GenerateKeyPair(td, kpGen,
                                            &bkey, &vkey,
                                            nickname, 0, 0, /* XXX */
                                            token, NULL);

    NSSAlgNParam_Destroy(kpGen);

    if (status == PR_SUCCESS) {
	NSSPublicKey_Destroy(bkey);
	NSSPrivateKey_Destroy(vkey);
	PR_fprintf(PR_STDOUT, "Key pair successfully generated.\n");
    } else {
	CMD_PrintError("Key generation failed.");
    }
    return status;
}

static PRStatus
delete_certificates
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *nickname
)
{
    PRStatus status;
    NSSCert **certs, **cp;
    cp = certs = NSSTrustDomain_FindCertsByNickname(td,
                                                           nickname, 
                                                           NULL,
                                                           0,
                                                           NULL);
    while (cp && *cp) {
	status = NSSCert_DeleteStoredObject(*cp, NULL);
	if (status != PR_SUCCESS) {
	    fprintf(stderr, "Failed to delete certificate %s\n", nickname);
	    break;
	}
	cp++;
    }
    NSSCertArray_Destroy(certs);
    return status;
}

PRStatus
DeleteObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname
)
{
    PRStatus status;
    PKIObjectType objectKind;
    objectKind = get_object_class(objectTypeOpt);
    switch (objectKind) {
    case PKIAny: /* default to certificate */
    case PKICert:
	status = delete_certificates(td, tokenOpt, nickname);
	break;
    case PKIPublicKey:
	break;
    case PKIPrivateKey:
	break;
    case PKIUnknown:
	status = PR_FAILURE;
	break;
    }
    return status;
}

static PRStatus
delete_orphan_callback(NSSPrivateKey *vk, void *arg)
{
    PRStatus status;
    CMDRunTimeData *rtData = (CMDRunTimeData *)arg;
    NSSUTF8 *nickname = nssPrivateKey_GetNickname(vk, NULL);
    NSSCert **certs;
    NSSPublicKey *pubkey;
    PR_fprintf(rtData->output.file, "Deleting %s\n", nickname);
    certs = NSSPrivateKey_FindCerts(vk, NULL, 0, NULL);
    if (certs) {
	NSSCertArray_Destroy(certs);
	return PR_SUCCESS; /* not an orphan */
    }
    pubkey = NSSPrivateKey_FindPublicKey(vk);
    if (pubkey) {
	status = NSSPublicKey_DeleteStoredObject(pubkey, NULL);
	if (status == PR_SUCCESS) {
	    PR_fprintf(rtData->output.file, "deleted public key, ");
	} else {
	    PR_fprintf(rtData->output.file, "FAILED to delete public key, ");
	}
	NSSPublicKey_Destroy(pubkey);
    }
    status = NSSPrivateKey_DeleteStoredObject(vk, NULL);
    if (status == PR_SUCCESS) {
	PR_fprintf(rtData->output.file, "deleted private key\n");
    } else {
	PR_fprintf(rtData->output.file, "FAILED to delete private key\n");
    }
    return PR_SUCCESS;
}

PRStatus
DeleteOrphanedKeyPairs
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  CMDRunTimeData *rtData
)
{
    if (NSSTrustDomain_Login(td, NULL) != PR_SUCCESS) {
	return PR_FAILURE;
    }
    (void)NSSTrustDomain_TraversePrivateKeys(td,
                                             delete_orphan_callback,
                                             rtData);
    return PR_SUCCESS;
}

