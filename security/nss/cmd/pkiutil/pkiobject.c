
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
	return PKICertificate;
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

/* XXX */
static NSSItem *
get_cert_serial_number(NSSCertificate *c)
{
    NSSPKIXCertificate *pkixCert;
    NSSPKIXTBSCertificate *tbsCert;
    pkixCert = (NSSPKIXCertificate *)NSSCertificate_GetDecoding(c);
    tbsCert = NSSPKIXCertificate_GetTBSCertificate(pkixCert);
    return NSSPKIXTBSCertificate_GetSerialNumber(tbsCert);
}

/* XXX should have a filter function */
static NSSCertificate *
find_nick_cert_by_sn(NSSTrustDomain *td, char *nickname, char *serial)
{
    int i = 0;
    NSSCertificate **certs;
    NSSCertificate *c = NULL;
    certs = NSSTrustDomain_FindCertificatesByNickname(td, nickname,
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
	NSSCertificateArray_Destroy(certs);
    }
    return c;
}

static PRStatus
print_cert_callback(NSSCertificate *c, void *arg)
{
    CMDRunTimeData *rtData = (CMDRunTimeData *)arg;
    CMDPrinter printer;
    NSSUTF8 *nickname = nssCertificate_GetNickname(c, NULL);
    NSSItem *serialNumber;
    NSSUsages usages;
    PRBool isUserCert = NSSCertificate_IsPrivateKeyAvailable(c, NULL, NULL);
    serialNumber = get_cert_serial_number(c);
    if (NSSCertificate_GetTrustedUsages(c, &usages) == NULL) {
	CMD_PrintError("Failed to obtain trusted usages");
	return PR_FAILURE;
    }
    PR_fprintf(rtData->output.file, " %c", (isUserCert) ? 'u' : '-');
    CMD_InitPrinter(&printer, rtData->output.file, 0, 80);
    CMD_PrintCertificateTrust(&printer, &usages, NULL);
    PR_fprintf(rtData->output.file, " %-40s", nickname);
    CMD_PrintHex(&printer, serialNumber, NULL);
    PR_fprintf(rtData->output.file, "    ");
    PR_fprintf(rtData->output.file, "\n");
    return PR_SUCCESS;
}

static PRStatus
print_decoded_cert(CMDRunTimeData *rtData, NSSCertificate *c)
{
    CMDPrinter printer;

    CMD_InitPrinter(&printer, rtData->output.file, 
                    DEFAULT_LEFT_MARGIN, DEFAULT_RIGHT_MARGIN);

    if (NSSCertificate_GetType(c) == NSSCertificateType_PKIX) {
	NSSPKIXCertificate *pkixCert;
	pkixCert = (NSSPKIXCertificate *)NSSCertificate_GetDecoding(c);
	if (pkixCert) {
	    CMD_PrintPKIXCertificate(&printer, pkixCert, "Certificate");
	}
    }
    /* XXX */
    PR_fprintf(printer.out, "\n");
    return PR_FAILURE;
}

static PRStatus
dump_cert_callback(NSSCertificate *c, void *arg)
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
    NSSCertificate **certs, **cp;
    NSSPublicKey *pubkey;
    PR_fprintf(rtData->output.file, "Listing %s", nickname);
    certs = NSSPrivateKey_FindCertificates(vk, NULL, 0, NULL);
    if (certs) {
	PR_fprintf(rtData->output.file, " for certs ");
	for (cp = certs; *cp; cp++) {
	    nickname = nssCertificate_GetNickname(*cp, NULL);
	    PR_fprintf(rtData->output.file, "%s ", nickname);
	}
	NSSCertificateArray_Destroy(certs);
    }
    pubkey = NSSPrivateKey_FindPublicKey(vk);
    if (pubkey) {
	PR_fprintf(rtData->output.file, ", have public key");
	NSSPublicKey_Destroy(pubkey);
    }
    printf("\n");
    return PR_SUCCESS;
}

static PRStatus
list_nickname_certs
(
  NSSTrustDomain *td,
  char *nickname,
  PRUint32 maximumOpt,
  PRStatus (* callback)(NSSCertificate *c, void *arg),
  void *arg
)
{
    NSSCertificate **certs = NULL;
    NSSCertificate **certp;
    NSSCertificate *cert[2];
    if (maximumOpt == 1) {
	cert[0] = NSSTrustDomain_FindBestCertificateByNickname(td,
	                                                       nickname, 
	                                                       NSSTime_Now(),
	                                                       NULL,
	                                                       NULL);
	cert[1] = NULL;
	certs = cert;
    } else {
	certs = NSSTrustDomain_FindCertificatesByNickname(td,
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
	    NSSDER *encoding = nssCertificate_GetEncoding(*certp);
	    NSSCertificate *c;
	    c = NSSTrustDomain_FindCertificateByEncodedCertificate(td,
                                                                   encoding);
	}
    }
    if (maximumOpt == 1) {
	NSSCertificate_Destroy(cert[0]);
    } else {
	NSSCertificateArray_Destroy(certs);
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
    (void)NSSTrustDomain_TraverseCertificates(td,
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
    case PKICertificate:
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
    NSSCertificate *c;
    NSSCertificate **chain;

    if (serial) {
	c = find_nick_cert_by_sn(td, nickname, serial);
    } else {
	c = NSSTrustDomain_FindBestCertificateByNickname(td, nickname, 
	                                                 NSSTime_Now(), 
	                                                 NULL, NULL);
    }

    if (!c) {
	CMD_PrintError("Failed to find certificate %s", nickname);
	return PR_FAILURE;
    }

    chain = NSSCertificate_BuildChain(c, NSSTime_Now(), 
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
    NSSCertificateArray_Destroy(chain);
    return PR_SUCCESS;
}

static PRStatus
dump_cert_info
(
  NSSTrustDomain *td,
  NSSCertificate *c,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PRUint32 i, j;
    NSSToken **tokens, **tp;

    tokens = NSSCertificate_GetTokens(c, NULL);
    if (tokens) {
	for (tp = tokens; *tp; tp++) {
	    PR_fprintf(rtData->output.file, 
	               "nickname \"%s\" on token \"%s\"\n",
	               NSSCertificate_GetNickname(c, *tp),
	               NSSToken_GetName(*tp));
	}
	NSSTokenArray_Destroy(tokens);
	PR_fprintf(rtData->output.file, "\n");
    }
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
    NSSCertificate *c;

    switch (get_object_class(objectType)) {
    case PKICertificate:
    case PKIAny:         /* default to certificate */
	if (serialOpt) {
	    c = find_nick_cert_by_sn(td, nickname, serialOpt);
	    status = dump_cert_info(td, c, rtData);
	    NSSCertificate_Destroy(c);
	} else if (info) {
	    c = NSSTrustDomain_FindBestCertificateByNickname(td, nickname, 
	                                                     NSSTime_Now(), 
	                                                     NULL,
	                                                     NULL);
	    status = dump_cert_info(td, c, rtData);
	    NSSCertificate_Destroy(c);
	} else {
	    status = list_nickname_certs(td, nickname, 1,
	                                 dump_cert_callback, rtData);
	}
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
    NSSCertificate *c;
    NSSUsages usages;

    if (usageStr) {
	get_usages_from_string(usageStr, &usages);
    }

    if (serial) {
	c = find_nick_cert_by_sn(td, nickname, serial);
    } else {
	c = NSSTrustDomain_FindBestCertificateByNickname(td, nickname, 
	                                                 NSSTime_Now(), 
	                                                 NULL,
	                                                 NULL);
    }
    if (!c) {
	CMD_PrintError("Failed to locate cert %s", nickname);
	return PR_FAILURE;
    }

    status = NSSCertificate_Validate(c, NSSTime_Now(), &usages, NULL);
    if (status == PR_SUCCESS) {
	PR_fprintf(PR_STDOUT, "Certificate validated.\n");
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
    NSSCertificate *c;


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
	c = NSSTrustDomain_FindBestCertificateByNickname(td, nickname, 
	                                                 NSSTime_Now(), 
	                                                 NULL,
	                                                 NULL);
    }
    if (!c) {
	CMD_PrintError("Failed to locate cert %s", nickname);
	return PR_FAILURE;
    }

    status = NSSCertificate_SetTrustedUsages(c, &usages);

    NSSCertificate_Destroy(c);
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
    NSSCertificate *cert;

    /* get the encoded cert from the input source */
    encoding = CMD_GetInput(rtData);
    /* import into trust domain */
    cert = NSSTrustDomain_ImportEncodedCertificate(td, encoding,
                                                   token, nickname);
    if (cert) {
	PR_fprintf(PR_STDOUT, "Import successful.\n");
	dump_cert_info(td, cert, rtData);
	NSSCertificate_Destroy(cert);
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
    NSSKeyPairType keyPairType;

    if (!keyTypeOpt) {
	/* default to RSA */
	keyPairType = NSSKeyPairType_RSA;
    } else {
	keyPairType = get_key_pair_type(keyTypeOpt);
	if (keyPairType == NSSKeyPairType_Unknown) {
	    PR_fprintf(PR_STDERR, "%s is not a valid key type.\n", 
	                           keyTypeOpt);
	    return PR_FAILURE;
	}
    }

    /* get the encoded key from the input source */
    encoding = CMD_GetInput(rtData);
    /* import into trust domain */
    vkey = NSSTrustDomain_ImportEncodedPrivateKey(td, encoding,
                                                  keyPairType, 0, 0,
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
    NSSToken *token;

    /* XXX */
    token = tokenOpt ? tokenOpt : nss_GetDefaultDatabaseToken();

    objectKind = get_object_class(objectTypeOpt);
    switch (objectKind) {
    case PKIAny: /* default to certificate */
    case PKICertificate:
	status = import_certificate(td, token, nickname, rtData);
	break;
    case PKIPublicKey:
	break;
    case PKIPrivateKey:
	status = import_private_key(td, token, nickname, keyTypeOpt,
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
    NSSCertificate *c = (NSSCertificate *)arg;
    NSSUTF8 *nickname = nssCertificate_GetNickname(c, NULL);
    PR_fprintf(PR_STDOUT, "%s", nickname);
}

static NSSCertificate *
cert_chooser(NSSCertificate **certs)
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
    NSSCertificate *cert, **certs;
    certs = NSSTrustDomain_FindCertificatesByNickname(td, nickname, 
                                                      NULL, 0, NULL);
    if (certs) {
	cert = cert_chooser(certs);
	if (cert) {
	    NSSDER *enc = nssCertificate_GetEncoding(cert);
	    CMD_DumpOutput(enc, rtData);
	    status = PR_SUCCESS;
	}
	NSSCertificateArray_Destroy(certs);
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
  CMDRunTimeData *rtData
)
{
    PRStatus status = PR_FAILURE;
    NSSPrivateKey *vkey, **vkeys;
    NSSCertificate *ucert, **ucerts;

#if 0
    vkeys = NSSTrustDomain_FindPrivateKeysByNickname(td, nickname);
#else
vkeys = NULL;
#endif
    if (vkeys) {
	vkey = private_key_chooser(vkeys);
    } else {
	ucerts = NSSTrustDomain_FindUserCertificates(td, NULL, 0, NULL);
	if (ucerts) {
	    ucert = cert_chooser(ucerts);
	    if (ucert) {
		vkey = NSSCertificate_FindPrivateKey(ucert, NULL);
	    }
	    NSSCertificateArray_Destroy(ucerts);
	}
    }
    if (vkey) {
	NSSAlgorithmAndParameters *pbe;
	NSSParameters params;
	NSSOID *pbeAlg;
	NSSItem *encKey;
	params.pbe.iteration = 1;
	generate_salt(&params.pbe.salt);
	pbeAlg = NSSOID_CreateFromTag(NSS_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC);
	if (!pbeAlg) {
	    return PR_FAILURE;
	}
	pbe = NSSOID_CreateAlgorithmAndParameters(pbeAlg, &params, NULL);
	if (!pbe) {
	    return PR_FAILURE;
	}
	encKey = NSSPrivateKey_Encode(vkey, pbe, NULL,
	                              CMD_PWCallbackForKeyEncoding(NULL), 
	                              NULL, NULL);
	NSS_ZFreeIf(params.pbe.salt.data);
	NSSAlgorithmAndParameters_Destroy(pbe);
	if (encKey) {
	    CMD_DumpOutput(encKey, rtData);
	    NSSItem_Destroy(encKey);
	    status = PR_SUCCESS;
	}
    }
    return status;
}

PRStatus
ExportObject (
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PKIObjectType objectKind;
    objectKind = get_object_class(objectTypeOpt);
    switch (objectKind) {
    case PKIAny: /* default to certificate */
    case PKICertificate:
	status = export_certificate(td, tokenOpt, nickname, rtData);
	break;
    case PKIPrivateKey:
	status = export_private_key(td, tokenOpt, nickname, rtData);
	break;
    case PKIPublicKey: /* don't handle this one */
    case PKIUnknown:
	status = PR_FAILURE;
	break;
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
    NSSCertificate **certs, **cp;
    cp = certs = NSSTrustDomain_FindCertificatesByNickname(td,
                                                           nickname, 
                                                           NULL,
                                                           0,
                                                           NULL);
    while (cp && *cp) {
	status = NSSCertificate_DeleteStoredObject(*cp, NULL);
	if (status != PR_SUCCESS) {
	    fprintf(stderr, "Failed to delete certificate %s\n", nickname);
	    break;
	}
	cp++;
    }
    NSSCertificateArray_Destroy(certs);
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
    case PKICertificate:
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
    NSSCertificate **certs;
    NSSPublicKey *pubkey;
    PR_fprintf(rtData->output.file, "Deleting %s\n", nickname);
    certs = NSSPrivateKey_FindCertificates(vk, NULL, 0, NULL);
    if (certs) {
	NSSCertificateArray_Destroy(certs);
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

