
#include <string.h>
#include "nssbase.h"
#include "nssdev.h"
#include "nsspki.h"
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

static PRStatus
print_cert_callback(NSSCertificate *c, void *arg)
{
    CMDRunTimeData *rtData = (CMDRunTimeData *)arg;
    NSSUTF8 *nickname = nssCertificate_GetNickname(c, NULL);
#if 0
    PRBool isUserCert = NSSCertificate_IsPrivateKeyAvailable(c, NULL, NULL);
#else
    PRBool isUserCert = PR_FALSE;
#endif
    PR_fprintf(rtData->output.file, "Listing %c %s\n", 
                                    (isUserCert) ? '*' : ' ',
                                    nickname);
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
    NSSUTF8 *nickname = nssCertificate_GetNickname(c, NULL);
    if (rtData->output.mode == CMDFileMode_PrettyPrint) {
	print_decoded_cert(rtData, c);
    } else if (rtData->output.mode == CMDFileMode_Binary) {
	NSSDER *encoding = nssCertificate_GetEncoding(c);
	PR_Write(rtData->output.file, encoding->data, encoding->size);
    }
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
	                                                       NSSUsage_Any,
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

static PRStatus
dump_cert_chain
(
  NSSTrustDomain *td,
  NSSCertificate *c,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PRUint32 i, j;
    NSSCertificate **chain, **chainp;

    chain = NSSCertificate_BuildChain(c, NSSTime_Now(), NSSUsage_Any,
                                      NULL, /* policies   */
                                      NULL, /* certs[]    */
                                      0,    /* rvLimit    */
                                      NULL, /* arena      */
                                      &status);
    chainp = chain;
    i = 0;
    while (chainp && *chainp) {
	for (j=0; j<i; j++) PR_fprintf(rtData->output.file, " ");
	status = print_cert_callback(*chainp, rtData);
	i++;
	chainp++;
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
  PRBool info,
  PRBool chain,
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    NSSCertificate *c;

    switch (get_object_class(objectType)) {
    case PKICertificate:
    case PKIAny:         /* default to certificate */
	if (chain) {
	    c = NSSTrustDomain_FindBestCertificateByNickname(td, nickname, 
	                                                     NSSTime_Now(), 
	                                                     NSSUsage_Any,
	                                                     NULL);
	    status = dump_cert_chain(td, c, rtData);
	    NSSCertificate_Destroy(c);
	} else if (info) {
	    c = NSSTrustDomain_FindBestCertificateByNickname(td, nickname, 
	                                                     NSSTime_Now(), 
	                                                     NSSUsage_Any,
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

/* XXX make NSSItem methods public */
#if 0
static NSSItem *
read_input
(
  RunTimeData *rtData
)
{
    PRFileInfo info;
    PRInt32 numBytes;
    PRStatus status;
    NSSItem *dest = NULL;
    PRFileDesc *src = rtData->input.file;
    /* XXX handle base64 input */
#ifdef nodef
    if (src == PR_STDIN)
	return secu_StdinToItem(dst);
#endif
    status = PR_GetOpenFileInfo(src, &info);
    if (status != PR_SUCCESS) {
	goto loser;
    }
    dest = PR_NEWZAP(NSSItem);
    if (!dest) {
	goto loser;
    }
    numBytes = PR_Read(src, dest->data, info.size);
    if (numBytes != info.size) {
	goto loser;
    }
    return PR_SUCCESS;
loser:
    if (dest) {
	PR_Free(dest);
    }
    return PR_FAILURE;
}
#endif

static PRStatus
import_certificate
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
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
                                                   tokenOpt, nickname);
    if (cert) {
	PR_fprintf(PR_STDOUT, "Import successful.\n");
	dump_cert_info(td, cert, rtData);
	NSSCertificate_Destroy(cert);
    } else {
	PR_fprintf(PR_STDERR, "Import failed!\n");
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
  CMDRunTimeData *rtData
)
{
    PRStatus status;
    PKIObjectType objectKind;
    objectKind = get_object_class(objectTypeOpt);
    switch (objectKind) {
    case PKIAny: /* default to certificate */
    case PKICertificate:
	status = import_certificate(td, tokenOpt, nickname, rtData);
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

