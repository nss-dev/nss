
#include "cmdutil.h"

#define PKIUTIL_VERSION_STRING "pkiutil version 0.1"

extern char *progName;

typedef enum 
{
    PKIUnknown = -1,
    PKICertificate,
    PKIPublicKey,
    PKIPrivateKey,
    PKIAny
} PKIObjectType;

PRStatus
AddObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname,
  CMDRunTimeData *rtData
);

/* XXX need to be more specific (serial number?) */
PRStatus
DeleteObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nickname
);

PRStatus
ListObjects
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectTypeOpt,
  char *nicknameOpt,
  PRUint32 maximumOpt,
  CMDRunTimeData *rtData
);

PRStatus
DumpObject
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  char *objectType,
  char *nickname,
  PRBool chain,
  CMDRunTimeData *rtData
);

PRStatus
DeleteOrphanedKeyPairs
(
  NSSTrustDomain *td,
  NSSToken *tokenOpt,
  CMDRunTimeData *rtData
);

