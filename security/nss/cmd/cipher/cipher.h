
#include "cmdutil.h"
#include "nssdev.h"
#include "nsspki.h"
#include "nss.h"

#define CIPHER_VERSION_STRING "cipher version 0.1"

/*#define SOFTOKEN_NAME "NSS Generic Crypto Services"*/
#define SOFTOKEN_NAME "NSS Certificate DB"

NSSToken *
GetSoftwareToken();

PRStatus
Hash
(
  NSSCryptoContext *cc,
  char *cipher,
  CMDRunTimeData *rtData
);

PRStatus
Encrypt
(
  NSSCryptoContext *cc,
  char *cipher,
  char *key,
  char *iv,
  CMDRunTimeData *rtData
);

NSSSymmetricKey *
GenerateSymmetricKey
(
  NSSTrustDomain *td,
  /*NSSCryptoContext *cc,*/
  NSSToken *token,
  char *cipher,
  unsigned int length,
  char *name
);

PRStatus
GenerateKeyPair
(
  NSSTrustDomain *td,
  /*NSSCryptoContext *cc,*/
  NSSToken *token,
  char *cipher,
  char *name,
  NSSPrivateKey **privateKey,
  NSSPublicKey **publicKey
);

