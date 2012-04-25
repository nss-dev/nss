/*
 * Return SSLKEAType derived from cert's Public Key algorithm info.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* $Id$ */

#include "cert.h"
#include "ssl.h"	/* for SSLKEAType */
#include "secoid.h"

SSLKEAType
NSS_FindCertKEAType(CERTCertificate * cert)
{
  SSLKEAType keaType = kt_null; 
  int tag;
  
  if (!cert) goto loser;
  
  tag = SECOID_GetAlgorithmTag(&(cert->subjectPublicKeyInfo.algorithm));
  
  switch (tag) {
  case SEC_OID_X500_RSA_ENCRYPTION:
  case SEC_OID_PKCS1_RSA_ENCRYPTION:
    keaType = kt_rsa;
    break;
  case SEC_OID_X942_DIFFIE_HELMAN_KEY:
    keaType = kt_dh;
    break;
#ifdef NSS_ENABLE_ECC
  case SEC_OID_ANSIX962_EC_PUBLIC_KEY:
    keaType = kt_ecdh;
    break;
#endif /* NSS_ENABLE_ECC */
  default:
    keaType = kt_null;
  }
  
 loser:
  
  return keaType;

}

