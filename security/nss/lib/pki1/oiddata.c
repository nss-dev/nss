/* THIS IS A GENERATED FILE */
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
#ifdef DEBUG
static const char CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$ ; @(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef PKI1T_H
#include "pki1t.h"
#endif /* PKI1T_H */

/* grr -- not defined in stan header yet */
#ifndef CKM_INVALID_MECHANISM
#define CKM_INVALID_MECHANISM 0xffffffff
#endif

const NSSOID nss_builtin_oids[] = {
  {
#ifdef DEBUG
    "ccitt",
    "ITU-T",
#endif /* DEBUG */
    { "\x80\x00", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "recommendation",
    "ITU-T Recommendation",
#endif /* DEBUG */
    { "\x00", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "question",
    "ITU-T Question",
#endif /* DEBUG */
    { "\x01", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "administration",
    "ITU-T Administration",
#endif /* DEBUG */
    { "\x02", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "network-operator",
    "ITU-T Network Operator",
#endif /* DEBUG */
    { "\x03", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "identified-organization",
    "ITU-T Identified Organization",
#endif /* DEBUG */
    { "\x04", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "data",
    "RFC Data",
#endif /* DEBUG */
    { "\x09", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pss",
    "PSS British Telecom X.25 Network",
#endif /* DEBUG */
    { "\x09\x92\x26", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ucl",
    "RFC 1274 UCL Data networks",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pilot",
    "RFC 1274 pilot",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "attributeType",
    "RFC 1274 Attribute Type",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "uid",
    "RFC 1274 User Id",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "mail",
    "RFC 1274 E-mail Addres",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x03", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "dc",
    "RFC 2247 Domain Component",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x01\x19", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "attributeSyntax",
    "RFC 1274 Attribute Syntax",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "iA5StringSyntax",
    "RFC 1274 IA5 String Attribute Syntax",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x03\x04", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "caseIgnoreIA5StringSyntax",
    "RFC 1274 Case-Ignore IA5 String Attribute Syntax",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x03\x05", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "objectClass",
    "RFC 1274 Object Class",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "groups",
    "RFC 1274 Groups",
#endif /* DEBUG */
    { "\x09\x92\x26\x89\x93\xf2\x2c\x64\x0a", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ucl",
    "RFC 1327 ucl",
#endif /* DEBUG */
    { "\x09\x92\x26\x86\xe8\xc4\xb5\xbe\x2c", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "iso",
    "ISO",
#endif /* DEBUG */
    { "\x80\x01", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "standard",
    "ISO Standard",
#endif /* DEBUG */
    { "\x28", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "registration-authority",
    "ISO Registration Authority",
#endif /* DEBUG */
    { "\x29", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "member-body",
    "ISO Member Body",
#endif /* DEBUG */
    { "\x2a", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "australia",
    "Australia (ISO)",
#endif /* DEBUG */
    { "\x2a\x24", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "taiwan",
    "Taiwan (ISO)",
#endif /* DEBUG */
    { "\x2a\x81\x1e", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ireland",
    "Ireland (ISO)",
#endif /* DEBUG */
    { "\x2a\x82\x74", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "norway",
    "Norway (ISO)",
#endif /* DEBUG */
    { "\x2a\x84\x42", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "sweden",
    "Sweden (ISO)",
#endif /* DEBUG */
    { "\x2a\x85\x70", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "great-britain",
    "Great Britain (ISO)",
#endif /* DEBUG */
    { "\x2a\x86\x3a", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us",
    "United States (ISO)",
#endif /* DEBUG */
    { "\x2a\x86\x48", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "organization",
    "US (ISO) organization",
#endif /* DEBUG */
    { "\x2a\x86\x48\x01", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ansi-z30-50",
    "ANSI Z39.50",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x13", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "dicom",
    "DICOM",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x18", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ieee-1224",
    "IEEE 1224",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x21", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ieee-802-10",
    "IEEE 802.10",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x26", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ieee-802-11",
    "IEEE 802.11",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x34", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x9-57",
    "ANSI X9.57",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "holdInstruction",
    "ANSI X9.57 Hold Instruction",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38\x02", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-holdinstruction-none",
    "ANSI X9.57 Hold Instruction: None",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38\x02\x01", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-holdinstruction-callissuer",
    "ANSI X9.57 Hold Instruction: Call Issuer",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38\x02\x02", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-holdinstruction-reject",
    "ANSI X9.57 Hold Instruction: Reject",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38\x02\x03", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x9algorithm",
    "ANSI X9.57 Algorithm",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38\x04", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-dsa",
    "ANSI X9.57 DSA Signature",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38\x04\x01", 7 },
    CKK_DSA,
    CKM_DSA,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-dsa-with-sha1",
    "ANSI X9.57 Algorithm DSA Signature with SHA-1 Digest",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x38\x04\x03", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_DSA_SHA1,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x942",
    "ANSI X9.42",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x3e", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "algorithm",
    "ANSI X9.42 Algorithm",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x3e\x02", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "dhpublicnumber",
    "Diffie-Hellman Public Key Algorithm",
#endif /* DEBUG */
    { "\x2a\x86\x48\xce\x3e\x02\x01", 7 },
    CKK_DH,
    CKM_DH_PKCS_DERIVE,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "entrust",
    "Entrust Technologies",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf6\x7d", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rsadsi",
    "RSA Data Security Inc.",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs",
    "PKCS",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-1",
    "PKCS #1",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rsaEncryption",
    "PKCS #1 RSA Encryption",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", 9 },
    CKK_RSA,
    CKM_RSA_PKCS,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "md2WithRSAEncryption",
    "PKCS #1 MD2 With RSA Encryption",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_MD2_RSA_PKCS,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "md4WithRSAEncryption",
    "PKCS #1 MD4 With RSA Encryption",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "md5WithRSAEncryption",
    "PKCS #1 MD5 With RSA Encryption",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_MD5_RSA_PKCS,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "sha1WithRSAEncryption",
    "PKCS #1 SHA-1 With RSA Encryption",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_SHA1_RSA_PKCS,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-5",
    "PKCS #5",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x05", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithMD2AndDES-CBC",
    "PKCS #5 Password Based Encryption With MD2 and DES-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_PBE_MD2_DES_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithMD5AndDES-CBC",
    "PKCS #5 Password Based Encryption With MD5 and DES-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_PBE_MD5_DES_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSha1AndDES-CBC",
    "PKCS #5 Password Based Encryption With SHA-1 and DES-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0a", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_DES_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-7",
    "PKCS #7",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x07", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "data",
    "PKCS #7 Data",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "signedData",
    "PKCS #7 Signed Data",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "envelopedData",
    "PKCS #7 Enveloped Data",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "signedAndEnvelopedData",
    "PKCS #7 Signed and Enveloped Data",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "digestedData",
    "PKCS #7 Digested Data",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x05", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "encryptedData",
    "PKCS #7 Encrypted Data",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x06", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-9",
    "PKCS #9",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "emailAddress",
    "PKCS #9 Email Address",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "unstructuredName",
    "PKCS #9 Unstructured Name",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "contentType",
    "PKCS #9 Content Type",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "messageDigest",
    "PKCS #9 Message Digest",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "signingTime",
    "PKCS #9 Signing Time",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "counterSignature",
    "PKCS #9 Counter Signature",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x06", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "challengePassword",
    "PKCS #9 Challenge Password",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x07", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "unstructuredAddress",
    "PKCS #9 Unstructured Address",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x08", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "extendedCertificateAttributes",
    "PKCS #9 Extended Certificate Attributes",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x09", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "sMIMECapabilities",
    "PKCS #9 S/MIME Capabilities",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0f", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "friendlyName",
    "PKCS #9 Friendly Name",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x14", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "localKeyID",
    "PKCS #9 Local Key ID",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x15", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "certTypes",
    "PKCS #9 Certificate Types",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x16", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x509Certificate",
    "PKCS #9 Certificate Type = X.509",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x16\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "sdsiCertificate",
    "PKCS #9 Certificate Type = SDSI",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x16\x02", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "crlTypes",
    "PKCS #9 Certificate Revocation List Types",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x17", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x509Crl",
    "PKCS #9 CRL Type = X.509",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x17\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12",
    "PKCS #12",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12PbeIds",
    "PKCS #12 Password Based Encryption IDs",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSHA1And128BitRC4",
    "PKCS #12 Password Based Encryption With SHA-1 and 128-bit RC4",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSHA1And40BitRC4",
    "PKCS #12 Password Based Encryption With SHA-1 and 40-bit RC4",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x02", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSHA1And3-KeyTripleDES-CBC",
    "PKCS #12 Password Based Encryption With SHA-1 and 3-key Triple DES-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x03", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSHA1And2-KeyTripleDES-CBC",
    "PKCS #12 Password Based Encryption With SHA-1 and 2-key Triple DES-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x04", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_PBE_SHA1_DES2_EDE_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSHA1And128BitRC2-CBC",
    "PKCS #12 Password Based Encryption With SHA-1 and 128-bit RC2-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x05", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSHA1And40BitRC2-CBC",
    "PKCS #12 Password Based Encryption With SHA-1 and 40-bit RC2-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x06", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12EspvkIds",
    "PKCS #12 ESPVK IDs",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs8-key-shrouding",
    "PKCS #12 Key Shrouding",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x02\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "draft1Pkcs-12Bag-ids",
    "Draft 1.0 PKCS #12 Bag IDs",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "keyBag",
    "Draft 1.0 PKCS #12 Key Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x03\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "certAndCRLBagId",
    "Draft 1.0 PKCS #12 Cert and CRL Bag ID",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x03\x02", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "secretBagId",
    "Draft 1.0 PKCS #12 Secret Bag ID",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x03\x03", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "safeContentsId",
    "Draft 1.0 PKCS #12 Safe Contents Bag ID",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x03\x04", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-8ShroudedKeyBagId",
    "Draft 1.0 PKCS #12 PKCS #8-shrouded Key Bag ID",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x03\x05", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12CertBagIds",
    "PKCS #12 Certificate Bag IDs",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x509CertCRLBagId",
    "PKCS #12 X.509 Certificate and CRL Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x04\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "SDSICertBagID",
    "PKCS #12 SDSI Certificate Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x04\x02", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12Oids",
    "PKCS #12 OIDs (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12PbeIds",
    "PKCS #12 OIDs PBE IDs (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSha1And128BitRC4",
    "PKCS #12 OIDs PBE with SHA-1 and 128-bit RC4 (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x01\x01", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_128_BIT_RC4,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSha1And40BitRC4",
    "PKCS #12 OIDs PBE with SHA-1 and 40-bit RC4 (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x01\x02", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_40_BIT_RC4,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSha1AndTripleDES-CBC",
    "PKCS #12 OIDs PBE with SHA-1 and Triple DES-CBC (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x01\x03", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_TRIPLE_DES_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSha1And128BitRC2-CBC",
    "PKCS #12 OIDs PBE with SHA-1 and 128-bit RC2-CBC (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x01\x04", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_128_BIT_RC2_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pbeWithSha1And40BitRC2-CBC",
    "PKCS #12 OIDs PBE with SHA-1 and 40-bit RC2-CBC (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x01\x05", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_NETSCAPE_PBE_SHA1_40_BIT_RC2_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12EnvelopingIds",
    "PKCS #12 OIDs Enveloping IDs (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x02", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rsaEncryptionWith128BitRC4",
    "PKCS #12 OIDs Enveloping RSA Encryption with 128-bit RC4",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x02\x01", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rsaEncryptionWith40BitRC4",
    "PKCS #12 OIDs Enveloping RSA Encryption with 40-bit RC4",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x02\x02", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rsaEncryptionWithTripleDES",
    "PKCS #12 OIDs Enveloping RSA Encryption with Triple DES",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x02\x03", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12SignatureIds",
    "PKCS #12 OIDs Signature IDs (XXX)",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x03", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rsaSignatureWithSHA1Digest",
    "PKCS #12 OIDs RSA Signature with SHA-1 Digest",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x05\x03\x01", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12Version1",
    "PKCS #12 Version 1",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-12BagIds",
    "PKCS #12 Bag IDs",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "keyBag",
    "PKCS #12 Key Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01\x01", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkcs-8ShroudedKeyBag",
    "PKCS #12 PKCS #8-shrouded Key Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01\x02", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "certBag",
    "PKCS #12 Certificate Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01\x03", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "crlBag",
    "PKCS #12 CRL Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01\x04", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "secretBag",
    "PKCS #12 Secret Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01\x05", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "safeContentsBag",
    "PKCS #12 Safe Contents Bag",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01\x06", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "digest",
    "RSA digest algorithm",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x02", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "md2",
    "MD2",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x02\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_MD2,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "md4",
    "MD4",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x02\x04", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "md5",
    "MD5",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x02\x05", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_MD5,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "cipher",
    "RSA cipher algorithm",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x03", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rc2cbc",
    "RC2-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x03\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rc4",
    "RC4",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x03\x04", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_RC4,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "desede3cbc",
    "DES-EDE3-CBC",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x03\x07", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_DES3_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rc5cbcpad",
    "RC5-CBCPad",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x0d\x03\x09", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_RC5_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "microsoft",
    "Microsoft",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x14", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "columbia-university",
    "Columbia University",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x18", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "unisys",
    "Unisys",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x24", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "xapia",
    "XAPIA",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf7\x7a", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "wordperfect",
    "WordPerfect",
#endif /* DEBUG */
    { "\x2a\x86\x48\x86\xf8\x23", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "identified-organization",
    "ISO identified organizations",
#endif /* DEBUG */
    { "\x2b", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us-dod",
    "United States Department of Defense",
#endif /* DEBUG */
    { "\x2b\x06", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "internet",
    "The Internet",
#endif /* DEBUG */
    { "\x2b\x06\x01", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "directory",
    "Internet: Directory",
#endif /* DEBUG */
    { "\x2b\x06\x01\x01", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "management",
    "Internet: Management",
#endif /* DEBUG */
    { "\x2b\x06\x01\x02", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "experimental",
    "Internet: Experimental",
#endif /* DEBUG */
    { "\x2b\x06\x01\x03", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "private",
    "Internet: Private",
#endif /* DEBUG */
    { "\x2b\x06\x01\x04", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "security",
    "Internet: Security",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "",
    "",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-pkix",
    "Public Key Infrastructure",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "PKIX1Explicit88",
    "RFC 2459 Explicitly Tagged Module, 1988 Syntax",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x00\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "PKIXImplicit88",
    "RFC 2459 Implicitly Tagged Module, 1988 Syntax",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x00\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "PKIXExplicit93",
    "RFC 2459 Explicitly Tagged Module, 1993 Syntax",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x00\x03", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-pe",
    "PKIX Private Certificate Extensions",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x01", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-pe-authorityInfoAccess",
    "Certificate Authority Information Access",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x01\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-qt",
    "PKIX Policy Qualifier Types",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x02", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-qt-cps",
    "PKIX CPS Pointer Qualifier",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x02\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-qt-unotice",
    "PKIX User Notice Qualifier",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x02\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp",
    "PKIX Key Purpose",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-serverAuth",
    "TLS Web Server Authentication Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-clientAuth",
    "TLS Web Client Authentication Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-codeSigning",
    "Code Signing Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x03", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-emailProtection",
    "E-Mail Protection Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x04", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-ipsecEndSystem",
    "IPSEC End System Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x05", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-ipsecTunnel",
    "IPSEC Tunnel Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x06", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-ipsecUser",
    "IPSEC User Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x07", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-kp-timeStamping",
    "Time Stamping Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x08", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ocsp-responder",
    "OCSP Responder Certificate",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x03\x09", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkix-id-pkix",
    "",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkix-id-pkip",
    "",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkix-id-regctrl",
    "CRMF Registration Control",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "regtoken",
    "CRMF Registration Control, Registration Token",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x01\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "authenticator",
    "CRMF Registration Control, Registration Authenticator",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x01\x02", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkipubinfo",
    "CRMF Registration Control, PKI Publication Info",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x01\x03", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pki-arch-options",
    "CRMF Registration Control, PKI Archive Options",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x01\x04", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "old-cert-id",
    "CRMF Registration Control, Old Certificate ID",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x01\x05", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "protocol-encryption-key",
    "CRMF Registration Control, Protocol Encryption Key",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x01\x06", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "pkix-id-reginfo",
    "CRMF Registration Info",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "utf8-pairs",
    "CRMF Registration Info, UTF8 Pairs",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x02\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "cert-request",
    "CRMF Registration Info, Certificate Request",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x07\x05\x02\x02", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ad",
    "PKIX Access Descriptors",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ad-ocsp",
    "PKIX Online Certificate Status Protocol",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "basic-response",
    "OCSP Basic Response",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "nonce-extension",
    "OCSP Nonce Extension",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "response",
    "OCSP Response Types Extension",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "crl",
    "OCSP CRL Reference Extension",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "no-check",
    "OCSP No Check Extension",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01\x05", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "archive-cutoff",
    "OCSP Archive Cutoff Extension",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01\x06", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "service-locator",
    "OCSP Service Locator Extension",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x01\x07", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ad-caIssuers",
    "Certificate Authority Issuers",
#endif /* DEBUG */
    { "\x2b\x06\x01\x05\x05\x07\x30\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "snmpv2",
    "Internet: SNMPv2",
#endif /* DEBUG */
    { "\x2b\x06\x01\x06", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "mail",
    "Internet: mail",
#endif /* DEBUG */
    { "\x2b\x06\x01\x07", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "mime-mhs",
    "Internet: mail MIME mhs",
#endif /* DEBUG */
    { "\x2b\x06\x01\x07\x01", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ecma",
    "European Computers Manufacturing Association",
#endif /* DEBUG */
    { "\x2b\x0c", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "oiw",
    "Open Systems Implementors Workshop",
#endif /* DEBUG */
    { "\x2b\x0e", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "secsig",
    "Open Systems Implementors Workshop Security Special Interest Group",
#endif /* DEBUG */
    { "\x2b\x0e\x03", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "oIWSECSIGAlgorithmObjectIdentifiers",
    "OIW SECSIG Algorithm OIDs",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x01", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "algorithm",
    "OIW SECSIG Algorithm",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "desecb",
    "DES-ECB",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x06", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_DES_ECB,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "descbc",
    "DES-CBC",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x07", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_DES_CBC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "desofb",
    "DES-OFB",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x08", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "descfb",
    "DES-CFB",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x09", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "desmac",
    "DES-MAC",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x0a", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_DES_MAC,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "isoSHAWithRSASignature",
    "ISO SHA with RSA Signature",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x0f", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "desede",
    "DES-EDE",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x11", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "sha1",
    "SHA-1",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x1a", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_SHA_1,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "bogusDSASignatureWithSHA1Digest",
    "Forgezza DSA Signature with SHA-1 Digest",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x02\x1b", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_DSA_SHA1,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "authentication-mechanism",
    "OIW SECSIG Authentication Mechanisms",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x03", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "security-attribute",
    "OIW SECSIG Security Attributes",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x04", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "document-definition",
    "OIW SECSIG Document Definitions used in security",
#endif /* DEBUG */
    { "\x2b\x0e\x03\x05", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "directory-services-sig",
    "OIW directory services sig",
#endif /* DEBUG */
    { "\x2b\x0e\x07", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ewos",
    "European Workshop on Open Systems",
#endif /* DEBUG */
    { "\x2b\x10", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "osf",
    "Open Software Foundation",
#endif /* DEBUG */
    { "\x2b\x16", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "nordunet",
    "Nordunet",
#endif /* DEBUG */
    { "\x2b\x17", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "nato-id-org",
    "NATO identified organisation",
#endif /* DEBUG */
    { "\x2b\x1a", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "teletrust",
    "Teletrust",
#endif /* DEBUG */
    { "\x2b\x24", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "smpte",
    "Society of Motion Picture and Television Engineers",
#endif /* DEBUG */
    { "\x2b\x34", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "sita",
    "Societe Internationale de Telecommunications Aeronautiques",
#endif /* DEBUG */
    { "\x2b\x45", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "iana",
    "Internet Assigned Numbers Authority",
#endif /* DEBUG */
    { "\x2b\x5a", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "thawte",
    "Thawte",
#endif /* DEBUG */
    { "\x2b\x65", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "joint-iso-ccitt",
    "Joint ISO/ITU-T assignment",
#endif /* DEBUG */
    { "\x80\x02", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "presentation",
    "Joint ISO/ITU-T Presentation",
#endif /* DEBUG */
    { "\x50", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "asn-1",
    "Abstract Syntax Notation One",
#endif /* DEBUG */
    { "\x51", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "acse",
    "Association Control",
#endif /* DEBUG */
    { "\x52", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rtse",
    "Reliable Transfer",
#endif /* DEBUG */
    { "\x53", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rose",
    "Remote Operations",
#endif /* DEBUG */
    { "\x54", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x500",
    "Directory",
#endif /* DEBUG */
    { "\x55", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "modules",
    "X.500 modules",
#endif /* DEBUG */
    { "\x55\x01", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "service-environment",
    "X.500 service environment",
#endif /* DEBUG */
    { "\x55\x02", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "application-context",
    "X.500 application context",
#endif /* DEBUG */
    { "\x55\x03", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at",
    "X.520 attribute types",
#endif /* DEBUG */
    { "\x55\x04", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-commonName",
    "X.520 Common Name",
#endif /* DEBUG */
    { "\x55\x04\x03", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-surname",
    "X.520 Surname",
#endif /* DEBUG */
    { "\x55\x04\x04", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-countryName",
    "X.520 Country Name",
#endif /* DEBUG */
    { "\x55\x04\x06", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-localityName",
    "X.520 Locality Name",
#endif /* DEBUG */
    { "\x55\x04\x07", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-stateOrProvinceName",
    "X.520 State or Province Name",
#endif /* DEBUG */
    { "\x55\x04\x08", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-organizationName",
    "X.520 Organization Name",
#endif /* DEBUG */
    { "\x55\x04\x0a", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-organizationalUnitName",
    "X.520 Organizational Unit Name",
#endif /* DEBUG */
    { "\x55\x04\x0b", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-title",
    "X.520 Title",
#endif /* DEBUG */
    { "\x55\x04\x0c", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-name",
    "X.520 Name",
#endif /* DEBUG */
    { "\x55\x04\x29", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-givenName",
    "X.520 Given Name",
#endif /* DEBUG */
    { "\x55\x04\x2a", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-initials",
    "X.520 Initials",
#endif /* DEBUG */
    { "\x55\x04\x2b", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-generationQualifier",
    "X.520 Generation Qualifier",
#endif /* DEBUG */
    { "\x55\x04\x2c", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-at-dnQualifier",
    "X.520 DN Qualifier",
#endif /* DEBUG */
    { "\x55\x04\x2e", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "attribute-syntax",
    "X.500 attribute syntaxes",
#endif /* DEBUG */
    { "\x55\x05", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "object-classes",
    "X.500 standard object classes",
#endif /* DEBUG */
    { "\x55\x06", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "attribute-set",
    "X.500 attribute sets",
#endif /* DEBUG */
    { "\x55\x07", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "algorithms",
    "X.500-defined algorithms",
#endif /* DEBUG */
    { "\x55\x08", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "encryption",
    "X.500-defined encryption algorithms",
#endif /* DEBUG */
    { "\x55\x08\x01", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rsa",
    "RSA Encryption Algorithm",
#endif /* DEBUG */
    { "\x55\x08\x01\x01", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_RSA_X_509,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "abstract-syntax",
    "X.500 abstract syntaxes",
#endif /* DEBUG */
    { "\x55\x09", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "operational-attribute",
    "DSA Operational Attributes",
#endif /* DEBUG */
    { "\x55\x0c", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "matching-rule",
    "Matching Rule",
#endif /* DEBUG */
    { "\x55\x0d", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "knowledge-matching-rule",
    "X.500 knowledge Matching Rules",
#endif /* DEBUG */
    { "\x55\x0e", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "name-form",
    "X.500 name forms",
#endif /* DEBUG */
    { "\x55\x0f", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "group",
    "X.500 groups",
#endif /* DEBUG */
    { "\x55\x10", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "subentry",
    "X.500 subentry",
#endif /* DEBUG */
    { "\x55\x11", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "operational-attribute-type",
    "X.500 operational attribute type",
#endif /* DEBUG */
    { "\x55\x12", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "operational-binding",
    "X.500 operational binding",
#endif /* DEBUG */
    { "\x55\x13", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "schema-object-class",
    "X.500 schema Object class",
#endif /* DEBUG */
    { "\x55\x14", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "schema-operational-attribute",
    "X.500 schema operational attributes",
#endif /* DEBUG */
    { "\x55\x15", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "administrative-role",
    "X.500 administrative roles",
#endif /* DEBUG */
    { "\x55\x17", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "access-control-attribute",
    "X.500 access control attribute",
#endif /* DEBUG */
    { "\x55\x18", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ros",
    "X.500 ros object",
#endif /* DEBUG */
    { "\x55\x19", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "contract",
    "X.500 contract",
#endif /* DEBUG */
    { "\x55\x1a", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "package",
    "X.500 package",
#endif /* DEBUG */
    { "\x55\x1b", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "access-control-schema",
    "X.500 access control schema",
#endif /* DEBUG */
    { "\x55\x1c", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce",
    "X.500 Certificate Extension",
#endif /* DEBUG */
    { "\x55\x1d", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "subject-directory-attributes",
    "Certificate Subject Directory Attributes",
#endif /* DEBUG */
    { "\x55\x1d\x05", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-subjectDirectoryAttributes",
    "Certificate Subject Directory Attributes",
#endif /* DEBUG */
    { "\x55\x1d\x09", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-subjectKeyIdentifier",
    "Certificate Subject Key ID",
#endif /* DEBUG */
    { "\x55\x1d\x0e", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-keyUsage",
    "Certificate Key Usage",
#endif /* DEBUG */
    { "\x55\x1d\x0f", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-privateKeyUsagePeriod",
    "Certificate Private Key Usage Period",
#endif /* DEBUG */
    { "\x55\x1d\x10", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-subjectAltName",
    "Certificate Subject Alternate Name",
#endif /* DEBUG */
    { "\x55\x1d\x11", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-issuerAltName",
    "Certificate Issuer Alternate Name",
#endif /* DEBUG */
    { "\x55\x1d\x12", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-basicConstraints",
    "Certificate Basic Constraints",
#endif /* DEBUG */
    { "\x55\x1d\x13", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-cRLNumber",
    "CRL Number",
#endif /* DEBUG */
    { "\x55\x1d\x14", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-cRLReasons",
    "CRL Reason Code",
#endif /* DEBUG */
    { "\x55\x1d\x15", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-holdInstructionCode",
    "Hold Instruction Code",
#endif /* DEBUG */
    { "\x55\x1d\x17", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-invalidityDate",
    "Invalid Date",
#endif /* DEBUG */
    { "\x55\x1d\x18", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-deltaCRLIndicator",
    "Delta CRL Indicator",
#endif /* DEBUG */
    { "\x55\x1d\x1b", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-issuingDistributionPoint",
    "Issuing Distribution Point",
#endif /* DEBUG */
    { "\x55\x1d\x1c", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-certificateIssuer",
    "Certificate Issuer",
#endif /* DEBUG */
    { "\x55\x1d\x1d", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-nameConstraints",
    "Certificate Name Constraints",
#endif /* DEBUG */
    { "\x55\x1d\x1e", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-cRLDistributionPoints",
    "CRL Distribution Points",
#endif /* DEBUG */
    { "\x55\x1d\x1f", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-certificatePolicies",
    "Certificate Policies",
#endif /* DEBUG */
    { "\x55\x1d\x20", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-policyMappings",
    "Certificate Policy Mappings",
#endif /* DEBUG */
    { "\x55\x1d\x21", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "policy-constraints",
    "Certificate Policy Constraints (old)",
#endif /* DEBUG */
    { "\x55\x1d\x22", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-ce-authorityKeyIdentifier",
    "Certificate Authority Key Identifier",
#endif /* DEBUG */
    { "\x55\x1d\x23", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-policyConstraints",
    "Certificate Policy Constraints",
#endif /* DEBUG */
    { "\x55\x1d\x24", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-ce-extKeyUsage",
    "Extended Key Usage",
#endif /* DEBUG */
    { "\x55\x1d\x25", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "id-mgt",
    "X.500 Management Object",
#endif /* DEBUG */
    { "\x55\x1e", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "x400",
    "X.400 MHS",
#endif /* DEBUG */
    { "\x56", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ccr",
    "Committment, Concurrency and Recovery",
#endif /* DEBUG */
    { "\x57", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "oda",
    "Office Document Architecture",
#endif /* DEBUG */
    { "\x58", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "osi-management",
    "OSI management",
#endif /* DEBUG */
    { "\x59", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "tp",
    "Transaction Processing",
#endif /* DEBUG */
    { "\x5a", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "dor",
    "Distinguished Object Reference",
#endif /* DEBUG */
    { "\x5b", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "rdt",
    "Referenced Data Transfer",
#endif /* DEBUG */
    { "\x5c", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "nlm",
    "Network Layer Management",
#endif /* DEBUG */
    { "\x5d", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "tlm",
    "Transport Layer Management",
#endif /* DEBUG */
    { "\x5e", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "llm",
    "Link Layer Management",
#endif /* DEBUG */
    { "\x5f", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "country",
    "Country Assignments",
#endif /* DEBUG */
    { "\x60", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "canada",
    "Canada",
#endif /* DEBUG */
    { "\x60\x7c", 2 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "taiwan",
    "Taiwan",
#endif /* DEBUG */
    { "\x60\x81\x1e", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "norway",
    "Norway",
#endif /* DEBUG */
    { "\x60\x84\x42", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "switzerland",
    "Switzerland",
#endif /* DEBUG */
    { "\x60\x85\x74", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us",
    "United States",
#endif /* DEBUG */
    { "\x60\x86\x48", 3 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us-company",
    "United States Company",
#endif /* DEBUG */
    { "\x60\x86\x48\x01", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us-government",
    "United States Government (1.101)",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us-dod",
    "United States Department of Defense",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-infosec",
    "US DOD Infosec",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-modules",
    "US DOD Infosec modules",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x00", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-algorithms",
    "US DOD Infosec algorithms (MISSI)",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "old-dss",
    "MISSI DSS Algorithm (Old)",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "skipjack-cbc-64",
    "Skipjack CBC64",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_SKIPJACK_CBC64,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "kea",
    "MISSI KEA Algorithm",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01\x0a", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "old-kea-dss",
    "MISSI KEA and DSS Algorithm (Old)",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01\x0c", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "dss",
    "MISSI DSS Algorithm",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01\x13", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "kea-dss",
    "MISSI KEA and DSS Algorithm",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01\x14", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "alt-kea",
    "MISSI Alternate KEA Algorithm",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x01\x16", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-formats",
    "US DOD Infosec formats",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-policy",
    "US DOD Infosec policy",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x03", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-object-classes",
    "US DOD Infosec object classes",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x04", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-attributes",
    "US DOD Infosec attributes",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x05", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "id-attribute-syntax",
    "US DOD Infosec attribute syntax",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x65\x02\x01\x06", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "netscape",
    "Netscape Communications Corp.",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "cert-ext",
    "Netscape Cert Extensions",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "cert-type",
    "Certificate Type",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "base-url",
    "Certificate Extension Base URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "revocation-url",
    "Certificate Revocation URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "ca-revocation-url",
    "Certificate Authority Revocation URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "ca-crl-download-url",
    "Certificate Authority CRL Download URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x05", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ca-cert-url",
    "Certificate Authority Certificate Download URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x06", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "renewal-url",
    "Certificate Renewal URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x07", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "ca-policy-url",
    "Certificate Authority Policy URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x08", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "homepage-url",
    "Certificate Homepage URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x09", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "entity-logo",
    "Certificate Entity Logo",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x0a", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "user-picture",
    "Certificate User Picture",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x0b", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ssl-server-name",
    "Certificate SSL Server Name",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x0c", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "comment",
    "Certificate Comment",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x0d", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "thayes",
    "",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x01\x0e", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_TRUE
  },
  {
#ifdef DEBUG
    "data-type",
    "Netscape Data Types",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x02", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "gif",
    "image/gif",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x02\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "jpeg",
    "image/jpeg",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x02\x02", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "url",
    "URL",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x02\x03", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "html",
    "text/html",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x02\x04", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "cert-sequence",
    "Certificate Sequence",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x02\x05", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "directory",
    "Netscape Directory",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x03", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "policy",
    "Netscape Policy Type OIDs",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x04", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "export-approved",
    "Strong Crypto Export Approved",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x04\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "cert-server",
    "Netscape Certificate Server",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x05", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "",
    "",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x05\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "recovery-request",
    "Netscape Cert Server Recovery Request",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x05\x01\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "algs",
    "Netscape algorithm OIDs",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x06", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "smime-kea",
    "Netscape S/MIME KEA",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x06\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "name-components",
    "Netscape Name Components",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x07", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "nickname",
    "Netscape Nickname",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x42\x07\x01", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "verisign",
    "Verisign",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x45", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "",
    "",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x45\x01", 8 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "",
    "",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x45\x01\x07", 9 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "",
    "",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x45\x01\x07\x01", 10 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "verisign-user-notices",
    "Verisign User Notices",
#endif /* DEBUG */
    { "\x60\x86\x48\x01\x86\xf8\x45\x01\x07\x01\x01", 11 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us-government",
    "US Government (101)",
#endif /* DEBUG */
    { "\x60\x86\x48\x65", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "us-government2",
    "US Government (102)",
#endif /* DEBUG */
    { "\x60\x86\x48\x66", 4 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "old-netscape",
    "Netscape Communications Corp. (Old)",
#endif /* DEBUG */
    { "\x60\x86\x48\xd8\x6a", 5 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ns-cert-ext",
    "Netscape Cert Extensions (Old NS)",
#endif /* DEBUG */
    { "\x60\x86\x48\xd8\x6a\x01", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "netscape-ok",
    "Netscape says this cert is ok (Old NS)",
#endif /* DEBUG */
    { "\x60\x86\x48\xd8\x6a\x01\x01", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "issuer-logo",
    "Certificate Issuer Logo (Old NS)",
#endif /* DEBUG */
    { "\x60\x86\x48\xd8\x6a\x01\x02", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "subject-logo",
    "Certificate Subject Logo (Old NS)",
#endif /* DEBUG */
    { "\x60\x86\x48\xd8\x6a\x01\x03", 7 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ns-file-type",
    "Netscape File Type",
#endif /* DEBUG */
    { "\x60\x86\x48\xd8\x6a\x02", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "ns-image-type",
    "Netscape Image Type",
#endif /* DEBUG */
    { "\x60\x86\x48\xd8\x6a\x03", 6 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "registration-procedures",
    "Registration procedures",
#endif /* DEBUG */
    { "\x61", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "physical-layer-management",
    "Physical layer Management",
#endif /* DEBUG */
    { "\x62", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "mheg",
    "MHEG",
#endif /* DEBUG */
    { "\x63", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "guls",
    "Generic Upper Layer Security",
#endif /* DEBUG */
    { "\x64", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "tls",
    "Transport Layer Security Protocol",
#endif /* DEBUG */
    { "\x65", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "nls",
    "Network Layer Security Protocol",
#endif /* DEBUG */
    { "\x66", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  },
  {
#ifdef DEBUG
    "organization",
    "International organizations",
#endif /* DEBUG */
    { "\x67", 1 },
    CKK_INVALID_KEY_TYPE,
    CKM_INVALID_MECHANISM,
    PR_FALSE
  }
};

const PRUint32 nss_builtin_oid_count = 379;


