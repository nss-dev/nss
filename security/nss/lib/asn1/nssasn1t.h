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

#ifndef NSSASN1T_H
#define NSSASN1T_H

#ifdef DEBUG
static const char NSSASN1T_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/* XXX */
#include "secasn1t.h"

/*
 * nssasn1t.h
 *
 * This file contains the public types related to our ASN.1 encoder 
 * and decoder.
 */

PR_BEGIN_EXTERN_C

/*
 * NSSASN1EncodingType
 *
 * This type enumerates specific types of ASN.1 encodings.
 */

typedef enum {
  NSSASN1BER,               /* Basic Encoding Rules */
  NSSASN1CER,               /* Canonical Encoding Rules */
  NSSASN1DER,               /* Distinguished Encoding Rules */
  NSSASN1LWER,              /* LightWeight Encoding Rules */
  NSSASN1PER,               /* Packed Encoding Rules */
  NSSASN1UnknownEncoding = -1
} NSSASN1EncodingType;

/* XXX more consideration here */

typedef SEC_ASN1Template NSSASN1Template;

#define NSSASN1_TAG_MASK               SEC_ASN1_TAG_MASK

#define NSSASN1_TAGNUM_MASK            SEC_ASN1_TAGNUM_MASK
#define NSSASN1_BOOLEAN                SEC_ASN1_BOOLEAN
#define NSSASN1_INTEGER                SEC_ASN1_INTEGER
#define NSSASN1_BIT_STRING             SEC_ASN1_BIT_STRING
#define NSSASN1_OCTET_STRING           SEC_ASN1_OCTET_STRING
#define NSSASN1_NULL                   SEC_ASN1_NULL
#define NSSASN1_OBJECT_ID              SEC_ASN1_OBJECT_ID
#define NSSASN1_OBJECT_DESCRIPTOR      SEC_ASN1_OBJECT_DESCRIPTOR
/* External type and instance-of type   0x08 */
#define NSSASN1_REAL                   SEC_ASN1_REAL
#define NSSASN1_ENUMERATED             SEC_ASN1_ENUMERATED
#define NSSASN1_EMBEDDED_PDV           SEC_ASN1_EMBEDDED_PDV
#define NSSASN1_UTF8_STRING            SEC_ASN1_UTF8_STRING
#define NSSASN1_SEQUENCE               SEC_ASN1_SEQUENCE
#define NSSASN1_SET                    SEC_ASN1_SET
#define NSSASN1_NUMERIC_STRING         SEC_ASN1_NUMERIC_STRING
#define NSSASN1_PRINTABLE_STRING       SEC_ASN1_PRINTABLE_STRING
#define NSSASN1_T61_STRING             SEC_ASN1_T61_STRING
#define NSSASN1_TELETEX_STRING         NSSASN1_T61_STRING
#define NSSASN1_VIDEOTEX_STRING        SEC_ASN1_VIDEOTEX_STRING
#define NSSASN1_IA5_STRING             SEC_ASN1_IA5_STRING
#define NSSASN1_UTC_TIME               SEC_ASN1_UTC_TIME
#define NSSASN1_GENERALIZED_TIME       SEC_ASN1_GENERALIZED_TIME
#define NSSASN1_GRAPHIC_STRING         SEC_ASN1_GRAPHIC_STRING
#define NSSASN1_VISIBLE_STRING         SEC_ASN1_VISIBLE_STRING
#define NSSASN1_GENERAL_STRING         SEC_ASN1_GENERAL_STRING
#define NSSASN1_UNIVERSAL_STRING       SEC_ASN1_UNIVERSAL_STRING
/*                                      0x1d */
#define NSSASN1_BMP_STRING             SEC_ASN1_BMP_STRING
#define NSSASN1_HIGH_TAG_NUMBER        SEC_ASN1_HIGH_TAG_NUMBER

#define NSSASN1_METHOD_MASK            SEC_ASN1_METHOD_MASK
#define NSSASN1_PRIMITIVE              SEC_ASN1_PRIMITIVE
#define NSSASN1_CONSTRUCTED            SEC_ASN1_CONSTRUCTED
                                                                
#define NSSASN1_CLASS_MASK             SEC_ASN1_CLASS_MASK
#define NSSASN1_UNIVERSAL              SEC_ASN1_UNIVERSAL
#define NSSASN1_APPLICATION            SEC_ASN1_APPLICATION
#define NSSASN1_CONTEXT_SPECIFIC       SEC_ASN1_CONTEXT_SPECIFIC
#define NSSASN1_PRIVATE                SEC_ASN1_PRIVATE

#define NSSASN1_OPTIONAL               SEC_ASN1_OPTIONAL 
#define NSSASN1_EXPLICIT               SEC_ASN1_EXPLICIT 
#define NSSASN1_ANY                    SEC_ASN1_ANY      
#define NSSASN1_INLINE                 SEC_ASN1_INLINE   
#define NSSASN1_POINTER                SEC_ASN1_POINTER  
#define NSSASN1_GROUP                  SEC_ASN1_GROUP    
#define NSSASN1_DYNAMIC                SEC_ASN1_DYNAMIC  
#define NSSASN1_SKIP                   SEC_ASN1_SKIP     
#define NSSASN1_INNER                  SEC_ASN1_INNER    
#define NSSASN1_SAVE                   SEC_ASN1_SAVE     
#define NSSASN1_MAY_STREAM             SEC_ASN1_MAY_STREAM
#define NSSASN1_SKIP_REST              SEC_ASN1_SKIP_REST
#define NSSASN1_CHOICE                 SEC_ASN1_CHOICE

#define NSSASN1_SEQUENCE_OF            SEC_ASN1_SEQUENCE_OF 
#define NSSASN1_SET_OF                 SEC_ASN1_SET_OF      
#define NSSASN1_ANY_CONTENTS           SEC_ASN1_ANY_CONTENTS

typedef SEC_ASN1TemplateChooserPtr NSSASN1ChooseTemplateFunction;

typedef SEC_ASN1DecoderContext NSSASN1Decoder;
typedef SEC_ASN1EncoderContext NSSASN1Encoder;

typedef enum {
  NSSASN1EncodingPartIdentifier    = SEC_ASN1_Identifier,
  NSSASN1EncodingPartLength        = SEC_ASN1_Length,
  NSSASN1EncodingPartContents      = SEC_ASN1_Contents,
  NSSASN1EncodingPartEndOfContents = SEC_ASN1_EndOfContents
} NSSASN1EncodingPart;

typedef SEC_ASN1NotifyProc NSSASN1NotifyFunction;

typedef SEC_ASN1WriteProc NSSASN1EncoderWriteFunction;
typedef SEC_ASN1WriteProc NSSASN1DecoderFilterFunction;

PR_END_EXTERN_C

#endif /* NSSASN1T_H */
