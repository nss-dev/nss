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

#ifndef NSSASN1_H
#define NSSASN1_H

#ifdef DEBUG
static const char NSSASN1_CVS_ID[] = "@(#) $RCSfile$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

/*
 * nssasn1.h
 *
 */

#ifndef NSSASN1T_H
#include "nssasn1t.h"
#endif /* NSSASN1T_H */

PR_BEGIN_EXTERN_C

/*
 * NSSASN1Decoder
 *
 * ... description here ...
 *
 *  NSSASN1Decoder_Create (Factory/Constructor)
 *  NSSASN1Decoder_Update
 *  NSSASN1Decoder_Finish (Destructor)
 *  NSSASN1Decoder_SetFilter
 *  NSSASN1Decoder_GetFilter
 *  NSSASN1Decoder_SetNotify
 *  NSSASN1Decoder_GetNotify
 *
 * Debug builds only:
 *
 *  NSSASN1Decoder_verify
 *
 * Related functions that aren't type methods:
 *
 *  NSSASN1_Decode
 *  NSSASN1_DecodeBER
 */

/*
 * NSSASN1Decoder_Create
 *
 * This routine creates an ASN.1 Decoder, which will use the specified
 * template to decode a datastream into the specified destination
 * structure.  If the optional arena argument is non-NULL, blah blah 
 * blah.  XXX fgmr Should we include an NSSASN1EncodingType argument, 
 * as a hint?  Or is each encoding distinctive?  This routine may 
 * return NULL upon error, in which case an error will have been 
 * placed upon the error stack.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_POINTER
 *  ...
 *
 * Return value:
 *  NULL upon error
 *  A pointer to an ASN.1 Decoder upon success.
 */

NSS_EXTERN NSSASN1Decoder *
NSSASN1Decoder_Create
(
  NSSArena *arenaOpt,
  void *destination,
  const NSSASN1Template template[]
);

extern const NSSError NSS_ERROR_NO_MEMORY;
extern const NSSError NSS_ERROR_INVALID_ARENA;
extern const NSSError NSS_ERROR_INVALID_POINTER;

/*
 * NSSASN1Decoder_Update
 *
 * This routine feeds data to the decoder.  In the event of an error, 
 * it will place an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_INVALID_ASN1DECODER
 *  NSS_ERROR_INVALID_BER
 *  ...
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success.
 */

NSS_EXTERN PRStatus
NSSASN1Decoder_Update
(
  NSSASN1Decoder *decoder,
  const void *data,
  PRUint32 amount
);

extern const NSSError NSS_ERROR_NO_MEMORY;
extern const NSSError NSS_ERROR_INVALID_ASN1DECODER;
extern const NSSError NSS_ERROR_INVALID_BER;

/*
 * NSSASN1Decoder_Finish
 *
 * This routine finishes the decoding and destroys the decoder.
 * In the event of an error, it will place an error on the error
 * stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1DECODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Decoder_Finish
(
  NSSASN1Decoder *decoder
);

extern const NSSError NSS_ERROR_INVALID_ASN1DECODER;

/*
 * NSSASN1Decoder_SetFilter
 *
 * This routine registers a callback filter routine with the decoder,
 * which will be called blah blah blah.  The specified argument will
 * be passed as-is to the filter routine.  The routine pointer may
 * be NULL, in which case no filter callback will be called.  If the
 * noStore boolean is PR_TRUE, then decoded fields will not be stored
 * in the destination structure specified when the decoder was 
 * created.  This routine returns a PRStatus value; in the event of
 * an error, it will place an error on the error stack and return
 * PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1DECODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Decoder_SetFilter
(
  NSSASN1Decoder *decoder,
  NSSASN1DecoderFilterFunction *callback,
  void *argument,
  PRBool noStore
);

extern const NSSError NSS_ERROR_INVALID_ASN1DECODER;

/*
 * NSSASN1Decoder_GetFilter
 *
 * If the optional pCallbackOpt argument to this routine is non-null,
 * then the pointer to any callback function established for this
 * decoder with NSSASN1Decoder_SetFilter will be stored at the 
 * location indicated by it.  If the optional pArgumentOpt
 * pointer is non-null, the filter's closure argument will be stored
 * there.  If the optional pNoStoreOpt pointer is non-null, the
 * noStore value specified when setting the filter will be stored
 * there.  This routine returns a PRStatus value; in the event of
 * an error it will place an error on the error stack and return
 * PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1DECODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Decoder_GetFilter
(
  NSSASN1Decoder *decoder,
  NSSASN1DecoderFilterFunction **pCallbackOpt,
  void **pArgumentOpt,
  PRBool *pNoStoreOpt
);

extern const NSSError NSS_ERROR_INVALID_ASN1DECODER;

/*
 * NSSASN1Decoder_SetNotify
 *
 * This routine registers a callback notify routine with the decoder,
 * which will be called whenever.. The specified argument will be
 * passed as-is to the notify routine.  The routine pointer may be
 * NULL, in which case no notify routine will be called.  This routine
 * returns a PRStatus value; in the event of an error it will place
 * an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1DECODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Decoder_SetNotify
(
  NSSASN1Decoder *decoder,
  NSSASN1NotifyFunction *callback,
  void *argument
);

extern const NSSError NSS_ERROR_INVALID_ASN1DECODER;

/*
 * NSSASN1Decoder_GetNotify
 *
 * If the optional pCallbackOpt argument to this routine is non-null,
 * then the pointer to any callback function established for this
 * decoder with NSSASN1Decoder_SetNotify will be stored at the 
 * location indicated by it.  If the optional pArgumentOpt pointer is
 * non-null, the filter's closure argument will be stored there.
 * This routine returns a PRStatus value; in the event of an error it
 * will place an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1DECODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Decoder_GetNotify
(
  NSSASN1Decoder *decoder,
  NSSASN1NotifyFunction **pCallbackOpt,
  void **pArgumentOpt
);

extern const NSSError NSS_ERROR_INVALID_ASN1DECODER;

/*
 * NSSASN1_Decode
 *
 * This routine will decode the specified data into the specified
 * destination structure, as specified by the specified template.
 * This routine returns a PRStatus value; in the event of an error
 * it will place an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_INVALID_BER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1_Decode
(
  NSSArena *arenaOpt,
  void *destination,
  const NSSASN1Template template[],
  const void *berData,
  PRUint32 amount
);

extern const NSSError NSS_ERROR_NO_MEMORY;
extern const NSSError NSS_ERROR_INVALID_ARENA;
extern const NSSError NSS_ERROR_INVALID_POINTER;
extern const NSSError NSS_ERROR_INVALID_BER;

/*
 * NSSASN1_DecodeBER
 *
 * This routine will decode the data in the specified NSSBER
 * into the destination structure, as specified by the template.
 * This routine returns a PRStatus value; in the event of an error
 * it will place an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_INVALID_NSSBER
 *  NSS_ERROR_INVALID_BER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1_DecodeBER
(
  NSSArena *arenaOpt,
  void *destination,
  const NSSASN1Template template[],
  const NSSBER *data
);

extern const NSSError NSS_ERROR_NO_MEMORY;
extern const NSSError NSS_ERROR_INVALID_ARENA;
extern const NSSError NSS_ERROR_INVALID_POINTER;
extern const NSSError NSS_ERROR_INVALID_BER;

/*
 * NSSASN1Encoder
 *
 * ... description here ...
 *
 *  NSSASN1Encoder_Create (Factory/Constructor)
 *  NSSASN1Encoder_Update
 *  NSSASN1Encoder_Finish (Destructor)
 *  NSSASN1Encoder_SetNotify
 *  NSSASN1Encoder_GetNotify
 *  NSSASN1Encoder_SetStreaming
 *  NSSASN1Encoder_GetStreaming
 *  NSSASN1Encoder_SetTakeFromBuffer
 *  NSSASN1Encoder_GetTakeFromBuffer
 *
 * Debug builds only:
 *
 *  NSSASN1Encoder_verify
 *
 * Related functions that aren't type methods:
 *
 *  NSSASN1_Encode
 *  NSSASN1_EncodeItem
 */

/*
 * NSSASN1Encoder_Create
 *
 * This routine creates an ASN.1 Encoder, blah blah blah.  This 
 * may return NULL upon error, in which case an error will have been
 * placed on the error stack.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_ENCODING_NOT_SUPPORTED
 *  ...
 *
 * Return value:
 *  NULL upon error
 *  A pointer to an ASN.1 Encoder upon success
 */

NSS_EXTERN NSSASN1Encoder *
NSSASN1Encoder_Create
(
  const void *source,
  const NSSASN1Template template[],
  NSSASN1EncodingType encoding,
  NSSASN1EncoderWriteFunction *sink,
  void *argument
);

extern const NSSError NSS_ERROR_NO_MEMORY;
extern const NSSError NSS_ERROR_INVALID_ARENA;
extern const NSSError NSS_ERROR_INVALID_POINTER;
extern const NSSError NSS_ERROR_ENCODING_NOT_SUPPORTED;

/*
 * NSSASN1Encoder_Update
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1ENCODER
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_Update
(
  NSSASN1Encoder *encoder,
  const void *data,
  PRUint32 length
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;
extern const NSSError NSS_ERROR_INVALID_POINTER;

/*
 * NSSASN1Encoder_Finish
 *
 * Destructor.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1ENCODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_Finish
(
  NSSASN1Encoder *encoder
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;

/*
 * NSSASN1Encoder_SetNotify
 *
 * This routine registers a callback notify routine with the encoder,
 * which will be called whenever.. The specified argument will be
 * passed as-is to the notify routine.  The routine pointer may be
 * NULL, in which case no notify routine will be called.  This routine
 * returns a PRStatus value; in the event of an error it will place
 * an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1DECODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_SetNotify
(
  NSSASN1Encoder *encoder,
  NSSASN1NotifyFunction *callback,
  void *argument
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;

/*
 * NSSASN1Encoder_GetNotify
 *
 * If the optional pCallbackOpt argument to this routine is non-null,
 * then the pointer to any callback function established for this
 * decoder with NSSASN1Encoder_SetNotify will be stored at the 
 * location indicated by it.  If the optional pArgumentOpt pointer is
 * non-null, the filter's closure argument will be stored there.
 * This routine returns a PRStatus value; in the event of an error it
 * will place an error on the error stack and return PR_FAILURE.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1ENCODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_GetNotify
(
  NSSASN1Encoder *encoder,
  NSSASN1NotifyFunction **pCallbackOpt,
  void **pArgumentOpt
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;

/*
 * NSSASN1Encoder_SetStreaming
 *
 * 
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1ENCODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_SetStreaming
(
  NSSASN1Encoder *encoder,
  PRBool streaming
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;

/*
 * NSSASN1Encoder_GetStreaming
 *
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1ENCODER
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_GetStreaming
(
  NSSASN1Encoder *encoder,
  PRBool *pStreaming
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;
extern const NSSError NSS_ERROR_INVALID_POINTER;

/*
 * NSSASN1Encoder_SetTakeFromBuffer
 *
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1ENCODER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_SetTakeFromBuffer
(
  NSSASN1Encoder *encoder,
  PRBool takeFromBuffer
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;

/*
 * NSSASN1Encoder_GetTakeFromBuffer
 *
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_ASN1ENCODER
 *  NSS_ERROR_INVALID_POINTER
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1Encoder_GetTakeFromBuffer
(
  NSSASN1Encoder *encoder,
  PRBool *pTakeFromBuffer
);

extern const NSSError NSS_ERROR_INVALID_ASN1ENCODER;
extern const NSSError NSS_ERROR_INVALID_POINTER;

/*
 * NSSASN1_Encode
 *
 * 
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_ENCODING_NOT_SUPPORTED
 *  ...
 *
 * Return value:
 *  PR_FAILURE upon error
 *  PR_SUCCESS upon success
 */

NSS_EXTERN PRStatus
NSSASN1_Encode
(
  const void *source,
  const NSSASN1Template template[],
  NSSASN1EncodingType encoding,
  NSSASN1EncoderWriteFunction *sink,
  void *argument
);

extern const NSSError NSS_ERROR_NO_MEMORY;
extern const NSSError NSS_ERROR_INVALID_ARENA;
extern const NSSError NSS_ERROR_INVALID_POINTER;
extern const NSSError NSS_ERROR_ENCODING_NOT_SUPPORTED;

/*
 * NSSASN1_EncodeItem
 *
 * There must be a better name.  If the optional arena argument is
 * non-null, it'll be used for the space.  If the optional rvOpt is
 * non-null, it'll be the return value-- if it is null, a new one
 * will be allocated.
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_POINTER
 *  NSS_ERROR_ENCODING_NOT_SUPPORTED
 *
 * Return value:
 *  NULL upon error
 *  A valid pointer to an NSSDER upon success
 */

NSS_EXTERN NSSDER *
NSSASN1_EncodeItem
(
  NSSArena *arenaOpt,
  NSSDER *rvOpt,
  const void *source,
  const NSSASN1Template template[],
  NSSASN1EncodingType encoding
);

extern const NSSError NSS_ERROR_NO_MEMORY;
extern const NSSError NSS_ERROR_INVALID_ARENA;
extern const NSSError NSS_ERROR_INVALID_POINTER;
extern const NSSError NSS_ERROR_ENCODING_NOT_SUPPORTED;

#if 0
/*
 * Other basic types' encoding and decoding helper functions:
 *
 *  NSSASN1_CreatePRUint32FromBER
 *  NSSASN1_GetDERFromPRUint32
 *  NSSASN1_CreatePRInt32FromBER
 *  NSSASN1_GetDERFromPRInt32
 * ..etc..
 */

/*
 * NSSASN1_CreatePRUint32FromBER
 *
 */

NSS_EXTERN PRStatus
NSSASN1_CreatePRUint32FromBER
(
  NSSBER *encoded,
  PRUint32 *pResult
);

/*
 * NSSASN1_GetDERFromPRUint32
 *
 */

NSS_EXTERN NSSDER *
NSSASN1_GetDERFromPRUint32
(
  NSSArena *arenaOpt,
  NSSDER *rvOpt,
  PRUint32 value
);

/*
 * NSSASN1_CreatePRInt32FromBER
 *
 */

NSS_EXTERN PRStatus
NSSASN1_CreatePRInt32FromBER
(
  NSSBER *encoded,
  PRInt32 *pResult
);

/*
 * NSSASN1_GetDERFromPRInt32
 *
 */

NSS_EXTERN NSSDER *
NSSASN1_GetDERFromPRInt32
(
  NSSArena *arenaOpt,
  NSSDER *rvOpt,
  PRInt32 value
);
#endif

/*
 * Builtin templates
 */

/*
 * Generic Templates
 * One for each of the simple types, plus a special one for ANY, plus:
 *	- a pointer to each one of those
 *	- a set of each one of those
 *
 * Note that these are alphabetical (case insensitive); please add new
 * ones in the appropriate place.
 */

/* XXX idm - some of these will be exported, but... */
#if 0
extern const NSSASN1Template *NSSASN1Template_Any;
extern const NSSASN1Template *NSSASN1Template_BitString;
extern const NSSASN1Template *NSSASN1Template_BMPString;
extern const NSSASN1Template *NSSASN1Template_Boolean;
extern const NSSASN1Template *NSSASN1Template_Enumerated;
extern const NSSASN1Template *NSSASN1Template_GeneralizedTime;
extern const NSSASN1Template *NSSASN1Template_IA5String;
extern const NSSASN1Template NSSASN1Template_Integer[];
extern const NSSASN1Template *NSSASN1Template_Null;
extern const NSSASN1Template *NSSASN1Template_ObjectID;
extern const NSSASN1Template *NSSASN1Template_OctetString;
extern const NSSASN1Template *NSSASN1Template_PrintableString;
extern const NSSASN1Template *NSSASN1Template_T61String;
extern const NSSASN1Template *NSSASN1Template_UniversalString;
extern const NSSASN1Template *NSSASN1Template_UTCTime;
extern const NSSASN1Template *NSSASN1Template_UTF8String;
extern const NSSASN1Template *NSSASN1Template_VisibleString;

extern const NSSASN1Template *NSSASN1Template_PointerToAny;
extern const NSSASN1Template *NSSASN1Template_PointerToBitString;
extern const NSSASN1Template *NSSASN1Template_PointerToBMPString;
extern const NSSASN1Template *NSSASN1Template_PointerToBoolean;
extern const NSSASN1Template *NSSASN1Template_PointerToEnumerated;
extern const NSSASN1Template *NSSASN1Template_PointerToGeneralizedTime;
extern const NSSASN1Template *NSSASN1Template_PointerToIA5String;
extern const NSSASN1Template *NSSASN1Template_PointerToInteger;
extern const NSSASN1Template *NSSASN1Template_PointerToNull;
extern const NSSASN1Template *NSSASN1Template_PointerToObjectID;
extern const NSSASN1Template *NSSASN1Template_PointerToOctetString;
extern const NSSASN1Template *NSSASN1Template_PointerToPrintableString;
extern const NSSASN1Template *NSSASN1Template_PointerToT61String;
extern const NSSASN1Template *NSSASN1Template_PointerToUniversalString;
extern const NSSASN1Template *NSSASN1Template_PointerToUTCTime;
extern const NSSASN1Template *NSSASN1Template_PointerToUTF8String;
extern const NSSASN1Template *NSSASN1Template_PointerToVisibleString;

extern const NSSASN1Template *NSSASN1Template_SetOfAny;
extern const NSSASN1Template *NSSASN1Template_SetOfBitString;
extern const NSSASN1Template *NSSASN1Template_SetOfBMPString;
extern const NSSASN1Template *NSSASN1Template_SetOfBoolean;
extern const NSSASN1Template *NSSASN1Template_SetOfEnumerated;
extern const NSSASN1Template *NSSASN1Template_SetOfGeneralizedTime;
extern const NSSASN1Template *NSSASN1Template_SetOfIA5String;
extern const NSSASN1Template *NSSASN1Template_SetOfInteger;
extern const NSSASN1Template *NSSASN1Template_SetOfNull;
extern const NSSASN1Template *NSSASN1Template_SetOfObjectID;
extern const NSSASN1Template *NSSASN1Template_SetOfOctetString;
extern const NSSASN1Template *NSSASN1Template_SetOfPrintableString;
extern const NSSASN1Template *NSSASN1Template_SetOfT61String;
extern const NSSASN1Template *NSSASN1Template_SetOfUniversalString;
extern const NSSASN1Template *NSSASN1Template_SetOfUTCTime;
extern const NSSASN1Template *NSSASN1Template_SetOfUTF8String;
extern const NSSASN1Template *NSSASN1Template_SetOfVisibleString;
#endif

#if 0
/*
 *
 */

NSS_EXTERN NSSUTF8 *
nssUTF8_CreateFromBER
(
  NSSArena *arenaOpt,
  nssStringType type,
  NSSBER *berData
);

NSS_EXTERN NSSDER *
nssUTF8_GetDEREncoding
(
  NSSArena *arenaOpt,
  /* Should have an NSSDER *rvOpt */
  nssStringType type,
  const NSSUTF8 *string
);
#endif

PR_END_EXTERN_C

#endif /* NSSASN1_H */
