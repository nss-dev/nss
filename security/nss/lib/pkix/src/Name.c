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
static const char CVS_ID[] = "@(#) $Source$ $Revision$ $Date$ $Name$";
#endif /* DEBUG */

#ifndef PKIXM_H
#include "../include/pkixm.h"
#endif /* PKIXM_H */

/*
 * nssPKIXName_template
 *
 */

const NSSASN1Template nssPKIXName_template[] = {
  { NSSASN1_CHOICE, offsetof(NSSPKIXName, choice), 0, sizeof(NSSPKIXName) },
  { NSSASN1_POINTER, offsetof(NSSPKIXName, u.rdnSequence), 
    nssPKIXRDNSequence_template, NSSPKIXNameChoice_rdnSequence },
  { 0 }
};

static PRStatus
encode_me(NSSPKIXName *name)
{
    NSSASN1EncodingType encoding = NSSASN1DER;
    if (NSSITEM_IS_EMPTY(&name->der)) {
	if ((NSSBER *)NULL == NSSASN1_EncodeItem(name->arena, 
	                                         &name->der,
	                                         name,
	                                         nssPKIXName_template, 
	                                         encoding))
	{
	    return PR_FAILURE;
	}
    }
    return PR_SUCCESS;
}

static PRStatus
decode_me(NSSPKIXName *name)
{
    if (!NSSITEM_IS_EMPTY(&name->der)) {
	return NSSASN1_DecodeBER(name->arena, name, 
	                         nssPKIXName_template, &name->der);
    } else {
	return PR_FAILURE;
    }
}

static NSSPKIXName *
create_me
(
  NSSArena *arenaOpt
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXName *rv = (NSSPKIXName *)NULL;

  if( (NSSArena *)NULL == arenaOpt ) {
    arena = NSSArena_Create();
    if( (NSSArena *)NULL == arena ) {
      goto loser;
    }
    arena_allocated = PR_TRUE;
  } else {
    arena = arenaOpt;
    mark = nssArena_Mark(arena);
    if( (nssArenaMark *)NULL == mark ) {
      goto loser;
    }
  }

  rv = nss_ZNEW(arena, NSSPKIXName);
  if( (NSSPKIXName *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

  return (NSSPKIXName *)NULL;
}

#if 0
/*
 * nssPKIXName_Create
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_CHOICE
 *  NSS_ERROR_INVALID_ARGUMENT
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
nssPKIXName_Create
(
  NSSArena *arenaOpt,
  NSSPKIXNameChoice choice,
  void *arg
)
{
  NSSPKIXName *rv = (NSSPKIXName *)NULL;

  switch( choice ) {
  case NSSPKIXNameChoice_rdnSequence:
    break;
  case NSSPKIXNameChoice_NSSinvalid:
  default:
#if 0
    nss_SetError(NSS_ERROR_INVALID_CHOICE);
#endif
    goto loser;
  }

  rv = create_me(arenaOpt);
  if (!rv) {
    return (NSSPKIXName *)NULL;
  }

  rv->utf8 = NSSUTF8_Duplicate(string, arena);
  if( (NSSUTF8 *)NULL == rv->utf8 ) {
    goto loser;
  }
  
  rv->choice = choice;
  switch( choice ) {
  case NSSPKIXNameChoice_rdnSequence:
    rv->u.rdnSequence = nssPKIXRDNSequence_Duplicate((NSSPKIXRDNSequence *)arg, arena);
    if( (NSSPKIXRDNSequence *)NULL == rv->u.rdnSequence ) {
      goto loser;
    }
    break;
  case NSSPKIXNameChoice_NSSinvalid:
  default:
    nss_SetError(NSS_ERROR_INVALID_CHOICE);
    goto loser;
  }

  return rv;

 loser:
  nssPKIXName_Destroy(rv);
  return (NSSPKIXName *)NULL;
}
#endif

/*
 * nssPKIXName_CreateFromRDNSequence
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_PKIX_RDN_SEQUENCE
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
nssPKIXName_CreateFromRDNSequence
(
  NSSArena *arenaOpt,
  NSSPKIXRDNSequence *rdnSequence
)
{
#if 0
  NSSPKIXName *rv = (NSSPKIXName *)NULL;

  rv = create_me(arenaOpt);
  if (!rv) {
    return (NSSPKIXName *)NULL;
  }

  rv->utf8 = NSSUTF8_Duplicate(string, arena);
  if( (NSSUTF8 *)NULL == rv->utf8 ) {
    goto loser;
  }
  
  rv->choice = NSSPKIXNameChoice_rdnSequence;
  rv->u.rdnSequence = rdnSequence;

  return rv;

 loser:
  nssPKIXName_Destroy(rv);
#endif
  return (NSSPKIXName *)NULL;
}

/*
 * nssPKIXName_CreateFromUTF8
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_STRING
 *  NSS_ERROR_UNKNOWN_ATTRIBUTE
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
nssPKIXName_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
  NSSPKIXName *rv = (NSSPKIXName *)NULL;

  rv = create_me(arenaOpt);
  if (!rv) {
    return (NSSPKIXName *)NULL;
  }

  rv->utf8 = NSSUTF8_Duplicate(string, rv->arena);
  if( (NSSUTF8 *)NULL == rv->utf8 ) {
    goto loser;
  }
  
  /* Insert intelligence here -- fgmr */
#if 0
  nss_SetError(NSS_ERROR_INTERNAL_ERROR);
#endif
  goto loser;

  return rv;

 loser:
  nssPKIXName_Destroy(rv);
  return (NSSPKIXName *)NULL;
}

NSS_IMPLEMENT void
nssPKIXName_SetArena
(
  NSSPKIXName *name,
  NSSArena *arena
)
{
  name->arena = arena;
#if 0
  switch( name->choice ) {
  case NSSPKIXNameChoice_rdnSequence:
    nssPKIXRDNSequence_SetArena(name->u.rdnSequence, arena);
  case NSSPKIXNameChoice_NSSinvalid:
  default:
    break;
  }
#endif
}

/*
 * nssPKIXName_Decode
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
nssPKIXName_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  PRStatus status;
  NSSPKIXName *rv = (NSSPKIXName *)NULL;

  rv = create_me(arenaOpt);
  if (!rv) {
    return (NSSPKIXName *)NULL;
  }

  if ((NSSItem *)NULL == NSSItem_Duplicate(ber, rv->arena, &rv->der)) {
    goto loser;
  }

  status = decode_me(rv);
  if( PR_SUCCESS != status ) {
    goto loser;
  }

  nssPKIXName_SetArena(rv, rv->arena);

  return rv;

 loser:
  nssPKIXName_Destroy(rv);
  return (NSSPKIXName *)NULL;
}

/*
 * nssPKIXName_Destroy
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *
 * Return value:
 *  PR_SUCCESS upon success
 *  PR_FAILURE upon failure
 */

NSS_IMPLEMENT PRStatus
nssPKIXName_Destroy
(
  NSSPKIXName *name
)
{
  if( PR_TRUE == name->i_allocated_arena ) {
    return NSSArena_Destroy(name->arena);
  }
  return PR_SUCCESS;
}

/*
 * nssPKIXName_Duplicate
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
nssPKIXName_Duplicate
(
  NSSPKIXName *name,
  NSSArena *arenaOpt
)
{
  NSSPKIXName *rv = (NSSPKIXName *)NULL;

  rv = create_me(arenaOpt);
  if (!rv) {
    return (NSSPKIXName *)NULL;
  }

  if (!NSSITEM_IS_EMPTY(&name->der)) {
    if (NSSItem_Duplicate(&name->der, rv->arena, &rv->der) ==
         (NSSDER *)NULL)
    {
      goto loser;
    }
  }

  if( (NSSUTF8 *)NULL != name->utf8 ) {
    rv->utf8 = NSSUTF8_Duplicate(name->utf8, rv->arena);
    if( (NSSUTF8 *)NULL == rv->utf8 ) {
      goto loser;
    }
  }
  
  rv->choice = name->choice;
  switch( name->choice ) {
  case NSSPKIXNameChoice_rdnSequence:
    rv->u.rdnSequence = nssPKIXRDNSequence_Duplicate(name->u.rdnSequence, rv->arena);
    if( (NSSPKIXRDNSequence *)NULL == rv->u.rdnSequence ) {
      goto loser;
    }
    break;
  case NSSPKIXNameChoice_NSSinvalid:
  default:
#if 0
    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
#endif
    goto loser;
  }

  return rv;

 loser:
  nssPKIXName_Destroy(rv);
  return (NSSPKIXName *)NULL;
}

/*
 * nssPKIXName_Encode
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid NSSBER pointer upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSBER *
nssPKIXName_Encode
(
  NSSPKIXName *name
)
{
#if 0
  switch( encoding ) {
  case NSSASN1BER:
  case NSSASN1DER:
#endif
    if (encode_me(name) == PR_FAILURE) {
      return (NSSBER *)NULL;
    }
    return &name->der;
#if 0
  default:
    nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
    return (NSSBER *)NULL;
  }
#endif
}

/*
 * nssPKIXName_Equal
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *
 * Return value:
 *  PR_TRUE if the two objects have equal values
 *  PR_FALSE otherwise
 *  PR_FALSE upon error
 */

NSS_IMPLEMENT PRBool
nssPKIXName_Equal
(
  NSSPKIXName *one,
  NSSPKIXName *two,
  PRStatus *statusOpt
)
{

  if (!NSSITEM_IS_EMPTY(&one->der) && !NSSITEM_IS_EMPTY(&two->der)) {
    return NSSItem_Equal(&one->der, &two->der, statusOpt);
  }

  if( one->choice != two->choice ) {
    if( (PRStatus *)NULL != statusOpt ) {
      *statusOpt = PR_SUCCESS;
    }
    return PR_FALSE;
  }

  switch( one->choice ) {
  case NSSPKIXNameChoice_rdnSequence:
    return nssPKIXRDNSequence_Equal(one->u.rdnSequence, two->u.rdnSequence, statusOpt);
  case NSSPKIXNameChoice_NSSinvalid:
  default:
    break;
  }

#if 0
  nss_SetError(NSS_ERROR_INTERNAL_ERROR);
#endif
  if( (PRStatus *)NULL != statusOpt ) {
    *statusOpt = PR_FAILURE;
  }
  return PR_FALSE;
}

/*
 * nssPKIXName_GetChoice
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *
 * Return value:
 *  A valid element of the NSSPKIXNameChoice enumeration upon success
 *  The value NSSPKIXNameChoice_NSSinvalid (-1) upon error
 */

NSS_IMPLEMENT NSSPKIXNameChoice
nssPKIXName_GetChoice
(
  NSSPKIXName *name
)
{
  return name->choice;
}

/*
 * nssPKIXName_GetRDNSequence
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_WRONG_CHOICE
 *
 * Return value:
 *  A pointer to a valid NSSPKIXRDNSequence upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXRDNSequence *
nssPKIXName_GetRDNSequence
(
  NSSPKIXName *name,
  NSSArena *arenaOpt
)
{
  switch( name->choice ) {
  case NSSPKIXNameChoice_rdnSequence:
    return nssPKIXRDNSequence_Duplicate(name->u.rdnSequence, arenaOpt);
  case NSSPKIXNameChoice_NSSinvalid:
  default:
    break;
  }

#if 0
  nss_SetError(NSS_ERROR_WRONG_CHOICE);
#endif
  return (NSSPKIXRDNSequence *)NULL;
}

/*
 * nssPKIXName_GetSpecifiedChoice
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_WRONG_CHOICE
 *
 * Return value:
 *  A valid pointer ...
 *  NULL upon failure
 */

NSS_IMPLEMENT void *
nssPKIXName_GetSpecifiedChoice
(
  NSSPKIXName *name,
  NSSPKIXNameChoice choice,
  NSSArena *arenaOpt
)
{
  if( choice != name->choice ) {
#if 0
    nss_SetError(NSS_ERROR_WRONG_CHOICE);
#endif
    return (void *)NULL;
  }

  switch( name->choice ) {
  case NSSPKIXNameChoice_rdnSequence:
    return (void *)nssPKIXRDNSequence_Duplicate(name->u.rdnSequence, arenaOpt);
  case NSSPKIXNameChoice_NSSinvalid:
  default:
    break;
  }

#if 0
  nss_SetError(NSS_ERROR_WRONG_CHOICE);
#endif
  return (NSSPKIXRDNSequence *)NULL;
}

/*
 * nssPKIXName_GetUTF8Encoding
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid NSSUTF8 pointer upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSUTF8 *
nssPKIXName_GetUTF8Encoding
(
  NSSPKIXName *name,
  NSSArena *arenaOpt
)
{
  if( (NSSUTF8 *)NULL == name->utf8 ) {
    /* xxx fgmr fill this in from pki1 implementation */
  }
  return NSSUTF8_Duplicate(name->utf8, arenaOpt);
}

/*
 * NSSPKIXName_Create
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_CHOICE
 *  NSS_ERROR_INVALID_ARGUMENT
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXName *
NSSPKIXName_Create
(
  NSSArena *arenaOpt,
  NSSPKIXNameChoice choice,
  void *arg
)
{
  nss_ClearErrorStack();

  return nssPKIXName_Create(arenaOpt, choice, arg);
}
#endif

/*
 * NSSPKIXName_CreateFromRDNSequence
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_PKIX_RDN_SEQUENCE
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
NSSPKIXName_CreateFromRDNSequence
(
  NSSArena *arenaOpt,
  NSSPKIXRDNSequence *rdnSequence
)
{
  nss_ClearErrorStack();

  return nssPKIXName_CreateFromRDNSequence(arenaOpt, rdnSequence);
}

/*
 * NSSPKIXName_CreateFromUTF8
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_INVALID_STRING
 *  NSS_ERROR_UNKNOWN_ATTRIBUTE
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
NSSPKIXName_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
  nss_ClearErrorStack();

  return nssPKIXName_CreateFromUTF8(arenaOpt, string);
}

/*
 * NSSPKIXName_CreateFromBER
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

#if 0
NSS_IMPLEMENT NSSPKIXName *
NSSPKIXName_CreateFromBER
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  nss_ClearErrorStack();

  return nssPKIXName_CreateFromBER(arenaOpt, ber);
}
#endif

/*
 * NSSPKIXName_Destroy
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *
 * Return value:
 *  PR_SUCCESS upon success
 *  PR_FAILURE upon failure
 */

NSS_IMPLEMENT PRStatus
NSSPKIXName_Destroy
(
  NSSPKIXName *name
)
{
  nss_ClearErrorStack();

  return nssPKIXName_Destroy(name);
}

/*
 * NSSPKIXName_Duplicate
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid pointer to an NSSPKIXName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXName *
NSSPKIXName_Duplicate
(
  NSSPKIXName *name,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXName_Duplicate(name, arenaOpt);
}

/*
 * NSSPKIXName_Encode
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid NSSBER pointer upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSBER *
NSSPKIXName_Encode
(
  NSSPKIXName *name
)
{
  nss_ClearErrorStack();

  return nssPKIXName_Encode(name);
}

/*
 * NSSPKIXName_Equal
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *
 * Return value:
 *  PR_TRUE if the two objects have equal values
 *  PR_FALSE otherwise
 *  PR_FALSE upon error
 */

NSS_IMPLEMENT PRBool
NSSPKIXName_Equal
(
  NSSPKIXName *name1,
  NSSPKIXName *name2,
  PRStatus *statusOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXName_Equal(name1, name2, statusOpt);
}

/*
 * NSSPKIXName_GetChoice
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *
 * Return value:
 *  A valid element of the NSSPKIXNameChoice enumeration upon success
 *  The value NSSPKIXNameChoice_NSSinvalid (-1) upon error
 */

NSS_IMPLEMENT NSSPKIXNameChoice
NSSPKIXName_GetChoice
(
  NSSPKIXName *name
)
{
  nss_ClearErrorStack();

  return nssPKIXName_GetChoice(name);
}

/*
 * NSSPKIXName_GetRDNSequence
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_WRONG_CHOICE
 *
 * Return value:
 *  A pointer to a valid NSSPKIXRDNSequence upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXRDNSequence *
NSSPKIXName_GetRDNSequence
(
  NSSPKIXName *name,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXName_GetRDNSequence(name, arenaOpt);
}

/*
 * NSSPKIXName_GetSpecifiedChoice
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_WRONG_CHOICE
 *
 * Return value:
 *  A valid pointer ...
 *  NULL upon failure
 */

NSS_IMPLEMENT void *
NSSPKIXName_GetSpecifiedChoice
(
  NSSPKIXName *name,
  NSSPKIXNameChoice choice,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXName_GetSpecifiedChoice(name, choice, arenaOpt);
}

/*
 * NSSPKIXName_GetUTF8Encoding
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_NAME
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid NSSUTF8 pointer upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSUTF8 *
NSSPKIXName_GetUTF8Encoding
(
  NSSPKIXName *name,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXName_GetUTF8Encoding(name, arenaOpt);
}

