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
 * nssPKIXRelativeDistinguishedName_template
 *
 */

const NSSASN1Template nssPKIXRelativeDistinguishedName_template[] = {
  { NSSASN1_SET_OF, offsetof(NSSPKIXRelativeDistinguishedName, atavs),
    nssPKIXAttributeTypeAndValue_template, 
    sizeof(NSSPKIXRelativeDistinguishedName) }
};

NSS_IMPLEMENT PRStatus
nss_pkix_RelativeDistinguishedName_Clear
(
  NSSPKIXRelativeDistinguishedName *rdn
)
{
#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }
#endif /* NSSDEBUG */

  if( (NSSBER *)NULL != rdn->ber ) {
    nss_ZFreeIf(rdn->ber->data);
    nss_ZFreeIf(rdn->ber);
  }

  if( (NSSDER *)NULL != rdn->der ) {
    nss_ZFreeIf(rdn->der->data);
    nss_ZFreeIf(rdn->der);
  }

  nss_ZFreeIf(rdn->utf8);

  return PR_SUCCESS;
}

NSS_IMPLEMENT void
nss_pkix_RelativeDistinguishedName_Count
(
  NSSPKIXRelativeDistinguishedName *rdn
)
{
#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return;
  }
#endif /* NSSDEBUG */

  PR_ASSERT((NSSPKIXAttributeTypeAndValue **)NULL != rdn->atavs);
  if( (NSSPKIXAttributeTypeAndValue **)NULL == rdn->atavs ) {
    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
    return PR_FAILURE;
  }

  if( 0 == rdn->count ) {
    PRUint32 i;
    for( i = 0; i < 0xFFFFFFFF; i++ ) {
      if( (NSSPKIXAttributeTypeAndValue *)NULL == rdn->atavs[i] ) {
        break;
      }
    }

#ifdef PEDANTIC
    if( 0xFFFFFFFF == i ) {
      return;
    }
#endif /* PEDANTIC */

    rdn->count = i;
  }

  return;
}

NSS_EXTERN NSSPKIXRelativeDistinguishedName *
nss_pkix_RelativeDistinguishedName_V_Create
(
  NSSArena *arenaOpt,
  PRUint32 count,
  va_list ap
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRelativeDistinguishedName *rv = (NSSPKIXRelativeDistinguishedName *)NULL;
  PRStatus status;
  PRUint32 i;

#ifdef NSSDEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }
#endif /* NSSDEBUG */

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

  rv = nss_ZNEW(arena, NSSPKIXRelativeDistinguishedName);
  if( (NSSPKIXRelativeDistinguishedName *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->count = count;

  rv->atav = nss_ZNEWARRAY(arena, NSSPKIXAttributeTypeAndValue *, count);
  if( (NSSPKIXAttributeTypeAndValue **)NULL == rv->atav ) {
    goto loser;
  }

  for( i = 0; i < count; i++ ) {
    NSSPKIXAttributeTypeAndValue *v = (NSSPKIXAttributeTypeAndValue *)
      va_arg(ap, NSSPKIXAttributeTypeAndValue *);

#ifdef NSSDEBUG
    /* 
     * It's okay to test this down here, since 
     * supposedly these have already been checked.
     */
    if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(v) ) {
      goto loser;
    }
#endif /* NSSDEBUG */

    rv->atav[i] = nssPKIXAttributeTypeAndValue_Duplicate(v, arena);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == rv->atav[i] ) {
      goto loser;
    }
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

#ifdef DEBUG
  if( PR_SUCCESS != nss_pkix_RelativeDistinguishedName_add_pointer(rv) ) {
    goto loser;
  }

  if( PR_SUCCESS != NSSArena_registerDestructor(arena, 
        nss_pkix_RelativeDistinguishedName_remove_pointer, rv) ) {
    (void)nss_pkix_RelativeDistinguishedName_remove_pointer(rv);
    goto loser;
  }
#endif /* DEBUG */

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

  return (NSSPKIXRelativeDistinguishedName *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXRelativeDistinguishedName_AddAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *atav
)
{
  PRUint32 newcount;
  NSSPKIXAttributeTypeAndValue **newarray;

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }

  if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
    return PR_FAILURE;
  }
#endif /* NSSDEBUG */

  PR_ASSERT((NSSPKIXAttributeTypeAndValue **)NULL != rdn->atavs);
  if( (NSSPKIXAttributeTypeAndValue **)NULL == rdn->atavs ) {
    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
    return PR_FAILURE;
  }

  if( 0 == rdn->count ) {
    nss_pkix_RelativeDistinguishedName_Count(rdn);
  }

  newcount = rdn->count+1;
  /* Check newcount for a rollover. */

  /* Remember that our atavs array is NULL-terminated */
  newarray = (NSSPKIXAttributeTypeAndValue **)nss_ZRealloc(rdn->atavs,
               ((newcount+1) * sizeof(NSSPKIXAttributeTypeAndValue *)));
  if( (NSSPKIXAttributeTypeAndValue **)NULL == newarray ) {
    return PR_FAILURE;
  }

  rdn->atavs = newarray;

  rdn->atavs[ rdn->count ] = nssPKIXAttributeTypeAndValue_Duplicate(atav, rdn->arena);
  if( (NSSPKIXAttributeTypeAndValue *)NULL == rdn->atavs[ rdn->count ] ) {
    return PR_FAILURE; /* array is "too big" but whatever */
  }

  rdn->count = newcount;

  return nss_pkix_RelativeDistinguishedName_Clear(rdn);
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
nssPKIXRelativeDistinguishedName_Create
(
  NSSArena *arenaOpt,
  NSSPKIXAttributeTypeAndValue *atav1,
  ...
)
{
  va_list ap;
  NSSPKIXRelativeDistinguishedName *rv;
  PRUint32 count;

#ifdef NSSDEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }

  /* Is there a nonzero minimum number of ATAVs required? */

  {
    va_start(ap, arenaOpt);

    while( 1 ) {
      NSSPKIXAttributeTypeAndValue *atav;
      atav = (NSSPKIXAttributeTypeAndValue *)va_arg(ap, NSSPKIXAttributeTypeAndValue *);
      if( (NSSPKIXAttributeTypeAndValue *)NULL == atav ) {
        break;
      }

      if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
        va_end(ap);
        return (NSSPKIXRelativeDistinguishedName *)NULL;
      }
    }

    va_end(ap);
  }
#endif /* NSSDEBUG */

  va_start(ap, arenaOpt);

  for( count = 0; ; count++ ) {
    NSSPKIXAttributeTypeAndValue *atav;
    atav = (NSSPKIXAttributeTypeAndValue *)va_arg(ap, NSSPKIXAttributeTypeAndValue *);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == atav ) {
      break;
    }

#ifdef PEDANTIC
    if( count == 0xFFFFFFFF ) {
      nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
      va_end(ap);
      return (NSSPKIXAttributeTypeAndValue *)NULL;
    }
#endif /* PEDANTIC */
  }

  va_end(ap);

  va_start(ap, arenaOpt);
  rv = nss_pkix_RelativeDistinguishedName_V_Create(arenaOpt, count, ap);
  va_end(ap);

  return rv;
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
nssPKIXRelativeDistinguishedName_CreateFromArray
(
  NSSArena *arenaOpt,
  PRUint32 count,
  NSSPKIXAttributeTypeAndValue *atavs
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRelativeDistinguishedName *rv = (NSSPKIXRelativeDistinguishedName *)NULL;
  PRStatus status;
  PRUint32 i;

#ifdef NSSDEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }

  {
    PRUint32 i;

    for( i = 0; i < count; i++ ) {
      if( PR_SUCCESS != nssAttributeTypeAndValue_verifyPointer(&atavs[i]) ) {
        return (NSSPKIXAttribute *)NULL;
      }
    }
  }
#endif /* NSSDEBUG */

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

  rv = nss_ZNEW(arena, NSSPKIXRelativeDistinguishedName);
  if( (NSSPKIXRelativeDistinguishedName *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->count = count;

  rv->atav = nss_ZNEWARRAY(arena, NSSPKIXAttributeTypeAndValue *, count);
  if( (NSSPKIXAttributeTypeAndValue **)NULL == rv->atav ) {
    goto loser;
  }

  for( i = 0; i < count; i++ ) {
    NSSPKIXAttributeTypeAndValue *v = atavs[i];

    rv->atav[i] = nssPKIXAttributeTypeAndValue_Duplicate(v, arena);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == rv->atav[i] ) {
      goto loser;
    }
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

#ifdef DEBUG
  if( PR_SUCCESS != nss_pkix_RelativeDistinguishedName_add_pointer(rv) ) {
    goto loser;
  }
#endif /* DEBUG */

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

  return (NSSPKIXRelativeDistinguishedName *)NULL;
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
nssPKIXRelativeDistinguishedName_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRelativeDistinguishedName *rv = (NSSPKIXRelativeDistinguishedName *)NULL;
  PRStatus status;
  PRUint32 i;

#ifdef NSSDEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }

  if( (NSSUTF8 *)NULL == string ) {
    nss_SetError(NSS_ERROR_INVALID_STRING);
    return (NSSPKIXRelativeDistinguishedName *)NULL;
  }
#endif /* NSSDEBUG */

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

  rv = nss_ZNEW(arena, NSSPKIXRelativeDistinguishedName);
  if( (NSSPKIXRelativeDistinguishedName *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->utf8 = NSSUTF8_Duplicate(string, arena);
  if( (NSSUTF8 *)NULL == rv->utf8 ) {
    goto loser;
  }
  
  /* Insert intelligence here -- fgmr */
  nss_SetError(NSS_ERROR_INTERNAL_ERROR);
  goto loser;

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

#ifdef DEBUG
  if( PR_SUCCESS != nss_pkix_RelativeDistinguishedName_add_pointer(rv) ) {
    goto loser;
  }
#endif /* DEBUG */

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

  return (NSSPKIXRelativeDistinguishedName *)NULL;
}

/*
 * nssPKIXRelativeDistinguishedName_Decode
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXRelativeDistinguishedName upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
nssPKIXRelativeDistinguishedName_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRelativeDistinguishedName *rv = (NSSPKIXRelativeDistinguishedName *)NULL;
  PRStatus status;
  PRUint32 i;

#ifdef NSSDEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }

  if( PR_SUCCESS != NSSItem_verifyPointer(ber) ) {
    return (NSSPKIXRelativeDistinguishedName *)NULL;
  }
#endif /* NSSDEBUG */

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

  rv = nss_ZNEW(arena, NSSPKIXRelativeDistinguishedName);
  if( (NSSPKIXRelativeDistinguishedName *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->ber = NSSItem_Duplicate(ber, arena, (NSSItem *)NULL);
  if( (NSSItem *)NULL == rv->ber ) {
    goto loser;
  }

  status = NSSASN1_DecodeBER(arena, rv, nssPKIXRelativeDistinguishedName_template, ber);
  if( PR_SUCCESS != status ) {
    goto loser;
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

#ifdef DEBUG
  if( PR_SUCCESS != nss_pkix_RelativeDistinguishedName_add_pointer(rv) ) {
    goto loser;
  }
#endif /* DEBUG */

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

  return (NSSPKIXRelativeDistinguishedName *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXRelativeDistinguishedName_Destroy
(
  NSSPKIXRelativeDistinguishedName *rdn
)
{
#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }
#endif /* NSSDEBUG */

#ifdef DEBUG
  (void)nss_pkix_RelativeDistinguishedName_remove_pointer(rdn);
#endif /* DEBUG */

  if( PR_TRUE == rdn->i_allocated_arena ) {
    return NSSArena_Destroy(rdn->arena);
  }

  return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
nssPKIXRelativeDistinguishedName_Duplicate
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSArena *arenaOpt
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRelativeDistinguishedName *rv = (NSSPKIXRelativeDistinguishedName *)NULL;
  PRStatus status;
  PRUint32 i;
  NSSPKIXAttributeTypeAndValue **from, **to;

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSPKIXRelativeDistinguishedName *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }
#endif /* NSSDEBUG */

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

  rv = nss_ZNEW(arena, NSSPKIXRelativeDistinguishedName);
  if( (NSSPKIXRelativeDistinguishedName *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;

  if( (NSSDER *)NULL != rdn->der ) {
    rv->der = NSSItem_Duplicate(rdn->der, arena, (NSSItem *)NULL);
    if( (NSSDER *)NULL == rv->der ) {
      goto loser;
    }
  }

  if( (NSSBER *)NULL != rdn->ber ) {
    rv->ber = NSSItem_Duplicate(rdn->ber, arena, (NSSItem *)NULL);
    if( (NSSBER *)NULL == rv->ber ) {
      goto loser;
    }
  }

  if( (NSSUTF8 *)NULL != rdn->utf8 ) {
    rv->utf8 = NSSUTF8_Duplicate(rdn->utf8, arena);
    if( (NSSUTF8 *)NULL == rv->utf8 ) {
      goto loser;
    }
  }

  rv->count = rdn->count;

  {
    if( 0 == rdn->count ) {
      nss_pkix_RelativeDistinguishedName_Count(rdn);
      if( 0 == rdn->count ) {
        nss_SetError(NSS_ERROR_INTERNAL_ERROR);
        goto loser;
      }

      rv->count = rdn->count; /* might as well save it */
    }

    rv->atavs = nss_ZNEWARRAY(arena, NSSPKIXAttributeTypeAndValue *, rdn->count + 1);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == rv->atavs ) {
      goto loser;
    }
  }

  for( from = &rdn->atavs[0], to = &rv->atavs[0]; *from; from++, to++ ) {
    *to = nssPKIXAttributeTypeAndValue_Duplicate(*from, arena);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == *to ) {
      goto loser;
    }
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

#ifdef DEBUG
  if( PR_SUCCESS != nss_pkix_RelativeDistinguishedName_add_pointer(rv) ) {
    goto loser;
  }
#endif /* DEBUG */

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

  return (NSSPKIXRelativeDistinguishedName *)NULL;
}

/*
 * nssPKIXRelativeDistinguishedName_Encode
 *
 * -- fgmr comments --
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_PKIX_RDN
 *  NSS_ERROR_INVALID_ARENA
 *  NSS_ERROR_NO_MEMORY
 *
 * Return value:
 *  A valid NSSBER pointer upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSBER *
nssPKIXRelativeDistinguishedName_Encode
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  NSSBER *it;

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSBER *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSBER *)NULL;
    }
  }
#endif /* NSSDEBUG */

  switch( encoding ) {
  case NSSASN1BER:
    if( (NSSBER *)NULL != rdn->ber ) {
      it = rdn->ber;
      goto done;
    }
    /*FALLTHROUGH*/
  case NSSASN1DER:
    if( (NSSDER *)NULL != rdn->der ) {
      it = rdn->der;
      goto done;
    }
    break;
  default:
    nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
    return (NSSBER *)NULL;
  }

  it = NSSASN1_EncodeItem(rdn->arena, (NSSItem *)NULL, rdn,
                          nssPKIXRelativeDistinguishedName_template,
                          encoding);
  if( (NSSBER *)NULL == it ) {
    return (NSSBER *)NULL;
  }

  switch( encoding ) {
  case NSSASN1BER:
    rdn->ber = it;
    break;
  case NSSASN1DER:
    rdn->der = it;
    break;
  default:
    PR_ASSERT(0);
    break;
  }

 done:
  return NSSItem_Duplicate(it, arenaOpt, rvOpt);
}

NSS_IMPLEMENT PRBool
nssPKIXRelativeDistinguishedName_Equal
(
  NSSPKIXRelativeDistinguishedName *one,
  NSSPKIXRelativeDistinguishedName *two,
  PRStatus *statusOpt
)
{

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(one) ) {
    goto loser;
  }

  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(two) ) {
    goto loser;
  }
#endif /* NSSDEBUG */

  if( (NSSDER *)NULL == one->der ) {
    one->der = NSSASN1_EncodeItem(one->arena, (NSSItem *)NULL, one,
                                  nssPKIXRelativeDistinguishedName_template,
                                  NSSASN1DER);
    if( (NSSDER *)NULL == one->der ) {
      goto loser;
    }
  }

  if( (NSSDER *)NULL == two->der ) {
    two->der = NSSASN1_EncodeItem(two->arena, (NSSItem *)NULL, two,
                                  nssPKIXRelativeDistinguishedName_template,
                                  NSSASN1DER);
    if( (NSSDER *)NULL == two->der ) {
      goto loser;
    }
  }

  return NSSItem_Equal(one->der, two->der, statusOpt);

 loser:
  if( (PRStatus *)NULL != statusOpt ) {
    *statusOpt = PR_FAILURE;
  }

  return PR_FALSE;
}

NSS_IMPLEMENT PRInt32
nssPKIXRelativeDistinguishedName_FindAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *atav
)
{
  PRUint32 i;
  NSSPKIXAttributeTypeAndValue **a;

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return -1;
  }

  if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
    return -1;
  }
#endif /* NSSDEBUG */

  PR_ASSERT((NSSPKIXAttributeTypeAndValue **)NULL != rdn->atavs);
  if( (NSSPKIXAttributeTypeAndValue **)NULL == rdn->atavs ) {
    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
    return -1;
  }

  for( i = 0, a = rdn->atavs; *a; a++, (i > 0x7fffffff) || i++ ) {
    if( PR_TRUE == nssPKIXAttributeTypeAndValue_Equal(*a, atav) ) {
      if( i > 0x7fffffff ) {
        nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
        return -1;
      }
      return (PRInt32)i;
    }
  }

  nss_SetError(NSS_ERROR_NOT_FOUND);
  return -1;
}

NSS_IMPLEMENT NSSPKIXAttributeTypeAndValue *
nssPKIXRelativeDistinguishedName_GetAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  PRInt32 i,
  NSSArena *arenaOpt
)
{

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSPKIXAttributeTypeAndValue *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXAttributeTypeAndValue *)NULL;
    }
  }
#endif /* NSSDEBUG */

  if( 0 == rdn->count ) {
    nss_pkix_RelativeDistinguishedName_Count(rdn);
  }

  if( (i < 0) || (i >= rdn->count) ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXAttributeTypeAndValue *)NULL;
  }

  return nssPKIXAttributeTypeAndValue_Duplicate(rdn->atavs[i], arenaOpt);
}

NSS_IMPLEMENT PRInt32
nssPKIXRelativeDistinguishedName_GetAttributeTypeAndValueCount
(
  NSSPKIXRelativeDistinguishedName *rdn
)
{
#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return -1;
  }
#endif /* NSSDEBUG */

  if( 0 == rdn->count ) {
    nss_pkix_RelativeDistinguishedName_Count(rdn);
  }

#ifdef PEDANTIC
  if( 0 == rdn->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return -1;
  }
#endif /* PEDANTIC */

  if( rdn->count > 0x7fffffff ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return -1;
  }

  return (PRInt32)(rdn->count);
}

NSS_IMPLEMENT NSSPKIXAttributeTypeAndValue **
nssPKIXRelativeDistinguishedName_GetAttributeTypeAndValues
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *rvOpt[],
  PRInt32 limit,
  NSSArena *arenaOpt
)
{
  NSSPKIXAttributeTypeAndValue **rv = (NSSPKIXAttributeTypeAndValue **)NULL;
  PRUint32 i;

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSPKIXAttributeTypeAndValue **)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyOpt(attribute) ) {
      return (NSSPKIXAttributeTypeAndValue **)NULL;
    }
  }
#endif /* NSSDEBUG */

  if( 0 == rdn->count ) {
    nss_pkix_RelativeDistinguishedName_Count(rdn);
  }

#ifdef PEDANTIC
  if( 0 == rdn->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXAttributeTypeAndValue **)NULL;
  }
#endif /* PEDANTIC */

  if( (limit < rdn->count) &&
      !((0 == limit) && ((NSSPKIXAttributeTypeAndValue **)NULL == rvOpt)) ) {
    nss_SetError(NSS_ERROR_ARRAY_TOO_SMALL);
    return (NSSPKIXAttributeTypeAndValue **)NULL;
  }

  limit = rdn->count;
  if( (NSSPKIXAttributeTypeAndValue **)NULL == rvOpt ) {
    rv = nss_ZNEWARRAY(arenaOpt, NSSPKIXAttributeTypeAndValue *, limit);
    if( (NSSPKIXAttributeTypeAndValue **)NULL == rv ) {
      return (NSSPKIXAttributeTypeAndValue **)NULL;
    }
  } else {
    rv = rvOpt;
  }

  for( i = 0; i < limit; i++ ) {
    rv[i] = nssPKIXAttributeTypeAndValue_Duplicate(rdn->atav[i], arenaOpt);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == rv[i] ) {
      goto loser;
    }
  }

  return rv;

 loser:
  for( i = 0; i < limit; i++ ) {
    NSSPKIXAttributeTypeAndValue *x = rv[i];
    if( (NSSPKIXAttributeTypeAndValue *)NULL == x ) {
      break;
    }
    (void)nssPKIXAttributeTypeAndValue_Destroy(x);
  }

  if( rv != rvOpt ) {
    nss_ZFreeIf(rv);
  }

  return (NSSPKIXAttributeTypeAndValue **)NULL;
}

NSS_IMPLEMENT NSSUTF8 *
nssPKIXRelativeDistinguishedName_GetUTF8Encoding
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSArena *arenaOpt
)
{
#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSUTF8 *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSUTF8 *)NULL;
    }
  }
#endif /* NSSDEBUG */

  if( (NSSUTF8 *)NULL == rdn->utf8 ) {
    /* xxx fgmr fill this in from pki1 implementation */
  }

  return NSSUTF8_Duplicate(rdn->utf8, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssPKIXRelativeDistinguishedName_RemoveAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  PRInt32 i
)
{

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }
#endif /* NSSDEBUG */

  if( 0 == rdn->count ) {
    nss_pkix_RelativeDistinguishedName_Count(rdn);
  }

  if( i < 0 ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return PR_FAILURE;
  }

  /* Is there a technical minimum? */
  /*
   *  if( 1 == rdn->count ) {
   *    nss_SetError(NSS_ERROR_AT_MINIMUM);
   *    return PR_FAILURE;
   *  }
   */

#ifdef PEDANTIC
  if( 0 == rdn->count ) {
    NSSPKIXAttributeTypeAndValue **ip;
    /* Too big.. but we can still remove one */
    nssPKIXAttributeTypeAndValue_Destroy(rdn->atavs[i]);
    for( ip = &rdn->atavs[i]; *ip; ip++ ) {
      ip[0] = ip[1];
    }
  } else
#endif /* PEDANTIC */

  {
    NSSPKIXAttributeTypeAndValue *si;
    PRUint32 end;

    if( i >= rdn->count ) {
      nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
      return PR_FAILURE;
    }

    end = rdn->count - 1;
    
    si = rdn->atavs[i];
    rdn->atavs[i] = rdn->atavs[end];
    rdn->atavs[end] = (NSSPKIXAttributeTypeAndValue *)NULL;

    nssPKIXAttributeTypeAndValue_Destroy(si);

    /* We could realloc down, but we know it's a no-op */
    rdn->count = end;
  }

  return nss_pkix_RelativeDistinguishedName_Clear(rdn);
}

NSS_IMPLEMENT PRStatus
nssPKIXRelativeDistinguishedName_SetAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  PRInt32 i,
  NSSPKIXAttributeTypeAndValue *atav
)
{
  NSSPKIXAttributeTypeAndValue *dup;

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }

  if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
    return PR_FAILURE;
  }
#endif /* NSSDEBUG */

  PR_ASSERT((NSSPKIXAttributeTypeAndValue **)NULL != rdn->atavs);
  if( (NSSPKIXAttributeTypeAndValue **)NULL == rdn->atavs ) {
    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
    return PR_FAILURE;
  }

  if( 0 == rdn->count ) {
    nss_pkix_RelativeDistinguishedName_Count(rdn);
  }

  if( (i < 0) || (i >= rdn->count) ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return PR_FAILURE;
  }

  dup = nssPKIXAttributeTypeAndValue_Duplicate(atav, rdn->arena);
  if( (NSSPKIXAttributeTypeAndValue *)NULL == dup ) {
    return PR_FAILURE;
  }

  nssPKIXAttributeTypeAndValue_Destroy(rdn->atavs[i]);
  rdn->atavs[i] = dup;

  return nss_pkix_RelativeDistinguishedName_Clear(rdn);
}

NSS_IMPLEMENT PRStatus
nssPKIXRelativeDistinguishedName_SetAttributeTypeAndValues
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *atavs[],
  PRInt32 countOpt
)
{
  NSSPKIXAttributeTypeAndValue **ip;
  NSSPKIXAttributeTypeAndValue **newarray;
  PRUint32 i;
  nssArenaMark *mark;

#ifdef NSSDEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }

  if( (NSSPKIXAttributeTypeAndValues **)NULL == atavs ) {
    nss_SetError(NSS_ERROR_INVALID_POINTER);
    return PR_FAILURE;
  }

  {
    PRUint32 i, count;

    if( 0 == countOpt ) {
      for( i = 0; i < 0x80000000; i++ ) {
        if( (NSSPKIXAttributeTypeAndValue *)NULL == atav[i] ) {
          break;
        }
      }

#ifdef PEDANTIC
      if( 0x80000000 == i ) {
        nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
        return PR_FAILURE;
      }
#endif /* PEDANTIC */

      count = (PRUint32)i;
    } else {
      if( countOpt < 0 ) {
        nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
        return PR_FAILURE;
      }

      count = (PRUint32)countOpt;
    }

    for( i = 0; i < count; i++ ) {
      if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav[i]) ) {
        return PR_FAILURE;
      }
    }
  }
#endif /* NSSDEBUG */

  if( 0 == countOpt ) {
    for( i = 0; i < 0xffffffff; i++ ) {
      if( (NSSPKIXAttributeTypeAndValue *)NULL == atavs[i] ) {
        break;
      }
    }

#ifdef PEDANTIC
    if( 0xffffffff == 0 ) {
      nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
      reutrn PR_FAILURE;
    }
#endif /* PEDANTIC */

    countOpt = i;
  }

  mark = nssArena_Mark(rdn->mark);
  if( (nssArenaMark *)NULL == mark ) {
    return PR_FAILURE;
  }

  newarray = nss_ZNEWARRAY(rdn->arena, NSSPKIXAttributeTypeAndValue *, countOpt);
  if( (NSSPKIXAttributeTypeAndValue **)NULL == newarray ) {
    goto loser;
  }

  for( i = 0; i < countOpt; i++ ) {
    newarray[i] = nssPKIXAttributeTypeAndValue_Duplicate(atavs[i], rdn->arena);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == newarray[i] ) {
      goto loser;
    }
  }

  for( i = 0; i < rdn->count; i++ ) {
    if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_Destroy(rdn->atavs[i]) ) {
      goto loser;
    }
  }

  nss_ZFreeIf(rdn->atavs);

  rdn->count = countOpt;
  rdn->atavs = newarray;

  (void)nss_pkix_RelativeDistinguishedName_Clear(rdn);

  return nssArena_Unmark(rdn->arena, mark);

 loser:
  (void)nssArena_Release(a->arena, mark);
  return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
NSSPKIXRelativeDistinguishedName_RemoveAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  PRInt32 i
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_RemoveAttributeTypeAndValue(rdn, i);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRelativeDistinguishedName_SetAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  PRInt32 i,
  NSSPKIXAttributeTypeAndValue *atav
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }

  if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
    return PR_FAILURE;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_SetAttributeTypeAndValue(rdn, i, atav);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRelativeDistinguishedName_SetAttributeTypeAndValues
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *atavs[],
  PRInt32 countOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }

  if( (NSSPKIXAttributeTypeAndValue **)NULL == atavs ) {
    nss_SetError(NSS_ERROR_INVALID_POINTER);
    return PR_FAILURE;
  }

  {
    PRUint32 i, count;

    if( 0 == countOpt ) {
      for( i = 0; i < 0x80000000; i++ ) {
        if( (NSSPKIXAttributeTypeAndValue *)NULL == atavs[i] ) {
          break;
        }
      }

#ifdef PEDANTIC
      if( 0x80000000 == i ) {
        nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
        return PR_FAILURE;
      }
#endif /* PEDANTIC */

      count = (PRUint32)i;
    } else {
      if( countOpt < 0 ) {
        nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
        return PR_FAILURE;
      }

      count = (PRUint32)countOpt;
    }

    for( i = 0; i < count; i++ ) {
      if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atavs[i]) ) {
        return PR_FAILURE;
      }
    }
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_SetAttributeTypeAndValues(rdn, atavs, countOpt);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRelativeDistinguishedName_AddAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *atav
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }

  if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
    return PR_FAILURE;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_AddAttributeTypeAndValue(rdn, atav);
}

NSS_EXTERN NSSPKIXRelativeDistinguishedName *
NSSPKIXRelativeDistinguishedName_Create
(
  NSSArena *arenaOpt,
  NSSPKIXAttributeTypeAndValue *atav1,
  ...
)
{
  va_list ap;
  NSSPKIXRelativeDistinguishedName *rv;
  PRUint32 count;

  nss_ClearErrorStack();

#ifdef DEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }

  /* Is there a nonzero minimum number of ATAVs required? */

  {
    va_start(ap, arenaOpt);

    while( 1 ) {
      NSSPKIXAttributeTypeAndValue *atav;
      atav = (NSSPKIXAttributeTypeAndValue *)va_arg(ap, NSSPKIXAttributeTypeAndValue *);
      if( (NSSPKIXAttributeTypeAndValue *)NULL == atav ) {
        break;
      }

      if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
        va_end(ap);
        return (NSSPKIXRelativeDistinguishedName *)NULL;
      }
    }

    va_end(ap);
  }
#endif /* DEBUG */

  va_start(ap, arenaOpt);

  for( count = 0; ; count++ ) {
    NSSPKIXAttributeTypeAndValue *atav;
    atav = (NSSPKIXAttributeTypeAndValue *)va_arg(ap, NSSPKIXAttributeTypeAndValue *);
    if( (NSSPKIXAttributeTypeAndValue *)NULL == atav ) {
      break;
    }

#ifdef PEDANTIC
    if( count == 0xFFFFFFFF ) {
      nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
      va_end(ap);
      return (NSSPKIXAttributeTypeAndValue *)NULL;
    }
#endif /* PEDANTIC */
  }

  va_end(ap);

  va_start(ap, arenaOpt);
  rv = nss_pkix_RelativeDistinguishedName_V_Create(arenaOpt, count, ap);
  va_end(ap);

  return rv;
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
NSSPKIXRelativeDistinguishedName_CreateFromArray
(
  NSSArena *arenaOpt,
  PRUint32 count,
  NSSPKIXAttributeTypeAndValue *atavs[]
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXAttribute *)NULL;
    }
  }

  {
    PRUint32 i;

    for( i = 0; i < count; i++ ) {
      if( PR_SUCCESS != nssAttributeTypeAndValue_verifyPointer(&atavs[i]) ) {
        return (NSSPKIXAttribute *)NULL;
      }
    }
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_CreateFromArray(arenaOpt, count, atavs);
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
NSSPKIXRelativeDistinguishedName_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }

  if( (NSSUTF8 *)NULL == string ) {
    nss_SetError(NSS_ERROR_INVALID_STRING);
    return (NSSPKIXRelativeDistinguishedName *)NULL;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_CreateFromUTF8(arenaOpt, string);
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
NSSPKIXRelativeDistinguishedName_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }

  if( PR_SUCCESS != NSSItem_verifyPointer(ber) ) {
    return (NSSPKIXRelativeDistinguishedName *)NULL;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_Decode(arenaOpt, ber);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRelativeDistinguishedName_Destroy
(
  NSSPKIXRelativeDistinguishedName *rdn
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_Destroy(rdn);
}

NSS_IMPLEMENT NSSPKIXRelativeDistinguishedName *
NSSPKIXRelativeDistinguishedName_Duplicate
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSPKIXRelativeDistinguishedName *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXRelativeDistinguishedName *)NULL;
    }
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_Duplicate(rdn, arenaOpt);
}


NSS_IMPLEMENT NSSBER *
NSSPKIXRelativeDistinguishedName_Encode
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSBER *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSBER *)NULL;
    }
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_Encode(rdn, encoding, rvOpt, arenaOpt);
}

NSS_EXTERN PRBool
NSSPKIXRelativeDistinguishedName_Equal
(
  NSSPKIXRelativeDistinguishedName *one,
  NSSPKIXRelativeDistinguishedName *two,
  PRStatus *statusOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(one) ) {
    if( (PRStatus *)NULL != statusOpt ) {
      *statusOpt = PR_FAILURE;
    }

    return PR_FALSE;
  }

  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(two) ) {
    if( (PRStatus *)NULL != statusOpt ) {
      *statusOpt = PR_FAILURE;
    }

    return PR_FALSE;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_Equal(one, two, statusOpt);
}

NSS_EXTERN PRInt32
NSSPKIXRelativeDistinguishedName_FindAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *atav
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return PR_FAILURE;
  }

  if( PR_SUCCESS != nssPKIXAttributeTypeAndValue_verifyPointer(atav) ) {
    return PR_FAILURE;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_FindAttributeTypeAndValue(rdn, atav);
}

NSS_IMPLEMENT NSSPKIXAttributeTypeAndValue *
NSSPKIXRelativeDistinguishedName_GetAttributeTypeAndValue
(
  NSSPKIXRelativeDistinguishedName *rdn,
  PRInt32 i,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSPKIXAttributeTypeAndValue *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSPKIXAttributeTypeAndValue *)NULL;
    }
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_GetAttributeTypeAndValue(rdn, i, arenaOpt);
}

NSS_IMPLEMENT PRInt32
NSSPKIXRelativeDistinguishedName_GetAttributeTypeAndValueCount
(
  NSSPKIXRelativeDistinguishedName *rdn
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return -1;
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_GetAttributeTypeAndValueCount(rdn);
}


NSS_IMPLEMENT NSSPKIXAttributeTypeAndValue **
NSSPKIXRelativeDistinguishedName_GetAttributeTypeAndValues
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSPKIXAttributeTypeAndValue *rvOpt[],
  PRInt32 limit,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSPKIXAttributeTypeAndValue **)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyOpt(attribute) ) {
      return (NSSPKIXAttributeTypeAndValue **)NULL;
    }
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_GetAttributeTypeAndValues(rdn, rvOpt, limit, arenaOpt);
}

NSS_IMPLEMENT NSSUTF8 *
NSSPKIXRelativeDistinguishedName_GetUTF8Encoding
(
  NSSPKIXRelativeDistinguishedName *rdn,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG
  if( PR_SUCCESS != nssPKIXRelativeDistinguishedName_verifyPointer(rdn) ) {
    return (NSSUTF8 *)NULL;
  }

  if( (NSSArena *)NULL != arenaOpt ) {
    if( PR_SUCCESS != NSSArena_verifyPointer(arenaOpt) ) {
      return (NSSUTF8 *)NULL;
    }
  }
#endif /* DEBUG */

  return nssPKIXRelativeDistinguishedName_GetUTF8Encoding(rdn, arenaOpt);
}

