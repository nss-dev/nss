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
 * nssPKIXRDNSequence_template
 *
 */

/* XXX */
const NSSASN1Template nssPKIXRDN_template[] = {
  { NSSASN1_SET_OF, offsetof(NSSPKIXRDN, atavs),
    nssPKIXATAV_template, sizeof(NSSPKIXRDN) }
};

const NSSASN1Template nssPKIXRDNSequence_template[] = {
  { NSSASN1_SEQUENCE_OF, offsetof(NSSPKIXRDNSequence, rdns),
    nssPKIXRDN_template, sizeof(NSSPKIXRDNSequence) },
  { 0 }
};

static void
clear_me
(
  NSSPKIXRDNSequence *rdnseq
)
{
    memset(&rdnseq->der, 0, sizeof(rdnseq->der));
    rdnseq->utf8 = (NSSUTF8 *)NULL;
}

NSS_IMPLEMENT void
nss_pkix_RDNSequence_Count
(
  NSSPKIXRDNSequence *rdnseq
)
{
  PR_ASSERT((NSSPKIXRDN **)NULL != rdnseq->rdns);
  if( (NSSPKIXRDN **)NULL == rdnseq->rdns ) {
#if 0
    nss_SetError(NSS_ERROR_INTERNAL_ERROR);
#endif
    return;
  }

  if( 0 == rdnseq->count ) {
    PRUint32 i;
    for( i = 0; i < 0xFFFFFFFF; i++ ) {
      if( (NSSPKIXRDN *)NULL == rdnseq->rdns[i] ) {
        break;
      }
    }

#ifdef PEDANTIC
    if( 0xFFFFFFFF == i ) {
      return;
    }
#endif /* PEDANTIC */

    rdnseq->count = i;
  }

  return;
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
nss_pkix_RDNSequence_v_create
(
  NSSArena *arenaOpt,
  PRUint32 count,
  va_list ap
)
{
#if 0
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRDNSequence *rv = (NSSPKIXRDNSequence *)NULL;
  PRStatus status;
  PRUint32 i;

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

  rv = nss_ZNEW(arena, NSSPKIXRDNSequence);
  if( (NSSPKIXRDNSequence *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->count = count;

  rv->rdns = nss_ZNEWARRAY(arena, NSSPKIXRDN *, count);
  if( (NSSPKIXRDN **)NULL == rv->rdns ) {
    goto loser;
  }

  for( i = 0; i < count; i++ ) {
    NSSPKIXRDN *v = (NSSPKIXRDN *)
      va_arg(ap, NSSPKIXRDN *);

    rv->rdns[i] = nssPKIXRDN_Duplicate(v, arena);
    if( (NSSPKIXRDN *)NULL == rv->rdns[i] ) {
      goto loser;
    }
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

#endif
  return (NSSPKIXRDNSequence *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXRDNSequence_AppendRDN
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rdn
)
{
#if 0
  NSSPKIXRDN **na;
  NSSPKIXRDN *dup;

  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXRDN *)NULL;
  }
#endif /* PEDANTIC */

  na = (NSSPKIXRDN **)
    nss_ZRealloc(rdnseq->rdns, ((rdnseq->count+2) * 
      sizeof(NSSPKIXRDN *)));
  if( (NSSPKIXRDN **)NULL == na ) {
    return PR_FAILURE;
  }

  rdnseq->rdns = na;

  dup = nssPKIXRDN_Duplicate(rdn, rdnseq->arena);
  if( (NSSPKIXRDN *)NULL == dup ) {
    return PR_FAILURE;
  }

  na[ rdnseq->count++ ] = dup;

  clear_me(rdnseq);
  return PR_SUCCESS;
#endif
  return PR_FAILURE;
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
nssPKIXRDNSequence_Create
(
  NSSArena *arenaOpt,
  NSSPKIXRDN *rdn1,
  ...
)
{
  va_list ap;
  NSSPKIXRDNSequence *rv;
  PRUint32 count;

  va_start(ap, rdn1);

  for( count = 0; ; count++ ) {
    NSSPKIXRDN *rdn;
    rdn = (NSSPKIXRDN *)va_arg(ap, NSSPKIXRDN *);
    if( (NSSPKIXRDN *)NULL == rdn ) {
      break;
    }

#ifdef PEDANTIC
    if( count == 0xFFFFFFFF ) {
      nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
      va_end(ap);
      return (NSSPKIXRDN *)NULL;
    }
#endif /* PEDANTIC */
  }

  va_end(ap);

  va_start(ap, rdn1);
  rv = nss_pkix_RDNSequence_v_create(arenaOpt, count, ap);
  va_end(ap);

  return rv;
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
nssPKIXRDNSequence_CreateFromArray
(
  NSSArena *arenaOpt,
  PRUint32 count,
  NSSPKIXRDN **rdns
)
{
#if 0
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRDNSequence *rv = (NSSPKIXRDNSequence *)NULL;
  PRStatus status;
  PRUint32 i;

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

  rv = nss_ZNEW(arena, NSSPKIXRDNSequence);
  if( (NSSPKIXRDNSequence *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->count = count;

  rv->rdns = nss_ZNEWARRAY(arena, NSSPKIXRDN *, (count+1));
  if( (NSSPKIXRDN **)NULL == rv->rdns ) {
    goto loser;
  }

  for( i = 0; i < count; i++ ) {
    NSSPKIXRDN *v = rdns[i];

    rv->rdns[i] = nssPKIXRDN_Duplicate(v, arena);
    if( (NSSPKIXRDN *)NULL == rv->rdns[i] ) {
      goto loser;
    }
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

#endif
  return (NSSPKIXRDNSequence *)NULL;
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
nssPKIXRDNSequence_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
#if 0
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRDNSequence *rv = (NSSPKIXRDNSequence *)NULL;
  PRStatus status;
  PRUint32 i;

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

  rv = nss_ZNEW(arena, NSSPKIXRDNSequence);
  if( (NSSPKIXRDNSequence *)NULL == rv ) {
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

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

#endif
  return (NSSPKIXRDNSequence *)NULL;
}

NSS_IMPLEMENT void
nssPKIXRDNSequence_SetArena
(
  NSSPKIXRDNSequence *rdnseq,
  NSSArena *arena
)
{
    rdnseq->arena = arena;
#if 0
    foreach ...
#endif
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
nssPKIXRDNSequence_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRDNSequence *rv = (NSSPKIXRDNSequence *)NULL;
  PRStatus status;

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

  rv = nss_ZNEW(arena, NSSPKIXRDNSequence);
  if( (NSSPKIXRDNSequence *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;

  status = NSSASN1_DecodeBER(arena, rv, nssPKIXRDNSequence_template, ber);
  if( PR_SUCCESS != status ) {
    goto loser;
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

  return (NSSPKIXRDNSequence *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXRDNSequence_Destroy
(
  NSSPKIXRDNSequence *rdnseq
)
{
  if( PR_TRUE == rdnseq->i_allocated_arena ) {
    return NSSArena_Destroy(rdnseq->arena);
  }

  return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
nssPKIXRDNSequence_Duplicate
(
  NSSPKIXRDNSequence *rdnseq,
  NSSArena *arenaOpt
)
{
#if 0
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXRDNSequence *rv = (NSSPKIXRDNSequence *)NULL;
  PRStatus status;
  PRUint32 i;

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

  rv = nss_ZNEW(arena, NSSPKIXRDNSequence);
  if( (NSSPKIXRDNSequence *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;

  if( (NSSDER *)NULL != rdnseq->der ) {
    rv->der = NSSItem_Duplicate(rdnseq->der, arena, (NSSItem *)NULL);
    if( (NSSDER *)NULL == rv->der ) {
      goto loser;
    }
  }

  if( (NSSUTF8 *)NULL != rdnseq->utf8 ) {
    rv->utf8 = NSSUTF8_Duplicate(rdnseq->utf8, arena);
    if( (NSSUTF8 *)NULL == rv->utf8 ) {
      goto loser;
    }
  }

  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXRDN *)NULL;
  }
#endif /* PEDANTIC */

  rv->count = rdnseq->count;

  rv->rdns = nss_ZNEWARRAY(arena, NSSPKIXRDN *, (rv->count+1));
  if( (NSSPKIXRDN **)NULL == rv->rdns ) {
    goto loser;
  }

  for( i = 0; i < rdnseq->count; i++ ) {
    NSSPKIXRDN *v = rdnseq->rdns[i];

    rv->rdns[i] = nssPKIXRDN_Duplicate(v, arena);
    if( (NSSPKIXRDN *)NULL == rv->rdns[i] ) {
      goto loser;
    }
  }

  if( (nssArenaMark *)NULL != mark ) {
    if( PR_SUCCESS != nssArena_Unmark(arena, mark) ) {
      goto loser;
    }
  }

  return rv;

 loser:
  if( (nssArenaMark *)NULL != mark ) {
    (void)nssArena_Release(arena, mark);
  }

  if( PR_TRUE == arena_allocated ) {
    (void)NSSArena_Destroy(arena);
  }

#endif
  return (NSSPKIXRDNSequence *)NULL;
}

NSS_IMPLEMENT NSSBER *
nssPKIXRDNSequence_Encode
(
  NSSPKIXRDNSequence *rdnseq,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  NSSBER *it;

  switch( encoding ) {
  case NSSASN1BER:
  case NSSASN1DER:
    if( (NSSDER *)NULL != rdnseq->der ) {
      it = rdnseq->der;
      goto done;
    }
    break;
  default:
#if 0
    nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
    return (NSSBER *)NULL;
  }

  it = NSSASN1_EncodeItem(rdnseq->arena, (NSSItem *)NULL, rdnseq,
                          nssPKIXRDNSequence_template, encoding);
  if( (NSSBER *)NULL == it ) {
    return (NSSBER *)NULL;
  }

  switch( encoding ) {
  case NSSASN1BER:
  case NSSASN1DER:
    rdnseq->der = it;
    break;
  default:
    PR_ASSERT(0);
    break;
  }

 done:
  return NSSItem_Duplicate(it, arenaOpt, rvOpt);
}

NSS_IMPLEMENT PRBool
nssPKIXRDNSequence_Equal
(
  NSSPKIXRDNSequence *one,
  NSSPKIXRDNSequence *two,
  PRStatus *statusOpt
)
{
  NSSPKIXRDN **a;
  NSSPKIXRDN **b;

  if( ((NSSDER *)NULL != one->der) && ((NSSDER *)NULL != two->der) ) {
    return NSSItem_Equal(one->der, two->der, statusOpt);
  }

  /*
   * Since this is a sequence, the order is significant.
   * So we just walk down both lists, comparing.
   */

  for( a = one->rdns, b = two->rdns; *a && *b; a++, b++ ) {
#if 0
    if( PR_FALSE == nssPKIXRDN_Equal(*a, *b, statusOpt) ) {
      return PR_FALSE;
    }
#endif
  }

  if( (PRStatus *)NULL != statusOpt ) {
    *statusOpt = PR_SUCCESS;
  }

  if( *a || *b ) {
    return PR_FALSE;
  }

  return PR_TRUE;
}

NSS_IMPLEMENT PRInt32
nssPKIXRDNSequence_FindRDN
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rdn
)
{
#if 0
  PRUint32 i;
  NSSPKIXRDN **a;

  for( i = 0, a = rdnseq->rdns; *a; a++, (i > 0x7fffffff) || i++ ) {
    if( PR_TRUE == nssPKIXRDN_Equal(*a, rdn) ) {
      if( i > 0x7fffffff ) {
        nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
        return -1;
      }
      return (PRInt32)i;
    }
  }

  nss_SetError(NSS_ERROR_NOT_FOUND);
#endif
  return -1;
}

NSS_IMPLEMENT NSSPKIXRDN *
nssPKIXRDNSequence_GetRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i,
  NSSArena *arenaOpt
)
{
  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXRDN *)NULL;
  }
#endif /* PEDANTIC */

  if( (i < 0) || (i >= rdnseq->count) ) {
#if 0
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
#endif
    return (NSSPKIXRDN *)NULL;
  }

  return rdnseq->rdns[i];
}

NSS_IMPLEMENT PRInt32
nssPKIXRDNSequence_GetRDNCount
(
  NSSPKIXRDNSequence *rdnseq
)
{
  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return -1;
  }
#endif /* PEDANTIC */

  if( rdnseq->count > 0x7fffffff ) {
#if 0
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
#endif
    return -1;
  }

  return (PRInt32)(rdnseq->count);
}

NSS_IMPLEMENT NSSPKIXRDN **
nssPKIXRDNSequence_GetRDNs
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rvOpt[],
  PRInt32 limit,
  NSSArena *arenaOpt
)
{
#if 0
  NSSPKIXRDN **rv = (NSSPKIXRDN **)NULL;
  PRUint32 i;

  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXRDN **)NULL;
  }
#endif /* PEDANTIC */

  if( (limit < rdnseq->count) &&
      !((0 == limit) && ((NSSPKIXRDN **)NULL == rvOpt)) ) {
    nss_SetError(NSS_ERROR_ARRAY_TOO_SMALL);
    return (NSSPKIXRDN **)NULL;
  }

  limit = rdnseq->count;
  if( (NSSPKIXRDN **)NULL == rvOpt ) {
    rv = nss_ZNEWARRAY(arenaOpt, NSSPKIXRDN *, limit);
    if( (NSSPKIXRDN **)NULL == rv ) {
      return (NSSPKIXRDN **)NULL;
    }
  } else {
    rv = rvOpt;
  }

  for( i = 0; i < limit; i++ ) {
    rv[i] = nssPKIXRDN_Duplicate(rdnseq->rdns[i], arenaOpt);
    if( (NSSPKIXRDN *)NULL == rv[i] ) {
      goto loser;
    }
  }

  return rv;

 loser:
  for( i = 0; i < limit; i++ ) {
    NSSPKIXRDN *x = rv[i];
    if( (NSSPKIXRDN *)NULL == x ) {
      break;
    }
    (void)nssPKIXRDN_Destroy(x);
  }

  if( rv != rvOpt ) {
    nss_ZFreeIf(rv);
  }

#endif
  return (NSSPKIXRDN **)NULL;
}

NSS_IMPLEMENT NSSUTF8 *
nssPKIXRDNSequence_GetUTF8Encoding
(
  NSSPKIXRDNSequence *rdnseq,
  NSSArena *arenaOpt
)
{
  if( (NSSUTF8 *)NULL == rdnseq->utf8 ) {
    /* xxx fgmr fill this in from pki1 implementation */
  }

  return NSSUTF8_Duplicate(rdnseq->utf8, arenaOpt);
}

NSS_IMPLEMENT PRStatus
nssPKIXRDNSequence_InsertRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i,
  NSSPKIXRDN *rdn
)
{
  NSSPKIXRDN **na;
  NSSPKIXRDN *dup;
  PRInt32 c;

  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXRDN *)NULL;
  }
#endif /* PEDANTIC */

  if( (i < 0) || (i >= rdnseq->count) ) {
#if 0
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
#endif
    return PR_FAILURE;
  }

  na = (NSSPKIXRDN **)
    nss_ZRealloc(rdnseq->rdns, ((rdnseq->count+2) * 
      sizeof(NSSPKIXRDN *)));
  if( (NSSPKIXRDN **)NULL == na ) {
    return PR_FAILURE;
  }

  rdnseq->rdns = na;

#if 0
  dup = nssPKIXRDN_Duplicate(rdn, rdnseq->arena);
#endif
  if( (NSSPKIXRDN *)NULL == dup ) {
    return PR_FAILURE;
  }

  for( c = rdnseq->count; c > i; c-- ) {
    na[ c ] = na[ c-1 ];
  }

  na[ i ] = dup;
  rdnseq->count++;

  clear_me(rdnseq);
  return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssPKIXRDNSequence_RemoveRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i
)
{
#if 0
  NSSPKIXRDN **na;
  PRInt32 c;

  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXRDN *)NULL;
  }
#endif /* PEDANTIC */

  if( (i < 0) || (i >= rdnseq->count) ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return PR_FAILURE;
  }

  nssPKIXRDN_Destroy(rdnseq->rdns[i]);

  rdnseq->rdns[i] = rdnseq->rdns[ rdnseq->count ];
  rdnseq->rdns[ rdnseq->count ] = (NSSPKIXRDN *)NULL;
  rdnseq->count--;

  na = (NSSPKIXRDN **)
    nss_ZRealloc(rdnseq->rdns, ((rdnseq->count) * 
      sizeof(NSSPKIXRDN *)));
  if( (NSSPKIXRDN **)NULL == na ) {
    return PR_FAILURE;
  }

  rdnseq->rdns = na;

  clear_me(rdnseq);
  return PR_SUCCESS;
#endif
  return PR_FAILURE;
}

NSS_IMPLEMENT PRStatus
nssPKIXRDNSequence_SetRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i,
  NSSPKIXRDN *rdn
)
{
  NSSPKIXRDN *dup;

  if( 0 == rdnseq->count ) {
    nss_pkix_RDNSequence_Count(rdnseq);
  }

#ifdef PEDANTIC
  if( 0 == rdnseq->count ) {
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
    return (NSSPKIXRDN *)NULL;
  }
#endif /* PEDANTIC */

  if( (i < 0) || (i >= rdnseq->count) ) {
#if 0
    nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
#endif
    return PR_FAILURE;
  }

#if 0
  dup = nssPKIXRDN_Duplicate(rdn, rdnseq->arena);
  if( (NSSPKIXRDN *)NULL == dup ) {
    return PR_FAILURE;
  }

  nssPKIXRDN_Destroy(rdnseq->rdns[i]);
#endif
  rdnseq->rdns[i] = dup;

  clear_me(rdnseq);
  return PR_SUCCESS;
}

NSS_IMPLEMENT PRStatus
nssPKIXRDNSequence_SetRDNs
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rdns[],
  PRInt32 countOpt
)
{
#if 0
  NSSPKIXRDN **ip;
  NSSPKIXRDN **newarray;
  PRUint32 i;
  nssArenaMark *mark;

#ifdef NSSDEBUG

  {
    PRUint32 i, count;

    if( 0 == countOpt ) {
      for( i = 0; i < 0x80000000; i++ ) {
        if( (NSSPKIXRDN *)NULL == rdns[i] ) {
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

  }
#endif /* NSSDEBUG */

  mark = nssArena_Mark(rdnseq->arena);
  if( (nssArenaMark *)NULL == mark ) {
    return PR_FAILURE;
  }

  newarray = nss_ZNEWARRAY(rdnseq->arena, NSSPKIXRDN *, countOpt);
  if( (NSSPKIXRDN **)NULL == newarray ) {
    goto loser;
  }

  for( i = 0; i < countOpt; i++ ) {
    newarray[i] = nssPKIXRDN_Duplicate(rdns[i], rdnseq->arena);
    if( (NSSPKIXRDN *)NULL == newarray[i] ) {
      goto loser;
    }
  }

  for( i = 0; i < rdnseq->count; i++ ) {
    if( PR_SUCCESS != nssPKIXRDN_Destroy(rdnseq->rdns[i]) ) {
      goto loser;
    }
  }

  nss_ZFreeIf(rdnseq->rdns);

  rdnseq->count = countOpt;
  rdnseq->rdns = newarray;

  clear_me(rdnseq);

  return nssArena_Unmark(rdnseq->arena, mark);

 loser:
  (void)nssArena_Release(rdnseq->arena, mark);
#endif
  return PR_FAILURE;
}


NSS_IMPLEMENT PRStatus
NSSPKIXRDNSequence_RemoveRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_RemoveRDN(rdnseq, i);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRDNSequence_SetRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i,
  NSSPKIXRDN *rdn
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_SetRDN(rdnseq, i, rdn);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRDNSequence_SetRDNs
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rdns[],
  PRInt32 countOpt
)
{
  nss_ClearErrorStack();

#ifdef DEBUG

  if( (NSSPKIXRDN **)NULL == rdns ) {
#if 0
    nss_SetError(NSS_ERROR_INVALID_POINTER);
#endif
    return PR_FAILURE;
  }

  {
    PRUint32 i, count;

    if( 0 == countOpt ) {
      for( i = 0; i < 0x80000000; i++ ) {
        if( (NSSPKIXRDN *)NULL == rdns[i] ) {
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
#if 0
        nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
#endif
        return PR_FAILURE;
      }

      count = (PRUint32)countOpt;
    }

  }
#endif /* DEBUG */

  return nssPKIXRDNSequence_SetRDNs(rdnseq, rdns, countOpt);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRDNSequence_AppendRDN
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rdn
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_AppendRDN(rdnseq, rdn);
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
NSSPKIXRDNSequence_Create
(
  NSSArena *arenaOpt,
  NSSPKIXRDN *rdn1,
  ...
)
{
  va_list ap;
  NSSPKIXRDNSequence *rv;
  PRUint32 count;

  nss_ClearErrorStack();

  va_start(ap, rdn1);

  for( count = 0; ; count++ ) {
    NSSPKIXRDN *rdn;
    rdn = (NSSPKIXRDN *)va_arg(ap, NSSPKIXRDN *);
    if( (NSSPKIXRDN *)NULL == rdn ) {
      break;
    }

#ifdef PEDANTIC
    if( count == 0xFFFFFFFF ) {
      nss_SetError(NSS_ERROR_VALUE_OUT_OF_RANGE);
      va_end(ap);
      return (NSSPKIXRDN *)NULL;
    }
#endif /* PEDANTIC */
  }

  va_end(ap);

  va_start(ap, rdn1);
  rv = nss_pkix_RDNSequence_v_create(arenaOpt, count, ap);
  va_end(ap);

  return rv;
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
NSSPKIXRDNSequence_CreateFromArray
(
  NSSArena *arenaOpt,
  PRUint32 count,
  NSSPKIXRDN *rdns[]
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_CreateFromArray(arenaOpt, count, rdns);
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
NSSPKIXRDNSequence_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_CreateFromUTF8(arenaOpt, string);
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
NSSPKIXRDNSequence_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_Decode(arenaOpt, ber);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRDNSequence_Destroy
(
  NSSPKIXRDNSequence *rdnseq
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_Destroy(rdnseq);
}

NSS_IMPLEMENT NSSPKIXRDNSequence *
NSSPKIXRDNSequence_Duplicate
(
  NSSPKIXRDNSequence *rdnseq,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_Duplicate(rdnseq, arenaOpt);
}

NSS_IMPLEMENT NSSBER *
NSSPKIXRDNSequence_Encode
(
  NSSPKIXRDNSequence *rdnseq,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_Encode(rdnseq, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRBool
NSSPKIXRDNSequence_Equal
(
  NSSPKIXRDNSequence *one,
  NSSPKIXRDNSequence *two,
  PRStatus *statusOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_Equal(one, two, statusOpt);
}

NSS_IMPLEMENT PRInt32
NSSPKIXRDNSequence_FindRDN
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rdn
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_FindRDN(rdnseq, rdn);
}

NSS_IMPLEMENT NSSPKIXRDN *
NSSPKIXRDNSequence_GetRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_GetRDN(rdnseq, i, arenaOpt);
}

NSS_IMPLEMENT PRInt32
NSSPKIXRDNSequence_GetRDNCount
(
  NSSPKIXRDNSequence *rdnseq
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_GetRDNCount(rdnseq);
}

NSS_IMPLEMENT NSSPKIXRDN **
NSSPKIXRDNSequence_GetRDNs
(
  NSSPKIXRDNSequence *rdnseq,
  NSSPKIXRDN *rvOpt[],
  PRInt32 limit,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_GetRDNs(rdnseq, rvOpt, limit, arenaOpt);
}

NSS_IMPLEMENT NSSUTF8 *
NSSPKIXRDNSequence_GetUTF8Encoding
(
  NSSPKIXRDNSequence *rdnseq,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_GetUTF8Encoding(rdnseq, arenaOpt);
}

NSS_IMPLEMENT PRStatus
NSSPKIXRDNSequence_InsertRDN
(
  NSSPKIXRDNSequence *rdnseq,
  PRInt32 i,
  NSSPKIXRDN *rdn
)
{
  nss_ClearErrorStack();

  return nssPKIXRDNSequence_InsertRDN(rdnseq, i, rdn);
}
