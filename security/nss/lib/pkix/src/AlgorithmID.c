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
 * nssPKIXAlgorithmIdentifier_template
 *
 */

const NSSASN1Template nssPKIXAlgorithmIdentifier_template[] = 
{
 { NSSASN1_SEQUENCE,   0, NULL, sizeof(NSSPKIXAlgorithmIdentifier)      },
 { NSSASN1_OBJECT_ID,  offsetof(NSSPKIXAlgorithmIdentifier, algID)      },
 { NSSASN1_OPTIONAL |
    NSSASN1_ANY,       offsetof(NSSPKIXAlgorithmIdentifier, parameters) },
 { 0 }
};

static PRStatus
decode_me(NSSPKIXAlgorithmIdentifier *algid)
{
    if (!NSSITEM_IS_EMPTY(&algid->der)) {
	return NSSASN1_DecodeBER(algid->arena, algid, 
	                         nssPKIXAlgorithmIdentifier_template, 
	                         &algid->der);
    } else {
	return PR_FAILURE;
    }
}

NSS_IMPLEMENT PRStatus
nss_pkix_AlgorithmIdentifier_Clear
(
  NSSPKIXAlgorithmIdentifier *algid
)
{
  /* XXX */
  return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
nssPKIXAlgorithmIdentifier_Create
(
  NSSArena *arenaOpt,
  NSSOID *algorithm,
  NSSItem *parameters
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXAlgorithmIdentifier *rv = (NSSPKIXAlgorithmIdentifier *)NULL;

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

  rv = nss_ZNEW(arena, NSSPKIXAlgorithmIdentifier);
  if( (NSSPKIXAlgorithmIdentifier *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  /* XXX */
#if 0
  rv->algorithm = algorithm;
  rv->parameters = NSSItem_Duplicate(parameters, arena, (NSSItem *)NULL);
  if( (NSSItem *)NULL == rv->parameters ) {
    goto loser;
  }
#endif

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

  return (NSSPKIXAlgorithmIdentifier *)NULL;
}

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
nssPKIXAlgorithmIdentifier_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXAlgorithmIdentifier *rv = (NSSPKIXAlgorithmIdentifier *)NULL;
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

  rv = nss_ZNEW(arena, NSSPKIXAlgorithmIdentifier);
  if( (NSSPKIXAlgorithmIdentifier *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->der = *ber;

  status = NSSASN1_DecodeBER(arena, rv, 
                             nssPKIXAlgorithmIdentifier_template, ber);
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

  return (NSSPKIXAlgorithmIdentifier *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXAlgorithmIdentifier_Destroy
(
  NSSPKIXAlgorithmIdentifier *algid
)
{
  if( PR_TRUE == algid->i_allocated_arena ) {
    return NSSArena_Destroy(algid->arena);
  }

  return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
nssPKIXAlgorithmIdentifier_Duplicate
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSArena *arenaOpt
)
{
#if 0
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXAlgorithmIdentifier *rv = (NSSPKIXAlgorithmIdentifier *)NULL;

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

  rv = nss_ZNEW(arena, NSSPKIXAlgorithmIdentifier);
  if( (NSSPKIXAlgorithmIdentifier *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;

  rv->der = NSSItem_Duplicate(algid->der, arena, (NSSItem *)NULL);
  if( (NSSItem *)NULL == rv->der ) {
    goto loser;
  }

  rv->algorithm = algid->algorithm;

  rv->parameters = NSSItem_Duplicate(algid->parameters, arena, (NSSItem *)NULL);
  if( (NSSItem *)NULL == rv->parameters ) {
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

#endif
  return (NSSPKIXAlgorithmIdentifier *)NULL;
}

NSS_IMPLEMENT NSSBER *
nssPKIXAlgorithmIdentifier_Encode
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  NSSItem *it;

  switch( encoding ) {
  case NSSASN1BER:
  case NSSASN1DER:
    if (!NSSITEM_IS_EMPTY(&algid->der)) {
      it = &algid->der;
      goto done;
    }
    break;
  default:
#if 0
    nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
    return (NSSBER *)NULL;
  }

  it = NSSASN1_EncodeItem(algid->arena, (NSSItem *)NULL, algid,
                          nssPKIXAlgorithmIdentifier_template, encoding);
  if( (NSSBER *)NULL == it ) {
    return (NSSBER *)NULL;
  }

  switch( encoding ) {
  case NSSASN1BER:
  case NSSASN1DER:
    algid->der = *it;
    break;
  default:
    PR_ASSERT(0);
    break;
  }

 done:
  return NSSItem_Duplicate(it, arenaOpt, rvOpt);
}

NSS_IMPLEMENT PRBool
nssPKIXAlgorithmIdentifier_Equal
(
  NSSPKIXAlgorithmIdentifier *algid1,
  NSSPKIXAlgorithmIdentifier *algid2,
  PRStatus *statusOpt
)
{
#if 0
  if( algid1->algorithm != algid2->algorithm ) {
    if( (PRStatus *)NULL != statusOpt ) {
      *statusOpt = PR_SUCCESS;
    }
    return PR_FALSE;
  }

  return nssItem_Equal(algid1->parameters, algid2->parameters, statusOpt);
#endif
  return PR_FALSE;
}

NSS_IMPLEMENT NSSOID *
nssPKIXAlgorithmIdentifier_GetAlgorithm
(
  NSSPKIXAlgorithmIdentifier *algid
)
{
    if (NSSITEM_IS_EMPTY(&algid->algID)) {
	if (NSSITEM_IS_EMPTY(&algid->der) ||
	    decode_me(algid) == PR_FAILURE)
	{
	    return (NSSOID *)NULL;
	}
    }
    return NSSOID_Create(&algid->algID);
}

NSS_IMPLEMENT NSSItem *
nssPKIXAlgorithmIdentifier_GetParameters
(
  NSSPKIXAlgorithmIdentifier *algid
)
{
    if (NSSITEM_IS_EMPTY(&algid->algID)) {
	if (NSSITEM_IS_EMPTY(&algid->der) ||
	    decode_me(algid) == PR_FAILURE)
	{
	    return (NSSItem *)NULL;
	}
    }
  return &algid->parameters;
}

NSS_IMPLEMENT PRStatus
nssPKIXAlgorithmIdentifier_SetAlgorithm
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSOID *algorithm
)
{
#if 0
  algid->algorithm = algorithm;
#endif
  return nss_pkix_AlgorithmIdentifier_Clear(algid);
}

NSS_IMPLEMENT PRStatus
nssPKIXAlgorithmIdentifier_SetParameters
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSItem *parameters
)
{
  algid->parameters = *parameters;
  return nss_pkix_AlgorithmIdentifier_Clear(algid);
}

NSS_IMPLEMENT PRStatus
NSSPKIXAlgorithmIdentifier_SetAlgorithm
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSOID *algorithm
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_SetAlgorithm(algid, algorithm);
}

NSS_IMPLEMENT PRStatus
NSSPKIXAlgorithmIdentifier_SetParameters
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSItem *parameters
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_SetParameters(algid, parameters);
}

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
NSSPKIXAlgorithmIdentifier_Create
(
  NSSArena *arenaOpt,
  NSSOID *algorithm,
  NSSItem *parameters
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_Create(arenaOpt, algorithm, parameters);
}

NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
NSSPKIXAlgorithmIdentifier_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_Decode(arenaOpt, ber);
}

NSS_IMPLEMENT PRStatus
NSSPKIXAlgorithmIdentifier_Destroy
(
  NSSPKIXAlgorithmIdentifier *algid
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_Destroy(algid);
}


NSS_IMPLEMENT NSSPKIXAlgorithmIdentifier *
NSSPKIXAlgorithmIdentifier_Duplicate
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_Duplicate(algid, arenaOpt);
}

NSS_IMPLEMENT NSSBER *
NSSPKIXAlgorithmIdentifier_Encode
(
  NSSPKIXAlgorithmIdentifier *algid,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_Encode(algid, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRBool
NSSPKIXAlgorithmIdentifier_Equal
(
  NSSPKIXAlgorithmIdentifier *algid1,
  NSSPKIXAlgorithmIdentifier *algid2,
  PRStatus *statusOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_Equal(algid1, algid2, statusOpt);
}

NSS_IMPLEMENT NSSOID *
NSSPKIXAlgorithmIdentifier_GetAlgorithm
(
  NSSPKIXAlgorithmIdentifier *algid
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_GetAlgorithm(algid);
}

NSS_IMPLEMENT NSSItem *
NSSPKIXAlgorithmIdentifier_GetParameters
(
  NSSPKIXAlgorithmIdentifier *algid
)
{
  nss_ClearErrorStack();

  return nssPKIXAlgorithmIdentifier_GetParameters(algid);
}

