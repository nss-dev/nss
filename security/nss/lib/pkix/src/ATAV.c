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
 * nssPKIXATAV_template
 *
 */

const NSSASN1Template nssPKIXATAV_template[] = {
  { NSSASN1_SEQUENCE,  0, NULL, sizeof(NSSPKIXATAV) },
  { NSSASN1_OBJECT_ID, offsetof(NSSPKIXATAV, type)  },
  { NSSASN1_ANY,       offsetof(NSSPKIXATAV, value) },
  { 0 }
};

NSS_IMPLEMENT PRStatus
nss_pkix_AttributeTypeAndValue_Clear
(
  NSSPKIXATAV *atav
)
{

  if( (NSSDER *)NULL != atav->der ) {
    nss_ZFreeIf(atav->der->data);
    nss_ZFreeIf(atav->der);
  }

  nss_ZFreeIf(atav->utf8);

  return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXATAV *
nssPKIXATAV_Create
(
  NSSArena *arenaOpt,
  NSSPKIXAttributeType *typeOid,
  NSSPKIXAttributeValue *value
)
{
#if 0
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXATAV *rv = (NSSPKIXATAV *)NULL;

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

  rv = nss_ZNEW(arena, NSSPKIXATAV);
  if( (NSSPKIXATAV *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->type = typeOid;

  {
    NSSItem tmp;
    if( (NSSItem *)NULL == nssOID_GetDEREncoding(typeOid, arena, &tmp) ) {
      goto loser;
    }

    rv->type.size = tmp.size;
    rv->type.data = tmp.data;
  }

  {
    NSSItem tmp;
    if( (NSSItem *)NULL == NSSItem_Duplicate(value, arena, &tmp) ) {
      goto loser;
    }

    rv->value.size = tmp.size;
    rv->value.data = tmp.data;
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

  return (NSSPKIXATAV *)NULL;
}

NSS_IMPLEMENT NSSPKIXATAV *
nssPKIXATAV_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXATAV *rv = (NSSPKIXATAV *)NULL;

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

  rv = nss_ZNEW(arena, NSSPKIXATAV);
  if( (NSSPKIXATAV *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  rv->utf8 = NSSUTF8_Duplicate(string, arena);
  if( (NSSUTF8 *)NULL == rv->utf8 ) {
    goto loser;
  }
  
  /* Fill this in later from ../pki1/atav.c implementation */
#if 0
  nss_SetError(NSS_ERROR_INTERNAL_ERROR);
#endif
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

  return (NSSPKIXATAV *)NULL;
}

/*
 * nssPKIXATAV_Decode
 *
 * 
 *
 * The error may be one of the following values:
 *  NSS_ERROR_INVALID_BER
 *  NSS_ERROR_NO_MEMORY
 *  NSS_ERROR_INVALID_ARENA
 *
 * Return value:
 *  A valid pointer to an NSSPKIXATAV upon success
 *  NULL upon failure
 */

NSS_IMPLEMENT NSSPKIXATAV *
nssPKIXATAV_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXATAV *rv = (NSSPKIXATAV *)NULL;
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

  rv = nss_ZNEW(arena, NSSPKIXATAV);
  if( (NSSPKIXATAV *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;
  /* For this object, BER is DER */
  rv->der = NSSItem_Duplicate(ber, arena, (NSSItem *)NULL);
  if( (NSSItem *)NULL == rv->der ) {
    goto loser;
  }

  status = NSSASN1_DecodeBER(arena, rv, 
                             nssPKIXATAV_template,
                             ber);
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

  return (NSSPKIXATAV *)NULL;
}

NSS_IMPLEMENT PRStatus
nssPKIXATAV_Destroy
(
  NSSPKIXATAV *atav
)
{
  if( PR_TRUE == atav->i_allocated_arena ) {
    return NSSArena_Destroy(atav->arena);
  }

  return PR_SUCCESS;
}

NSS_IMPLEMENT NSSPKIXATAV *
nssPKIXATAV_Duplicate
(
  NSSPKIXATAV *atav,
  NSSArena *arenaOpt
)
{
  NSSArena *arena;
  PRBool arena_allocated = PR_FALSE;
  nssArenaMark *mark = (nssArenaMark *)NULL;
  NSSPKIXATAV *rv = (NSSPKIXATAV *)NULL;

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

  rv = nss_ZNEW(arena, NSSPKIXATAV);
  if( (NSSPKIXATAV *)NULL == rv ) {
    goto loser;
  }

  rv->arena = arena;
  rv->i_allocated_arena = arena_allocated;

  if( (NSSDER *)NULL != atav->der ) {
    rv->der = NSSItem_Duplicate(atav->der, arena, (NSSItem *)NULL);
    if( (NSSDER *)NULL == rv->der ) {
      goto loser; /* actually, this isn't fatal */
    }
  }

  {
    NSSItem src, dst;
    src.size = atav->type.size;
    src.data = atav->type.data;
    if( (NSSItem *)NULL == NSSItem_Duplicate(&src, arena, &dst) ) {
      goto loser;
    }
    rv->type.size = dst.size;
    rv->type.data = dst.data;
  }

  {
    NSSItem src, dst;
    src.size = atav->value.size;
    src.data = atav->value.data;
    if( (NSSItem *)NULL == NSSItem_Duplicate(&src, arena, &dst) ) {
      goto loser;
    }
    rv->value.size = dst.size;
    rv->value.data = dst.data;
  }

  rv->type = atav->type;

  if( (NSSUTF8 *)NULL != atav->utf8 ) {
    rv->utf8 = NSSUTF8_Duplicate(atav->utf8, arena);
    if( (NSSUTF8 *)NULL == rv->utf8 ) {
      goto loser; /* actually, this isn't fatal */
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

  return (NSSPKIXATAV *)NULL;
}

NSS_EXTERN NSSBER *
nssPKIXATAV_Encode
(
  NSSPKIXATAV *atav,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  switch( encoding ) {
  case NSSASN1BER:
  case NSSASN1DER:
    break;
  case NSSASN1CER:
  case NSSASN1LWER:
  case NSSASN1PER:
  default:
#if 0
    nss_SetError(NSS_ERROR_UNSUPPORTED_ENCODING);
#endif
    return (NSSBER *)NULL;
  }

  /* For this item its DER is BER */

  if( (NSSDER *)NULL == atav->der ) {
    atav->der = NSSASN1_EncodeItem(atav->arena, (NSSItem *)NULL, atav,
                  nssPKIXATAV_template, NSSASN1DER);
    if( (NSSDER *)NULL == atav->der ) {
      return (NSSBER *)NULL;
    }
  }

  return NSSItem_Duplicate(atav->der, arenaOpt, rvOpt);
}

NSS_IMPLEMENT PRBool
nssPKIXATAV_Equal
(
  NSSPKIXATAV *atav1,
  NSSPKIXATAV *atav2,
  PRStatus *statusOpt
)
{
  NSSItem one, two;

  if( (PRStatus *)NULL != statusOpt ) {
    *statusOpt = PR_SUCCESS;
  }

  one.size = atav1->type.size;
  one.data = atav1->type.data;
  two.size = atav2->type.size;
  two.data = atav2->type.data;

  if( PR_FALSE == NSSItem_Equal(&one, &two, statusOpt) ) {
    return PR_FALSE;
  }

  one.size = atav1->value.size;
  one.data = atav1->value.data;
  two.size = atav2->value.size;
  two.data = atav2->value.data;

  return NSSItem_Equal(&one, &two, statusOpt);
}

NSS_IMPLEMENT NSSPKIXAttributeType *
nssPKIXATAV_GetType
(
  NSSPKIXATAV *atav
)
{

#if 0
  if( (NSSPKIXAttributeType *)NULL == atav->type ) {
    NSSItem ber;

    ber.size = atav->type.size;
    ber.data = atav->type.data;

    atav->type = (NSSPKIXAttributeType *)NSSOID_CreateFromBER(&ber);
  }

  return atav->type;
#endif
  return NULL;
}

NSS_IMPLEMENT NSSUTF8 *
nssPKIXATAV_GetUTF8Encoding
(
  NSSPKIXATAV *atav,
  NSSArena *arenaOpt
)
{

  if( (NSSUTF8 *)NULL == atav->utf8 ) {
    /* xxx fgmr fill this in from the ../pki1/atav.c implementation */
  }

  return NSSUTF8_Duplicate(atav->utf8, arenaOpt);
}

NSS_EXTERN NSSPKIXAttributeValue *
nssPKIXATAV_GetValue
(
  NSSPKIXATAV *atav,
  NSSPKIXAttributeValue *rvOpt,
  NSSArena *arenaOpt
)
{
  NSSItem tmp;

  tmp.size = atav->value.size;
  tmp.data = atav->value.data;

  return NSSItem_Duplicate(&tmp, arenaOpt, rvOpt);
}

NSS_EXTERN PRStatus
nssPKIXATAV_SetType
(
  NSSPKIXATAV *atav,
  NSSPKIXAttributeType *attributeType
)
{
#if 0
  NSSDER tmp;

  atav->type = attributeType;

  nss_ZFreeIf(atav->type.data);
  if( (NSSDER *)NULL == nssOID_GetDEREncoding(atav->type, &tmp, atav->arena) ) {
    return PR_FAILURE;
  }

  atav->type.size = tmp.size;
  atav->type.data = tmp.data;
#endif

  return nss_pkix_AttributeTypeAndValue_Clear(atav);
}

NSS_IMPLEMENT PRStatus
nssPKIXATAV_SetValue
(
  NSSPKIXATAV *atav,
  NSSPKIXAttributeValue *value
)
{
  NSSItem tmp;

  if( (NSSItem *)NULL == NSSItem_Duplicate(value, atav->arena, &tmp) ) {
    return PR_FAILURE;
  }

  nss_ZFreeIf(atav->value.data);
  atav->value.size = tmp.size;
  atav->value.data = tmp.data;

  return nss_pkix_AttributeTypeAndValue_Clear(atav);
}

NSS_IMPLEMENT NSSPKIXATAV *
NSSPKIXATAV_Create
(
  NSSArena *arenaOpt,
  NSSPKIXAttributeType *typeOid,
  NSSPKIXAttributeValue *value
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_Create(arenaOpt, typeOid, value);
}

NSS_IMPLEMENT NSSPKIXATAV *
NSSPKIXATAV_CreateFromUTF8
(
  NSSArena *arenaOpt,
  NSSUTF8 *string
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_CreateFromUTF8(arenaOpt, string);
}

NSS_IMPLEMENT NSSPKIXATAV *
NSSPKIXATAV_Decode
(
  NSSArena *arenaOpt,
  NSSBER *ber
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_Decode(arenaOpt, ber);
}

NSS_IMPLEMENT PRStatus
NSSPKIXATAV_Destroy
(
  NSSPKIXATAV *atav
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_Destroy(atav);
}

NSS_IMPLEMENT NSSPKIXATAV *
NSSPKIXATAV_Duplicate
(
  NSSPKIXATAV *atav,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_Duplicate(atav, arenaOpt);
}

NSS_IMPLEMENT NSSBER *
NSSPKIXATAV_Encode
(
  NSSPKIXATAV *atav,
  NSSASN1EncodingType encoding,
  NSSBER *rvOpt,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_Encode(atav, encoding, rvOpt, arenaOpt);
}

NSS_IMPLEMENT PRBool
NSSPKIXATAV_Equal
(
  NSSPKIXATAV *atav1,
  NSSPKIXATAV *atav2,
  PRStatus *statusOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_Equal(atav1, atav2, statusOpt);
}

NSS_IMPLEMENT NSSPKIXAttributeType *
NSSPKIXATAV_GetType
(
  NSSPKIXATAV *atav
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_GetType(atav);
}

NSS_IMPLEMENT NSSUTF8 *
NSSPKIXATAV_GetUTF8Encoding
(
  NSSPKIXATAV *atav,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_GetUTF8Encoding(atav, arenaOpt);
}

NSS_IMPLEMENT NSSPKIXAttributeValue *
NSSPKIXATAV_GetValue
(
  NSSPKIXATAV *atav,
  NSSPKIXAttributeValue *itemOpt,
  NSSArena *arenaOpt
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_GetValue(atav, itemOpt, arenaOpt);
}

NSS_IMPLEMENT PRStatus
NSSPKIXATAV_SetType
(
  NSSPKIXATAV *atav,
  NSSPKIXAttributeType *attributeType
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_SetType(atav, attributeType);
}

NSS_IMPLEMENT PRStatus
NSSPKIXATAV_SetValue
(
  NSSPKIXATAV *atav,
  NSSPKIXAttributeValue *value
)
{
  nss_ClearErrorStack();

  return nssPKIXATAV_SetValue(atav, value);
}

