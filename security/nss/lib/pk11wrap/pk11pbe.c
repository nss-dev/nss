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

#include "plarena.h"

#include "seccomon.h"
#include "secitem.h"
#include "secport.h"
#include "hasht.h"
#include "pkcs11t.h"
/*#include "blapi.h" */
#include "sechash.h"
#include "secasn1.h"
#include "secder.h"
#include "secoid.h"
#include "alghmac.h"
#include "secerr.h"

typedef struct SEC_PKCS5PBEParameterStr SEC_PKCS5PBEParameter;

struct SEC_PKCS5PBEParameterStr {
    PRArenaPool *poolp;
    SECItem     salt;           /* octet string */
    SECItem     iteration;      /* integer */
};


/* template for PKCS 5 PBE Parameter.  This template has been expanded
 * based upon the additions in PKCS 12.  This should eventually be moved
 * if RSA updates PKCS 5.
 */
const SEC_ASN1Template SEC_PKCS5PBEParameterTemplate[] =
{
    { SEC_ASN1_SEQUENCE, 
	0, NULL, sizeof(SEC_PKCS5PBEParameter) },
    { SEC_ASN1_OCTET_STRING, 
	offsetof(SEC_PKCS5PBEParameter, salt) },
    { SEC_ASN1_INTEGER,
	offsetof(SEC_PKCS5PBEParameter, iteration) },
    { 0 }
};

const SEC_ASN1Template SEC_V2PKCS12PBEParameterTemplate[] =
{   
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SEC_PKCS5PBEParameter) },
    { SEC_ASN1_OCTET_STRING, offsetof(SEC_PKCS5PBEParameter, salt) },
    { SEC_ASN1_INTEGER, offsetof(SEC_PKCS5PBEParameter, iteration) },
    { 0 }
};

/* maps crypto algorithm from PBE algorithm.
 */
SECOidTag 
SEC_PKCS5GetCryptoAlgorithm(SECAlgorithmID *algid)
{

    SECOidTag algorithm;

    if(algid == NULL)
	return SEC_OID_UNKNOWN;

    algorithm = SECOID_GetAlgorithmTag(algid);
    switch(algorithm)
    {
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC:
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC:
	    return SEC_OID_DES_EDE3_CBC;
	case SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC:
	case SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC:
	case SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC:
	    return SEC_OID_DES_CBC;
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC:
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC:
	    return SEC_OID_RC2_CBC;
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4:
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4:
	    return SEC_OID_RC4;
	default:
	    break;
    }

    return SEC_OID_UNKNOWN;
}

/* check to see if an oid is a pbe algorithm
 */ 
PRBool 
SEC_PKCS5IsAlgorithmPBEAlg(SECAlgorithmID *algid)
{
    return (PRBool)(SEC_PKCS5GetCryptoAlgorithm(algid) != SEC_OID_UNKNOWN);
}

/* maps PBE algorithm from crypto algorithm, assumes SHA1 hashing.
 */
SECOidTag 
SEC_PKCS5GetPBEAlgorithm(SECOidTag algTag, int keyLen)
{
    switch(algTag)
    {
	case SEC_OID_DES_EDE3_CBC:
	    switch(keyLen) {
		case 168:
		case 192:
		    return SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC;
		case 128:
		case 92:
		    return SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC;
		default:
		    break;
	    }
	    break;
	case SEC_OID_DES_CBC:
	    return SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC;
	case SEC_OID_RC2_CBC:
	    switch(keyLen) {
		case 40:
		    return SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC;
		case 128:
		    return SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC;
		default:
		    break;
	    }
	    break;
	case SEC_OID_RC4:
	    switch(keyLen) {
		case 40:
		    return SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4;
		case 128:
		    return SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4;
		default:
		    break;
	    }
	    break;
	default:
	    break;
    }

    return SEC_OID_UNKNOWN;
}


/* get the key length needed for the PBE algorithm
 */

int 
SEC_PKCS5GetKeyLength(SECAlgorithmID *algid)
{

    SECOidTag algorithm;

    if(algid == NULL)
	return SEC_OID_UNKNOWN;

    algorithm = SECOID_GetAlgorithmTag(algid);

    switch(algorithm)
    {
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC:
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC:
	    return 24;
	case SEC_OID_PKCS5_PBE_WITH_MD2_AND_DES_CBC:
	case SEC_OID_PKCS5_PBE_WITH_SHA1_AND_DES_CBC:
	case SEC_OID_PKCS5_PBE_WITH_MD5_AND_DES_CBC:
	    return 8;
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC:
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_40_BIT_RC4:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC:
	    return 5;
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC:
	case SEC_OID_PKCS12_PBE_WITH_SHA1_AND_128_BIT_RC4:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4:
	    return 16;
	default:
	    break;
    }
    return -1;
}


/* the V2 algorithms only encode the salt, there is no iteration
 * count so we need a check for V2 algorithm parameters.
 */
static PRBool
sec_pkcs5_is_algorithm_v2_pkcs12_algorithm(SECOidTag algorithm)
{
    switch(algorithm) 
    {
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC4:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC4:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_3KEY_TRIPLE_DES_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_2KEY_TRIPLE_DES_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_128_BIT_RC2_CBC:
	case SEC_OID_PKCS12_V2_PBE_WITH_SHA1_AND_40_BIT_RC2_CBC:
	    return PR_TRUE;
	default:
	    break;
    }

    return PR_FALSE;
}
/* destroy a pbe parameter.  it assumes that the parameter was 
 * generated using the appropriate create function and therefor
 * contains an arena pool.
 */
static void 
sec_pkcs5_destroy_pbe_param(SEC_PKCS5PBEParameter *pbe_param)
{
    if(pbe_param != NULL)
	PORT_FreeArena(pbe_param->poolp, PR_TRUE);
}

/* creates a PBE parameter based on the PBE algorithm.  the only required
 * parameters are algorithm and interation.  the return is a PBE parameter
 * which conforms to PKCS 5 parameter unless an extended parameter is needed.
 * this is primarily if keyLen and a variable key length algorithm are
 * specified.
 *   salt -  if null, a salt will be generated from random bytes.
 *   iteration - number of iterations to perform hashing.
 *   keyLen - only used in variable key length algorithms
 *   iv - if null, the IV will be generated based on PKCS 5 when needed.
 *   params - optional, currently unsupported additional parameters.
 * once a parameter is allocated, it should be destroyed calling 
 * sec_pkcs5_destroy_pbe_parameter or SEC_PKCS5DestroyPBEParameter.
 */
static SEC_PKCS5PBEParameter *
sec_pkcs5_create_pbe_parameter(SECOidTag algorithm, 
			SECItem *salt, 
			int iteration)
{
    PRArenaPool *poolp = NULL;
    SEC_PKCS5PBEParameter *pbe_param = NULL;
    SECStatus rv; 
    void *dummy = NULL;

    if(iteration < 0) {
	return NULL;
    }
    if(!salt || !salt->data) {
	return NULL;
    } 

    poolp = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);
    if(poolp == NULL)
	return NULL;

    pbe_param = (SEC_PKCS5PBEParameter *)PORT_ArenaZAlloc(poolp,
	sizeof(SEC_PKCS5PBEParameter));
    if(!pbe_param) {
	PORT_FreeArena(poolp, PR_TRUE);
	return NULL;
    }

    pbe_param->poolp = poolp;

    rv = SECITEM_CopyItem(poolp, &pbe_param->salt, salt);

    if(rv != SECSuccess) {
	PORT_FreeArena(poolp, PR_TRUE);
	return NULL;
    }

    /* encode the integer */
    dummy = SEC_ASN1EncodeInteger(poolp, &pbe_param->iteration, 
		iteration);
    rv = (dummy) ? SECSuccess : SECFailure;

    if(rv != SECSuccess) {
	PORT_FreeArena(poolp, PR_FALSE);
	return NULL;
    }

    return pbe_param;
}

/* creates a algorithm ID containing the PBE algorithm and appropriate
 * parameters.  the required parameter is the algorithm.  if salt is
 * not specified, it is generated randomly.  if IV is specified, it overrides
 * the PKCS 5 generation of the IV.  
 *
 * the returned SECAlgorithmID should be destroyed using 
 * SECOID_DestroyAlgorithmID
 */
SECAlgorithmID *
SEC_PKCS5CreateAlgorithmID(SECOidTag algorithm, 
			   SECItem *salt, 
			   int iteration)
{
    PRArenaPool *poolp = NULL;
    SECAlgorithmID *algid, *ret_algid;
    SECItem der_param;
    SECStatus rv = SECFailure;
    SEC_PKCS5PBEParameter *pbe_param;

#ifdef nodef
    if(sec_pkcs5_hash_algorithm(algorithm) == SEC_OID_UNKNOWN)
	return NULL;
#endif

    if(iteration <= 0) {
	return NULL;
    }

    der_param.data = NULL;
    der_param.len = 0;

    /* generate the parameter */
    pbe_param = sec_pkcs5_create_pbe_parameter(algorithm, salt, iteration);
    if(!pbe_param) {
	return NULL;
    }

    poolp = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);
    if(!poolp) {
	sec_pkcs5_destroy_pbe_param(pbe_param);
	return NULL;
    }

    /* generate the algorithm id */
    algid = (SECAlgorithmID *)PORT_ArenaZAlloc(poolp, sizeof(SECAlgorithmID));
    if(algid != NULL) {
	void *dummy;
	if(!sec_pkcs5_is_algorithm_v2_pkcs12_algorithm(algorithm)) {
	    dummy = SEC_ASN1EncodeItem(poolp, &der_param, pbe_param,
					SEC_PKCS5PBEParameterTemplate);
	} else {
	    dummy = SEC_ASN1EncodeItem(poolp, &der_param, pbe_param,
	    				SEC_V2PKCS12PBEParameterTemplate);
	}
	
	if(dummy) {
	    rv = SECOID_SetAlgorithmID(poolp, algid, algorithm, &der_param);
	}
    }

    ret_algid = NULL;
    if(algid != NULL) {
	ret_algid = (SECAlgorithmID *)PORT_ZAlloc(sizeof(SECAlgorithmID));
	if(ret_algid != NULL) {
	    rv = SECOID_CopyAlgorithmID(NULL, ret_algid, algid);
	    if(rv != SECSuccess) {
		SECOID_DestroyAlgorithmID(ret_algid, PR_TRUE);
		ret_algid = NULL;
	    }
	}
    }
	
    if(poolp != NULL) {
	PORT_FreeArena(poolp, PR_TRUE);
	algid = NULL;
    }

    sec_pkcs5_destroy_pbe_param(pbe_param);

    return ret_algid;
}

SECStatus
PBE_PK11ParamToAlgid(SECOidTag algTag, SECItem *param, PRArenaPool *arena, 
		     SECAlgorithmID *algId)
{
    CK_PBE_PARAMS *pbe_param;
    SECItem pbeSalt;
    SECAlgorithmID *pbeAlgID = NULL;
    SECStatus rv;

    if(!param || !algId) {
	return SECFailure;
    }

    pbe_param = (CK_PBE_PARAMS *)param->data;
    pbeSalt.data = (unsigned char *)pbe_param->pSalt;
    pbeSalt.len = pbe_param->ulSaltLen;
    pbeAlgID = SEC_PKCS5CreateAlgorithmID(algTag, &pbeSalt, 
					  (int)pbe_param->ulIteration);
    if(!pbeAlgID) {
	return SECFailure;
    }

    rv = SECOID_CopyAlgorithmID(arena, algId, pbeAlgID);
    SECOID_DestroyAlgorithmID(pbeAlgID, PR_TRUE);
    return rv;
}
