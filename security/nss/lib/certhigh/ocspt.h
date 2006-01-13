/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1994-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

/*
 * Public header for exported OCSP types.
 *
 * $Id$
 */

#ifndef _OCSPT_H_
#define _OCSPT_H_

/*
 * The following are all opaque types.  If someone needs to get at
 * a field within, then we need to fix the API.  Try very hard not
 * make the type available to them.
 */
typedef struct CERTOCSPRequestStr CERTOCSPRequest;
typedef struct CERTOCSPResponseStr CERTOCSPResponse;

/*
 * XXX I think only those first two above should need to be exported,
 * but until I know for certain I am leaving the rest of these here, too.
 */
typedef struct CERTOCSPCertIDStr CERTOCSPCertID;
typedef struct CERTOCSPCertStatusStr CERTOCSPCertStatus;
typedef struct CERTOCSPSingleResponseStr CERTOCSPSingleResponse;

/*
 * This interface is described in terms of an HttpClient which
 * supports at least a specified set of functions. (An implementer may
 * provide HttpClients with additional functionality accessible only to
 * users with a particular implementation in mind.) The basic behavior
 * is provided by defining a set of functions, listed in an
 * SEC_HttpClientFcnStruct. If the implementor of a SpecificHttpClient
 * registers his SpecificHttpClient as the default HttpClient, then his
 * functions will be called by the user of an HttpClient, such as an
 * OCSPChecker.
 *
 * The implementer of a specific HttpClient (e.g., the NSS-provided
 * DefaultHttpClient), populates an SEC_HttpClientFcnStruct, uses it to
 * register his client, and waits for his functions to be called.
 *
 * For future expandability, the SEC_HttpClientFcnStruct is defined as a
 * union, with the version field acting as a selector. The proposed
 * initial version of the structure is given following the definition
 * of the union. The HttpClientState structure is implementation-
 * dependent, and should be opaque to the user.
 */

/*
 * This function creates a HttpClientState object. The implementer of a
 * specific HttpClient will allocate the necessary space, when this
 * function is called, and will free it when the corresponding FreeFcn
 * is called. The user of the client must supply this HttpClientState
 * object to subsequent calls.
 *
 * Parameter http_uri may be encoded as UTF-8.
 *
 * An implementation that does not support the requested http_uri or
 * http_request_method should report SECFailure.
 *
 * If the function returns SECSuccess, the returned clientState
 * must cleaned up with a call to SEC_HttpClient_Free,
 * after processing is finished.
 */
typedef SECStatus (*SEC_HttpClient_CreateFcn)(
	PRArenaPool *arena,
	const PRIntervalTime timeout, 
	const char *http_uri,
	const char *http_request_method, 
	void **clientState);

/*
 * This function sets data to be sent to the server for an HTTP request
 * of http_request_method == POST. If a particular implementation 
 * supports it, the details for the POST request can be set by calling 
 * this function, prior to activating the request with TryFcn.
 *
 * An implementation that does not support the POST method should 
 * implement a SetPostDataFcn function that returns immediately.
 *
 * Setting http_content_type is optional, the parameter may
 * by NULL or the empty string.
 */ 
typedef SECStatus (*SEC_HttpClient_SetPostDataFcn)(
	void *clientState,
	const char *http_data, 
	const size_t http_data_len,
	const char *http_content_type);

/*
 * This function sets an additional HTTP protocol request header.
 * If a particular implementation supports it, one or multiple headers
 * can be added to the request by calling this function once or multiple
 * times, prior to activating the request with TryFcn.
 *
 * An implementation that does not support setting additional headers
 * should implement a AddRequestHeaderFcn function that returns immediately.
 */ 
typedef SECStatus (*SEC_HttpClient_AddRequestHeaderFcn)(
	void *clientState,
	const char *http_header_name, 
	const char *http_header_value);

/*
 * This function initiates or continues an HTTP request. After
 * parameters have been set with the Create function and, optionally,
 * modified or enhanced with the AddParams function, this call creates
 * the socket conection and initiates the communication.
 *
 * If a timeout value of zero is specified, indicating non-blocking
 * I/O, the client creates a non-blocking socket, and returns a status
 * of SECWouldBlock and a non-NULL PRPollDesc if the operation is not
 * complete. In that case all other return parameters are undefined.
 * The caller is expected to repeat the call, possibly after using
 * PRPoll to determine that a completion has occurred, until a return
 * value of SECSuccess (and a NULL value for pPollDesc) or a return
 * value of SECFailure (indicating failure on the network level)
 * is obtained.
 *
 * The caller is permitted to provide NULL values for any of the
 * http_response arguments, indicating the caller is not interested in
 * those values. If the caller does provide an address, the HttpClient
 * stores at that address a pointer to the corresponding argument, at
 * the completion of the operation.
 *
 * All returned pointers will be owned by the the HttpClient
 * implementation and will remain valid until the call to 
 * SEC_HttpClient_FreeFcn.
 */ 
typedef SECStatus (*SEC_HttpClient_TryFcn)(
	void *clientState,
	PRPollDesc **pPollDesc,
	unsigned int *http_response_code, 
	char **http_response_content_type, 
	char **http_response_headers, 
	char **http_response_data, 
	size_t *http_response_data_len); 

/*
 * Calling CancelFcn asks for premature termination of the request.
 *
 * Future calls to SEC_HttpClient_Try on the clientState should
 * by avoided, but in this case the HttpClient implementation 
 * is expected to return immediately with SECFailure.
 *
 * After calling CancelFcn, a separate call to SEC_HttpClient_FreeFcn 
 * is still necessary to free resources.
 */ 
typedef SECStatus (*SEC_HttpClient_CancelFcn)(
	void *clientState); 

/*
 * Before calling this function, it must be assured the request
 * has been completed, i.e. either SEC_HttpClient_Try has
 * returned SECSuccess, or the request has been canceled with
 * a call to SEC_HttpClient_CancelFcn.
 * 
 * This function frees the client state object, closes all sockets, 
 * discards all partial results, frees any memory that was allocated 
 * by the client, and invalidates all response pointers that might
 * have been returned by SEC_HttpClient_TryFcn
 */ 
typedef SECStatus (*SEC_HttpClient_FreeFcn)(
	void *clientState); 

typedef struct SEC_HttpClientFcnV1Struct {
	SEC_HttpClient_CreateFcn createFcn;
	SEC_HttpClient_SetPostDataFcn setPostDataFcn;
	SEC_HttpClient_AddRequestHeaderFcn addRequestHeaderFcn;
	SEC_HttpClient_TryFcn tryFcn;
	SEC_HttpClient_CancelFcn cancelFcn;
	SEC_HttpClient_FreeFcn freeFcn;
} SEC_HttpClientFcnV1;

typedef struct SEC_HttpClientFcnStruct {
	PRInt16 version;
	union {
		SEC_HttpClientFcnV1 ftable1;
		/* SEC_HttpClientFcnV2 ftable2; */
		/* ...                      */
	} fcnTable;
} SEC_HttpClientFcn;

#endif /* _OCSPT_H_ */
