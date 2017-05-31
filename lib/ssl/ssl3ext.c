/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * SSL3 Protocol
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* TLS extension code moved here from ssl3ecc.c */

#include "nssrenam.h"
#include "nss.h"
#include "ssl.h"
#include "sslimpl.h"
#include "sslproto.h"
#include "ssl3exthandle.h"
#include "tls13exthandle.h"

/* Callback function that handles a received extension. */
typedef SECStatus (*ssl3ExtensionHandlerFunc)(const sslSocket *ss,
                                              TLSExtensionData *xtnData,
                                              SECItem *data);

/* Row in a table of hello extension handlers. */
typedef struct {
    SSLExtensionType ex_type;
    ssl3ExtensionHandlerFunc ex_handler;
} ssl3ExtensionHandler;

/* Table of handlers for received TLS hello extensions, one per extension.
 * In the second generation, this table will be dynamic, and functions
 * will be registered here.
 */
/* This table is used by the server, to handle client hello extensions. */
static const ssl3ExtensionHandler clientHelloHandlers[] = {
    { ssl_server_name_xtn, &ssl3_HandleServerNameXtn },
    { ssl_supported_groups_xtn, &ssl_HandleSupportedGroupsXtn },
    { ssl_ec_point_formats_xtn, &ssl3_HandleSupportedPointFormatsXtn },
    { ssl_session_ticket_xtn, &ssl3_ServerHandleSessionTicketXtn },
    { ssl_renegotiation_info_xtn, &ssl3_HandleRenegotiationInfoXtn },
    { ssl_next_proto_nego_xtn, &ssl3_ServerHandleNextProtoNegoXtn },
    { ssl_app_layer_protocol_xtn, &ssl3_ServerHandleAppProtoXtn },
    { ssl_use_srtp_xtn, &ssl3_ServerHandleUseSRTPXtn },
    { ssl_cert_status_xtn, &ssl3_ServerHandleStatusRequestXtn },
    { ssl_signature_algorithms_xtn, &ssl3_HandleSigAlgsXtn },
    { ssl_extended_master_secret_xtn, &ssl3_HandleExtendedMasterSecretXtn },
    { ssl_signed_cert_timestamp_xtn, &ssl3_ServerHandleSignedCertTimestampXtn },
    { ssl_tls13_key_share_xtn, &tls13_ServerHandleKeyShareXtn },
    { ssl_tls13_pre_shared_key_xtn, &tls13_ServerHandlePreSharedKeyXtn },
    { ssl_tls13_early_data_xtn, &tls13_ServerHandleEarlyDataXtn },
    { ssl_tls13_psk_key_exchange_modes_xtn, &tls13_ServerHandlePskModesXtn },
    { 0, NULL }
};

/* These two tables are used by the client, to handle server hello
 * extensions. */
static const ssl3ExtensionHandler serverHelloHandlersTLS[] = {
    { ssl_server_name_xtn, &ssl3_HandleServerNameXtn },
    /* TODO: add a handler for ssl_ec_point_formats_xtn */
    { ssl_session_ticket_xtn, &ssl3_ClientHandleSessionTicketXtn },
    { ssl_renegotiation_info_xtn, &ssl3_HandleRenegotiationInfoXtn },
    { ssl_next_proto_nego_xtn, &ssl3_ClientHandleNextProtoNegoXtn },
    { ssl_app_layer_protocol_xtn, &ssl3_ClientHandleAppProtoXtn },
    { ssl_use_srtp_xtn, &ssl3_ClientHandleUseSRTPXtn },
    { ssl_cert_status_xtn, &ssl3_ClientHandleStatusRequestXtn },
    { ssl_extended_master_secret_xtn, &ssl3_HandleExtendedMasterSecretXtn },
    { ssl_signed_cert_timestamp_xtn, &ssl3_ClientHandleSignedCertTimestampXtn },
    { ssl_tls13_key_share_xtn, &tls13_ClientHandleKeyShareXtn },
    { ssl_tls13_pre_shared_key_xtn, &tls13_ClientHandlePreSharedKeyXtn },
    { ssl_tls13_early_data_xtn, &tls13_ClientHandleEarlyDataXtn },
    { 0, NULL }
};

static const ssl3ExtensionHandler helloRetryRequestHandlers[] = {
    { ssl_tls13_key_share_xtn, tls13_ClientHandleKeyShareXtnHrr },
    { ssl_tls13_cookie_xtn, tls13_ClientHandleHrrCookie },
    { 0, NULL }
};

static const ssl3ExtensionHandler serverHelloHandlersSSL3[] = {
    { ssl_renegotiation_info_xtn, &ssl3_HandleRenegotiationInfoXtn },
    { 0, NULL }
};

static const ssl3ExtensionHandler newSessionTicketHandlers[] = {
    { ssl_tls13_early_data_xtn,
      &tls13_ClientHandleTicketEarlyDataXtn },
    { 0, NULL }
};

/* This table is used by the client to handle server certificates in TLS 1.3 */
static const ssl3ExtensionHandler serverCertificateHandlers[] = {
    { ssl_signed_cert_timestamp_xtn, &ssl3_ClientHandleSignedCertTimestampXtn },
    { ssl_cert_status_xtn, &ssl3_ClientHandleStatusRequestXtn },
    { 0, NULL }
};

static const ssl3ExtensionHandler certificateRequestHandlers[] = {
    { ssl_signature_algorithms_xtn, &ssl3_HandleSigAlgsXtn },
    { ssl_tls13_certificate_authorities_xtn,
      &tls13_ClientHandleCertAuthoritiesXtn },
    { 0, NULL }
};

/* Tables of functions to format TLS hello extensions, one function per
 * extension.
 * These static tables are for the formatting of client hello extensions.
 * The server's table of hello senders is dynamic, in the socket struct,
 * and sender functions are registered there.
 * NB: the order of these extensions can have an impact on compatibility. Some
 * servers (e.g. Tomcat) will terminate the connection if the last extension in
 * the client hello is empty (for example, the extended master secret
 * extension, if it were listed last). See bug 1243641.
 */
static const sslExtensionBuilder clientHelloSendersTLS[] =
    {
      { ssl_server_name_xtn, &ssl3_ClientSendServerNameXtn },
      { ssl_extended_master_secret_xtn, &ssl3_SendExtendedMasterSecretXtn },
      { ssl_renegotiation_info_xtn, &ssl3_SendRenegotiationInfoXtn },
      { ssl_supported_groups_xtn, &ssl_SendSupportedGroupsXtn },
      { ssl_ec_point_formats_xtn, &ssl3_SendSupportedPointFormatsXtn },
      { ssl_session_ticket_xtn, &ssl3_ClientSendSessionTicketXtn },
      { ssl_next_proto_nego_xtn, &ssl3_ClientSendNextProtoNegoXtn },
      { ssl_app_layer_protocol_xtn, &ssl3_ClientSendAppProtoXtn },
      { ssl_use_srtp_xtn, &ssl3_ClientSendUseSRTPXtn },
      { ssl_cert_status_xtn, &ssl3_ClientSendStatusRequestXtn },
      { ssl_signed_cert_timestamp_xtn, &ssl3_ClientSendSignedCertTimestampXtn },
      { ssl_tls13_key_share_xtn, &tls13_ClientSendKeyShareXtn },
      { ssl_tls13_early_data_xtn, &tls13_ClientSendEarlyDataXtn },
      /* Some servers (e.g. WebSphere Application Server 7.0 and Tomcat) will
       * time out or terminate the connection if the last extension in the
       * client hello is empty. They are not intolerant of TLS 1.2, so list
       * signature_algorithms at the end. See bug 1243641. */
      { ssl_tls13_supported_versions_xtn, &tls13_ClientSendSupportedVersionsXtn },
      { ssl_signature_algorithms_xtn, &ssl3_SendSigAlgsXtn },
      { ssl_tls13_cookie_xtn, &tls13_ClientSendHrrCookieXtn },
      { ssl_tls13_psk_key_exchange_modes_xtn, &tls13_ClientSendPskModesXtn },
      /* The pre_shared_key extension MUST be last. */
      { ssl_tls13_pre_shared_key_xtn, &tls13_ClientSendPreSharedKeyXtn },
      { 0, NULL }
    };

static const sslExtensionBuilder clientHelloSendersSSL3[] = {
    { ssl_renegotiation_info_xtn, &ssl3_SendRenegotiationInfoXtn },
    { 0, NULL }
};

static const sslExtensionBuilder tls13_cert_req_senders[] = {
    { ssl_signature_algorithms_xtn, &ssl3_SendSigAlgsXtn },
    { ssl_tls13_certificate_authorities_xtn, &tls13_SendCertAuthoritiesXtn },
    { 0, NULL }
};

static PRBool
arrayContainsExtension(const PRUint16 *array, PRUint32 len, PRUint16 ex_type)
{
    unsigned int i;
    for (i = 0; i < len; i++) {
        if (ex_type == array[i])
            return PR_TRUE;
    }
    return PR_FALSE;
}

PRBool
ssl3_ExtensionNegotiated(const sslSocket *ss, PRUint16 ex_type)
{
    const TLSExtensionData *xtnData = &ss->xtnData;
    return arrayContainsExtension(xtnData->negotiated,
                                  xtnData->numNegotiated, ex_type);
}

PRBool
ssl3_ClientExtensionAdvertised(const sslSocket *ss, PRUint16 ex_type)
{
    const TLSExtensionData *xtnData = &ss->xtnData;
    return arrayContainsExtension(xtnData->advertised,
                                  xtnData->numAdvertised, ex_type);
}

/* Go through hello extensions in |b| and deserialize
 * them into the list in |ss->ssl3.hs.remoteExtensions|.
 * The only checking we do in this point is for duplicates.
 *
 * IMPORTANT: This list just contains pointers to the incoming
 * buffer so they can only be used during ClientHello processing.
 */
SECStatus
ssl3_ParseExtensions(sslSocket *ss, PRUint8 **b, PRUint32 *length)
{
    /* Clean out the extensions list. */
    ssl3_DestroyRemoteExtensions(&ss->ssl3.hs.remoteExtensions);

    while (*length) {
        SECStatus rv;
        PRUint32 extension_type;
        SECItem extension_data = { siBuffer, NULL, 0 };
        TLSExtension *extension;
        PRCList *cursor;

        /* Get the extension's type field */
        rv = ssl3_ConsumeHandshakeNumber(ss, &extension_type, 2, b, length);
        if (rv != SECSuccess) {
            return SECFailure; /* alert already sent */
        }

        SSL_TRC(10, ("%d: SSL3[%d]: parsing extension %d",
                     SSL_GETPID(), ss->fd, extension_type));
        /* Check whether an extension has been sent multiple times. */
        for (cursor = PR_NEXT_LINK(&ss->ssl3.hs.remoteExtensions);
             cursor != &ss->ssl3.hs.remoteExtensions;
             cursor = PR_NEXT_LINK(cursor)) {
            if (((TLSExtension *)cursor)->type == extension_type) {
                (void)SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
                PORT_SetError(SSL_ERROR_RX_UNEXPECTED_EXTENSION);
                return SECFailure;
            }
        }

        /* Get the data for this extension, so we can pass it or skip it. */
        rv = ssl3_ConsumeHandshakeVariable(ss, &extension_data, 2, b, length);
        if (rv != SECSuccess) {
            return rv; /* alert already sent */
        }

        extension = PORT_ZNew(TLSExtension);
        if (!extension) {
            return SECFailure;
        }

        extension->type = (PRUint16)extension_type;
        extension->data = extension_data;
        PR_APPEND_LINK(&extension->link, &ss->ssl3.hs.remoteExtensions);
    }

    return SECSuccess;
}

TLSExtension *
ssl3_FindExtension(sslSocket *ss, SSLExtensionType extension_type)
{
    PRCList *cursor;

    for (cursor = PR_NEXT_LINK(&ss->ssl3.hs.remoteExtensions);
         cursor != &ss->ssl3.hs.remoteExtensions;
         cursor = PR_NEXT_LINK(cursor)) {
        TLSExtension *extension = (TLSExtension *)cursor;

        if (extension->type == extension_type) {
            return extension;
        }
    }

    return NULL;
}

/* Go through the hello extensions in |ss->ssl3.hs.remoteExtensions|.
 * For each one, find the extension handler in the table, and
 * if present, invoke that handler.
 * Servers ignore any extensions with unknown extension types.
 * Clients reject any extensions with unadvertised extension types
 *
 * In TLS >= 1.3, the client checks that extensions appear in the
 * right phase.
 */
SECStatus
ssl3_HandleParsedExtensions(sslSocket *ss,
                            SSLHandshakeType handshakeMessage)
{
    const ssl3ExtensionHandler *handlers;
    const ssl3ExtensionHandler *handler;
    /* HelloRetryRequest doesn't set ss->version. It might be safe to
     * do so, but we weren't entirely sure. TODO(ekr@rtfm.com). */
    PRBool isTLS13 = (ss->version >= SSL_LIBRARY_VERSION_TLS_1_3) ||
                     (handshakeMessage == ssl_hs_hello_retry_request);
    /* The following messages can include extensions that were not included in
     * the original ClientHello. */
    PRBool allowNotOffered = (handshakeMessage == ssl_hs_client_hello) ||
                             (handshakeMessage == ssl_hs_certificate_request) ||
                             (handshakeMessage == ssl_hs_new_session_ticket);
    PRCList *cursor;

    switch (handshakeMessage) {
        case ssl_hs_client_hello:
            handlers = clientHelloHandlers;
            break;
        case ssl_hs_new_session_ticket:
            PORT_Assert(ss->version >= SSL_LIBRARY_VERSION_TLS_1_3);
            handlers = newSessionTicketHandlers;
            break;
        case ssl_hs_hello_retry_request:
            handlers = helloRetryRequestHandlers;
            break;
        case ssl_hs_encrypted_extensions:
            PORT_Assert(ss->version >= SSL_LIBRARY_VERSION_TLS_1_3);
        /* fall through */
        case ssl_hs_server_hello:
            if (ss->version > SSL_LIBRARY_VERSION_3_0) {
                handlers = serverHelloHandlersTLS;
            } else {
                handlers = serverHelloHandlersSSL3;
            }
            break;
        case ssl_hs_certificate:
            PORT_Assert(!ss->sec.isServer);
            handlers = serverCertificateHandlers;
            break;
        case ssl_hs_certificate_request:
            PORT_Assert(!ss->sec.isServer);
            handlers = certificateRequestHandlers;
            break;
        default:
            PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
            PORT_Assert(0);
            return SECFailure;
    }

    for (cursor = PR_NEXT_LINK(&ss->ssl3.hs.remoteExtensions);
         cursor != &ss->ssl3.hs.remoteExtensions;
         cursor = PR_NEXT_LINK(cursor)) {
        TLSExtension *extension = (TLSExtension *)cursor;

        /* Check whether the server sent an extension which was not advertised
         * in the ClientHello.
         *
         * Note that a TLS 1.3 server should check if CertificateRequest
         * extensions were sent.  But the extensions used for CertificateRequest
         * do not have any response, so we rely on
         * ssl3_ClientExtensionAdvertised to return false on the server.  That
         * results in the server only rejecting any extension. */
        if (!allowNotOffered && (extension->type != ssl_tls13_cookie_xtn) &&
            !ssl3_ClientExtensionAdvertised(ss, extension->type)) {
            (void)SSL3_SendAlert(ss, alert_fatal, unsupported_extension);
            PORT_SetError(SSL_ERROR_RX_UNEXPECTED_EXTENSION);
            return SECFailure;
        }

        /* Check that this is a legal extension in TLS 1.3 */
        if (isTLS13) {
            switch (tls13_ExtensionStatus(extension->type, handshakeMessage)) {
                case tls13_extension_allowed:
                    break;
                case tls13_extension_unknown:
                    if (allowNotOffered) {
                        continue; /* Skip over unknown extensions. */
                    }
                /* Fall through. */
                case tls13_extension_disallowed:
                    tls13_FatalError(ss, SSL_ERROR_EXTENSION_DISALLOWED_FOR_VERSION,
                                     unsupported_extension);
                    return SECFailure;
            }
        }

        /* Special check for this being the last extension if it's
         * PreSharedKey */
        if (ss->sec.isServer && isTLS13 &&
            (extension->type == ssl_tls13_pre_shared_key_xtn) &&
            (PR_NEXT_LINK(cursor) != &ss->ssl3.hs.remoteExtensions)) {
            tls13_FatalError(ss,
                             SSL_ERROR_RX_MALFORMED_CLIENT_HELLO,
                             illegal_parameter);
            return SECFailure;
        }

        /* find extension_type in table of Hello Extension Handlers */
        for (handler = handlers; handler->ex_handler; ++handler) {
            /* if found, call this handler */
            if (handler->ex_type == extension->type) {
                SECStatus rv;

                rv = (*handler->ex_handler)(ss, &ss->xtnData,
                                            &extension->data);
                if (rv != SECSuccess) {
                    if (!ss->ssl3.fatalAlertSent) {
                        /* send a generic alert if the handler didn't already */
                        (void)SSL3_SendAlert(ss, alert_fatal, handshake_failure);
                    }
                    return SECFailure;
                }
                break;
            }
        }
    }
    return SECSuccess;
}

/* Syntactic sugar around ssl3_ParseExtensions and
 * ssl3_HandleParsedExtensions. */
SECStatus
ssl3_HandleExtensions(sslSocket *ss,
                      PRUint8 **b, PRUint32 *length,
                      SSLHandshakeType handshakeMessage)
{
    SECStatus rv;

    rv = ssl3_ParseExtensions(ss, b, length);
    if (rv != SECSuccess)
        return rv;

    rv = ssl3_HandleParsedExtensions(ss, handshakeMessage);
    if (rv != SECSuccess)
        return rv;

    ssl3_DestroyRemoteExtensions(&ss->ssl3.hs.remoteExtensions);
    return SECSuccess;
}

/* Add a callback function to the table of senders of server hello extensions.
 */
SECStatus
ssl3_RegisterExtensionSender(const sslSocket *ss,
                             TLSExtensionData *xtnData,
                             PRUint16 ex_type,
                             sslExtensionBuilderFunc cb)
{
    int i;
    sslExtensionBuilder *sender;
    if (ss->version < SSL_LIBRARY_VERSION_TLS_1_3) {
        sender = &xtnData->serverHelloSenders[0];
    } else {
        if (tls13_ExtensionStatus(ex_type, ssl_hs_server_hello) ==
            tls13_extension_allowed) {
            PORT_Assert(tls13_ExtensionStatus(ex_type,
                                              ssl_hs_encrypted_extensions) ==
                        tls13_extension_disallowed);
            sender = &xtnData->serverHelloSenders[0];
        } else if (tls13_ExtensionStatus(ex_type,
                                         ssl_hs_encrypted_extensions) ==
                   tls13_extension_allowed) {
            sender = &xtnData->encryptedExtensionsSenders[0];
        } else if (tls13_ExtensionStatus(ex_type, ssl_hs_certificate) ==
                   tls13_extension_allowed) {
            sender = &xtnData->certificateSenders[0];
        } else {
            PORT_Assert(0);
            PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
            return SECFailure;
        }
    }
    for (i = 0; i < SSL_MAX_EXTENSIONS; ++i, ++sender) {
        if (!sender->ex_sender) {
            sender->ex_type = ex_type;
            sender->ex_sender = cb;
            return SECSuccess;
        }
        /* detect duplicate senders */
        PORT_Assert(sender->ex_type != ex_type);
        if (sender->ex_type == ex_type) {
            /* duplicate */
            break;
        }
    }
    PORT_Assert(i < SSL_MAX_EXTENSIONS); /* table needs to grow */
    PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
    return SECFailure;
}

/* Call extension handlers for the given message. */
SECStatus
ssl_ConstructExtensions(sslSocket *ss, sslBuffer *buf, SSLHandshakeType message)
{
    const sslExtensionBuilder *sender;
    SECStatus rv;

    PORT_Assert(buf->len == 0);

    switch (message) {
        case ssl_hs_client_hello:
            if (ss->vrange.max > SSL_LIBRARY_VERSION_3_0) {
                sender = clientHelloSendersTLS;
            } else {
                sender = clientHelloSendersSSL3;
            }
            break;

        case ssl_hs_server_hello:
            sender = ss->xtnData.serverHelloSenders;
            break;

        case ssl_hs_certificate_request:
            PORT_Assert(ss->version >= SSL_LIBRARY_VERSION_TLS_1_3);
            sender = tls13_cert_req_senders;
            break;

        case ssl_hs_certificate:
            PORT_Assert(ss->version >= SSL_LIBRARY_VERSION_TLS_1_3);
            sender = ss->xtnData.certificateSenders;
            break;

        case ssl_hs_encrypted_extensions:
            PORT_Assert(ss->version >= SSL_LIBRARY_VERSION_TLS_1_3);
            sender = ss->xtnData.encryptedExtensionsSenders;
            break;

        default:
            PORT_Assert(0);
            PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
            return SECFailure;
    }

    for (; sender->ex_sender; ++sender) {
        PRBool append = PR_FALSE;
        unsigned int start = buf->len;
        unsigned int length;

        /* Save space for the extension type and length. Note that we don't grow
         * the buffer now; rely on sslBuffer_Append* to do that. */
        buf->len += 4;
        rv = (*sender->ex_sender)(ss, &ss->xtnData, buf, &append);
        if (rv != SECSuccess) {
            goto loser;
        }

        /* Save the length and go back to the start. */
        length = buf->len - start - 4;
        buf->len = start;
        if (!append) {
            continue;
        }

        buf->len = start;
        rv = sslBuffer_AppendNumber(buf, sender->ex_type, 2);
        if (rv != SECSuccess) {
            goto loser; /* Code already set. */
        }
        rv = sslBuffer_AppendNumber(buf, length, 2);
        if (rv != SECSuccess) {
            goto loser; /* Code already set. */
        }
        /* Skip over the extension body. */
        buf->len += length;

        if (message == ssl_hs_client_hello) {
            ss->xtnData.advertised[ss->xtnData.numAdvertised++] =
                sender->ex_type;
        }
    }

    if (buf->len > 0xffff) {
        PORT_SetError(SSL_ERROR_TX_RECORD_TOO_LONG);
        goto loser;
    }

    return SECSuccess;

loser:
    sslBuffer_Clear(buf);
    return SECFailure;
}

/* This extension sender can be used anywhere that an always empty extension is
 * needed. Mostly that is for ServerHello where sender registration is dynamic;
 * ClientHello senders are usually conditional in some way. */
SECStatus
ssl_SendEmptyExtension(const sslSocket *ss, TLSExtensionData *xtnData,
                       sslBuffer *buf, PRBool *append)
{
    *append = PR_TRUE;
    return SECSuccess;
}

/* Takes the size of the ClientHello, less the record header, and determines how
 * much padding is required. */
static unsigned int
ssl_CalculatePaddingExtLen(const sslSocket *ss, unsigned int clientHelloLength)
{
    unsigned int recordLength = 1 /* handshake message type */ +
                                3 /* handshake message length */ +
                                clientHelloLength;
    unsigned int extensionLen;

    /* Don't pad for DTLS, for SSLv3, or for renegotiation. */
    if (IS_DTLS(ss) ||
        ss->vrange.max < SSL_LIBRARY_VERSION_TLS_1_0 ||
        ss->firstHsDone) {
        return 0;
    }

    /* A padding extension may be included to ensure that the record containing
     * the ClientHello doesn't have a length between 256 and 511 bytes
     * (inclusive). Initial ClientHello records with such lengths trigger bugs
     * in F5 devices. */
    if (recordLength < 256 || recordLength >= 512) {
        return 0;
    }

    extensionLen = 512 - recordLength;
    /* Extensions take at least four bytes to encode. Always include at least
     * one byte of data if we are padding. Some servers will time out or
     * terminate the connection if the last ClientHello extension is empty. */
    if (extensionLen < 5) {
        extensionLen = 5;
    }

    return extensionLen - 4;
}

/* ssl3_SendPaddingExtension possibly adds an extension which ensures that a
 * ClientHello record is either < 256 bytes or is >= 512 bytes. This ensures
 * that we don't trigger bugs in F5 products.
 *
 * This takes an existing extension buffer, |buf|, and the length of the
 * remainder of the ClientHello, |prefixLen|.  It modifies the extension buffer
 * to insert padding at the right place.
 */
SECStatus
ssl_InsertPaddingExtension(const sslSocket *ss, unsigned int prefixLen,
                           sslBuffer *buf)
{
    static unsigned char padding[252] = { 0 };
    unsigned int paddingLen;
    unsigned int tailLen;
    SECStatus rv;

    /* Account for the size of the header, the length field of the extensions
     * block and the size of the existing extensions. */
    paddingLen = ssl_CalculatePaddingExtLen(ss, prefixLen + 2 + buf->len);
    if (!paddingLen) {
        return SECSuccess;
    }

    /* Move the tail if there is one. This only happens if we are sending the
     * TLS 1.3 PSK extension, which needs to be at the end. */
    if (ss->xtnData.paddingOffset) {
        PORT_Assert(buf->len > ss->xtnData.paddingOffset);
        tailLen = buf->len - ss->xtnData.paddingOffset;
        rv = sslBuffer_Grow(buf, buf->len + 4 + paddingLen);
        if (rv != SECSuccess) {
            return SECFailure;
        }
        PORT_Memmove(buf->buf + ss->xtnData.paddingOffset + 4 + paddingLen,
                     buf->buf + ss->xtnData.paddingOffset,
                     tailLen);
        buf->len = ss->xtnData.paddingOffset;
    } else {
        tailLen = 0;
    }

    rv = sslBuffer_AppendNumber(buf, ssl_padding_xtn, 2);
    if (rv != SECSuccess) {
        return SECFailure; /* Code already set. */
    }
    rv = sslBuffer_AppendVariable(buf, padding, paddingLen, 2);
    if (rv != SECSuccess) {
        return SECFailure; /* Code already set. */
    }

    buf->len += tailLen;

    return SECSuccess;
}

void
ssl3_DestroyRemoteExtensions(PRCList *list)
{
    PRCList *cur_p;

    while (!PR_CLIST_IS_EMPTY(list)) {
        cur_p = PR_LIST_TAIL(list);
        PR_REMOVE_LINK(cur_p);
        PORT_Free(cur_p);
    }
}

/* Initialize the extension data block. */
void
ssl3_InitExtensionData(TLSExtensionData *xtnData)
{
    /* Set things up to the right starting state. */
    PORT_Memset(xtnData, 0, sizeof(*xtnData));
    xtnData->peerSupportsFfdheGroups = PR_FALSE;
    PR_INIT_CLIST(&xtnData->remoteKeyShares);
}

/* Free everything that has been allocated and then reset back to
 * the starting state. */
void
ssl3_ResetExtensionData(TLSExtensionData *xtnData)
{
    /* Clean up. */
    ssl3_FreeSniNameArray(xtnData);
    PORT_Free(xtnData->sigSchemes);
    SECITEM_FreeItem(&xtnData->nextProto, PR_FALSE);
    tls13_DestroyKeyShares(&xtnData->remoteKeyShares);
    SECITEM_FreeItem(&xtnData->certReqContext, PR_FALSE);
    if (xtnData->certReqAuthorities.arena) {
        PORT_FreeArena(xtnData->certReqAuthorities.arena, PR_FALSE);
        xtnData->certReqAuthorities.arena = NULL;
    }

    /* Now reinit. */
    ssl3_InitExtensionData(xtnData);
}

/* Thunks to let extension handlers operate on const sslSocket* objects. */
void
ssl3_ExtSendAlert(const sslSocket *ss, SSL3AlertLevel level,
                  SSL3AlertDescription desc)
{
    (void)SSL3_SendAlert((sslSocket *)ss, level, desc);
}

void
ssl3_ExtDecodeError(const sslSocket *ss)
{
    (void)ssl3_DecodeError((sslSocket *)ss);
}

SECStatus
ssl3_ExtConsumeHandshake(const sslSocket *ss, void *v, PRUint32 bytes,
                         PRUint8 **b, PRUint32 *length)
{
    return ssl3_ConsumeHandshake((sslSocket *)ss, v, bytes, b, length);
}

SECStatus
ssl3_ExtConsumeHandshakeNumber(const sslSocket *ss, PRUint32 *num,
                               PRUint32 bytes, PRUint8 **b, PRUint32 *length)
{
    return ssl3_ConsumeHandshakeNumber((sslSocket *)ss, num, bytes, b, length);
}

SECStatus
ssl3_ExtConsumeHandshakeVariable(const sslSocket *ss, SECItem *i,
                                 PRUint32 bytes, PRUint8 **b,
                                 PRUint32 *length)
{
    return ssl3_ConsumeHandshakeVariable((sslSocket *)ss, i, bytes, b, length);
}
