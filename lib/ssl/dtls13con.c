/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * DTLS 1.3 Protocol
 */

#include "ssl.h"
#include "sslimpl.h"
#include "sslproto.h"

/* DTLS 1.3 Record map for ACK processing.
 * This represents a single fragment, so a record which includes
 * multiple fragments will have one entry for each fragment on the
 * sender. We use the same structure on the receiver for convenience
 * but the only value we actually use is |record|.
 */
typedef struct DTLSHandshakeRecordEntryStr {
    PRCList link;
    PRUint16 messageSeq;      /* The handshake message sequence */
    PRUint32 offset;          /* The offset into the handshake message. */
    PRUint32 length;          /* The length of the fragment. */
    sslSequenceNumber record; /* The record */
    PRBool acked;             /* Has this packet been acked. */
} DTLSHandshakeRecordEntry;

SECStatus
dtls13_RememberFragment(sslSocket *ss,
                        PRCList *list,
                        PRUint32 sequence,
                        PRUint32 offset,
                        PRUint32 length,
                        sslSequenceNumber record)
{
    DTLSHandshakeRecordEntry *entry;
    PORT_Assert(IS_DTLS(ss));
    PORT_Assert(tls13_MaybeTls13(ss));
    PORT_Assert(sequence != 0xffff);
    SSL_TRC(20, ("%d: SSL3[%d]: %s remembering %s record=%llx msg=%d offset=%d",
                 SSL_GETPID(), ss->fd,
                 SSL_ROLE(ss),
                 list == &ss->ssl3.hs.dtlsSentHandshake ? "sent" : "received",
                 record, sequence, offset));

    entry = PORT_ZAlloc(sizeof(DTLSHandshakeRecordEntry));
    if (!entry) {
        return SECFailure;
    }

    entry->messageSeq = sequence;
    entry->offset = offset;
    entry->length = length;
    entry->record = record;
    entry->acked = PR_FALSE;

    PR_APPEND_LINK(&entry->link, list);

    return SECSuccess;
}

SECStatus
dtls13_SendAck(sslSocket *ss)
{
    sslBuffer buf = { NULL, 0, 0 };
    SECStatus rv = SECSuccess;
    PRCList *cursor;
    PRInt32 sent;

    SSL_TRC(10, ("%d: SSL3[%d]: Sending ACK",
                 SSL_GETPID(), ss->fd));

    for (cursor = PR_LIST_HEAD(&ss->ssl3.hs.dtlsRcvdHandshake);
         cursor != &ss->ssl3.hs.dtlsRcvdHandshake;
         cursor = PR_NEXT_LINK(cursor)) {
        DTLSHandshakeRecordEntry *entry = (DTLSHandshakeRecordEntry *)cursor;

        SSL_TRC(10, ("%d: SSL3[%d]: ACK for record=%llx",
                     SSL_GETPID(), ss->fd, entry->record));
        rv = sslBuffer_AppendNumber(&buf, entry->record, 8);
        if (rv != SECSuccess) {
            goto loser;
        }
    }

    ssl_GetXmitBufLock(ss);
    sent = ssl3_SendRecord(ss, NULL, content_ack,
                           buf.buf, buf.len, 0);
    ssl_ReleaseXmitBufLock(ss);
    if (sent != buf.len) {
        rv = SECFailure;
        if (sent != -1) {
            PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
        }
    }

loser:
    sslBuffer_Clear(&buf);
    return rv;
}

void
dtls13_SendAckCb(sslSocket *ss)
{
    if (!IS_DTLS(ss)) {
        return;
    }
    (void)dtls13_SendAck(ss);
}

/* Check to see if all of a message was ACKed. */
PRBool
dtls13_FragmentWasAcked(sslSocket *ss, PRUint16 msgSeq, PRUint32 offset,
                        PRUint32 len)
{
    PRCList *cursor;
    PORT_Assert(msgSeq != 0xffff);
    PORT_Assert(tls13_MaybeTls13(ss));

    for (cursor = PR_LIST_HEAD(&ss->ssl3.hs.dtlsSentHandshake);
         cursor != &ss->ssl3.hs.dtlsSentHandshake;
         cursor = PR_NEXT_LINK(cursor)) {
        DTLSHandshakeRecordEntry *entry = (DTLSHandshakeRecordEntry *)cursor;
        if (!entry->acked) {
            continue;
        }
        if (msgSeq != entry->messageSeq) {
            continue;
        }
        if (offset < entry->offset)
            continue;
        if ((offset + len) > (entry->offset + entry->length))
            continue;
        return PR_TRUE;
    }
    return PR_FALSE;
}

ssl3CipherSpec *
dtls13_FindCipherSpecByEpoch(sslSocket *ss, CipherSpecDirection direction,
                             DTLSEpoch epoch)
{
    PRCList *cur_p;
    PORT_Assert(ss->version >= SSL_LIBRARY_VERSION_TLS_1_3);
    for (cur_p = PR_LIST_HEAD(&ss->ssl3.hs.cipherSpecs);
         cur_p != &ss->ssl3.hs.cipherSpecs;
         cur_p = PR_NEXT_LINK(cur_p)) {
        ssl3CipherSpec *spec = (ssl3CipherSpec *)cur_p;

        if (spec->epoch != epoch) {
            continue;
        }
        if (direction != spec->direction) {
            continue;
        }
        return spec;
    }
    return NULL;
}

SECStatus
dtls13_SetupAcks(sslSocket *ss)
{
    if (ss->version < SSL_LIBRARY_VERSION_TLS_1_3) {
        return SECSuccess;
    }

    if (ss->ssl3.hs.endOfFlight) {
        dtls_CancelTimer(ss, ss->ssl3.hs.ackTimer);

        if (ss->ssl3.hs.ws == idle_handshake && ss->sec.isServer) {
            SSL_TRC(10, ("%d: SSL3[%d]: dtls_HandleHandshake, sending ACK",
                         SSL_GETPID(), ss->fd));
            return dtls13_SendAck(ss);
        }
        return SECSuccess;
    }

    /* We need to send an ACK. */
    if (!ss->ssl3.hs.ackTimer->cb) {
        /* We're not armed, so arm. */
        SSL_TRC(10, ("%d: SSL3[%d]: dtls_HandleHandshake, arming ack timer",
                     SSL_GETPID(), ss->fd));
        return dtls_StartTimer(ss, ss->ssl3.hs.ackTimer,
                               DTLS_RETRANSMIT_INITIAL_MS / 4,
                               dtls13_SendAckCb);
    }
    /* The ack timer is already armed, so just return. */
    return SECSuccess;
}

/*
 * Special case processing for out-of-epoch records.
 * This can only handle ACKs for now and everything else generates
 * an error. In future, may also handle KeyUpdate.
 *
 * The error checking here is as follows:
 *
 * - If it's not encrypted, out of epoch stuff is just discarded.
 * - If it's encrypted, out of epoch stuff causes an error.
 */
SECStatus
dtls13_HandleOutOfEpochRecord(sslSocket *ss, const ssl3CipherSpec *spec,
                              SSL3ContentType rType,
                              sslBuffer *databuf)
{
    SECStatus rv;
    sslBuffer buf = *databuf;

    databuf->len = 0; /* Discard data whatever happens. */
    PORT_Assert(IS_DTLS(ss));
    PORT_Assert(ss->version >= SSL_LIBRARY_VERSION_TLS_1_3);
    /* Can't happen, but double check. */
    if (!IS_DTLS(ss) || (ss->version < SSL_LIBRARY_VERSION_TLS_1_3)) {
        tls13_FatalError(ss, SEC_ERROR_LIBRARY_FAILURE, internal_error);
        return SECFailure;
    }
    SSL_TRC(10, ("%d: DTLS13[%d]: handle out of epoch record: type=%d", SSL_GETPID(),
                 ss->fd, rType));

    if (rType == content_ack) {
        ssl_GetSSL3HandshakeLock(ss);
        rv = dtls13_HandleAck(ss, &buf);
        ssl_ReleaseSSL3HandshakeLock(ss);
        PORT_Assert(databuf->len == 0);
        return rv;
    }

    switch (spec->epoch) {
        case TrafficKeyClearText:
            /* Drop. */
            return SECSuccess;

        case TrafficKeyHandshake:
            /* Drop out of order handshake messages, but if we are the
             * server, we might have processed the client's Finished and
             * moved on to application data keys, but the client has
             * retransmitted Finished (e.g., because our ACK got lost.)
             * We just retransmit the previous Finished to let the client
             * complete. */
            if (rType == content_handshake) {
                if ((ss->sec.isServer) &&
                    (ss->ssl3.hs.ws == idle_handshake)) {
                    PORT_Assert(dtls_TimerActive(ss, ss->ssl3.hs.hdTimer));
                    return dtls13_SendAck(ss);
                }
                return SECSuccess;
            }

            /* This isn't a handshake record, so shouldn't be encrypted
             * under the handshake key. */
            break;

        default:
            /* Any other epoch is forbidden. */
            break;
    }

    SSL_TRC(10, ("%d: SSL3[%d]: unexpected out of epoch record type %d", SSL_GETPID(),
                 ss->fd, rType));

    (void)SSL3_SendAlert(ss, alert_fatal, illegal_parameter);
    PORT_SetError(SSL_ERROR_RX_UNKNOWN_RECORD_TYPE);
    return SECFailure;
}

/* Store the null cipher spec with the right refct. */
SECStatus
dtls13_SaveNullCipherSpec(sslSocket *ss, const ssl3CipherSpec *crSpec)
{
    ssl3CipherSpec *spec;
    extern const char kKeyPhaseCleartext[];
    PORT_Assert(IS_DTLS(ss));

    spec = PORT_ZNew(ssl3CipherSpec);
    if (!spec) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }
    spec->refCt = 1;
    spec->cipher_def = crSpec->cipher_def;
    spec->mac_def = crSpec->mac_def;
    spec->decode = crSpec->decode;
    spec->epoch = crSpec->epoch;
    PORT_Memcpy(&spec->recvdRecords, &crSpec->recvdRecords,
                sizeof(spec->recvdRecords));
    spec->direction = CipherSpecRead;
    spec->phase = kKeyPhaseCleartext;
    spec->read_seq_num = crSpec->write_seq_num;
    spec->refCt = 1;

    PR_APPEND_LINK(&spec->link, &ss->ssl3.hs.cipherSpecs);

    return SECSuccess;
}

void
dtls13_ReleaseReadCipherSpec(sslSocket *ss, DTLSEpoch epoch)
{
    ssl3CipherSpec *spec;
    if (!IS_DTLS(ss)) {
        return;
    }

    SSL_TRC(10, ("%d: SSL3[%d]: releasing read cipher spec for epoch %d",
                 SSL_GETPID(), ss->fd, epoch));

    spec = dtls13_FindCipherSpecByEpoch(ss, CipherSpecRead, epoch);
    if (!spec) {
        return;
    }

    tls13_CipherSpecRelease(spec);
}

SECStatus
dtls13_HandleAck(sslSocket *ss, sslBuffer *databuf)
{
    PRUint8 *b = databuf->buf;
    PRUint32 l = databuf->len;
    SECStatus rv;
    PRBool messagesSent;

    /* Ensure we don't loop. */
    databuf->len = 0;

    PORT_Assert(IS_DTLS(ss));
    if (!tls13_MaybeTls13(ss)) {
        tls13_FatalError(ss, SSL_ERROR_RX_UNKNOWN_RECORD_TYPE, illegal_parameter);
        return SECSuccess;
    }

    SSL_TRC(10, ("%d: SSL3[%d]: Handling ACK", SSL_GETPID(), ss->fd));
    while (l > 0) {
        PRUint64 seq;
        PRCList *cursor;

        rv = ssl3_ConsumeHandshakeNumber64(ss, &seq, 8, &b, &l);
        if (rv != SECSuccess) {
            return SECFailure;
        }

        for (cursor = PR_LIST_HEAD(&ss->ssl3.hs.dtlsSentHandshake);
             cursor != &ss->ssl3.hs.dtlsSentHandshake;
             cursor = PR_NEXT_LINK(cursor)) {
            DTLSHandshakeRecordEntry *entry = (DTLSHandshakeRecordEntry *)cursor;

            if (entry->record == seq) {
                SSL_TRC(10, (
                                "%d: SSL3[%d]: Marking record=%llx message %d offset %d length=%d as ACKed",
                                SSL_GETPID(), ss->fd,
                                seq, entry->messageSeq, entry->offset, entry->length));
                entry->acked = PR_TRUE;
            }
        }
    }

    /* Try to flush. */
    rv = dtls_TransmitMessageFlight(ss, &messagesSent);
    if (rv != SECSuccess) {
        return SECFailure;
    }

    /* Reset the retransmit timer. */
    if (ss->ssl3.hs.rtTimer->cb) {
        (void)dtls_RestartTimer(ss, ss->ssl3.hs.rtTimer);
    }

    /* If no messages were sent, then clean up. */
    if (!messagesSent) {
        SSL_TRC(10, (
                        "%d: SSL3[%d]: No more unacked handshake messages, cancelling retransmits",
                        SSL_GETPID(), ss->fd));

        dtls_CancelTimer(ss, ss->ssl3.hs.rtTimer);
        ssl_ClearPRCList(&ss->ssl3.hs.dtlsSentHandshake, NULL);
        dtls_FreeHandshakeMessages(&ss->ssl3.hs.lastMessageFlight);
        /* If the handshake is finished, and we're the client then
         * also clean up the handshake read cipher spec. Any ACKs
         * we receive will be with the application data cipher spec.
         * The server needs to keep the handshake cipher spec around
         * for the holddown period to process retransmitted Finisheds.
         */
        if (!ss->sec.isServer && (ss->ssl3.hs.ws == idle_handshake)) {
            dtls13_ReleaseReadCipherSpec(ss, TrafficKeyHandshake);
        }
    }
    return SECSuccess;
}

/* Clean up the read timer for the handshake cipher suites on the
 * server.
 *
 * In DTLS 1.3, the client speaks last (Finished), and will retransmit
 * until the server ACKs that message (using application data cipher
 * suites). I.e.,
 *
 * - The client uses the retransmit timer and retransmits using the
 *   saved write handshake cipher suite.
 * - The server keeps the saved read handshake cipher suite around
 *   for the holddown period in case it needs to read the Finished.
 *
 * After the holddown period, the server assumes the client is happy
 * and discards the handshake read cipher suite.
 */
void
dtls13_HolddownTimerCb(sslSocket *ss)
{
    SSL_TRC(10, ("%d: SSL3[%d]: holddown timer fired",
                 SSL_GETPID(), ss->fd));
    dtls13_ReleaseReadCipherSpec(ss, TrafficKeyHandshake);
    ssl_ClearPRCList(&ss->ssl3.hs.dtlsRcvdHandshake, NULL);
}
