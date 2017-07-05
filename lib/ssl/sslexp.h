/*
 * This file contains prototypes for experimental SSL functions.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __sslexp_h_
#define __sslexp_h_

#include "ssl.h"
#include "sslerr.h"

SEC_BEGIN_PROTOS

/* The functions in this header file are not guaranteed to remain available in
 * future NSS versions. Code that uses these functions needs to safeguard
 * against the function not being available. */

#define SSL_EXPERIMENTAL_API(name, arglist, args)                   \
    (SSL_GetExperimentalAPI(name)                                   \
         ? ((SECStatus(*) arglist)SSL_GetExperimentalAPI(name))args \
         : SECFailure)

/*
 * Setup the anti-replay buffer for supporting 0-RTT in TLS 1.3 on servers.
 *
 * To use 0-RTT on a server, you must call this function.  Failing to call this
 * function will result in all 0-RTT being rejected.  Connections will complete,
 * but early data will be rejected.
 *
 * NSS uses a Bloom filter to track the ClientHello messages that it receives
 * (specifically, it uses the PSK binder).  This function initializes a pair of
 * Bloom filters.  The two filters are alternated over time, with new
 * ClientHello messages recorded in the current filter and, if they are not
 * already present, being checked against the previous filter.  If the
 * ClientHello is found, then early data is rejected, but the handshake is
 * allowed to proceed.
 *
 * The false-positive probability of Bloom filters means that some valid
 * handshakes will be marked as potential replays.  Early data will be rejected
 * for a false positive.  To minimize this and to allow a trade-off of space
 * against accuracy, the size of the Bloom filter can be set by this function.
 *
 * The first tuning parameter to consider is |window|, which determines the
 * window over which ClientHello messages will be tracked.  This also causes
 * early data to be rejected if a ClientHello contains a ticket age parameter
 * that is outside of this window (see Section 4.2.10.4 of
 * draft-ietf-tls-tls13-20 for details).  Set |window| to account for any
 * potential sources of clock error.  |window| is the entire width of the
 * window, which is symmetrical.  Therefore to allow 5 seconds of clock error in
 * both directions, set the value to 10 seconds (i.e., 10 * PR_USEC_PER_SEC).
 *
 * After calling this function, early data will be rejected until |window|
 * elapses.  This prevents replay across crashes and restarts.  Only call this
 * function once to avoid inadvertently disabling 0-RTT (use PR_CallOnce() to
 * avoid this problem).
 *
 * The primary tuning parameter is |bits| which determines the amount of memory
 * allocated to each Bloom filter.  NSS will allocate two Bloom filters, each
 * |2^(bits - 3)| octets in size.  The value of |bits| is primarily driven by
 * the number of connections that are expected in any time window.  Note that
 * this needs to account for there being two filters both of which have
 * (presumably) independent false positive rates.  The following formulae can be
 * used to find a value of |bits| and |k| given a chosen false positive
 * probability |p| and the number of requests expected in a given window |n|:
 *
 *   bits = log2(n) + log2(-ln(1 - sqrt(1 - p))) + 1.0575327458897952
 *   k = -log2(p)
 *
 * ... where log2 and ln are base 2 and e logarithms respectively.  For a target
 * false positive rate of 1% and 1000 handshake attempts, this produces bits=14
 * and k=7.  This results in two Bloom filters that are 2kB each in size.  Note
 * that rounding |k| and |bits| up causes the false positive probability for
 * these values to be a much lower 0.123%.
 *
 * IMPORTANT: This anti-replay scheme has several weaknesses.  See the TLS 1.3
 * specification for the details of the generic problems with this technique.
 *
 * In addition to the generic anti-replay weaknesses, the state that the server
 * maintains is in local memory only.  Servers that operate in a cluster, even
 * those that use shared memory for tickets, will not share anti-replay state.
 * Early data can be replayed at least once with every server instance that will
 * accept tickets that are encrypted with the same key.
 */
#define SSL_SetupAntiReplay(window, k, bits)                                    \
    SSL_EXPERIMENTAL_API("SSL_SetupAntiReplay",                                 \
                         (PRTime _window, unsigned int _k, unsigned int _bits), \
                         (window, k, bits))

SEC_END_PROTOS

#endif /* __sslexp_h_ */
