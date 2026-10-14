/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * test_httpdefaultclient.c
 *
 * Test HttpDefaultClient header parsing, in particular that a malformed
 * HTTP response whose body is larger than its declared Content-Length is
 * rejected rather than overflowing the response buffer (bug 2050034).
 *
 */

#include "testutil.h"
#include "testutil_nss.h"
#include "pkix_pl_common.h"
#include "pkix_pl_httpdefaultclient.h"

static void *plContext = NULL;

/*
 * Drives pkix_pl_HttpDefaultClient_HdrCheckComplete over a single,
 * fully-buffered HTTP response and checks the resulting connectStatus.
 *
 * "response"/"responseLen" describe the bytes the client has just received
 * (header and body together, exactly as a single read would have delivered
 * them). "expectedStatus" is the connectStatus the header parser should
 * settle on.
 */
static void
testResponse(
    char *subTestName,
    const char *response,
    PKIX_UInt32 responseLen,
    HttpConnectStatus expectedStatus)
{
    PKIX_PL_HttpDefaultClient *client = NULL;
    PKIX_Boolean keepGoing = PKIX_FALSE;
    char *rcvBuf = NULL;

    PKIX_TEST_STD_VARS();

    subTest(subTestName);

    PKIX_TEST_EXPECT_NO_ERROR(pkix_pl_HttpDefaultClient_Create(
        "localhost", 80, &client, plContext));

    /*
     * Hand the client a receive buffer holding the whole response. The
     * buffer is sized exactly to the bytes received, so an over-copy past
     * the declared Content-Length is caught by ASan as a heap overflow.
     */
    PKIX_TEST_EXPECT_NO_ERROR(
        PKIX_PL_Malloc(responseLen, (void **)&rcvBuf, plContext));
    PORT_Memcpy(rcvBuf, response, responseLen);

    client->rcvBuf = rcvBuf;
    client->capacity = responseLen;
    client->filledupBytes = 0;
    client->connectStatus = HTTP_RECV_HDR;

    /* Ownership of rcvBuf passes to the client; it is freed on Destroy. */
    rcvBuf = NULL;

    PKIX_TEST_EXPECT_NO_ERROR(pkix_pl_HttpDefaultClient_HdrCheckComplete(
        client, responseLen, &keepGoing, plContext));

    if (client->connectStatus != expectedStatus) {
        pkixTestErrorMsg =
            "HdrCheckComplete produced an unexpected connectStatus.";
        goto cleanup;
    }

cleanup:

    PKIX_TEST_DECREF_AC(client);

    PKIX_TEST_RETURN();
}

int
test_httpdefaultclient(int argc, char *argv[])
{
    /*
     * A 1-byte body that occupies its full declared Content-Length: the
     * parser should report a complete message.
     */
    const char *exact =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Content-Length: 1\r\n"
        "\r\n"
        "A";

    /*
     * Content-Length declares more than is present: the parser should ask
     * for more body data.
     */
    const char *shortBody =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Content-Length: 16\r\n"
        "\r\n"
        "A";

    /*
     * The malformed case from bug 2050034: Content-Length declares 1 byte
     * but 64 body bytes are delivered in the same buffer. The parser must
     * reject the response rather than copy 64 bytes into a 1-byte buffer.
     */
    const char *overflow =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Content-Length: 1\r\n"
        "\r\n"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    PKIX_UInt32 actualMinorVersion = 0;

    PKIX_TEST_STD_VARS();

    startTests("HttpDefaultClient");

    PKIX_TEST_EXPECT_NO_ERROR(PKIX_Initialize(PKIX_TRUE, /* nssInitNeeded */
                                              PKIX_MAJOR_VERSION,
                                              PKIX_MINOR_VERSION,
                                              PKIX_MINOR_VERSION,
                                              &actualMinorVersion,
                                              &plContext));

    testResponse("Body matches Content-Length (complete)",
                 exact, PL_strlen(exact), HTTP_COMPLETE);

    testResponse("Body shorter than Content-Length (need more)",
                 shortBody, PL_strlen(shortBody), HTTP_RECV_BODY);

    testResponse("Body longer than Content-Length (bug 2050034)",
                 overflow, PL_strlen(overflow), HTTP_ERROR);

cleanup:

    PKIX_Shutdown(plContext);

    PKIX_TEST_RETURN();

    endTests("HttpDefaultClient");

    return (0);
}
