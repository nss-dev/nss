/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "ssl.h"
#include "sslproto.h"

#include <memory>

#include "test_io.h"
#include "tls_agent.h"
#include "tls_parser.h"
#include "tls_filter.h"
#include "tls_connect.h"


namespace nss_test {

TEST(FuzzTest, Fuzz) {
	FILE *fp;
	uint8_t *buf;
	DataBuffer* data;
	unsigned long length;
	const char *test_case_name = getenv("FUZZ_TEST_CASE");
	ASSERT_NE(nullptr, test_case_name);

	TlsAgent* client_ = new TlsAgent("client", TlsAgent::CLIENT, STREAM, ssl_kea_rsa);
	PRFileDesc* fd = DummyPrSocket::CreateFD("client", STREAM);
	DummyPrSocket* ds = DummyPrSocket::GetAdapter(fd);

	client_->Init();
	client_->adapter()->SetPeer(ds);
	client_->StartConnect();

	fp = fopen(test_case_name, "rb");
	ASSERT_NE(nullptr, fp);
	fseek(fp , 0, SEEK_END);
	length = ftell(fp) + 1;
	buf = (uint8_t *)malloc(length);
	fseek(fp , 0, SEEK_SET);
	fread(buf, 1, sizeof(buf), fp);
	fclose(fp);
	data = new DataBuffer(buf, length);
	free(buf);

	client_->adapter()->PacketReceived(*data);
	client_->Handshake();

	delete data;
	delete ds;
	delete fd;
	delete client_;
}

}
