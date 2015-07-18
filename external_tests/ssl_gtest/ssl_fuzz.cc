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

#define BUF_SIZE 100

namespace nss_test {


TEST(FuzzTest, Fuzz) {
	FILE *fp;
	uint8_t buf[BUF_SIZE] = {0};
	DataBuffer* data;

	TlsAgent* client_ = new TlsAgent("client", TlsAgent::CLIENT, STREAM, ssl_kea_rsa);
	PRFileDesc* fd = DummyPrSocket::CreateFD("client", STREAM);
	DummyPrSocket* ds = DummyPrSocket::GetAdapter(fd);
	
	client_->adapter()->SetPeer(ds);

	fp = fopen("/dev/urandom", "rb");
	fread(buf, 1, BUF_SIZE, fp);
	fclose(fp);
	data = new DataBuffer();
	data->Assign(buf, BUF_SIZE);

	client_->adapter()->PacketReceived(*data);

	delete data;
	delete fd;
	delete client_;
}

}  // namespace nspr_test
