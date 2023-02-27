# DO NOT EDIT: generated from  config.mk.template
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# add fixes for platform integration issues here.
# 
# liboqs programs expect the public include files to be in oqs/xxxx,
# So we put liboqs in it's own module, oqs, and point to the dist files
INCLUDES += -I$(SOURCE_XP_DIR)/private

SHARED_LIBRARY_LIBS = \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common_aes.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-sha256-256s-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_kem_kyber_pqcrystals-kyber_kyber512_ref.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-shake256-128s-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_dilithium_pqcrystals-dilithium_dilithium2_ref.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common_sha3_xkcp_low_KeccakP-1600_plain-64bits.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-sha256-128f-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-shake256-192f-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-sha256-192f-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-sha256-192s-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-shake256-256f-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_kem.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_dilithium_pqcrystals-dilithium_dilithium3_ref.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common_sha3_xkcp_low_KeccakP-1600times4_serial.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_falcon_pqclean_falcon-512_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common_pqclean_shims.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common_rand.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-shake256-192s-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-shake256-256s-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-sha256-128s-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-sha256-256f-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_falcon.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common_sha2.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_common_sha3.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_falcon_pqclean_falcon-1024_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_dilithium_pqcrystals-dilithium_dilithium5_ref.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_sphincs_pqclean_sphincs-shake256-128f-simple_clean.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_kem_kyber.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_kem_kyber_pqcrystals-kyber_kyber768_ref.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_sig_dilithium.$(LIB_SUFFIX) \
	$(DIST)/lib/$(LIB_PREFIX)oqs_src_kem_kyber_pqcrystals-kyber_kyber1024_ref.$(LIB_SUFFIX) \
	$(NULL)

SHARED_LIBRARY_DIRS = \
	include \
	src/common/aes \
	src/sig/sphincs/pqclean_sphincs-sha256-256s-simple_clean \
	src/kem/kyber/pqcrystals-kyber_kyber512_ref \
	src/sig/sphincs \
	src/sig/sphincs/pqclean_sphincs-shake256-128s-simple_clean \
	src/sig/dilithium/pqcrystals-dilithium_dilithium2_ref \
	src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits \
	src/sig/sphincs/pqclean_sphincs-sha256-128f-simple_clean \
	src/sig/sphincs/pqclean_sphincs-shake256-192f-simple_clean \
	src/sig/sphincs/pqclean_sphincs-sha256-192f-simple_clean \
	src/sig \
	src/common \
	src/sig/sphincs/pqclean_sphincs-sha256-192s-simple_clean \
	src/sig/sphincs/pqclean_sphincs-shake256-256f-simple_clean \
	src/kem \
	src/sig/dilithium/pqcrystals-dilithium_dilithium3_ref \
	src/common/sha3/xkcp_low/KeccakP-1600times4/serial \
	src/sig/falcon/pqclean_falcon-512_clean \
	src/common/pqclean_shims \
	src/common/rand \
	src/sig/sphincs/pqclean_sphincs-shake256-192s-simple_clean \
	src/sig/sphincs/pqclean_sphincs-shake256-256s-simple_clean \
	src/sig/sphincs/pqclean_sphincs-sha256-128s-simple_clean \
	src/sig/sphincs/pqclean_sphincs-sha256-256f-simple_clean \
	src/sig/falcon \
	src/common/sha2 \
	src/common/sha3 \
	src/sig/falcon/pqclean_falcon-1024_clean \
	src/sig/dilithium/pqcrystals-dilithium_dilithium5_ref \
	src/sig/sphincs/pqclean_sphincs-shake256-128f-simple_clean \
	src/kem/kyber \
	src/kem/kyber/pqcrystals-kyber_kyber768_ref \
	src/sig/dilithium \
	src/kem/kyber/pqcrystals-kyber_kyber1024_ref \
	$(NULL)

     
