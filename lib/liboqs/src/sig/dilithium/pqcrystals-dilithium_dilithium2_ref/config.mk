# DO NOT EDIT: generated from  config.mk.subdirs.template
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# add fixes for platform integration issues here.
#
# liboqs programs expect the public include files to be in oqs/xxxx,
# So we put liboqs in it's own module, oqs, and point to the dist files
INCLUDES += -I$(CORE_DEPTH)/lib/liboqs/src/common/pqclean_shims -I$(CORE_DEPTH)/lib/liboqs/src/common/sha3/xkcp_low/KeccakP-1600/plain-64bits
DEFINES += -DDILITHIUM_MODE=2 -DDILITHIUM_RANDOMIZED_SIGNING

ifeq ($(OS_ARCH), Darwin)
DEFINES += -DOQS_HAVE_ALIGNED_ALLOC -DOQS_HAVE_MEMALIGN -DOQS_HAVE_POSIX_MEMALIGN
endif

