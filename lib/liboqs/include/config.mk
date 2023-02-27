# DO NOT EDIT: generated from  config.mk.include.template
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# this controls where the headers are written to, liboqs
# reuses names like crazy and some of the internal headers
# match the liboqs external header names. liboqs distinguishes
# this by and explicit oqs/ in the name, so copy the headers
# to our module/oqs
SOURCE_XPPRIVATE_DIR   = $(SOURCE_XP_DIR)/private/$(MODULE)/oqs

