/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef ML_DSAT_H
#define ML_DSAT_H

// ML_DSA Key and signature sizes, independent of implementation

// ml_dsa_44
#define ML_DSA_44_PUBLICKEY_LEN 1312
#define ML_DSA_44_PRIVATEKEY_LEN 2560
#define ML_DSA_44_SIGNATURE_LEN 2420

// ml_dsa_65
#define ML_DSA_65_PUBLICKEY_LEN 1952
#define ML_DSA_65_PRIVATEKEY_LEN 4032
#define ML_DSA_65_SIGNATURE_LEN 3309

// ml_dsa_87
#define ML_DSA_87_PUBLICKEY_LEN 2592
#define ML_DSA_87_PRIVATEKEY_LEN 4896
#define ML_DSA_87_SIGNATURE_LEN 4627

// the max defines and common defines
#define MAX_ML_DSA_PRIVATE_KEY_LEN ML_DSA_87_PRIVATEKEY_LEN
#define MAX_ML_DSA_PUBLIC_KEY_LEN ML_DSA_87_PUBLICKEY_LEN
#define MAX_ML_DSA_SIGNATURE_LEN ML_DSA_87_SIGNATURE_LEN
#define ML_DSA_SEED_LEN 32

#endif /* ML_DSAT_H */
