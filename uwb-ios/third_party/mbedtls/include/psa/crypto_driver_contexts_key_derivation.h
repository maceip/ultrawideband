/*
 *  Declaration of context structures for use with the PSA driver wrapper
 *  interface. This file contains the context structures for key derivation
 *  operations.
 *
 *  Warning: This file will be auto-generated in the future.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h.
 *
 * \note This header and its content are not part of the Mbed TLS API and
 * applications must not depend on it. Its main purpose is to define the
 * multi-part state objects of the PSA drivers included in the cryptographic
 * library. The definitions of these objects are then used by crypto_struct.h
 * to define the implementation-defined types of PSA multi-part state objects.
 */
/*  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H
#define PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H

#include "psa/crypto_driver_common.h"

/* Include the context structure definitions for the Mbed TLS software drivers */
#include "psa/crypto_builtin_key_derivation.h"

/* Include the context structure definitions for those drivers that were
 * declared during the autogeneration process. */

typedef union {
    unsigned dummy; /* Make sure this union is always non-empty */
#if defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXTRACT) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_HKDF_EXPAND)
    psa_hkdf_key_derivation_t MBEDTLS_PRIVATE(hkdf);
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PRF) || \
    defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_PSK_TO_MS)
    psa_tls12_prf_key_derivation_t MBEDTLS_PRIVATE(tls12_prf);
#endif
#if defined(MBEDTLS_PSA_BUILTIN_ALG_TLS12_ECJPAKE_TO_PMS)
    psa_tls12_ecjpake_to_pms_t MBEDTLS_PRIVATE(tls12_ecjpake_to_pms);
#endif
} psa_driver_key_derivation_context_t;

#endif /* PSA_CRYPTO_DRIVER_CONTEXTS_KEY_DERIVATION_H */
/* End of automatically generated file. */
