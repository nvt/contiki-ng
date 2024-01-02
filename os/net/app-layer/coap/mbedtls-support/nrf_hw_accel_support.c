/*
 * Copyright (c) 2022, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         Hardware acceleration support for Mbed TLS from nRF SDK.
 * \author
 *         Jayendra Ellamathy <ejayen@gmail.com>
 */

#include MBEDTLS_CONFIG_FILE

#ifdef NRF_HW_ACCEL_FOR_MBEDTLS

#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/platform_util.h"

#include "nrf_crypto.h"
#include "nrf_crypto_error.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_ecdh.h"
#include "nrf_crypto_ecdsa.h"
#include "nrf_crypto_rng.h"

#include "sys/log.h"

/* Log configuration */
#define LOG_MODULE "Mbed-TLS HW Accel"
#define LOG_LEVEL LOG_LEVEL_DTLS

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
int
mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                            const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
  nrf_crypto_ecdh_secp256r1_shared_secret_t nrf_z;
  nrf_crypto_ecc_public_key_t nrf_Q;
  nrf_crypto_ecc_private_key_t nrf_d;
  nrf_crypto_ecc_secp256r1_raw_public_key_t nrf_Q_raw;
  nrf_crypto_ecc_secp256r1_raw_private_key_t nrf_d_raw;
  int ret = -1;
  ret_code_t nrf_ret = NRF_SUCCESS;
  size_t size;

  if(grp == NULL || Q == NULL || d == NULL || z == NULL) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    return ret;
  }

  /* Only Secp256r1 NIST curve supported for now */
  if(grp->id != MBEDTLS_ECP_DP_SECP256R1) {
    ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Unsupported NIST curve");
    return ret;
  }

  /* Convert from Mbed TLS format to raw binary format */
  size = sizeof(nrf_crypto_ecc_secp256r1_raw_private_key_t);
  if((ret = mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(X), nrf_Q_raw, size)) != 0) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad public key");
    return ret;
  }
  if((ret = mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(Y), &nrf_Q_raw[size], size)) != 0) {
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad public key");
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    return ret;
  }

  if((ret = mbedtls_mpi_write_binary(d, nrf_d_raw, size)) != 0) {
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad private key");
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    return ret;
  }

  /* Convert from raw binary format to nRF crypto format */
  size = sizeof(nrf_Q_raw);
  if((nrf_ret = nrf_crypto_ecc_public_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,
        &nrf_Q, nrf_Q_raw, size)) != NRF_SUCCESS) {
    ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, (nrf_crypto_error_string_get(nrf_ret)));
    return ret;
  }

  size = sizeof(nrf_d_raw);
  if((nrf_ret = nrf_crypto_ecc_private_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,
        &nrf_d, nrf_d_raw, size)) != NRF_SUCCESS) {
    ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, (nrf_crypto_error_string_get(nrf_ret)));
    return ret;
  }

  /* nRF crypto ECDH shared secret computation */
  size = sizeof(nrf_z);
  if((nrf_ret = nrf_crypto_ecdh_compute(NULL,
                                        &nrf_d, &nrf_Q, nrf_z, &size)) != NRF_SUCCESS) {
    ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, (nrf_crypto_error_string_get(nrf_ret)));
    return ret;
  }

  /* Convert back from raw binary format to Mbed TLS format */
  if((ret = mbedtls_mpi_read_binary(z, nrf_z, size)) != 0) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad shared secret");
    return ret;
  }

  return 0;
}
#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
int
mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                     const unsigned char *buf, size_t blen,
                     const mbedtls_ecp_point *Q,
                     const mbedtls_mpi *r,
                     const mbedtls_mpi *s)
{
  nrf_crypto_ecc_secp256r1_raw_public_key_t nrf_Q_raw;
  nrf_crypto_ecc_public_key_t nrf_Q;
  nrf_crypto_ecdsa_secp256r1_signature_t signature;
  int ret = -1;
  ret_code_t nrf_ret = NRF_SUCCESS;
  size_t size;

  if(grp == NULL || Q == NULL || r == NULL
     || s == NULL || buf == NULL || blen == 0) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    return ret;
  }

  /* Only Secp256r1 NIST curve supported for now */
  if(grp->id != MBEDTLS_ECP_DP_SECP256R1) {
    ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Unsupported NIST curve");
    return ret;
  }

  /* Convert from Mbed TLS format to raw binary format */
  size = sizeof(nrf_crypto_ecc_secp256r1_raw_private_key_t);
  if((ret = mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(X), nrf_Q_raw, size)) != 0) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad public key");
    return ret;
  }
  if((ret = mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(Y), &nrf_Q_raw[size], size)) != 0) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad public key");
    return ret;
  }

  if((ret = mbedtls_mpi_write_binary(r, signature, size)) != 0) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad signature");
    return ret;
  }

  if((ret = mbedtls_mpi_write_binary(s, &signature[size], size)) != 0) {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, "Bad signature");
    return ret;
  }

  /* Convert from raw binary format to nRF crypto format */
  size = sizeof(nrf_Q_raw);
  if((nrf_ret = nrf_crypto_ecc_public_key_from_raw(
        &g_nrf_crypto_ecc_secp256r1_curve_info,
        &nrf_Q, nrf_Q_raw, size)) != NRF_SUCCESS) {
    ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, (nrf_crypto_error_string_get(nrf_ret)));
    return ret;
  }

  /* nRF crypto ECDSA verify */
  size = sizeof(signature);
  if((nrf_ret = nrf_crypto_ecdsa_verify(NULL,
                                        &nrf_Q, buf, blen, signature, size)) != NRF_SUCCESS) {
    ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
    LOG_ERR("%s:%d: %s\n", __FILE__, __LINE__, (nrf_crypto_error_string_get(nrf_ret)));
    return ret;
  }

  return 0;
}
#endif /* MBEDTLS_ECDSA_VERIFY_ALT */
#endif /* NRF_HW_ACCEL_FOR_MBEDTLS */
