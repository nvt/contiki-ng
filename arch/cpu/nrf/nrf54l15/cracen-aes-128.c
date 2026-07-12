/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
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
/*---------------------------------------------------------------------------*/
/**
 * \file
 *         AES-128 driver for the nRF54L15 CRACEN cryptographic accelerator.
 * \author
 *         Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 *
 *         The single-block ECB operation drives the CRACEN CryptoMaster with a
 *         chain of DMA descriptors (config + key + payload in, ciphertext out),
 *         following the sequence the vendored nrfx CRACEN driver uses
 *         internally for its CTR-DRBG. Only public nrfx HALs are used here.
 *
 *         Note: the CryptoMaster is a single shared resource. This driver
 *         claims and releases it per block and does not yet arbitrate against
 *         other CRACEN users (e.g. the CTR-DRBG RNG); such arbitration is
 *         future work once both land on the same tree.
 */
/*---------------------------------------------------------------------------*/
#include "contiki.h"
#include "cracen-aes-128.h"

#include <nrfx.h>
#include <hal/nrf_cracen.h>
#include <hal/nrf_cracen_cm.h>
#include <helpers/nrf_cracen_cm_dma.h>

#include <string.h>
/*---------------------------------------------------------------------------*/
/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "CRACEN-AES"
#define LOG_LEVEL LOG_LEVEL_NONE
/*---------------------------------------------------------------------------*/
static uint8_t current_key[AES_128_KEY_LENGTH];
/*---------------------------------------------------------------------------*/
/*
 * Run one AES-128 ECB block through the CryptoMaster.
 * Returns true on success, false if the hardware reported a DMA error.
 */
static bool
aes_ecb_block(const uint8_t *key, const uint8_t *input, uint8_t *output)
{
  static const uint32_t aes_config_value = NRF_CRACEN_CM_AES_CONFIG(
    NRF_CRACEN_CM_AES_CONFIG_MODE_ECB,
    NRF_CRACEN_CM_AES_CONFIG_KEY_SW_PROGRAMMED,
    false, false, false);

  struct nrf_cracen_cm_dma_desc in_descs[3];
  struct nrf_cracen_cm_dma_desc out_desc;
  uint32_t pending;
  uint32_t busy;

  /* Fetch chain: AES configuration, key, then the 16-byte payload. */
  in_descs[0].p_addr = (uint8_t *)(uintptr_t)&aes_config_value;
  in_descs[0].length = sizeof(aes_config_value) | NRF_CRACEN_CM_DMA_DESC_LENGTH_REALIGN;
  in_descs[0].dmatag = NRF_CRACEN_CM_DMA_TAG_AES_CONFIG(NRF_CRACEN_CM_AES_REG_OFFSET_CONFIG);
  in_descs[0].p_next = &in_descs[1];

  in_descs[1].p_addr = (uint8_t *)(uintptr_t)key;
  in_descs[1].length = AES_128_KEY_LENGTH | NRF_CRACEN_CM_DMA_DESC_LENGTH_REALIGN;
  in_descs[1].dmatag = NRF_CRACEN_CM_DMA_TAG_AES_CONFIG(NRF_CRACEN_CM_AES_REG_OFFSET_KEY);
  in_descs[1].p_next = &in_descs[2];

  in_descs[2].p_addr = (uint8_t *)(uintptr_t)input;
  in_descs[2].length = AES_128_BLOCK_SIZE | NRF_CRACEN_CM_DMA_DESC_LENGTH_REALIGN;
  in_descs[2].dmatag = NRF_CRACEN_CM_DMA_TAG_LAST | NRF_CRACEN_CM_DMA_TAG_ENGINE_AES
                       | NRF_CRACEN_CM_DMA_TAG_DATATYPE_AES_PAYLOAD;
  in_descs[2].p_next = NRF_CRACEN_CM_DMA_DESC_STOP;

  /* Push chain: the 16-byte ciphertext. */
  out_desc.p_addr = output;
  out_desc.length = AES_128_BLOCK_SIZE | NRF_CRACEN_CM_DMA_DESC_LENGTH_REALIGN;
  out_desc.dmatag = NRF_CRACEN_CM_DMA_TAG_LAST;
  out_desc.p_next = NRF_CRACEN_CM_DMA_DESC_STOP;

  nrf_cracen_module_enable(NRF_CRACEN, NRF_CRACEN_MODULE_CRYPTOMASTER_MASK);

  nrf_cracen_cm_fetch_addr_set(NRF_CRACENCORE, (void *)in_descs);
  nrf_cracen_cm_push_addr_set(NRF_CRACENCORE, (void *)&out_desc);
  nrf_cracen_cm_config_indirect_set(NRF_CRACENCORE,
                                    (nrf_cracen_cm_config_indirect_mask_t)
                                    (NRF_CRACEN_CM_CONFIG_INDIRECT_FETCH_MASK |
                                     NRF_CRACEN_CM_CONFIG_INDIRECT_PUSH_MASK));

  /* Ensure the descriptors are visible before the CryptoMaster reads them. */
  __DMB();

  nrf_cracen_cm_start(NRF_CRACENCORE);

  /* The CryptoMaster completes in a few cycles; busy-wait rather than take an
   * interrupt for a single block. */
  do {
    pending = nrf_cracen_cm_int_pending_get(NRF_CRACENCORE);
    if(pending & (NRF_CRACEN_CM_INT_FETCH_ERROR_MASK |
                  NRF_CRACEN_CM_INT_PUSH_ERROR_MASK)) {
      LOG_ERR("CryptoMaster DMA error (0x%08lx)\n", (unsigned long)pending);
      break;
    }
    busy = nrf_cracen_cm_status_get(NRF_CRACENCORE,
                                    (NRF_CRACEN_CM_STATUS_BUSY_FETCH_MASK |
                                     NRF_CRACEN_CM_STATUS_BUSY_PUSH_MASK |
                                     NRF_CRACEN_CM_STATUS_PUSH_WAITING_MASK));
  } while(busy);

  nrf_cracen_cm_softreset(NRF_CRACENCORE);
  nrf_cracen_module_disable(NRF_CRACEN, NRF_CRACEN_MODULE_CRYPTOMASTER_MASK);

  return (pending & (NRF_CRACEN_CM_INT_FETCH_ERROR_MASK |
                     NRF_CRACEN_CM_INT_PUSH_ERROR_MASK)) == 0;
}
/*---------------------------------------------------------------------------*/
static void
set_key(const uint8_t *key)
{
  memcpy(current_key, key, sizeof(current_key));
}
/*---------------------------------------------------------------------------*/
static void
encrypt(uint8_t *plaintext_and_result)
{
  uint8_t output[AES_128_BLOCK_SIZE];

  if(aes_ecb_block(current_key, plaintext_and_result, output)) {
    memcpy(plaintext_and_result, output, sizeof(output));
  }
}
/*---------------------------------------------------------------------------*/
const struct aes_128_driver cracen_aes_128_driver = {
  set_key,
  encrypt
};
/*---------------------------------------------------------------------------*/
