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
/**
 * \file
 *         Hardware random number generation via the nRF54L15 CRACEN
 *         cryptographic accelerator (CTR-DRBG).
 *
 *         The vendored nrfx CRACEN driver only exposes a CTR-DRBG random
 *         generator (no AES/hash/PKE), which is exactly what we need to feed
 *         the Contiki-NG CSPRNG with hardware entropy on the nRF54L15, since
 *         this SoC has no standalone RNG peripheral.
 * \author
 *         Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */
/*---------------------------------------------------------------------------*/
#include "cracen-rng.h"

#include <nrfx.h>
#include <nrfx_cracen.h>
/*---------------------------------------------------------------------------*/
bool
cracen_rng_get(uint8_t *buf, size_t len)
{
  bool ok;

  if(buf == NULL || len == 0) {
    return false;
  }

  if(nrfx_cracen_ctr_drbg_init() != NRFX_SUCCESS) {
    return false;
  }

  ok = nrfx_cracen_ctr_drbg_random_get(buf, len) == NRFX_SUCCESS;

  nrfx_cracen_ctr_drbg_uninit();

  return ok;
}
/*---------------------------------------------------------------------------*/
