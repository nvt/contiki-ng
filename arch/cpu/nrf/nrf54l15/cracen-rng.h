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
 * \author
 *         Nicolas Tsiftes <nicolas.tsiftes@ri.se>
 */
/*---------------------------------------------------------------------------*/
#ifndef CRACEN_RNG_H_
#define CRACEN_RNG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/*---------------------------------------------------------------------------*/
/**
 * \brief      Fill a buffer with random bytes from the CRACEN CTR-DRBG.
 * \param buf  Destination buffer.
 * \param len  Number of random bytes to generate.
 * \return     True on success, false if the CRACEN RNG could not be used.
 *
 *             The CRACEN TRNG/CryptoMaster is claimed for the duration of the
 *             call and released again before returning, so the engine remains
 *             available to other users between calls.
 */
bool cracen_rng_get(uint8_t *buf, size_t len);
/*---------------------------------------------------------------------------*/
#endif /* CRACEN_RNG_H_ */
