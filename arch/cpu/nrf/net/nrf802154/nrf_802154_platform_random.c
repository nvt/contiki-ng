/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*---------------------------------------------------------------------------*/
/**
 * \file
 *      Random number platform for nrf_802154 on the nRF5340 network core.
 *      Backed by the Contiki-NG random module.
 *
 *      The library only calls nrf_802154_random_get() from its CSMA-CA
 *      backoff, which this port disables (NRF_802154_CSMA_CA_ENABLED 0;
 *      Contiki-NG does CSMA backoff on the app core). It is therefore
 *      currently dormant and provided for completeness / future features.
 */
/*---------------------------------------------------------------------------*/
#include "platform/nrf_802154_random.h"
#include "lib/random.h"

#include <stdint.h>
/*---------------------------------------------------------------------------*/
void
nrf_802154_random_init(void)
{
  /* Contiki-NG random is initialized during boot. */
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_random_deinit(void)
{
}
/*---------------------------------------------------------------------------*/
uint32_t
nrf_802154_random_get(void)
{
  return (uint32_t)random_rand() | ((uint32_t)random_rand() << 16);
}
/*---------------------------------------------------------------------------*/
