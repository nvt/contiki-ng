/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*---------------------------------------------------------------------------*/
/**
 * \file
 *      Temperature platform for nrf_802154 on the nRF5340 network core.
 *
 *      Used by the library to compensate the RSSI/ED and CCA thresholds.
 *      Returns a fixed 20 C for now; a later revision can read the TEMP
 *      peripheral on the network core.
 */
/*---------------------------------------------------------------------------*/
#include "platform/nrf_802154_temperature.h"

#include <stdint.h>
/*---------------------------------------------------------------------------*/
void
nrf_802154_temperature_init(void)
{
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_temperature_deinit(void)
{
}
/*---------------------------------------------------------------------------*/
int8_t
nrf_802154_temperature_get(void)
{
  return 20; /* degrees Celsius */
}
/*---------------------------------------------------------------------------*/
