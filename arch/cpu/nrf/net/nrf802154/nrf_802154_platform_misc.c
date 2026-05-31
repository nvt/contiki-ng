/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*---------------------------------------------------------------------------*/
/**
 * \file
 *      Miscellaneous platform callouts for nrf_802154 on the nRF5340
 *      network core.
 */
/*---------------------------------------------------------------------------*/
#include "nrf_802154.h"

#include <stdint.h>
/*---------------------------------------------------------------------------*/
void
nrf_802154_custom_part_of_radio_init(void)
{
  /* No custom RADIO register initialization needed. */
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_tx_ack_started(const uint8_t *p_data)
{
  (void)p_data;
}
/*---------------------------------------------------------------------------*/
