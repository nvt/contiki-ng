/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*---------------------------------------------------------------------------*/
/**
 * \file
 *      IRQ abstraction layer for nrf_802154 on the nRF5340 network core.
 *
 *      The 802.15.4 driver uses two interrupts: RADIO and an EGU (SWI).
 *      On the network core these are RADIO_IRQn and EGU0_IRQn (the library
 *      default NRF_802154_EGU_INSTANCE_NO is 0). The registered ISRs are
 *      dispatched from the NVIC handlers defined here. With the direct
 *      (non-SWI) notification/request implementation selected in the
 *      project config, the EGU ISR is normally never registered, but the
 *      handler is provided for completeness.
 *
 *      The legacy nrf-ieee-driver-arch.c (which also defines
 *      RADIO_IRQHandler) must be filtered out of the net-core build.
 */
/*---------------------------------------------------------------------------*/
#include "platform/nrf_802154_irq.h"
#include "nrf_802154_config.h"
#include "nrf.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

static nrf_802154_isr_t radio_isr;
static nrf_802154_isr_t egu_isr;
/*---------------------------------------------------------------------------*/
void
nrf_802154_irq_init(uint32_t irqn, int32_t prio, nrf_802154_isr_t isr)
{
  if(prio < 0) {
    /* Negative priorities denote zero-latency IRQs, which a bare-metal
     * Contiki-NG build does not expose; clamp to the highest programmable
     * priority. */
    prio = 0;
  }

  if(irqn == RADIO_IRQn) {
    radio_isr = isr;
  } else if(irqn == EGU0_IRQn) {
    egu_isr = isr;
  }

  NVIC_SetPriority((IRQn_Type)irqn, (uint32_t)prio);
  NVIC_ClearPendingIRQ((IRQn_Type)irqn);
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_irq_enable(uint32_t irqn)
{
  NVIC_EnableIRQ((IRQn_Type)irqn);
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_irq_disable(uint32_t irqn)
{
  NVIC_DisableIRQ((IRQn_Type)irqn);
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_irq_set_pending(uint32_t irqn)
{
  NVIC_SetPendingIRQ((IRQn_Type)irqn);
}
/*---------------------------------------------------------------------------*/
void
nrf_802154_irq_clear_pending(uint32_t irqn)
{
  NVIC_ClearPendingIRQ((IRQn_Type)irqn);
}
/*---------------------------------------------------------------------------*/
bool
nrf_802154_irq_is_enabled(uint32_t irqn)
{
  return NVIC_GetEnableIRQ((IRQn_Type)irqn) != 0;
}
/*---------------------------------------------------------------------------*/
uint32_t
nrf_802154_irq_priority_get(uint32_t irqn)
{
  return NVIC_GetPriority((IRQn_Type)irqn);
}
/*---------------------------------------------------------------------------*/
#if !NRF_802154_INTERNAL_RADIO_IRQ_HANDLING
/* When internal RADIO IRQ handling is enabled, nrf_802154_trx.c provides
 * RADIO_IRQHandler itself, so only define it here in the external case. */
void
RADIO_IRQHandler(void)
{
  if(radio_isr != NULL) {
    radio_isr();
  }
}
#endif
/*---------------------------------------------------------------------------*/
#if !NRF_802154_INTERNAL_SWI_IRQ_HANDLING
void
EGU0_IRQHandler(void)
{
  if(egu_isr != NULL) {
    egu_isr();
  }
}
#endif
/*---------------------------------------------------------------------------*/
