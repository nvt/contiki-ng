/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/*---------------------------------------------------------------------------*/
/**
 * \file
 *      Platform assert override for nrf_802154 on the nRF5340 network core.
 *      Adapted from arch/cpu/nrf/nrf54l15/nrf_802154_platform_assert.h.
 *
 *      The network core has no UARTE (NRF_HAS_UARTE 0); its debug output is
 *      forwarded to the application core over the IPC log ring buffer via
 *      dbg_putchar(). On an internal library assertion this reports
 *      "802154! file:line" through that path and then resets the core. BKPT
 *      is avoided on purpose: with a debugger attached it would halt in
 *      Debug state instead of escalating, hanging the core silently.
 */
/*---------------------------------------------------------------------------*/
#ifndef NRF_802154_PLATFORM_ASSERT_H_
#define NRF_802154_PLATFORM_ASSERT_H_
/*---------------------------------------------------------------------------*/
__attribute__((noreturn))
static inline void
nrf_802154_platform_assert_fail(const char *file, unsigned line)
{
  extern int dbg_putchar(int c);
  const char *basename = file;
  const char *p;
  char digits[10];
  int i;
  volatile int d;

  for(p = "802154! "; *p != '\0'; p++) {
    dbg_putchar(*p);
  }

  /* Print the basename of __FILE__. */
  for(p = file; *p != '\0'; p++) {
    if(*p == '/') {
      basename = p + 1;
    }
  }
  for(p = basename; *p != '\0'; p++) {
    dbg_putchar(*p);
  }
  dbg_putchar(':');

  /* Print __LINE__ in decimal. */
  if(line == 0) {
    dbg_putchar('0');
  } else {
    i = 0;
    while(line > 0) {
      digits[i++] = (char)('0' + (line % 10));
      line /= 10;
    }
    while(i-- > 0) {
      dbg_putchar(digits[i]);
    }
  }
  dbg_putchar('\n');

  /* Brief spin so the IPC log drains before reset. */
  for(d = 0; d < 100000; d++) {
  }

  /* System reset via SCB->AIRCR (CMSIS NVIC_SystemReset() equivalent). */
  __asm volatile("dsb 0xF" ::: "memory");
  *((volatile unsigned long *)0xE000ED0CUL) = 0x05FA0004UL;
  __asm volatile("dsb 0xF" ::: "memory");
  for(;;) {
    __asm volatile("nop");
  }
}
/*---------------------------------------------------------------------------*/
#define NRF_802154_ASSERT(condition)                                    \
  do {                                                                  \
    if(!(condition)) {                                                  \
      nrf_802154_platform_assert_fail(__FILE__, __LINE__);              \
    }                                                                   \
  } while(0)
/*---------------------------------------------------------------------------*/
#endif /* NRF_802154_PLATFORM_ASSERT_H_ */
